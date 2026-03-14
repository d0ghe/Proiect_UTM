param(
  [switch]$ForceInstall,
  [switch]$SkipInstall,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $repoRoot 'backend'
$frontendDir = Join-Path $repoRoot 'frontend'
$apiToken = 'utm-auth-token-1773500227333'

function Assert-PathExists {
  param(
    [string]$Path,
    [string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Label not found: $Path"
  }
}

function Assert-CommandExists {
  param(
    [string]$CommandName
  )

  if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
    throw "Required command not found in PATH: $CommandName"
  }
}

function Stop-PortListeners {
  param(
    [int[]]$Ports
  )

  foreach ($port in $Ports) {
    $lines = netstat -ano -p TCP | Select-String 'LISTENING' | Where-Object { $_.ToString() -match ":$port\s" }

    foreach ($line in $lines) {
      $parts = ($line.ToString() -replace '\s+', ' ').Trim().Split(' ')
      if ($parts.Count -lt 5) {
        continue
      }

      $processId = 0
      if (-not [int]::TryParse($parts[4], [ref]$processId)) {
        continue
      }

      if ($processId -le 0) {
        continue
      }

      if ($DryRun) {
        Write-Host "[dry-run] Would stop PID $processId on port $port"
        continue
      }

      try {
        Stop-Process -Id $processId -Force -ErrorAction Stop
        Write-Host "Stopped PID $processId on port $port"
      } catch {
        Write-Warning "Could not stop PID $processId on port ${port}: $($_.Exception.Message)"
      }
    }
  }
}

function Install-Dependencies {
  param(
    [string]$ProjectDir,
    [string]$Label
  )

  $nodeModules = Join-Path $ProjectDir 'node_modules'
  $lockFile = Join-Path $ProjectDir 'package-lock.json'
  $shouldInstall = $ForceInstall -or (-not $SkipInstall -and -not (Test-Path -LiteralPath $nodeModules))

  if (-not $shouldInstall) {
    Write-Host "$Label dependencies already present."
    return
  }

  $installCommand = if (Test-Path -LiteralPath $lockFile) { 'ci' } else { 'install' }
  Write-Host "Installing $Label dependencies with npm $installCommand..."

  if ($DryRun) {
    Write-Host "[dry-run] Would run npm.cmd $installCommand in $ProjectDir"
    return
  }

  Push-Location $ProjectDir
  try {
    & npm.cmd $installCommand
    if ($LASTEXITCODE -ne 0) {
      throw "npm $installCommand failed in $ProjectDir"
    }
  } finally {
    Pop-Location
  }
}

function Start-ServiceWindow {
  param(
    [string]$Label,
    [string]$WorkingDir,
    [string]$Command
  )

  if ($DryRun) {
    Write-Host "[dry-run] Would start $Label with: $Command"
    return $null
  }

  $fullCommand = "Set-Location -LiteralPath '$WorkingDir'; $Command"
  $process = Start-Process powershell.exe -ArgumentList '-NoExit', '-Command', $fullCommand -PassThru
  Write-Host "$Label started in a new window (PID $($process.Id))."
  return $process
}

function Test-BackendHealth {
  $headers = @{ Authorization = "Bearer $apiToken" }

  for ($attempt = 1; $attempt -le 12; $attempt++) {
    try {
      $response = Invoke-RestMethod -Uri 'http://localhost:5000/api/status' -Headers $headers -TimeoutSec 4
      return $response
    } catch {
      Start-Sleep -Seconds 2
    }
  }

  return $null
}

Assert-PathExists -Path $backendDir -Label 'Backend directory'
Assert-PathExists -Path $frontendDir -Label 'Frontend directory'
Assert-CommandExists -CommandName 'node'
Assert-CommandExists -CommandName 'npm.cmd'

Write-Host "Preparing local stack from $repoRoot"
Stop-PortListeners -Ports @(5000, 5173)
Install-Dependencies -ProjectDir $backendDir -Label 'Backend'
Install-Dependencies -ProjectDir $frontendDir -Label 'Frontend'

$backendProcess = Start-ServiceWindow -Label 'Backend' -WorkingDir $backendDir -Command 'node server.js'
$frontendProcess = Start-ServiceWindow -Label 'Frontend' -WorkingDir $frontendDir -Command 'npm.cmd run dev -- --host 0.0.0.0'

if (-not $DryRun) {
  $backendStatus = Test-BackendHealth
  if ($backendStatus) {
    Write-Host "Backend healthy on http://localhost:5000"
    Write-Host "Platform: $($backendStatus.platform)"
    Write-Host "CPU: $($backendStatus.cpu_percent)% | RAM: $($backendStatus.ram_percent)% | RX: $($backendStatus.rx_rate) | TX: $($backendStatus.tx_rate)"
  } else {
    Write-Warning 'Backend did not answer in time. Check the backend PowerShell window for errors.'
  }

  Write-Host 'Frontend should be available on http://localhost:5173'
  Write-Host "Backend PID: $($backendProcess.Id)"
  Write-Host "Frontend PID: $($frontendProcess.Id)"
}
