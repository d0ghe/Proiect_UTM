param(
  [switch]$ForceInstall,
  [switch]$SkipInstall,
  [switch]$DryRun,
  [switch]$SkipNodeInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $repoRoot 'backend'
$frontendDir = Join-Path $repoRoot 'frontend'
$backendEnvPath = Join-Path $backendDir '.env'
$backendEnvExamplePath = Join-Path $backendDir '.env.example'

function Assert-PathExists {
  param(
    [string]$Path,
    [string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Label not found: $Path"
  }
}

function Test-CommandExists {
  param(
    [string]$CommandName
  )

  return [bool](Get-Command $CommandName -ErrorAction SilentlyContinue)
}

function Assert-CommandExists {
  param(
    [string]$CommandName
  )

  if (-not (Test-CommandExists -CommandName $CommandName)) {
    throw "Required command not found in PATH: $CommandName"
  }
}

function Write-Step {
  param(
    [string]$Message
  )

  Write-Host ''
  Write-Host "==> $Message"
}

function Refresh-ProcessPath {
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $combined = @($machinePath, $userPath) | Where-Object { $_ } | Select-Object -Unique
  if ($combined.Count -gt 0) {
    $env:Path = ($combined -join ';')
  }
}

function Invoke-ExternalCommand {
  param(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$Description
  )

  $display = if ($Arguments -and $Arguments.Count -gt 0) {
    "$FilePath $($Arguments -join ' ')"
  } else {
    $FilePath
  }

  if ($DryRun) {
    Write-Host "[dry-run] Would run $Description with: $display"
    return
  }

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Description failed with exit code $LASTEXITCODE."
  }
}

function Install-NodeJs {
  if ((Test-CommandExists -CommandName 'node') -and (Test-CommandExists -CommandName 'npm.cmd')) {
    Write-Host 'Node.js and npm are already available.'
    return
  }

  if ($SkipNodeInstall) {
    throw 'Node.js is required but was not found, and automatic Node.js installation was skipped.'
  }

  Write-Host 'Node.js was not found. Attempting to install Node.js LTS...'

  $attempts = @(
    @{
      Name = 'winget'
      Available = (Test-CommandExists -CommandName 'winget')
      FilePath = 'winget'
      Arguments = @(
        'install',
        '--id', 'OpenJS.NodeJS.LTS',
        '-e',
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--silent'
      )
    },
    @{
      Name = 'choco'
      Available = (Test-CommandExists -CommandName 'choco')
      FilePath = 'choco'
      Arguments = @('install', 'nodejs-lts', '-y')
    },
    @{
      Name = 'scoop'
      Available = (Test-CommandExists -CommandName 'scoop')
      FilePath = 'scoop'
      Arguments = @('install', 'nodejs-lts')
    }
  )

  $installed = $false
  foreach ($attempt in $attempts) {
    if (-not $attempt.Available) {
      continue
    }

    try {
      Invoke-ExternalCommand -FilePath $attempt.FilePath -Arguments $attempt.Arguments -Description "Node.js installation via $($attempt.Name)"
      $installed = $true
      break
    } catch {
      Write-Warning "$($attempt.Name) could not install Node.js automatically: $($_.Exception.Message)"
    }
  }

  if (-not $installed -and -not $DryRun) {
    throw 'Automatic Node.js installation failed. Install Node.js LTS manually from https://nodejs.org/ or enable winget/choco/scoop, then rerun this script.'
  }

  if ($DryRun) {
    Write-Host '[dry-run] Skipping PATH refresh and Node.js verification.'
    return
  }

  Refresh-ProcessPath
  Start-Sleep -Seconds 2

  Assert-CommandExists -CommandName 'node'
  Assert-CommandExists -CommandName 'npm.cmd'
  Write-Host "Node.js ready: $(node --version)"
  Write-Host "npm ready: $(npm.cmd --version)"
}

function Ensure-BackendEnv {
  if (Test-Path -LiteralPath $backendEnvPath) {
    Write-Host 'Backend .env already present.'
    return
  }

  if (-not (Test-Path -LiteralPath $backendEnvExamplePath)) {
    Write-Warning 'No backend .env or .env.example file was found.'
    return
  }

  if ($DryRun) {
    Write-Host "[dry-run] Would create $backendEnvPath from $backendEnvExamplePath"
    return
  }

  Copy-Item -LiteralPath $backendEnvExamplePath -Destination $backendEnvPath
  Write-Host 'Created backend .env from .env.example.'
  Write-Warning 'External features such as Hybrid Analysis require your own API key in backend/.env before they will work.'
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
    Invoke-ExternalCommand -FilePath 'npm.cmd' -Arguments @($installCommand) -Description "$Label dependency installation"
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
  for ($attempt = 1; $attempt -le 12; $attempt++) {
    try {
      $response = Invoke-RestMethod -Uri 'http://localhost:5000/api/health' -TimeoutSec 4
      return $response
    } catch {
      Start-Sleep -Seconds 2
    }
  }

  return $null
}

Assert-PathExists -Path $backendDir -Label 'Backend directory'
Assert-PathExists -Path $frontendDir -Label 'Frontend directory'

Write-Step -Message "Preparing local stack from $repoRoot"
Install-NodeJs
Ensure-BackendEnv
Stop-PortListeners -Ports @(5000, 5173)

Write-Step -Message 'Installing project dependencies'
Install-Dependencies -ProjectDir $backendDir -Label 'Backend'
Install-Dependencies -ProjectDir $frontendDir -Label 'Frontend'

Write-Step -Message 'Starting backend and frontend'
$backendProcess = Start-ServiceWindow -Label 'Backend' -WorkingDir $backendDir -Command 'node server.js'
$frontendProcess = Start-ServiceWindow -Label 'Frontend' -WorkingDir $frontendDir -Command 'npm.cmd run dev -- --host 0.0.0.0'

if (-not $DryRun) {
  Write-Step -Message 'Checking backend health'
  $backendStatus = Test-BackendHealth
  if ($backendStatus) {
    Write-Host "Backend healthy on http://localhost:5000"
    Write-Host "Status: $($backendStatus.message)"
  } else {
    Write-Warning 'Backend did not answer in time. Check the backend PowerShell window for errors.'
  }

  Write-Host 'Frontend should be available on http://localhost:5173'
  Write-Host "Backend PID: $($backendProcess.Id)"
  Write-Host "Frontend PID: $($frontendProcess.Id)"
}
