import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import process from 'node:process'
import { execFile, spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const backendDir = path.join(projectRoot, 'backend')
const restartLogDir = path.join(process.env.TEMP || process.env.TMP || backendDir, 'argus')
const restartLogPath = path.join(restartLogDir, 'backend-restart.log')

function checkBackendHealth(timeoutMs = 2500) {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:5000/api/health', { timeout: timeoutMs }, (res) => {
      res.resume()
      resolve(res.statusCode >= 200 && res.statusCode < 500)
    })

    req.on('timeout', () => {
      req.destroy()
      resolve(false)
    })
    req.on('error', () => resolve(false))
  })
}

function stopStaleBackendProcesses() {
  if (process.platform !== 'win32') {
    return Promise.resolve()
  }

  const escapedBackend = backendDir.replace(/'/g, "''")
  const script = [
    `$backend='${escapedBackend}';`,
    "Get-CimInstance Win32_Process -Filter \"name = 'node.exe'\" |",
    "Where-Object { $_.CommandLine -match 'server\\.js' -and $_.CommandLine -like \"*$backend*\" } |",
    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }',
  ].join(' ')

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeout: 8000, windowsHide: true },
      () => resolve(),
    )
  })
}

function startBackendProcess() {
  fs.mkdirSync(restartLogDir, { recursive: true })
  const out = fs.openSync(restartLogPath, 'a')
  const child = spawn('node.exe', ['server.js'], {
    cwd: backendDir,
    detached: true,
    stdio: ['ignore', out, out],
    windowsHide: true,
  })
  child.unref()
  return child.pid
}

async function waitForBackend(timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await checkBackendHealth(1500)) {
      return true
    }
    await new Promise((resolve) => setTimeout(resolve, 750))
  }
  return false
}

function backendRestartPlugin() {
  return {
    name: 'argus-backend-restarter',
    configureServer(server) {
      server.middlewares.use('/__argus/restart-backend', async (req, res) => {
        if (req.method !== 'POST') {
          res.statusCode = 405
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ success: false, message: 'POST required.' }))
          return
        }

        res.setHeader('Content-Type', 'application/json')

        try {
          if (await checkBackendHealth()) {
            res.end(JSON.stringify({ success: true, alreadyRunning: true, message: 'Backend is already online.' }))
            return
          }

          await stopStaleBackendProcesses()
          const pid = startBackendProcess()
          const online = await waitForBackend()

          res.end(JSON.stringify({
            success: online,
            pid,
            logPath: restartLogPath,
            message: online
              ? 'Backend restarted successfully.'
              : `Backend restart was requested, but health check did not pass yet. Check ${restartLogPath}.`,
          }))
        } catch (error) {
          res.end(JSON.stringify({
            success: false,
            message: error.message || 'Could not restart backend.',
            logPath: restartLogPath,
          }))
        }
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), backendRestartPlugin()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
})
