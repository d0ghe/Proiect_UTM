const http    = require('http');
const cors    = require('cors');
const express = require('express');
const { exec } = require('child_process');

const { loadRuntimeConfig }       = require('./utils/runtimeConfig');
const { attach: attachWebSocket } = require('./utils/wsBroadcaster');
const { startProxy, stopProxy, PROXY_PORT } = require('./utils/httpProxy');
const { initBlockedDomains }               = require('./utils/contentFilter');
const { getContentFilterState }            = require('./store/contentFilterStore');

global.stats = {
  files_scanned: 0,
  threats_found: 0,
  quarantined:   0,
  status:        'Online',
};

loadRuntimeConfig();
require('./watcher');

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ success: true, message: 'Containment Atlas backend is online.' });
});

app.use('/api',                require('./routes/auth'));
app.use('/api/status',         require('./routes/status'));
app.use('/api/stats',          require('./routes/stats'));
app.use('/api/firewall',       require('./routes/firewall'));
app.use('/api/antivirus',      require('./routes/antivirus'));
app.use('/api/events',         require('./routes/events'));
app.use('/api/controls',       require('./routes/controls'));
app.use('/api/cleanup',        require('./routes/cleanup'));
app.use('/api/content-filter', require('./routes/contentFilter'));
app.use('/api/signal',         require('./routes/signal'));
app.use('/api/intel',          require('./routes/intelligence'));

const server = http.createServer(app);
attachWebSocket(server);

/* ─── WinINET helpers (Chrome/Edge proxy via registry) ──────────────────── */

const REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

function run(cmd) {
  return new Promise((resolve) => exec(cmd, resolve));
}

async function enableChromeProxy() {
  await Promise.all([
    run(`reg add "${REG}" /v ProxyEnable /t REG_DWORD /d 1 /f`),
    run(`reg add "${REG}" /v ProxyServer /t REG_SZ /d "127.0.0.1:${PROXY_PORT}" /f`),
    run(`reg add "${REG}" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;<local>" /f`),
  ]);
  // Notifică Chrome să reîncarce setările imediat (fără restart browser)
  const ps = [
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;`,
    `public class WI{[DllImport("wininet.dll")]`,
    `public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}';`,
    `[WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;`,
    `[WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`,
  ].join('');
  await run(`powershell -NonInteractive -ExecutionPolicy Bypass -Command "${ps}"`);
  console.log(`[+] Chrome proxy setat → 127.0.0.1:${PROXY_PORT}`);
}

async function disableChromeProxy() {
  await run(`reg add "${REG}" /v ProxyEnable /t REG_DWORD /d 0 /f`);
  const ps = [
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;`,
    `public class WI{[DllImport("wininet.dll")]`,
    `public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}';`,
    `[WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;`,
    `[WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`,
  ].join('');
  await run(`powershell -NonInteractive -ExecutionPolicy Bypass -Command "${ps}"`);
  console.log('[+] Chrome proxy dezactivat — conexiune directă restaurată.');
}

/* ─── Startup ────────────────────────────────────────────────────────────── */

server.listen(PORT, async () => {
  console.log(`[+] Sentinel backend  →  http://localhost:${PORT}`);
  console.log(`[+] WebSocket alerts  →  ws://localhost:${PORT}/ws/alerts`);

  startProxy();
  await enableChromeProxy();

  // Reîncarcă domeniile blocate din cache local (fără rețea)
  const cfState = getContentFilterState();
  await initBlockedDomains(cfState.policy);
});

/* ─── Cleanup la oprire (Ctrl+C) ────────────────────────────────────────── */

async function shutdown() {
  console.log('\n[!] Oprire — restaurez conexiunea directă în Chrome...');
  await disableChromeProxy();
  stopProxy(() => process.exit(0));
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
