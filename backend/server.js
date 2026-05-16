const http    = require('http');
const cors    = require('cors');
const express = require('express');
const fs      = require('fs');
const path    = require('path');
const { exec } = require('child_process');

process.on('uncaughtException',  (err) => console.error('[!] uncaughtException:', err.message));
process.on('unhandledRejection', (err) => console.error('[!] unhandledRejection:', err?.message || err));

const { loadRuntimeConfig }       = require('./utils/runtimeConfig');
const { attach: attachWebSocket } = require('./utils/wsBroadcaster');
const { initBlockedDomains, removeQuicBlock } = require('./utils/contentFilter');
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
  res.json({ success: true, message: 'U-Trust backend is online.' });
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
app.use('/api/report',         require('./routes/report'));
app.use('/api/geo-filter',     require('./routes/geoFilter'));
app.use('/api/rules',          require('./routes/rules'));
app.use('/api/memory',         require('./routes/memory'));

const server = http.createServer(app);
attachWebSocket(server);

server.on('error', (error) => {
  if (error?.code === 'EADDRINUSE') {
    console.error(`[!] Backend port ${PORT} is already in use. Stop the existing backend process and try again.`);
    process.exit(1);
  }

  console.error('[!] HTTP server error:', error?.message || error);
  process.exit(1);
});

/* ─── WinINET helpers (Chrome/Edge proxy via registry) ──────────────────── */

const REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const BROWSER_PROXY_PORT = 8877;
const PROXY_PAC_DIR = path.join(process.env.TEMP || process.env.TMP || __dirname, 'u-trust');
const PROXY_PAC_PATH = path.join(PROXY_PAC_DIR, 'browser-proxy.pac');
const BROWSER_PROXY_ENABLED = parseBoolean(
  process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED || process.env.CONTENT_FILTER_PROXY_ENABLED,
  true,
);
let stopBrowserProxyServer = null;

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }

  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return fallback;
}

function run(cmd) {
  return new Promise((resolve) => exec(cmd, (error, stdout, stderr) => resolve({ error, stdout, stderr })));
}

function buildPacFileUrl(filePath) {
  return `file:///${path.resolve(filePath).replace(/\\/g, '/')}`;
}

function writeBrowserProxyPac() {
  fs.mkdirSync(PROXY_PAC_DIR, { recursive: true });
  const pac = `function FindProxyForURL(url, host) {
  if (
    isPlainHostName(host) ||
    shExpMatch(host, "localhost") ||
    shExpMatch(host, "127.*") ||
    shExpMatch(host, "10.*") ||
    shExpMatch(host, "192.168.*") ||
    shExpMatch(host, "172.16.*") ||
    shExpMatch(host, "172.17.*") ||
    shExpMatch(host, "172.18.*") ||
    shExpMatch(host, "172.19.*") ||
    shExpMatch(host, "172.2*.*") ||
    shExpMatch(host, "172.30.*") ||
    shExpMatch(host, "172.31.*")
  ) {
    return "DIRECT";
  }

  return "PROXY 127.0.0.1:${BROWSER_PROXY_PORT}; DIRECT";
}
`;
  fs.writeFileSync(PROXY_PAC_PATH, pac, 'utf8');
  return buildPacFileUrl(PROXY_PAC_PATH);
}

function startBrowserProxy() {
  const { startProxy, stopProxy } = require('./utils/httpProxy');
  stopBrowserProxyServer = stopProxy;
  startProxy();
}

function stopBrowserProxy(cb) {
  if (stopBrowserProxyServer) {
    stopBrowserProxyServer(cb);
    stopBrowserProxyServer = null;
    return;
  }

  if (cb) cb();
}

async function enableChromeProxy() {
  if (process.platform !== 'win32') {
    console.log('[i] Browser proxy auto-config is only supported on Windows; skipping WinINET setup.');
    return;
  }

  const pacUrl = writeBrowserProxyPac();
  await Promise.all([
    run(`reg add "${REG}" /v ProxyEnable /t REG_DWORD /d 0 /f`),
    run(`reg add "${REG}" /v AutoConfigURL /t REG_SZ /d "${pacUrl}" /f`),
    run(`reg delete "${REG}" /v ProxyServer /f`),
    run(`reg delete "${REG}" /v ProxyOverride /f`),
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
  console.log(`[+] Browser PAC set to ${pacUrl} with DIRECT fallback.`);
}

async function disableChromeProxy() {
  if (process.platform !== 'win32') {
    return;
  }

  await Promise.all([
    run(`reg add "${REG}" /v ProxyEnable /t REG_DWORD /d 0 /f`),
    run(`reg delete "${REG}" /v AutoConfigURL /f`),
    run(`reg delete "${REG}" /v ProxyServer /f`),
    run(`reg delete "${REG}" /v ProxyOverride /f`),
  ]);
  const ps = [
    `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;`,
    `public class WI{[DllImport("wininet.dll")]`,
    `public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}';`,
    `[WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;`,
    `[WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`,
  ].join('');
  await run(`powershell -NonInteractive -ExecutionPolicy Bypass -Command "${ps}"`);
  console.log('[+] Browser proxy disabled; direct connection restored.');
}

/* ─── Startup ────────────────────────────────────────────────────────────── */

async function disableChromeProxyIfOwned() {
  if (process.platform !== 'win32') {
    return;
  }

  const [proxyResult, pacResult] = await Promise.all([
    run(`reg query "${REG}" /v ProxyServer`),
    run(`reg query "${REG}" /v AutoConfigURL`),
  ]);
  const proxyServer = String(proxyResult.stdout || '');
  const pacConfig = String(pacResult.stdout || '');
  const ownedProxy = proxyServer.includes(`127.0.0.1:${BROWSER_PROXY_PORT}`)
    || proxyServer.includes(`localhost:${BROWSER_PROXY_PORT}`)
    || pacConfig.includes('u-trust')
    || pacConfig.includes('browser-proxy.pac');

  if (ownedProxy) {
    await disableChromeProxy();
  }
}

server.listen(PORT, async () => {
  console.log(`[+] U-Trust backend  ->  http://localhost:${PORT}`);
  console.log(`[+] WebSocket alerts  →  ws://localhost:${PORT}/ws/alerts`);

  if (BROWSER_PROXY_ENABLED) {
    startBrowserProxy();
    await enableChromeProxy();
  } else {
    await disableChromeProxyIfOwned();
    removeQuicBlock();
    console.log('[i] Browser proxy disabled. Platform will not change system/browser proxy settings.');
  }

  // Reîncarcă domeniile blocate din cache local (fără rețea)
  const cfState = getContentFilterState();
  await initBlockedDomains(cfState.policy);
});

/* ─── Cleanup la oprire (Ctrl+C) ────────────────────────────────────────── */

async function shutdown() {
  console.log('\n[!] Stopping backend...');
  await disableChromeProxyIfOwned();
  stopBrowserProxy(() => process.exit(0));
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
