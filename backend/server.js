const http    = require('http');
const cors    = require('cors');
const express = require('express');

process.on('uncaughtException',  (err) => console.error('[!] uncaughtException:', err.message));
process.on('unhandledRejection', (err) => console.error('[!] unhandledRejection:', err?.message || err));

const { loadRuntimeConfig }       = require('./utils/runtimeConfig');
const { attach: attachWebSocket } = require('./utils/wsBroadcaster');
const { initBlockedDomains, removeQuicBlock } = require('./utils/contentFilter');
const {
  disableBrowserProxyIfOwned,
  enableBrowserProxyAutoConfig,
  getBrowserProxyPacContent,
} = require('./utils/browserProxyManager');
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
  res.json({ success: true, message: 'Argus backend is online.' });
});

app.get('/browser-proxy.pac', (_req, res) => {
  res.type('application/x-ns-proxy-autoconfig; charset=utf-8');
  res.send(getBrowserProxyPacContent());
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

/* Browser proxy helpers */

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

server.listen(PORT, async () => {
  console.log(`[+] Argus backend  ->  http://localhost:${PORT}`);
  console.log(`[+] WebSocket alerts  →  ws://localhost:${PORT}/ws/alerts`);

  if (BROWSER_PROXY_ENABLED) {
    startBrowserProxy();
    await enableBrowserProxyAutoConfig();
  } else {
    await disableBrowserProxyIfOwned();
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
  await disableBrowserProxyIfOwned();
  stopBrowserProxy(() => process.exit(0));
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
