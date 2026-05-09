const http    = require('http');
const cors    = require('cors');
const express = require('express');

const { loadRuntimeConfig }       = require('./utils/runtimeConfig');
const { attach: attachWebSocket } = require('./utils/wsBroadcaster');
const { startProxy, stopProxy, PROXY_PORT } = require('./utils/httpProxy');
const { enableProxy, disableProxy } = require('./utils/systemProxy');
const { applyOsRule }               = require('./utils/osFirewall');
const { getFirewallRules }          = require('./store/runtimeState');

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

server.listen(PORT, async () => {
  console.log(`[+] Sentinel backend  →  http://localhost:${PORT}`);
  console.log(`[+] WebSocket alerts  →  ws://localhost:${PORT}/ws/alerts`);

  // Pornește proxy-ul interceptor și configurează browserele să-l folosească
  startProxy();
  const proxyRes = await enableProxy('127.0.0.1', PROXY_PORT);
  console.log(`[+] UTM Proxy pornit pe portul ${PROXY_PORT}`);
  if (proxyRes.notes && proxyRes.notes.length) {
    proxyRes.notes.forEach((n) => console.log(`    ${n}`));
  }

  // Re-aplică regulile active BLOCK în Windows Firewall via PowerShell (dacă e admin)
  const activeBlocks = getFirewallRules().filter(
    (r) => String(r.action).toUpperCase() === 'BLOCK' &&
           String(r.status).toLowerCase() === 'active'
  );
  if (activeBlocks.length > 0) {
    console.log(`[+] Sincronizez ${activeBlocks.length} regulă(i) BLOCK în Windows Firewall...`);
    for (const rule of activeBlocks) {
      const r = await applyOsRule(rule);
      console.log(`    port ${rule.port}: ${r.message}`);
    }
  }
});

// Curăță setările de proxy la oprire — evită situația "no internet"
async function shutdown() {
  console.log('\n[!] Oprire server — dezactivez proxy-ul din browsere...');
  try {
    await disableProxy();
    console.log('[+] Proxy dezactivat. Browsere restaurate la conexiune directă.');
  } catch (e) {
    console.error('[!] Eroare la dezactivarea proxy-ului:', e.message);
  }
  stopProxy(() => process.exit(0));
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
