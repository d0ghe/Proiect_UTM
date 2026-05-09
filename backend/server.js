const http = require('http');
const cors = require('cors');
const express = require('express');
const { loadRuntimeConfig } = require('./utils/runtimeConfig');
const { attach: attachWebSocket } = require('./utils/wsBroadcaster');

global.stats = {
  files_scanned: 0,
  threats_found: 0,
  quarantined: 0,
  status: 'Online',
};

loadRuntimeConfig();
require('./watcher');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/api/health', (_req, res) => {
  res.json({
    success: true,
    message: 'Containment Atlas backend is online.',
  });
});

app.use('/api', require('./routes/auth'));
app.use('/api/status', require('./routes/status'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/firewall', require('./routes/firewall'));
app.use('/api/antivirus', require('./routes/antivirus'));
app.use('/api/events', require('./routes/events'));
app.use('/api/controls', require('./routes/controls'));
app.use('/api/cleanup', require('./routes/cleanup'));
app.use('/api/content-filter', require('./routes/contentFilter'));
app.use('/api/signal', require('./routes/signal'));
app.use('/api/intel', require('./routes/intelligence'));

const server = http.createServer(app);
attachWebSocket(server);

server.listen(PORT, () => {
  console.log(`[+] Sentinel backend listening on http://localhost:${PORT}`);
  console.log(`[+] WebSocket alerts: ws://localhost:${PORT}/ws/alerts`);
});
