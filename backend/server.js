require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const cors = require('cors');
const express = require('express');

global.stats = {
  files_scanned: 0,
  threats_found: 0,
  quarantined: 0,
  status: 'Online',
};

require('./watcher');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.use('/api', require('./routes/auth'));
app.use('/api/status', require('./routes/status'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/firewall', require('./routes/firewall'));
app.use('/api/antivirus', require('./routes/antivirus'));
app.use('/api/events', require('./routes/events'));
app.use('/api/controls', require('./routes/controls'));
app.use('/api/cleanup', require('./routes/cleanup'));

app.listen(PORT, () => {
  console.log(`[+] Sentinel backend listening on http://localhost:${PORT}`);
});
