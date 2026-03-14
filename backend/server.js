const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// --- IMPORTĂM RUTELE ---
const firewallRoutes = require('./routes/firewall');
const authRoutes = require('./routes/auth');
const statsRouter = require('./routes/stats');
app.use('/api/stats', statsRouter);
const antivirusRoutes = require('./routes/antivirus');
app.use('/api/antivirus', antivirusRoutes);

// --- LEGĂM RUTELE LA URL-URI ---
// Orice link care începe cu /api/firewall va fi trimis către fișierul firewall.js
app.use('/api/firewall', firewallRoutes);

// Orice link care începe cu /api va fi trimis către fișierul auth.js (ex: /api/login)
app.use('/api', authRoutes);

app.listen(PORT, () => {
    console.log(`[+] UTM Backend rulează curat și ordonat pe http://localhost:${PORT}`);
});