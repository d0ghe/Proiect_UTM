require('dotenv').config(); // Încarcă variabilele din .env (cheia API, portul etc.)
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// --- MIDDLEWARE ---
// Permitem Frontend-ului să comunice cu Backend-ul fără blocaje de securitate
app.use(cors()); 
app.use(express.json());

// --- RUTE API ---
const firewallRoutes = require('./routes/firewall');
const authRoutes = require('./routes/auth');
const statsRouter = require('./routes/stats');
const antivirusRoutes = require('./routes/antivirus');

// Legăm modulele la adresele lor
app.use('/api/firewall', firewallRoutes);
app.use('/api/stats', statsRouter);
app.use('/api/antivirus', antivirusRoutes);
app.use('/api', authRoutes); // Pentru /api/login, /api/register

// --- RUTA STATUS (Inima Dashboard-ului) ---
/**
 * Această rută "hrănește" Dashboard-ul cu date live.
 * Frontend-ul tău dă refresh la fiecare 5 secunde aici.
 */
app.get('/api/status', (req, res) => {
    // Aici simulăm datele de sistem. 
    // Mai târziu le putem lega de "paznicul" nostru în timp real.
    res.json({
        status: "Online",
        platform: process.platform === 'win32' ? 'Windows Node' : 'Linux Node',
        uptime: `${Math.floor(process.uptime() / 60)} min`,
        temperature_c: 42.5, // Poți pune date reale mai târziu
        cpu_usage: Math.floor(Math.random() * 20) + 10, // Simulare 10-30%
        ram_usage: 45,
        ram_used_mb: 1024,
        files_scanned: 154, // Acestea vor crește când activăm Watcher-ul
        threats_found: 2,
        quarantined: 2,
        firewall_status: "Active",
        rules_active: 12,
        blocked_today: 45,
        allowed_today: 1205
    });
});

// --- PORNIRE SERVER ---
app.listen(PORT, () => {
    console.log('--------------------------------------------------');
    console.log(`[🚀] UTM Sentinel Backend pornit cu succes!`);
    console.log(`[📡] Endpoint principal: http://localhost:${PORT}`);
    console.log(`[🛡️] Antivirus Engine: Operational`);
    console.log('--------------------------------------------------');
});