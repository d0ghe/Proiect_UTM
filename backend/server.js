require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

global.stats = {
    files_scanned: 154,
    threats_found: 2,
    quarantined: 2,
    status: "Online",
};

require('./watcher'); // Pornește paznicul cu notificări

const app = express();
const PORT = process.env.PORT || 5000;
const QUARANTINE_DIR = path.join(__dirname, 'quarantine');

app.use(cors());
app.use(express.json());

// Rute
app.use('/api/antivirus', require('./routes/antivirus'));

// Ruta pentru tabelul de carantină din Frontend
app.get('/api/quarantine-list', (req, res) => {
    if (!fs.existsSync(QUARANTINE_DIR)) return res.json([]);
    const files = fs.readdirSync(QUARANTINE_DIR).map(file => {
        const s = fs.statSync(path.join(QUARANTINE_DIR, file));
        return { name: file, date: s.birthtime, size: (s.size / 1024).toFixed(2) + ' KB' };
    });
    res.json(files.reverse());
});

app.get('/api/status', (req, res) => {
    res.json({
        ...global.stats,
        platform: "Windows Node",
        uptime: `${Math.floor(process.uptime() / 60)} min`,
        cpu_usage: (Math.random() * 5 + 10).toFixed(1),
        ram_usage: 45
    });
});

app.listen(PORT, () => {
    console.log(`[🚀] Sentinel Online la http://localhost:${PORT}`);
});