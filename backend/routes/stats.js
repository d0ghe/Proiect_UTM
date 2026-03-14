const express = require('express');
const router = express.Router();
const os = require('os'); // Modul nativ Node.js pentru info sistem
const verifyToken = require('../middleware/verifyToken');

// Protejăm și această rută
router.use(verifyToken);

router.get('/system', (req, res) => {
    // Calculăm memoria RAM
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const ramUsagePercent = ((usedMem / totalMem) * 100).toFixed(2);

    // Info despre CPU
    const cpus = os.cpus();
    const cpuModel = cpus[0].model;

    res.json({
        cpu: {
            model: cpuModel,
            cores: cpus.length,
            load: (os.loadavg()[0] * 10).toFixed(2) // Simulare load (loadavg pe Windows e mai ciudat, dar e ok pt test)
        },
        ram: {
            total: (totalMem / (1024 ** 3)).toFixed(2) + " GB",
            used: (usedMem / (1024 ** 3)).toFixed(2) + " GB",
            percent: ramUsagePercent + "%"
        },
        uptime: (os.uptime() / 3600).toFixed(2) + " ore",
        platform: os.platform()
    });
});

module.exports = router;