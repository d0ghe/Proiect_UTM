const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { scanProcessMemory } = require('../utils/memoryScanner');
const { broadcast } = require('../utils/wsBroadcaster');
const { addActivityEntry } = require('../store/activityLog');

const router = express.Router();
router.use(verifyToken);

let lastScan = null;
let scanning = false;

router.get('/scan', async (_req, res) => {
  if (scanning) {
    return res.json({ success: true, scanning: true, lastScan });
  }

  scanning = true;
  try {
    const result = await scanProcessMemory();
    lastScan = result;

    if (result.summary?.critical > 0) {
      addActivityEntry('ALERT', 'Memory', `Memory scan: ${result.summary.critical} critical process(es)`,
        result.processes.filter((p) => p.threat === 'CRITICAL').map((p) => p.name).join(', '));
      broadcast({ category: 'memory_threat', severity: 'critical', summary: result.summary });
    } else if (result.summary?.suspicious > 0) {
      addActivityEntry('WARNING', 'Memory', `Memory scan: ${result.summary.suspicious} suspicious process(es)`, '');
    }

    res.json({ success: true, scanning: false, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  } finally {
    scanning = false;
  }
});

router.get('/last', (_req, res) => {
  res.json({ success: true, scanning, lastScan });
});

module.exports = router;
