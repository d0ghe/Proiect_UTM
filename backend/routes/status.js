const express = require('express');
const fs = require('fs');
const path = require('path');

const verifyToken = require('../middleware/verifyToken');
const { collectTelemetry } = require('../utils/telemetry');
const { readScanLogs, summarizeScanLogs } = require('../utils/scanLog');
const { countActiveFirewallRules, getControls, getFirewallRules } = require('../store/runtimeState');

const router = express.Router();
const LOG_FILE = path.join(__dirname, '../scans.log');
const QUARANTINE_DIR = path.join(__dirname, '../quarantine');

router.use(verifyToken);

function countQuarantinedFiles() {
  if (!fs.existsSync(QUARANTINE_DIR)) {
    return 0;
  }

  return fs.readdirSync(QUARANTINE_DIR).length;
}

router.get('/', async (_req, res) => {
  try {
    const [telemetry] = await Promise.all([collectTelemetry()]);
    const controls = getControls();
    const firewallRules = getFirewallRules();
    const activeRules = countActiveFirewallRules();
    const logs = readScanLogs(LOG_FILE);
    const logSummary = summarizeScanLogs(logs);
    const quarantineCount = countQuarantinedFiles();
    const blockRules = firewallRules.filter((rule) => String(rule.action).toUpperCase() === 'BLOCK').length;
    const allowRules = firewallRules.filter((rule) => String(rule.action).toUpperCase() === 'ALLOW').length;
    const globalFilesScanned = Number(global.stats?.files_scanned || 0);
    const globalThreats = Number(global.stats?.threats_found || 0);
    const globalQuarantine = Number(global.stats?.quarantined || 0);

    res.json({
      success: true,
      platform: telemetry.platform,
      status: controls.maintenanceMode ? 'Maintenance' : 'Operational',
      firewall: controls.firewallEnabled ? 'Active' : 'Inactive',
      antivirus: controls.protectionEnabled ? 'Protected' : 'Paused',
      uptime: telemetry.uptime,
      cpu_percent: telemetry.cpu.load,
      ram_percent: telemetry.ram.percent,
      ram_used_mb: telemetry.ram.used === null ? null : Math.round(telemetry.ram.used * 1024),
      temperature_c: telemetry.temperature.celsius,
      temperature_source: telemetry.temperature.source,
      temperature_available: telemetry.temperature.available,
      rules_active: activeRules,
      blocked_today: blockRules,
      allowed_today: allowRules,
      files_scanned: Math.max(globalFilesScanned, logSummary.total),
      threats_found: Math.max(globalThreats, logSummary.infected),
      quarantined: Math.max(globalQuarantine, quarantineCount),
      alerts_today: logSummary.infected + logSummary.review + logSummary.failed,
      high_severity: logSummary.infected,
      rules_loaded: firewallRules.length,
      connected_clients: telemetry.connectedClients,
      rx_rate: telemetry.network.rxRate,
      tx_rate: telemetry.network.txRate,
      controls,
      cpu: telemetry.cpu,
      ram: telemetry.ram,
      network: telemetry.network,
      temperature: telemetry.temperature,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Could not collect system status.',
      error: error.message,
    });
  }
});

module.exports = router;
