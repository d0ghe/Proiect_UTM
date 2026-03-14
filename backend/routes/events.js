const express = require('express');
const path = require('path');

const verifyToken = require('../middleware/verifyToken');
const { getControls, getFirewallRules } = require('../store/runtimeState');
const { readScanLogs } = require('../utils/scanLog');

const router = express.Router();
const LOG_FILE = path.join(__dirname, '../scans.log');

router.use(verifyToken);

function buildLogEvent(line, index) {
  const match = line.match(/^\[(.+?)\]\s+STATUS:\s+([^|]+)\s+\|\s+Fisier:\s+([^|]+)\s+\|\s+Hash:\s+([^|]+)\s+\|\s+Rezultat:\s+(.+)$/);

  if (!match) {
    return {
      id: `log-${index}`,
      source: 'Protection',
      severity: 'info',
      title: 'Scan log entry',
      detail: line,
      time: new Date().toISOString(),
    };
  }

  const [, timestamp, status, filename, hash, result] = match;
  const normalizedStatus = status.trim().toUpperCase();
  const severity = normalizedStatus === 'INFECTED'
    ? 'critical'
    : normalizedStatus === 'ERROR' || normalizedStatus === 'REVIEW'
      ? 'warning'
      : 'info';

  return {
    id: `${filename.trim()}-${hash.trim()}-${index}`,
    source: 'Protection',
    severity,
    title: `${normalizedStatus} file scan`,
    detail: `${filename.trim()} -> ${result.trim()}`,
    time: timestamp.trim(),
  };
}

router.get('/', (_req, res) => {
  const controls = getControls();
  const rules = getFirewallRules();
  const scanLogs = readScanLogs(LOG_FILE);
  const activeRules = rules.filter((rule) => String(rule.status).toLowerCase() === 'active').length;

  const events = [
    {
      id: `controls-${controls.lastUpdated}`,
      source: 'Controls',
      severity: controls.maintenanceMode ? 'warning' : 'info',
      title: controls.maintenanceMode ? 'Maintenance mode enabled' : 'Control plane ready',
      detail: controls.telemetryEnabled
        ? 'Telemetry collection is enabled for the dashboard.'
        : 'Telemetry collection has been paused from controls.',
      time: controls.lastUpdated,
    },
    {
      id: `firewall-${activeRules}`,
      source: 'Firewall',
      severity: activeRules > 0 ? 'info' : 'warning',
      title: `${rules.length} firewall rules loaded`,
      detail: `${activeRules} rules are currently active on the device.`,
      time: new Date().toISOString(),
    },
    ...scanLogs.slice(0, 8).map(buildLogEvent),
  ];

  res.json({ success: true, events });
});

module.exports = router;
