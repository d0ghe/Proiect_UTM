const express = require('express');
const path = require('path');

const verifyToken = require('../middleware/verifyToken');
const { getAnalysisJobs } = require('../store/analysisStore');
const { getContentFilterState } = require('../store/contentFilterStore');
const { buildOverview: buildContentFilterOverview } = require('../utils/contentFilter');
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

function toEventTimestamp(value) {
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : 0;
}

router.get('/', (_req, res) => {
  const controls = getControls();
  const rules = getFirewallRules();
  const contentFilter = buildContentFilterOverview(getContentFilterState());
  const scanLogs = readScanLogs(LOG_FILE);
  const analysisJobs = getAnalysisJobs();
  const activeRules = rules.filter((rule) => String(rule.status).toLowerCase() === 'active').length;
  const analysisEvents = analysisJobs
    .flatMap((job) => (Array.isArray(job.history) ? job.history : []).map((entry) => ({
      id: `${job.id}-${entry.id}`,
      source: entry.source || 'Hybrid Analysis',
      severity: entry.severity || 'info',
      title: entry.title || 'Analysis update',
      detail: entry.detail || job.message || 'Analysis activity recorded.',
      time: entry.time || job.updatedAt || job.createdAt,
    })))
    .slice(0, 12);

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
      time: controls.lastUpdated,
    },
    {
      id: `content-filter-${contentFilter.runtime.lastApplyAt || 'idle'}`,
      source: 'Content Filter',
      severity: contentFilter.policy.enabled && !contentFilter.runtime.applied ? 'warning' : 'info',
      title: contentFilter.policy.enabled ? 'Hosts policy configured' : 'Content filtering idle',
      detail: contentFilter.policy.enabled
        ? `${contentFilter.runtime.appliedDomainCount || 0} domains are prepared for hosts-based blocking across ${contentFilter.runtime.enabledCategoryIds.length} categories.`
        : 'No content-filter policy is currently enforced on the hosts file.',
      time: contentFilter.runtime.lastApplyAt || contentFilter.policy.lastUpdated || controls.lastUpdated,
    },
    ...scanLogs.slice(0, 8).map(buildLogEvent),
    ...analysisEvents,
  ].sort((left, right) => toEventTimestamp(right.time) - toEventTimestamp(left.time));

  res.json({ success: true, events });
});

module.exports = router;
