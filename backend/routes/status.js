const express = require('express');
const fs = require('fs');
const path = require('path');

const verifyToken = require('../middleware/verifyToken');
const { summarizeAnalysisJobs } = require('../store/analysisStore');
const { getContentFilterState } = require('../store/contentFilterStore');
const { collectTelemetry } = require('../utils/telemetry');
const { buildOverview: buildContentFilterOverview } = require('../utils/contentFilter');
const { readScanLogs, summarizeScanLogs } = require('../utils/scanLog');
const { countActiveFirewallRules, getControls, getFirewallRules } = require('../store/runtimeState');
const { getHybridAnalysisConfig } = require('../utils/hybridAnalysis');

const router = express.Router();
const LOG_FILE = path.join(__dirname, '../scans.log');
const QUARANTINE_DIR = path.join(__dirname, '../quarantine');
const hybridAnalysisConfig = getHybridAnalysisConfig();

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
    const analysisSummary = summarizeAnalysisJobs();
    const contentFilter = buildContentFilterOverview(getContentFilterState());
    const quarantineCount = countQuarantinedFiles();
    const blockRules = firewallRules.filter((rule) => String(rule.action).toUpperCase() === 'BLOCK').length;
    const allowRules = firewallRules.filter((rule) => String(rule.action).toUpperCase() === 'ALLOW').length;
    const globalFilesScanned = Number(global.stats?.files_scanned || 0);
    const globalThreats = Number(global.stats?.threats_found || 0);
    const globalQuarantine = Number(global.stats?.quarantined || 0);

    res.json({
      success: true,
      platform: telemetry.platform,
      os: telemetry.os,
      status: controls.maintenanceMode ? 'Maintenance' : 'Operational',
      firewall: controls.firewallEnabled ? 'Active' : 'Inactive',
      antivirus: controls.protectionEnabled ? 'Protected' : 'Paused',
      uptime: telemetry.uptime,
      cpu_percent: telemetry.cpu.load,
      ram_percent: telemetry.ram.percent,
      gpu_percent: telemetry.gpu.usagePercent,
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
      sandbox_jobs_pending: analysisSummary.pending + analysisSummary.running,
      sandbox_jobs_completed: analysisSummary.completed,
      hybrid_analysis_findings: analysisSummary.review + analysisSummary.malicious,
      hybrid_analysis_available: hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured,
      connected_clients: telemetry.connectedClients,
      rx_rate: telemetry.network.rxRate,
      tx_rate: telemetry.network.txRate,
      content_filter_enabled: contentFilter.policy.enabled,
      content_filter_domains: contentFilter.runtime.appliedDomainCount,
      content_filter_last_applied: contentFilter.runtime.lastApplyAt,
      content_filter_categories: contentFilter.runtime.enabledCategoryIds.length,
      content_filter_ready: contentFilter.runtime.environment.supported,
      contentFilter,
      controls,
      cpu: telemetry.cpu,
      gpu: telemetry.gpu,
      ram: telemetry.ram,
      network: telemetry.network,
      packets: telemetry.packets,
      connectionSummary: telemetry.connectionSummary,
      temperature: telemetry.temperature,
      analysis: analysisSummary,
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
