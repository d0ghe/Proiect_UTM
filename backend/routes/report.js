const express = require('express');
const fs = require('fs');
const path = require('path');

const verifyToken = require('../middleware/verifyToken');
const { buildSecurityReport } = require('../utils/pdfReport');
const { collectTelemetry } = require('../utils/telemetry');
const { buildOverview: buildContentFilterOverview } = require('../utils/contentFilter');
const { getContentFilterState } = require('../store/contentFilterStore');
const { readScanLogs, summarizeScanLogs } = require('../utils/scanLog');
const { countActiveFirewallRules, getControls, getFirewallRules } = require('../store/runtimeState');
const { summarizeAnalysisJobs } = require('../store/analysisStore');
const { getHybridAnalysisConfig } = require('../utils/hybridAnalysis');

const router = express.Router();
const LOG_FILE = path.join(__dirname, '../scans.log');
const QUARANTINE_DIR = path.join(__dirname, '../quarantine');

router.use(verifyToken);

router.get('/security', async (_req, res) => {
  try {
    const [telemetry] = await Promise.all([collectTelemetry()]);
    const controls = getControls();
    const firewallRules = getFirewallRules();
    const logs = readScanLogs(LOG_FILE);
    const logSummary = summarizeScanLogs(logs);
    const analysisSummary = summarizeAnalysisJobs();
    const contentFilter = buildContentFilterOverview(getContentFilterState());
    const quarantineCount = fs.existsSync(QUARANTINE_DIR) ? fs.readdirSync(QUARANTINE_DIR).length : 0;
    const hybridAnalysisConfig = getHybridAnalysisConfig();

    const statusData = {
      status:    controls.maintenanceMode ? 'Maintenance' : 'Operational',
      platform:  telemetry.platform,
      os:        telemetry.os,
      uptime:    telemetry.uptime,
      firewall:  controls.firewallEnabled  ? 'Active'     : 'Inactive',
      antivirus: controls.protectionEnabled ? 'Protected'  : 'Paused',
      cpu_percent:  telemetry.cpu.load,
      ram_percent:  telemetry.ram.percent,
      rules_loaded: firewallRules.length,
      rules_active: countActiveFirewallRules(),
      blocked_today: firewallRules.filter((r) => String(r.action).toUpperCase() === 'BLOCK').length,
      allowed_today: firewallRules.filter((r) => String(r.action).toUpperCase() === 'ALLOW').length,
      files_scanned: Math.max(Number(global.stats?.files_scanned || 0), logSummary.total),
      threats_found: Math.max(Number(global.stats?.threats_found || 0), logSummary.infected),
      quarantined:   Math.max(Number(global.stats?.quarantined   || 0), quarantineCount),
      alerts_today:  logSummary.infected + logSummary.review + logSummary.failed,
      high_severity: logSummary.infected,
      sandbox_jobs_pending:   analysisSummary.pending + analysisSummary.running,
      sandbox_jobs_completed: analysisSummary.completed,
      hybrid_analysis_findings:  analysisSummary.review + analysisSummary.malicious,
      hybrid_analysis_available: hybridAnalysisConfig.enabled && hybridAnalysisConfig.isConfigured,
      controls,
      contentFilter,
    };

    const pdfBuffer = await buildSecurityReport(statusData);
    const filename = `containment-atlas-report-${new Date().toISOString().slice(0, 10)}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.end(pdfBuffer);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not generate report.', error: error.message });
  }
});

module.exports = router;
