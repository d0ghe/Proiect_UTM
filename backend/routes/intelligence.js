/**
 * Intelligence Routes — MITRE matrix, Threat Intel, Honeypots, Baseline,
 * YARA-style rules, deep file analysis (PE/IOC/scripts/EML).
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const verifyToken = require('../middleware/verifyToken');
const { requireRole } = require('../middleware/requireRole');

const { getMitreMatrix, mapToMitre } = require('../utils/mitreMapping');
const { getIntelDashboard, resetIntel, getMitreHeatmap } = require('../utils/threatIntel');
const { plantCanaries, listCanaries, listEvents, removeAllCanaries, checkCanaries } = require('../utils/honeypot');
const { getBaselineSummary, recordSample, resetBaseline } = require('../utils/behavioralBaseline');
const { getAlerts: getRansomAlerts, getCurrentWindow } = require('../utils/ransomwareCanary');
const { runRules } = require('../utils/yaraEngine');
const { parsePE } = require('../utils/peParser');
const { extractIOCs } = require('../utils/iocExtractor');
const { decodeStrings } = require('../utils/stringDecoder');
const { analyzeScript } = require('../utils/scriptDeobfuscator');
const { parseEml } = require('../utils/emlParser');
const { analyzeEntropy } = require('../utils/entropyAnalysis');
const { detectEvasion } = require('../utils/evasionDetection');
const { detectSubbyteInjection } = require('../utils/subbyteInjection');
const { computeHeuristicScore } = require('../utils/heuristicScorer');
const { scanBufferForHexSignatures } = require('../utils/hexSignatures');
const { buildScanReport } = require('../utils/pdfReport');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const RULES_FILE = path.join(__dirname, '../store/yara-rules.txt');

router.use(verifyToken);

// ─── MITRE ATT&CK ──────────────────────────────────────────────────────────
router.get('/mitre/matrix', (_req, res) => {
  res.json({ success: true, tactics: getMitreMatrix() });
});

// ─── Threat Intelligence ──────────────────────────────────────────────────
router.get('/intel/dashboard', (_req, res) => {
  res.json({ success: true, intel: getIntelDashboard() });
});

router.post('/intel/reset', requireRole('admin'), (_req, res) => {
  resetIntel();
  res.json({ success: true, message: 'Threat intel data reset.' });
});

router.get('/intel/mitre-heatmap', (_req, res) => {
  res.json({ success: true, heatmap: getMitreHeatmap() });
});

// ─── Honeypots ────────────────────────────────────────────────────────────
router.get('/honeypots', (_req, res) => {
  res.json({ success: true, canaries: listCanaries(), events: listEvents() });
});

router.post('/honeypots/plant', requireRole('admin'), (req, res) => {
  const targetDir = String(req.body?.targetDir || '').trim();
  if (!targetDir) {
    return res.status(400).json({ success: false, message: 'targetDir is required.' });
  }
  try {
    const created = plantCanaries(targetDir);
    res.json({ success: true, created, targetDir });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/honeypots/check', (_req, res) => {
  const triggered = checkCanaries();
  res.json({ success: true, triggered });
});

router.delete('/honeypots/all', requireRole('admin'), (_req, res) => {
  const removed = removeAllCanaries();
  res.json({ success: true, removed });
});

// ─── Behavioral Baseline ──────────────────────────────────────────────────
router.get('/baseline', (_req, res) => {
  res.json({ success: true, baseline: getBaselineSummary() });
});

router.post('/baseline/sample', (req, res) => {
  const sample = req.body || {};
  const result = recordSample(sample);
  res.json({ success: true, ...result });
});

router.post('/baseline/reset', requireRole('admin'), (_req, res) => {
  resetBaseline();
  res.json({ success: true, message: 'Baseline reset.' });
});

// ─── Ransomware Alerts ────────────────────────────────────────────────────
router.get('/ransomware/alerts', (_req, res) => {
  res.json({ success: true, alerts: getRansomAlerts(), window: getCurrentWindow() });
});

// ─── YARA-style Rules ─────────────────────────────────────────────────────
router.get('/rules', (_req, res) => {
  let rulesText = '';
  try {
    if (fs.existsSync(RULES_FILE)) rulesText = fs.readFileSync(RULES_FILE, 'utf8');
  } catch { /* ignore */ }
  res.json({ success: true, rules: rulesText });
});

router.put('/rules', requireRole('admin'), (req, res) => {
  const text = String(req.body?.rules || '');
  try {
    fs.writeFileSync(RULES_FILE, text);
    res.json({ success: true, message: 'Rules saved.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/rules/test', upload.single('file'), (req, res) => {
  const rulesText = req.body?.rules || (fs.existsSync(RULES_FILE) ? fs.readFileSync(RULES_FILE, 'utf8') : '');
  const buf = req.file?.buffer || Buffer.from(req.body?.content || '');
  if (!buf || buf.length === 0) {
    return res.status(400).json({ success: false, message: 'Provide a file or text content.' });
  }
  try {
    const result = runRules(buf, rulesText);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── Deep File Analysis (one-shot) ────────────────────────────────────────
router.post('/analyze/deep', upload.single('file'), (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ success: false, message: 'No file uploaded.' });

  const buf = file.buffer;
  const filename = file.originalname || 'sample.bin';

  const hexResult = scanBufferForHexSignatures(buf);
  const entropyResult = analyzeEntropy(buf);
  const evasionResult = detectEvasion(buf);
  const injectionResult = detectSubbyteInjection(buf);
  const iocs = extractIOCs(buf);
  const stringDecoded = decodeStrings(buf).findings;
  const scriptResult = analyzeScript(buf, filename);
  const peResult = parsePE(buf);

  const rulesText = fs.existsSync(RULES_FILE) ? fs.readFileSync(RULES_FILE, 'utf8') : '';
  const yaraResult = rulesText ? runRules(buf, rulesText) : { matched: [], rules: [] };

  const heuristicScore = computeHeuristicScore({
    hexMatches: hexResult.matches,
    entropyResult,
    evasionResult,
    injectionResult,
  });

  const totalScore = Math.min(
    heuristicScore.score
    + (iocs.suspicionScore || 0)
    + (decodeStrings(buf).riskContribution || 0)
    + (scriptResult.riskContribution || 0)
    + (yaraResult.matched.filter((m) => m.severity === 'critical').length * 25),
    100,
  );

  const mitreTechniques = mapToMitre({
    evasionIndicators: evasionResult.indicators,
    injectionResult,
    entropyResult,
    iocs,
    stringDecoded,
    scriptObfuscation: scriptResult.findings,
  });

  res.json({
    success: true,
    filename,
    sizeBytes: buf.length,
    hexMatches: hexResult.matches,
    entropyResult,
    evasionResult,
    injectionResult,
    iocs,
    stringDecoded,
    scriptResult,
    peResult,
    yaraResult,
    heuristicScore,
    aggregatedScore: totalScore,
    mitreTechniques,
  });
});

// ─── EML Email Scanner ────────────────────────────────────────────────────
router.post('/analyze/eml', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'Upload an .eml file.' });
  try {
    const parsed = parseEml(req.file.buffer);
    const attachmentReports = parsed.attachments.map((att) => {
      const hex = scanBufferForHexSignatures(att.buffer);
      const entropy = analyzeEntropy(att.buffer);
      const evasion = detectEvasion(att.buffer);
      const injection = detectSubbyteInjection(att.buffer);
      const score = computeHeuristicScore({ hexMatches: hex.matches, entropyResult: entropy, evasionResult: evasion, injectionResult: injection });
      return {
        filename: att.filename,
        contentType: att.contentType,
        size: att.size,
        hexMatches: hex.matches,
        entropy,
        evasion,
        injection,
        score,
      };
    });
    res.json({ success: true, headers: parsed.headers, summary: parsed.summary, attachmentReports });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── PDF Report Generation ────────────────────────────────────────────────
router.post('/report/pdf', async (req, res) => {
  const scanResult = req.body?.scanResult;
  if (!scanResult) return res.status(400).json({ success: false, message: 'Provide scanResult in body.' });
  try {
    const pdfBuffer = await buildScanReport(scanResult);
    const filename = `report_${(scanResult.filename || 'scan').replace(/[^\w.-]/g, '_')}_${Date.now()}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(pdfBuffer);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
