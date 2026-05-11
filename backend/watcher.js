const chokidar = require('chokidar');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const notifier = require('node-notifier');

const { scanBufferForHexSignatures } = require('./utils/hexSignatures');
const { analyzeEntropy } = require('./utils/entropyAnalysis');
const { detectEvasion } = require('./utils/evasionDetection');
const { detectSubbyteInjection } = require('./utils/subbyteInjection');
const { computeHeuristicScore } = require('./utils/heuristicScorer');
const { extractIOCs } = require('./utils/iocExtractor');
const { mapToMitre } = require('./utils/mitreMapping');
const { decodeStrings } = require('./utils/stringDecoder');
const { analyzeScript } = require('./utils/scriptDeobfuscator');
const { parsePE } = require('./utils/peParser');
const { runRules } = require('./utils/yaraEngine');
const { getRulesText } = require('./store/yaraStore');
const { isZip, scanArchive } = require('./utils/archiveScanner');
const { recordFileEvent, setAlertCallback } = require('./utils/ransomwareCanary');
const { checkCanaries } = require('./utils/honeypot');
const { recordScan } = require('./utils/threatIntel');
const { addActivityEntry } = require('./store/activityLog');
const { broadcast } = require('./utils/wsBroadcaster');

const homeDir = process.env.USERPROFILE || process.env.HOME || '';
const watchTargets = [
  path.join(homeDir, 'Desktop'),
  path.join(homeDir, 'Downloads'),
  path.join(homeDir, 'OneDrive', 'Desktop'),
  path.join(homeDir, 'OneDrive', 'Downloads'),
].filter((dir) => dir && fs.existsSync(dir));

const QUARANTINE_DIR = path.join(__dirname, 'quarantine');
if (!fs.existsSync(QUARANTINE_DIR)) fs.mkdirSync(QUARANTINE_DIR);
const REPO_ROOT = path.resolve(__dirname, '..');
const EICAR_MARKER = ['EICAR', 'STANDARD', 'ANTIVIRUS', 'TEST', 'FILE'].join('-');
const AUTO_QUARANTINE_THRESHOLD = Number(process.env.AUTO_QUARANTINE_THRESHOLD || 85);
const MAX_AUTO_SCAN_BYTES = 25 * 1024 * 1024; // 25 MB

const ignoredRoots = [QUARANTINE_DIR, REPO_ROOT].map((entry) => path.resolve(entry));

const shouldIgnorePath = (targetPath) => {
  const resolvedPath = path.resolve(targetPath);
  return ignoredRoots.some((entry) => resolvedPath === entry || resolvedPath.startsWith(`${entry}${path.sep}`));
};

setAlertCallback((alert) => {
  try {
    notifier.notify({
      title: '🛡️ Ransomware Alert',
      message: alert.detail,
      sound: true,
      wait: false,
      appID: 'UTM Containment Atlas',
    });
  } catch { /* ignore */ }

  addActivityEntry('ALERT', 'Ransomware', `Ransomware Indicator: ${alert.type}`, alert.detail);
  broadcast({ category: 'ransomware', severity: alert.severity, ...alert });
});

function notifyThreat(fileName, threatName) {
  try {
    notifier.notify({
      title: '🛡️ Sentinel Security Alert',
      message: `Threat detected: ${threatName}. ${fileName} moved to quarantine.`,
      sound: true,
      wait: false,
      appID: 'UTM Containment Atlas',
    });
  } catch { /* ignore */ }
}

function quarantine(filePath, threatName) {
  const fileName = path.basename(filePath);
  const destPath = path.join(QUARANTINE_DIR, `${Date.now()}_${fileName}.quarantine`);
  try {
    fs.renameSync(filePath, destPath);
  } catch {
    try {
      fs.copyFileSync(filePath, destPath);
      fs.unlinkSync(filePath);
    } catch (err) {
      console.warn(`[Watcher] Could not quarantine ${fileName}:`, err.message);
      return null;
    }
  }
  console.log(`[🔒] Quarantined: ${fileName} (${threatName})`);
  if (global.stats) {
    global.stats.threats_found++;
    global.stats.quarantined++;
  }
  return destPath;
}

async function scanFile(filePath) {
  const fileName = path.basename(filePath);
  if (fileName.startsWith('~') || fileName.endsWith('.tmp') || shouldIgnorePath(filePath)) return;

  // Înregistrează în detectorul de ransomware (mass-write detection)
  recordFileEvent('change', filePath);

  console.log(`[🔍] Scanning: ${fileName}`);
  if (global.stats) global.stats.files_scanned++;

  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_AUTO_SCAN_BYTES) {
      console.log(`[⏩] Skipping large file (${(stat.size / 1024 / 1024).toFixed(1)} MB): ${fileName}`);
      return;
    }

    const fileBuffer = fs.readFileSync(filePath);
    const fileContent = fileBuffer.toString('utf8');

    // EICAR fast-path
    if (fileContent.includes(EICAR_MARKER)) {
      notifyThreat(fileName, 'EICAR_Test_File');
      const dest = quarantine(filePath, 'EICAR_Test_File');
      addActivityEntry('ALERT', 'Protection', `Auto-Quarantined: ${fileName}`, 'EICAR test signature');
      broadcast({ category: 'auto_quarantine', severity: 'critical', filename: fileName, threat: 'EICAR_Test_File', quarantinePath: dest });
      return;
    }

    // Deep heuristic pipeline (full — identical to manual scan)
    const hexResult       = scanBufferForHexSignatures(fileBuffer);
    const entropyResult   = analyzeEntropy(fileBuffer);
    const evasionResult   = detectEvasion(fileBuffer);
    const injectionResult = detectSubbyteInjection(fileBuffer);
    const iocs            = extractIOCs(fileBuffer);
    const stringDecoded   = decodeStrings(fileBuffer);
    const scriptResult    = analyzeScript(fileBuffer, fileName);
    const peResult        = parsePE(fileBuffer);

    const heuristicScore = computeHeuristicScore({
      hexMatches: hexResult.matches,
      entropyResult,
      evasionResult,
      injectionResult,
      peResult,
    });

    // YARA rule matching
    const yaraResult   = runRules(fileBuffer, getRulesText());
    const yaraCritical = yaraResult.matched.filter((m) => m.severity === 'critical');
    const yaraWarning  = yaraResult.matched.filter((m) => m.severity === 'warning');
    const isPortableExecutable = Boolean(peResult?.isValidPE);
    const yaraScore = Math.min(
      yaraCritical.length * 35 + yaraWarning.length * 10,
      isPortableExecutable ? 45 : 60,
    );
    const supplementalScore = Math.min(
      (iocs.suspicionScore || 0)
      + (stringDecoded.riskContribution || 0)
      + (scriptResult.riskContribution || 0),
      isPortableExecutable ? 25 : 40,
    );

    heuristicScore.score = Math.min(
      100,
      heuristicScore.score
      + supplementalScore
      + yaraScore,
    );
    if (heuristicScore.score >= 85) heuristicScore.verdict = 'HIGH_RISK';
    else if (heuristicScore.score >= 55) heuristicScore.verdict = 'MEDIUM_RISK';
    else if (heuristicScore.score >= 15) heuristicScore.verdict = 'LOW_RISK';
    else heuristicScore.verdict = 'MINIMAL_RISK';

    const mitreTechniques = mapToMitre({
      evasionIndicators: evasionResult.indicators,
      injectionResult,
      entropyResult,
      iocs,
      stringDecoded: stringDecoded.findings,
      scriptObfuscation: scriptResult.findings,
    });

    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // Archive scanning — detect threats inside ZIPs
    let archiveThreat = null;
    if (isZip(fileBuffer)) {
      try {
        const entries = await scanArchive(fileBuffer, fileName, async (buf, name) => {
          const h = scanBufferForHexSignatures(buf);
          const e = analyzeEntropy(buf);
          const ev = detectEvasion(buf);
          const inj = detectSubbyteInjection(buf);
          const pe = parsePE(buf);
          const hs = computeHeuristicScore({ hexMatches: h.matches, entropyResult: e, evasionResult: ev, injectionResult: inj, peResult: pe });
          const yr = runRules(buf, getRulesText());
          const archiveYaraScore = Math.min(
            yr.matched.filter((m) => m.severity === 'critical').length * 35
            + yr.matched.filter((m) => m.severity === 'warning').length * 10,
            pe?.isValidPE ? 45 : 60,
          );
          hs.score = Math.min(100, hs.score + archiveYaraScore);
          return { filename: name, status: hs.score >= AUTO_QUARANTINE_THRESHOLD || yr.matched.some((m) => m.severity === 'critical') ? 'INFECTED' : 'CLEAN', score: hs.score };
        });
        const infected = entries.filter((e) => e.status === 'INFECTED');
        if (infected.length > 0) {
          archiveThreat = `Archive contains ${infected.length} infected entry(ies): ${infected.map((e) => e.filename).join(', ')}`;
        }
      } catch { /* non-fatal */ }
    }

    recordScan({
      filename: fileName,
      sha256,
      status: heuristicScore.score >= AUTO_QUARANTINE_THRESHOLD ? 'INFECTED' : 'CLEAN',
      iocs,
      mitreTechniques,
    });

    const criticalHex = hexResult.matches.filter((m) => m.severity === 'critical');
    const eicarHexMatch = criticalHex.find((match) => match.name === 'EICAR_Hex_Signature');
    const shouldQuarantine = eicarHexMatch
      || yaraCritical.length > 0
      || archiveThreat !== null
      || heuristicScore.score >= AUTO_QUARANTINE_THRESHOLD;

    if (shouldQuarantine) {
      const reason = yaraCritical.length > 0
        ? `YARA: ${yaraCritical.map((m) => m.name).join(', ')}`
        : archiveThreat
          ? archiveThreat
          : eicarHexMatch
            ? `Critical hex: ${eicarHexMatch.name}`
            : `Heuristic score ${heuristicScore.score}/100 (${heuristicScore.verdict})`;
      notifyThreat(fileName, reason);
      const dest = quarantine(filePath, reason);
      addActivityEntry('ALERT', 'Protection', `Auto-Quarantined: ${fileName}`, reason);
      broadcast({
        category: 'auto_quarantine',
        severity: 'critical',
        filename: fileName,
        sha256,
        threat: reason,
        score: heuristicScore.score,
        verdict: heuristicScore.verdict,
        mitre: mitreTechniques.slice(0, 5).map((t) => t.id),
        quarantinePath: dest,
      });
    } else if (heuristicScore.score >= 55 || criticalHex.length > 0) {
      console.log(`[⚠️] Suspicious: ${fileName} (score ${heuristicScore.score})`);
      addActivityEntry('WARNING', 'Protection', `Suspicious File: ${fileName}`, `Heuristic ${heuristicScore.score}/100`);
      broadcast({
        category: 'suspicious_file',
        severity: 'warning',
        filename: fileName,
        score: heuristicScore.score,
        verdict: heuristicScore.verdict,
      });
    } else {
      console.log(`[✅] Clean: ${fileName}`);
    }
  } catch (err) {
    if (err.code !== 'EBUSY' && err.code !== 'ENOENT') {
      console.error('[❌] Watcher error:', err.message);
    }
  }
}

// Periodic honeypot check (la fiecare 30s)
setInterval(() => {
  try {
    const triggered = checkCanaries();
    for (const ev of triggered) {
      addActivityEntry('ALERT', 'Honeypot', `Canary Triggered: ${ev.name}`, ev.message);
      broadcast({ category: 'honeypot', severity: ev.severity, ...ev });
      try {
        notifier.notify({
          title: '🍯 Honeypot Triggered',
          message: ev.message,
          sound: true,
          wait: false,
          appID: 'UTM Containment Atlas',
        });
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
}, 30000);

const watcher = chokidar.watch(watchTargets, {
  persistent: true,
  ignoreInitial: true,
  ignored: (targetPath) => shouldIgnorePath(targetPath),
  awaitWriteFinish: { stabilityThreshold: 1000, pollInterval: 100 },
});

watcher
  .on('add', (p) => scanFile(p))
  .on('change', (p) => scanFile(p))
  .on('unlink', (p) => recordFileEvent('unlink', p));

console.log(`[+] Watcher monitoring ${watchTargets.length} directories.`);

module.exports = watcher;
