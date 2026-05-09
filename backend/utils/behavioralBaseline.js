/**
 * Behavioral Baseline Anomaly Detection
 *
 * Învață în primele 7 zile pattern-ul "normal" al sistemului:
 *  - CPU/RAM avg și max per oră
 *  - Lista de procese văzute frecvent
 *  - Conexiuni de rețea tipice (port + protocol)
 *
 * După perioada de învățare, alertează la deviații semnificative
 * (ex: spike CPU 90% la 3 AM, proces nou care nu apare în baseline,
 * conexiuni la porturi nemaivăzute).
 *
 * Statistică simplă (z-score), fără ML.
 */

const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, '../store/baseline.json');
const LEARNING_PERIOD_MS = 7 * 24 * 60 * 60 * 1000; // 7 zile
const Z_SCORE_THRESHOLD = 2.5; // > 2.5 σ = anomalie

function loadBaseline() {
  try {
    if (!fs.existsSync(STORE_FILE)) {
      return {
        startedAt: Date.now(),
        samples: 0,
        cpuByHour: {},
        ramByHour: {},
        knownProcesses: {},
        knownPorts: {},
        anomalies: [],
      };
    }
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    return {
      startedAt: Date.now(),
      samples: 0,
      cpuByHour: {},
      ramByHour: {},
      knownProcesses: {},
      knownPorts: {},
      anomalies: [],
    };
  }
}

function saveBaseline(data) {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(data));
  } catch (err) {
    console.warn('[Baseline] Could not persist:', err.message);
  }
}

function updateRunningStats(stats, value) {
  if (!stats) stats = { count: 0, mean: 0, m2: 0 };
  stats.count++;
  const delta = value - stats.mean;
  stats.mean += delta / stats.count;
  const delta2 = value - stats.mean;
  stats.m2 += delta * delta2;
  return stats;
}

function getStdDev(stats) {
  if (!stats || stats.count < 2) return 0;
  return Math.sqrt(stats.m2 / (stats.count - 1));
}

function isLearning(baseline) {
  return Date.now() - baseline.startedAt < LEARNING_PERIOD_MS;
}

/**
 * Înregistrează un sample de telemetrie. Returnează lista de anomalii detectate.
 *
 * @param {Object} sample
 * @param {number} sample.cpuPercent
 * @param {number} sample.ramPercent
 * @param {Array<string>} [sample.processes]
 * @param {Array<{port:number, proto:string}>} [sample.connections]
 */
function recordSample(sample) {
  const baseline = loadBaseline();
  baseline.samples++;
  const hour = new Date().getHours();

  baseline.cpuByHour[hour] = updateRunningStats(baseline.cpuByHour[hour], sample.cpuPercent || 0);
  baseline.ramByHour[hour] = updateRunningStats(baseline.ramByHour[hour], sample.ramPercent || 0);

  const learning = isLearning(baseline);
  const anomalies = [];

  // Procese
  for (const proc of sample.processes || []) {
    if (!baseline.knownProcesses[proc]) {
      baseline.knownProcesses[proc] = { firstSeen: Date.now(), occurrences: 0 };
      if (!learning) {
        anomalies.push({
          type: 'new_process',
          severity: 'warning',
          detail: `Proces nou observat: ${proc}`,
          at: new Date().toISOString(),
        });
      }
    }
    baseline.knownProcesses[proc].occurrences++;
    baseline.knownProcesses[proc].lastSeen = Date.now();
  }

  // Porturi/conexiuni
  for (const conn of sample.connections || []) {
    const key = `${conn.proto || 'tcp'}:${conn.port}`;
    if (!baseline.knownPorts[key]) {
      baseline.knownPorts[key] = { firstSeen: Date.now(), occurrences: 0 };
      if (!learning && conn.port > 1024 && conn.port !== 443 && conn.port !== 80) {
        anomalies.push({
          type: 'new_connection',
          severity: 'warning',
          detail: `Conexiune nouă pe ${key}`,
          at: new Date().toISOString(),
        });
      }
    }
    baseline.knownPorts[key].occurrences++;
  }

  // CPU spike — z-score
  if (!learning) {
    const cpuStats = baseline.cpuByHour[hour];
    if (cpuStats && cpuStats.count >= 10) {
      const std = getStdDev(cpuStats);
      const z = std > 0 ? (sample.cpuPercent - cpuStats.mean) / std : 0;
      if (z > Z_SCORE_THRESHOLD && sample.cpuPercent > 70) {
        anomalies.push({
          type: 'cpu_spike',
          severity: 'critical',
          detail: `CPU ${sample.cpuPercent.toFixed(1)}% la ora ${hour}:00 — z-score ${z.toFixed(2)} (medie ${cpuStats.mean.toFixed(1)}±${std.toFixed(1)})`,
          at: new Date().toISOString(),
        });
      }
    }

    const ramStats = baseline.ramByHour[hour];
    if (ramStats && ramStats.count >= 10) {
      const std = getStdDev(ramStats);
      const z = std > 0 ? (sample.ramPercent - ramStats.mean) / std : 0;
      if (z > Z_SCORE_THRESHOLD && sample.ramPercent > 80) {
        anomalies.push({
          type: 'ram_spike',
          severity: 'warning',
          detail: `RAM ${sample.ramPercent.toFixed(1)}% la ora ${hour}:00 — z-score ${z.toFixed(2)}`,
          at: new Date().toISOString(),
        });
      }
    }
  }

  if (anomalies.length > 0) {
    baseline.anomalies = [...anomalies, ...baseline.anomalies].slice(0, 200);
  }

  saveBaseline(baseline);
  return { learning, anomalies, daysSinceStart: Math.floor((Date.now() - baseline.startedAt) / 86400000) };
}

function getBaselineSummary() {
  const baseline = loadBaseline();
  const learning = isLearning(baseline);
  const cpuMeans = Object.entries(baseline.cpuByHour).map(([h, s]) => ({ hour: parseInt(h, 10), mean: s.mean.toFixed(1), std: getStdDev(s).toFixed(1), count: s.count }));
  return {
    learning,
    daysSinceStart: Math.floor((Date.now() - baseline.startedAt) / 86400000),
    samples: baseline.samples,
    knownProcessCount: Object.keys(baseline.knownProcesses).length,
    knownPortCount: Object.keys(baseline.knownPorts).length,
    cpuByHour: cpuMeans,
    recentAnomalies: baseline.anomalies.slice(0, 30),
  };
}

function resetBaseline() {
  saveBaseline({
    startedAt: Date.now(),
    samples: 0,
    cpuByHour: {},
    ramByHour: {},
    knownProcesses: {},
    knownPorts: {},
    anomalies: [],
  });
}

module.exports = { recordSample, getBaselineSummary, resetBaseline };
