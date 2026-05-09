/**
 * Threat Intelligence Aggregator
 *
 * Agregă date din scan logs, IOCs detectate, alerte ransomware, baseline
 * anomalies, și honeypot triggers într-un dashboard unificat.
 */

const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, '../store/threat-intel.json');

function loadIntel() {
  try {
    if (!fs.existsSync(STORE_FILE)) {
      return {
        topHashes: {},
        topDomains: {},
        topIPs: {},
        topMitreTechniques: {},
        infectedFilesByDay: {},
        startedAt: new Date().toISOString(),
      };
    }
    return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch {
    return {
      topHashes: {},
      topDomains: {},
      topIPs: {},
      topMitreTechniques: {},
      infectedFilesByDay: {},
      startedAt: new Date().toISOString(),
    };
  }
}

function saveIntel(data) {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(data));
  } catch (err) {
    console.warn('[ThreatIntel] Could not persist:', err.message);
  }
}

function bumpCounter(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

/**
 * Înregistrează un scan în threat intel (topuri, IOCs, MITRE).
 */
function recordScan(scanResult) {
  if (!scanResult) return;

  const intel = loadIntel();
  const today = new Date().toISOString().slice(0, 10);

  if (scanResult.status === 'INFECTED' && scanResult.sha256) {
    bumpCounter(intel.topHashes, scanResult.sha256);
    intel.infectedFilesByDay[today] = (intel.infectedFilesByDay[today] || 0) + 1;
  }

  for (const url of scanResult.iocs?.urls || []) {
    try {
      const u = new URL(url);
      bumpCounter(intel.topDomains, u.hostname);
    } catch { /* skip invalid */ }
  }
  for (const d of scanResult.iocs?.domains || []) bumpCounter(intel.topDomains, d);
  for (const ip of scanResult.iocs?.ips || []) bumpCounter(intel.topIPs, ip);
  for (const tech of scanResult.mitreTechniques || []) {
    bumpCounter(intel.topMitreTechniques, tech.id);
    // per-day tracking for heat-map (keep last 30 days)
    if (!intel.mitreByDay) intel.mitreByDay = {};
    if (!intel.mitreByDay[today]) intel.mitreByDay[today] = {};
    bumpCounter(intel.mitreByDay[today], tech.id);
  }

  // Trim mitreByDay to last 30 days
  if (intel.mitreByDay) {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    for (const d of Object.keys(intel.mitreByDay)) {
      if (d < cutoff) delete intel.mitreByDay[d];
    }
  }

  saveIntel(intel);
}

function topN(obj, n = 10) {
  return Object.entries(obj)
    .sort(([, a], [, b]) => b - a)
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
}

function getIntelDashboard() {
  const intel = loadIntel();
  const today = new Date();
  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000).toISOString().slice(0, 10);
    last7Days.push({ date: d, infected: intel.infectedFilesByDay[d] || 0 });
  }

  return {
    startedAt: intel.startedAt,
    totalUniqueHashes: Object.keys(intel.topHashes).length,
    totalUniqueDomains: Object.keys(intel.topDomains).length,
    totalUniqueIPs: Object.keys(intel.topIPs).length,
    topHashes: topN(intel.topHashes, 10),
    topDomains: topN(intel.topDomains, 10),
    topIPs: topN(intel.topIPs, 10),
    topMitreTechniques: topN(intel.topMitreTechniques, 10),
    infectedTimeline: last7Days,
  };
}

function getMitreHeatmap() {
  const intel = loadIntel();
  const { getMitreMatrix, MITRE_TECHNIQUES } = require('./mitreMapping');
  const matrix = getMitreMatrix();
  const totals = intel.topMitreTechniques || {};
  const byDay  = intel.mitreByDay || {};

  // Build last-30-days array
  const days = [];
  for (let i = 29; i >= 0; i--) {
    days.push(new Date(Date.now() - i * 86400000).toISOString().slice(0, 10));
  }

  // Enrich matrix with hit counts
  const enriched = matrix.map((tactic) => ({
    ...tactic,
    techniques: tactic.techniques.map((tech) => ({
      ...tech,
      totalHits: totals[tech.id] || 0,
      dailyHits: days.map((d) => ({ date: d, count: (byDay[d]?.[tech.id] || 0) })),
    })),
  }));

  const maxHits = Math.max(1, ...Object.values(totals));

  return { tactics: enriched, days, maxHits };
}

function resetIntel() {
  saveIntel({
    topHashes: {},
    topDomains: {},
    topIPs: {},
    topMitreTechniques: {},
    infectedFilesByDay: {},
    startedAt: new Date().toISOString(),
  });
}

module.exports = { recordScan, getIntelDashboard, resetIntel };
