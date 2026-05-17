/**
 * PDF Forensic Report Generator
 *
 * Generează rapoarte PDF profesionale pentru rezultatele unui scan sau
 * pentru threat intelligence. Folosește pdfkit (deja instalat).
 */

const PDFDocument = require('pdfkit');
const { PassThrough } = require('stream');

const COLORS = {
  primary: '#3aa6ff',
  text: '#1a2030',
  muted: '#666',
  critical: '#d93b3b',
  warning: '#e8a33d',
  ok: '#3cba84',
  panel: '#f4f7fb',
};

function severityColor(s) {
  const v = String(s || '').toLowerCase();
  if (v === 'critical' || v === 'high_risk' || v === 'infected') return COLORS.critical;
  if (v === 'warning' || v === 'medium_risk' || v === 'review') return COLORS.warning;
  return COLORS.ok;
}

function header(doc, title, subtitle) {
  doc.rect(0, 0, doc.page.width, 80).fill(COLORS.text);
  doc.fillColor('#ffffff').fontSize(18).font('Helvetica-Bold').text('Argus', 40, 25);
  doc.fillColor(COLORS.primary).fontSize(10).text('FORENSIC ANALYSIS REPORT', 40, 50);
  doc.fillColor('#ffffff').fontSize(9).text(new Date().toISOString(), 40, 62);
  doc.fillColor(COLORS.text);
  doc.moveDown(4);
  doc.font('Helvetica-Bold').fontSize(20).fillColor(COLORS.text).text(title, 40);
  if (subtitle) doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted).text(subtitle, 40);
  doc.moveDown(1);
}

function sectionTitle(doc, text) {
  doc.moveDown(0.7);
  doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.primary).text(text, 40);
  doc.moveTo(40, doc.y + 2).lineTo(doc.page.width - 40, doc.y + 2).strokeColor(COLORS.primary).lineWidth(1).stroke();
  doc.moveDown(0.5);
  doc.fillColor(COLORS.text).font('Helvetica').fontSize(10);
}

function keyVal(doc, key, value) {
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted).text(`${key}: `, { continued: true });
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.text).text(String(value));
}

function badge(doc, text, color) {
  const w = doc.widthOfString(text) + 10;
  const x = doc.x;
  const y = doc.y;
  doc.rect(x, y, w, 14).fill(color);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(9).text(text, x + 5, y + 3);
  doc.fillColor(COLORS.text).font('Helvetica').fontSize(10);
  doc.moveDown(0.6);
}

function bullet(doc, text) {
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.text).text(`  • ${text}`, 50);
}

/**
 * Generează un raport PDF dintr-un rezultat de scan și returnează un Buffer.
 *
 * @param {Object} scanResult - obiectul rezultat din scanFile()
 * @returns {Promise<Buffer>}
 */
function buildScanReport(scanResult) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 40 });
    const stream = new PassThrough();
    const chunks = [];

    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
    doc.pipe(stream);

    header(doc, scanResult.filename || 'Unknown File', `SHA-256: ${scanResult.sha256 || 'n/a'}`);

    // Status badge
    badge(doc, scanResult.status || 'UNKNOWN', severityColor(scanResult.status));

    // Overview
    sectionTitle(doc, 'Overview');
    keyVal(doc, 'File Size', `${(scanResult.sizeBytes || 0).toLocaleString()} bytes`);
    keyVal(doc, 'Detection Method', scanResult.method || 'n/a');
    keyVal(doc, 'Signature', scanResult.signature || '—');
    keyVal(doc, 'Verdict Message', scanResult.message || '—');

    // Heuristic Score
    const ds = scanResult.deepAnalysis;
    if (ds?.heuristicScore) {
      sectionTitle(doc, 'Heuristic Risk Score');
      keyVal(doc, 'Score', `${ds.heuristicScore.score}/100`);
      doc.moveDown(0.2);
      badge(doc, ds.heuristicScore.verdict, severityColor(ds.heuristicScore.verdict));
      if (ds.heuristicScore.reasons?.length) {
        doc.moveDown(0.3);
        doc.font('Helvetica-Bold').fontSize(10).text('Reasons:', 40);
        for (const r of ds.heuristicScore.reasons) bullet(doc, r);
      }
    }

    // Evasion
    if (ds?.evasionResult?.indicators?.length) {
      sectionTitle(doc, 'Evasion Indicators');
      for (const ind of ds.evasionResult.indicators) {
        doc.font('Helvetica-Bold').fontSize(10).fillColor(severityColor(ind.severity))
          .text(`[${ind.severity.toUpperCase()}] ${ind.category}`, 40);
        doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(ind.description, 50);
        doc.moveDown(0.3);
      }
    }

    // Sub-byte injection
    if (ds?.injectionResult) {
      const inj = ds.injectionResult;
      const total = (inj.codeCaves?.length || 0) + (inj.appendedPayloads?.length || 0) + (inj.polyglot?.length || 0);
      if (total > 0) {
        sectionTitle(doc, 'Sub-byte Injection Indicators');
        for (const c of inj.codeCaves.slice(0, 5)) bullet(doc, c.description);
        for (const a of inj.appendedPayloads) bullet(doc, a.description);
        for (const p of inj.polyglot) bullet(doc, p.description);
      }
    }

    // Hex matches
    if (scanResult.hexMatches?.length) {
      sectionTitle(doc, 'Hex Signature Matches');
      for (const m of scanResult.hexMatches) {
        doc.font('Helvetica-Bold').fontSize(10).fillColor(severityColor(m.severity))
          .text(`[${m.severity}] ${m.name} @ ${m.offsetHex}`, 40);
        doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(m.description, 50);
        doc.moveDown(0.2);
      }
    }

    // Providers
    if (scanResult.providers?.length) {
      sectionTitle(doc, 'Provider Verdicts');
      for (const p of scanResult.providers) {
        keyVal(doc, p.name, `${p.verdict || p.status || 'n/a'} — ${p.message || ''}`);
      }
    }

    // Footer
    doc.fontSize(8).fillColor(COLORS.muted).text(
      'Report generated by Argus - Heuristic Multi-Layer Analysis Platform',
      40,
      doc.page.height - 50,
      { align: 'center', width: doc.page.width - 80 },
    );

    doc.end();
  });
}

/**
 * Generează un raport PDF de securitate al platformei și returnează un Buffer.
 *
 * @param {Object} status  - răspunsul complet de la GET /api/status
 * @returns {Promise<Buffer>}
 */
function buildSecurityReport(status) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 40 });
    const stream = new PassThrough();
    const chunks = [];

    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
    doc.pipe(stream);

    /* ── Header ── */
    header(doc, 'Security Status Report', `Generated: ${new Date().toUTCString()}`);

    /* ── System Overview ── */
    sectionTitle(doc, 'System Overview');
    keyVal(doc, 'Status',    status.status   || 'Unknown');
    keyVal(doc, 'Platform',  status.platform || 'Unknown');
    keyVal(doc, 'OS',        status.os        || 'Unknown');
    keyVal(doc, 'Uptime',    status.uptime    || 'Unknown');
    keyVal(doc, 'CPU',       `${status.cpu_percent ?? '—'}%`);
    keyVal(doc, 'RAM',       `${status.ram_percent ?? '—'}%`);
    keyVal(doc, 'Firewall',  status.firewall  || 'Unknown');
    keyVal(doc, 'Antivirus', status.antivirus || 'Unknown');

    /* ── Firewall Rules ── */
    sectionTitle(doc, 'Firewall Rules');
    const rules = status.contentFilter ? [] : [];
    const fw = status.controls || {};
    keyVal(doc, 'Firewall Enabled', fw.firewallEnabled ? 'Yes' : 'No');
    keyVal(doc, 'Total Rules',  String(status.rules_loaded  ?? '—'));
    keyVal(doc, 'Active Rules', String(status.rules_active  ?? '—'));
    keyVal(doc, 'Block Rules',  String(status.blocked_today ?? '—'));
    keyVal(doc, 'Allow Rules',  String(status.allowed_today ?? '—'));

    /* ── Content Filter ── */
    sectionTitle(doc, 'Content Filter');
    const cf = status.contentFilter;
    if (cf) {
      keyVal(doc, 'Enabled',         cf.policy?.enabled ? 'Yes' : 'No');
      keyVal(doc, 'Blocked Domains',  String(cf.runtime?.appliedDomainCount ?? 0));
      keyVal(doc, 'Active Categories', (cf.runtime?.enabledCategoryIds || []).join(', ') || 'None');
      keyVal(doc, 'Last Applied',      cf.runtime?.lastApplyAt || 'Never');
      keyVal(doc, 'Last Synced',       cf.runtime?.lastSyncedAt || 'Never');

      const cats = (cf.categories || []).filter((c) => c.enabled);
      if (cats.length > 0) {
        doc.moveDown(0.4);
        doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted).text('Category breakdown:');
        doc.moveDown(0.2);
        for (const cat of cats) {
          bullet(doc, `${cat.label}: ${(cat.domainCount || 0).toLocaleString()} domains`);
        }
      }
    } else {
      bullet(doc, 'No content filter data available.');
    }

    /* ── Antivirus ── */
    sectionTitle(doc, 'Antivirus & Threat Detection');
    keyVal(doc, 'Protection',    status.antivirus      || 'Unknown');
    keyVal(doc, 'Files Scanned', String(status.files_scanned ?? 0));
    keyVal(doc, 'Threats Found', String(status.threats_found ?? 0));
    keyVal(doc, 'Quarantined',   String(status.quarantined   ?? 0));
    keyVal(doc, 'Alerts Today',  String(status.alerts_today  ?? 0));
    keyVal(doc, 'High Severity', String(status.high_severity ?? 0));

    /* ── Sandbox ── */
    if (status.hybrid_analysis_available) {
      sectionTitle(doc, 'Sandbox Analysis');
      keyVal(doc, 'Jobs Pending',   String(status.sandbox_jobs_pending   ?? 0));
      keyVal(doc, 'Jobs Completed', String(status.sandbox_jobs_completed ?? 0));
      keyVal(doc, 'Findings',       String(status.hybrid_analysis_findings ?? 0));
    }

    /* ── Footer ── */
    doc.fontSize(8).fillColor(COLORS.muted).text(
      'Report generated by Argus - Unified Threat Management Platform',
      40,
      doc.page.height - 50,
      { align: 'center', width: doc.page.width - 80 },
    );

    doc.end();
  });
}

module.exports = { buildScanReport, buildSecurityReport };
