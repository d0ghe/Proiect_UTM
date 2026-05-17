/* eslint-disable react-refresh/only-export-components */
/**
 * Intelligence Pages — pagini noi pentru:
 *  - MITRE ATT&CK Matrix
 *  - Threat Intelligence Dashboard
 *  - Honeypots
 *  - YARA Rules Editor
 *  - Live Alerts (WebSocket)
 */

import { useEffect, useState } from 'react';

const PANEL_HEADER = (kicker, title) => (
  <div className="panel-card__header">
    <div>
      <p className="panel-kicker">{kicker}</p>
      <h3>{title}</h3>
    </div>
  </div>
);

// MITRE ATT&CK source helpers
function buildTechniqueMeta(matrix = []) {
  const meta = {};
  for (const tactic of matrix || []) {
    for (const technique of tactic.techniques || []) {
      meta[technique.id] = {
        id: technique.id,
        name: technique.name,
        tactic: tactic.name,
        tacticId: tactic.id,
      };
    }
  }
  return meta;
}

function buildTechniqueSourceRows(memoryScan, techniqueMeta) {
  const rows = [];
  const processes = Array.isArray(memoryScan?.processes) ? memoryScan.processes : [];

  for (const proc of processes) {
    for (const technique of proc.mitreTechniques || []) {
      const meta = techniqueMeta[technique.id] || technique;
      const services = Array.isArray(technique.source?.services)
        ? technique.source.services
        : Array.isArray(proc.services) ? proc.services : [];
      const serviceLabel = services
        .map((service) => {
          const displayName = service.displayName || service.DisplayName || '';
          const name = service.name || service.Name || '';
          if (displayName && name && displayName !== name) return `${displayName} (${name})`;
          return displayName || name;
        })
        .filter(Boolean)
        .join(', ');
      rows.push({
        id: `${technique.id}-${proc.pid}-${rows.length}`,
        techniqueId: technique.id,
        techniqueName: meta.name || technique.name,
        tactic: meta.tactic || technique.tactic,
        application: technique.source?.application || proc.name || 'Unknown process',
        serviceLabel,
        pid: technique.source?.pid || proc.pid,
        path: technique.source?.path || proc.path || '',
        parentName: technique.source?.parentName || proc.parentName || '',
        threat: technique.source?.threat || proc.threat || '',
        evidence: (technique.evidence || []).filter(Boolean),
      });
    }
  }

  const severityRank = { CRITICAL: 0, SUSPICIOUS: 1, CLEAN: 2 };
  return rows.sort((left, right) =>
    (severityRank[left.threat] ?? 3) - (severityRank[right.threat] ?? 3)
    || left.techniqueId.localeCompare(right.techniqueId)
  );
}

// ─── MITRE ATT&CK Matrix Page ───────────────────────────────────────────────
export function MitrePage({ matrix, intel, memoryScan, loading, onRefresh }) {
  const techniqueMeta = buildTechniqueMeta(matrix || []);
  const sourceRows = buildTechniqueSourceRows(memoryScan, techniqueMeta);
  const sourceCounts = sourceRows.reduce((counts, row) => {
    counts[row.techniqueId] = (counts[row.techniqueId] || 0) + 1;
    return counts;
  }, {});
  const intelCounts = (intel?.topMitreTechniques || []).reduce((counts, item) => {
    counts[item.key] = item.count;
    return counts;
  }, {});
  const counts = { ...sourceCounts };
  Object.entries(intelCounts).forEach(([id, count]) => {
    counts[id] = (counts[id] || 0) + count;
  });
  const tactics = (matrix || []).map((t) => ({
    ...t,
    techniques: t.techniques.map((tech) => ({ ...tech, totalHits: counts[tech.id] || 0 })),
  }));
  const totalHits = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const activeTech = tactics.flatMap((t) => t.techniques).filter((t) => (t.totalHits || 0) > 0).length;
  const triggeringApps = new Set(sourceRows.map((row) => `${row.application}:${row.pid}`)).size;

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Argus / MITRE ATT&CK</p>
          <h1 className="page-title">ATT&CK Matrix</h1>
          <p className="page-subtitle">Techniques observed by Argus, with the application or service that triggered each signal.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">Refresh</button>
        </div>
      </div>

      {/* Summary row */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        {[
          { label: 'Techniques Triggered', value: activeTech, color: '#ff453a' },
          { label: 'Total Detections', value: totalHits, color: '#f5a623' },
          { label: 'Tactics Covered', value: tactics.filter((t) => t.techniques.some((te) => te.totalHits > 0)).length, color: '#34c759' },
          { label: 'Triggering Apps', value: triggeringApps, color: '#64d2ff' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ flex: '1 1 160px', padding: '0.85rem 1.1rem', background: '#141414', border: '1px solid #2a2a2a', borderRadius: '10px' }}>
            <div style={{ fontSize: '0.75rem', color: '#636366', marginBottom: '0.3rem' }}>{label}</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color }}>{value}</div>
          </div>
        ))}
      </div>

      {loading ? <div className="empty-state">Loading MITRE data...</div> : null}

      <section className="panel-card page-section-gap">
        {PANEL_HEADER('Source Attribution', 'Triggering Applications / Services')}
        {sourceRows.length === 0 ? (
          <div className="empty-state">
            No application-level MITRE triggers yet. Run a Memory Scan to attach techniques to running processes.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Application / Service</th>
                  <th>PID</th>
                  <th>Parent</th>
                  <th>Evidence</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {sourceRows.slice(0, 80).map((row) => (
                  <tr key={row.id}>
                    <td>
                      <strong>{row.techniqueId}</strong>
                      <br />
                      <span style={{ color: '#888' }}>{row.techniqueName}</span>
                    </td>
                    <td>
                      <strong>{row.application}</strong>
                      {row.serviceLabel ? <div style={{ color: '#8ecbff', fontSize: '0.75rem', marginTop: 2 }}>Service: {row.serviceLabel}</div> : null}
                      {row.path ? <div style={{ color: '#666', fontSize: '0.75rem', marginTop: 2 }}>{row.path}</div> : null}
                    </td>
                    <td>{row.pid || '-'}</td>
                    <td>{row.parentName || '-'}</td>
                    <td>{row.evidence[0] || '-'}</td>
                    <td>
                      <span className={`severity-pill severity-pill--${row.threat === 'CRITICAL' ? 'critical' : 'warning'}`}>
                        {row.threat || 'detected'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel-card">
        {PANEL_HEADER('Enterprise Matrix', 'Observed Techniques')}
        <div className="mitre-matrix">
          {tactics.map((tactic) => (
            <div className="mitre-tactic" key={tactic.id}>
              <h4 className="mitre-tactic__title">{tactic.name}</h4>
              <p className="mitre-tactic__id">{tactic.id}</p>
              <div className="mitre-tactic__list">
                {tactic.techniques.map((tech) => (
                  <div key={tech.id} className={`mitre-technique ${tech.totalHits > 0 ? 'mitre-technique--hit' : ''}`} title={`${tech.name} — ${tech.totalHits || 0} hit(s)`}>
                    <strong>{tech.id}</strong>
                    <span>{tech.name}</span>
                    {tech.totalHits > 0 && <small style={{ color: '#ff453a', fontWeight: 700 }}>{tech.totalHits}×</small>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// ─── Memory Scan Page ────────────────────────────────────────────────────────
export function MemoryScanPage({ data, loading, onScan }) {
  const result  = data?.lastScan;
  const summary = result?.summary;
  const [showAll, setShowAll] = useState(false);

  const threatColor = (t) => t === 'CRITICAL' ? '#ff453a' : t === 'SUSPICIOUS' ? '#f5a623' : '#34c759';
  const findingColor = (severity) => severity === 'critical' ? '#ff453a' : severity === 'warning' ? '#f5a623' : '#64d2ff';

  const allProcs    = result?.processes || [];
  const visibleProcs = showAll ? allProcs : allProcs.filter((p) => p.threat !== 'CLEAN');

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Argus / Memory</p>
          <h1 className="page-title">Live Process Memory Scanner</h1>
          <p className="page-subtitle">Analyzes all running processes: suspicious paths, argument obfuscation, masquerading, and abnormal parent-child chains.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {summary && (
            <>
              <button
                className={`control-btn${showAll ? '' : ' control-btn--ghost'}`}
                onClick={() => setShowAll(true)}
                type="button"
              >
                All ({summary.total})
              </button>
              <button
                className={`control-btn${!showAll ? '' : ' control-btn--ghost'}`}
                onClick={() => setShowAll(false)}
                type="button"
                style={!showAll ? { borderColor: '#ff453a', color: '#ff453a', background: 'rgba(255,69,58,0.12)' } : {}}
              >
                Threats ({summary.critical + summary.suspicious})
              </button>
            </>
          )}
          <button className="control-btn" onClick={onScan} disabled={loading} type="button" style={{ background: '#1c4532', borderColor: '#34c759', color: '#34c759' }}>
            {loading ? 'Scanning…' : 'Scan Now'}
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#636366', background: '#141414', borderRadius: 10, marginBottom: '1.25rem', border: '1px solid #2a2a2a' }}>
          Enumerating processes via WMI… This takes 10-20 seconds.
        </div>
      )}

      {summary && !loading && (
        <>
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
            {[
              { label: 'Total Processes', value: summary.total, color: '#e8e8e8' },
              { label: 'Critical', value: summary.critical, color: '#ff453a' },
              { label: 'Suspicious', value: summary.suspicious, color: '#f5a623' },
              { label: 'Clean', value: summary.clean, color: '#34c759' },
              { label: 'Info Only', value: summary.infoOnly || 0, color: '#64d2ff' },
              { label: 'Scan Time', value: `${summary.scanTimeMs}ms`, color: '#636366' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ flex: '1 1 120px', padding: '0.85rem 1rem', background: '#141414', border: '1px solid #2a2a2a', borderRadius: 10 }}>
                <div style={{ fontSize: '0.72rem', color: '#636366', marginBottom: '0.3rem' }}>{label}</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 700, color }}>{value}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {visibleProcs.map((proc) => (
              <div
                key={proc.pid}
                style={{
                  padding: '0.9rem 1.1rem',
                  background: '#141414',
                  border: `1px solid ${proc.threat === 'CLEAN' ? '#2a2a2a' : `${threatColor(proc.threat)}22`}`,
                  borderLeft: `3px solid ${threatColor(proc.threat)}`,
                  borderRadius: 8,
                  opacity: proc.threat === 'CLEAN' ? 0.65 : 1,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: proc.findings.length ? '0.4rem' : 0 }}>
                  <span style={{
                    fontSize: '0.7rem', fontWeight: 700, padding: '0.15rem 0.5rem', borderRadius: 4,
                    background: `${threatColor(proc.threat)}22`, color: threatColor(proc.threat),
                    border: `1px solid ${threatColor(proc.threat)}`,
                  }}>
                    {proc.threat}
                  </span>
                  <strong style={{ fontSize: '0.9rem' }}>{proc.name}</strong>
                  <span style={{ fontSize: '0.75rem', color: '#636366' }}>PID {proc.pid}</span>
                  {proc.memMB > 0 && <span style={{ fontSize: '0.72rem', color: '#555' }}>{proc.memMB} MB</span>}
                  {proc.isKnownGood && <span style={{ fontSize: '0.68rem', color: '#34c759', background: 'rgba(52,199,89,0.1)', border: '1px solid rgba(52,199,89,0.3)', padding: '0.1rem 0.4rem', borderRadius: 4 }}>known-good</span>}
                  {proc.score > 0 && <span style={{ fontSize: '0.72rem', color: '#636366', marginLeft: 'auto' }}>Score: {proc.score}</span>}
                </div>
                {proc.path && <div style={{ fontSize: '0.72rem', color: '#666', fontFamily: 'monospace', marginBottom: proc.findings.length ? '0.4rem' : 0 }}>{proc.path}</div>}
                {proc.findings.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                    {proc.findings.map((f, i) => {
                      const color = findingColor(f.severity);
                      return (
                        <span
                          key={i}
                          style={{
                            fontSize: '0.68rem', padding: '0.1rem 0.45rem', borderRadius: 4,
                            background: `${color}22`,
                            color,
                            border: `1px solid ${color}44`,
                          }}
                          title={f.detail}
                        >
                          {f.type}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
            {!showAll && summary.critical === 0 && summary.suspicious === 0 && (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#34c759', background: '#141414', borderRadius: 10, border: '1px solid #34c75922' }}>
                ✓ No suspicious processes detected across {summary.total} running processes.
              </div>
            )}
          </div>

          <div style={{ marginTop: '1rem', fontSize: '0.75rem', color: '#444', textAlign: 'right' }}>
            Showing {visibleProcs.length} of {summary.total} processes · Scanned at {new Date(summary.scannedAt).toLocaleString()}
          </div>
        </>
      )}

      {!summary && !loading && (
        <div style={{ padding: '3rem', textAlign: 'center', color: '#636366', background: '#141414', borderRadius: 10, border: '1px solid #2a2a2a' }}>
          Click "Scan Now" to analyze all running processes for malicious indicators.
        </div>
      )}
    </div>
  );
}

// ─── Threat Intel Dashboard Page ────────────────────────────────────────────
export function ThreatIntelPage({ intel, loading, onRefresh, onReset }) {
  const data = intel || {};
  const maxInfected = Math.max(1, ...(data.infectedTimeline || []).map((d) => d.infected));

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Argus / Threat Intelligence</p>
          <h1 className="page-title">Threat Intelligence Dashboard</h1>
          <p className="page-subtitle">Aggregated global statistics: top hashes, domains, IPs, and MITRE techniques.</p>
        </div>
        <div className="header-meta">
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">Refresh</button>
          <button className="control-btn control-btn--amber" onClick={onReset} type="button">Reset Intel</button>
        </div>
      </div>

      {loading ? <div className="empty-state">Loading...</div> : null}

      <div className="panel-grid panel-grid--stats">
        <div className="stat-card accent-blue"><p className="stat-label">Unique Hashes</p><p className="stat-value">{data.totalUniqueHashes || 0}</p></div>
        <div className="stat-card accent-amber"><p className="stat-label">Unique Domains</p><p className="stat-value">{data.totalUniqueDomains || 0}</p></div>
        <div className="stat-card accent-red"><p className="stat-label">Unique IPs</p><p className="stat-value">{data.totalUniqueIPs || 0}</p></div>
        <div className="stat-card accent-green"><p className="stat-label">Tracked Since</p><p className="stat-value" style={{ fontSize: '0.95rem' }}>{data.startedAt ? new Date(data.startedAt).toLocaleDateString() : '—'}</p></div>
      </div>

      <section className="panel-card">
        {PANEL_HEADER('7-Day Trend', 'Detected Threats Timeline')}
        <div className="intel-timeline">
          {(data.infectedTimeline || []).map((d) => (
            <div className="intel-bar" key={d.date} title={`${d.date}: ${d.infected}`}>
              <div className="intel-bar__fill" style={{ height: `${(d.infected / maxInfected) * 100}%` }} />
              <span className="intel-bar__label">{d.date.slice(5)}</span>
              <span className="intel-bar__value">{d.infected}</span>
            </div>
          ))}
        </div>
      </section>

      <div className="panel-grid panel-grid--split">
        <section className="panel-card">
          {PANEL_HEADER('Top 10', 'Hash Indicators')}
          <ol className="intel-list">
            {(data.topHashes || []).map((h) => (
              <li key={h.key}><code title={h.key}>{h.key.slice(0, 16)}...</code> <span>{h.count}×</span></li>
            ))}
            {(data.topHashes || []).length === 0 ? <p className="empty-state">No hashes recorded yet.</p> : null}
          </ol>
        </section>
        <section className="panel-card">
          {PANEL_HEADER('Top 10', 'Domain Indicators')}
          <ol className="intel-list">
            {(data.topDomains || []).map((d) => (
              <li key={d.key}><code>{d.key}</code> <span>{d.count}×</span></li>
            ))}
            {(data.topDomains || []).length === 0 ? <p className="empty-state">No domains.</p> : null}
          </ol>
        </section>
        <section className="panel-card">
          {PANEL_HEADER('Top 10', 'IP Indicators')}
          <ol className="intel-list">
            {(data.topIPs || []).map((d) => (
              <li key={d.key}><code>{d.key}</code> <span>{d.count}×</span></li>
            ))}
            {(data.topIPs || []).length === 0 ? <p className="empty-state">No IPs.</p> : null}
          </ol>
        </section>
        <section className="panel-card">
          {PANEL_HEADER('Top 10', 'MITRE Techniques')}
          <ol className="intel-list">
            {(data.topMitreTechniques || []).map((t) => (
              <li key={t.key}><code>{t.key}</code> <span>{t.count}×</span></li>
            ))}
            {(data.topMitreTechniques || []).length === 0 ? <p className="empty-state">No MITRE hits yet.</p> : null}
          </ol>
        </section>
      </div>
    </div>
  );
}

// ─── Honeypots Page ─────────────────────────────────────────────────────────
export function HoneypotsPage({ data, onRefresh, onPlant, onRemove, onCheck }) {
  const [targetDir, setTargetDir] = useState('');

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Argus / Honeypots</p>
          <h1 className="page-title">Honeypot Canary Files</h1>
          <p className="page-subtitle">Decoy files planted to detect exfiltration, ransomware, and insider threats.</p>
        </div>
        <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">Refresh</button>
      </div>

      <section className="panel-card">
        {PANEL_HEADER('Plant Canaries', 'Deploy Tripwire Files')}
        <div className="field-grid">
          <label className="field-group field-group--wide">
            <span className="field-label">Target directory (full path)</span>
            <input className="field-input" value={targetDir} onChange={(e) => setTargetDir(e.target.value)} placeholder="C:\Users\Public\Documents\Honeypot" />
          </label>
          <div className="form-actions">
            <button className="control-btn control-btn--primary" disabled={!targetDir.trim()} onClick={() => onPlant(targetDir)} type="button">Plant Canaries</button>
            <button className="control-btn control-btn--ghost" onClick={onCheck} type="button">Check Now</button>
            <button className="control-btn control-btn--amber" onClick={onRemove} type="button">Remove All</button>
          </div>
        </div>
      </section>

      <div className="panel-grid panel-grid--split">
        <section className="panel-card">
          {PANEL_HEADER('Active', `Canaries (${(data?.canaries || []).length})`)}
          <div className="stack-list">
            {(data?.canaries || []).map((c) => (
              <div className="stack-item" key={c.id}>
                <span className={`meta-chip ${c.triggered ? 'meta-chip--alert' : ''}`}>{c.triggered ? 'TRIGGERED' : 'ARMED'}</span>
                <p><strong>{c.name}</strong> — <code>{c.path}</code></p>
              </div>
            ))}
            {(data?.canaries || []).length === 0 ? <p className="empty-state">No canaries planted.</p> : null}
          </div>
        </section>
        <section className="panel-card">
          {PANEL_HEADER('Trigger History', 'Honeypot Events')}
          <div className="stack-list">
            {(data?.events || []).slice(0, 20).map((e) => (
              <div className="stack-item" key={e.id}>
                <span className="meta-chip">{e.type.toUpperCase()}</span>
                <p><strong>{e.name}</strong> — {e.message}</p>
                <p className="event-meta">{new Date(e.at).toLocaleString()}</p>
              </div>
            ))}
            {(data?.events || []).length === 0 ? <p className="empty-state">No events.</p> : null}
          </div>
        </section>
      </div>
    </div>
  );
}

// ─── YARA Rules Editor Page ─────────────────────────────────────────────────
export function RulesPage({ rulesText, onSave, onTest }) {
  const [text, setText] = useState(rulesText || '');
  const [testFile, setTestFile] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [saveMsg, setSaveMsg] = useState('');

  /* eslint-disable react-hooks/set-state-in-effect */
  useEffect(() => { setText(rulesText || ''); }, [rulesText]);
  /* eslint-enable react-hooks/set-state-in-effect */

  const handleSave = async () => {
    setSaveMsg('Saving...');
    try {
      await onSave(text);
      setSaveMsg('Saved.');
    } catch (e) {
      setSaveMsg('Error: ' + e.message);
    }
  };

  const handleTest = async () => {
    if (!testFile) return;
    try {
      const result = await onTest(testFile, text);
      setTestResult(result);
    } catch (e) {
      setTestResult({ error: e.message });
    }
  };

  const example = `rule Suspicious_Powershell {
  meta:
    author = "analyst"
    severity = "critical"
  strings:
    $a = "Invoke-Expression"
    $b = "FromBase64String"
    $c = "DownloadString"
  condition:
    $a and ($b or $c)
}

rule Embedded_PE {
  meta:
    severity = "warning"
  strings:
    $mz = { 4D 5A }
  condition:
    $mz
}`;

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Argus / Custom Rules</p>
          <h1 className="page-title">YARA-style Rule Editor</h1>
          <p className="page-subtitle">Define custom detections with ASCII strings, hex patterns, regex, and logical conditions.</p>
        </div>
      </div>

      <section className="panel-card">
        {PANEL_HEADER('DSL', 'Rules Source')}
        <textarea
          className="rules-editor"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={example}
          spellCheck="false"
          rows={20}
        />
        <div className="form-actions">
          <button className="control-btn control-btn--primary" onClick={handleSave} type="button">Save Rules</button>
          <button className="control-btn control-btn--ghost" onClick={() => setText(example)} type="button">Load Example</button>
          {saveMsg ? <span className="form-message">{saveMsg}</span> : null}
        </div>
      </section>

      <section className="panel-card">
        {PANEL_HEADER('Test', 'Run Rules Against File')}
        <input type="file" onChange={(e) => setTestFile(e.target.files?.[0] || null)} className="field-input" />
        <div className="form-actions" style={{ marginTop: 10 }}>
          <button className="control-btn control-btn--primary" disabled={!testFile} onClick={handleTest} type="button">Test</button>
        </div>
        {testResult ? (
          <div className="rules-result">
            {testResult.error ? <p className="form-message form-message--error">{testResult.error}</p> : (
              <>
                <p><strong>Matches:</strong> {testResult.matched?.length || 0}</p>
                {(testResult.matched || []).map((m) => (
                  <div className={`stack-item rule-match rule-match--${m.severity}`} key={m.name}>
                    <strong>{m.name}</strong>
                    <p>Strings: {m.matchedStrings?.join(', ') || '—'}</p>
                  </div>
                ))}
              </>
            )}
          </div>
        ) : null}
      </section>
    </div>
  );
}

// ─── Live Alerts (WebSocket) ────────────────────────────────────────────────
export function LiveAlertsBanner({ alerts }) {
  if (!alerts || alerts.length === 0) return null;
  const latest = alerts[0];
  return (
    <div className={`live-alert live-alert--${latest.severity || 'info'}`}>
      <span className="live-alert__dot" />
      <strong>LIVE:</strong> [{(latest.category || '').replace(/_/g, ' ')}] {latest.detail || latest.filename || latest.message || 'New event'}
      <span className="live-alert__time">{new Date(latest.at).toLocaleTimeString()}</span>
    </div>
  );
}

// ─── useLiveAlerts hook (WebSocket) ─────────────────────────────────────────
export function useLiveAlerts(wsUrl) {
  const [alerts, setAlerts] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!wsUrl) return undefined;
    let ws;
    let reconnectTimer;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => setConnected(true);
        ws.onclose = () => {
          setConnected(false);
          reconnectTimer = setTimeout(connect, 5000);
        };
        ws.onerror = () => { try { ws.close(); } catch { /* ignore */ } };
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === 'replay') {
              setAlerts(msg.events || []);
            } else if (msg.type === 'alert') {
              setAlerts((prev) => [msg, ...prev].slice(0, 50));
            }
          } catch { /* ignore */ }
        };
      } catch { /* ignore */ }
    };
    connect();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) try { ws.close(); } catch { /* ignore */ }
    };
  }, [wsUrl]);

  return { alerts, connected };
}

// ─── IOC Display Component ──────────────────────────────────────────────────
export function IocDisplay({ iocs }) {
  if (!iocs) return null;
  const hasAny = (iocs.urls?.length || iocs.ips?.length || iocs.domains?.length || iocs.bitcoinAddresses?.length) > 0;
  if (!hasAny) return null;

  return (
    <div className="ioc-block">
      <p className="panel-kicker">Network IOCs</p>
      {iocs.urls?.length > 0 ? <p><strong>URLs ({iocs.urls.length}):</strong> {iocs.urls.slice(0, 3).map((u) => <code key={u}>{u.slice(0, 50)}</code>)}</p> : null}
      {iocs.ips?.length > 0 ? <p><strong>IPs:</strong> {iocs.ips.slice(0, 5).map((ip) => <code key={ip}>{ip}</code>)}</p> : null}
      {iocs.domains?.length > 0 ? <p><strong>Domains:</strong> {iocs.domains.slice(0, 5).map((d) => <code key={d}>{d}</code>)}</p> : null}
      {iocs.bitcoinAddresses?.length > 0 ? <p className="ioc-warning"><strong>⚠️ BTC Addresses (ransom indicator):</strong> {iocs.bitcoinAddresses.length}</p> : null}
      {iocs.suspiciousTlds?.length > 0 ? <p className="ioc-warning"><strong>⚠️ Suspicious TLDs:</strong> {iocs.suspiciousTlds.join(', ')}</p> : null}
    </div>
  );
}

// ─── PE Info Display ────────────────────────────────────────────────────────
export function PeDisplay({ peResult }) {
  if (!peResult || !peResult.isValidPE) return null;
  return (
    <div className="pe-block">
      <p className="panel-kicker">Portable Executable Analysis</p>
      <div className="pe-grid">
        <span><strong>Architecture:</strong> {peResult.architecture}</span>
        <span><strong>Sections:</strong> {peResult.numberOfSections}</span>
        <span><strong>Entry Point:</strong> <code>{peResult.entryPointHex}</code></span>
        <span><strong>Build Date:</strong> {peResult.timeDateStampISO?.slice(0, 10) || '—'}</span>
      </div>
      <div className="pe-sections">
        {(peResult.sections || []).map((s) => (
          <span key={s.name} className={`pe-section ${s.isWrite && s.isExecute ? 'pe-section--danger' : ''}`} title={`Size: ${s.sizeOfRawData}`}>
            {s.name} <code>{s.permissions}</code>
          </span>
        ))}
      </div>
      {peResult.anomalies?.length > 0 ? (
        <div className="pe-anomalies">
          <strong>Anomalies:</strong>
          {peResult.anomalies.map((a, i) => (
            <p key={i} className={`pe-anomaly pe-anomaly--${a.severity}`}>[{a.severity}] {a.section}: {a.description}</p>
          ))}
        </div>
      ) : null}
      {peResult.importedDlls?.length > 0 ? (
        <p><strong>Imports:</strong> {peResult.importedDlls.slice(0, 8).join(', ')}{peResult.importedDlls.length > 8 ? `... (+${peResult.importedDlls.length - 8})` : ''}</p>
      ) : null}
    </div>
  );
}

// ─── MITRE Mini-display (for scan result cards) ─────────────────────────────
export function MitreChips({ techniques }) {
  if (!techniques || techniques.length === 0) return null;
  return (
    <div className="mitre-chips">
      <span className="panel-kicker">MITRE ATT&CK:</span>
      {techniques.slice(0, 8).map((t) => (
        <span className="mitre-chip" key={t.id} title={`${t.tactic}: ${t.name}\n${(t.evidence || []).join('\n')}`}>
          {t.id} <small>{t.name}</small>
        </span>
      ))}
    </div>
  );
}
