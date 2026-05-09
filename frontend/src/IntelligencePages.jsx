/**
 * Intelligence Pages — pagini noi pentru:
 *  - MITRE ATT&CK Matrix
 *  - Threat Intelligence Dashboard
 *  - Honeypots
 *  - YARA Rules Editor
 *  - Live Alerts (WebSocket)
 *  - Entropy Heatmap canvas
 */

import { useEffect, useRef, useState, useCallback } from 'react';

const PANEL_HEADER = (kicker, title) => (
  <div className="panel-card__header">
    <div>
      <p className="panel-kicker">{kicker}</p>
      <h3>{title}</h3>
    </div>
  </div>
);

// ─── Entropy Heatmap Canvas ─────────────────────────────────────────────────
export function EntropyHeatmap({ blocks, height = 60 }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !Array.isArray(blocks) || blocks.length === 0) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const blockWidth = Math.max(1, width / blocks.length);
    ctx.clearRect(0, 0, width, height);

    blocks.forEach((b, idx) => {
      const e = b.entropy || 0;
      const ratio = Math.min(1, e / 8);
      // Verde (low) → galben (med) → roșu (high)
      let r, g, bl;
      if (ratio < 0.5) {
        r = Math.round(60 + ratio * 2 * 195);
        g = 200;
        bl = 100;
      } else {
        r = 255;
        g = Math.round(200 - (ratio - 0.5) * 2 * 180);
        bl = 60;
      }
      ctx.fillStyle = `rgba(${r},${g},${bl},0.85)`;
      ctx.fillRect(idx * blockWidth, 0, Math.ceil(blockWidth), height);
    });
  }, [blocks, height]);

  if (!blocks || blocks.length === 0) {
    return <div className="empty-state">Nu există blocuri de entropie de afișat.</div>;
  }

  return (
    <div className="entropy-heatmap">
      <canvas ref={canvasRef} width={800} height={height} style={{ width: '100%', height, borderRadius: 6 }} />
      <div className="entropy-heatmap__legend">
        <span>0.0</span>
        <span>4.0</span>
        <span>8.0 (max)</span>
      </div>
    </div>
  );
}

// ─── MITRE ATT&CK Matrix Page ───────────────────────────────────────────────
export function MitrePage({ matrix, intel, loading, onRefresh }) {
  const detectedTechs = new Set((intel?.topMitreTechniques || []).map((t) => t.key));

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Containment Atlas / MITRE ATT&CK</p>
          <h1 className="page-title">ATT&CK Coverage Matrix</h1>
          <p className="page-subtitle">Tehnici MITRE detectate live de motorul euristic, mapate la tactici Enterprise.</p>
        </div>
        <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">Refresh</button>
      </div>

      {loading ? <div className="empty-state">Loading MITRE matrix...</div> : null}

      <div className="mitre-matrix">
        {(matrix || []).map((tactic) => (
          <div className="mitre-tactic" key={tactic.id}>
            <h4 className="mitre-tactic__title">{tactic.name}</h4>
            <p className="mitre-tactic__id">{tactic.id}</p>
            <div className="mitre-tactic__list">
              {tactic.techniques.map((tech) => {
                const isHit = detectedTechs.has(tech.id);
                return (
                  <div key={tech.id} className={`mitre-technique ${isHit ? 'mitre-technique--hit' : ''}`} title={tech.name}>
                    <strong>{tech.id}</strong>
                    <span>{tech.name}</span>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
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
          <p className="page-breadcrumb">Containment Atlas / Threat Intelligence</p>
          <h1 className="page-title">Threat Intelligence Dashboard</h1>
          <p className="page-subtitle">Statistici globale agregate: top hash-uri, domenii, IP-uri, tehnici MITRE.</p>
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
export function HoneypotsPage({ data, loading, onRefresh, onPlant, onRemove, onCheck }) {
  const [targetDir, setTargetDir] = useState('');

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Containment Atlas / Honeypots</p>
          <h1 className="page-title">Honeypot Canary Files</h1>
          <p className="page-subtitle">Fișiere "momeală" plantate pentru a detecta exfiltrare, ransomware, insider threat.</p>
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

  useEffect(() => { setText(rulesText || ''); }, [rulesText]);

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
          <p className="page-breadcrumb">Containment Atlas / Custom Rules</p>
          <h1 className="page-title">YARA-style Rule Editor</h1>
          <p className="page-subtitle">Definește detecții custom: ASCII strings, hex patterns, regex, cu condiții logice.</p>
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
