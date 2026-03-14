import { startTransition, useCallback, useEffect, useState } from 'react';
import './App.css';

const API_TOKEN = import.meta.env.VITE_PLATFORM_TOKEN ?? 'utm-auth-token-1773500227333';
const POLL_INTERVAL = 8000;
const API_BASE_CANDIDATES = Array.from(new Set([
  import.meta.env.VITE_API_BASE_URL,
  '/api',
  'http://localhost:5000/api',
].filter(Boolean)));

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid-1x2' },
  { id: 'firewall', label: 'Firewall', icon: 'shield-shaded' },
  { id: 'protection', label: 'Protection', icon: 'activity' },
  { id: 'telemetry', label: 'Telemetry', icon: 'diagram-3' },
  { id: 'events', label: 'Events', icon: 'terminal' },
  { id: 'controls', label: 'Controls', icon: 'sliders' },
];

const CONTROL_META = [
  { key: 'firewallEnabled', label: 'Firewall', copy: 'Enable or pause rule enforcement across the local packet filter.' },
  { key: 'protectionEnabled', label: 'Protection', copy: 'Keep malware scanning and quarantine activity available to operators.' },
  { key: 'telemetryEnabled', label: 'Telemetry', copy: 'Allow the dashboard and telemetry page to collect live system metrics.' },
  { key: 'eventsEnabled', label: 'Events', copy: 'Continue collecting operational events from scans and control changes.' },
  { key: 'maintenanceMode', label: 'Maintenance Mode', copy: 'Use a reduced-noise operating mode during maintenance windows.' },
];

const EICAR_SELF_TEST_CONTENT = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function buildApiUrl(pathname, baseUrl = API_BASE_CANDIDATES[0]) {
  const normalizedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
  const normalizedPath = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return `${normalizedBase}${normalizedPath}`;
}

function buildApiCandidates(pathname) {
  return API_BASE_CANDIDATES.map((baseUrl) => buildApiUrl(pathname, baseUrl));
}

function pickFirst(...values) {
  return values.find((value) => value !== null && value !== undefined && value !== '');
}

function toNumber(value) {
  if (value === null || value === undefined || value === '') {
    return undefined;
  }

  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }

  const numeric = Number(String(value).replace(/[^\d.-]/g, ''));
  return Number.isFinite(numeric) ? numeric : undefined;
}

function formatDisplay(value, fallback = '-') {
  return value === null || value === undefined || value === '' ? fallback : String(value);
}

function formatPercent(value) {
  const numeric = toNumber(value);
  if (numeric === undefined) {
    return '0%';
  }

  return `${numeric.toFixed(1)}%`;
}

function formatDateTime(value) {
  if (!value) {
    return '-';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatGigabytes(value) {
  const numeric = toNumber(value);
  return numeric === undefined ? '0.0 GB' : `${numeric.toFixed(1)} GB`;
}

function formatInteger(value) {
  const numeric = toNumber(value);
  return numeric === undefined ? '0' : `${Math.round(numeric)}`;
}

function formatRate(value) {
  if (value === null || value === undefined || value === '') {
    return '0 B/s';
  }

  return String(value);
}

function extractApiErrorMessage({ pathname, payload, raw, response }) {
  const normalizedPayloadMessage = typeof payload?.message === 'string' ? payload.message.trim() : '';
  if (normalizedPayloadMessage && !normalizedPayloadMessage.startsWith('<!DOCTYPE html>')) {
    return normalizedPayloadMessage;
  }

  const rawText = typeof raw === 'string' ? raw.trim() : '';
  const cannotGetMatch = rawText.match(/Cannot GET\s+([^\s<]+)/i) || rawText.match(/<pre>\s*Cannot GET\s+([^\s<]+)\s*<\/pre>/i);

  if (cannotGetMatch) {
    return `Endpoint unavailable: ${cannotGetMatch[1]}. Make sure the updated backend is running on port 5000.`;
  }

  if (/^<!DOCTYPE html>/i.test(rawText) || /^<html/i.test(rawText)) {
    return `Backend returned an HTML error page for ${pathname}. Make sure the updated API server is running.`;
  }

  if (response.status === 404) {
    return `Endpoint unavailable: ${pathname}.`;
  }

  return `HTTP ${response.status}`;
}

async function requestJson(pathname, options = {}) {
  const isFormData = options.body instanceof FormData;
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  headers.set('Authorization', `Bearer ${API_TOKEN}`);

  if (!isFormData && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  let lastError = null;

  for (const candidateUrl of buildApiCandidates(pathname)) {
    try {
      const response = await fetch(candidateUrl, {
        ...options,
        headers,
      });

      const raw = await response.text();
      let payload = null;

      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch {
          payload = { message: raw };
        }
      }

      if (response.ok && typeof raw === 'string' && /^\s*<!DOCTYPE html>/i.test(raw)) {
        throw new Error(extractApiErrorMessage({ pathname, payload, raw, response }));
      }

      if (!response.ok) {
        throw new Error(extractApiErrorMessage({ pathname, payload, raw, response }));
      }

      return payload;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error(`Could not reach API endpoint ${pathname}.`);
}

function normalizeStatusPayload(payload) {
  return {
    ...payload,
    platform: pickFirst(payload?.platform, payload?.system, payload?.hostname),
    status: pickFirst(payload?.status, payload?.health, 'Operational'),
    firewall: pickFirst(payload?.firewall, payload?.firewall_status, 'Active'),
    antivirus: pickFirst(payload?.antivirus, payload?.protection, 'Protected'),
    uptime: pickFirst(payload?.uptime, payload?.uptime_human),
    cpu_percent: pickFirst(payload?.cpu_percent, toNumber(payload?.cpu?.load)),
    ram_percent: pickFirst(payload?.ram_percent, toNumber(payload?.ram?.percent)),
    ram_used_mb: pickFirst(payload?.ram_used_mb, payload?.ram?.used !== undefined ? Math.round(payload.ram.used * 1024) : undefined),
    rules_active: pickFirst(payload?.rules_active, payload?.firewall_rules_count),
    blocked_today: pickFirst(payload?.blocked_today, payload?.blocked_rules),
    allowed_today: pickFirst(payload?.allowed_today, payload?.allowed_rules),
    files_scanned: pickFirst(payload?.files_scanned, payload?.scan_count),
    threats_found: pickFirst(payload?.threats_found, payload?.infected),
    quarantined: pickFirst(payload?.quarantined, payload?.quarantine_count),
    alerts_today: pickFirst(payload?.alerts_today, payload?.events_today),
    high_severity: pickFirst(payload?.high_severity, payload?.critical_alerts),
    rules_loaded: pickFirst(payload?.rules_loaded, payload?.firewall_rules_loaded),
    connected_clients: pickFirst(payload?.connected_clients, payload?.clients_online),
    rx_rate: pickFirst(payload?.rx_rate, payload?.network?.rxRate),
    tx_rate: pickFirst(payload?.tx_rate, payload?.network?.txRate),
  };
}

function getSeverityClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'critical') {
    return 'severity-pill severity-pill--critical';
  }

  if (normalized === 'warning') {
    return 'severity-pill severity-pill--warning';
  }

  return 'severity-pill severity-pill--info';
}

function StatusBadge({ value }) {
  const normalized = String(value || '').toLowerCase();
  const isActive = ['active', 'online', 'operational', 'protected', 'ready', 'live'].includes(normalized);
  const isInactive = ['inactive', 'offline', 'paused', 'error'].includes(normalized);
  const badgeClass = isActive ? 'badge-active' : isInactive ? 'badge-inactive' : 'badge-warning';

  return (
    <span className={`status-badge ${badgeClass}`}>
      <span className="badge-dot" />
      {value}
    </span>
  );
}

function StatCard({ accent, label, meta, value }) {
  return (
    <div className={`stat-card accent-${accent}`}>
      <p className="stat-label">{label}</p>
      <p className="stat-value">{value}</p>
      {meta ? <p className="stat-meta">{meta}</p> : null}
    </div>
  );
}

function TelemetryCard({ label, value }) {
  return (
    <div className="telemetry-card">
      <span className="telemetry-label">{label}</span>
      <strong className="telemetry-value">{value}</strong>
    </div>
  );
}

function ModuleCard({ action, children, onAction, status, tag, title }) {
  return (
    <div className="module-card">
      <div className="module-header">
        <div className="module-title-group">
          <span className="module-tag">{tag}</span>
          <h3 className="module-title">{title}</h3>
        </div>
        <StatusBadge value={status} />
      </div>
      <div className="module-body">{children}</div>
      {action ? (
        <div className="module-footer">
          <button className="control-btn" onClick={onAction} type="button">
            {action}
          </button>
        </div>
      ) : null}
    </div>
  );
}

function PageHeader({ action, breadcrumb, subtitle, title }) {
  return (
    <div className="page-header">
      <div>
        <p className="page-breadcrumb">{breadcrumb}</p>
        <h1 className="page-title">{title}</h1>
        {subtitle ? <p className="page-subtitle">{subtitle}</p> : null}
      </div>
      {action ? <div className="header-meta">{action}</div> : null}
    </div>
  );
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

function DataPair({ label, value }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Sidebar({ active, onNavigate }) {
  return (
    <aside className="control-sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark brand-mark--icon" aria-hidden="true">
          <i className="bi bi-layers-fill" />
        </span>
        <div className="brand-copy">
          <span className="brand-label">Sentinel Core</span>
          <span className="brand-sub">adaptive defense workspace</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? 'nav-item--active' : ''}`}
            onClick={() => startTransition(() => onNavigate(item.id))}
            title={item.label}
            type="button"
          >
            <i className={`bi bi-${item.icon}`} />
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-device">
          <span className="device-dot" />
          <span className="device-name">core-fabric-01</span>
        </div>
      </div>
    </aside>
  );
}

function Dashboard({ data, onNavigate, onRefresh }) {
  const controls = data?.controls || {};
  const maintenanceMode = Boolean(controls.maintenanceMode);
  const protectionStatus = formatDisplay(data?.antivirus, 'Protected');
  const activeControls = Object.entries(controls).filter(([key, value]) => key !== 'maintenanceMode' && value === true).length;

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Overview"
        title="Operations Dashboard"
        subtitle="Live posture, runtime health, and control plane readiness for the local security stack."
        action={(
          <>
            <span className="last-updated">
              Live <span className="live-dot" />
            </span>
            <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
              Refresh
            </button>
          </>
        )}
      />

      <div className="stat-strip">
        <StatCard accent="neutral" label="Platform" value={formatDisplay(data?.platform)} />
        <StatCard accent={maintenanceMode ? 'amber' : 'green'} label="System" value={formatDisplay(data?.status)} />
        <StatCard accent="neutral" label="Uptime" value={formatDisplay(data?.uptime)} />
        <StatCard accent={toNumber(data?.cpu_percent) > 80 ? 'red' : 'blue'} label="CPU Usage" value={formatPercent(data?.cpu_percent)} />
        <StatCard
          accent={toNumber(data?.ram_percent) > 85 ? 'red' : 'blue'}
          label="RAM Usage"
          value={formatPercent(data?.ram_percent)}
          meta={data?.ram_used_mb ? `${formatInteger(data.ram_used_mb)} MB used` : 'memory'}
        />
      </div>

      <div className="module-grid">
        <ModuleCard title="Telemetry" tag="TEL-01" status="Live" action="Open Telemetry" onAction={() => onNavigate('telemetry')}>
          <p className="module-desc">
            Real-time host metrics gathered from the local backend, focused on values this machine exposes reliably.
          </p>
          <div className="telemetry-grid">
            <TelemetryCard label="CPU" value={formatPercent(data?.cpu_percent)} />
            <TelemetryCard label="RAM" value={formatPercent(data?.ram_percent)} />
            <TelemetryCard label="RX Rate" value={formatRate(data?.rx_rate)} />
            <TelemetryCard label="TX Rate" value={formatRate(data?.tx_rate)} />
            <TelemetryCard label="Uptime" value={formatDisplay(data?.uptime, '0')} />
            <TelemetryCard label="Clients" value={formatInteger(data?.connected_clients)} />
          </div>
        </ModuleCard>

        <ModuleCard title="Firewall" tag="FW-01" status={formatDisplay(data?.firewall)} action="Manage Rules" onAction={() => onNavigate('firewall')}>
          <p className="module-desc">
            Review packet-filter rules, add new entries, and remove stale controls directly from the console.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.rules_active)}</span>
              <span className="mini-stat-label">Active Rules</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.blocked_today)}</span>
              <span className="mini-stat-label">Block Rules</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.allowed_today)}</span>
              <span className="mini-stat-label">Allow Rules</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Protection" tag="SEC-01" status={protectionStatus} action="Open Protection" onAction={() => onNavigate('protection')}>
          <p className="module-desc">
            Scan files, inspect recent antivirus logs, and verify what has already been moved into quarantine.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.files_scanned)}</span>
              <span className="mini-stat-label">Files Scanned</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.threats_found)}</span>
              <span className="mini-stat-label">Threats Found</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.quarantined)}</span>
              <span className="mini-stat-label">Quarantined</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Events" tag="EVT-01" status={toNumber(data?.alerts_today) > 0 ? 'Warning' : 'Active'} action="View Events" onAction={() => onNavigate('events')}>
          <p className="module-desc">
            Operational events combine scan activity, control changes, and rule posture into one feed for quick review.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.alerts_today)}</span>
              <span className="mini-stat-label">Open Alerts</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.high_severity)}</span>
              <span className="mini-stat-label">High Severity</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.rules_loaded)}</span>
              <span className="mini-stat-label">Rules Loaded</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Controls" tag="CTL-01" status={maintenanceMode ? 'Maintenance' : 'Ready'} action="Open Controls" onAction={() => onNavigate('controls')}>
          <p className="module-desc">
            Toggle telemetry, protection, firewall, and event collection from one control plane without leaving the dashboard.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{activeControls}</span>
              <span className="mini-stat-label">Controls Enabled</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{maintenanceMode ? 'Yes' : 'No'}</span>
              <span className="mini-stat-label">Maintenance</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatDateTime(controls.lastUpdated)}</span>
              <span className="mini-stat-label">Last Update</span>
            </div>
          </div>
        </ModuleCard>
      </div>
    </div>
  );
}

function FirewallPage({ error, loading, onAddRule, onDeleteRule, onRefresh, rules, summary }) {
  const [form, setForm] = useState({
    action: 'BLOCK',
    protocol: 'TCP',
    port: '443',
    ip: 'Any',
    status: 'Active',
    desc: '',
  });
  const [submitError, setSubmitError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitError('');
    setIsSubmitting(true);

    try {
      await onAddRule({
        ...form,
        port: Number(form.port),
      });
      setForm((current) => ({
        ...current,
        port: '443',
        desc: '',
      }));
    } catch (submitIssue) {
      setSubmitError(submitIssue.message);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Firewall"
        title="Firewall Rules"
        subtitle="Manage the ruleset that backs the backend firewall API."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Rules
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="green" label="Rules Loaded" value={formatInteger(summary?.total)} />
        <StatCard accent="blue" label="Rules Active" value={formatInteger(summary?.active)} />
        <StatCard accent="red" label="Block Rules" value={formatInteger(summary?.blockedRules)} />
        <StatCard accent="neutral" label="Allow Rules" value={formatInteger(summary?.allowedRules)} />
      </div>

      <div className="panel-grid panel-grid--split">
        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Rule Composer</p>
              <h3>Create Firewall Rule</h3>
            </div>
          </div>

          <form className="field-grid" onSubmit={handleSubmit}>
            <label className="field-group">
              <span className="field-label">Action</span>
              <select className="field-input" value={form.action} onChange={(event) => setForm({ ...form, action: event.target.value })}>
                <option value="BLOCK">Block</option>
                <option value="ALLOW">Allow</option>
              </select>
            </label>

            <label className="field-group">
              <span className="field-label">Protocol</span>
              <select className="field-input" value={form.protocol} onChange={(event) => setForm({ ...form, protocol: event.target.value })}>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </label>

            <label className="field-group">
              <span className="field-label">Port</span>
              <input className="field-input" min="1" step="1" type="number" value={form.port} onChange={(event) => setForm({ ...form, port: event.target.value })} />
            </label>

            <label className="field-group">
              <span className="field-label">IP Scope</span>
              <input className="field-input" type="text" value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} />
            </label>

            <label className="field-group field-group--wide">
              <span className="field-label">Description</span>
              <textarea className="field-input field-input--textarea" rows="4" value={form.desc} onChange={(event) => setForm({ ...form, desc: event.target.value })} />
            </label>

            {(submitError || error) ? <p className="form-message form-message--error">{submitError || error}</p> : null}

            <div className="form-actions">
              <button className="control-btn control-btn--primary" disabled={isSubmitting} type="submit">
                {isSubmitting ? 'Saving...' : 'Add Rule'}
              </button>
            </div>
          </form>
        </section>

        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Live Ruleset</p>
              <h3>Current Entries</h3>
            </div>
          </div>

          {loading && rules.length === 0 ? <EmptyState text="Loading firewall rules..." /> : null}
          {!loading && rules.length === 0 ? <EmptyState text="No firewall rules are configured yet." /> : null}

          {rules.length > 0 ? (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Protocol</th>
                    <th>Port</th>
                    <th>Scope</th>
                    <th>Status</th>
                    <th>Description</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{rule.action}</td>
                      <td>{rule.protocol}</td>
                      <td>{rule.port}</td>
                      <td>{rule.ip}</td>
                      <td><StatusBadge value={rule.status} /></td>
                      <td>{rule.desc}</td>
                      <td className="table-actions">
                        <button className="control-btn control-btn--danger" onClick={() => onDeleteRule(rule.id)} type="button">
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function ProtectionPage({ data, onRefresh, onRunSelfTest, onScan }) {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [scanError, setScanError] = useState('');

  async function handleScan(event) {
    event.preventDefault();

    if (selectedFiles.length === 0) {
      setScanError('Select at least one file before starting a scan.');
      return;
    }

    setScanError('');

    try {
      await onScan(selectedFiles);
      setSelectedFiles([]);
      event.currentTarget.reset();
    } catch (scanIssue) {
      setScanError(scanIssue.message);
    }
  }

  async function handleRunSelfTest() {
    setScanError('');

    try {
      await onRunSelfTest();
    } catch (scanIssue) {
      setScanError(scanIssue.message);
    }
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Protection"
        title="Protection Console"
        subtitle="Run antivirus scans, review the scan log, and inspect quarantine inventory."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Protection
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="blue" label="Total Scans" value={formatInteger(data.summary?.total)} />
        <StatCard accent="red" label="Threats Found" value={formatInteger(data.summary?.infected)} />
        <StatCard accent="green" label="Clean Files" value={formatInteger(data.summary?.clean)} />
        <StatCard accent="amber" label="Quarantined" value={formatInteger(data.summary?.quarantined)} />
      </div>

      <div className="panel-grid panel-grid--split">
        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">File Intake</p>
              <h3>Run Manual Scan</h3>
            </div>
          </div>

          <form className="field-grid" onSubmit={handleScan}>
            <label className="field-group field-group--wide">
              <span className="field-label">Files</span>
              <input
                className="field-input"
                multiple
                onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))}
                type="file"
              />
            </label>

            <p className="page-note">
              Local EICAR detection works immediately. The self-test button sends the payload from browser memory, without writing it to local disk first.
            </p>

            {(scanError || data.error) ? <p className="form-message form-message--error">{scanError || data.error}</p> : null}

            <div className="form-actions">
              <button className="control-btn control-btn--primary" disabled={data.scanLoading} type="submit">
                {data.scanLoading ? 'Scanning...' : 'Start Scan'}
              </button>
              <button className="control-btn control-btn--amber" disabled={data.scanLoading} onClick={handleRunSelfTest} type="button">
                {data.scanLoading ? 'Scanning...' : 'Run EICAR Self-Test'}
              </button>
            </div>
          </form>

          <div className="result-stack">
            <div className="result-stack__header">
              <p className="panel-kicker">Latest Result</p>
              <h4>Most Recent Files</h4>
            </div>

            {data.lastResults.length === 0 ? <EmptyState text="No manual scan results yet." /> : null}

            {data.lastResults.map((result) => (
              <div className="result-item" key={`${result.filename}-${result.sha256 || result.status}`}>
                <div className="result-item__main">
                  <strong>{result.filename}</strong>
                  <span>{result.signature || result.message || result.method}</span>
                </div>
                <StatusBadge value={result.status} />
              </div>
            ))}
          </div>
        </section>

        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Recent Activity</p>
              <h3>Scan Logs</h3>
            </div>
          </div>

          {data.loading && data.logs.length === 0 ? <EmptyState text="Loading scan logs..." /> : null}
          {!data.loading && data.logs.length === 0 ? <EmptyState text="No scan log entries yet." /> : null}

          {data.logs.length > 0 ? (
            <div className="stack-list">
              {data.logs.slice(0, 10).map((line, index) => (
                <div className="stack-item" key={`${line}-${index}`}>
                  <span className="meta-chip">{line.includes('STATUS: INFECTED') ? 'INFECTED' : line.includes('STATUS: REVIEW') ? 'REVIEW' : 'LOG'}</span>
                  <p>{line}</p>
                </div>
              ))}
            </div>
          ) : null}
        </section>
      </div>

      <section className="panel-card">
        <div className="panel-card__header">
          <div>
            <p className="panel-kicker">Isolation Store</p>
            <h3>Quarantine Inventory</h3>
          </div>
        </div>

        {data.loading && data.quarantine.length === 0 ? <EmptyState text="Loading quarantine inventory..." /> : null}
        {!data.loading && data.quarantine.length === 0 ? <EmptyState text="Quarantine is empty." /> : null}

        {data.quarantine.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Captured</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {data.quarantine.map((file) => (
                  <tr key={`${file.name}-${file.date}`}>
                    <td>{file.name}</td>
                    <td>{formatDateTime(file.date)}</td>
                    <td>{file.size}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function TelemetryPage({ data, error, loading, onRefresh }) {
  const telemetry = data || {};

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Telemetry"
        title="Telemetry"
        subtitle="Detailed host runtime, CPU, memory, and interface data from the backend telemetry layer."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Telemetry
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="neutral" label="Platform" value={formatDisplay(telemetry.platform)} />
        <StatCard accent="blue" label="CPU Usage" value={formatPercent(telemetry.cpu_percent)} />
        <StatCard accent="blue" label="RAM Usage" value={formatPercent(telemetry.ram_percent)} />
        <StatCard accent="neutral" label="Uptime" value={formatDisplay(telemetry.uptime, '0')} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {loading && !data ? <EmptyState text="Loading telemetry..." /> : null}

      {data ? (
        <div className="panel-grid panel-grid--triple">
          <section className="panel-card">
            <div className="panel-card__header">
              <div>
                <p className="panel-kicker">Compute</p>
                <h3>CPU Profile</h3>
              </div>
            </div>
            <div className="detail-grid">
              <DataPair label="Model" value={formatDisplay(telemetry.cpu?.model)} />
              <DataPair label="Cores" value={formatInteger(telemetry.cpu?.cores)} />
              <DataPair label="Physical" value={formatInteger(telemetry.cpu?.physicalCores)} />
              <DataPair label="Load" value={formatPercent(telemetry.cpu?.load)} />
              <DataPair label="Uptime" value={formatDisplay(telemetry.uptime)} />
            </div>
          </section>

          <section className="panel-card">
            <div className="panel-card__header">
              <div>
                <p className="panel-kicker">Memory</p>
                <h3>RAM Consumption</h3>
              </div>
            </div>
            <div className="detail-grid">
              <DataPair label="Used" value={formatGigabytes(telemetry.ram?.used)} />
              <DataPair label="Total" value={formatGigabytes(telemetry.ram?.total)} />
              <DataPair label="Percent" value={formatPercent(telemetry.ram?.percent)} />
            </div>
          </section>

          <section className="panel-card panel-card--wide">
            <div className="panel-card__header">
              <div>
                <p className="panel-kicker">Host Runtime</p>
                <h3>Interface Snapshot</h3>
              </div>
            </div>
            <div className="detail-grid detail-grid--wide">
              <DataPair label="Platform" value={formatDisplay(telemetry.platform)} />
              <DataPair label="Uptime" value={formatDisplay(telemetry.uptime, '0')} />
              <DataPair label="Interface" value={formatDisplay(telemetry.network?.iface)} />
              <DataPair label="RX Rate" value={formatRate(telemetry.rx_rate ?? telemetry.network?.rxRate)} />
              <DataPair label="TX Rate" value={formatRate(telemetry.tx_rate ?? telemetry.network?.txRate)} />
              <DataPair label="Connected Clients" value={formatInteger(telemetry.connected_clients)} />
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}

function EventsPage({ data, error, loading, onRefresh }) {
  const events = data || [];
  const critical = events.filter((event) => event.severity === 'critical').length;
  const warning = events.filter((event) => event.severity === 'warning').length;
  const info = events.filter((event) => event.severity === 'info').length;

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Events"
        title="Events"
        subtitle="Protection, controls, and firewall activity collected into one operational stream."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Events
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="red" label="Critical" value={formatInteger(critical)} />
        <StatCard accent="amber" label="Warning" value={formatInteger(warning)} />
        <StatCard accent="blue" label="Info" value={formatInteger(info)} />
        <StatCard accent="neutral" label="Total" value={formatInteger(events.length)} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {loading && events.length === 0 ? <EmptyState text="Loading events..." /> : null}
      {!loading && events.length === 0 ? <EmptyState text="No events available yet." /> : null}

      {events.length > 0 ? (
        <div className="stack-list">
          {events.map((event) => (
            <article className="event-card" key={event.id}>
              <div className="event-card__top">
                <div className="event-card__title">
                  <p className="panel-kicker">{event.source}</p>
                  <h3>{event.title}</h3>
                </div>
                <span className={getSeverityClass(event.severity)}>{event.severity}</span>
              </div>
              <p className="event-card__detail">{event.detail}</p>
              <p className="event-card__time">{formatDateTime(event.time)}</p>
            </article>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ControlsPage({ data, error, loading, onRefresh, onToggle, savingKey }) {
  const controls = data || {};
  const activeControls = CONTROL_META.filter((item) => controls[item.key] === true).length;

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Sentinel / Controls"
        title="Controls"
        subtitle="Toggle backend modules without leaving the console."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Controls
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="green" label="Enabled" value={formatInteger(activeControls)} />
        <StatCard accent="amber" label="Maintenance" value={controls.maintenanceMode ? 'On' : 'Off'} />
        <StatCard accent="neutral" label="Last Update" value={formatDateTime(controls.lastUpdated)} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {loading && !data ? <EmptyState text="Loading controls..." /> : null}

      {data ? (
        <div className="control-stack">
          {CONTROL_META.map((item) => {
            const enabled = Boolean(controls[item.key]);
            const isSaving = savingKey === item.key;

            return (
              <section className="panel-card" key={item.key}>
                <div className="toggle-row">
                  <div>
                    <p className="panel-kicker">Control</p>
                    <h3>{item.label}</h3>
                    <p className="module-desc">{item.copy}</p>
                  </div>

                  <div className="toggle-row__actions">
                    <span className={`toggle-pill ${enabled ? 'toggle-pill--on' : 'toggle-pill--off'}`}>
                      {enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <button className="control-btn control-btn--primary" disabled={isSaving} onClick={() => onToggle(item.key)} type="button">
                      {isSaving ? 'Saving...' : enabled ? 'Disable' : 'Enable'}
                    </button>
                  </div>
                </div>
              </section>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [serverData, setServerData] = useState(null);
  const [connStatus, setConnStatus] = useState('connecting');
  const [connMessage, setConnMessage] = useState('Connecting to backend...');
  const [firewallData, setFirewallData] = useState({ rules: [], summary: null, loading: false, error: '' });
  const [protectionData, setProtectionData] = useState({
    summary: {},
    logs: [],
    quarantine: [],
    lastResults: [],
    loading: false,
    scanLoading: false,
    error: '',
  });
  const [telemetryData, setTelemetryData] = useState({ data: null, loading: false, error: '' });
  const [eventsData, setEventsData] = useState({ events: [], loading: false, error: '' });
  const [controlsData, setControlsData] = useState({ controls: null, loading: false, savingKey: '', error: '' });

  const fetchDashboard = useCallback(async () => {
    try {
      const payload = normalizeStatusPayload(await requestJson('/status'));
      setServerData(payload);
      setConnStatus('ok');
      setConnMessage('Live telemetry connected.');
    } catch (error) {
      setConnStatus('error');
      setConnMessage(error.message || 'Connection failed.');
    }
  }, []);

  const loadFirewall = useCallback(async () => {
    setFirewallData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const [rules, summaryPayload] = await Promise.all([requestJson('/firewall/rules'), requestJson('/firewall/summary')]);
      setFirewallData({ rules: Array.isArray(rules) ? rules : [], summary: summaryPayload?.summary || null, loading: false, error: '' });
    } catch (error) {
      setFirewallData((current) => ({ ...current, loading: false, error: error.message || 'Could not load firewall data.' }));
    }
  }, []);

  const loadProtection = useCallback(async () => {
    setProtectionData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const [summaryPayload, logsPayload, quarantinePayload] = await Promise.all([
        requestJson('/antivirus/summary'),
        requestJson('/antivirus/logs'),
        requestJson('/antivirus/quarantine'),
      ]);

      setProtectionData((current) => ({
        ...current,
        summary: summaryPayload?.summary || {},
        logs: logsPayload?.logs || [],
        quarantine: quarantinePayload?.files || [],
        loading: false,
        error: '',
      }));
    } catch (error) {
      setProtectionData((current) => ({ ...current, loading: false, error: error.message || 'Could not load protection data.' }));
    }
  }, []);

  const loadTelemetry = useCallback(async () => {
    setTelemetryData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const payload = await requestJson('/stats/system');
      setTelemetryData({ data: payload, loading: false, error: '' });
    } catch (error) {
      setTelemetryData((current) => ({ ...current, loading: false, error: error.message || 'Could not load telemetry.' }));
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const payload = await requestJson('/events');
      setEventsData({ events: payload?.events || [], loading: false, error: '' });
    } catch (error) {
      setEventsData((current) => ({ ...current, loading: false, error: error.message || 'Could not load events.' }));
    }
  }, []);

  const loadControls = useCallback(async () => {
    setControlsData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const payload = await requestJson('/controls');
      setControlsData((current) => ({ ...current, controls: payload?.controls || null, loading: false, error: '' }));
    } catch (error) {
      setControlsData((current) => ({ ...current, loading: false, error: error.message || 'Could not load controls.' }));
    }
  }, []);

  const handleAddFirewallRule = useCallback(async (rule) => {
    const payload = await requestJson('/firewall/rules', { method: 'POST', body: JSON.stringify(rule) });
    await Promise.all([loadFirewall(), fetchDashboard(), loadEvents()]);
    return payload;
  }, [fetchDashboard, loadEvents, loadFirewall]);

  const handleDeleteFirewallRule = useCallback(async (ruleId) => {
    await requestJson(`/firewall/rules/${ruleId}`, { method: 'DELETE' });
    await Promise.all([loadFirewall(), fetchDashboard(), loadEvents()]);
  }, [fetchDashboard, loadEvents, loadFirewall]);

  const handleScanFiles = useCallback(async (files) => {
    setProtectionData((current) => ({ ...current, scanLoading: true, error: '' }));
    try {
      const formData = new FormData();
      files.forEach((file, index) => {
        const filename = file?.name || `scan-${index + 1}.bin`;
        formData.append('files', file, filename);
      });
      const payload = await requestJson('/antivirus/scan', { method: 'POST', body: formData });

      setProtectionData((current) => ({
        ...current,
        scanLoading: false,
        lastResults: payload?.results || [],
        error: '',
      }));

      await Promise.all([loadProtection(), fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setProtectionData((current) => ({ ...current, scanLoading: false, error: error.message || 'Could not complete scan.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents, loadProtection]);

  const handleRunEicarSelfTest = useCallback(async () => {
    const eicarFile = new File([EICAR_SELF_TEST_CONTENT], 'eicar-self-test.txt', {
      type: 'text/plain',
    });

    return handleScanFiles([eicarFile]);
  }, [handleScanFiles]);

  const handleToggleControl = useCallback(async (key) => {
    const nextValue = !controlsData.controls?.[key];
    setControlsData((current) => ({ ...current, savingKey: key, error: '' }));
    try {
      const payload = await requestJson('/controls', {
        method: 'PATCH',
        body: JSON.stringify({ [key]: nextValue }),
      });

      setControlsData((current) => ({
        ...current,
        controls: payload?.controls || current.controls,
        savingKey: '',
        error: '',
      }));

      await Promise.all([fetchDashboard(), loadControls(), loadEvents()]);
    } catch (error) {
      setControlsData((current) => ({ ...current, savingKey: '', error: error.message || 'Could not update controls.' }));
    }
  }, [controlsData.controls, fetchDashboard, loadControls, loadEvents]);

  useEffect(() => {
    fetchDashboard();
    const intervalId = setInterval(fetchDashboard, POLL_INTERVAL);
    return () => clearInterval(intervalId);
  }, [fetchDashboard]);

  useEffect(() => {
    if (activePage === 'firewall') {
      loadFirewall();
    }
    if (activePage === 'protection') {
      loadProtection();
    }
    if (activePage === 'telemetry') {
      loadTelemetry();
    }
    if (activePage === 'events') {
      loadEvents();
    }
    if (activePage === 'controls') {
      loadControls();
    }
  }, [activePage, loadControls, loadEvents, loadFirewall, loadProtection, loadTelemetry]);

  return (
    <div className="control-app">
      <Sidebar active={activePage} onNavigate={setActivePage} />

      <div className="control-main">
        {connStatus === 'error' ? (
          <div className="conn-banner conn-banner--error">
            Backend unavailable at <code>{buildApiUrl('/status')}</code>. {connMessage}
          </div>
        ) : null}

        {connStatus === 'connecting' ? <div className="conn-banner conn-banner--info">Connecting to backend...</div> : null}
        {activePage === 'dashboard' ? <Dashboard data={serverData} onNavigate={setActivePage} onRefresh={fetchDashboard} /> : null}
        {activePage === 'firewall' ? (
          <FirewallPage
            error={firewallData.error}
            loading={firewallData.loading}
            onAddRule={handleAddFirewallRule}
            onDeleteRule={handleDeleteFirewallRule}
            onRefresh={loadFirewall}
            rules={firewallData.rules}
            summary={firewallData.summary}
          />
        ) : null}
        {activePage === 'protection' ? (
          <ProtectionPage
            data={protectionData}
            onRefresh={loadProtection}
            onRunSelfTest={handleRunEicarSelfTest}
            onScan={handleScanFiles}
          />
        ) : null}
        {activePage === 'telemetry' ? (
          <TelemetryPage data={telemetryData.data} error={telemetryData.error} loading={telemetryData.loading} onRefresh={loadTelemetry} />
        ) : null}
        {activePage === 'events' ? <EventsPage data={eventsData.events} error={eventsData.error} loading={eventsData.loading} onRefresh={loadEvents} /> : null}
        {activePage === 'controls' ? (
          <ControlsPage
            data={controlsData.controls}
            error={controlsData.error}
            loading={controlsData.loading}
            onRefresh={loadControls}
            onToggle={handleToggleControl}
            savingKey={controlsData.savingKey}
          />
        ) : null}
      </div>
    </div>
  );
}
