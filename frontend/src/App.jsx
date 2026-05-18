import { startTransition, useCallback, useEffect, useState } from 'react';
import './App.css';
import './AppleOverrides.css';
import ContentFilterPage from './ContentFilterPage.jsx';
import {
  MitrePage,
  ThreatIntelPage,
  HoneypotsPage,
  RulesPage,
  MemoryScanPage,
  LiveAlertsBanner,
  useLiveAlerts,
  IocDisplay,
  PeDisplay,
  MitreChips,
} from './IntelligencePages.jsx';

const POLL_INTERVAL = 8000;
const APP_NAME = 'Argus';
const APP_TAGLINE = 'endpoint defense';
const prefersDirectApi = typeof window !== 'undefined' && ['localhost', '127.0.0.1'].includes(window.location.hostname);
const API_BASE_CANDIDATES = Array.from(new Set([
  import.meta.env.VITE_API_BASE_URL,
  prefersDirectApi ? 'http://localhost:5000/api' : '/api',
  prefersDirectApi ? '/api' : 'http://localhost:5000/api',
].filter(Boolean)));

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid-1x2' },
  { id: 'platform', label: 'Platform', icon: 'pc-display-horizontal' },
  { id: 'cleanup', label: 'Cleanup', icon: 'trash3' },
  { id: 'firewall', label: 'Firewall', icon: 'shield-shaded' },
  { id: 'filtering', label: 'Filtering', icon: 'funnel' },
  { id: 'protection', label: 'Protection', icon: 'activity' },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: 'crosshair' },
  { id: 'geoblocking', label: 'Geo Tracking', icon: 'globe2' },
  { id: 'memory', label: 'Memory Scan', icon: 'cpu' },
  { id: 'intel', label: 'Threat Intel', icon: 'shield-check' },
  { id: 'events', label: 'Events', icon: 'terminal' },
  { id: 'controls', label: 'Controls', icon: 'sliders' },
];

const CONTROL_META = [
  { key: 'firewallEnabled', label: 'Firewall', copy: 'Enable or pause rule enforcement across the local packet filter.' },
  { key: 'protectionEnabled', label: 'Protection', copy: 'Keep malware scanning and quarantine activity available to operators.' },
  { key: 'telemetryEnabled', label: 'Telemetry', copy: 'Allow the dashboard to collect live system metrics.' },
  { key: 'eventsEnabled', label: 'Events', copy: 'Continue collecting operational events from scans and control changes.' },
  { key: 'maintenanceMode', label: 'Maintenance Mode', copy: 'Use a reduced-noise operating mode during maintenance windows.' },
];

const EICAR_MARKER = ['EICAR', 'STANDARD', 'ANTIVIRUS', 'TEST', 'FILE'].join('-');
const EICAR_SELF_TEST_CONTENT = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', EICAR_MARKER, '!$H+H*'].join('');
let runtimeSessionToken = '';
let runtimeSessionPromise = null;

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

function formatPercent(value, fallback = '0 %') {
  const numeric = toNumber(value);
  if (numeric === undefined) {
    return fallback;
  }

  return `${numeric.toFixed(1)} %`;
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

function formatCompactDateTime(value) {
  if (!value) {
    return '-';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function formatGigabytes(value, fallback = '0.0 GB') {
  const numeric = toNumber(value);
  return numeric === undefined ? fallback : `${numeric.toFixed(1)} GB`;
}

function formatInteger(value, fallback = '0') {
  const numeric = toNumber(value);
  return numeric === undefined ? fallback : `${Math.round(numeric)}`;
}

function formatBytes(value) {
  const numeric = toNumber(value);
  if (numeric === undefined) {
    return '0 B';
  }

  if (numeric < 1024) {
    return `${Math.round(numeric)} B`;
  }

  if (numeric < 1024 ** 2) {
    return `${(numeric / 1024).toFixed(1)} KB`;
  }

  if (numeric < 1024 ** 3) {
    return `${(numeric / 1024 ** 2).toFixed(1)} MB`;
  }

  return `${(numeric / 1024 ** 3).toFixed(1)} GB`;
}

function formatRate(value) {
  if (value === null || value === undefined || value === '') {
    return '0 B/s';
  }

  return String(value);
}

function formatPlatformVersion(osInfo) {
  if (!osInfo) {
    return '-';
  }

  const version = String(osInfo.version || '').trim();
  const release = String(osInfo.release || '').trim();

  if (version && release) {
    const normalizedVersion = version.toLowerCase();
    const normalizedRelease = release.toLowerCase();

    if (normalizedVersion === normalizedRelease || normalizedVersion.includes(normalizedRelease)) {
      return version;
    }

    if (normalizedRelease.includes(normalizedVersion)) {
      return release;
    }
  }

  return pickFirst(
    [version, release].filter(Boolean).join(' ').trim(),
    version,
    release,
    osInfo.family,
    '-',
  );
}

function formatConnectionEndpoint(address, port) {
  const resolvedAddress = formatDisplay(address, '-');
  const resolvedPort = formatDisplay(port, '');
  return resolvedPort && resolvedPort !== '-' ? `${resolvedAddress}:${resolvedPort}` : resolvedAddress;
}

function sortEventsNewestFirst(events) {
  return [...(Array.isArray(events) ? events : [])].sort((left, right) => {
    const leftTime = new Date(left?.time || 0).getTime();
    const rightTime = new Date(right?.time || 0).getTime();
    return rightTime - leftTime;
  });
}

function setRuntimeSessionToken(token) {
  runtimeSessionToken = token || '';
}

function buildHttpError(message, status) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function requestPublicJson(pathname, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (!headers.has('Content-Type')) {
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

      if (!response.ok) {
        throw buildHttpError(
          typeof payload?.message === 'string' && payload.message.trim() ? payload.message.trim() : `HTTP ${response.status}`,
          response.status,
        );
      }

      return payload;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error(`Could not reach API endpoint ${pathname}.`);
}

async function ensureRuntimeSession(forceRefresh = false) {
  if (!forceRefresh && runtimeSessionToken) {
    return runtimeSessionToken;
  }

  if (!forceRefresh && runtimeSessionPromise) {
    return runtimeSessionPromise;
  }

  runtimeSessionPromise = requestPublicJson('/session')
    .then((payload) => {
      const token = payload?.token;
      if (!token) {
        throw new Error('Backend did not return a runtime session token.');
      }

      setRuntimeSessionToken(token);
      return token;
    })
    .finally(() => {
      runtimeSessionPromise = null;
    });

  return runtimeSessionPromise;
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
  headers.set('Authorization', `Bearer ${await ensureRuntimeSession(options.forceSessionRefresh)}`);

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
        throw buildHttpError(extractApiErrorMessage({ pathname, payload, raw, response }), response.status);
      }

      return payload;
    } catch (error) {
      lastError = error;
    }
  }

  if ((lastError?.status === 401 || lastError?.status === 403) && !options._retriedSession) {
    setRuntimeSessionToken('');
    return requestJson(pathname, {
      ...options,
      _retriedSession: true,
      forceSessionRefresh: true,
    });
  }

  throw lastError || new Error(`Could not reach API endpoint ${pathname}.`);
}

function normalizeStatusPayload(payload) {
  const analysis = payload?.analysis || {};

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
    sandbox_jobs_pending: pickFirst(payload?.sandbox_jobs_pending, (analysis.pending || 0) + (analysis.running || 0)),
    sandbox_jobs_completed: pickFirst(payload?.sandbox_jobs_completed, analysis.completed),
    hybrid_analysis_findings: pickFirst(payload?.hybrid_analysis_findings, (analysis.review || 0) + (analysis.malicious || 0)),
    hybrid_analysis_available: pickFirst(payload?.hybrid_analysis_available, false),
    connected_clients: pickFirst(payload?.connected_clients, payload?.clients_online),
    rx_rate: pickFirst(payload?.rx_rate, payload?.network?.rxRate),
    tx_rate: pickFirst(payload?.tx_rate, payload?.network?.txRate),
    content_filter_enabled: pickFirst(payload?.content_filter_enabled, payload?.contentFilter?.policy?.enabled, false),
    content_filter_domains: pickFirst(payload?.content_filter_domains, payload?.contentFilter?.runtime?.appliedDomainCount, 0),
    content_filter_last_applied: pickFirst(payload?.content_filter_last_applied, payload?.contentFilter?.runtime?.lastApplyAt),
    content_filter_categories: pickFirst(payload?.content_filter_categories, payload?.contentFilter?.runtime?.enabledCategoryIds?.length, 0),
    content_filter_ready: pickFirst(payload?.content_filter_ready, payload?.contentFilter?.runtime?.environment?.supported, false),
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
  const isActive = ['active', 'online', 'operational', 'protected', 'ready', 'live', 'clean', 'completed'].includes(normalized);
  const isInactive = ['inactive', 'offline', 'paused', 'error', 'failed'].includes(normalized);
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

function TelemetryDetailPanels({ data, error, loading }) {
  const telemetry = data || {};
  const hasTelemetry = Boolean(data);

  return (
    <>
      <div className="panel-grid panel-grid--stats">
        <StatCard accent="neutral" label="Platform" value={formatDisplay(telemetry.platform)} />
        <StatCard accent="blue" label="CPU Usage" value={formatPercent(telemetry.cpu_percent)} />
        <StatCard accent="blue" label="RAM Usage" value={formatPercent(telemetry.ram_percent)} />
        <StatCard accent="neutral" label="Uptime" value={formatDisplay(telemetry.uptime, '0')} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {loading && !hasTelemetry ? <EmptyState text="Loading telemetry..." /> : null}

      {hasTelemetry ? (
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
              <DataPair label="Load" value={formatPercent(telemetry.cpu?.load ?? telemetry.cpu_percent)} />
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
              <DataPair label="Percent" value={formatPercent(telemetry.ram?.percent ?? telemetry.ram_percent)} />
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
              <DataPair label="Version" value={formatPlatformVersion(telemetry.os)} />
              <DataPair label="Build" value={formatDisplay(telemetry.os?.build, 'Unavailable')} />
              <DataPair label="Interface" value={formatDisplay(telemetry.network?.iface)} />
              <DataPair label="RX Rate" value={formatRate(telemetry.rx_rate ?? telemetry.network?.rxRate)} />
              <DataPair label="TX Rate" value={formatRate(telemetry.tx_rate ?? telemetry.network?.txRate)} />
              <DataPair label="Connected Clients" value={formatInteger(telemetry.connected_clients)} />
              <DataPair label="Incoming Packets" value={formatInteger(telemetry.packets?.rxPackets)} />
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

function Sidebar({ active, onNavigate }) {
  return (
    <aside className="control-sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark brand-mark--icon" aria-hidden="true">
          <img className="brand-icon" src="/favicon.svg" alt="" />
        </span>
        <div className="brand-copy">
          <span className="brand-label">{APP_NAME}</span>
          <span className="brand-sub">{APP_TAGLINE}</span>
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

      
    </aside>
  );
}

function Dashboard({ data, onNavigate, onRefresh, onTelemetryRefresh, telemetryData, telemetryError, telemetryLoading }) {
  const controls = data?.controls || {};
  const maintenanceMode = Boolean(controls.maintenanceMode);
  const protectionStatus = formatDisplay(data?.antivirus, 'Protected');
  const activeControls = Object.entries(controls).filter(([key, value]) => key !== 'maintenanceMode' && value === true).length;
  const telemetrySnapshot = telemetryData || data;
  const [exporting, setExporting] = useState(false);

  async function handleExportPdf() {
    setExporting(true);
    try {
      const urls = buildApiCandidates('/report/security');
      let response;
      for (const url of urls) {
        try {
          response = await fetch(url, {
            headers: { Authorization: `Bearer ${runtimeSessionToken}` },
          });
          if (response.ok) break;
        } catch { /* try next */ }
      }
      if (!response?.ok) throw new Error('Could not generate report.');
      const blob = await response.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `argus-report-${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Overview`}
        title="Argus Command Center"
        subtitle="Runtime posture, active containment layers, provider findings, and machine health mapped into one operator workspace."
        action={(
          <>
            <span className="last-updated">
              Live <span className="live-dot" />
            </span>
            <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
              Refresh
            </button>
            <button className="control-btn" onClick={handleExportPdf} disabled={exporting} type="button">
              {exporting ? 'Generating…' : 'Export PDF'}
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

      <section className="dashboard-section">
        <div className="dashboard-section-heading">
          <div>
            <p className="panel-kicker">Telemetry</p>
            <h2>Live Host Runtime</h2>
          </div>
          <button className="control-btn control-btn--ghost" onClick={onTelemetryRefresh || onRefresh} type="button">
            Refresh Telemetry
          </button>
        </div>
        <TelemetryDetailPanels data={telemetrySnapshot} error={telemetryError} loading={telemetryLoading} />
      </section>

      <div className="dashboard-section-heading">
        <div>
          <p className="panel-kicker">Command Center</p>
          <h2>Modules</h2>
        </div>
      </div>

      <div className="module-grid">
        <ModuleCard title="Telemetry" tag="TEL-01" status={telemetryLoading ? 'Loading' : 'Live'} action="Refresh" onAction={onTelemetryRefresh || onRefresh}>
          <p className="module-desc">
            Real-time host metrics gathered from the local backend, focused on values this machine exposes reliably.
          </p>
          <div className="telemetry-grid">
            <TelemetryCard label="CPU" value={formatPercent(telemetrySnapshot?.cpu_percent)} />
            <TelemetryCard label="RAM" value={formatPercent(telemetrySnapshot?.ram_percent)} />
            <TelemetryCard label="RX Rate" value={formatRate(telemetrySnapshot?.rx_rate ?? telemetrySnapshot?.network?.rxRate)} />
            <TelemetryCard label="TX Rate" value={formatRate(telemetrySnapshot?.tx_rate ?? telemetrySnapshot?.network?.txRate)} />
            <TelemetryCard label="Clients" value={formatInteger(telemetrySnapshot?.connected_clients)} />
          </div>
        </ModuleCard>

        <ModuleCard title="Platform" tag="PLT-01" status="Ready" action="Open Platform" onAction={() => onNavigate('platform')}>
          <p className="module-desc">
            Review OS version and build information, open port counts, and live connection telemetry from the mini packet monitor.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatDisplay(data?.os?.build, 'N/A')}</span>
              <span className="mini-stat-label">Build</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.connected_clients)}</span>
              <span className="mini-stat-label">Clients</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatRate(data?.rx_rate)}</span>
              <span className="mini-stat-label">RX Rate</span>
            </div>
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

        <ModuleCard
          title="Content Filtering"
          tag="CF-01"
          status={data?.content_filter_enabled ? 'Armed' : data?.content_filter_ready ? 'Ready' : 'Offline'}
          action="Open Filtering"
          onAction={() => onNavigate('filtering')}
        >
          <p className="module-desc">
            Proxy-based containment for adult content, ads, malware, gambling, piracy, social platforms, and DNS-bypass routes.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.content_filter_domains)}</span>
              <span className="mini-stat-label">Managed Domains</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.content_filter_categories)}</span>
              <span className="mini-stat-label">Categories</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value mini-stat-value--compact" title={formatDateTime(data?.content_filter_last_applied)}>
                {formatCompactDateTime(data?.content_filter_last_applied)}
              </span>
              <span className="mini-stat-label">Last Apply</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Protection" tag="SEC-01" status={protectionStatus} action="Open Protection" onAction={() => onNavigate('protection')}>
          <p className="module-desc">
            Scan files, enrich verdicts with Hybrid Analysis, and track Falcon Sandbox jobs without losing the current local heuristics flow.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.files_scanned)}</span>
              <span className="mini-stat-label">Files Scanned</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.hybrid_analysis_findings)}</span>
              <span className="mini-stat-label">HA Findings</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatInteger(data?.sandbox_jobs_pending)}</span>
              <span className="mini-stat-label">Sandbox Pending</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Cleanup" tag="CLN-01" status="Ready" action="Open Cleanup" onAction={() => onNavigate('cleanup')}>
          <p className="module-desc">
            Launch the native OS cleanup tool or clear temp files directly from Sentinel when you need quick maintenance.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{formatDisplay(data?.os?.family, 'OS')}</span>
              <span className="mini-stat-label">Family</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatDisplay(data?.os?.version, 'N/A')}</span>
              <span className="mini-stat-label">Version</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{formatDisplay(data?.status, 'Ready')}</span>
              <span className="mini-stat-label">System</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Events" tag="EVT-01" status={toNumber(data?.alerts_today) > 0 ? 'Warning' : 'Active'} action="View Events" onAction={() => onNavigate('events')}>
          <p className="module-desc">
            Operational events combine scan activity, Hybrid Analysis jobs, control changes, and rule posture into one feed for quick review.
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
              <span className="mini-stat-value">{formatInteger(data?.sandbox_jobs_completed)}</span>
              <span className="mini-stat-label">Sandbox Done</span>
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
              <span className="mini-stat-value mini-stat-value--compact" title={formatDateTime(controls.lastUpdated)}>
                {formatCompactDateTime(controls.lastUpdated)}
              </span>
              <span className="mini-stat-label">Last Update</span>
            </div>
          </div>
        </ModuleCard>
      </div>
    </div>
  );
}

function OsBanner({ msg, ok }) {
  if (!msg) return null;
  return (
    <p style={{
      background:   ok ? 'rgba(52,199,89,0.08)'  : 'rgba(255,69,58,0.08)',
      border:       `1px solid ${ok ? 'rgba(52,199,89,0.35)' : 'rgba(255,69,58,0.35)'}`,
      borderRadius: '6px', padding: '0.5rem 0.75rem',
      fontSize:     '0.8rem', color: ok ? '#34c759' : '#ff453a', margin: 0,
    }}>
      {ok ? '✓ ' : '⚠ '}{msg}
    </p>
  );
}

function FirewallPage({ error, loading, onAddRule, onDeleteRule, onRefresh, rules, summary }) {
  const [form, setForm] = useState({ action: 'BLOCK', protocol: 'TCP', port: '', ip: 'Any', status: 'Active', desc: '' });
  const [submitError, setSubmitError]   = useState('');
  const [osStatus,    setOsStatus]      = useState(null);   // { ok, msg }
  const [deletingId,  setDeletingId]    = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const osFirewall = summary?.osFirewall || {};

  async function handleSubmit(event) {
    event.preventDefault();
    setSubmitError('');
    setOsStatus(null);

    const portNum = Number(form.port);
    if (!form.port || !Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
      setSubmitError('Enter a valid port between 1 and 65535.');
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await onAddRule({ ...form, port: portNum });
      if (result?.osFirewall) {
        setOsStatus({ ok: result.osFirewall.success === true, msg: result.osFirewall.message || '' });
      }
      await onRefresh();
      setForm((c) => ({ ...c, port: '', desc: '' }));
    } catch (e) {
      setSubmitError(e.message);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleDelete(ruleId) {
    setDeletingId(ruleId);
    try {
      await onDeleteRule(ruleId);
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Firewall`}
        title="Firewall Rules"
        subtitle="Manage safe local policy rules without blocking normal web access on ports 80, 443, or DNS."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">Refresh</button>
        )}
      />


      <div className="panel-grid panel-grid--stats">
        <StatCard accent="neutral" label="Total Rules"  value={formatInteger(summary?.total)} />
        <StatCard accent="blue"    label="Active"       value={formatInteger(summary?.active)} />
        <StatCard accent="red"     label="Block"        value={formatInteger(summary?.blockedRules)} />
        <StatCard accent="green"   label="Allow"        value={formatInteger(summary?.allowedRules)} />
        <StatCard accent="amber"   label="OS Applied"   value={formatInteger(summary?.osApplied)} />
      </div>

      {osFirewall.message ? (
        <div className={`form-message ${osFirewall.canApply ? 'form-message--success' : 'form-message--error'}`} style={{ alignItems: 'center', display: 'flex', gap: '0.75rem', justifyContent: 'space-between' }}>
          <span>{osFirewall.message}</span>
        </div>
      ) : null}

      <div className="panel-grid panel-grid--split">
        {/* ── Rule Composer ── */}
        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Rule Composer</p>
              <h3>Add Firewall Rule</h3>
            </div>
          </div>

          <form className="field-grid" onSubmit={handleSubmit}>
            <label className="field-group">
              <span className="field-label">Action</span>
              <select className="field-input" value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
                <option value="BLOCK">Block</option>
                <option value="ALLOW">Allow</option>
              </select>
            </label>

            <label className="field-group">
              <span className="field-label">Protocol</span>
              <select className="field-input" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>
            </label>

            <label className="field-group">
              <span className="field-label">Port <span style={{ fontWeight: 400, opacity: 0.5 }}>(1–65535)</span></span>
              <input
                autoComplete="off"
                className="field-input"
                inputMode="numeric"
                placeholder="ex: 8080, 3389, 22"
                type="text"
                value={form.port}
                onChange={(e) => setForm({ ...form, port: e.target.value.replace(/\D/g, '') })}
              />
            </label>

            <label className="field-group">
              <span className="field-label">IP / Scope</span>
              <input className="field-input" placeholder="Any" type="text" value={form.ip}
                onChange={(e) => setForm({ ...form, ip: e.target.value })} />
            </label>

            <label className="field-group field-group--wide">
              <span className="field-label">Description</span>
              <textarea className="field-input field-input--textarea" rows="2" value={form.desc}
                onChange={(e) => setForm({ ...form, desc: e.target.value })} />
            </label>

            {(submitError || error) ? <p className="form-message form-message--error">{submitError || error}</p> : null}
            <OsBanner msg={osStatus?.msg} ok={osStatus?.ok} />

            <div className="form-actions">
              <button className="control-btn control-btn--primary" disabled={isSubmitting || !form.port} type="submit">
                {isSubmitting ? 'Applying...' : 'Add Rule'}
              </button>
            </div>
          </form>
        </section>

        {/* ── Current Entries ── */}
        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Live Ruleset</p>
              <h3>Current Entries</h3>
            </div>
            <span style={{ fontSize: '0.75rem', opacity: 0.5 }}>{rules.length} rule{rules.length !== 1 ? 's' : ''}</span>
          </div>

          {loading && rules.length === 0 ? <EmptyState text="Loading rules..." /> : null}
          {!loading && rules.length === 0 ? <EmptyState text="No rules configured." /> : null}

          {rules.length > 0 ? (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Proto</th>
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
                      <td>
                        <span style={{
                          fontWeight: 600,
                          color: rule.action === 'BLOCK' ? '#ff453a' : '#34c759',
                          fontSize: '0.8rem',
                        }}>
                          {rule.action}
                        </span>
                      </td>
                      <td>{rule.protocol}</td>
                      <td style={{ fontWeight: 600 }}>{rule.port}</td>
                      <td>{rule.ip}</td>
                      <td><StatusBadge value={rule.status} /></td>
                      <td style={{ opacity: 0.65, fontSize: '0.8rem' }}>{rule.desc || '—'}</td>
                      <td className="table-actions">
                        <button
                          className="control-btn control-btn--danger"
                          disabled={deletingId === rule.id}
                          onClick={() => handleDelete(rule.id)}
                          type="button"
                        >
                          {deletingId === rule.id ? '…' : 'Delete'}
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

function DeepAnalysisPanel({ deepAnalysis }) {
  if (!deepAnalysis) {
    return null;
  }

  const { evasionResult, injectionResult, heuristicScore } = deepAnalysis;
  if (!evasionResult && !injectionResult && !heuristicScore) {
    return null;
  }

  const score = heuristicScore?.score ?? 0;
  const verdict = heuristicScore?.verdict || 'MINIMAL_RISK';
  const verdictClass = verdict === 'HIGH_RISK'
    ? 'deep-score--high'
    : verdict === 'MEDIUM_RISK'
      ? 'deep-score--medium'
      : verdict === 'LOW_RISK'
        ? 'deep-score--low'
        : 'deep-score--minimal';

  const indicators = Array.isArray(evasionResult?.indicators) ? evasionResult.indicators : [];
  const codeCaves = Array.isArray(injectionResult?.codeCaves) ? injectionResult.codeCaves : [];
  const appended = Array.isArray(injectionResult?.appendedPayloads) ? injectionResult.appendedPayloads : [];
  const polyglot = Array.isArray(injectionResult?.polyglot) ? injectionResult.polyglot : [];
  const reasons = Array.isArray(heuristicScore?.reasons) ? heuristicScore.reasons : [];

  return (
    <div className="deep-analysis">
      <div className="deep-analysis__header">
        <span className="panel-kicker">Deep Analysis (3-Layer Heuristic Engine)</span>
        <div className={`deep-score ${verdictClass}`}>
          <strong>{score}/100</strong>
          <span>{verdict.replace('_', ' ')}</span>
        </div>
      </div>

      <div className="deep-analysis__grid">
        {/* MODUL 1: Behavioral / Heuristic Score */}
        <div className="deep-card">
          <p className="deep-card__title">1. Heuristic Score Engine</p>
          <p className="deep-card__metric">{score}<span>/100</span></p>
          <p className="deep-card__verdict">{verdict.replace('_', ' ')}</p>
          {reasons.length > 0 ? (
            <ul className="deep-card__list">
              {reasons.slice(0, 5).map((reason, idx) => (
                <li key={`reason-${idx}`}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p className="deep-card__empty">No risk signals.</p>
          )}
        </div>

        {/* MODUL 2: Evasion Technique Detection */}
        <div className="deep-card">
          <p className="deep-card__title">2. Evasion Detection</p>
          <p className="deep-card__metric">{indicators.length}<span> indicator{indicators.length === 1 ? '' : 's'}</span></p>
          {indicators.length > 0 ? (
            <div className="deep-card__chips">
              {indicators.map((ind, idx) => (
                <span
                  key={`ev-${idx}`}
                  className={`deep-chip deep-chip--${ind.severity}`}
                  title={ind.description}
                >
                  {ind.category.replace(/_/g, ' ')} ({ind.matches?.length || 0})
                </span>
              ))}
            </div>
          ) : (
            <p className="deep-card__empty">No evasion techniques detected.</p>
          )}
        </div>

        {/* MODUL 3: Sub-byte Injection Detection */}
        <div className="deep-card">
          <p className="deep-card__title">3. Sub-byte Injection</p>
          <p className="deep-card__metric">
            {codeCaves.length + appended.length + polyglot.length}<span> hit{codeCaves.length + appended.length + polyglot.length === 1 ? '' : 's'}</span>
          </p>
          {codeCaves.length > 0 ? (
            <p className="deep-card__note">
              <strong>{codeCaves.length}</strong> code cave{codeCaves.length === 1 ? '' : 's'} - max {codeCaves[0]?.size} bytes @ {codeCaves[0]?.offsetHex}
            </p>
          ) : null}
          {appended.length > 0 ? (
            <p className="deep-card__note">
              <strong>{appended.length}</strong> payload{appended.length === 1 ? '' : 's'} after EOF: {appended.map((a) => a.type).join(', ')}
            </p>
          ) : null}
          {polyglot.length > 0 ? (
            <p className="deep-card__note">
              Polyglot: {polyglot[0]?.formats?.join(' + ')}
            </p>
          ) : null}
          {codeCaves.length + appended.length + polyglot.length === 0 ? (
            <p className="deep-card__empty">No sub-byte injection detected.</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ProtectionPage({ data, onPollAnalysis, onRefresh, onRunSelfTest, onScan, onSubmitUrl }) {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [scanError, setScanError] = useState('');
  const [selectedProviders, setSelectedProviders] = useState([]);
  const [hybridAnalysisOptInPublic, setHybridAnalysisOptInPublic] = useState(false);
  const [hasCustomizedProviders, setHasCustomizedProviders] = useState(false);
  const [urlToSubmit, setUrlToSubmit] = useState('');
  const [urlError, setUrlError] = useState('');
  const providerSummary = data.summary?.providerSummary || {};
  const recentJobs = Array.isArray(data.recentJobs) ? data.recentJobs : [];

  useEffect(() => {
    if (hasCustomizedProviders || !Array.isArray(data.providers) || data.providers.length === 0) {
      return;
    }

    setSelectedProviders(
      data.providers
        .filter((provider) => provider.defaultSelected && provider.available !== false)
        .map((provider) => provider.id),
    );
    setHybridAnalysisOptInPublic(Boolean(data.hybridAnalysisOptInPublic));
  }, [data.hybridAnalysisOptInPublic, data.providers, hasCustomizedProviders]);

  function handleProviderToggle(providerId) {
    setHasCustomizedProviders(true);
    setSelectedProviders((current) => (
      current.includes(providerId)
        ? current.filter((value) => value !== providerId)
        : [...current, providerId]
    ));
  }

  async function handleScan(event) {
    event.preventDefault();
    const formElement = event.currentTarget;

    if (selectedFiles.length === 0) {
      setScanError('Select at least one file before starting a scan.');
      return;
    }

    setScanError('');

    try {
      await onScan(selectedFiles, {
        hybridAnalysisOptInPublic,
        providers: selectedProviders,
      });
      setSelectedFiles([]);
      formElement?.reset();
    } catch (scanIssue) {
      setScanError(scanIssue.message);
    }
  }

  async function handleRunSelfTest() {
    setScanError('');

    try {
      await onRunSelfTest({
        hybridAnalysisOptInPublic,
        providers: selectedProviders,
      });
    } catch (scanIssue) {
      setScanError(scanIssue.message);
    }
  }

  async function handleUrlSubmit(event) {
    event.preventDefault();
    setUrlError('');

    if (!urlToSubmit.trim()) {
      setUrlError('Enter a URL before submitting it to Falcon Sandbox.');
      return;
    }

    try {
      await onSubmitUrl(urlToSubmit.trim(), {
        hybridAnalysisOptInPublic,
      });
      setUrlToSubmit('');
    } catch (submitIssue) {
      setUrlError(submitIssue.message);
    }
  }

  async function handlePoll(jobId) {
    setScanError('');

    try {
      await onPollAnalysis(jobId);
    } catch (pollIssue) {
      setScanError(pollIssue.message);
    }
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Protection`}
        title="Protection Console"
        subtitle="Run local and cloud scans, enrich results with Hybrid Analysis, and track Falcon Sandbox jobs without replacing the current protection flow."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Protection
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="blue" label="Total Scans" value={formatInteger(data.summary?.total)} />
        <StatCard accent="red" label="Threats Found" value={formatInteger(data.summary?.infected)} />
        <StatCard accent="amber" label="Review Queue" value={formatInteger(data.summary?.review)} />
        <StatCard accent="blue" label="Sandbox Pending" value={formatInteger((providerSummary.pending || 0) + (providerSummary.running || 0))} />
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
              <span className="file-upload-box">
                <input
                  className="file-upload-input"
                  multiple
                  onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))}
                  type="file"
                />
                <span className="file-upload-box__icon">
                  <i className="bi bi-upload" />
                </span>
                <span className="file-upload-box__text">
                  {selectedFiles.length > 0 ? `${selectedFiles.length} file${selectedFiles.length === 1 ? '' : 's'} selected` : 'Upload files'}
                </span>
              </span>
              {selectedFiles.length > 0 ? (
                <span className="file-upload-box__meta">
                  {selectedFiles.slice(0, 3).map((file) => file.name).join(', ')}
                  {selectedFiles.length > 3 ? ` +${selectedFiles.length - 3}` : ''}
                </span>
              ) : null}
            </label>

            <p className="page-note">
              Local EICAR detection works immediately. The self-test button sends the payload from browser memory, without writing it to local disk first.
            </p>

            <div className="field-group field-group--wide">
              <span className="field-label">Providers</span>
              <div className="provider-list">
                {Array.isArray(data.providers) && data.providers.length > 0 ? data.providers.map((provider) => {
                  const checked = selectedProviders.includes(provider.id);
                  const isLocked = provider.configurable === false;

                  return (
                    <label className={`provider-option ${provider.available === false ? 'provider-option--disabled' : ''}`} key={provider.id}>
                      <div className="provider-option__top">
                        <span className="provider-option__label">
                          <input
                            checked={isLocked || checked}
                            disabled={provider.available === false || isLocked || data.scanLoading || data.urlSubmitLoading}
                            onChange={() => handleProviderToggle(provider.id)}
                            type="checkbox"
                          />
                          <strong>{provider.name}</strong>
                        </span>
                        <StatusBadge value={provider.enabled ? 'Ready' : provider.available ? 'Configured' : 'Unavailable'} />
                      </div>
                      <p className="provider-option__copy">
                        {provider.id === 'hybrid-analysis' ? 'Quick scan uploads the file privately to Hybrid Analysis and surfaces CrowdStrike ML / Falcon verdicts when available.' : null}
                        {provider.id === 'falcon-sandbox' ? 'Full detonation queues a persisted sandbox job and lets you poll the report for MITRE, hosts, signatures, and dropped files.' : null}
                        {provider.id === 'malwarebazaar' ? 'Hash lookup against MalwareBazaar keeps the existing cloud verdict path in place.' : null}
                        {provider.id === 'local-heuristic' ? 'Fast local heuristic detection always runs and remains authoritative for the EICAR self-test.' : null}
                      </p>
                    </label>
                  );
                }) : <EmptyState text="Loading provider availability..." />}
              </div>
            </div>

            <label className="field-group field-group--wide provider-consent">
              <span className="provider-option__label">
                <input
                  checked={hybridAnalysisOptInPublic}
                  disabled={data.scanLoading || data.urlSubmitLoading}
                  onChange={(event) => {
                    setHasCustomizedProviders(true);
                    setHybridAnalysisOptInPublic(event.target.checked);
                  }}
                  type="checkbox"
                />
                <strong>Allow public or community submission</strong>
              </span>
              <span className="provider-consent__copy">
                Leave this off to keep Hybrid Analysis and Falcon Sandbox submissions private whenever the provider allows private processing.
              </span>
            </label>

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
        </section>

        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Falcon Sandbox</p>
              <h3>Submit URL</h3>
            </div>
          </div>

          <form className="field-grid" onSubmit={handleUrlSubmit}>
            <label className="field-group field-group--wide">
              <span className="field-label">URL</span>
              <input
                className="field-input"
                onChange={(event) => setUrlToSubmit(event.target.value)}
                placeholder="https://example.test/file.exe"
                type="url"
                value={urlToSubmit}
              />
            </label>

            <p className="page-note">
              URL submission uses Falcon Sandbox and creates a persisted job you can poll from this page. Configure `HYBRID_ANALYSIS_ENVIRONMENT_ID` on the backend before using this flow.
            </p>

            {(urlError || data.urlSubmitError) ? <p className="form-message form-message--error">{urlError || data.urlSubmitError}</p> : null}

            <div className="form-actions">
              <button className="control-btn control-btn--primary" disabled={data.urlSubmitLoading} type="submit">
                {data.urlSubmitLoading ? 'Submitting...' : 'Submit URL'}
              </button>
            </div>
          </form>
        </section>
      </div>

      <section className="panel-card page-section-gap">
        <div className="panel-card__header">
          <div>
            <p className="panel-kicker">Latest Result</p>
            <h3>Most Recent Files</h3>
          </div>
        </div>

        <div className="result-stack">
          {data.lastResults.length === 0 ? <EmptyState text="No manual scan results yet." /> : null}

          {data.lastResults.map((result) => (
            <article className="analysis-result-card" key={`${result.filename}-${result.sha256 || result.status}`}>
              <div className="analysis-result-card__top">
                <div className="result-item__main">
                  <strong>{result.filename}</strong>
                  <span>{result.signature || result.message || result.method}</span>
                </div>
                <StatusBadge value={result.status} />
              </div>

              <div className="analysis-result-body">
                <div className="analysis-result-main">
                  <div className="provider-chip-row">
                    {(Array.isArray(result.providers) ? result.providers : []).map((provider) => (
                      <span className="meta-chip" key={`${result.filename}-${provider.id}`}>
                        {provider.name}: {provider.verdict || provider.status}
                      </span>
                    ))}
                  </div>

              {Array.isArray(result.hexMatches) && result.hexMatches.length > 0 ? (
                <div className="hex-match-row">
                  {result.hexMatches.map((match) => (
                    <span
                      className={`hex-chip hex-chip--${match.severity}`}
                      key={match.name}
                      title={`${match.description} — offset ${match.offsetHex}`}
                    >
                      {match.name} @{match.offsetHex}
                    </span>
                  ))}
                </div>
              ) : null}

              <DeepAnalysisPanel deepAnalysis={result.deepAnalysis} />

              <MitreChips techniques={result.mitreTechniques} />
              <IocDisplay iocs={result.iocs} />
              <PeDisplay peResult={result.deepAnalysis?.peResult} />

              <div className="form-actions">
                <button
                  className="control-btn control-btn--ghost"
                  type="button"
                  onClick={async () => {
                    try {
                      const res = await fetch(buildApiUrl('/intel/report/pdf'), {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${runtimeSessionToken}` },
                        body: JSON.stringify({ scanResult: result }),
                      });
                      if (!res.ok) throw new Error('PDF generation failed');
                      const blob = await res.blob();
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `report_${(result.filename || 'scan').replace(/[^\w.-]/g, '_')}.pdf`;
                      a.click();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      alert('PDF error: ' + err.message);
                    }
                  }}
                >
                  📄 Download PDF Report
                </button>
              </div>

              {result.hybridAnalysis?.quickScan ? (
                <div className="analysis-inline-grid">
                  <DataPair label="HA Verdict" value={formatDisplay(result.hybridAnalysis.quickScan.rawVerdict || result.hybridAnalysis.quickScan.verdict, '-')} />
                  <DataPair label="Threat Score" value={formatDisplay(result.hybridAnalysis.quickScan.threatScore, '-')} />
                  <DataPair label="Classification" value={formatDisplay(result.hybridAnalysis.quickScan.classification, '-')} />
                  <DataPair label="Report" value={result.hybridAnalysis.quickScan.reportUrl ? 'Available' : 'Pending'} />
                </div>
              ) : null}

              {result.sandboxJob ? (
                <div className="analysis-job-card">
                  <div>
                    <p className="panel-kicker">Falcon Sandbox</p>
                    <h4>{formatDisplay(result.sandboxJob.status, 'queued')}</h4>
                    <p className="analysis-job-card__copy">
                      {result.sandboxJob.verdict ? `Verdict: ${result.sandboxJob.verdict}.` : 'Waiting for a completed sandbox report.'}
                    </p>
                  </div>
                  <div className="analysis-job-card__actions">
                    <button
                      className="control-btn control-btn--ghost"
                      disabled={data.pollingJobId === result.sandboxJob.id}
                      onClick={() => handlePoll(result.sandboxJob.id)}
                      type="button"
                    >
                      {data.pollingJobId === result.sandboxJob.id ? 'Polling...' : 'Poll Report'}
                    </button>
                    {result.sandboxJob.reportUrl ? (
                      <a className="control-btn control-btn--amber" href={result.sandboxJob.reportUrl} rel="noreferrer" target="_blank">
                        Open Report
                      </a>
                    ) : null}
                  </div>
                </div>
              ) : null}
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <div className="panel-grid panel-grid--split">
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

        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Sandbox Jobs</p>
              <h3>Recent Analysis</h3>
            </div>
          </div>

          {recentJobs.length === 0 ? <EmptyState text="No Falcon Sandbox jobs have been created yet." /> : null}

          {recentJobs.length > 0 ? (
            <div className="result-stack">
              {recentJobs.map((job) => (
                <article className="analysis-job-card analysis-job-card--list" key={job.id}>
                  <div>
                    <p className="panel-kicker">{job.type === 'url' ? 'URL Job' : 'File Job'}</p>
                    <h4>{formatDisplay(job.filename || job.url || job.sha256, job.id)}</h4>
                    <p className="analysis-job-card__copy">
                      {formatDisplay(job.message, 'Sandbox job recorded.')}
                    </p>
                    <div className="provider-chip-row">
                      <span className="meta-chip">Status: {formatDisplay(job.status, 'queued')}</span>
                      {job.verdict ? <span className="meta-chip">Verdict: {job.verdict}</span> : null}
                      {job.environmentId ? <span className="meta-chip">Env: {job.environmentId}</span> : null}
                    </div>
                  </div>
                  <div className="analysis-job-card__actions">
                    <button
                      className="control-btn control-btn--ghost"
                      disabled={data.pollingJobId === job.id}
                      onClick={() => handlePoll(job.id)}
                      type="button"
                    >
                      {data.pollingJobId === job.id ? 'Polling...' : 'Poll Report'}
                    </button>
                    {job.reportUrl ? (
                      <a className="control-btn control-btn--amber" href={job.reportUrl} rel="noreferrer" target="_blank">
                        Open Report
                      </a>
                    ) : null}
                  </div>
                </article>
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
  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Telemetry`}
        title="Telemetry"
        subtitle="Detailed host runtime, CPU, memory, and interface data from the backend telemetry layer."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Telemetry
          </button>
        )}
      />

      <TelemetryDetailPanels data={data} error={error} loading={loading} />
    </div>
  );
}

function PlatformPage({ data, error, loading, onRefresh }) {
  const telemetry = data || {};
  const packetStats = telemetry.packets || {};
  const connectionSummary = telemetry.connectionSummary || {};
  const connections = Array.isArray(telemetry.connections) ? telemetry.connections : [];
  const normalizedVersion = String(telemetry.os?.version || '').trim().toLowerCase();
  const normalizedRelease = String(telemetry.os?.release || '').trim().toLowerCase();
  const showRelease = normalizedRelease && normalizedRelease !== normalizedVersion && !normalizedVersion.includes(normalizedRelease);

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Platform`}
        title="Platform"
        subtitle="Operating system details, Windows version and build metadata, and a lightweight packet and port monitor."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Platform
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="neutral" label="Platform" value={formatDisplay(telemetry.os?.family || telemetry.platform)} />
        <StatCard accent="blue" label="Version" value={formatPlatformVersion(telemetry.os)} />
        <StatCard accent="neutral" label="Build" value={formatDisplay(telemetry.os?.build, 'Unavailable')} />
        <StatCard accent="green" label="Listening Ports" value={formatInteger(connectionSummary.listening)} />
        <StatCard accent="blue" label="Incoming Packets" value={formatInteger(packetStats.rxPackets)} />
        <StatCard accent="blue" label="Outgoing Packets" value={formatInteger(packetStats.txPackets)} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {loading && !data ? <EmptyState text="Loading platform details..." /> : null}

      {data ? (
        <>
          <div className="panel-grid panel-grid--split">
            <section className="panel-card">
              <div className="panel-card__header">
                <div>
                  <p className="panel-kicker"></p>
                  <h3>Operating System</h3>
                </div>
              </div>
              <div className="detail-grid">
                <DataPair label="Hostname" value={formatDisplay(telemetry.os?.hostname)} />
                <DataPair label="Family" value={formatDisplay(telemetry.os?.family)} />
                <DataPair label="Platform Key" value={formatDisplay(telemetry.os?.platformKey)} />
                <DataPair label="Version" value={formatDisplay(telemetry.os?.version)} />
                {showRelease ? <DataPair label="Release" value={formatDisplay(telemetry.os?.release)} /> : null}
                <DataPair label="Build" value={formatDisplay(telemetry.os?.build, 'Unavailable')} />
                <DataPair label="Kernel" value={formatDisplay(telemetry.os?.kernel)} />
                <DataPair label="Architecture" value={formatDisplay(telemetry.os?.arch)} />
              </div>
            </section>

            <section className="panel-card">
              <div className="panel-card__header">
                <div>
                  <p className="panel-kicker"></p>
                  <h3>Packet Monitor</h3>
                </div>
              </div>
              <div className="detail-grid">
                <DataPair label="Interface" value={formatDisplay(telemetry.network?.iface)} />
                <DataPair label="RX Rate" value={formatRate(telemetry.rx_rate ?? telemetry.network?.rxRate)} />
                <DataPair label="TX Rate" value={formatRate(telemetry.tx_rate ?? telemetry.network?.txRate)} />
                <DataPair label="RX Bytes" value={formatBytes(packetStats.rxBytes)} />
                <DataPair label="TX Bytes" value={formatBytes(packetStats.txBytes)} />
                <DataPair label="Incoming Packets" value={formatInteger(packetStats.rxPackets)} />
                <DataPair label="Outgoing Packets" value={formatInteger(packetStats.txPackets)} />
                <DataPair label="Established" value={formatInteger(connectionSummary.established)} />
                <DataPair label="Listening" value={formatInteger(connectionSummary.listening)} />
                <DataPair label="Open Ports" value={connectionSummary.ports?.length ? connectionSummary.ports.join(', ') : '-'} />
              </div>
            </section>
          </div>

          <section className="panel-card">
            <div className="panel-card__header">
              <div>
                <p className="panel-kicker"></p>
                <h3>Connection Monitor</h3>
              </div>
            </div>

            {connections.length === 0 ? <EmptyState text="No connection details available right now." /> : null}

            {connections.length > 0 ? (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Local Endpoint</th>
                      <th>Remote Endpoint</th>
                      <th>State</th>
                      <th>PID</th>
                      <th>Process</th>
                    </tr>
                  </thead>
                  <tbody>
                    {connections.map((connection, index) => (
                      <tr key={`${connection.protocol}-${connection.localPort}-${connection.remotePort}-${connection.pid}-${index}`}>
                        <td>{formatDisplay(connection.protocol)}</td>
                        <td>{formatConnectionEndpoint(connection.localAddress, connection.localPort)}</td>
                        <td>{formatConnectionEndpoint(connection.remoteAddress, connection.remotePort)}</td>
                        <td>{formatDisplay(connection.state)}</td>
                        <td>{formatDisplay(connection.pid, '-')}</td>
                        <td>{formatDisplay(connection.processName, '-')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}

function CleanupPage({ actionLoading, data, error, lastResult, loading, message, onOpenNative, onRefresh, platformInfo }) {
  const nativeAction = data?.nativeAction || {};
  const tempTargets = Array.isArray(data?.tempTargets) ? data.tempTargets : [];

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Cleanup`}
        title="Cleanup"
        subtitle="Use the native cleanup tool for this platform from the console."
        action={(
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh Cleanup
          </button>
        )}
      />

      <div className="panel-grid panel-grid--stats">
        <StatCard accent="neutral" label="Platform" value={formatDisplay(platformInfo?.family || data?.platformKey)} />
        <StatCard accent="neutral" label="Version" value={formatPlatformVersion(platformInfo)} />
        <StatCard accent="blue" label="Temp Targets" value={formatInteger(tempTargets.length)} />
        <StatCard accent={nativeAction.supported ? 'green' : 'amber'} label="Native Tool" value={nativeAction.supported ? nativeAction.label : 'Unavailable'} />
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {message ? <p className="form-message form-message--success">{message}</p> : null}
      {loading && !data ? <EmptyState text="Loading cleanup actions..." /> : null}

      {data ? (
        <>
          <div className="panel-grid panel-grid--split">
            <section className="panel-card">
              <div className="panel-card__header">
                <div>
                  <p className="panel-kicker">Cleanup Actions</p>
                  <h3>Maintenance Tools</h3>
                </div>
              </div>

              <div className="detail-grid">
                <DataPair label="Native Tool" value={nativeAction.supported ? nativeAction.label : 'Unavailable'} />
                <DataPair label="Description" value={formatDisplay(nativeAction.description, 'No native cleanup action available.')} />
                <DataPair label="Platform" value={formatDisplay(data.platformKey)} />
              </div>

              <div className="result-stack">
                <div className="form-actions">
                  <button
                    className="control-btn control-btn--primary"
                    disabled={!nativeAction.supported || actionLoading === 'native'}
                    onClick={onOpenNative}
                    type="button"
                  >
                    {actionLoading === 'native' ? 'Opening...' : nativeAction.label || 'Open Native Cleanup'}
                  </button>
                </div>
              </div>
            </section>

            <section className="panel-card">
              <div className="panel-card__header">
                <div>
                  <p className="panel-kicker">Temp Locations</p>
                  <h3>Targets</h3>
                </div>
              </div>

              {tempTargets.length === 0 ? <EmptyState text="No temp targets were reported by the backend." /> : null}

              {tempTargets.length > 0 ? (
                <div className="stack-list">
                  {tempTargets.map((target) => (
                    <div className="stack-item" key={target}>
                      <span className="meta-chip">TEMP</span>
                      <p>{target}</p>
                    </div>
                  ))}
                </div>
              ) : null}
            </section>
          </div>

          {lastResult ? (
            <section className="panel-card">
              <div className="panel-card__header">
                <div>
                  <p className="panel-kicker">Last Run</p>
                  <h3>Cleanup Summary</h3>
                </div>
              </div>
              <div className="detail-grid detail-grid--wide">
                <DataPair label="Removed Entries" value={formatInteger(lastResult.removedEntries)} />
                <DataPair label="Reclaimed Space" value={formatBytes(lastResult.reclaimedBytes)} />
                <DataPair label="Completed" value={formatDateTime(lastResult.completedAt)} />
                <DataPair label="Directories" value={formatInteger(lastResult.tempTargets?.length)} />
              </div>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function EventsPage({ data, error, loading, onRefresh }) {
  const events = Array.isArray(data) ? data : [];
  const critical = events.filter((event) => event.severity === 'critical').length;
  const warning = events.filter((event) => event.severity === 'warning').length;
  const info = events.filter((event) => event.severity === 'info').length;

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Events`}
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
        breadcrumb={`${APP_NAME} / Controls`}
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

import { ComposableMap, Geographies, Geography, Marker, Line } from 'react-simple-maps';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Coordonate centru tari (lon, lat) - Romania e destinatia
const DEST = [25.0, 45.9]; // Romania
const COUNTRY_COORDS_UI = {
  CN:[104.2,35.9], RU:[105.3,61.5], KP:[127.5,40.3], IR:[53.7,32.4],
  BY:[28.0,53.7],  CU:[-79.5,21.5], SY:[38.3,35.0],  SD:[29.9,12.9],
  MM:[95.9,21.9],  VN:[108.3,14.1], PK:[69.3,30.4],  NG:[8.7,9.1],
  IN:[78.7,20.6],  BR:[-51.9,-14.2],UA:[31.2,48.4],  TR:[35.2,39.1],
  ID:[113.9,-0.8], EG:[30.8,26.8],  TH:[100.5,15.9], PH:[122.9,12.9],
  BD:[90.4,23.7],  MX:[-102.5,23.6],VE:[-66.6,6.4],  IQ:[43.7,33.2],
  AF:[67.7,33.9],  LY:[17.2,26.3],  SO:[46.2,6.1],   YE:[48.5,15.6],
  HK:[114.2,22.4], TW:[120.9,23.7], US:[-95.7,37.1], GB:[-3.4,55.4],
  DE:[10.5,51.2],  FR:[2.2,46.2],   NL:[5.3,52.3],   RO:[25.0,45.9],
  PL:[19.1,51.9],  KZ:[67.0,48.0],  UZ:[63.9,41.4],  AZ:[47.6,40.1],
  GE:[43.4,42.3],
};

function countryFlag(code) {
  return [...code.toUpperCase()].map((ch) => String.fromCodePoint(0x1F1E6 - 65 + ch.charCodeAt(0))).join('');
}

// Amber = geo tracking, red = content-filter block
const GEO_COLOR     = '#f5a623';
const CONTENT_COLOR = '#ff453a';
const INBOUND_COLOR = '#64d2ff';
const OUTBOUND_COLOR = '#34c759';

function getGeoActivityColor(item) {
  if (item.type === 'content') return CONTENT_COLOR;
  if (item.type === 'inbound') return INBOUND_COLOR;
  if (item.type === 'outbound') return OUTBOUND_COLOR;
  return GEO_COLOR;
}

function getGeoActivityLabel(item) {
  if (item.type === 'content') return 'Content Filter';
  if (item.type === 'inbound') return 'Inbound';
  if (item.type === 'outbound') return 'Outbound';
  return 'Geo Tracking';
}

function getGeoActivityCoords(item) {
  return Array.isArray(item.coords) ? item.coords : COUNTRY_COORDS_UI[item.country];
}

function AttackMap({ attacks, connections = [] }) {
  const [now, setNow] = useState(0);
  useEffect(() => {
    const updateNow = () => setNow(Date.now());
    updateNow();
    const id = setInterval(updateNow, 1500);
    return () => clearInterval(id);
  }, []);

  const FADE_MS = 22000;
  const connectionActivity = connections.map((connection) => ({
    ...connection,
    type: connection.direction,
    hostname: connection.remoteAddress,
    timestamp: connection.timestamp || now,
  }));
  const activity = [...connectionActivity, ...attacks];
  const visible = activity
    .filter((a) => getGeoActivityCoords(a) && now - a.timestamp < FADE_MS)
    .slice(0, 20);

  const geoCount     = attacks.filter((a) => a.type === 'geo').length;
  const contentCount = attacks.filter((a) => a.type === 'content').length;
  const inboundCount = connections.filter((a) => a.direction === 'inbound').length;
  const outboundCount = connections.filter((a) => a.direction === 'outbound').length;

  return (
    <div style={{ background: '#0a0a0a', border: '1px solid #1e1e1e', borderRadius: '12px', overflow: 'hidden', marginBottom: '1.5rem' }}>
      {/* Header */}
      <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid #1a1a1a', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        <span style={{ fontWeight: 600, fontSize: '0.85rem', flex: 1 }}>Connection Map</span>
        <span style={{ fontSize: '0.75rem' }}>
          <span style={{ color: GEO_COLOR, fontWeight: 600 }}>● Geo Tracking</span>
          <span style={{ color: '#444', margin: '0 0.5rem' }}>|</span>
          <span style={{ color: CONTENT_COLOR, fontWeight: 600 }}>● Content Filter</span>
        </span>
        <span style={{ fontSize: '0.75rem' }}>
          <span style={{ color: INBOUND_COLOR, fontWeight: 600 }}>Inbound</span>
          <span style={{ color: '#444', margin: '0 0.5rem' }}>|</span>
          <span style={{ color: OUTBOUND_COLOR, fontWeight: 600 }}>Outbound</span>
        </span>
        <span style={{ fontSize: '0.72rem', color: '#666' }}>
          {inboundCount} inbound / {outboundCount} outbound
        </span>
        <span style={{ fontSize: '0.72rem', color: '#444' }}>
          {activity.length > 0 ? `${geoCount + contentCount} blocked events` : 'Waiting for country-linked activity...'}
        </span>
      </div>

      {/* Harta */}
      <ComposableMap projectionConfig={{ scale: 147, center: [10, 15] }} style={{ width: '100%', height: 'auto', display: 'block' }}>
        <Geographies geography={GEO_URL}>
          {({ geographies }) => geographies.map((geo) => (
            <Geography
              key={geo.rsmKey}
              geography={geo}
              fill="#161616"
              stroke="#252525"
              strokeWidth={0.4}
              style={{ default: { outline: 'none' }, hover: { outline: 'none' }, pressed: { outline: 'none' } }}
            />
          ))}
        </Geographies>

        {/* Linii de la sursa la Romania */}
        {visible.map((atk, i) => {
          const age     = now - atk.timestamp;
          const opacity = Math.max(0.08, 1 - age / FADE_MS);
          const color   = getGeoActivityColor(atk);
          return (
            <Line
              key={`line-${atk.timestamp}-${i}`}
              from={getGeoActivityCoords(atk)}
              to={DEST}
              stroke={color}
              strokeWidth={1.4}
              strokeOpacity={opacity}
              strokeLinecap="round"
            />
          );
        })}

        {/* Dot sursa */}
        {visible.map((atk, i) => {
          const age     = now - atk.timestamp;
          const opacity = Math.max(0.2, 1 - age / FADE_MS);
          const color   = getGeoActivityColor(atk);
          return (
            <Marker key={`dot-${atk.timestamp}-${i}`} coordinates={getGeoActivityCoords(atk)}>
              <circle r={3.5} fill={color} fillOpacity={opacity} />
            </Marker>
          );
        })}

        {/* Romania — destinatie */}
        <Marker coordinates={DEST}>
          <circle r={6} fill="#0a84ff" stroke="#ffffff" strokeWidth={1.5} />
          <circle r={10} fill="none" stroke="#0a84ff" strokeWidth={1} strokeOpacity={0.3} />
        </Marker>
      </ComposableMap>

      {/* Feed atacuri recente */}
      {activity.length > 0 && (
        <div style={{ borderTop: '1px solid #1a1a1a', maxHeight: '130px', overflowY: 'auto' }}>
          {activity.slice(0, 12).map((atk, i) => {
            const color = getGeoActivityColor(atk);
            const label = getGeoActivityLabel(atk);
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.35rem 1.25rem', borderBottom: '1px solid #111', fontSize: '0.76rem' }}>
                <span style={{ color, fontWeight: 700, minWidth: '1.4rem' }}>{countryFlag(atk.country)}</span>
                <span style={{ color, fontSize: '0.7rem', background: `${color}18`, borderRadius: '4px', padding: '0.1rem 0.4rem', whiteSpace: 'nowrap' }}>{label}</span>
                <span style={{ color: '#888', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{atk.hostname || atk.remoteAddress}</span>
                <span style={{ color: '#3a3a3a', whiteSpace: 'nowrap' }}>{new Date(atk.timestamp).toLocaleTimeString()}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function GeoFilterPage({ data, onRefresh }) {
  const [attacks, setAttacks] = useState([]);
  const [connections, setConnections] = useState([]);
  const [connectionSummary, setConnectionSummary] = useState({ total: 0, inbound: 0, outbound: 0, countries: 0, byCountry: [] });
  const [activityLoading, setActivityLoading] = useState(false);

  const fetchGeoActivity = useCallback(async () => {
    setActivityLoading(true);
    try {
      const [attackPayload, connectionPayload] = await Promise.all([
        requestJson('/geo-filter/attacks'),
        requestJson('/geo-filter/connections?limit=160'),
      ]);
      setAttacks(attackPayload?.attacks || []);
      setConnections(connectionPayload?.items || []);
      setConnectionSummary(connectionPayload?.summary || { total: 0, inbound: 0, outbound: 0, countries: 0, byCountry: [] });
    } catch { /* ignore */ }
    finally {
      setActivityLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchGeoActivity();
    const id = setInterval(fetchGeoActivity, 5000);
    return () => clearInterval(id);
  }, [fetchGeoActivity]);

  async function handleRefresh() {
    await Promise.all([
      fetchGeoActivity(),
      onRefresh?.(),
    ]);
  }

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb={`${APP_NAME} / Geo Tracking`}
        title="Geo Tracking"
        subtitle="Track public inbound and outbound network activity on the connection map."
        action={
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="control-btn control-btn--ghost" disabled={activityLoading || data.loading} onClick={handleRefresh} type="button">
              {activityLoading || data.loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        }
      />

      {data.error ? <p style={{ color: '#ff453a', marginBottom: '1rem' }}>{data.error}</p> : null}

      {/* Harta */}
      <AttackMap attacks={attacks} connections={connections} />

      <div className="panel-grid panel-grid--stats" style={{ marginBottom: '1rem' }}>
        <StatCard accent="neutral" label="Geo Connections" value={formatInteger(connectionSummary.total)} />
        <StatCard accent="blue" label="Inbound" value={formatInteger(connectionSummary.inbound)} />
        <StatCard accent="green" label="Outbound" value={formatInteger(connectionSummary.outbound)} />
        <StatCard accent="amber" label="Countries" value={formatInteger(connectionSummary.countries)} />
      </div>

      <section className="panel-card" style={{ marginBottom: '1rem' }}>
        <div className="panel-card__header">
          <div>
            <p className="panel-kicker">Live Network Geography</p>
            <h3>Inbound / Outbound Connections</h3>
          </div>
          <span style={{ fontSize: '0.75rem', opacity: 0.55 }}>{connections.length} country-linked</span>
        </div>
        {connections.length === 0 ? <EmptyState text="No public inbound or outbound connections with country data right now." /> : null}
        {connections.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Direction</th>
                  <th>Country</th>
                  <th>Remote</th>
                  <th>Local</th>
                  <th>Proto</th>
                  <th>State</th>
                  <th>Process</th>
                </tr>
              </thead>
              <tbody>
                {connections.slice(0, 80).map((connection, index) => (
                  <tr key={`${connection.remoteAddress}-${connection.remotePort}-${connection.localPort}-${index}`}>
                    <td>
                      <span style={{ color: connection.direction === 'inbound' ? INBOUND_COLOR : OUTBOUND_COLOR, fontWeight: 700 }}>
                        {connection.direction}
                      </span>
                    </td>
                    <td>{countryFlag(connection.country)} {connection.country}{connection.city ? ` / ${connection.city}` : ''}</td>
                    <td>{formatConnectionEndpoint(connection.remoteAddress, connection.remotePort)}</td>
                    <td>{formatConnectionEndpoint(connection.localAddress, connection.localPort)}</td>
                    <td>{connection.protocol || '-'}</td>
                    <td>{connection.state || '-'}</td>
                    <td>{connection.processName || connection.pid || '-'}</td>
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

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [serverData, setServerData] = useState(null);
  const [connStatus, setConnStatus] = useState('connecting');
  const [connMessage, setConnMessage] = useState('Connecting to backend...');
  const [backendRestarting, setBackendRestarting] = useState(false);
  const [backendRestartMessage, setBackendRestartMessage] = useState('');
  const [firewallData, setFirewallData] = useState({ rules: [], summary: null, loading: false, error: '' });
  const [protectionData, setProtectionData] = useState({
    summary: {},
    logs: [],
    quarantine: [],
    lastResults: [],
    providers: [],
    recentJobs: [],
    hybridAnalysisOptInPublic: false,
    loading: false,
    scanLoading: false,
    pollingJobId: '',
    urlSubmitLoading: false,
    urlSubmitError: '',
    error: '',
  });
  const [telemetryData, setTelemetryData] = useState({ data: null, loading: false, error: '' });
  const [cleanupData, setCleanupData] = useState({
    data: null,
    loading: false,
    actionLoading: '',
    error: '',
    message: '',
    lastResult: null,
  });
  const [eventsData, setEventsData] = useState({ events: [], loading: false, error: '' });
  const [mitreData, setMitreData] = useState({ matrix: [], intel: null, memoryScan: null, loading: false });
  const [memoryData, setMemoryData] = useState({ lastScan: null, loading: false, error: '' });
  const [intelData, setIntelData] = useState({ intel: null, loading: false });
  const [honeypotsData, setHoneypotsData] = useState({ canaries: [], events: [], loading: false });
  const [rulesData, setRulesData] = useState({ rules: '', loading: false });

  // ─── Live Alerts via WebSocket ─────────────────────────────────────────────
  const wsUrl = (() => {
    if (typeof window === 'undefined') return null;
    const isLocal = ['localhost', '127.0.0.1'].includes(window.location.hostname);
    const host = isLocal ? 'localhost:5000' : window.location.host;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${host}/ws/alerts`;
  })();
  const { alerts: liveAlerts } = useLiveAlerts(wsUrl);
  const [controlsData, setControlsData] = useState({ controls: null, loading: false, savingKey: '', error: '' });
  const [contentFilterData, setContentFilterData] = useState({
    policy: null,
    categories: [],
    runtime: null,
    loading: false,
    saving: false,
    syncing: false,
    applying: false,
    removing: false,
    checking: false,
    error: '',
    message: '',
    checkResult: null,
  });
  const [geoFilterData, setGeoFilterData] = useState({ enabled: false, blockedCountries: [], loading: false, saving: false, syncing: false, syncStatus: {}, error: '', checkResult: null });

  const fetchDashboard = useCallback(async () => {
    try {
      const payload = normalizeStatusPayload(await requestJson('/status'));
      setServerData(payload);
      setConnStatus('ok');
      setConnMessage('Live telemetry connected.');
      setBackendRestartMessage('');
    } catch (error) {
      setConnStatus('error');
      setConnMessage(error.message || 'Connection failed.');
    }
  }, []);

  const handleRestartBackend = useCallback(async () => {
    setBackendRestarting(true);
    setBackendRestartMessage('Restarting backend...');

    try {
      const response = await fetch('/__argus/restart-backend', {
        method: 'POST',
        headers: { Accept: 'application/json' },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.success === false) {
        throw new Error(payload.message || `Restart failed with HTTP ${response.status}.`);
      }

      setBackendRestartMessage(payload.message || 'Backend restarted. Reconnecting...');
      await fetchDashboard();
    } catch (error) {
      setConnStatus('error');
      setBackendRestartMessage(error.message || 'Could not restart backend from the local dev server.');
    } finally {
      setBackendRestarting(false);
    }
  }, [fetchDashboard]);

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
      const [summaryPayload, logsPayload, quarantinePayload, providersPayload] = await Promise.all([
        requestJson('/antivirus/summary'),
        requestJson('/antivirus/logs'),
        requestJson('/antivirus/quarantine'),
        requestJson('/antivirus/providers'),
      ]);
      const defaultPublicOptIn = Boolean(
        providersPayload?.providers?.find((provider) => provider.id === 'hybrid-analysis')?.defaults?.publicSubmission,
      );

      setProtectionData((current) => ({
        ...current,
        summary: summaryPayload?.summary || {},
        logs: logsPayload?.logs || [],
        quarantine: quarantinePayload?.files || [],
        providers: providersPayload?.providers || [],
        recentJobs: summaryPayload?.summary?.recentJobs || [],
        hybridAnalysisOptInPublic: current.hybridAnalysisOptInPublic || defaultPublicOptIn,
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

  const refreshDashboard = useCallback(async () => {
    await Promise.all([fetchDashboard(), loadTelemetry()]);
  }, [fetchDashboard, loadTelemetry]);

  const loadCleanup = useCallback(async () => {
    setCleanupData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const payload = await requestJson('/cleanup');
      setCleanupData((current) => ({
        ...current,
        data: payload,
        loading: false,
        error: '',
      }));
    } catch (error) {
      setCleanupData((current) => ({ ...current, loading: false, error: error.message || 'Could not load cleanup actions.' }));
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsData((current) => ({ ...current, loading: true, error: '' }));
    try {
      const payload = await requestJson('/events');
      setEventsData({ events: sortEventsNewestFirst(payload?.events || []), loading: false, error: '' });
    } catch (error) {
      setEventsData((current) => ({ ...current, loading: false, error: error.message || 'Could not load events.' }));
    }
  }, []);

  const loadMitre = useCallback(async () => {
    setMitreData((current) => ({ ...current, loading: true }));
    try {
      const [matrixRes, intelRes, memoryRes] = await Promise.all([
        requestJson('/intel/mitre/matrix'),
        requestJson('/intel/intel/dashboard'),
        requestJson('/memory/last').catch(() => null),
      ]);
      setMitreData({ matrix: matrixRes?.tactics || [], intel: intelRes?.intel || null, memoryScan: memoryRes?.lastScan || null, loading: false });
    } catch {
      setMitreData((c) => ({ ...c, loading: false }));
    }
  }, []);

  const handleMemoryScan = useCallback(async () => {
    setMemoryData((c) => ({ ...c, loading: true, scanning: true, error: '' }));
    try {
      const payload = await requestJson(`/memory/scan?ts=${Date.now()}`, { cache: 'no-store' });
      if (payload?.success === false) {
        throw new Error(payload.error || payload.message || 'Memory scan failed.');
      }

      const lastScan = payload?.summary ? payload : payload?.lastScan || null;
      setMemoryData({
        lastScan,
        loading: false,
        scanning: Boolean(payload?.scanning && !lastScan?.summary),
        error: '',
      });
    } catch (err) {
      setMemoryData((c) => ({ ...c, loading: false, scanning: false, error: err.message || 'Memory scan failed.' }));
    }
  }, []);

  const loadIntel = useCallback(async () => {
    setIntelData((current) => ({ ...current, loading: true }));
    try {
      const payload = await requestJson('/intel/intel/dashboard');
      setIntelData({ intel: payload?.intel || null, loading: false });
    } catch {
      setIntelData((c) => ({ ...c, loading: false }));
    }
  }, []);

  const handleResetIntel = useCallback(async () => {
    try {
      await requestJson('/intel/intel/reset', { method: 'POST' });
      await loadIntel();
    } catch { /* ignore */ }
  }, [loadIntel]);

  const loadHoneypots = useCallback(async () => {
    setHoneypotsData((current) => ({ ...current, loading: true }));
    try {
      const payload = await requestJson('/intel/honeypots');
      setHoneypotsData({ canaries: payload?.canaries || [], events: payload?.events || [], loading: false });
    } catch {
      setHoneypotsData((c) => ({ ...c, loading: false }));
    }
  }, []);

  const handlePlantHoneypots = useCallback(async (targetDir) => {
    try {
      await requestJson('/intel/honeypots/plant', { method: 'POST', body: JSON.stringify({ targetDir }) });
      await loadHoneypots();
    } catch { /* ignore */ }
  }, [loadHoneypots]);

  const handleCheckHoneypots = useCallback(async () => {
    try {
      await requestJson('/intel/honeypots/check', { method: 'POST' });
      await loadHoneypots();
    } catch { /* ignore */ }
  }, [loadHoneypots]);

  const handleRemoveAllHoneypots = useCallback(async () => {
    try {
      await fetch(buildApiUrl('/intel/honeypots/all'), {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${runtimeSessionToken}` },
      });
      await loadHoneypots();
    } catch { /* ignore */ }
  }, [loadHoneypots]);

  const loadRules = useCallback(async () => {
    setRulesData((current) => ({ ...current, loading: true }));
    try {
      const payload = await requestJson('/intel/rules');
      setRulesData({ rules: payload?.rules || '', loading: false });
    } catch {
      setRulesData((c) => ({ ...c, loading: false }));
    }
  }, []);

  const handleSaveRules = useCallback(async (text) => {
    await requestJson('/intel/rules', { method: 'PUT', body: JSON.stringify({ rules: text }) });
    await loadRules();
  }, [loadRules]);

  const handleTestRules = useCallback(async (file, text) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('rules', text);
    const res = await fetch(buildApiUrl('/intel/rules/test'), {
      method: 'POST',
      body: fd,
      headers: { Authorization: `Bearer ${runtimeSessionToken}` },
    });
    return res.json();
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

  const loadContentFilter = useCallback(async () => {
    setContentFilterData((current) => ({ ...current, loading: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter');
      setContentFilterData((current) => ({
        ...current,
        policy: payload?.policy || null,
        categories: payload?.categories || [],
        runtime: payload?.runtime || null,
        loading: false,
        error: '',
      }));
    } catch (error) {
      setContentFilterData((current) => ({ ...current, loading: false, error: error.message || 'Could not load content-filter policy.' }));
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

  const handleScanFiles = useCallback(async (files, options = {}) => {
    setProtectionData((current) => ({ ...current, scanLoading: true, error: '' }));
    try {
      const formData = new FormData();
      files.forEach((file, index) => {
        const filename = file?.name || `scan-${index + 1}.bin`;
        formData.append('files', file, filename);
      });
      formData.append('providersSpecified', 'true');
      (options.providers || []).forEach((provider) => {
        formData.append('providers[]', provider);
      });
      formData.append('hybridAnalysisOptInPublic', String(Boolean(options.hybridAnalysisOptInPublic)));

      const payload = await requestJson('/antivirus/scan', { method: 'POST', body: formData });

      setProtectionData((current) => ({
        ...current,
        scanLoading: false,
        lastResults: payload?.results || [],
        recentJobs: [
          ...((payload?.results || []).map((result) => result?.sandboxJob).filter(Boolean)),
          ...current.recentJobs,
        ].slice(0, 8),
        error: '',
      }));

      await Promise.all([loadProtection(), fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setProtectionData((current) => ({ ...current, scanLoading: false, error: error.message || 'Could not complete scan.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents, loadProtection]);

  const handleRunEicarSelfTest = useCallback(async (options = {}) => {
    const eicarFile = new File([EICAR_SELF_TEST_CONTENT], 'eicar-self-test.txt', {
      type: 'text/plain',
    });

    return handleScanFiles([eicarFile], options);
  }, [handleScanFiles]);

  const handleSubmitProtectionUrl = useCallback(async (url, options = {}) => {
    setProtectionData((current) => ({ ...current, urlSubmitLoading: true, urlSubmitError: '', error: '' }));
    try {
      const payload = await requestJson('/antivirus/submit-url', {
        method: 'POST',
        body: JSON.stringify({
          url,
          hybridAnalysisOptInPublic: Boolean(options.hybridAnalysisOptInPublic),
        }),
      });

      setProtectionData((current) => ({
        ...current,
        urlSubmitLoading: false,
        urlSubmitError: '',
        recentJobs: [payload?.job, ...current.recentJobs].filter(Boolean).slice(0, 8),
      }));

      await Promise.all([loadProtection(), fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setProtectionData((current) => ({
        ...current,
        urlSubmitLoading: false,
        urlSubmitError: error.message || 'Could not submit URL.',
      }));
      throw error;
    }
  }, [fetchDashboard, loadEvents, loadProtection]);

  const handlePollAnalysis = useCallback(async (jobId) => {
    setProtectionData((current) => ({ ...current, pollingJobId: jobId, error: '', urlSubmitError: '' }));
    try {
      const payload = await requestJson(`/antivirus/analysis/${jobId}/poll`, { method: 'POST' });
      setProtectionData((current) => ({
        ...current,
        pollingJobId: '',
        recentJobs: current.recentJobs.map((job) => (job.id === jobId ? payload?.job || job : job)),
        lastResults: current.lastResults.map((result) => (
          result?.sandboxJob?.id === jobId
            ? {
                ...result,
                sandboxJob: {
                  ...result.sandboxJob,
                  ...payload?.job,
                },
              }
            : result
        )),
      }));
      await Promise.all([loadProtection(), fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setProtectionData((current) => ({ ...current, pollingJobId: '', error: error.message || 'Could not poll analysis job.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents, loadProtection]);

  const handleOpenNativeCleanup = useCallback(async () => {
    setCleanupData((current) => ({ ...current, actionLoading: 'native', error: '', message: '' }));
    try {
      const payload = await requestJson('/cleanup/open-native', { method: 'POST' });
      setCleanupData((current) => ({
        ...current,
        actionLoading: '',
        error: '',
        message: payload?.message || 'Native cleanup launched.',
      }));
    } catch (error) {
      setCleanupData((current) => ({ ...current, actionLoading: '', error: error.message || 'Could not open native cleanup.' }));
    }
  }, []);

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

  const handleSaveContentFilterPolicy = useCallback(async (policyPatch) => {
    setContentFilterData((current) => ({ ...current, saving: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter', {
        method: 'PATCH',
        body: JSON.stringify(policyPatch),
      });

      setContentFilterData((current) => ({
        ...current,
        policy: payload?.policy || current.policy,
        categories: payload?.categories || current.categories,
        runtime: payload?.runtime || current.runtime,
        saving: false,
        error: '',
        message: payload?.message || 'Content-filter policy updated.',
      }));

      await Promise.all([fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setContentFilterData((current) => ({ ...current, saving: false, error: error.message || 'Could not save content-filter policy.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents]);

  const handleSyncContentFilter = useCallback(async () => {
    setContentFilterData((current) => ({ ...current, syncing: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter/sync', { method: 'POST' });
      setContentFilterData((current) => ({
        ...current,
        policy: payload?.policy || current.policy,
        categories: payload?.categories || current.categories,
        runtime: payload?.runtime || current.runtime,
        syncing: false,
        error: '',
        message: payload?.message || 'Content-filter sources synchronized.',
      }));
      await Promise.all([fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setContentFilterData((current) => ({ ...current, syncing: false, error: error.message || 'Could not sync content-filter sources.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents]);

  const handleApplyContentFilter = useCallback(async (policyPatch) => {
    setContentFilterData((current) => ({ ...current, applying: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter/apply', {
        method: 'POST',
        body: JSON.stringify(policyPatch),
      });
      setContentFilterData((current) => ({
        ...current,
        policy: payload?.policy || current.policy,
        categories: payload?.categories || current.categories,
        runtime: payload?.runtime || current.runtime,
        applying: false,
        error: '',
        message: payload?.message || 'Content-filter policy applied.',
      }));
      await Promise.all([fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setContentFilterData((current) => ({ ...current, applying: false, error: error.message || 'Could not apply content-filter policy.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents]);

  const handleRemoveContentFilter = useCallback(async () => {
    setContentFilterData((current) => ({ ...current, removing: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter/remove', { method: 'POST' });
      setContentFilterData((current) => ({
        ...current,
        policy: payload?.policy || current.policy,
        categories: payload?.categories || current.categories,
        runtime: payload?.runtime || current.runtime,
        removing: false,
        error: '',
        message: payload?.message || 'Content-filter entries removed.',
      }));
      await Promise.all([fetchDashboard(), loadEvents()]);
      return payload;
    } catch (error) {
      setContentFilterData((current) => ({ ...current, removing: false, error: error.message || 'Could not remove content-filter entries.' }));
      throw error;
    }
  }, [fetchDashboard, loadEvents]);

  const loadGeoFilter = useCallback(async () => {
    setGeoFilterData((c) => ({ ...c, loading: true, error: '' }));
    try {
      const payload = await requestJson('/geo-filter');
      setGeoFilterData((c) => ({
        ...c,
        enabled: Boolean(payload?.enabled),
        blockedCountries: payload?.blockedCountries || [],
        syncStatus: payload?.syncStatus || c.syncStatus,
        loading: false,
      }));
    } catch (err) {
      setGeoFilterData((c) => ({ ...c, loading: false, error: err.message }));
    }
  }, []);


  const handleCheckContentFilterDomain = useCallback(async (domain) => {
    setContentFilterData((current) => ({ ...current, checking: true, error: '', message: '' }));
    try {
      const payload = await requestJson('/content-filter/check', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      });
      setContentFilterData((current) => ({
        ...current,
        checking: false,
        error: '',
        checkResult: payload?.result || null,
      }));
      return payload;
    } catch (error) {
      setContentFilterData((current) => ({ ...current, checking: false, error: error.message || 'Could not check the requested domain.' }));
      throw error;
    }
  }, []);

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

    if (activePage === 'dashboard' || activePage === 'telemetry' || activePage === 'platform') {
      loadTelemetry();
    }

    if (activePage === 'cleanup') {
      loadCleanup();
    }

    if (activePage === 'events') {
      loadEvents();
    }

    if (activePage === 'mitre') {
      loadMitre();
    }

    if (activePage === 'intel') {
      loadIntel();
    }

    if (activePage === 'honeypots') {
      loadHoneypots();
    }

    if (activePage === 'rules') {
      loadRules();
    }

    if (activePage === 'controls') {
      loadControls();
    }

    if (activePage === 'filtering') {
      loadContentFilter();
    }

    if (activePage === 'geoblocking') {
      loadGeoFilter();
    }
  }, [activePage, loadCleanup, loadContentFilter, loadControls, loadEvents, loadFirewall, loadGeoFilter, loadProtection, loadTelemetry, loadMitre, loadIntel, loadHoneypots, loadRules]);

  return (
    <div className="control-app">
      <Sidebar active={activePage} onNavigate={setActivePage} />

      <div className="control-main">
        {connStatus === 'error' ? (
          <div className="conn-banner conn-banner--error">
            <span>
              Backend unavailable at <code>{buildApiUrl('/status')}</code>. {connMessage}
              {backendRestartMessage ? <span className="conn-banner__note"> {backendRestartMessage}</span> : null}
            </span>
            <button
              className="control-btn control-btn--primary conn-banner__action"
              disabled={backendRestarting}
              onClick={handleRestartBackend}
              type="button"
            >
              {backendRestarting ? 'Restarting...' : 'Restart Backend'}
            </button>
          </div>
        ) : null}

        {connStatus === 'connecting' ? <div className="conn-banner conn-banner--info">Connecting to backend...</div> : null}
        <LiveAlertsBanner alerts={liveAlerts} />
        {activePage === 'dashboard' ? (
          <Dashboard
            data={serverData}
            onNavigate={setActivePage}
            onRefresh={refreshDashboard}
            onTelemetryRefresh={loadTelemetry}
            telemetryData={telemetryData.data}
            telemetryError={telemetryData.error}
            telemetryLoading={telemetryData.loading}
          />
        ) : null}
        {activePage === 'mitre' ? <MitrePage matrix={mitreData.matrix} intel={mitreData.intel} memoryScan={mitreData.memoryScan} loading={mitreData.loading} onRefresh={loadMitre} /> : null}
        {activePage === 'memory' ? <MemoryScanPage data={memoryData} loading={memoryData.loading} onScan={handleMemoryScan} /> : null}
        {activePage === 'intel' ? <ThreatIntelPage intel={intelData.intel} loading={intelData.loading} onRefresh={loadIntel} onReset={handleResetIntel} /> : null}
        {activePage === 'honeypots' ? <HoneypotsPage data={honeypotsData} loading={honeypotsData.loading} onRefresh={loadHoneypots} onPlant={handlePlantHoneypots} onCheck={handleCheckHoneypots} onRemove={handleRemoveAllHoneypots} /> : null}
        {activePage === 'rules' ? <RulesPage rulesText={rulesData.rules} onSave={handleSaveRules} onTest={handleTestRules} /> : null}
        {activePage === 'platform' ? (
          <PlatformPage data={telemetryData.data} error={telemetryData.error} loading={telemetryData.loading} onRefresh={loadTelemetry} />
        ) : null}
        {activePage === 'cleanup' ? (
          <CleanupPage
            actionLoading={cleanupData.actionLoading}
            data={cleanupData.data}
            error={cleanupData.error}
            lastResult={cleanupData.lastResult}
            loading={cleanupData.loading}
            message={cleanupData.message}
            onOpenNative={handleOpenNativeCleanup}
            onRefresh={loadCleanup}
            platformInfo={telemetryData.data?.os || serverData?.os}
          />
        ) : null}
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
        {activePage === 'filtering' ? (
          <ContentFilterPage
            data={contentFilterData}
            error={contentFilterData.error}
            loading={contentFilterData.loading}
            onApply={handleApplyContentFilter}
            onCheck={handleCheckContentFilterDomain}
            onRefresh={loadContentFilter}
            onRemove={handleRemoveContentFilter}
            onSavePolicy={handleSaveContentFilterPolicy}
            onSync={handleSyncContentFilter}
          />
        ) : null}
        {activePage === 'protection' ? (
          <ProtectionPage
            data={protectionData}
            onPollAnalysis={handlePollAnalysis}
            onRefresh={loadProtection}
            onRunSelfTest={handleRunEicarSelfTest}
            onScan={handleScanFiles}
            onSubmitUrl={handleSubmitProtectionUrl}
          />
        ) : null}
        {activePage === 'telemetry' ? (
          <TelemetryPage data={telemetryData.data} error={telemetryData.error} loading={telemetryData.loading} onRefresh={loadTelemetry} />
        ) : null}
        {activePage === 'events' ? <EventsPage data={eventsData.events} error={eventsData.error} loading={eventsData.loading} onRefresh={loadEvents} /> : null}
        {activePage === 'geoblocking' ? (
          <GeoFilterPage data={geoFilterData} onRefresh={loadGeoFilter} />
        ) : null}
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
