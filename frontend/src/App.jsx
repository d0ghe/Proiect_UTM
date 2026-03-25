import { startTransition, useCallback, useEffect, useState } from 'react';
import './App.css';
import ContentFilterPage from './ContentFilterPage.jsx';

const POLL_INTERVAL = 8000;
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
    gpu_percent: pickFirst(payload?.gpu_percent, toNumber(payload?.gpu?.usagePercent)),
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

function Sidebar({ active, onNavigate }) {
  return (
    <aside className="control-sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark brand-mark--icon" aria-hidden="true">
          <i className="bi bi-bezier2" />
        </span>
        <div className="brand-copy">
          <span className="brand-label">Containment Atlas</span>
          <span className="brand-sub">policy cartography for local defense</span>
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
          <span className="device-name">atlas-node-01</span>
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
        breadcrumb="Containment Atlas / Overview"
        title="Atlas Command Surface"
        subtitle="Runtime posture, active containment layers, provider findings, and machine health mapped into one operator workspace."
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
        <StatCard accent="blue" label="GPU Usage" value={formatPercent(data?.gpu_percent, 'Unavailable')} />
      </div>

      <div className="module-grid">
        <ModuleCard title="Telemetry" tag="TEL-01" status="Live" action="Open Telemetry" onAction={() => onNavigate('telemetry')}>
          <p className="module-desc">
            Real-time host metrics gathered from the local backend, focused on values this machine exposes reliably.
          </p>
          <div className="telemetry-grid">
            <TelemetryCard label="CPU" value={formatPercent(data?.cpu_percent)} />
            <TelemetryCard label="RAM" value={formatPercent(data?.ram_percent)} />
            <TelemetryCard label="GPU" value={formatPercent(data?.gpu_percent, 'Unavailable')} />
            <TelemetryCard label="RX Rate" value={formatRate(data?.rx_rate)} />
            <TelemetryCard label="TX Rate" value={formatRate(data?.tx_rate)} />
            <TelemetryCard label="Clients" value={formatInteger(data?.connected_clients)} />
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
            Hosts-based containment for adult content, ads, malware, gambling, piracy, social platforms, and DNS-bypass routes.
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
        breadcrumb="Containment Atlas / Firewall"
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
        breadcrumb="Containment Atlas / Protection"
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

              <div className="provider-chip-row">
                {(Array.isArray(result.providers) ? result.providers : []).map((provider) => (
                  <span className="meta-chip" key={`${result.filename}-${provider.id}`}>
                    {provider.name}: {provider.verdict || provider.status}
                  </span>
                ))}
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
  const telemetry = data || {};

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Containment Atlas / Telemetry"
        title="Telemetry"
        subtitle="Detailed host runtime, CPU, memory, GPU, and interface data from the backend telemetry layer."
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
        <StatCard accent="blue" label="GPU Usage" value={formatPercent(telemetry.gpu_percent ?? telemetry.gpu?.usagePercent, 'Unavailable')} />
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

          <section className="panel-card">
            <div className="panel-card__header">
              <div>
                <p className="panel-kicker">Graphics</p>
                <h3>GPU Monitor</h3>
              </div>
            </div>
            <div className="detail-grid">
              <DataPair label="Model" value={formatDisplay(telemetry.gpu?.model, 'Unavailable')} />
              <DataPair label="Usage" value={formatPercent(telemetry.gpu?.usagePercent, 'Unavailable')} />
              <DataPair label="Adapters" value={formatInteger(telemetry.gpu?.controllers?.length)} />
              <DataPair label="Source" value={formatDisplay(telemetry.gpu?.source, 'Unavailable')} />
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
        breadcrumb="Containment Atlas / Platform"
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
                  <p className="panel-kicker">Host Identity</p>
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
                  <p className="panel-kicker">Mini Wireshark</p>
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
                <p className="panel-kicker">Mini Wireshark</p>
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

function CleanupPage({ actionLoading, data, error, lastResult, loading, message, onClearTempFiles, onOpenNative, onRefresh, platformInfo }) {
  const nativeAction = data?.nativeAction || {};
  const tempTargets = Array.isArray(data?.tempTargets) ? data.tempTargets : [];

  return (
    <div className="page-content">
      <PageHeader
        breadcrumb="Containment Atlas / Cleanup"
        title="Cleanup"
        subtitle="Use the native cleanup tool for this platform or clear temp files directly from the console."
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
                  <button
                    className="control-btn control-btn--amber"
                    disabled={actionLoading === 'temp'}
                    onClick={onClearTempFiles}
                    type="button"
                  >
                    {actionLoading === 'temp' ? 'Cleaning...' : 'Delete Temp Files'}
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
        breadcrumb="Containment Atlas / Events"
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
        breadcrumb="Containment Atlas / Controls"
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

  const handleClearTempFiles = useCallback(async () => {
    setCleanupData((current) => ({ ...current, actionLoading: 'temp', error: '', message: '' }));
    try {
      const payload = await requestJson('/cleanup/temp-files', { method: 'POST' });
      setCleanupData((current) => ({
        ...current,
        actionLoading: '',
        error: '',
        message: payload?.message || 'Temp files removed.',
        lastResult: payload?.result || null,
      }));
      await fetchDashboard();
    } catch (error) {
      setCleanupData((current) => ({ ...current, actionLoading: '', error: error.message || 'Could not clear temp files.' }));
    }
  }, [fetchDashboard]);

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

    if (activePage === 'telemetry' || activePage === 'platform') {
      loadTelemetry();
    }

    if (activePage === 'cleanup') {
      loadCleanup();
    }

    if (activePage === 'events') {
      loadEvents();
    }

    if (activePage === 'controls') {
      loadControls();
    }

    if (activePage === 'filtering') {
      loadContentFilter();
    }
  }, [activePage, loadCleanup, loadContentFilter, loadControls, loadEvents, loadFirewall, loadProtection, loadTelemetry]);

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
            onClearTempFiles={handleClearTempFiles}
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
