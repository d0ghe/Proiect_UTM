import { useCallback, useEffect, useState } from 'react';
import './App.css';

const BACKEND_URL = import.meta.env.VITE_STATUS_URL ?? 'http://192.168.10.124:5000/api/status';
const API_TOKEN = import.meta.env.VITE_PLATFORM_TOKEN ?? 'utm-auth-token-1773500227333';
const POLL_INTERVAL = 8000;

// The backend blocks requests without a Bearer token.
// Any future fetch or axios call should send the same Authorization header.
const REQUEST_HEADERS = {
  Accept: 'application/json',
  Authorization: `Bearer ${API_TOKEN}`,
};

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid-1x2' },
  { id: 'firewall', label: 'Firewall', icon: 'shield-shaded' },
  { id: 'protection', label: 'Protection', icon: 'activity' },
  { id: 'telemetry', label: 'Telemetry', icon: 'diagram-3' },
  { id: 'events', label: 'Events', icon: 'terminal' },
  { id: 'controls', label: 'Controls', icon: 'sliders' },
];

function pickFirst(...values) {
  return values.find((value) => value !== null && value !== undefined && value !== '');
}

function formatTemperature(data) {
  const raw = pickFirst(
    data?.temperature_c,
    data?.temperature,
    data?.cpu_temp,
    data?.cpu_temp_c,
    data?.cpu_temperature,
    data?.temp,
    data?.temp_c,
  );

  if (raw === undefined) {
    return '-';
  }

  const numeric = Number(raw);
  if (Number.isFinite(numeric)) {
    const digits = Number.isInteger(numeric) ? 0 : 1;
    return `${numeric.toFixed(digits)} C`;
  }

  return String(raw);
}

function formatPercent(value) {
  if (value === undefined) {
    return '-';
  }

  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${numeric}%` : String(value);
}

function formatDisplay(value) {
  return value === undefined ? '-' : String(value);
}

function StatusBadge({ value }) {
  const isActive = value === 'Active' || value === 'Online' || value === 'Operational';
  const isInactive = value === 'Inactive' || value === 'Offline';
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
      {meta && <p className="stat-meta">{meta}</p>}
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
      {action && (
        <div className="module-footer">
          <button className="control-btn" onClick={onAction} type="button">
            {action}
          </button>
        </div>
      )}
    </div>
  );
}

function Sidebar({ active, onNavigate }) {
  return (
    <aside className="control-sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark brand-mark--icon" aria-hidden="true">
          <i className="bi bi-cpu-fill" />
        </span>
        <div className="brand-copy">
          <span className="brand-label">Sentinel Core</span>
          <span className="brand-sub">edge security console</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? 'nav-item--active' : ''}`}
            onClick={() => onNavigate(item.id)}
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
          <span className="device-name">edge-node-01</span>
        </div>
      </div>
    </aside>
  );
}

function Dashboard({ data, onRefresh }) {
  const uptime = formatDisplay(pickFirst(data?.uptime, data?.uptime_human, data?.boot_time));
  const platform = formatDisplay(pickFirst(data?.platform, data?.system, data?.hostname));
  const systemStatus = formatDisplay(pickFirst(data?.status, data?.health, data?.state, 'Unknown'));
  const firewall = formatDisplay(pickFirst(data?.firewall, data?.firewall_status, 'Unknown'));
  const protection = formatDisplay(pickFirst(data?.antivirus, data?.protection, data?.antivirus_status, 'Unknown'));
  const cpu = pickFirst(data?.cpu_percent, data?.cpu, data?.cpu_usage);
  const ram = pickFirst(data?.ram_percent, data?.memory_percent, data?.ram_usage);
  const temperature = formatTemperature(data);

  const rulesActive = formatDisplay(pickFirst(data?.rules_active, data?.firewall_rules_count, data?.rules_count));
  const blockedToday = formatDisplay(pickFirst(data?.blocked_today, data?.threats_blocked, data?.blocked_requests));
  const allowedToday = formatDisplay(pickFirst(data?.allowed_today, data?.allowed_requests, data?.connections_allowed));

  const filesScanned = formatDisplay(pickFirst(data?.files_scanned, data?.scan_count, data?.objects_scanned));
  const threatsFound = formatDisplay(pickFirst(data?.threats_found, data?.malware_found, data?.detections_today));
  const quarantined = formatDisplay(pickFirst(data?.quarantined, data?.quarantine_count, data?.isolated_hosts));

  const alertsToday = formatDisplay(pickFirst(data?.alerts_today, data?.ids_alerts, data?.events_today));
  const highSeverity = formatDisplay(pickFirst(data?.high_severity, data?.critical_alerts, data?.severity_high));
  const rulesLoaded = formatDisplay(pickFirst(data?.ids_rules_loaded, data?.rules_loaded, data?.signatures_loaded));

  const requestsToday = formatDisplay(pickFirst(data?.requests_today, data?.proxy_requests, data?.web_requests));
  const blockedUrls = formatDisplay(pickFirst(data?.blocked_urls, data?.blocked_domains, data?.blocked_sites));
  const categories = formatDisplay(pickFirst(data?.categories, data?.filter_categories, data?.policy_groups));

  const activeClients = formatDisplay(pickFirst(data?.connected_clients, data?.clients_online, data?.active_connections));
  const rxTraffic = formatDisplay(pickFirst(data?.rx_rate, data?.network_rx, data?.download_rate));
  const txTraffic = formatDisplay(pickFirst(data?.tx_rate, data?.network_tx, data?.upload_rate));

  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Sentinel / Overview</p>
          <h1 className="page-title">Operations Dashboard</h1>
        </div>
        <div className="header-meta">
          <span className="last-updated">
            Live <span className="live-dot" />
          </span>
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh
          </button>
        </div>
      </div>

      <div className="stat-strip">
        <StatCard accent="neutral" label="Platform" value={platform} />
        <StatCard accent="green" label="System" value={systemStatus} />
        <StatCard accent="amber" label="Temperature" value={temperature} meta="hardware" />
        <StatCard accent="neutral" label="Uptime" value={uptime} />
        <StatCard accent={Number(cpu) > 80 ? 'red' : 'blue'} label="CPU Usage" value={formatPercent(cpu)} meta="processor" />
        <StatCard
          accent={Number(ram) > 85 ? 'red' : 'blue'}
          label="RAM Usage"
          value={formatPercent(ram)}
          meta={data?.ram_used_mb ? `${data.ram_used_mb} MB used` : 'memory'}
        />
      </div>

      <div className="module-grid">
        <ModuleCard title="System Stats" tag="SYS-01" status={systemStatus} action="Refresh Telemetry" onAction={onRefresh}>
          <p className="module-desc">
            Live operational telemetry for the edge node. Temperature and runtime stats stay visible next to security controls.
          </p>
          <div className="telemetry-grid">
            <TelemetryCard label="Temperature" value={temperature} />
            <TelemetryCard label="Active Clients" value={activeClients} />
            <TelemetryCard label="RX Traffic" value={rxTraffic} />
            <TelemetryCard label="TX Traffic" value={txTraffic} />
            <TelemetryCard label="CPU" value={formatPercent(cpu)} />
            <TelemetryCard label="RAM" value={formatPercent(ram)} />
          </div>
        </ModuleCard>

        <ModuleCard title="Firewall" tag="NET-01" status={firewall} action="Manage Rules">
          <p className="module-desc">
            Packet filtering via iptables or nftables. Controls ingress and egress traffic between WAN and LAN interfaces based on defined rulesets.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{rulesActive}</span>
              <span className="mini-stat-label">Rules Active</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{blockedToday}</span>
              <span className="mini-stat-label">Blocked Today</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{allowedToday}</span>
              <span className="mini-stat-label">Allowed</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Protection" tag="SEC-01" status={protection} action="Run Scan">
          <p className="module-desc">
            Malware protection integrated with proxy and endpoint services. Surfaces scan counts, detections, and quarantine activity.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{filesScanned}</span>
              <span className="mini-stat-label">Files Scanned</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{threatsFound}</span>
              <span className="mini-stat-label">Threats Found</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{quarantined}</span>
              <span className="mini-stat-label">Quarantined</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Intrusion Detection" tag="IDS-01" status="Inactive" action="Configure IDS">
          <p className="module-desc">
            Suricata or Snort for real-time traffic analysis. Detects known attack patterns, port scans, and unusual behavior across interfaces.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{alertsToday}</span>
              <span className="mini-stat-label">Alerts Today</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{highSeverity}</span>
              <span className="mini-stat-label">High Severity</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{rulesLoaded}</span>
              <span className="mini-stat-label">Rules Loaded</span>
            </div>
          </div>
        </ModuleCard>

        <ModuleCard title="Content Filter" tag="PRX-01" status="Inactive" action="Edit Categories">
          <p className="module-desc">
            Proxy-based content filtering enforces browsing policy for clients on the network and tracks blocked requests by category.
          </p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{requestsToday}</span>
              <span className="mini-stat-label">Requests Today</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{blockedUrls}</span>
              <span className="mini-stat-label">Blocked URLs</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{categories}</span>
              <span className="mini-stat-label">Categories</span>
            </div>
          </div>
        </ModuleCard>
      </div>
    </div>
  );
}

function Placeholder({ page }) {
  return (
    <div className="page-content">
      <div className="page-header">
        <div>
          <p className="page-breadcrumb">Sentinel / {page}</p>
          <h1 className="page-title">{page}</h1>
        </div>
      </div>
      <div className="coming-soon">
        <p className="coming-title">Module under construction</p>
        <p className="coming-sub">This section will be available once the backend endpoint is wired up.</p>
      </div>
    </div>
  );
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [serverData, setServerData] = useState(null);
  const [connStatus, setConnStatus] = useState('connecting');
  const [connMessage, setConnMessage] = useState('Connecting to backend...');

  const fetchData = useCallback(async () => {
    try {
      const response = await fetch(BACKEND_URL, {
        headers: REQUEST_HEADERS,
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error('Unauthorized. Send Authorization: Bearer <token> on every request.');
        }

        throw new Error(`HTTP ${response.status}`);
      }

      const payload = await response.json();
      setServerData(payload);
      setConnStatus('ok');
      setConnMessage('Live telemetry connected.');
    } catch (error) {
      setConnStatus('error');
      setConnMessage(error.message || 'Connection failed.');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const intervalId = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(intervalId);
  }, [fetchData]);

  return (
    <div className="control-app">
      <Sidebar active={activePage} onNavigate={setActivePage} />

      <div className="control-main">
        {connStatus === 'error' && (
          <div className="conn-banner conn-banner--error">
            Backend unreachable or blocked at <code>{BACKEND_URL}</code>. {connMessage}
          </div>
        )}
        {connStatus === 'connecting' && (
          <div className="conn-banner conn-banner--info">Connecting to backend...</div>
        )}

        {activePage === 'dashboard' && <Dashboard data={serverData} onRefresh={fetchData} />}
        {activePage !== 'dashboard' && (
          <Placeholder page={NAV_ITEMS.find((item) => item.id === activePage)?.label ?? activePage} />
        )}
      </div>
    </div>
  );
}
