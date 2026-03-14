import { useCallback, useEffect, useState } from 'react';
import './App.css';

// --- CONFIGURARE CONEXIUNE ---
// Schimbat de la IP-ul prietenului la localhost pentru a se "pupa" cu backend-ul tău
const BACKEND_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:5000';
const BACKEND_STATUS_URL = `${BACKEND_BASE_URL}/api/status`;

// Token-ul trebuie să fie același cu cel din backend/.env (JWT_SECRET sau ce folosești)
const API_TOKEN = import.meta.env.VITE_PLATFORM_TOKEN ?? 'utm-auth-token-1773500227333';
const POLL_INTERVAL = 5000; // Am scăzut la 5 secunde pentru un feeling mai "live"

const REQUEST_HEADERS = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${API_TOKEN}`,
};

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid-1x2' },
  { id: 'firewall', label: 'Firewall', icon: 'shield-shaded' },
  { id: 'protection', label: 'Protection', icon: 'activity' },
  { id: 'telemetry', label: 'Telemetry', icon: 'diagram-3' },
  { id: 'events', label: 'Events', icon: 'terminal' },
  { id: 'controls', label: 'Controls', icon: 'sliders' },
];

// --- HELPER FUNCTIONS ---
function pickFirst(...values) {
  return values.find((value) => value !== null && value !== undefined && value !== '');
}

function formatTemperature(data) {
  const raw = pickFirst(data?.temperature_c, data?.cpu_temp);
  if (raw === undefined) return '-';
  return `${Number(raw).toFixed(1)}°C`;
}

function formatPercent(value) {
  if (value === undefined) return '-';
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${numeric.toFixed(1)}%` : String(value);
}

function formatDisplay(value) {
  return value === undefined || value === null ? '-' : String(value);
}

// --- COMPONENTS ---
function StatusBadge({ value }) {
  const val = String(value).toLowerCase();
  const isActive = val === 'active' || val === 'online' || val === 'operational' || val === 'ok';
  const isInactive = val === 'inactive' || val === 'offline' || val === 'error';
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
  // Mapare date din backend
  const cpu = pickFirst(data?.cpu_usage, data?.cpu_percent, 0);
  const ram = pickFirst(data?.ram_usage, data?.ram_percent, 0);
  const systemStatus = formatDisplay(data?.status || 'Online');

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
        <StatCard accent="neutral" label="Platform" value={formatDisplay(data?.platform)} />
        <StatCard accent="green" label="System" value={systemStatus} />
        <StatCard accent="amber" label="Temperature" value={formatTemperature(data)} meta="hardware" />
        <StatCard accent="neutral" label="Uptime" value={formatDisplay(data?.uptime)} />
        <StatCard accent={Number(cpu) > 80 ? 'red' : 'blue'} label="CPU Usage" value={formatPercent(cpu)} meta="processor" />
        <StatCard accent={Number(ram) > 85 ? 'red' : 'blue'} label="RAM Usage" value={formatPercent(ram)} meta="memory" />
      </div>

      <div className="module-grid">
        <ModuleCard title="Protection" tag="SEC-01" status={systemStatus} action="Run Scan">
          <p className="module-desc">Monitorizare malware si activitate de carantina in timp real.</p>
          <div className="module-stats-row">
            <div className="mini-stat">
              <span className="mini-stat-value">{data?.files_scanned || 0}</span>
              <span className="mini-stat-label">Files Scanned</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{data?.threats_found || 0}</span>
              <span className="mini-stat-label">Threats Found</span>
            </div>
            <div className="mini-stat">
              <span className="mini-stat-value">{data?.quarantined || 0}</span>
              <span className="mini-stat-label">Quarantined</span>
            </div>
          </div>
        </ModuleCard>
        
        {/* Adaugă aici restul de ModuleCard-uri dacă vrei să le păstrezi pe toate */}
      </div>
    </div>
  );
}

function Placeholder({ page }) {
  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">{page}</h1>
      </div>
      <div className="coming-soon">Modul în construcție...</div>
    </div>
  );
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [serverData, setServerData] = useState(null);
  const [connStatus, setConnStatus] = useState('connecting');
  const [connMessage, setConnMessage] = useState('Connecting...');

  const fetchData = useCallback(async () => {
    try {
      const response = await fetch(BACKEND_STATUS_URL, {
        headers: REQUEST_HEADERS,
      });

      if (!response.ok) throw new Error(`Server Error: ${response.status}`);

      const payload = await response.json();
      setServerData(payload);
      setConnStatus('ok');
    } catch (error) {
      setConnStatus('error');
      setConnMessage(`Backend unreachable la ${BACKEND_STATUS_URL}. Asigura-te ca backend-ul e pornit!`);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  return (
    <div className="control-app">
      <Sidebar active={activePage} onNavigate={setActivePage} />
      <div className="control-main">
        {connStatus === 'error' && (
          <div className="conn-banner conn-banner--error">{connMessage}</div>
        )}
        {activePage === 'dashboard' ? (
          <Dashboard data={serverData} onRefresh={fetchData} />
        ) : (
          <Placeholder page={activePage} />
        )}
      </div>
    </div>
  );
}