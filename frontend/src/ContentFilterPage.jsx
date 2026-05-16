import { useEffect, useState } from 'react';

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

function formatInteger(value, fallback = '0') {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${Math.round(numeric)}` : fallback;
}

function textAreaValueFromList(value) {
  if (!Array.isArray(value) || value.length === 0) {
    return '';
  }

  return value.join('\n');
}

export default function ContentFilterPage({
  data,
  error,
  loading,
  onApply,
  onCheck,
  onRefresh,
  onRemove,
  onSavePolicy,
  onSync,
}) {
  const [enabled, setEnabled] = useState(false);
  const [categories, setCategories] = useState({});
  const [customBlocklist, setCustomBlocklist] = useState('');
  const [allowlist, setAllowlist] = useState('');
  const [domainCheck, setDomainCheck] = useState('');

  /* eslint-disable react-hooks/set-state-in-effect */
  useEffect(() => {
    setEnabled(Boolean(data?.policy?.enabled));
    setCategories(data?.policy?.categories || {});
    setCustomBlocklist(textAreaValueFromList(data?.policy?.customBlocklist));
    setAllowlist(textAreaValueFromList(data?.policy?.allowlist));
  }, [data?.policy]);
  /* eslint-enable react-hooks/set-state-in-effect */

  const runtime = data?.runtime || {};
  const environment = runtime.environment || {};
  const categoriesMeta = Array.isArray(data?.categories) ? data.categories : [];
  const busy = Boolean(loading || data?.saving || data?.syncing || data?.applying || data?.removing);
  const warningMessage = data?.message || runtime.lastMessage || '';
  const checkResult = data?.checkResult;
  const enforcementLabel = runtime.enforcementMode === 'proxy'
    ? 'Proxy'
    : 'None';
  const categoryIds = categoriesMeta.map((category) => category.id).filter(Boolean);
  const allCategoriesSelected = categoryIds.length > 0 && categoryIds.every((id) => categories[id]);

  function buildPayload() {
    return {
      enabled,
      categories,
      customBlocklist,
      allowlist,
    };
  }

  async function handleSavePolicy() {
    await onSavePolicy(buildPayload());
  }

  async function handleApplyPolicy() {
    await onApply(buildPayload());
  }

  function setAllCategories(value) {
    setCategories((current) => ({
      ...current,
      ...Object.fromEntries(categoryIds.map((id) => [id, value])),
    }));
  }

  return (
    <div className="page-content content-filter-page">
      <div className="page-header page-header--atlas">
        <div>
          <p className="page-breadcrumb">Argus / Policy Mesh</p>
          <h1 className="page-title">Content Filtering</h1>
          <p className="page-subtitle">
            Build a local proxy policy for adult content, ads, malware, gambling, social media, and custom domains.
          </p>
        </div>

        <div className="header-meta atlas-toolbar">
          <span className={`atlas-status ${enabled ? 'atlas-status--active' : 'atlas-status--idle'}`}>
            {enabled ? 'Policy Armed' : 'Policy Idle'}
          </span>
          <button className="control-btn control-btn--ghost" onClick={onRefresh} type="button">
            Refresh
          </button>
        </div>
      </div>

      <div className="stat-strip atlas-stat-strip">
        <div className="stat-card accent-green">
          <p className="stat-label">Managed Domains</p>
          <p className="stat-value">{formatInteger(runtime.appliedDomainCount)}</p>
          <p className="stat-meta">currently loaded into the proxy block cache</p>
        </div>
        <div className="stat-card accent-blue">
          <p className="stat-label">Enabled Categories</p>
          <p className="stat-value">{formatInteger(runtime.enabledCategoryIds?.length)}</p>
          <p className="stat-meta">category feeds currently selected</p>
        </div>
        <div className="stat-card accent-amber">
          <p className="stat-label">Last Sync</p>
          <p className="stat-value atlas-stat-value--compact">{formatDateTime(runtime.lastSyncedAt)}</p>
          <p className="stat-meta">remote feeds cached locally before apply</p>
        </div>
        <div className="stat-card accent-neutral">
          <p className="stat-label">Enforcement</p>
          <p className="stat-value atlas-stat-value--compact">{enforcementLabel}</p>
          <p className="stat-meta">{environment.permissionMessage || 'local proxy enforcement'}</p>
        </div>
      </div>

      {error ? <p className="form-message form-message--error">{error}</p> : null}
      {!error && warningMessage ? <p className="form-message form-message--success">{warningMessage}</p> : null}

      <div className="atlas-panel-grid">
        <section className="panel-card atlas-hero-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Containment Mode</p>
              <h3>Proxy Enforcement</h3>
            </div>
            <span className={`toggle-pill ${enabled ? 'toggle-pill--on' : 'toggle-pill--off'}`}>
              {enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>

          <div className="atlas-hero-copy">
            <p className="module-desc">
              This policy is enforced by the Argus local browser proxy. Domain lists stay in memory and requests are blocked before
              HTTP or HTTPS connections are opened.
            </p>

            <label className="atlas-switch" htmlFor="content-filter-enabled">
              <input
                checked={enabled}
                id="content-filter-enabled"
                onChange={(event) => setEnabled(event.target.checked)}
                type="checkbox"
              />
              <span>Arm the policy for the next apply</span>
            </label>
          </div>

          <div className="module-footer atlas-footer-actions">
            <button className="control-btn control-btn--ghost" disabled={busy} onClick={handleSavePolicy} type="button">
              {data?.saving ? 'Saving...' : 'Save Policy'}
            </button>
            <button className="control-btn" disabled={busy} onClick={onSync} type="button">
              {data?.syncing ? 'Syncing...' : 'Sync Sources'}
            </button>
            <button className="control-btn control-btn--primary" disabled={busy} onClick={handleApplyPolicy} type="button">
              {data?.applying ? 'Applying...' : 'Apply To Proxy'}
            </button>
            <button className="control-btn control-btn--danger" disabled={busy} onClick={onRemove} type="button">
              {data?.removing ? 'Removing...' : 'Clear Proxy'}
            </button>
          </div>
        </section>

        <section className="panel-card atlas-side-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Environment</p>
              <h3>Runtime Status</h3>
            </div>
          </div>

          <div className="detail-grid">
            <div className="detail-row">
              <span>Platform</span>
              <strong>{environment.platform || '-'}</strong>
            </div>
            <div className="detail-row">
              <span>Proxy Address</span>
              <strong>{runtime.proxyAddress || environment.proxyAddress || '-'}</strong>
            </div>
            <div className="detail-row">
              <span>Auto Proxy</span>
              <strong>{runtime.proxyEnabled ? 'On' : 'Off'}</strong>
            </div>
            <div className="detail-row">
              <span>Proxy Server</span>
              <strong>{runtime.proxyRunning || environment.proxyRunning ? 'Running' : 'Stopped'}</strong>
            </div>
            <div className="detail-row">
              <span>QUIC Guard</span>
              <strong>{runtime.quicBlocked ? 'On' : 'Off'}</strong>
            </div>
            <div className="detail-row">
              <span>Cache Status</span>
              <strong>{runtime.proxyMessage || '-'}</strong>
            </div>
            <div className="detail-row">
              <span>Last Apply</span>
              <strong>{formatDateTime(runtime.lastApplyAt)}</strong>
            </div>
          </div>
        </section>
      </div>

      <section className="panel-card page-section-gap">
        <div className="panel-card__header">
          <div>
            <p className="panel-kicker">Category Matrix</p>
            <h3>Threat Feeds</h3>
          </div>
          <div className="atlas-category-actions">
            <button
              className="control-btn control-btn--ghost"
              disabled={busy || allCategoriesSelected}
              onClick={() => setAllCategories(true)}
              type="button"
            >
              Select All
            </button>
            <button
              className="control-btn control-btn--ghost"
              disabled={busy || categoryIds.length === 0}
              onClick={() => setAllCategories(false)}
              type="button"
            >
              Clear
            </button>
          </div>
        </div>

        {loading && categoriesMeta.length === 0 ? <div className="empty-state">Loading content-filter sources...</div> : null}

        <div className="atlas-category-grid">
          {categoriesMeta.map((category) => (
            <label className={`atlas-category-card ${categories[category.id] ? 'atlas-category-card--active' : ''}`} key={category.id}>
              <div className="atlas-category-card__top">
                <div>
                  <p className="panel-kicker">{category.sourceName}</p>
                  <h3>{category.label}</h3>
                </div>
                <input
                  checked={Boolean(categories[category.id])}
                  onChange={(event) => setCategories((current) => ({ ...current, [category.id]: event.target.checked }))}
                  type="checkbox"
                />
              </div>
              <p className="module-desc">{category.description}</p>
              <div className="atlas-chip-row">
                <span className="meta-chip">{formatInteger(category.domainCount)} domains</span>
                <span className="meta-chip">{category.enabled ? 'selected' : 'available'}</span>
              </div>
            </label>
          ))}
        </div>
      </section>

      <div className="atlas-panel-grid">
        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Custom Domains</p>
              <h3>Additional Blocklist</h3>
            </div>
          </div>
          <div className="field-grid field-grid--single">
            <div className="field-group field-group--wide">
              <label className="field-label" htmlFor="custom-blocklist">One domain per line</label>
              <textarea
                className="field-input field-input--textarea"
                id="custom-blocklist"
                onChange={(event) => setCustomBlocklist(event.target.value)}
                placeholder={'example.com\ntracking.example.net'}
                value={customBlocklist}
              />
            </div>
          </div>
        </section>

        <section className="panel-card">
          <div className="panel-card__header">
            <div>
              <p className="panel-kicker">Exception Mesh</p>
              <h3>Allowlist</h3>
            </div>
          </div>
          <div className="field-grid field-grid--single">
            <div className="field-group field-group--wide">
              <label className="field-label" htmlFor="custom-allowlist">Domains that must stay reachable</label>
              <textarea
                className="field-input field-input--textarea"
                id="custom-allowlist"
                onChange={(event) => setAllowlist(event.target.value)}
                placeholder={'school.example.org\nportal.company.com'}
                value={allowlist}
              />
            </div>
          </div>
        </section>
      </div>

      <section className="panel-card">
        <div className="panel-card__header">
          <div>
            <p className="panel-kicker">Route Test</p>
            <h3>Check A Domain</h3>
          </div>
        </div>

        <div className="field-grid field-grid--check">
          <div className="field-group">
            <label className="field-label" htmlFor="domain-check">Domain</label>
            <input
              className="field-input"
              id="domain-check"
              onChange={(event) => setDomainCheck(event.target.value)}
              placeholder="ads.example.com"
              value={domainCheck}
            />
          </div>

          <div className="form-actions">
            <button className="control-btn control-btn--primary" disabled={busy || !domainCheck.trim()} onClick={() => onCheck(domainCheck)} type="button">
              {data?.checking ? 'Checking...' : 'Check Domain'}
            </button>
          </div>
        </div>

        {checkResult ? (
          <div className="detail-grid detail-grid--wide">
            <div className="detail-row">
              <span>Blocked</span>
              <strong>{checkResult.blocked ? 'Yes' : 'No'}</strong>
            </div>
            <div className="detail-row">
              <span>Matched Domain</span>
              <strong>{checkResult.matchedDomain || '-'}</strong>
            </div>
            <div className="detail-row">
              <span>Reasons</span>
              <strong>{Array.isArray(checkResult.reasons) && checkResult.reasons.length > 0 ? checkResult.reasons.join(', ') : '-'}</strong>
            </div>
            <div className="detail-row">
              <span>Checked</span>
              <strong>{checkResult.domain || '-'}</strong>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
