const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const { CATEGORY_IDS, setBlockedDomains } = require('../store/contentFilterStore');

// Optional hardening for proxy enforcement.
// Disabled by default because blocking all outbound UDP 443 can interrupt normal browsing.
const QUIC_RULE = 'UTM_BLOCK_QUIC_UDP443';
function applyQuicBlock() {
  if (process.platform !== 'win32') return;

  exec(
    `powershell -NonInteractive -ExecutionPolicy Bypass -Command "` +
    `Remove-NetFirewallRule -DisplayName '${QUIC_RULE}' -ErrorAction SilentlyContinue;` +
    `New-NetFirewallRule -DisplayName '${QUIC_RULE}' -Direction Outbound ` +
    `-Protocol UDP -RemotePort 443 -Action Block -Enabled True -ErrorAction Stop"`,
    (err) => { if (!err) console.log('[+] QUIC blocked (UDP 443 outbound) - social/gambling will be fully blocked.'); }
  );
}
function removeQuicBlock() {
  if (process.platform !== 'win32') return;

  exec(
    `powershell -NonInteractive -ExecutionPolicy Bypass -Command "` +
    `Remove-NetFirewallRule -DisplayName '${QUIC_RULE}' -ErrorAction SilentlyContinue"`,
    () => {}
  );
}

const CACHE_DIR = path.join(__dirname, '../store/content-filter-cache');
const PROXY_HOST = '127.0.0.1';
const SAFETY_ALLOWLIST = [
  'localhost',
  'msftconnecttest.com',
  'msftncsi.com',
  'windowsupdate.com',
  'update.microsoft.com',
];

function hageziWildcardUrls(filename) {
  return [
    `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/${filename}`,
    `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/${filename}`,
  ];
}

function hageziSource(filename) {
  const urls = hageziWildcardUrls(filename);
  return {
    sourceUrl: urls[0],
    sourceUrls: urls,
  };
}

const CATEGORY_LIBRARY = {
  adult: {
    id: 'adult',
    label: '18+ / Adult',
    description: 'Blocks adult and explicit domains.',
    sourceName: 'HaGeZi NSFW',
    ...hageziSource('nsfw-onlydomains.txt'),
  },
  ads: {
    id: 'ads',
    label: 'Ads & Trackers',
    description: 'Blocks ad networks, trackers and analytics domains (Google Ads, Yahoo Ads, AppNexus etc.).',
    sourceName: 'HaGeZi Pro Mini',
    ...hageziSource('pro.mini-onlydomains.txt'),
  },
  malware: {
    id: 'malware',
    label: 'Malware & Phishing',
    description: 'Blocks malware, phishing, scam, and command-and-control domains.',
    sourceName: 'HaGeZi TIF',
    ...hageziSource('tif-onlydomains.txt'),
  },
  gambling: {
    id: 'gambling',
    label: 'Gambling',
    description: 'Blocks gambling sites through the local browser proxy.',
    sourceName: 'HaGeZi Gambling',
    ...hageziSource('gambling-onlydomains.txt'),
  },
  social: {
    id: 'social',
    label: 'Social Media',
    description: 'Blocks Facebook, TikTok, Instagram and similar social platforms through the local browser proxy.',
    sourceName: 'HaGeZi Social',
    ...hageziSource('social-onlydomains.txt'),
  },
  piracy: {
    id: 'piracy',
    label: 'Piracy',
    description: 'Blocks torrent sites and illicit streaming platforms.',
    sourceName: 'HaGeZi Anti Piracy',
    ...hageziSource('anti.piracy-onlydomains.txt'),
  },
  bypass: {
    id: 'bypass',
    label: 'DNS Bypass',
    description: 'Blocks domains used to bypass DNS filtering (DoH providers, VPN, proxies).',
    sourceName: 'HaGeZi DoH/VPN/Proxy Bypass',
    ...hageziSource('doh-vpn-proxy-bypass-onlydomains.txt'),
  },
};

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }

  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  return fallback;
}

function isBrowserProxyEnabled() {
  return parseBoolean(
    process.env.CONTENT_FILTER_BROWSER_PROXY_ENABLED || process.env.CONTENT_FILTER_PROXY_ENABLED,
    true,
  );
}

function isQuicBlockEnabled() {
  return parseBoolean(process.env.CONTENT_FILTER_BLOCK_QUIC, false);
}

function createContentFilterError(message, status = 400, code = 'CONTENT_FILTER_ERROR') {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function getCachePath(categoryId) {
  return path.join(CACHE_DIR, `${categoryId}.txt`);
}

function inspectEnvironment() {
  const { PROXY_PORT, isRunning } = require('./httpProxy');
  const proxyPort = Number(PROXY_PORT || 8877);
  const browserProxyEnabled = isBrowserProxyEnabled();

  return {
    platform: process.platform,
    supported: true,
    mode: 'proxy',
    proxyHost: PROXY_HOST,
    proxyPort,
    proxyAddress: `${PROXY_HOST}:${proxyPort}`,
    proxyRunning: Boolean(isRunning()),
    browserProxyEnabled,
    canWrite: true,
    permissionMessage: browserProxyEnabled
      ? 'Local browser proxy enforcement is available without system file changes.'
      : 'Browser proxy auto-configuration is disabled, so filtering is not enforced.',
  };
}

function stripInlineComments(value) {
  return String(value || '').split('#')[0].trim();
}

function normalizeDomain(value) {
  let candidate = stripInlineComments(value)
    .replace(/^@@\|\|/, '')
    .replace(/^\|\|/, '')
    .replace(/\^$/, '')
    .replace(/^\*\./, '')
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();

  if (!candidate) {
    return '';
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(candidate)) {
    return '';
  }

  if (candidate.includes(' ')) {
    const parts = candidate.split(/\s+/).filter(Boolean);
    if (parts.length >= 2 && /^(\d{1,3}\.){3}\d{1,3}$/.test(parts[0])) {
      candidate = parts[1];
    } else {
      candidate = parts[0];
    }
  }

  candidate = candidate.replace(/^\.+/, '').replace(/\.+$/, '');

  if (!candidate || !candidate.includes('.') || /[^a-z0-9.-]/i.test(candidate)) {
    return '';
  }

  if (['localhost', 'localdomain'].includes(candidate)) {
    return '';
  }

  return candidate;
}

function parseDomainList(rawText) {
  return Array.from(new Set(
    String(rawText || '')
      .split(/\r?\n/)
      .map((line) => normalizeDomain(line))
      .filter(Boolean),
  ));
}

function looksLikeDownloadError(rawText) {
  const sample = String(rawText || '').slice(0, 1000).toLowerCase();
  return !sample.trim()
    || sample.includes('too many requests')
    || sample.includes('rate limit')
    || sample.includes('github terms')
    || sample.includes('<!doctype html')
    || sample.includes('<html')
    || sample.includes('404: not found')
    || sample.includes('not found');
}

function parseValidatedCategoryDomains(rawText, sourceLabel = 'blocklist') {
  const domains = parseDomainList(rawText);

  if (looksLikeDownloadError(rawText) || domains.length < 10) {
    throw createContentFilterError(
      `Downloaded ${sourceLabel} feed does not look like a valid domain list.`,
      502,
      'BLOCKLIST_INVALID',
    );
  }

  return domains;
}

function splitTextList(value) {
  if (Array.isArray(value)) {
    return value;
  }

  return String(value || '')
    .split(/\r?\n|,/)
    .map((entry) => normalizeDomain(entry))
    .filter(Boolean);
}

function isAllowlisted(domain, allowlist) {
  return allowlist.some((allowed) => domain === allowed || domain.endsWith(`.${allowed}`));
}

async function fetchText(sourceUrl, timeoutMs = 30000) {
  const response = await fetch(sourceUrl, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      'User-Agent': 'Argus-Core/1.0',
      Accept: 'text/plain',
    },
  });

  if (!response.ok) {
    throw createContentFilterError(`Blocklist download failed (${response.status}) for ${sourceUrl}.`, 502, 'BLOCKLIST_FETCH_FAILED');
  }

  return response.text();
}

async function fetchValidatedCategory(source, timeoutMs = 30000) {
  const urls = Array.isArray(source.sourceUrls) && source.sourceUrls.length > 0
    ? source.sourceUrls
    : [source.sourceUrl];
  let lastError = null;

  for (const sourceUrl of urls) {
    try {
      const raw = await fetchText(sourceUrl, timeoutMs);
      const domains = parseValidatedCategoryDomains(raw, source.label);
      return {
        domains,
        raw,
        sourceUrl,
      };
    } catch (error) {
      lastError = error;
      console.warn(`[!] Content filter source failed (${source.label}): ${sourceUrl} - ${error.message}`);
    }
  }

  throw lastError || createContentFilterError(
    `No source URL is configured for ${source.label}.`,
    502,
    'BLOCKLIST_SOURCE_MISSING',
  );
}

function readCachedCategory(categoryId) {
  const cachePath = getCachePath(categoryId);
  if (!fs.existsSync(cachePath)) {
    return null;
  }

  return {
    cachePath,
    raw: fs.readFileSync(cachePath, 'utf8'),
    lastSyncedAt: fs.statSync(cachePath).mtime.toISOString(),
  };
}

async function loadCategoryDomains(categoryId, options = {}) {
  const source = CATEGORY_LIBRARY[categoryId];
  if (!source) {
    throw createContentFilterError(`Unknown content-filter category: ${categoryId}`, 400, 'UNKNOWN_CATEGORY');
  }

  ensureCacheDir();
  const cached = readCachedCategory(categoryId);
  let domains = [];
  let fromCache = false;
  let lastSyncedAt = cached?.lastSyncedAt || null;
  let fetchError = '';
  let sourceUrl = source.sourceUrl;

  if (cached?.raw) {
    try {
      domains = parseValidatedCategoryDomains(cached.raw, `${source.label} cache`);
      fromCache = true;
    } catch (error) {
      fetchError = error.message;
    }
  }

  if (options.sync !== false) {
    try {
      const downloaded = await fetchValidatedCategory(source, options.timeoutMs || 30000);
      domains = downloaded.domains;
      fs.writeFileSync(getCachePath(categoryId), downloaded.raw);
      fromCache = false;
      sourceUrl = downloaded.sourceUrl;
      lastSyncedAt = new Date().toISOString();
    } catch (error) {
      fetchError = [fetchError, error.message].filter(Boolean).join(' | ');
      if (!domains.length) {
        throw error;
      }
    }
  } else if (!domains.length) {
    throw createContentFilterError(`No cached blocklist is available yet for ${source.label}.`, 400, 'BLOCKLIST_CACHE_MISSING');
  }

  return {
    categoryId,
    domains,
    source,
    sourceUrl,
    fromCache,
    lastSyncedAt,
    fetchError,
  };
}

async function compilePolicy(policy, options = {}) {
  const policyEnabled = Boolean(policy?.enabled);
  const enabledCategoryIds = policyEnabled
    ? CATEGORY_IDS.filter((id) => Boolean(policy?.categories?.[id]))
    : [];
  const selectedCategoryIds = CATEGORY_IDS.filter((id) => Boolean(policy?.categories?.[id]));
  const categoriesToLoad = options.loadAllCategories === true
    ? CATEGORY_IDS
    : selectedCategoryIds;
  const enabledCategorySet = new Set(enabledCategoryIds);
  const allowlist = Array.from(new Set([
    ...splitTextList(policy?.allowlist),
    ...splitTextList(SAFETY_ALLOWLIST),
  ]));
  const customBlocklist = policyEnabled ? splitTextList(policy?.customBlocklist) : [];
  const sourceStatus = {};
  const categoryDomainCounts = CATEGORY_IDS.reduce((counts, id) => {
    counts[id] = 0;
    return counts;
  }, {});
  const domainMap = new Map();

  // Resilient: dacă o categorie pică la download, continuă cu celelalte
  const categoryResults = (await Promise.allSettled(
    categoriesToLoad.map((categoryId) => loadCategoryDomains(categoryId, options))
  )).map((outcome) => {
    if (outcome.status === 'fulfilled') return outcome.value;
    console.error('[!] Content filter category failed:', outcome.reason?.message);
    return null;
  }).filter(Boolean);

  categoryResults.forEach((result) => {
    categoryDomainCounts[result.categoryId] = result.domains.length;
    sourceStatus[result.categoryId] = {
      label: result.source.label,
      sourceName: result.source.sourceName,
      sourceUrl: result.sourceUrl || result.source.sourceUrl,
      domainCount: result.domains.length,
      fromCache: result.fromCache,
      lastSyncedAt: result.lastSyncedAt,
      lastError: result.fetchError,
    };

    if (!enabledCategorySet.has(result.categoryId)) {
      return;
    }

    result.domains.forEach((domain) => {
      if (isAllowlisted(domain, allowlist)) {
        return;
      }

      const nextReasons = domainMap.get(domain) || new Set();
      nextReasons.add(result.categoryId);
      domainMap.set(domain, nextReasons);
    });
  });

  customBlocklist.forEach((domain) => {
    if (isAllowlisted(domain, allowlist)) {
      return;
    }

    const nextReasons = domainMap.get(domain) || new Set();
    nextReasons.add('custom');
    domainMap.set(domain, nextReasons);
  });

  return {
    allowlist,
    categoryDomainCounts,
    customBlocklist,
    domains: Array.from(domainMap.keys()).sort(),
    domainReasons: domainMap,
    enabledCategoryIds,
    sourceStatus,
  };
}

async function syncPolicy(policy, options = {}) {
  const compiled = await compilePolicy(policy, {
    sync: options.sync !== false,
    timeoutMs: options.timeoutMs,
  });

  return {
    ...compiled,
    lastSyncedAt: new Date().toISOString(),
  };
}

async function applyPolicy(policy, options = {}) {
  const compiled = await syncPolicy(policy, options);
  const proxyEnabled = isBrowserProxyEnabled();
  const policyEnabled = Boolean(policy?.enabled);
  const hasContent = policyEnabled && compiled.domains.length > 0;
  const environment = inspectEnvironment();
  const proxyApplied = proxyEnabled && hasContent;
  const quicBlockEnabled = isQuicBlockEnabled();

  setBlockedDomains(proxyApplied ? compiled.domains : []);

  // QUIC blocking is also opt-in because it affects every HTTPS/HTTP3 site.
  if (proxyApplied && quicBlockEnabled) {
    applyQuicBlock();
  } else if (quicBlockEnabled) {
    removeQuicBlock();
  }

  const proxyMessage = proxyApplied
    ? `Proxy cache updated with ${compiled.domains.length} blocked domains.`
    : hasContent
      ? 'Policy compiled, but browser proxy enforcement is disabled.'
      : 'No content-filter domains selected; proxy cache cleared.';

  return {
    ...compiled,
    applied: proxyApplied,
    enforcementMode: proxyApplied ? 'proxy' : 'none',
    proxyEnabled,
    proxyAddress: environment.proxyAddress,
    proxyPort: environment.proxyPort,
    proxyRunning: environment.proxyRunning,
    quicBlocked: proxyApplied && quicBlockEnabled,
    appliedDomainCount: proxyApplied ? compiled.domains.length : 0,
    proxyMessage,
    lastApplyAt: new Date().toISOString(),
  };
}

function removePolicyEnforcement() {
  setBlockedDomains([]);
  if (isQuicBlockEnabled()) {
    removeQuicBlock();
  }

  const environment = inspectEnvironment();

  return {
    removed: true,
    proxyEnabled: isBrowserProxyEnabled(),
    proxyAddress: environment.proxyAddress,
    proxyPort: environment.proxyPort,
    proxyRunning: environment.proxyRunning,
    proxyMessage: 'Content-filter proxy cache cleared.',
    lastRemoveAt: new Date().toISOString(),
  };
}

// Apelat la startup — reîncarcă domeniile din cache local (fără rețea)
async function initBlockedDomains(policy) {
  if (!isBrowserProxyEnabled()) {
    setBlockedDomains([]);
    return;
  }

  if (!policy?.enabled) {
    setBlockedDomains([]);
    return;
  }
  try {
    const compiled = await compilePolicy(policy, { sync: false });
    if (compiled.domains.length > 0) {
      setBlockedDomains(compiled.domains);
    }
  } catch {
    // Cache inexistent — normal la prima pornire
  }
}

async function checkDomainAgainstPolicy(domain, policy) {
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    throw createContentFilterError('A valid domain is required.', 400, 'INVALID_DOMAIN');
  }

  const compiled = await compilePolicy(policy, { sync: false });
  const reasons = [];
  let matchedDomain = '';

  for (const [candidate, candidateReasons] of compiled.domainReasons.entries()) {
    if (normalized === candidate || normalized.endsWith(`.${candidate}`)) {
      matchedDomain = candidate;
      reasons.push(...candidateReasons);
      break;
    }
  }

  return {
    blocked: reasons.length > 0 && !isAllowlisted(normalized, compiled.allowlist),
    domain: normalized,
    matchedDomain,
    reasons: Array.from(new Set(reasons)),
  };
}

function buildOverview(state) {
  const environment = inspectEnvironment();
  const enabledCategoryIds = CATEGORY_IDS.filter((id) => Boolean(state?.policy?.categories?.[id]));

  return {
    categories: CATEGORY_IDS.map((id) => ({
      id,
      ...CATEGORY_LIBRARY[id],
      enabled: Boolean(state?.policy?.categories?.[id]),
      domainCount: Number(state?.runtime?.categoryDomainCounts?.[id] || 0),
    })),
    policy: state?.policy,
    runtime: {
      ...state?.runtime,
      applied: environment.browserProxyEnabled ? Boolean(state?.runtime?.applied) : false,
      enforcementMode: environment.browserProxyEnabled ? (state?.runtime?.enforcementMode || 'none') : 'none',
      enabledCategoryIds,
      environment,
      proxyEnabled: environment.browserProxyEnabled,
      proxyAddress: state?.runtime?.proxyAddress || environment.proxyAddress,
      proxyPort: state?.runtime?.proxyPort || environment.proxyPort,
      proxyRunning: environment.proxyRunning,
    },
  };
}

module.exports = {
  CATEGORY_IDS,
  CATEGORY_LIBRARY,
  applyPolicy,
  applyQuicBlock,
  buildOverview,
  checkDomainAgainstPolicy,
  compilePolicy,
  createContentFilterError,
  initBlockedDomains,
  inspectEnvironment,
  removePolicyEnforcement,
  removeQuicBlock,
  parseDomainList,
  parseValidatedCategoryDomains,
  splitTextList,
  syncPolicy,
};
