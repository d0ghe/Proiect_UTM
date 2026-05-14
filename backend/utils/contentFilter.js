const fs = require('fs');
const path = require('path');
const { exec, spawnSync } = require('child_process');

const { CATEGORY_IDS, setBlockedDomains } = require('../store/contentFilterStore');

// Optional hardening for the legacy browser proxy mode.
// Disabled by default because blocking all outbound UDP 443 can interrupt normal browsing.
const QUIC_RULE = 'UTM_BLOCK_QUIC_UDP443';
function applyQuicBlock() {
  exec(
    `powershell -NonInteractive -ExecutionPolicy Bypass -Command "` +
    `Remove-NetFirewallRule -DisplayName '${QUIC_RULE}' -ErrorAction SilentlyContinue;` +
    `New-NetFirewallRule -DisplayName '${QUIC_RULE}' -Direction Outbound ` +
    `-Protocol UDP -RemotePort 443 -Action Block -Enabled True -ErrorAction Stop"`,
    (err) => { if (!err) console.log('[+] QUIC blocat (UDP 443 outbound) — social/gambling vor fi blocate complet.'); }
  );
}
function removeQuicBlock() {
  exec(
    `powershell -NonInteractive -ExecutionPolicy Bypass -Command "` +
    `Remove-NetFirewallRule -DisplayName '${QUIC_RULE}' -ErrorAction SilentlyContinue"`,
    () => {}
  );
}

const CACHE_DIR = path.join(__dirname, '../store/content-filter-cache');
const HOSTS_SECTION_START = '# === U-Trust Content Filter Start ===';
const HOSTS_SECTION_END = '# === U-Trust Content Filter End ===';
const LEGACY_HOSTS_SECTIONS = [
  {
    start: '# === Containment Atlas Content Filter Start ===',
    end: '# === Containment Atlas Content Filter End ===',
  },
];
const DEFAULT_HOSTS_MAX_DOMAINS = 5000;
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
    description: 'Blocks gambling sites. Necesită admin (Run as Administrator) pentru blocare completă HTTPS.',
    sourceName: 'HaGeZi Gambling',
    ...hageziSource('gambling-onlydomains.txt'),
  },
  social: {
    id: 'social',
    label: 'Social Media',
    description: 'Blocks Facebook, TikTok, Instagram etc. Necesită admin pentru blocare completă (QUIC/HTTP3).',
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
    false,
  );
}

function isQuicBlockEnabled() {
  return parseBoolean(process.env.CONTENT_FILTER_BLOCK_QUIC, false);
}

function getHostsMaxDomains() {
  const value = Number(process.env.CONTENT_FILTER_HOSTS_MAX_DOMAINS || DEFAULT_HOSTS_MAX_DOMAINS);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : DEFAULT_HOSTS_MAX_DOMAINS;
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

function getHostsFilePath(platform = process.platform) {
  if (platform === 'win32') {
    return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');
  }

  if (platform === 'linux' || platform === 'darwin') {
    return '/etc/hosts';
  }

  return null;
}

function inspectEnvironment() {
  const hostsPath = process.env.CONTENT_FILTER_HOSTS_FILE || getHostsFilePath();
  const supported = Boolean(hostsPath);

  if (!supported) {
    return {
      platform: process.platform,
      supported: false,
      hostsPath: null,
      canWrite: false,
      permissionMessage: 'Hosts-file enforcement is not implemented for this platform yet.',
    };
  }

  try {
    fs.accessSync(hostsPath, fs.constants.R_OK | fs.constants.W_OK);
    return {
      platform: process.platform,
      supported: true,
      hostsPath,
      canWrite: true,
      permissionMessage: 'Hosts file is writable.',
    };
  } catch (error) {
    return {
      platform: process.platform,
      supported: true,
      hostsPath,
      canWrite: false,
      permissionMessage: `Hosts file needs elevated privileges: ${error.message}`,
    };
  }
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
      'User-Agent': 'U-Trust-Core/1.0',
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
    enabledCategoryIds.map((categoryId) => loadCategoryDomains(categoryId, options))
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

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripManagedSection(hostsText) {
  return [
    { start: HOSTS_SECTION_START, end: HOSTS_SECTION_END },
    ...LEGACY_HOSTS_SECTIONS,
  ].reduce((nextHostsText, section) => {
    const pattern = new RegExp(`${escapeRegExp(section.start)}[\\s\\S]*?${escapeRegExp(section.end)}\\r?\\n?`, 'g');
    return nextHostsText.replace(pattern, '');
  }, String(hostsText || '')).trimEnd();
}

function buildManagedSection(compiled) {
  const summaryLines = [
    HOSTS_SECTION_START,
    `# Applied: ${new Date().toISOString()}`,
    `# Categories: ${(compiled.enabledCategoryIds.length > 0 ? compiled.enabledCategoryIds : ['custom']).join(', ')}`,
    `# Domains: ${compiled.domains.length}`,
  ];
  const domainLines = compiled.domains.flatMap((domain) => [
    `0.0.0.0 ${domain}`,
    `:: ${domain}`,
  ]);
  return [...summaryLines, ...domainLines, HOSTS_SECTION_END].join('\n');
}

function inspectManagedSection(hostsText) {
  const text = String(hostsText || '');
  const section = [
    { start: HOSTS_SECTION_START, end: HOSTS_SECTION_END },
    ...LEGACY_HOSTS_SECTIONS,
  ].map((candidate) => ({
    ...candidate,
    startIndex: text.indexOf(candidate.start),
    endIndex: text.indexOf(candidate.end),
  })).find((candidate) => candidate.startIndex !== -1 && candidate.endIndex !== -1 && candidate.endIndex >= candidate.startIndex);

  if (!section) {
    return {
      present: false,
      entryCount: 0,
    };
  }

  const sectionText = text.slice(section.startIndex, section.endIndex);
  return {
    present: true,
    entryCount: sectionText.split(/\r?\n/).filter((line) => /^\s*(?:0\.0\.0\.0|::)\s+/.test(line)).length,
  };
}

function writeHostsFile(hostsPath, content) {
  const nextContent = `${content.trimEnd()}\n`;
  const tempPath = path.join(getTempDir(), `u-trust-hosts-${process.pid}-${Date.now()}.tmp`);
  let lastError = null;

  for (let attempt = 1; attempt <= 20; attempt += 1) {
    try {
      fs.writeFileSync(hostsPath, nextContent, 'utf8');
      return;
    } catch (error) {
      lastError = error;
      if (!['EBUSY', 'EPERM', 'EACCES'].includes(error.code)) {
        throw error;
      }

      if (process.platform === 'win32') {
        try {
          fs.writeFileSync(tempPath, nextContent, 'utf8');
          const ps = [
            `$source=${psSingleQuote(tempPath)};`,
            `$dest=${psSingleQuote(hostsPath)};`,
            '$bytes=[IO.File]::ReadAllBytes($source);',
            '$stream=[IO.File]::Open($dest,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);',
            'try{$stream.SetLength(0);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}',
          ].join('');
          const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps], { encoding: 'utf8' });
          if (result.status === 0) {
            try { fs.unlinkSync(tempPath); } catch { /* ignore */ }
            return;
          }

          lastError = new Error((result.stderr || result.stdout || '').trim() || error.message);
          lastError.code = error.code;
        } catch (fallbackError) {
          lastError = fallbackError;
        }
      }

      sleepSync(350);
    }
  }

  try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch { /* ignore */ }
  throw lastError;
}

function getTempDir() {
  return process.env.TEMP || process.env.TMP || path.join(__dirname, '..', 'store');
}

function psSingleQuote(value) {
  return `'${String(value || '').replace(/'/g, "''")}'`;
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function flushDnsCache() {
  const commands = process.platform === 'win32'
    ? [['ipconfig', ['/flushdns']]]
    : process.platform === 'linux'
      ? [['resolvectl', ['flush-caches']], ['systemd-resolve', ['--flush-caches']]]
      : process.platform === 'darwin'
        ? [['dscacheutil', ['-flushcache']], ['killall', ['-HUP', 'mDNSResponder']]]
        : [];

  for (const [command, args] of commands) {
    const result = spawnSync(command, args, { encoding: 'utf8', timeout: 5000 });
    if (result.status === 0) {
      return `${command} ${args.join(' ')}`.trim();
    }
  }

  return 'DNS cache flush command was not available. A manual DNS flush may still be needed.';
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

  // Keep the legacy browser proxy fully opt-in. By default the app only writes
  // the hosts file and does not intercept browser traffic.
  const policyEnabled = Boolean(policy?.enabled);
  const hasContent = policyEnabled && compiled.domains.length > 0;
  if (proxyEnabled && hasContent) {
    setBlockedDomains(compiled.domains);
  } else {
    setBlockedDomains([]);
  }

  const environment = inspectEnvironment();
  let dnsFlushMessage = '';
  let hostsApplied = false;
  const hostsMaxDomains = getHostsMaxDomains();
  const tooLargeForHosts = hasContent && !proxyEnabled && compiled.domains.length > hostsMaxDomains;

  // Încearcă să scrie și în hosts file (funcționează dacă e admin)
  if (environment.supported && environment.canWrite) {
    const hostsPath = environment.hostsPath;
    const currentHosts = fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
    const strippedHosts = stripManagedSection(currentHosts);

    if (!policyEnabled || compiled.domains.length === 0 || tooLargeForHosts) {
      writeHostsFile(hostsPath, strippedHosts);
    } else {
      const managedSection = buildManagedSection(compiled);
      const nextContent = [strippedHosts, managedSection].filter(Boolean).join('\n\n');
      writeHostsFile(hostsPath, nextContent);
      hostsApplied = true;
    }
    dnsFlushMessage = flushDnsCache();
    if (tooLargeForHosts) {
      dnsFlushMessage = `Hosts enforcement skipped: ${compiled.domains.length} domains exceeds the safe Windows hosts limit (${hostsMaxDomains}). Existing managed entries were removed. ${dnsFlushMessage}`;
    }
  } else if (proxyEnabled) {
    dnsFlushMessage = environment.canWrite === false
      ? 'Hosts file needs admin - browser proxy fallback is active.'
      : 'Browser proxy fallback is active.';
  } else {
    dnsFlushMessage = environment.canWrite === false
      ? 'Hosts file needs admin; browser proxy is disabled, so no system-wide blocking was applied.'
      : 'Browser proxy is disabled and no supported hosts target is available.';
  }

  const proxyApplied = proxyEnabled && hasContent;
  const applied = hostsApplied || proxyApplied;
  const enforcementMode = hostsApplied ? 'hosts' : proxyApplied ? 'proxy' : 'none';

  // QUIC blocking is also opt-in because it affects every HTTPS/HTTP3 site.
  if (proxyApplied && isQuicBlockEnabled()) applyQuicBlock();
  else removeQuicBlock();

  return {
    ...compiled,
    applied,
    enforcementMode,
    hostsApplied,
    hostsMaxDomains,
    hostsSkippedReason: tooLargeForHosts
      ? `The policy has ${compiled.domains.length} domains, above the safe Windows hosts limit of ${hostsMaxDomains}.`
      : '',
    proxyEnabled,
    quicBlocked: proxyApplied && isQuicBlockEnabled(),
    appliedDomainCount: applied ? compiled.domains.length : 0,
    dnsFlushMessage,
    lastApplyAt: new Date().toISOString(),
  };
}

function removeManagedBlock() {
  // Clear optional proxy cache and remove optional QUIC rule.
  setBlockedDomains([]);
  removeQuicBlock();

  const environment = inspectEnvironment();
  let dnsFlushMessage = isBrowserProxyEnabled()
    ? 'Proxy cache cleared.'
    : 'Content-filter cache cleared.';

  if (environment.supported && environment.canWrite) {
    const hostsPath = environment.hostsPath;
    const currentHosts = fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
    const strippedHosts = stripManagedSection(currentHosts);
    writeHostsFile(hostsPath, strippedHosts);
    dnsFlushMessage = flushDnsCache();
  }

  return {
    removed: true,
    dnsFlushMessage,
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
  const hostsPath = environment.hostsPath;
  let hostsText = '';

  try {
    hostsText = hostsPath && fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
  } catch {
    hostsText = '';
  }

  const managedSection = inspectManagedSection(hostsText);
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
      enabledCategoryIds,
      environment,
      managedSectionPresent: managedSection.present,
      managedEntryCount: managedSection.entryCount,
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
  removeManagedBlock,
  removeQuicBlock,
  parseDomainList,
  parseValidatedCategoryDomains,
  splitTextList,
  syncPolicy,
};
