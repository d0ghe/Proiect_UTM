const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { CATEGORY_IDS } = require('../store/contentFilterStore');

const CACHE_DIR = path.join(__dirname, '../store/content-filter-cache');
const HOSTS_SECTION_START = '# === Containment Atlas Content Filter Start ===';
const HOSTS_SECTION_END = '# === Containment Atlas Content Filter End ===';
const CATEGORY_LIBRARY = {
  adult: {
    id: 'adult',
    label: '18+ / Adult',
    description: 'Blocks adult and explicit domains.',
    sourceName: 'HaGeZi NSFW',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt',
  },
  ads: {
    id: 'ads',
    label: 'Ads',
    description: 'Blocks popup ads and ad-heavy redirect domains.',
    sourceName: 'HaGeZi Pop-Up Ads',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt',
  },
  malware: {
    id: 'malware',
    label: 'Malware',
    description: 'Blocks malware, phishing, scam, and command-and-control domains.',
    sourceName: 'HaGeZi TIF Mini',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt',
  },
  gambling: {
    id: 'gambling',
    label: 'Gambling',
    description: 'Blocks common gambling domains with a size-optimized list.',
    sourceName: 'HaGeZi Gambling Mini',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling.mini-onlydomains.txt',
  },
  social: {
    id: 'social',
    label: 'Social',
    description: 'Blocks major social media domains.',
    sourceName: 'HaGeZi Social',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt',
  },
  piracy: {
    id: 'piracy',
    label: 'Piracy',
    description: 'Blocks common piracy and illicit distribution domains.',
    sourceName: 'HaGeZi Anti Piracy',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt',
  },
  bypass: {
    id: 'bypass',
    label: 'DNS Bypass',
    description: 'Blocks domains commonly used to bypass local DNS filtering.',
    sourceName: 'HaGeZi DoH/VPN/Proxy Bypass',
    sourceUrl: 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt',
  },
};

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
      'User-Agent': 'Sentinel-Core/1.0',
      Accept: 'text/plain',
    },
  });

  if (!response.ok) {
    throw createContentFilterError(`Blocklist download failed (${response.status}) for ${sourceUrl}.`, 502, 'BLOCKLIST_FETCH_FAILED');
  }

  return response.text();
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
  let raw = cached?.raw || '';
  let fromCache = Boolean(cached);
  let lastSyncedAt = cached?.lastSyncedAt || null;
  let fetchError = '';

  if (options.sync !== false) {
    try {
      raw = await fetchText(source.sourceUrl, options.timeoutMs || 30000);
      fs.writeFileSync(getCachePath(categoryId), raw);
      fromCache = false;
      lastSyncedAt = new Date().toISOString();
    } catch (error) {
      fetchError = error.message;
      if (!raw) {
        throw error;
      }
    }
  } else if (!raw) {
    throw createContentFilterError(`No cached blocklist is available yet for ${source.label}.`, 400, 'BLOCKLIST_CACHE_MISSING');
  }

  const domains = parseDomainList(raw);
  return {
    categoryId,
    domains,
    source,
    fromCache,
    lastSyncedAt,
    fetchError,
  };
}

async function compilePolicy(policy, options = {}) {
  const enabledCategoryIds = CATEGORY_IDS.filter((id) => Boolean(policy?.categories?.[id]));
  const allowlist = splitTextList(policy?.allowlist);
  const customBlocklist = splitTextList(policy?.customBlocklist);
  const sourceStatus = {};
  const categoryDomainCounts = CATEGORY_IDS.reduce((counts, id) => {
    counts[id] = 0;
    return counts;
  }, {});
  const domainMap = new Map();

  const categoryResults = await Promise.all(enabledCategoryIds.map((categoryId) => loadCategoryDomains(categoryId, options)));
  categoryResults.forEach((result) => {
    categoryDomainCounts[result.categoryId] = result.domains.length;
    sourceStatus[result.categoryId] = {
      label: result.source.label,
      sourceName: result.source.sourceName,
      sourceUrl: result.source.sourceUrl,
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
  const pattern = new RegExp(`${escapeRegExp(HOSTS_SECTION_START)}[\\s\\S]*?${escapeRegExp(HOSTS_SECTION_END)}\\r?\\n?`, 'g');
  return String(hostsText || '').replace(pattern, '').trimEnd();
}

function buildManagedSection(compiled) {
  const summaryLines = [
    HOSTS_SECTION_START,
    `# Applied: ${new Date().toISOString()}`,
    `# Categories: ${(compiled.enabledCategoryIds.length > 0 ? compiled.enabledCategoryIds : ['custom']).join(', ')}`,
    `# Domains: ${compiled.domains.length}`,
  ];
  const domainLines = compiled.domains.map((domain) => `0.0.0.0 ${domain}`);
  return [...summaryLines, ...domainLines, HOSTS_SECTION_END].join('\n');
}

function inspectManagedSection(hostsText) {
  const startIndex = String(hostsText || '').indexOf(HOSTS_SECTION_START);
  const endIndex = String(hostsText || '').indexOf(HOSTS_SECTION_END);

  if (startIndex === -1 || endIndex === -1 || endIndex < startIndex) {
    return {
      present: false,
      entryCount: 0,
    };
  }

  const sectionText = String(hostsText || '').slice(startIndex, endIndex);
  return {
    present: true,
    entryCount: sectionText.split(/\r?\n/).filter((line) => /^\s*0\.0\.0\.0\s+/.test(line)).length,
  };
}

function writeHostsFile(hostsPath, content) {
  fs.writeFileSync(hostsPath, `${content.trimEnd()}\n`, 'utf8');
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
    const result = spawnSync(command, args, { encoding: 'utf8' });
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
  const environment = inspectEnvironment();
  if (!environment.supported) {
    throw createContentFilterError(environment.permissionMessage, 400, 'PLATFORM_UNSUPPORTED');
  }

  if (!environment.canWrite) {
    throw createContentFilterError(environment.permissionMessage, 403, 'ELEVATION_REQUIRED');
  }

  const compiled = await syncPolicy(policy, options);
  const hostsPath = environment.hostsPath;
  const currentHosts = fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
  const strippedHosts = stripManagedSection(currentHosts);

  if (!policy?.enabled || compiled.domains.length === 0) {
    writeHostsFile(hostsPath, strippedHosts);
    return {
      ...compiled,
      applied: false,
      appliedDomainCount: 0,
      dnsFlushMessage: flushDnsCache(),
      lastApplyAt: new Date().toISOString(),
    };
  }

  const managedSection = buildManagedSection(compiled);
  const nextContent = [strippedHosts, managedSection].filter(Boolean).join('\n\n');
  writeHostsFile(hostsPath, nextContent);

  return {
    ...compiled,
    applied: true,
    appliedDomainCount: compiled.domains.length,
    dnsFlushMessage: flushDnsCache(),
    lastApplyAt: new Date().toISOString(),
  };
}

function removeManagedBlock() {
  const environment = inspectEnvironment();
  if (!environment.supported) {
    throw createContentFilterError(environment.permissionMessage, 400, 'PLATFORM_UNSUPPORTED');
  }

  if (!environment.canWrite) {
    throw createContentFilterError(environment.permissionMessage, 403, 'ELEVATION_REQUIRED');
  }

  const hostsPath = environment.hostsPath;
  const currentHosts = fs.existsSync(hostsPath) ? fs.readFileSync(hostsPath, 'utf8') : '';
  const strippedHosts = stripManagedSection(currentHosts);
  writeHostsFile(hostsPath, strippedHosts);

  return {
    removed: true,
    dnsFlushMessage: flushDnsCache(),
    lastRemoveAt: new Date().toISOString(),
  };
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
  buildOverview,
  checkDomainAgainstPolicy,
  compilePolicy,
  createContentFilterError,
  inspectEnvironment,
  removeManagedBlock,
  splitTextList,
  syncPolicy,
};
