const fs    = require('fs');
const path  = require('path');
const dns   = require('dns').promises;
const net   = require('net');
const geoip = require('geoip-lite');

const { getGeoFilterState } = require('../store/geoFilterStore');
const { readConnections } = require('./telemetry');

/* ── Cache DNS ─────────────────────────────────────────────────────────────── */
const dnsCache     = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000;

/* ── Attack log (in-memory, ultimele 200) ──────────────────────────────────── */
const attackLog = [];
const MAX_ATTACKS = 200;

/* ── Coordonate centru tara [lon, lat] ─────────────────────────────────────── */
const COUNTRY_COORDS = {
  AF:[67.7,33.9],AL:[20.2,41.2],DZ:[1.7,28.0],AO:[17.9,-11.2],AR:[-63.6,-38.4],
  AM:[45.0,40.1],AU:[133.8,-25.3],AT:[14.6,47.5],AZ:[47.6,40.1],BD:[90.4,23.7],
  BY:[28.0,53.7],BE:[4.5,50.5],BJ:[2.3,9.3],BA:[17.7,44.2],BR:[-51.9,-14.2],
  BG:[25.5,42.7],KH:[105.0,12.6],CM:[12.4,4.1],CA:[-96.8,56.1],CL:[-71.5,-35.7],
  CN:[104.2,35.9],CO:[-74.3,4.6],CG:[15.8,-0.2],CU:[-79.5,21.5],CZ:[15.5,49.8],
  DE:[10.5,51.2],DK:[10.0,56.3],DO:[-70.2,18.7],EG:[30.8,26.8],ET:[39.6,9.1],
  FI:[26.3,64.0],FR:[2.2,46.2],GE:[43.4,42.3],GH:[-1.0,7.9],GR:[22.0,39.1],
  GT:[-90.2,15.8],HN:[-86.6,15.2],HK:[114.2,22.4],HU:[19.5,47.2],IN:[78.7,20.6],
  ID:[113.9,-0.8],IR:[53.7,32.4],IQ:[43.7,33.2],IE:[-8.2,53.2],IL:[34.9,31.5],
  IT:[12.6,42.8],JP:[138.3,36.2],JO:[37.2,31.2],KZ:[67.0,48.0],KE:[37.9,0.0],
  KP:[127.5,40.3],KR:[127.8,36.6],KW:[47.5,29.3],LB:[35.9,33.9],LY:[17.2,26.3],
  LT:[23.9,55.2],MY:[109.7,2.6],MX:[-102.5,23.6],MA:[-7.1,31.8],MM:[95.9,21.9],
  NP:[84.1,28.4],NL:[5.3,52.3],NZ:[172.0,-40.9],NG:[8.7,9.1],NO:[8.5,60.5],
  PK:[69.3,30.4],PH:[122.9,12.9],PL:[19.1,51.9],PT:[-8.2,39.4],RO:[24.9,45.9],
  RU:[105.3,61.5],SA:[45.1,23.9],SN:[-14.5,14.5],RS:[21.0,44.0],SL:[-11.8,8.5],
  SO:[46.2,6.1],ZA:[22.9,-30.6],SD:[29.9,12.9],SY:[38.3,35.0],TW:[120.9,23.7],
  TZ:[34.9,-6.4],TH:[100.5,15.9],TN:[9.5,34.0],TR:[35.2,39.1],TM:[59.6,38.9],
  UA:[31.2,48.4],AE:[53.8,24.0],GB:[-3.4,55.4],US:[-95.7,37.1],UZ:[63.9,41.4],
  VE:[-66.6,6.4],VN:[108.3,14.1],YE:[48.5,15.6],ZM:[27.8,-13.1],ZW:[29.2,-19.0],
};

/* ── Liste domenii per tara (v2fly domain-list-community, mentinut de comunitate) */
// Each country has multiple mirror URLs — fetched in order, first success wins.
const COUNTRY_SOURCES = {
  CN: [
    'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/cn.yaml',
    'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China.list',
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cn',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/cn',
  ],
  RU: [
    'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-clashx.lst',
    'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-dnsmasq-nfset.lst',
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ru',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/ru',
  ],
  IR: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ir',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/ir',
  ],
  VN: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/vn',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/vn',
  ],
  KP: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/kp',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/kp',
  ],
  BY: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/by',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/by',
  ],
  IN: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/in',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/in',
  ],
  TR: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/tr',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/tr',
  ],
  PK: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/pk',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/pk',
  ],
  UA: [
    'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ua',
    'https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/ua',
  ],
};

const COUNTRY_TLD_ALIASES = {
  GB: ['uk'],
  RU: ['su', 'xn--p1ai', 'xn--p1acf'],
  CN: ['xn--fiqs8s', 'xn--fiqz9s', 'xn--55qx5d', 'xn--io0a7i'],
  HK: ['xn--j6w193g'],
  TW: ['xn--kprw13d', 'xn--kpry57d'],
  KR: ['xn--3e0b707e'],
  BY: ['xn--90ais'],
  IR: ['xn--mgba3a4f16a'],
  KZ: ['xn--80ao21a'],
  GE: ['xn--node'],
  AM: ['xn--y9a3aq'],
  IN: ['xn--h2brj9c', 'xn--45br5cyl', 'xn--xkc2dl3a5ee0h', 'xn--mgbbh1a71e'],
};

const COUNTRY_CURATED_DOMAINS = {
  CN: [
    'baidu.com', 'qq.com', 'weibo.com', 'bilibili.com', 'douyin.com', 'taobao.com',
    'tmall.com', 'jd.com', 'alipay.com', 'aliyun.com', '163.com', 'sina.com.cn',
    'sohu.com', 'zhihu.com', 'xiaomi.com', 'huawei.com', 'bytedance.com',
  ],
  RU: [
    'vk.com', 'ok.ru', 'yandex.com', 'yandex.net', 'mail.ru', 'rambler.ru',
    'rutube.ru', 'gazprom.ru', 'sberbank.ru', 'gosuslugi.ru', 'rbc.ru', 'ria.ru',
    'tass.ru', 'rt.com', 'sputniknews.com',
  ],
  IR: ['digikala.com', 'aparat.com', 'cafebazaar.ir', 'varzesh3.com', 'namava.ir'],
  VN: ['zing.vn', 'zalo.me', 'vnexpress.net', 'vietnamnet.vn', '24h.com.vn'],
  IN: ['hotstar.com', 'flipkart.com', 'paytm.com', 'timesofindia.indiatimes.com', 'ndtv.com'],
  TR: ['hurriyet.com.tr', 'sahibinden.com', 'trendyol.com', 'hepsiburada.com', 'milliyet.com.tr'],
  UA: ['ukr.net', 'pravda.com.ua', 'rozetka.com.ua', 'privatbank.ua'],
  BR: ['globo.com', 'uol.com.br', 'terra.com.br', 'mercadolivre.com.br'],
  ID: ['detik.com', 'kompas.com', 'tokopedia.com', 'bukalapak.com'],
  TH: ['pantip.com', 'sanook.com', 'kapook.com', 'thairath.co.th'],
  PH: ['abs-cbn.com', 'gmanetwork.com', 'inquirer.net', 'rappler.com'],
  PK: ['dawn.com', 'geo.tv', 'jang.com.pk', 'olx.com.pk'],
  NG: ['nairaland.com', 'punchng.com', 'vanguardngr.com', 'jumia.com.ng'],
  BY: ['tut.by', 'onliner.by', 'belta.by'],
  KZ: ['tengrinews.kz', 'zakon.kz', 'kaspi.kz'],
  AZ: ['trend.az', 'azernews.az'],
  GE: ['interpressnews.ge', 'myauto.ge'],
};

const CACHE_DIR = path.join(__dirname, '../store/geo-country-cache');

// In-memory domain sets per tara: { CN: Set([...]), RU: Set([...]) }
const countryDomainSets  = {};
const countrySyncStatus  = {};

/* ── Parser format v2fly ───────────────────────────────────────────────────── */
function parseV2flyDomains(raw) {
  const domains = [];
  for (const line of String(raw || '').split(/\r?\n/)) {
    const trimmed = line.split('#')[0].trim();
    if (!trimmed) continue;
    // Acceptam doar "domain:" si "full:" — ignoram include:, keyword:, regexp:
    if (/^(include|keyword|regexp):/i.test(trimmed)) continue;
    const match = trimmed.match(/^(?:domain:|full:)?([a-z0-9.-]+\.[a-z0-9-]+)(?:\s|@|$)/i);
    if (match) {
      const domain = match[1].replace(/^\.+|\.+$/g, '').toLowerCase();
      if (domain && !domain.includes('..')) domains.push(domain);
    }
  }
  return [...new Set(domains)];
}

function parseV2flyIncludes(raw) {
  return String(raw || '')
    .split(/\r?\n/)
    .map((line) => line.split('#')[0].trim())
    .map((line) => line.match(/^include:([a-z0-9._-]+)/i)?.[1])
    .filter(Boolean);
}

function normalizeDomainEntry(value) {
  let candidate = String(value || '').split('#')[0].trim();
  if (!candidate) return '';

  candidate = candidate
    .replace(/^-\s*/, '')
    .replace(/^payload:\s*/i, '')
    .replace(/^@@\|\|/, '')
    .replace(/^\|\|/, '')
    .replace(/\^$/, '')
    .replace(/^\+\./, '')
    .replace(/^\*\./, '')
    .replace(/^https?:\/\//i, '')
    .trim();

  if (/^(include|keyword|regexp):/i.test(candidate)) return '';
  if (/^(ip-cidr|ip-cidr6|geoip|process-name|final|match),/i.test(candidate)) return '';

  const clashMatch = candidate.match(/^(?:DOMAIN|DOMAIN-SUFFIX|DOMAIN-FULL|HOST|HOST-SUFFIX),\s*([^,\s]+)/i);
  if (clashMatch) {
    candidate = clashMatch[1];
  }

  const dnsmasqMatch = candidate.match(/(?:nftset|ipset|server|address)=\/([^/]+)\//i);
  if (dnsmasqMatch) {
    candidate = dnsmasqMatch[1];
  }

  candidate = candidate
    .replace(/^(?:domain|full):/i, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\.+|\.+$/g, '')
    .toLowerCase();

  if (candidate.includes(' ')) {
    const parts = candidate.split(/\s+/).filter(Boolean);
    candidate = /^(\d{1,3}\.){3}\d{1,3}$/.test(parts[0]) ? parts[1] : parts[0];
  }

  if (
    !candidate ||
    !candidate.includes('.') ||
    candidate.includes('..') ||
    /[^a-z0-9.-]/i.test(candidate) ||
    /^(\d{1,3}\.){3}\d{1,3}$/.test(candidate)
  ) {
    return '';
  }

  return candidate;
}

function parseCountryDomains(raw) {
  return [...new Set(
    String(raw || '')
      .split(/\r?\n/)
      .map((line) => normalizeDomainEntry(line))
      .filter(Boolean),
  )];
}

function uniqueDomains(domains) {
  return [...new Set((Array.isArray(domains) ? domains : [])
    .map((domain) => normalizeDomainEntry(domain))
    .filter(Boolean))];
}

function getCountryDomainSuffixes(country) {
  const code = String(country || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return [];

  return [...new Set([
    code.toLowerCase(),
    ...(COUNTRY_TLD_ALIASES[code] || []),
  ].map((suffix) => String(suffix || '').replace(/^\.+|\.+$/g, '').toLowerCase()).filter(Boolean))];
}

function getBuiltInCountryDomains(country) {
  return uniqueDomains(COUNTRY_CURATED_DOMAINS[String(country || '').toUpperCase()] || []);
}

/* ── Functii de cache pe disk ──────────────────────────────────────────────── */
function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function getCachePath(country) {
  return path.join(CACHE_DIR, `${country}.txt`);
}

function readCachedDomains(country) {
  const file = getCachePath(country);
  if (!fs.existsSync(file)) return null;
  const raw = fs.readFileSync(file, 'utf8');
  return { domains: uniqueDomains(raw.split('\n')), mtime: fs.statSync(file).mtime.toISOString() };
}

/* ── Timeout-compatible fetch (Node 16 + 18+) ─────────────────────────────── */
function fetchWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, {
    signal: controller.signal,
    headers: { 'User-Agent': 'Argus-Core/1.0', Accept: 'text/plain' },
  }).finally(() => clearTimeout(timer));
}

/* ── Sync si incarcare liste ───────────────────────────────────────────────── */
function getV2flyUrls(listName) {
  const normalized = String(listName || '').toLowerCase();
  return [
    `https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/${normalized}`,
    `https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/${normalized}`,
  ];
}

async function fetchV2flyList(listName, visited = new Set()) {
  const normalized = String(listName || '').toLowerCase();
  if (!normalized || visited.has(normalized) || visited.size > 30) return [];
  visited.add(normalized);

  const urls = getV2flyUrls(normalized);
  let lastErr;
  let onlyMissing = true;

  for (const url of urls) {
    try {
      const res = await fetchWithTimeout(url, 40000);
      if (res.status === 404) continue;
      onlyMissing = false;
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const directDomains = parseV2flyDomains(text);
      const includeDomains = [];

      for (const includeName of parseV2flyIncludes(text)) {
        try {
          includeDomains.push(...await fetchV2flyList(includeName, visited));
        } catch (error) {
          console.warn(`[geo] Include failed (${includeName}): ${error.message}`);
        }
      }

      return [...new Set([...directDomains, ...includeDomains])];
    } catch (err) {
      console.warn(`[geo] v2fly list failed (${url}): ${err.message}`);
      lastErr = err;
    }
  }

  if (onlyMissing) return [];
  throw lastErr || new Error('All mirrors failed');
}

async function fetchTextSourceDomains(sourceUrl) {
  const res = await fetchWithTimeout(sourceUrl, 40000);
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  return parseCountryDomains(text);
}

async function fetchCountryDomains(country) {
  const code = String(country || '').toUpperCase();
  const lower = code.toLowerCase();
  const domains = [...getBuiltInCountryDomains(code)];
  const errors = [];
  let remoteCount = 0;
  let triedV2fly = false;

  console.log(`[geo] Fetching ${code} website metadata`);

  for (const sourceUrl of COUNTRY_SOURCES[code] || []) {
    try {
      const isV2fly = /domain-list-community/i.test(sourceUrl);
      if (isV2fly) {
        if (triedV2fly) continue;
        triedV2fly = true;
        const fetched = await fetchV2flyList(lower);
        remoteCount += fetched.length;
        domains.push(...fetched);
        continue;
      }

      const fetched = await fetchTextSourceDomains(sourceUrl);
      remoteCount += fetched.length;
      domains.push(...fetched);
    } catch (error) {
      console.warn(`[geo] source failed (${code}): ${sourceUrl} - ${error.message}`);
      errors.push(`${sourceUrl}: ${error.message}`);
    }
  }

  if (!triedV2fly) {
    try {
      const fetched = await fetchV2flyList(lower);
      remoteCount += fetched.length;
      domains.push(...fetched);
    } catch (error) {
      console.warn(`[geo] v2fly fallback failed (${code}): ${error.message}`);
      errors.push(`v2fly:${lower}: ${error.message}`);
    }
  }

  const unique = uniqueDomains(domains);
  console.log(`[geo] ${code}: ${unique.length} domains, ${getCountryDomainSuffixes(code).length} suffix rules`);
  return {
    domains: unique,
    remoteCount,
    builtInCount: getBuiltInCountryDomains(code).length,
    suffixes: getCountryDomainSuffixes(code),
    errors,
  };
}

function buildCountrySyncStatus(country, options = {}) {
  const code = String(country || '').toUpperCase();
  const domains = uniqueDomains(options.domains || []);
  const suffixes = getCountryDomainSuffixes(code);
  const domainCount = domains.length;
  const suffixCount = suffixes.length;
  const error = Array.isArray(options.errors)
    ? options.errors.join(' | ')
    : String(options.error || '');

  return {
    count: domainCount + suffixCount,
    domainCount,
    suffixCount,
    builtInCount: Number(options.builtInCount || getBuiltInCountryDomains(code).length),
    remoteCount: Number(options.remoteCount || 0),
    suffixes,
    synced: options.synced !== false,
    lastSync: options.lastSync || new Date().toISOString(),
    error,
    geoIp: true,
    mode: 'country-suffix+domains+ip-geolocation',
    message: domainCount > 0
      ? 'Country website rules and IP geolocation are active.'
      : 'Country ccTLD rules and IP geolocation are active.',
    country: code,
  };
}

async function syncCountryDomains(countries) {
  ensureCacheDir();
  countries = Array.from(new Set((Array.isArray(countries) ? countries : [])
    .map((country) => String(country || '').toUpperCase())
    .filter((country) => /^[A-Z]{2}$/.test(country))));
  const results = {};

  await Promise.all(countries.map(async (country) => {
    try {
      const result = await fetchCountryDomains(country);
      const domains = uniqueDomains(result.domains);
      fs.writeFileSync(getCachePath(country), domains.join('\n'), 'utf8');
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        builtInCount: result.builtInCount,
        remoteCount: result.remoteCount,
        errors: result.errors,
        synced: true,
        lastSync: new Date().toISOString(),
      });
      results[country] = countrySyncStatus[country];
    } catch (err) {
      const cached = readCachedDomains(country);
      const domains = uniqueDomains([...(cached?.domains || []), ...getBuiltInCountryDomains(country)]);
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        synced: false,
        lastSync: cached?.mtime || null,
        error: err.message,
      });
      results[country] = countrySyncStatus[country];
    }
  }));

  return results;
}

// Incarca din cache la startup/prima folosire
async function initCountryDomains(countries) {
  countries = Array.from(new Set((Array.isArray(countries) ? countries : [])
    .map((country) => String(country || '').toUpperCase())
    .filter((country) => /^[A-Z]{2}$/.test(country))));

  for (const country of countries) {
    if (countryDomainSets[country]) continue;
    const cached = readCachedDomains(country);
    const builtIn = getBuiltInCountryDomains(country);
    if (cached && cached.domains.length > 0) {
      const domains = uniqueDomains([...cached.domains, ...builtIn]);
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        synced: true,
        lastSync: cached.mtime,
      });
    } else {
      const domains = uniqueDomains(builtIn);
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        synced: true,
        lastSync: null,
      });
    }
  }
}

function getCountrySyncStatus(countries = []) {
  const requested = Array.from(new Set([
    ...Object.keys(countrySyncStatus),
    ...(Array.isArray(countries) ? countries : []),
  ].map((country) => String(country || '').toUpperCase()).filter((country) => /^[A-Z]{2}$/.test(country))));

  requested.forEach((country) => {
    if (countrySyncStatus[country]) return;
    const cached = readCachedDomains(country);
    const builtIn = getBuiltInCountryDomains(country);
    if (cached && cached.domains.length > 0) {
      const domains = uniqueDomains([...cached.domains, ...builtIn]);
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        synced: true,
        lastSync: cached.mtime,
      });
    } else {
      const domains = uniqueDomains(builtIn);
      countryDomainSets[country] = new Set(domains);
      countrySyncStatus[country] = buildCountrySyncStatus(country, {
        domains,
        synced: true,
        lastSync: null,
      });
    }
  });

  return Object.fromEntries(requested.map((country) => [country, countrySyncStatus[country]]));
}

/* ── Verificare domeniu in lista tarii ─────────────────────────────────────── */
function isDomainInCountrySet(hostname, country) {
  const set = countryDomainSets[country];
  if (!set || set.size === 0) return false;
  const h = hostname.toLowerCase();
  if (set.has(h)) return true;
  // Verificam si subdomeniile: sub.baidu.com → baidu.com
  const parts = h.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (set.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

/* ── TLD-based fallback ────────────────────────────────────────────────────── */
const TLD_MAP = Object.fromEntries(
  Object.keys(COUNTRY_COORDS).flatMap((country) =>
    getCountryDomainSuffixes(country).map((suffix) => [suffix, country])
  )
);

function normalizeHostname(value) {
  let hostname = String(value || '').trim();
  if (!hostname) return '';

  try {
    hostname = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(hostname) ? hostname : `http://${hostname}`).hostname;
  } catch {
    hostname = hostname
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .replace(/\/.*$/, '')
      .replace(/:\d+$/, '');
  }

  return hostname
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '')
    .toLowerCase();
}

function countryFromTld(hostname) {
  const normalized = normalizeHostname(hostname);
  const tld = normalized.split('.').pop().toLowerCase();
  return TLD_MAP[tld] || null;
}

/* ── DNS → toate IP-urile ──────────────────────────────────────────────────── */
async function resolveAllIps(hostname) {
  hostname = normalizeHostname(hostname);
  if (!hostname) return [];
  if (net.isIP(hostname)) return [hostname];
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return [hostname];
  const cached = dnsCache.get(hostname);
  if (cached && Date.now() - cached.ts < DNS_CACHE_TTL) return cached.ips;
  try {
    const ips = await dns.resolve4(hostname);
    dnsCache.set(hostname, { ips, ts: Date.now() });
    return ips;
  } catch {
    try {
      const { address } = await dns.lookup(hostname, { family: 4 });
      dnsCache.set(hostname, { ips: [address], ts: Date.now() });
      return [address];
    } catch {
      return [];
    }
  }
}

/* ── Attack log helpers ────────────────────────────────────────────────────── */
function addAttack(type, country, hostname, geo) {
  const coords = COUNTRY_COORDS[country];
  if (!coords) return;
  attackLog.push({ type, country, hostname, city: geo?.city || '', coords, timestamp: Date.now() });
  if (attackLog.length > MAX_ATTACKS) attackLog.shift();
}

function addContentBlock(hostname) {
  resolveAllIps(hostname).then((ips) => {
    const ip      = ips[0];
    const geo     = ip ? geoip.lookup(ip) : null;
    const country = geo?.country || 'XX';
    const coords  = COUNTRY_COORDS[country];
    if (!coords) return;
    attackLog.push({ type: 'content', country, hostname, city: geo?.city || '', coords, timestamp: Date.now() });
    if (attackLog.length > MAX_ATTACKS) attackLog.shift();
  }).catch(() => {});
}

function getRecentAttacks(limit = 50) {
  return attackLog.slice(-limit).reverse();
}

function normalizeIpAddress(value) {
  return String(value || '')
    .trim()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/^::ffff:/i, '')
    .replace(/%.+$/, '');
}

function isPrivateIpv4(ip) {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

function isPrivateIpv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('fe80:') ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('ff')
  );
}

function isPublicIp(value) {
  const ip = normalizeIpAddress(value);
  const version = net.isIP(ip);
  if (version === 4) return !isPrivateIpv4(ip);
  if (version === 6) return !isPrivateIpv6(ip);
  return false;
}

function isEphemeralPort(port) {
  const numeric = Number(port);
  return Number.isInteger(numeric) && numeric >= 49152 && numeric <= 65535;
}

function classifyDirection(connection) {
  if (!isPublicIp(connection.remoteAddress)) return 'local';
  const localEphemeral = isEphemeralPort(connection.localPort);
  const remoteEphemeral = isEphemeralPort(connection.remotePort);

  if (localEphemeral && !remoteEphemeral) return 'outbound';
  if (!localEphemeral && remoteEphemeral) return 'inbound';
  if (Number(connection.remotePort) && Number(connection.localPort)) {
    return Number(connection.localPort) > Number(connection.remotePort) ? 'outbound' : 'inbound';
  }

  return 'outbound';
}

async function getGeoConnections(limit = 120) {
  const connectionData = await readConnections(limit);
  const now = Date.now();
  const items = connectionData.items
    .map((connection) => {
      const remoteIp = normalizeIpAddress(connection.remoteAddress);
      if (!isPublicIp(remoteIp)) return null;
      const geo = geoip.lookup(remoteIp);
      if (!geo?.country) return null;
      const coords = Array.isArray(geo.ll)
        ? [geo.ll[1], geo.ll[0]]
        : COUNTRY_COORDS[geo.country] || null;

      return {
        ...connection,
        remoteAddress: remoteIp,
        direction: classifyDirection(connection),
        country: geo.country,
        city: geo.city || '',
        region: geo.region || '',
        timezone: geo.timezone || '',
        coords,
        timestamp: now,
      };
    })
    .filter((connection) => connection && connection.direction !== 'local');

  const countries = {};
  items.forEach((connection) => {
    const current = countries[connection.country] || {
      country: connection.country,
      inbound: 0,
      outbound: 0,
      total: 0,
      coords: connection.coords,
    };
    current[connection.direction] = (current[connection.direction] || 0) + 1;
    current.total += 1;
    countries[connection.country] = current;
  });

  return {
    items,
    rawSummary: connectionData.summary,
    summary: {
      total: items.length,
      inbound: items.filter((connection) => connection.direction === 'inbound').length,
      outbound: items.filter((connection) => connection.direction === 'outbound').length,
      countries: Object.keys(countries).length,
      byCountry: Object.values(countries).sort((left, right) => right.total - left.total),
    },
  };
}

/* ── getCountry (pentru route /check) ─────────────────────────────────────── */
async function getCountry(hostname) {
  hostname = normalizeHostname(hostname);
  if (!hostname) return null;
  const tld = countryFromTld(hostname);
  if (tld) return tld;
  const ips = await resolveAllIps(hostname);
  for (const ip of ips) {
    const geo = geoip.lookup(ip);
    if (geo?.country) return geo.country;
  }
  return null;
}

/* ── Verificare principala ─────────────────────────────────────────────────── */
async function isGeoBlocked(hostname) {
  hostname = normalizeHostname(hostname);
  if (!hostname) return { blocked: false };

  const state = getGeoFilterState();
  if (!state.enabled || state.blockedCountries.length === 0) return { blocked: false };

  // Asigura ca listele sunt incarcate din cache
  await initCountryDomains(state.blockedCountries);

  // Strat 1: Lista de domenii asociate tarii (v2fly - comunitate)
  for (const country of state.blockedCountries) {
    if (isDomainInCountrySet(hostname, country)) {
      addAttack('geo', country, hostname, null);
      return { blocked: true, country, reason: 'domain-list' };
    }
  }

  // Strat 2: TLD-based (.cn → CN, .ru → RU etc.)
  const tldCountry = countryFromTld(hostname);
  if (tldCountry && state.blockedCountries.includes(tldCountry)) {
    addAttack('geo', tldCountry, hostname, null);
    return { blocked: true, country: tldCountry, reason: 'country-tld' };
  }

  // Strat 3: IP-based — toate A record-urile (fallback pentru restul)
  const ips = await resolveAllIps(hostname);
  for (const ip of ips) {
    const geo = geoip.lookup(ip);
    if (!geo?.country) continue;
    if (state.blockedCountries.includes(geo.country)) {
      addAttack('geo', geo.country, hostname, geo);
      return { blocked: true, country: geo.country, reason: 'ip-geolocation', ip };
    }
  }

  return { blocked: false };
}

module.exports = {
  isGeoBlocked, getCountry, getRecentAttacks, addContentBlock,
  syncCountryDomains, initCountryDomains, getCountrySyncStatus, getGeoConnections, COUNTRY_SOURCES,
  parseV2flyDomains, parseCountryDomains, getCountryDomainSuffixes, normalizeHostname, countryFromTld,
};
