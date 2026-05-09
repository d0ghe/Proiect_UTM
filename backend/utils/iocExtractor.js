/**
 * Network IOC (Indicators of Compromise) Extractor
 *
 * Extrage din fișiere/string-uri:
 *  - URL-uri (http/https/ftp)
 *  - Adrese IPv4 publice (filtrează RFC1918, loopback, multicast)
 *  - Domenii (FQDN)
 *  - Email addresses
 *  - Bitcoin / crypto addresses (ransom indicators)
 *  - Mutex names tipice de malware
 *  - Registry keys din path-uri tipice
 */

const URL_REGEX = /\b(?:https?|ftp):\/\/[a-zA-Z0-9._\-~:/?#@!$&'()*+,;=%]+/g;
const IPV4_REGEX = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|tk|ml|ga|cf|gq|xyz|top|club|online|site|store|tech|app|dev|edu|gov|mil|co\.uk|com\.cn|com\.ru|onion|i2p|ddns\.net|no-ip\.org|hopto\.org|servehttp\.com|duckdns\.org)\b/gi;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const BITCOIN_REGEX = /\b(?:bc1[a-z0-9]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const REGISTRY_REGEX = /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\.\-\s]+/gi;

const PRIVATE_IP_PREFIXES = ['10.', '127.', '169.254.', '192.168.', '0.', '255.', '224.', '239.'];
const PRIVATE_IP_RANGES_172 = (() => {
  const r = new Set();
  for (let i = 16; i <= 31; i++) r.add(`172.${i}.`);
  return r;
})();

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.download', '.review', '.work'];
const DGA_INDICATORS = /^[a-z0-9]{15,}\.(com|net|org|info|biz)$/i; // domenii lungi consonant-rich = DGA

function isPublicIPv4(ip) {
  if (PRIVATE_IP_PREFIXES.some((p) => ip.startsWith(p))) return false;
  for (const prefix of PRIVATE_IP_RANGES_172) {
    if (ip.startsWith(prefix)) return false;
  }
  return true;
}

function uniq(array) {
  return [...new Set(array)];
}

/**
 * Extrage IOCs dintr-un Buffer / String.
 *
 * @param {Buffer|string} input
 * @returns {{ urls, ips, domains, emails, bitcoinAddresses, registryKeys, suspicionScore, summary }}
 */
function extractIOCs(input) {
  const text = Buffer.isBuffer(input) ? input.toString('latin1') : String(input || '');

  const urls = uniq(text.match(URL_REGEX) || []).slice(0, 100);
  const allIps = uniq(text.match(IPV4_REGEX) || []);
  const ips = allIps.filter(isPublicIPv4).slice(0, 100);
  const domains = uniq(text.match(DOMAIN_REGEX) || [])
    .filter((d) => !d.endsWith('.exe') && !d.endsWith('.dll') && d.includes('.') && d.length < 80)
    .slice(0, 100);
  const emails = uniq(text.match(EMAIL_REGEX) || []).slice(0, 50);
  const bitcoinAddresses = uniq(text.match(BITCOIN_REGEX) || []).slice(0, 20);
  const registryKeys = uniq(text.match(REGISTRY_REGEX) || []).slice(0, 50);

  const suspiciousTldHits = domains.filter((d) => SUSPICIOUS_TLDS.some((tld) => d.toLowerCase().endsWith(tld)));
  const dgaSuspects = domains.filter((d) => DGA_INDICATORS.test(d));

  let score = 0;
  if (urls.length > 5) score += 10;
  if (ips.length > 3) score += 10;
  if (suspiciousTldHits.length > 0) score += 15;
  if (dgaSuspects.length > 0) score += 20;
  if (bitcoinAddresses.length > 0) score += 30; // ransom note indicator
  if (emails.length > 0 && bitcoinAddresses.length > 0) score += 10; // ransom contact

  const summary = [
    urls.length > 0 ? `${urls.length} URLs` : null,
    ips.length > 0 ? `${ips.length} IPs` : null,
    domains.length > 0 ? `${domains.length} domains` : null,
    bitcoinAddresses.length > 0 ? `${bitcoinAddresses.length} BTC addresses (ransom?)` : null,
    suspiciousTldHits.length > 0 ? `${suspiciousTldHits.length} suspicious TLDs` : null,
    dgaSuspects.length > 0 ? `${dgaSuspects.length} possible DGA domains` : null,
  ].filter(Boolean).join(', ') || 'No network IOCs found';

  return {
    urls,
    ips,
    domains,
    emails,
    bitcoinAddresses,
    registryKeys,
    suspiciousTlds: suspiciousTldHits,
    dgaSuspects,
    suspicionScore: Math.min(score, 50),
    summary,
  };
}

module.exports = { extractIOCs, isPublicIPv4 };
