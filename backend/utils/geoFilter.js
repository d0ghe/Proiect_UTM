const dns  = require('dns').promises;
const geoip = require('geoip-lite');

const { getGeoFilterState } = require('../store/geoFilterStore');

// Cache DNS per hostname pentru a nu rezolva la fiecare request
const dnsCache = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000; // 5 minute

async function resolveIp(hostname) {
  // Dacă e deja un IP, returnează-l direct
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return hostname;

  const cached = dnsCache.get(hostname);
  if (cached && Date.now() - cached.ts < DNS_CACHE_TTL) return cached.ip;

  try {
    const { address } = await dns.lookup(hostname, { family: 4 });
    dnsCache.set(hostname, { ip: address, ts: Date.now() });
    return address;
  } catch {
    return null;
  }
}

async function getCountry(hostname) {
  const ip = await resolveIp(hostname);
  if (!ip) return null;
  const geo = geoip.lookup(ip);
  return geo?.country || null;
}

async function isGeoBlocked(hostname) {
  const state = getGeoFilterState();
  if (!state.enabled || state.blockedCountries.length === 0) return { blocked: false };

  const country = await getCountry(hostname);
  if (!country) return { blocked: false };

  const blocked = state.blockedCountries.includes(country);
  return { blocked, country };
}

module.exports = { isGeoBlocked, getCountry };
