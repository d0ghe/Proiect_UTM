const fs = require('fs');
const path = require('path');

const STORE_FILE = path.join(__dirname, 'geo-filter-policy.json');

function createDefault() {
  return { enabled: false, blockedCountries: [] };
}

function read() {
  try {
    if (!fs.existsSync(STORE_FILE)) return createDefault();
    const raw = fs.readFileSync(STORE_FILE, 'utf8').trim();
    if (!raw) return createDefault();
    const parsed = JSON.parse(raw);
    return {
      enabled: Boolean(parsed.enabled),
      blockedCountries: Array.isArray(parsed.blockedCountries) ? parsed.blockedCountries : [],
    };
  } catch {
    return createDefault();
  }
}

function write(state) {
  fs.writeFileSync(STORE_FILE, JSON.stringify(state, null, 2));
}

function getGeoFilterState() {
  return read();
}

function updateGeoFilter(patch = {}) {
  const state = read();
  if (patch.enabled !== undefined) state.enabled = Boolean(patch.enabled);
  if (Array.isArray(patch.blockedCountries)) {
    state.blockedCountries = patch.blockedCountries
      .map((c) => String(c).toUpperCase().trim())
      .filter((c) => /^[A-Z]{2}$/.test(c));
  }
  write(state);
  return state;
}

module.exports = { getGeoFilterState, updateGeoFilter };
