const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { getGeoFilterState, updateGeoFilter } = require('../store/geoFilterStore');
const { getCountry, getRecentAttacks, syncCountryDomains, getCountrySyncStatus, COUNTRY_SOURCES } = require('../utils/geoFilter');

const router = express.Router();
router.use(verifyToken);

router.get('/', (_req, res) => {
  res.json({ success: true, ...getGeoFilterState() });
});

router.patch('/', (req, res) => {
  const state = updateGeoFilter(req.body || {});
  res.json({ success: true, message: 'Geo-filter policy updated.', ...state });
});

router.get('/attacks', (_req, res) => {
  res.json({ success: true, attacks: getRecentAttacks(50) });
});

router.post('/check', async (req, res) => {
  try {
    const hostname = String(req.body?.hostname || '').trim();
    if (!hostname) return res.status(400).json({ success: false, message: 'hostname required' });
    const country = await getCountry(hostname);
    const state = getGeoFilterState();
    const blocked = state.enabled && !!country && state.blockedCountries.includes(country);
    res.json({ success: true, hostname, country, blocked });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/sync', async (req, res) => {
  try {
    const state = getGeoFilterState();
    const countries = state.blockedCountries.filter((c) => COUNTRY_SOURCES[c]);
    if (countries.length === 0) {
      return res.json({ success: true, message: 'No countries with domain sources selected.', results: {} });
    }
    const results = await syncCountryDomains(countries);
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/sync-status', (_req, res) => {
  res.json({ success: true, status: getCountrySyncStatus() });
});

module.exports = router;
