const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { getGeoFilterState, updateGeoFilter } = require('../store/geoFilterStore');
const {
  getCountry,
  getGeoConnections,
  getRecentAttacks,
  initCountryDomains,
  isGeoBlocked,
  syncCountryDomains,
  getCountrySyncStatus,
} = require('../utils/geoFilter');

const router = express.Router();
router.use(verifyToken);

router.get('/', (_req, res) => {
  const state = getGeoFilterState();
  res.json({ success: true, syncStatus: getCountrySyncStatus(state.blockedCountries), ...state });
});

router.patch('/', async (req, res) => {
  const patch = { ...(req.body || {}) };
  if (
    patch.enabled === undefined &&
    Array.isArray(patch.blockedCountries) &&
    patch.blockedCountries.length > 0
  ) {
    patch.enabled = true;
  }

  const state = updateGeoFilter(patch);
  await initCountryDomains(state.blockedCountries);
  res.json({
    success: true,
    message: 'Geo-filter policy updated.',
    syncStatus: getCountrySyncStatus(state.blockedCountries),
    ...state,
  });
});

router.get('/attacks', (_req, res) => {
  res.json({ success: true, attacks: getRecentAttacks(50) });
});

router.get('/connections', async (req, res) => {
  try {
    const limit = Number(req.query.limit || 120);
    const connections = await getGeoConnections(limit);
    res.json({ success: true, ...connections });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/check', async (req, res) => {
  try {
    const hostname = String(req.body?.hostname || '').trim();
    if (!hostname) return res.status(400).json({ success: false, message: 'hostname required' });
    const state = getGeoFilterState();
    const geo = await isGeoBlocked(hostname);
    const country = geo.country || await getCountry(hostname);
    res.json({
      success: true,
      hostname,
      country,
      blocked: Boolean(geo.blocked),
      reason: geo.reason || '',
      ip: geo.ip || '',
      enforcementActive: state.enabled && state.blockedCountries.length > 0,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.post('/sync', async (req, res) => {
  try {
    const state = getGeoFilterState();
    const countries = state.blockedCountries;
    if (countries.length === 0) {
      return res.json({ success: true, message: 'No countries selected.', results: {} });
    }
    const results = await syncCountryDomains(countries);
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

router.get('/sync-status', (_req, res) => {
  const state = getGeoFilterState();
  res.json({ success: true, status: getCountrySyncStatus(state.blockedCountries) });
});

module.exports = router;
