const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { getGeoFilterState, updateGeoFilter } = require('../store/geoFilterStore');
const { getCountry } = require('../utils/geoFilter');

const router = express.Router();
router.use(verifyToken);

router.get('/', (_req, res) => {
  res.json({ success: true, ...getGeoFilterState() });
});

router.patch('/', (req, res) => {
  const state = updateGeoFilter(req.body || {});
  res.json({ success: true, message: 'Geo-filter policy updated.', ...state });
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

module.exports = router;
