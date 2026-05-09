const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const { getRulesText, getCustomRulesText, saveCustomRulesText, getBuiltinRules } = require('../store/yaraStore');
const { parseRules, runRules } = require('../utils/yaraEngine');

const router = express.Router();
router.use(verifyToken);

router.get('/', (_req, res) => {
  const custom = getCustomRulesText();
  const all = getRulesText();
  const parsed = parseRules(all);
  res.json({
    success: true,
    rules: custom,
    builtinRules: getBuiltinRules(),
    totalCount: parsed.length,
    ruleNames: parsed.map((r) => ({ name: r.name, severity: r.meta?.severity || 'warning' })),
  });
});

router.post('/', (req, res) => {
  const text = String(req.body?.rules || '');
  try {
    const parsed = parseRules(text);
    saveCustomRulesText(text);
    res.json({ success: true, count: parsed.length, message: `${parsed.length} custom rules saved.` });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

router.post('/test', (req, res) => {
  const { rules, sample } = req.body || {};
  if (!rules || !sample) {
    return res.status(400).json({ success: false, message: 'rules and sample (base64) required' });
  }
  try {
    const buf = Buffer.from(sample, 'base64');
    const result = runRules(buf, rules);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

module.exports = router;
