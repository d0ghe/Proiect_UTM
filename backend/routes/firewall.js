const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const {
  addFirewallRule,
  countActiveFirewallRules,
  deleteFirewallRule,
  getFirewallRules,
} = require('../store/runtimeState');

const router = express.Router();
router.use(verifyToken);

router.get('/rules', (_req, res) => {
  res.json(getFirewallRules());
});

router.get('/summary', (_req, res) => {
  const rules = getFirewallRules();
  res.json({
    success: true,
    summary: {
      total:        rules.length,
      active:       countActiveFirewallRules(),
      blockedRules: rules.filter((r) => String(r.status).toLowerCase() === 'active' && String(r.action).toUpperCase() === 'BLOCK').length,
      allowedRules: rules.filter((r) => String(r.status).toLowerCase() === 'active' && String(r.action).toUpperCase() === 'ALLOW').length,
    },
  });
});

router.post('/rules', (req, res) => {
  const { action, protocol, port, ip, status, desc } = req.body || {};

  const portNum = Number(port);
  if (!port || !Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
    return res.status(400).json({ success: false, message: 'Port invalid (1–65535).' });
  }

  const rule = addFirewallRule({ action, protocol, port: portNum, ip, status, desc });
  // Proxy-ul HTTP citește live din store — regula e activă imediat după adăugare
  res.status(201).json({ success: true, message: 'Regulă adăugată.', rule });
});

router.delete('/rules/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    return res.status(400).json({ success: false, message: 'ID invalid.' });
  }

  const removedRule = deleteFirewallRule(id);
  if (!removedRule) {
    return res.status(404).json({ success: false, message: `Regula ${id} nu există.` });
  }

  res.json({ success: true, message: `Regula portului ${removedRule.port} ștearsă.`, rule: removedRule });
});

module.exports = router;
