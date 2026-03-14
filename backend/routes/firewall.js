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
  const activeRules = countActiveFirewallRules();
  const blockedRules = rules.filter(
    (rule) => String(rule.status).toLowerCase() === 'active' && String(rule.action).toUpperCase() === 'BLOCK',
  ).length;
  const allowedRules = rules.filter(
    (rule) => String(rule.status).toLowerCase() === 'active' && String(rule.action).toUpperCase() === 'ALLOW',
  ).length;

  res.json({
    success: true,
    summary: {
      total: rules.length,
      active: activeRules,
      blockedRules,
      allowedRules,
    },
  });
});

router.post('/rules', (req, res) => {
  const { action, protocol, port, ip, status, desc } = req.body || {};

  if (!port || Number(port) <= 0) {
    return res.status(400).json({
      success: false,
      message: 'A valid port is required.',
    });
  }

  const rule = addFirewallRule({
    action,
    protocol,
    port,
    ip,
    status,
    desc,
  });

  res.status(201).json({
    success: true,
    message: 'Rule added.',
    rule,
  });
});

router.delete('/rules/:id', (req, res) => {
  const removedRule = deleteFirewallRule(Number(req.params.id));

  if (!removedRule) {
    return res.status(404).json({
      success: false,
      message: 'Rule not found.',
    });
  }

  res.json({
    success: true,
    message: `Rule ${removedRule.id} removed.`,
    rule: removedRule,
  });
});

module.exports = router;
