const express = require('express');

const verifyToken = require('../middleware/verifyToken');
const {
  addFirewallRule,
  countActiveFirewallRules,
  deleteFirewallRule,
  getFirewallRule,
  getFirewallRules,
  updateFirewallRule,
} = require('../store/runtimeState');
const {
  PROTECTED_WEB_PORTS,
  applyFirewallRuleToOs,
  inspectFirewallEnvironment,
  removeFirewallRuleFromOs,
  validateFirewallRule,
} = require('../utils/firewallManager');

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
      osApplied:    rules.filter((r) => Boolean(r.osApplied)).length,
      osFirewall:   inspectFirewallEnvironment(),
    },
  });
});

router.post('/rules', (req, res) => {
  const { action, protocol, port, ip, status, desc } = req.body || {};

  const portNum = Number(port);
  if (!port || !Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
    return res.status(400).json({ success: false, message: 'Invalid port (1-65535).' });
  }

  if (String(action || '').toUpperCase() === 'BLOCK' && PROTECTED_WEB_PORTS.has(portNum)) {
    return res.status(400).json({
      success: false,
      message: `Port ${portNum} is protected so normal web/DNS connectivity stays available. Use ALLOW for this port or block a narrower app/domain policy instead.`,
    });
  }

  const validation = validateFirewallRule({ action, protocol, port: portNum, ip });
  if (!validation.valid) {
    return res.status(400).json({ success: false, message: validation.message });
  }

  const rule = addFirewallRule({ action, protocol, port: portNum, ip, status, desc });
  const osFirewall = String(rule.status).toLowerCase() === 'active'
    ? applyFirewallRuleToOs(rule)
    : { success: true, applied: false, message: 'Rule saved as inactive; OS firewall was not changed.' };
  const nextRule = updateFirewallRule(rule.id, {
    osApplied: Boolean(osFirewall.applied),
    osMessage: osFirewall.message,
  }) || rule;

  res.status(201).json({
    success: true,
    message: osFirewall.applied
      ? 'The rule was added and applied to the OS firewall.'
      : 'The rule was saved in the application, but it was not applied to Windows Firewall.',
    osFirewall,
    rule: nextRule,
  });
});

router.post('/relaunch-admin', (_req, res) => {
  res.json({
    success: true,
    message: 'Platform restart is no longer required.',
    result: {
      relaunchRequired: false,
    },
  });
});

router.delete('/rules/:id', (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    return res.status(400).json({ success: false, message: 'ID invalid.' });
  }

  const existingRule = getFirewallRule(id);
  if (!existingRule) {
    return res.status(404).json({ success: false, message: `Rule ${id} does not exist.` });
  }

  let osFirewall = { success: true, applied: false, message: 'No OS firewall rule was recorded for this entry.' };
  if (existingRule.osApplied) {
    osFirewall = removeFirewallRuleFromOs(existingRule.id);
    if (!osFirewall.success) {
      return res.status(500).json({
        success: false,
        message: osFirewall.message,
        osFirewall,
        rule: existingRule,
      });
    }
  }

  const removedRule = deleteFirewallRule(id);

  res.json({ success: true, message: `Rule for port ${removedRule.port} deleted.`, osFirewall, rule: removedRule });
});

module.exports = router;
