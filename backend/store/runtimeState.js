const fs = require('fs');
const path = require('path');

const FIREWALL_RULES_FILE = path.join(__dirname, 'firewall-rules.json');

const DEFAULT_FIREWALL_RULES = [
  {
    id: 1,
    action: 'BLOCK',
    protocol: 'TCP',
    port: 22,
    ip: 'Any',
    status: 'Active',
    desc: 'Block remote SSH access',
    osApplied: false,
  },
  {
    id: 2,
    action: 'ALLOW',
    protocol: 'TCP',
    port: 80,
    ip: 'Any',
    status: 'Active',
    desc: 'Allow HTTP traffic',
    osApplied: false,
  },
  {
    id: 3,
    action: 'ALLOW',
    protocol: 'TCP',
    port: 443,
    ip: 'Any',
    status: 'Active',
    desc: 'Allow HTTPS traffic',
    osApplied: false,
  },
  {
    id: 4,
    action: 'ALLOW',
    protocol: 'UDP',
    port: 53,
    ip: 'Any',
    status: 'Active',
    desc: 'Allow DNS lookups',
    osApplied: false,
  },
];

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeRule(rule = {}) {
  return {
    id: Number(rule.id || Date.now()),
    action: String(rule.action || 'ALLOW').toUpperCase(),
    protocol: String(rule.protocol || 'TCP').toUpperCase(),
    port: Number(rule.port || 0),
    ip: rule.ip || 'Any',
    status: rule.status || 'Active',
    desc: rule.desc || 'Custom rule',
    osApplied: Boolean(rule.osApplied),
    osMessage: rule.osMessage || '',
    createdAt: rule.createdAt || new Date().toISOString(),
  };
}

function loadFirewallRules() {
  try {
    if (!fs.existsSync(FIREWALL_RULES_FILE)) {
      return clone(DEFAULT_FIREWALL_RULES).map(normalizeRule);
    }

    const parsed = JSON.parse(fs.readFileSync(FIREWALL_RULES_FILE, 'utf8'));
    if (!Array.isArray(parsed)) {
      return clone(DEFAULT_FIREWALL_RULES).map(normalizeRule);
    }

    return parsed.map(normalizeRule);
  } catch {
    return clone(DEFAULT_FIREWALL_RULES).map(normalizeRule);
  }
}

function saveFirewallRules() {
  fs.writeFileSync(FIREWALL_RULES_FILE, JSON.stringify(firewallRules, null, 2));
}

const firewallRules = loadFirewallRules();

const controls = {
  firewallEnabled: true,
  protectionEnabled: true,
  telemetryEnabled: true,
  eventsEnabled: true,
  maintenanceMode: false,
};

let lastUpdated = new Date().toISOString();

function cloneRule(rule) {
  return { ...rule };
}

function markUpdated() {
  lastUpdated = new Date().toISOString();
}

function getFirewallRules() {
  return firewallRules.map(cloneRule);
}

function getFirewallRule(id) {
  const rule = firewallRules.find((candidate) => candidate.id === id);
  return rule ? cloneRule(rule) : null;
}

function addFirewallRule(payload) {
  const newRule = normalizeRule({
    id: Date.now(),
    ...payload,
    createdAt: new Date().toISOString(),
  });

  firewallRules.unshift(newRule);
  markUpdated();
  saveFirewallRules();
  return cloneRule(newRule);
}

function updateFirewallRule(id, patch = {}) {
  const index = firewallRules.findIndex((rule) => rule.id === id);
  if (index === -1) {
    return null;
  }

  firewallRules[index] = normalizeRule({
    ...firewallRules[index],
    ...patch,
    id: firewallRules[index].id,
    createdAt: firewallRules[index].createdAt,
  });
  markUpdated();
  saveFirewallRules();
  return cloneRule(firewallRules[index]);
}

function deleteFirewallRule(id) {
  const index = firewallRules.findIndex((rule) => rule.id === id);
  if (index === -1) {
    return null;
  }

  const [removed] = firewallRules.splice(index, 1);
  markUpdated();
  saveFirewallRules();
  return cloneRule(removed);
}

function countActiveFirewallRules() {
  return firewallRules.filter((rule) => String(rule.status).toLowerCase() === 'active').length;
}

function getControls() {
  return {
    ...controls,
    lastUpdated,
  };
}

function updateControls(patch) {
  Object.entries(patch || {}).forEach(([key, value]) => {
    if (Object.prototype.hasOwnProperty.call(controls, key)) {
      controls[key] = Boolean(value);
    }
  });

  markUpdated();
  return getControls();
}

module.exports = {
  addFirewallRule,
  countActiveFirewallRules,
  deleteFirewallRule,
  getFirewallRule,
  getControls,
  getFirewallRules,
  updateFirewallRule,
  updateControls,
};
