const firewallRules = [
  {
    id: 1,
    action: 'BLOCK',
    protocol: 'TCP',
    port: 22,
    ip: 'Any',
    status: 'Active',
    desc: 'Block remote SSH access',
  },
  {
    id: 2,
    action: 'ALLOW',
    protocol: 'TCP',
    port: 80,
    ip: 'Any',
    status: 'Active',
    desc: 'Allow HTTP traffic',
  },
];

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

function addFirewallRule(payload) {
  const newRule = {
    id: Date.now(),
    action: String(payload.action || 'ALLOW').toUpperCase(),
    protocol: String(payload.protocol || 'TCP').toUpperCase(),
    port: Number(payload.port || 0),
    ip: payload.ip || 'Any',
    status: payload.status || 'Active',
    desc: payload.desc || 'Custom rule',
  };

  firewallRules.unshift(newRule);
  markUpdated();
  return cloneRule(newRule);
}

function deleteFirewallRule(id) {
  const index = firewallRules.findIndex((rule) => rule.id === id);
  if (index === -1) {
    return null;
  }

  const [removed] = firewallRules.splice(index, 1);
  markUpdated();
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
  getControls,
  getFirewallRules,
  updateControls,
};
