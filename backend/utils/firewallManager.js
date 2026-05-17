const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const PROTECTED_WEB_PORTS = new Set([53, 80, 443]);
const RULE_PREFIX = 'Argus Firewall Rule';

function runPowerShell(script, timeout = 10000) {
  if (process.platform !== 'win32') {
    return {
      status: 1,
      stdout: '',
      stderr: 'Windows Firewall commands are only available on Windows.',
    };
  }

  return spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { encoding: 'utf8', timeout, windowsHide: true },
  );
}

function psSingleQuote(value) {
  return `'${String(value || '').replace(/'/g, "''")}'`;
}

function getRuleDisplayName(ruleId) {
  return `${RULE_PREFIX} ${ruleId}`;
}

function getFirewallScriptPath(prefix) {
  const directory = path.join(process.env.TEMP || process.env.TMP || __dirname, 'argus');
  fs.mkdirSync(directory, { recursive: true });
  return path.join(directory, `${prefix}-${process.pid}-${Date.now()}.ps1`);
}

function isElevated() {
  if (process.platform !== 'win32') {
    return false;
  }

  const result = runPowerShell(
    '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
    5000,
  );

  return String(result.stdout || '').trim().toLowerCase() === 'true';
}

function inspectFirewallEnvironment() {
  if (process.platform !== 'win32') {
    return {
      supported: false,
      enforcementEnabled: false,
      canApply: false,
      platform: process.platform,
      message: 'OS firewall enforcement is implemented for Windows only. Rules remain available to the local proxy.',
    };
  }

  const canApply = isElevated();
  return {
    supported: true,
    enforcementEnabled: true,
    canApply,
    canElevatePerOperation: !canApply,
    requiresBackendRelaunch: false,
    platform: process.platform,
    message: canApply
      ? 'Windows Firewall rules can be applied directly.'
      : '',
  };
}

function normalizeProtocol(protocol) {
  const normalized = String(protocol || '').trim().toUpperCase();
  return ['TCP', 'UDP'].includes(normalized) ? normalized : '';
}

function normalizeAction(action) {
  const normalized = String(action || '').trim().toUpperCase();
  return ['ALLOW', 'BLOCK'].includes(normalized) ? normalized : '';
}

function normalizeAddress(ip) {
  const value = String(ip || 'Any').trim();
  return value && value.toLowerCase() !== 'any' ? value : 'Any';
}

function validateFirewallRule(rule = {}) {
  const action = normalizeAction(rule.action);
  if (!action) {
    return { valid: false, message: 'Action must be ALLOW or BLOCK.' };
  }

  const protocol = normalizeProtocol(rule.protocol);
  if (!protocol) {
    return { valid: false, message: 'Protocol must be TCP or UDP.' };
  }

  const port = Number(rule.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { valid: false, message: 'Port must be between 1 and 65535.' };
  }

  const address = normalizeAddress(rule.ip);
  if (/\s/.test(address)) {
    return { valid: false, message: 'IP / scope must not contain spaces.' };
  }

  return { valid: true, message: '' };
}

function buildFirewallCommand(rule) {
  const displayName = getRuleDisplayName(rule.id);
  const action = normalizeAction(rule.action) === 'BLOCK' ? 'Block' : 'Allow';
  const protocol = normalizeProtocol(rule.protocol);
  const port = Number(rule.port);
  const address = normalizeAddress(rule.ip);
  const remoteAddress = address === 'Any' ? '' : ` -RemoteAddress ${psSingleQuote(address)}`;

  return [
    `$name=${psSingleQuote(displayName)};`,
    'Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue;',
    `New-NetFirewallRule -DisplayName $name -Direction Outbound -Protocol ${protocol} -RemotePort ${port}${remoteAddress} -Action ${action} -Enabled True -ErrorAction Stop | Out-Null;`,
  ].join('');
}

function runElevatedFirewallScript(scriptBody, timeout = 120000) {
  if (process.platform !== 'win32') {
    return {
      status: 1,
      stdout: '',
      stderr: 'Windows Firewall elevation is only available on Windows.',
    };
  }

  const scriptPath = getFirewallScriptPath('firewall-op');
  const wrappedScript = [
    '$ErrorActionPreference = "Stop"',
    'try {',
    scriptBody,
    '  exit 0',
    '} catch {',
    '  Write-Error $_',
    '  exit 1',
    '}',
    '',
  ].join('\n');
  fs.writeFileSync(scriptPath, wrappedScript, 'utf8');

  const launcher = [
    `$script=${psSingleQuote(scriptPath)};`,
    '$args=@(',
    psSingleQuote('-NoProfile'),
    ',',
    psSingleQuote('-ExecutionPolicy'),
    ',',
    psSingleQuote('Bypass'),
    ',',
    psSingleQuote('-WindowStyle'),
    ',',
    psSingleQuote('Hidden'),
    ',',
    psSingleQuote('-File'),
    ',$script);',
    '$p=Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList $args;',
    'exit $p.ExitCode',
  ].join('');

  const result = runPowerShell(launcher, timeout);
  try { fs.unlinkSync(scriptPath); } catch { /* ignore */ }
  return result;
}

function applyFirewallRuleToOs(rule) {
  const validation = validateFirewallRule(rule);
  if (!validation.valid) {
    return { success: false, applied: false, message: validation.message };
  }

  const environment = inspectFirewallEnvironment();
  if (!environment.supported) {
    return { success: true, applied: false, message: environment.message };
  }

  if (!environment.canApply) {
    const elevatedResult = runElevatedFirewallScript(buildFirewallCommand(rule));
    if (elevatedResult.status === 0) {
      return {
        success: true,
        applied: true,
        message: `Windows Firewall rule applied: ${getRuleDisplayName(rule.id)}.`,
      };
    }

    return {
      success: false,
      applied: false,
      message: (elevatedResult.stderr || elevatedResult.stdout || 'Administrator approval was cancelled or the firewall rule failed.').trim(),
    };
  }

  const result = runPowerShell(buildFirewallCommand(rule));
  if (result.status !== 0) {
    return {
      success: false,
      applied: false,
      message: (result.stderr || result.stdout || 'Windows Firewall rejected the rule.').trim(),
    };
  }

  return {
    success: true,
    applied: true,
    message: `Windows Firewall rule applied: ${getRuleDisplayName(rule.id)}.`,
  };
}

function removeFirewallRuleFromOs(ruleId) {
  const environment = inspectFirewallEnvironment();
  if (!environment.supported) {
    return { success: true, applied: false, message: environment.message };
  }

  if (!environment.canApply) {
    const elevatedResult = runElevatedFirewallScript(
      `$name=${psSingleQuote(getRuleDisplayName(ruleId))};Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue`,
    );
    if (elevatedResult.status === 0) {
      return {
        success: true,
        applied: true,
        message: `Windows Firewall rule removed: ${getRuleDisplayName(ruleId)}.`,
      };
    }

    return {
      success: false,
      applied: false,
      message: (elevatedResult.stderr || elevatedResult.stdout || 'Administrator approval was cancelled or the firewall rule could not be removed.').trim(),
    };
  }

  const displayName = getRuleDisplayName(ruleId);
  const result = runPowerShell(
    `$name=${psSingleQuote(displayName)};Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue`,
  );

  if (result.status !== 0) {
    return {
      success: false,
      applied: false,
      message: (result.stderr || result.stdout || 'Could not remove Windows Firewall rule.').trim(),
    };
  }

  return {
    success: true,
    applied: true,
    message: `Windows Firewall rule removed: ${displayName}.`,
  };
}

module.exports = {
  PROTECTED_WEB_PORTS,
  applyFirewallRuleToOs,
  inspectFirewallEnvironment,
  removeFirewallRuleFromOs,
  validateFirewallRule,
};
