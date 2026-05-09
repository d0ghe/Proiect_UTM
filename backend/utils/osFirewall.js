/**
 * osFirewall.js — UTM Platform · Windows Firewall bridge
 *
 * Uses PowerShell New-NetFirewallRule / Remove-NetFirewallRule (Windows 8+).
 * These cmdlets are more reliable than netsh and have clear error messages.
 *
 * Requires the Node process to run as Administrator.
 * If not elevated, returns success=false with a clear message.
 */

const { exec } = require('child_process');

const IS_WIN = process.platform === 'win32';

/* ─── helpers ────────────────────────────────────────────────────────────── */

function run(cmd, timeout = 15_000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout }, (err, stdout, stderr) => {
      resolve({
        ok:     !err,
        out:    (stdout || '').trim(),
        err:    (stderr || '').trim(),
        errmsg: err ? err.message : '',
      });
    });
  });
}

function notAdmin(r) {
  const t = `${r.out} ${r.err} ${r.errmsg}`.toLowerCase();
  return (
    t.includes('requires elevation') ||
    t.includes('access is denied')   ||
    t.includes('access denied')      ||
    t.includes('(5)')                ||
    t.includes('is not recognized')  ||
    t.includes('operation not permitted')
  );
}

/* ─── Stable rule display name ───────────────────────────────────────────── */

function dispName(rule, dir) {
  // e.g.  UTM_BLOCK_TCP_80_1746012345_OUT
  return `UTM_${rule.action}_${rule.protocol}_${rule.port}_${rule.id}_${dir}`;
}

/* ─── PowerShell command builders ────────────────────────────────────────── */

function psAdd(rule, dir) {
  const name   = dispName(rule, dir);
  const action = rule.action === 'BLOCK' ? 'Block' : 'Allow';
  const proto  = rule.protocol; // TCP | UDP | ICMP
  const port   = rule.port;
  const dirPs  = dir === 'OUT' ? 'Outbound' : 'Inbound';

  if (proto === 'ICMP') {
    return (
      `New-NetFirewallRule -DisplayName '${name}' ` +
      `-Direction ${dirPs} -Protocol ICMPv4 -Action ${action} -Enabled True -ErrorAction Stop`
    );
  }

  // For Outbound rules: RemotePort = destination port (blocks browser→port80)
  // For Inbound rules:  LocalPort  = destination port  (blocks external→local port)
  const portParam = dir === 'OUT'
    ? `-RemotePort ${port}`
    : `-LocalPort ${port}`;

  return (
    `New-NetFirewallRule -DisplayName '${name}' ` +
    `-Direction ${dirPs} -Protocol ${proto} ${portParam} ` +
    `-Action ${action} -Enabled True -ErrorAction Stop`
  );
}

function psDel(rule, dir) {
  const name = dispName(rule, dir);
  return `Remove-NetFirewallRule -DisplayName '${name}' -ErrorAction SilentlyContinue`;
}

function wrapPs(cmd) {
  // Run a single PowerShell command and exit with the error count
  return `powershell -NonInteractive -ExecutionPolicy Bypass -Command "${cmd.replace(/"/g, '\\"')}"`;
}

/* ─── Linux iptables ─────────────────────────────────────────────────────── */

function ipt(rule, chain, op) {
  const proto  = rule.protocol.toLowerCase();
  const port   = rule.port;
  const target = rule.action === 'BLOCK' ? 'DROP' : 'ACCEPT';
  if (proto === 'icmp') return `iptables ${op} ${chain} -p ${proto} -j ${target}`;
  return `iptables ${op} ${chain} -p ${proto} --dport ${port} -j ${target}`;
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

async function applyOsRule(rule) {
  if (String(rule.status).toLowerCase() !== 'active') {
    return { success: true, osApplied: false, message: 'Rule inactive — not sent to OS.' };
  }

  let outRes, inRes;

  if (IS_WIN) {
    [outRes, inRes] = await Promise.all([
      run(wrapPs(psAdd(rule, 'OUT'))),
      run(wrapPs(psAdd(rule, 'IN'))),
    ]);
  } else {
    [outRes, inRes] = await Promise.all([
      run(ipt(rule, 'OUTPUT', '-A')),
      run(ipt(rule, 'INPUT',  '-A')),
    ]);
  }

  const allOk = outRes.ok && inRes.ok;
  const failed = [outRes, inRes].find((r) => !r.ok);

  if (allOk) {
    return {
      success:   true,
      osApplied: true,
      message:   'Regulă aplicată în Windows Firewall (Outbound + Inbound).',
    };
  }

  if (failed && notAdmin(failed)) {
    return {
      success:   false,
      osApplied: false,
      message:   'Necesită Administrator: pornește backend-ul ca Admin (click dreapta → Run as administrator).',
    };
  }

  const errDetail = failed ? (failed.out || failed.err || failed.errmsg) : 'eroare necunoscută';
  return {
    success:   false,
    osApplied: false,
    message:   `Eroare Windows Firewall: ${errDetail}`,
  };
}

async function removeOsRule(rule) {
  if (!IS_WIN) {
    // Linux: best effort
    const proto  = rule.protocol.toLowerCase();
    const port   = rule.port;
    const target = rule.action === 'BLOCK' ? 'DROP' : 'ACCEPT';
    await Promise.all([
      run(`iptables -D OUTPUT -p ${proto} --dport ${port} -j ${target}`),
      run(`iptables -D INPUT  -p ${proto} --dport ${port} -j ${target}`),
    ]);
    return { success: true, osRemoved: true, message: 'Regulă eliminată (iptables).' };
  }

  const [outRes, inRes] = await Promise.all([
    run(wrapPs(psDel(rule, 'OUT'))),
    run(wrapPs(psDel(rule, 'IN'))),
  ]);

  const allOk = outRes.ok && inRes.ok;
  return {
    success:   allOk,
    osRemoved: allOk,
    message:   allOk
      ? 'Regulă eliminată din Windows Firewall.'
      : `Atenție: regula din UI a fost ștearsă, dar eliminarea din Windows Firewall a eșuat: ${[outRes, inRes].find((r) => !r.ok)?.err || ''}`,
  };
}

/**
 * Check if Windows Firewall is enabled and the service is running.
 * Returns { enabled: bool, profile: string, message: string }
 */
async function checkFirewallStatus() {
  if (!IS_WIN) return { enabled: true, profile: 'linux', message: 'iptables available.' };

  const r = await run(
    'powershell -NonInteractive -ExecutionPolicy Bypass -Command ' +
    '"(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object Enabled -eq True).Count"',
    5000,
  );

  const count = parseInt(r.out, 10);
  if (!r.ok || isNaN(count)) {
    return { enabled: false, profile: 'unknown', message: 'Nu s-a putut verifica starea Windows Firewall.' };
  }

  return {
    enabled: count > 0,
    profile: `${count} profile(s) active`,
    message: count > 0
      ? `Windows Firewall activ (${count} profile).`
      : 'ATENȚIE: Windows Firewall dezactivat — regulile nu au efect!',
  };
}

module.exports = { applyOsRule, removeOsRule, checkFirewallStatus };
