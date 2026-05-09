/**
 * systemProxy.js — UTM Platform · Multi-Browser Proxy Configurator
 *
 * Sets proxy settings for every major browser WITHOUT administrator privileges:
 *
 *   Chrome / Edge / Brave / Opera / Vivaldi / IE
 *     → HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
 *       (WinINET — all Chromium-based browsers read this)
 *
 *   Firefox
 *     → %APPDATA%\Mozilla\Firefox\Profiles\*\user.js
 *       (user.js is always read on startup, overrides prefs.js)
 *       Firefox must be restarted once after the server starts to pick it up.
 *
 *   Bonus — if Node runs as Administrator:
 *     → New-NetFirewallRule (PowerShell) blocks at OS level:
 *       no browser can bypass it regardless of its proxy settings.
 */

'use strict';

const { exec }  = require('child_process');
const fs        = require('fs');
const path      = require('path');
const os        = require('os');

const REG_INET = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

/* ─── helpers ────────────────────────────────────────────────────────────── */

function cmd(command, timeout = 8000) {
  return new Promise((resolve) =>
    exec(command, { timeout }, (err, stdout, stderr) =>
      resolve({ ok: !err, out: (stdout || '').trim(), err: (stderr || '').trim() })
    )
  );
}

/* ─── 1. WinINET (Chrome / Edge / Brave / Opera / Vivaldi / IE) ─────────── */

async function setWinInetProxy(host, port) {
  if (process.platform !== 'win32') return { ok: true, note: 'skipped (non-Windows)' };

  const proxy = `${host}:${port}`;
  const results = await Promise.all([
    cmd(`reg add "${REG_INET}" /v ProxyEnable /t REG_DWORD /d 1 /f`),
    cmd(`reg add "${REG_INET}" /v ProxyServer /t REG_SZ /d "${proxy}" /f`),
    cmd(`reg add "${REG_INET}" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;<local>" /f`),
  ]);

  const failed = results.find((r) => !r.ok);
  if (failed) return { ok: false, note: `Registry write failed: ${failed.err}` };

  // Notify the system immediately so Chrome picks up without restart
  await notifyWinInet();
  return { ok: true, note: `WinINET proxy set → ${proxy}` };
}

async function clearWinInetProxy() {
  if (process.platform !== 'win32') return;
  await cmd(`reg add "${REG_INET}" /v ProxyEnable /t REG_DWORD /d 0 /f`);
  await notifyWinInet();
}

async function notifyWinInet() {
  // Calls InternetSetOption to make Chrome/Edge apply changes immediately
  const ps = `Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class WI {
  [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);
}
'@; [WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null; [WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`;
  await cmd(`powershell -NonInteractive -ExecutionPolicy Bypass -Command "${ps.replace(/\r?\n/g, ' ')}"`);
}

/* ─── 2. Firefox (user.js in every profile) ──────────────────────────────── */

const FIREFOX_PROFILES_DIR = path.join(
  os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'
);

const UTM_TAG = '// UTM_PROXY_START';
const UTM_END = '// UTM_PROXY_END';

function buildFirefoxPrefs(host, port) {
  return [
    UTM_TAG,
    `user_pref("network.proxy.type", 1);`,
    `user_pref("network.proxy.http", "${host}");`,
    `user_pref("network.proxy.http_port", ${port});`,
    `user_pref("network.proxy.ssl", "${host}");`,
    `user_pref("network.proxy.ssl_port", ${port});`,
    `user_pref("network.proxy.ftp", "${host}");`,
    `user_pref("network.proxy.ftp_port", ${port});`,
    `user_pref("network.proxy.no_proxies_on", "localhost,127.0.0.1");`,
    UTM_END,
  ].join('\n');
}

function getFirefoxProfiles() {
  try {
    if (!fs.existsSync(FIREFOX_PROFILES_DIR)) return [];
    return fs
      .readdirSync(FIREFOX_PROFILES_DIR)
      .map((name) => path.join(FIREFOX_PROFILES_DIR, name))
      .filter((p) => fs.statSync(p).isDirectory());
  } catch {
    return [];
  }
}

function setFirefoxProxy(host, port) {
  const profiles = getFirefoxProfiles();
  if (profiles.length === 0) return { ok: false, note: 'Firefox not found or no profiles.' };

  const prefs = buildFirefoxPrefs(host, port);
  let written = 0;

  for (const profileDir of profiles) {
    try {
      const userJs = path.join(profileDir, 'user.js');
      // Remove any previous UTM block then append fresh one
      let existing = '';
      if (fs.existsSync(userJs)) {
        existing = fs.readFileSync(userJs, 'utf8');
        // Strip old UTM block
        existing = existing.replace(
          new RegExp(`${UTM_TAG}[\\s\\S]*?${UTM_END}`, 'g'), ''
        ).trim();
      }
      fs.writeFileSync(userJs, (existing ? existing + '\n\n' : '') + prefs + '\n', 'utf8');
      written++;
    } catch { /* skip locked profile */ }
  }

  return {
    ok:   written > 0,
    note: written > 0
      ? `Firefox proxy set in ${written} profile(s). Restart Firefox once to apply.`
      : 'Could not write to any Firefox profile.',
  };
}

function clearFirefoxProxy() {
  for (const profileDir of getFirefoxProfiles()) {
    try {
      const userJs = path.join(profileDir, 'user.js');
      if (!fs.existsSync(userJs)) continue;
      let content = fs.readFileSync(userJs, 'utf8');
      content = content.replace(new RegExp(`${UTM_TAG}[\\s\\S]*?${UTM_END}`, 'g'), '').trim();
      if (content) {
        fs.writeFileSync(userJs, content + '\n', 'utf8');
      } else {
        fs.unlinkSync(userJs); // file only had UTM block → remove it
      }
    } catch { /* ignore */ }
  }
}

/* ─── 3. Windows Firewall (when running as Administrator) ───────────────── */

async function isWindowsAdmin() {
  if (process.platform !== 'win32') return false;
  // "net session" succeeds only when elevated
  const r = await cmd('net session', 3000);
  return r.ok;
}

function fwRuleName(rule, dir) {
  // e.g. UTM_BLOCK_TCP_80_OUT  (no id — survives rule re-add)
  return `UTM_${rule.action}_${rule.protocol}_${rule.port}_${dir}`;
}

function netshAdd(rule, dir) {
  const name   = fwRuleName(rule, dir);
  const proto  = rule.protocol.toUpperCase();
  const action = rule.action === 'BLOCK' ? 'block' : 'allow';
  const port   = rule.port;

  if (proto === 'ICMP') {
    return `netsh advfirewall firewall add rule name="${name}" protocol=icmpv4 dir=${dir.toLowerCase()} action=${action}`;
  }
  // OUT → remoteport blocks outbound to that port (e.g. browser → site:80)
  // IN  → localport  blocks inbound on that port
  const portParam = dir === 'OUT' ? `remoteport=${port}` : `localport=${port}`;
  return `netsh advfirewall firewall add rule name="${name}" protocol=${proto} dir=${dir.toLowerCase()} ${portParam} action=${action}`;
}

function netshDel(rule, dir) {
  return `netsh advfirewall firewall delete rule name="${fwRuleName(rule, dir)}"`;
}

async function applyOsFirewallRule(rule) {
  const admin = await isWindowsAdmin();
  if (!admin) return { ok: false, note: 'Not admin — OS firewall skipped (proxy still active).' };

  // Delete first (idempotent — avoids duplicate-rule errors on re-add)
  await Promise.all([
    cmd(netshDel(rule, 'OUT')),
    cmd(netshDel(rule, 'IN')),
  ]);

  const [outRes, inRes] = await Promise.all([
    cmd(netshAdd(rule, 'OUT')),
    cmd(netshAdd(rule, 'IN')),
  ]);

  // netsh prints "Ok." on success; non-zero exit = failure
  const allOk = outRes.ok && inRes.ok;
  return {
    ok:   allOk,
    note: allOk
      ? `OS Firewall applied — ALL browsers & apps blocked on port ${rule.port}.`
      : `OS Firewall error: OUT="${outRes.out||outRes.err}" IN="${inRes.out||inRes.err}"`,
  };
}

async function removeOsFirewallRule(rule) {
  const admin = await isWindowsAdmin();
  if (!admin) return { ok: false, note: 'Not admin — OS firewall skipped.' };

  const [outRes, inRes] = await Promise.all([
    cmd(netshDel(rule, 'OUT')),
    cmd(netshDel(rule, 'IN')),
  ]);

  return {
    ok:   outRes.ok && inRes.ok,
    note: 'OS Firewall rule removed.',
  };
}

/**
 * Called on server startup as admin — re-applies OS Firewall rules
 * for every active BLOCK rule currently in the in-memory store.
 */
async function syncOsFirewallRules(rules) {
  const admin = await isWindowsAdmin();
  if (!admin) return;

  const blockRules = rules.filter(
    (r) => String(r.action).toUpperCase() === 'BLOCK' &&
           String(r.status).toLowerCase() === 'active'
  );

  console.log(`[+] Syncing ${blockRules.length} BLOCK rule(s) to Windows Firewall...`);
  for (const rule of blockRules) {
    const res = await applyOsFirewallRule(rule);
    console.log(`    port ${rule.port}: ${res.note}`);
  }
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

async function enableProxy(host, port) {
  if (process.platform !== 'win32') return { ok: true, browsers: [], note: 'Non-Windows.' };

  const [inetRes, ffRes] = await Promise.all([
    setWinInetProxy(host, port),
    Promise.resolve(setFirefoxProxy(host, port)),
  ]);

  const admin = await isWindowsAdmin();

  return {
    ok:       inetRes.ok,
    admin,
    browsers: {
      chromium: inetRes.ok  ? 'active' : 'failed',
      firefox:  ffRes.ok    ? 'active (restart Firefox)' : ffRes.note,
      os:       admin       ? 'Windows Firewall available' : 'not admin — proxy only',
    },
    notes: [inetRes.note, ffRes.note].filter(Boolean),
  };
}

async function disableProxy() {
  if (process.platform !== 'win32') return;
  await clearWinInetProxy();
  clearFirefoxProxy();
}

module.exports = {
  enableProxy,
  disableProxy,
  applyOsFirewallRule,
  removeOsFirewallRule,
  syncOsFirewallRules,
  isWindowsAdmin,
};
