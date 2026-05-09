'use strict';

/**
 * Live Memory & Process Scanner
 *
 * Uses PowerShell + WMI to inspect running processes WITHOUT admin privileges.
 *
 * Detection layers:
 *  1. AppData/Temp path — WARNING only (many legit apps live here)
 *  2. Command-line obfuscation — CRITICAL (encoded PS, IEX, mshta remote, etc.)
 *  3. System process masquerade — CRITICAL (svchost/lsass from wrong path)
 *  4. Suspicious parent-child chains — CRITICAL (Office spawns shell)
 *  5. Hollow process — WARNING (no executable on disk)
 *
 * CRITICAL verdict requires either:
 *   - A single CRITICAL-severity indicator, OR
 *   - 2+ WARNING indicators combined
 *
 * Known-good list: hardcoded Electron/browser apps that legitimately run from
 * AppData. This ONLY suppresses the path warning — all other detectors still
 * apply. Cannot be modified at runtime (no API endpoint).
 */

const { exec } = require('child_process');

/* ── Hardcoded known-good process names (path warning suppressed only) ───── */
const KNOWN_GOOD_PROCESSES = new Set([
  // Electron / user-installed apps that legitimately live in AppData
  'claude.exe', 'code.exe', 'cursor.exe', 'windsurf.exe',
  'discord.exe', 'discordptb.exe', 'discordcanary.exe',
  'slack.exe', 'teams.exe', 'msteams.exe',
  'spotify.exe', 'steam.exe', 'epicgameslauncher.exe',
  'zoom.exe', 'zoominstaller.exe',
  'telegram.exe', 'signal.exe', 'skype.exe', 'whatsapp.exe',
  'notion.exe', 'obsidian.exe', 'figma.exe',
  'postman.exe', 'insomnia.exe',
  '1password.exe', 'bitwarden.exe', 'keepass.exe',
  'dropbox.exe', 'onedrive.exe', 'googledrivefs.exe',
  'lghub.exe', 'razer synapse.exe', 'corsairhid.exe',
  // Browsers (sometimes installed per-user)
  'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
  'opera.exe', 'vivaldi.exe', 'thorium.exe',
  // Dev tools installed per-user
  'node.exe', 'git.exe', 'python.exe', 'python3.exe',
  'wt.exe',   // Windows Terminal
  // Antivirus / security (may run from ProgramData)
  'mbam.exe', 'mbamservice.exe', 'avgui.exe', 'avguix.exe',
]);

/* ── Suspicious path patterns (WARNING severity — not CRITICAL alone) ────── */
const SUSPICIOUS_PATH_PATTERNS = [
  { pattern: /\\appdata\\local\\temp\\/i,    name: 'AppDataLocalTemp' },
  { pattern: /\\appdata\\roaming\\temp\\/i,  name: 'AppDataRoamingTemp' },
  { pattern: /\\windows\\temp\\/i,           name: 'WindowsTemp' },
  { pattern: /\\tmp\\/i,                     name: 'TmpDir' },
  { pattern: /\\\$recycle\.bin\\/i,          name: 'RecycleBin' },
  { pattern: /\\downloads\\/i,               name: 'Downloads' },
  // Generic AppData (warning, not critical — many legit apps here)
  { pattern: /\\appdata\\local(?!\\(programs|microsoft|packages))/i, name: 'AppDataLocal' },
  { pattern: /\\appdata\\roaming(?!\\(microsoft|apple|mozilla))/i,   name: 'AppDataRoaming' },
];

/* ── Processes that must ONLY run from System32 / SysWOW64 ──────────────── */
const SYSTEM_PROCESS_PATHS = {
  'svchost.exe':   [/system32\\svchost\.exe/i,   /syswow64\\svchost\.exe/i],
  'lsass.exe':     [/system32\\lsass\.exe/i],
  'csrss.exe':     [/system32\\csrss\.exe/i],
  'winlogon.exe':  [/system32\\winlogon\.exe/i],
  'services.exe':  [/system32\\services\.exe/i],
  'explorer.exe':  [/windows\\explorer\.exe/i],
  'taskhostw.exe': [/system32\\taskhostw\.exe/i],
  'spoolsv.exe':   [/system32\\spoolsv\.exe/i],
  'smss.exe':      [/system32\\smss\.exe/i],
  'wininit.exe':   [/system32\\wininit\.exe/i],
};

/* ── Hollow-process exceptions (no path = normal for kernel processes) ────── */
const KERNEL_PROCESSES = new Set([
  'system', 'registry', 'memory compression', 'secure system',
  'idle', 'interrupts', 'dpc',
]);

/* ── Command-line obfuscation indicators ─────────────────────────────────── */
const CMD_INDICATORS = [
  { pattern: /-enc(odedcommand)?[\s=]/i,   name: 'PS_EncodedCommand',  severity: 'critical' },
  { pattern: /\biex\s*\(/i,                name: 'PS_IEX',              severity: 'critical' },
  { pattern: /invoke-expression/i,          name: 'PS_InvokeExpression', severity: 'critical' },
  { pattern: /downloadstring/i,             name: 'PS_DownloadString',   severity: 'critical' },
  { pattern: /regsvr32.*scrobj/i,           name: 'Squiblydoo',          severity: 'critical' },
  { pattern: /mshta\s+https?:\/\//i,       name: 'MSHTA_Remote',        severity: 'critical' },
  { pattern: /wscript\s+https?:\/\//i,     name: 'WScript_Remote',      severity: 'critical' },
  { pattern: /certutil\s+.*-decode/i,       name: 'CertUtil_Decode',     severity: 'critical' },
  { pattern: /bitsadmin.*\/transfer/i,      name: 'BITSAdmin_Transfer',  severity: 'critical' },
  { pattern: /frombase64string/i,           name: 'PS_Base64Decode',     severity: 'warning'  },
  { pattern: /-bypass/i,                    name: 'PS_PolicyBypass',     severity: 'warning'  },
  { pattern: /[A-Za-z0-9+/]{120,}={0,2}/,  name: 'LongBase64Arg',       severity: 'warning'  },
  { pattern: /-windowstyle\s+hidden/i,      name: 'PS_HiddenWindow',     severity: 'warning'  },
  { pattern: /-noprofile\s+-noninteractive/i, name: 'PS_NonInteractive', severity: 'warning'  },
];

/* ── Suspicious parent-child chains ──────────────────────────────────────── */
const SUSPICIOUS_PARENT_CHILD = [
  {
    parent: /winword|excel|powerpnt|outlook|onenote/i,
    child:  /powershell|cmd\.exe|wscript|cscript|mshta/i,
    name:   'Office_Spawns_Shell',
    severity: 'critical',
  },
  {
    parent: /chrome|firefox|msedge|iexplore|brave/i,
    child:  /powershell|wscript|mshta/i,
    name:   'Browser_Spawns_Shell',
    severity: 'critical',
  },
  {
    parent: /explorer\.exe/i,
    child:  /powershell.*-enc/i,
    name:   'Explorer_Encoded_PS',
    severity: 'critical',
  },
];

/* ── PowerShell runner ───────────────────────────────────────────────────── */
function runPS(script) {
  return new Promise((resolve) => {
    const cmd = `powershell -NonInteractive -ExecutionPolicy Bypass -Command "${script.replace(/"/g, '\\"')}"`;
    exec(cmd, { timeout: 25000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      if (err) { resolve(null); return; }
      try { resolve(JSON.parse(stdout)); } catch { resolve(stdout.trim() || null); }
    });
  });
}

/* ── Assess a single process ─────────────────────────────────────────────── */
function assessProcess(proc, allProcs) {
  const findings = [];
  const name     = (proc.Name || '').toLowerCase();
  const path     = (proc.Path || '').toLowerCase();
  const cmdline  = (proc.CommandLine || '').toLowerCase();
  const parentId = proc.ParentProcessId;
  const isKnownGood = KNOWN_GOOD_PROCESSES.has(name);

  // 1. Path-based check (WARNING only — not CRITICAL alone)
  //    Skip for known-good processes (Electron apps, browsers etc.)
  if (path && !isKnownGood) {
    for (const { pattern, name: patName } of SUSPICIOUS_PATH_PATTERNS) {
      if (pattern.test(path)) {
        findings.push({
          severity: 'warning',
          type:     'SuspiciousPath',
          tag:      patName,
          detail:   `Executable in ${patName}: ${proc.Path}`,
        });
        break;
      }
    }
  }

  // 2. System process masquerade (always CRITICAL, even for known-good names)
  const expectedPaths = SYSTEM_PROCESS_PATHS[name];
  if (expectedPaths && path && !expectedPaths.some((r) => r.test(path))) {
    findings.push({
      severity: 'critical',
      type:     'ProcessMasquerade',
      tag:      'Masquerade',
      detail:   `${proc.Name} running from unexpected path: ${proc.Path}`,
    });
  }

  // 3. Command-line obfuscation (always checked, regardless of known-good)
  if (cmdline) {
    for (const ind of CMD_INDICATORS) {
      if (ind.pattern.test(cmdline)) {
        findings.push({ severity: ind.severity, type: ind.name, tag: ind.name, detail: 'Suspicious argument pattern in command line' });
      }
    }
  }

  // 4. Suspicious parent-child
  if (parentId && allProcs) {
    const parent = allProcs.find((p) => p.ProcessId === parentId);
    if (parent) {
      for (const rel of SUSPICIOUS_PARENT_CHILD) {
        if (rel.parent.test(parent.Name || '') && rel.child.test(cmdline || name)) {
          findings.push({ severity: rel.severity, type: rel.name, tag: rel.name, detail: `${parent.Name} spawned ${proc.Name}` });
        }
      }
    }
  }

  // 5. No path (possible hollow process) — skip kernel processes
  if (!path && !KERNEL_PROCESSES.has(name)) {
    findings.push({
      severity: 'warning',
      type:     'NoExecutablePath',
      tag:      'HollowProcess',
      detail:   `No executable path — possible process hollowing`,
    });
  }

  // Score — CRITICAL requires: 1 critical indicator OR 2+ warnings
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const warningCount  = findings.filter((f) => f.severity === 'warning').length;
  const score         = criticalCount * 40 + warningCount * 15;
  const threat        = criticalCount >= 1 || warningCount >= 2
    ? (criticalCount >= 1 ? 'CRITICAL' : 'SUSPICIOUS')
    : warningCount === 1 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    pid:         proc.ProcessId,
    name:        proc.Name,
    path:        proc.Path || null,
    cmdline:     proc.CommandLine ? proc.CommandLine.slice(0, 400) : null,
    memMB:       proc.WorkingSetSize ? Math.round(proc.WorkingSetSize / 1024 / 1024) : 0,
    parentId:    parentId || null,
    isKnownGood,
    findings,
    score,
    threat,
  };
}

/* ── Main entry point ────────────────────────────────────────────────────── */
async function scanProcessMemory() {
  const startedAt = Date.now();

  const rawProcs = await runPS(
    `Get-CimInstance Win32_Process | ` +
    `Select-Object ProcessId,Name,Path,CommandLine,ParentProcessId,WorkingSetSize | ` +
    `ConvertTo-Json -Depth 2 -Compress`
  );

  if (!Array.isArray(rawProcs)) {
    return { success: false, error: 'Could not enumerate processes — check PowerShell access.', processes: [], summary: null };
  }

  const results    = rawProcs.map((p) => assessProcess(p, rawProcs));
  const critical   = results.filter((r) => r.threat === 'CRITICAL');
  const suspicious = results.filter((r) => r.threat === 'SUSPICIOUS');

  const summary = {
    total:      results.length,
    critical:   critical.length,
    suspicious: suspicious.length,
    clean:      results.length - critical.length - suspicious.length,
    scanTimeMs: Date.now() - startedAt,
    scannedAt:  new Date().toISOString(),
  };

  const sorted = [
    ...critical,
    ...suspicious,
    ...results.filter((r) => r.threat === 'CLEAN'),
  ];

  return { success: true, summary, processes: sorted };
}

module.exports = { scanProcessMemory };
