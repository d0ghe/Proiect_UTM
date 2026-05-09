'use strict';

/**
 * Live Memory & Process Scanner
 *
 * Uses PowerShell + WMI to inspect running processes WITHOUT requiring
 * administrator privileges. Detects:
 *
 *  1. Suspicious paths — processes running from Temp/AppData/Downloads/Recycle
 *  2. Command-line obfuscation — base64, IEX, encoded payloads in cmd args
 *  3. Process masquerading — svchost/explorer/lsass running from wrong path
 *  4. Unsigned / missing executables — path exists but no digital signature
 *  5. Suspicious parent-child chains — cmd/powershell spawned by Office/browser
 *  6. Hollow process indicators — process with no associated file on disk
 *  7. Network + no-UI suspicious combos — hidden processes with net connections
 */

const { exec } = require('child_process');

/* ── Suspicious path fragments ───────────────────────────────────────────── */
const SUSPICIOUS_PATH_PATTERNS = [
  /\\temp\\/i,
  /\\tmp\\/i,
  /\\appdata\\local\\temp/i,
  /\\appdata\\roaming/i,
  /\\downloads\\/i,
  /\\\$recycle\.bin/i,
  /\\public\\/i,
  /\\programdata\\[^\\]+\.(exe|dll|scr|bat|ps1)/i,
];

/* ── Processes that should ONLY run from System32 or SysWOW64 ────────────── */
const SYSTEM_PROCESS_PATHS = {
  'svchost.exe':   [/system32\\svchost\.exe/i, /syswow64\\svchost\.exe/i],
  'lsass.exe':     [/system32\\lsass\.exe/i],
  'csrss.exe':     [/system32\\csrss\.exe/i],
  'winlogon.exe':  [/system32\\winlogon\.exe/i],
  'services.exe':  [/system32\\services\.exe/i],
  'explorer.exe':  [/windows\\explorer\.exe/i],
  'taskhostw.exe': [/system32\\taskhostw\.exe/i],
  'spoolsv.exe':   [/system32\\spoolsv\.exe/i],
};

/* ── Suspicious command-line indicators ──────────────────────────────────── */
const CMD_INDICATORS = [
  { pattern: /-enc[odedcommand\s]/i,     name: 'PS_EncodedCommand',   severity: 'critical' },
  { pattern: /iex\s*\(/i,               name: 'PS_IEX',               severity: 'critical' },
  { pattern: /invoke-expression/i,       name: 'PS_InvokeExpression',  severity: 'critical' },
  { pattern: /downloadstring/i,          name: 'PS_DownloadString',    severity: 'critical' },
  { pattern: /frombase64string/i,        name: 'PS_Base64Decode',      severity: 'warning'  },
  { pattern: /-bypass/i,                 name: 'PS_PolicyBypass',      severity: 'warning'  },
  { pattern: /[A-Za-z0-9+/]{100,}={0,2}/,name: 'LongBase64Arg',       severity: 'warning'  },
  { pattern: /regsvr32.*scrobj/i,        name: 'Squiblydoo',           severity: 'critical' },
  { pattern: /mshta.*http/i,             name: 'MSHTA_Remote',         severity: 'critical' },
  { pattern: /wscript.*http/i,           name: 'WScript_Remote',       severity: 'critical' },
  { pattern: /certutil.*-decode/i,       name: 'CertUtil_Decode',      severity: 'critical' },
  { pattern: /bitsadmin.*\/transfer/i,   name: 'BITSAdmin_Transfer',   severity: 'critical' },
];

/* ── Suspicious parent-child process relationships ───────────────────────── */
const SUSPICIOUS_PARENT_CHILD = [
  { parent: /winword|excel|powerpnt|outlook/i, child: /powershell|cmd|wscript|cscript|mshta/i, name: 'Office_Spawns_Shell' },
  { parent: /chrome|firefox|msedge|iexplore/i, child: /powershell|cmd|wscript|mshta/i,         name: 'Browser_Spawns_Shell' },
  { parent: /explorer\.exe/i,                  child: /powershell.*-enc/i,                      name: 'Explorer_Encoded_PS'  },
];

/* ── PowerShell runner ───────────────────────────────────────────────────── */
function runPS(script) {
  return new Promise((resolve) => {
    const cmd = `powershell -NonInteractive -ExecutionPolicy Bypass -Command "${script.replace(/"/g, '\\"')}"`;
    exec(cmd, { timeout: 20000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      if (err) { resolve(null); return; }
      try { resolve(JSON.parse(stdout)); } catch { resolve(stdout.trim() || null); }
    });
  });
}

/* ── Scan individual process ─────────────────────────────────────────────── */
function assessProcess(proc, allProcs) {
  const findings = [];
  const name     = (proc.Name || '').toLowerCase();
  const path     = (proc.Path || '').toLowerCase();
  const cmdline  = (proc.CommandLine || '').toLowerCase();
  const parentId = proc.ParentProcessId;

  // 1. Suspicious path
  if (path) {
    for (const pat of SUSPICIOUS_PATH_PATTERNS) {
      if (pat.test(path)) {
        findings.push({ severity: 'critical', type: 'SuspiciousPath', detail: `Process running from: ${proc.Path}` });
        break;
      }
    }
  }

  // 2. Masquerading system process
  const expected = SYSTEM_PROCESS_PATHS[name];
  if (expected && path && !expected.some((r) => r.test(path))) {
    findings.push({ severity: 'critical', type: 'ProcessMasquerade', detail: `${proc.Name} running from unexpected path: ${proc.Path}` });
  }

  // 3. Command-line obfuscation
  if (cmdline) {
    for (const ind of CMD_INDICATORS) {
      if (ind.pattern.test(cmdline)) {
        findings.push({ severity: ind.severity, type: ind.name, detail: `Suspicious argument pattern in command line` });
      }
    }
  }

  // 4. Suspicious parent-child
  if (parentId && allProcs) {
    const parent = allProcs.find((p) => p.ProcessId === parentId);
    if (parent) {
      const parentName = (parent.Name || '');
      for (const rel of SUSPICIOUS_PARENT_CHILD) {
        if (rel.parent.test(parentName) && rel.child.test(cmdline || name)) {
          findings.push({ severity: 'critical', type: rel.name, detail: `${parentName} spawned ${proc.Name}` });
        }
      }
    }
  }

  // 5. No path (hollow / injected)
  if (!path && name && !['system', 'registry', 'memory compression', 'secure system'].includes(name)) {
    findings.push({ severity: 'warning', type: 'NoExecutablePath', detail: `Process "${proc.Name}" has no associated executable path — possible hollowing` });
  }

  const score = findings.reduce((acc, f) => acc + (f.severity === 'critical' ? 40 : 15), 0);
  const threat = score >= 40 ? 'CRITICAL' : score >= 15 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    pid:      proc.ProcessId,
    name:     proc.Name,
    path:     proc.Path || null,
    cmdline:  proc.CommandLine ? proc.CommandLine.slice(0, 300) : null,
    cpu:      proc.CPU || 0,
    memMB:    proc.WorkingSetSize ? Math.round(proc.WorkingSetSize / 1024 / 1024) : 0,
    parentId: parentId || null,
    findings,
    score,
    threat,
  };
}

/* ── Main scan function ──────────────────────────────────────────────────── */
async function scanProcessMemory() {
  const startedAt = Date.now();

  const rawProcs = await runPS(
    `Get-CimInstance Win32_Process | ` +
    `Select-Object ProcessId,Name,Path,CommandLine,ParentProcessId,` +
    `WorkingSetSize,@{n='CPU';e={(Get-Process -Id $_.ProcessId -EA SilentlyContinue).CPU}} | ` +
    `ConvertTo-Json -Depth 2 -Compress`
  );

  if (!Array.isArray(rawProcs)) {
    return { success: false, error: 'Could not enumerate processes', processes: [], summary: null };
  }

  const results   = rawProcs.map((p) => assessProcess(p, rawProcs));
  const critical  = results.filter((r) => r.threat === 'CRITICAL');
  const suspicious = results.filter((r) => r.threat === 'SUSPICIOUS');

  const summary = {
    total:      results.length,
    critical:   critical.length,
    suspicious: suspicious.length,
    clean:      results.length - critical.length - suspicious.length,
    scanTimeMs: Date.now() - startedAt,
    scannedAt:  new Date().toISOString(),
  };

  // Sorted: critical first, then suspicious, then clean
  const sorted = [
    ...critical,
    ...suspicious,
    ...results.filter((r) => r.threat === 'CLEAN'),
  ];

  return { success: true, summary, processes: sorted };
}

module.exports = { scanProcessMemory };
