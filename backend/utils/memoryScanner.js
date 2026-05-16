'use strict';

const { exec } = require('child_process');

const KNOWN_GOOD_PROCESSES = new Set([
  'claude.exe', 'code.exe', 'cursor.exe', 'windsurf.exe', 'codex.exe',
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
  'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
  'opera.exe', 'vivaldi.exe', 'thorium.exe',
  'node.exe', 'git.exe', 'python.exe', 'python3.exe', 'wt.exe',
  'mbam.exe', 'mbamservice.exe', 'avgui.exe', 'avguix.exe',
]);

const WINDOWS_CORE_PROCESSES = new Set([
  'system idle process', 'system', 'registry', 'memory compression',
  'secure system', 'idle', 'interrupts', 'dpc',
  'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
  'lsass.exe', 'lsaiso.exe', 'svchost.exe', 'fontdrvhost.exe', 'wudfhost.exe',
  'dwm.exe', 'spoolsv.exe', 'taskhostw.exe', 'sihost.exe', 'runtimebroker.exe',
  'dasHost.exe', 'ctfmon.exe', 'audiodg.exe', 'conhost.exe',
]);

const SUSPICIOUS_PATH_PATTERNS = [
  { pattern: /\\appdata\\local\\temp\\/i, name: 'AppDataLocalTemp' },
  { pattern: /\\appdata\\roaming\\temp\\/i, name: 'AppDataRoamingTemp' },
  { pattern: /\\windows\\temp\\/i, name: 'WindowsTemp' },
  { pattern: /\\tmp\\/i, name: 'TmpDir' },
  { pattern: /\\\$recycle\.bin\\/i, name: 'RecycleBin' },
  { pattern: /\\downloads\\/i, name: 'Downloads' },
  { pattern: /\\appdata\\local(?!\\(programs|microsoft|packages))/i, name: 'AppDataLocal' },
  { pattern: /\\appdata\\roaming(?!\\(microsoft|apple|mozilla))/i, name: 'AppDataRoaming' },
];

const SYSTEM_PROCESS_PATHS = {
  'svchost.exe': [/\\windows\\system32\\svchost\.exe$/i, /\\windows\\syswow64\\svchost\.exe$/i],
  'lsass.exe': [/\\windows\\system32\\lsass\.exe$/i],
  'csrss.exe': [/\\windows\\system32\\csrss\.exe$/i],
  'winlogon.exe': [/\\windows\\system32\\winlogon\.exe$/i],
  'services.exe': [/\\windows\\system32\\services\.exe$/i],
  'explorer.exe': [/\\windows\\explorer\.exe$/i],
  'taskhostw.exe': [/\\windows\\system32\\taskhostw\.exe$/i],
  'spoolsv.exe': [/\\windows\\system32\\spoolsv\.exe$/i],
  'smss.exe': [/\\windows\\system32\\smss\.exe$/i],
  'wininit.exe': [/\\windows\\system32\\wininit\.exe$/i],
};

const STATIC_CMD_INDICATORS = [
  { pattern: /\biex\s*\(/i, name: 'PS_IEX', severity: 'critical' },
  { pattern: /invoke-expression/i, name: 'PS_InvokeExpression', severity: 'critical' },
  { pattern: /downloadstring/i, name: 'PS_DownloadString', severity: 'critical' },
  { pattern: /regsvr32.*scrobj/i, name: 'Squiblydoo', severity: 'critical' },
  { pattern: /mshta\s+https?:\/\//i, name: 'MSHTA_Remote', severity: 'critical' },
  { pattern: /wscript\s+https?:\/\//i, name: 'WScript_Remote', severity: 'critical' },
  { pattern: /certutil\s+.*-decode/i, name: 'CertUtil_Decode', severity: 'critical' },
  { pattern: /bitsadmin.*\/transfer/i, name: 'BITSAdmin_Transfer', severity: 'critical' },
  { pattern: /frombase64string/i, name: 'PS_Base64Decode', severity: 'warning' },
  { pattern: /-windowstyle\s+hidden/i, name: 'PS_HiddenWindow', severity: 'warning' },
];

const BENIGN_AUTOMATION_PATTERNS = [
  /long-lived powershell ast parser/i,
  /rust command-safety layer/i,
  /get-ciminstance\s+win32_process/i,
  /select-object\s+processid,name,path,commandline,parentprocessid,workingsetsize/i,
];

const RISKY_DECODED_PS_PATTERNS = [
  /\biex\b|\binvoke-expression\b/i,
  /downloadstring|downloadfile|net\.webclient|start-bitstransfer/i,
  /frombase64string|reflection\.assembly|add-type/i,
  /set-mppreference|add-mppreference|disableantispyware|exclusionpath/i,
  /regsvr32|rundll32|mshta|wscript|cscript|certutil|bitsadmin/i,
  /new-object\s+net\.webclient/i,
  /http[s]?:\/\/[^\s'"]+/i,
];

const SUSPICIOUS_PARENT_CHILD = [
  {
    parent: /winword|excel|powerpnt|outlook|onenote/i,
    child: /powershell|cmd\.exe|wscript|cscript|mshta/i,
    name: 'Office_Spawns_Shell',
    severity: 'critical',
  },
  {
    parent: /chrome|firefox|msedge|iexplore|brave/i,
    child: /powershell|wscript|mshta/i,
    name: 'Browser_Spawns_Shell',
    severity: 'critical',
  },
  {
    parent: /explorer\.exe/i,
    child: /powershell.*-enc/i,
    name: 'Explorer_Encoded_PS',
    severity: 'critical',
  },
];

function runPS(script) {
  return new Promise((resolve) => {
    const cmd = `powershell -NonInteractive -ExecutionPolicy Bypass -Command "${script.replace(/"/g, '\\"')}"`;
    exec(cmd, { timeout: 25000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      if (err) { resolve(null); return; }
      try { resolve(JSON.parse(stdout)); } catch { resolve(stdout.trim() || null); }
    });
  });
}

function normalizeProcessName(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeProcessPath(proc) {
  return String(proc.Path || proc.ExecutablePath || '').trim();
}

function findParent(proc, allProcs = []) {
  return allProcs.find((candidate) => Number(candidate.ProcessId) === Number(proc.ParentProcessId)) || null;
}

function addFinding(findings, severity, type, tag, detail) {
  findings.push({ severity, type, tag, detail });
}

function extractEncodedCommand(cmdline) {
  const match = String(cmdline || '').match(/-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})/i);
  return match?.[1] || '';
}

function decodePowerShellEncodedCommand(value) {
  if (!value) return '';

  try {
    const decoded = Buffer.from(value, 'base64').toString('utf16le').replace(/\0/g, '').trim();
    return decoded.length > 0 ? decoded : '';
  } catch {
    return '';
  }
}

function isTrustedCodexParent(parent) {
  const parentName = normalizeProcessName(parent?.Name);
  const parentPath = normalizeProcessPath(parent).toLowerCase();
  return parentName === 'codex.exe' && parentPath.includes('\\openai.chatgpt-');
}

function isOwnScannerCommand(cmdline) {
  return /get-ciminstance\s+win32_process/i.test(cmdline)
    && /convertto-json/i.test(cmdline)
    && /processid/i.test(cmdline)
    && /commandline/i.test(cmdline)
    && /parentprocessid/i.test(cmdline)
    && /workingsetsize/i.test(cmdline);
}

function isTrustedAutomationCommand(decoded, cmdline, parent) {
  return isOwnScannerCommand(decoded || cmdline)
    || (isTrustedCodexParent(parent) && BENIGN_AUTOMATION_PATTERNS.some((pattern) => pattern.test(decoded)));
}

function hasRiskyDecodedPowerShell(decoded) {
  return RISKY_DECODED_PS_PATTERNS.some((pattern) => pattern.test(decoded));
}

function assessPowerShellCommandLine(findings, proc, parent) {
  const name = normalizeProcessName(proc.Name);
  const cmdline = String(proc.CommandLine || '');
  if (!cmdline || !/^(powershell|pwsh)(\.exe)?$/i.test(name)) return;

  const encoded = extractEncodedCommand(cmdline);
  const decoded = decodePowerShellEncodedCommand(encoded);
  const trustedAutomation = isTrustedAutomationCommand(decoded, cmdline, parent);

  if (encoded) {
    if (trustedAutomation) {
      addFinding(
        findings,
        'info',
        'TrustedEncodedPowerShell',
        'TrustedAutomation',
        'Encoded PowerShell belongs to known local automation tooling.',
      );
    } else if (decoded && hasRiskyDecodedPowerShell(decoded)) {
      addFinding(
        findings,
        'critical',
        'PS_EncodedCommand',
        'DecodedRiskyPowerShell',
        `Encoded PowerShell decodes to risky behavior: ${decoded.slice(0, 180)}`,
      );
    } else {
      addFinding(
        findings,
        'warning',
        'PS_EncodedCommand',
        'EncodedPowerShell',
        decoded
          ? `Encoded PowerShell decoded without high-risk tokens: ${decoded.slice(0, 180)}`
          : 'Encoded PowerShell could not be decoded.',
      );
    }
  }

  const hasEncodedPayload = Boolean(encoded);
  for (const indicator of STATIC_CMD_INDICATORS) {
    if (!indicator.pattern.test(cmdline)) continue;
    addFinding(findings, indicator.severity, indicator.name, indicator.name, 'Suspicious argument pattern in command line.');
  }

  const hasLongBase64 = /[A-Za-z0-9+/]{120,}={0,2}/.test(cmdline);
  if (hasLongBase64 && !hasEncodedPayload) {
    addFinding(findings, 'warning', 'LongBase64Arg', 'LongBase64Arg', 'Long Base64-like command-line argument.');
  }

  const hasPolicyBypass = /-executionpolicy\s+bypass|-bypass\b/i.test(cmdline);
  const hasNonInteractive = /-noprofile\b.*-noninteractive\b|-noninteractive\b.*-noprofile\b/i.test(cmdline);

  if (hasPolicyBypass) {
    addFinding(
      findings,
      trustedAutomation ? 'info' : 'warning',
      'PS_PolicyBypass',
      'PS_PolicyBypass',
      trustedAutomation ? 'Policy bypass used by known local automation.' : 'PowerShell policy bypass argument.',
    );
  }

  if (hasNonInteractive) {
    addFinding(
      findings,
      trustedAutomation ? 'info' : 'warning',
      'PS_NonInteractive',
      'PS_NonInteractive',
      trustedAutomation ? 'Non-interactive PowerShell used by known local automation.' : 'Non-interactive PowerShell command.',
    );
  }
}

function assessGenericCommandLine(findings, proc) {
  const cmdline = String(proc.CommandLine || '');
  const name = normalizeProcessName(proc.Name);
  if (!cmdline || /^(powershell|pwsh)(\.exe)?$/i.test(name)) return;

  for (const indicator of STATIC_CMD_INDICATORS) {
    if (indicator.pattern.test(cmdline)) {
      addFinding(findings, indicator.severity, indicator.name, indicator.name, 'Suspicious argument pattern in command line.');
    }
  }
}

function assessProcess(proc, allProcs = []) {
  const findings = [];
  const name = normalizeProcessName(proc.Name);
  const originalPath = normalizeProcessPath(proc);
  const path = originalPath.toLowerCase();
  const cmdline = String(proc.CommandLine || '');
  const parent = findParent(proc, allProcs);
  const parentId = proc.ParentProcessId;
  const isKnownGood = KNOWN_GOOD_PROCESSES.has(name);

  if (path && !isKnownGood) {
    for (const { pattern, name: patternName } of SUSPICIOUS_PATH_PATTERNS) {
      if (pattern.test(path)) {
        addFinding(findings, 'warning', 'SuspiciousPath', patternName, `Executable in ${patternName}: ${originalPath}`);
        break;
      }
    }
  }

  const expectedPaths = SYSTEM_PROCESS_PATHS[name];
  if (expectedPaths && path && !expectedPaths.some((pattern) => pattern.test(path))) {
    addFinding(findings, 'critical', 'ProcessMasquerade', 'Masquerade', `${proc.Name} running from unexpected path: ${originalPath}`);
  }

  assessPowerShellCommandLine(findings, proc, parent);
  assessGenericCommandLine(findings, proc);

  if (parent) {
    for (const rel of SUSPICIOUS_PARENT_CHILD) {
      if (rel.parent.test(parent.Name || '') && rel.child.test(`${cmdline} ${name}`)) {
        addFinding(findings, rel.severity, rel.name, rel.name, `${parent.Name} spawned ${proc.Name}`);
      }
    }
  }

  if (!path) {
    const hasOtherSignal = findings.some((finding) => finding.severity === 'critical' || finding.severity === 'warning');
    const expectedSystemProcess = WINDOWS_CORE_PROCESSES.has(name) || SYSTEM_PROCESS_PATHS[name];
    const severity = hasOtherSignal || (!expectedSystemProcess && cmdline) ? 'warning' : 'info';
    addFinding(
      findings,
      severity,
      severity === 'info' ? 'LimitedProcessVisibility' : 'NoExecutablePath',
      severity === 'info' ? 'LimitedVisibility' : 'HollowProcess',
      severity === 'info'
        ? 'Windows did not expose the executable path through WMI for this process.'
        : 'No executable path was exposed while other suspicious context exists.',
    );
  }

  const criticalCount = findings.filter((finding) => finding.severity === 'critical').length;
  const warningCount = findings.filter((finding) => finding.severity === 'warning').length;
  const infoCount = findings.filter((finding) => finding.severity === 'info').length;
  const score = criticalCount * 50 + warningCount * 20;
  const threat = criticalCount >= 1
    ? 'CRITICAL'
    : warningCount >= 1 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    pid: proc.ProcessId,
    name: proc.Name,
    path: originalPath || null,
    cmdline: cmdline ? cmdline.slice(0, 400) : null,
    memMB: proc.WorkingSetSize ? Math.round(proc.WorkingSetSize / 1024 / 1024) : 0,
    parentId: parentId || null,
    parentName: parent?.Name || '',
    isKnownGood,
    findings,
    score,
    threat,
    visibilityLimited: !path,
    infoCount,
  };
}

async function scanProcessMemory() {
  const startedAt = Date.now();

  const rawProcs = await runPS(
    `Get-CimInstance Win32_Process | ` +
    `Select-Object ProcessId,Name,Path,ExecutablePath,CommandLine,ParentProcessId,WorkingSetSize | ` +
    `ConvertTo-Json -Depth 2 -Compress`
  );

  const processList = Array.isArray(rawProcs) ? rawProcs : rawProcs ? [rawProcs] : [];
  if (processList.length === 0) {
    return { success: false, error: 'Could not enumerate processes - check PowerShell access.', processes: [], summary: null };
  }

  const results = processList.map((proc) => assessProcess(proc, processList));
  const critical = results.filter((result) => result.threat === 'CRITICAL');
  const suspicious = results.filter((result) => result.threat === 'SUSPICIOUS');
  const infoOnly = results.filter((result) => result.threat === 'CLEAN' && result.infoCount > 0);

  const summary = {
    total: results.length,
    critical: critical.length,
    suspicious: suspicious.length,
    clean: results.length - critical.length - suspicious.length,
    infoOnly: infoOnly.length,
    scanTimeMs: Date.now() - startedAt,
    scannedAt: new Date().toISOString(),
  };

  const sorted = [
    ...critical,
    ...suspicious,
    ...infoOnly,
    ...results.filter((result) => result.threat === 'CLEAN' && result.infoCount === 0),
  ];

  return { success: true, summary, processes: sorted };
}

module.exports = {
  assessProcess,
  decodePowerShellEncodedCommand,
  extractEncodedCommand,
  scanProcessMemory,
};
