/**
 * Evasion Technique Detection Module
 *
 * Detectează static semne de tehnici de evitare a analizei:
 *  - Anti-VM: verificări de mașini virtuale (VMware, VirtualBox, QEMU)
 *  - Anti-debug: apeluri API pentru detectarea debugger-ului
 *  - Import-uri periculoase: injecție de proces, keylogging, rețea
 *  - Packer signatures: UPX, MPRESS, ASPack, PECompact
 *
 * Analiza este pur statică — nu execută codul, doar scanează octeții fișierului.
 */

const PACKER_BYTE_SIGNATURES = [
  {
    pattern: Buffer.from('555058', 'hex'),
    name: 'UPX_Header',
    description: 'UPX header signature (0x555058) - executable compressed with the UPX packer.',
  },
  {
    pattern: Buffer.from('4D5052455353', 'hex'),
    name: 'MPRESS_Packer',
    description: 'MPRESS packer signature detected - compressed executable code.',
  },
  {
    pattern: Buffer.from('2e4153506b', 'hex'),
    name: 'ASPack',
    description: 'ASPack packer signature - PE obfuscation/compression.',
  },
  {
    pattern: Buffer.from('50454b', 'hex'),
    name: 'PECompact',
    description: 'PECompact signature detected - compressed PE executable.',
  },
];

const ANTI_VM_STRINGS = [
  'VMwareService', 'VMwareTray', 'vmtoolsd', 'vm3dservice',
  'VBoxService', 'VBoxTray', 'VBoxClient', 'innotek',
  'VBOX', 'VMWARE', 'virtualbox', 'VirtualPC',
  'sandboxie', 'sbiedll', 'QEMU', 'bochs',
  'wireshark', 'procmon', 'procexp', 'ollydbg',
  'x64dbg', 'x32dbg', 'IDA', 'windbg',
];

const ANTI_DEBUG_STRINGS = [
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess', 'ZwQueryInformationProcess',
  'OutputDebugStringA', 'OutputDebugStringW',
  'ZwSetInformationThread', 'NtSetInformationThread',
  'DebugActiveProcess', 'DebugBreak',
  'GetTickCount', 'QueryPerformanceCounter',
];

const DANGEROUS_IMPORTS = [
  // Injecție de proces
  'CreateRemoteThread', 'CreateRemoteThreadEx',
  'WriteProcessMemory', 'ReadProcessMemory',
  'VirtualAllocEx', 'VirtualProtectEx',
  'OpenProcess', 'NtCreateThreadEx',
  // Hooking / keylogging
  'SetWindowsHookEx', 'GetAsyncKeyState', 'keybd_event',
  'mouse_event', 'GetForegroundWindow',
  // Registry persistence
  'RegCreateKeyEx', 'RegSetValueEx', 'RegOpenKeyEx',
  // Execuție
  'ShellExecute', 'ShellExecuteEx', 'WinExec', 'CreateProcess',
  // Rețea malicioasă
  'URLDownloadToFile', 'InternetOpenUrl', 'HttpSendRequest',
  'WSAStartup', 'connect', 'send', 'recv',
  // Criptare / exfiltrare
  'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash',
];

/**
 * Scanează string-urile din buffer folosind encoding latin1 (evită probleme UTF-8).
 * Returnează o listă de indicatori categorisați.
 *
 * @param {Buffer} fileBuffer
 * @returns {Array<{ category: string, severity: string, matches: string[], description: string }>}
 */
function scanStrings(fileBuffer) {
  const str = fileBuffer.toString('latin1');
  const indicators = [];

  const antiVm = ANTI_VM_STRINGS.filter((s) => str.includes(s));
  if (antiVm.length > 0) {
    indicators.push({
      category: 'anti_vm',
      severity: 'warning',
      matches: antiVm,
      description: `Anti-VM indicators found: ${antiVm.slice(0, 5).join(', ')}${antiVm.length > 5 ? ` (+${antiVm.length - 5})` : ''}.`,
    });
  }

  const antiDebug = ANTI_DEBUG_STRINGS.filter((s) => str.includes(s));
  if (antiDebug.length > 0) {
    indicators.push({
      category: 'anti_debug',
      severity: 'warning',
      matches: antiDebug,
      description: `Anti-debug APIs found: ${antiDebug.slice(0, 4).join(', ')}${antiDebug.length > 4 ? ` (+${antiDebug.length - 4})` : ''}.`,
    });
  }

  const dangerous = DANGEROUS_IMPORTS.filter((s) => str.includes(s));
  if (dangerous.length > 0) {
    indicators.push({
      category: 'dangerous_imports',
      severity: dangerous.length > 3 ? 'critical' : 'warning',
      matches: dangerous,
      description: `Dangerous API imports: ${dangerous.slice(0, 5).join(', ')}${dangerous.length > 5 ? ` (+${dangerous.length - 5})` : ''}.`,
    });
  }

  return indicators;
}

/**
 * Scanează buffer-ul pentru semnături de packer cunoscute.
 *
 * @param {Buffer} fileBuffer
 * @returns {Array<{ name: string, description: string }>}
 */
function scanPackers(fileBuffer) {
  const found = [];
  for (const sig of PACKER_BYTE_SIGNATURES) {
    if (fileBuffer.indexOf(sig.pattern) !== -1) {
      found.push({ name: sig.name, description: sig.description });
    }
  }
  return found;
}

/**
 * Rulează detecția completă de tehnici de evaziune pe un Buffer.
 *
 * @param {Buffer} fileBuffer
 * @returns {{ indicators: Array, packers: Array, riskContribution: number }}
 */
function detectEvasion(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    return { indicators: [], packers: [], riskContribution: 0 };
  }

  const indicators = scanStrings(fileBuffer);
  const packers = scanPackers(fileBuffer);

  if (packers.length > 0) {
    indicators.push({
      category: 'packer',
      severity: 'warning',
      matches: packers.map((p) => p.name),
      description: `Packer signatures detected: ${packers.map((p) => p.name).join(', ')}.`,
    });
  }

  const criticals = indicators.filter((i) => i.severity === 'critical').length;
  const warnings = indicators.filter((i) => i.severity === 'warning').length;
  const riskContribution = Math.min(criticals * 25 + warnings * 10, 50);

  return { indicators, packers, riskContribution };
}

module.exports = { detectEvasion };
