/**
 * MITRE ATT&CK Mapping Module
 *
 * Mapează detecțiile interne (categorii din celelalte module) la
 * tactici și tehnici MITRE ATT&CK Enterprise. Permite afișarea unei
 * matrici ATT&CK colorate cu tehnicile observate, terminologie standard
 * recunoscută în industrie.
 */

// Subset relevant din MITRE ATT&CK Enterprise (focus pe analiză statică)
const MITRE_TECHNIQUES = {
  T1027: { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  'T1027.002': { name: 'Software Packing', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1055: { name: 'Process Injection', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  'T1055.001': { name: 'DLL Injection', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  'T1055.002': { name: 'Portable Executable Injection', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1497: { name: 'Virtualization/Sandbox Evasion', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  'T1497.001': { name: 'System Checks', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1622: { name: 'Debugger Evasion', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1056: { name: 'Input Capture', tactic: 'Collection', tacticId: 'TA0009' },
  'T1056.001': { name: 'Keylogging', tactic: 'Collection', tacticId: 'TA0009' },
  T1547: { name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', tacticId: 'TA0003' },
  'T1547.001': { name: 'Registry Run Keys', tactic: 'Persistence', tacticId: 'TA0003' },
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'Execution', tacticId: 'TA0002' },
  'T1059.001': { name: 'PowerShell', tactic: 'Execution', tacticId: 'TA0002' },
  'T1059.005': { name: 'Visual Basic', tactic: 'Execution', tacticId: 'TA0002' },
  'T1059.007': { name: 'JavaScript', tactic: 'Execution', tacticId: 'TA0002' },
  T1071: { name: 'Application Layer Protocol', tactic: 'C2', tacticId: 'TA0011' },
  T1105: { name: 'Ingress Tool Transfer', tactic: 'C2', tacticId: 'TA0011' },
  T1140: { name: 'Deobfuscate/Decode Files', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1486: { name: 'Data Encrypted for Impact (Ransomware)', tactic: 'Impact', tacticId: 'TA0040' },
  T1083: { name: 'File and Directory Discovery', tactic: 'Discovery', tacticId: 'TA0007' },
  T1112: { name: 'Modify Registry', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1218: { name: 'System Binary Proxy Execution', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1036: { name: 'Masquerading', tactic: 'Defense Evasion', tacticId: 'TA0005' },
  T1573: { name: 'Encrypted Channel', tactic: 'C2', tacticId: 'TA0011' },
};

// Mapare: categorie internă → listă tehnici MITRE
const CATEGORY_TO_TECHNIQUE = {
  packer: ['T1027.002', 'T1027'],
  anti_vm: ['T1497.001', 'T1497'],
  anti_debug: ['T1622'],
  dangerous_imports: ['T1055'],
  injection_apis: ['T1055.001', 'T1055.002'],
  keylogging: ['T1056.001'],
  registry_persistence: ['T1547.001', 'T1112'],
  network_apis: ['T1071', 'T1105'],
  crypto_apis: ['T1573', 'T1486'],
  base64_encoded: ['T1140', 'T1027'],
  xor_encoded: ['T1140', 'T1027'],
  powershell_obfuscation: ['T1059.001', 'T1027'],
  vbscript_obfuscation: ['T1059.005', 'T1027'],
  javascript_obfuscation: ['T1059.007', 'T1027'],
  high_entropy: ['T1027.002'],
  code_cave: ['T1055.002'],
  appended_payload: ['T1027'],
  polyglot: ['T1027', 'T1036'],
  mass_write_ransomware: ['T1486'],
};

// Hint-uri pentru import-uri specifice
const IMPORT_TO_TECHNIQUE = {
  CreateRemoteThread: ['T1055.002'],
  WriteProcessMemory: ['T1055.002'],
  VirtualAllocEx: ['T1055.002'],
  SetWindowsHookEx: ['T1056'],
  GetAsyncKeyState: ['T1056.001'],
  RegSetValueEx: ['T1547.001', 'T1112'],
  URLDownloadToFile: ['T1105'],
  CryptEncrypt: ['T1486', 'T1573'],
};

/**
 * Generează lista de tehnici MITRE pentru un set de detecții.
 *
 * @param {Object} signals
 * @param {Array} signals.evasionIndicators
 * @param {Array} signals.injectionResult
 * @param {Array} signals.entropyResult
 * @param {Array} signals.iocs
 * @param {Array} signals.scriptObfuscation
 * @param {Array} signals.stringDecoded
 * @returns {Array<{ id, name, tactic, tacticId, evidence: string[] }>}
 */
function mapToMitre(signals = {}) {
  const techniques = new Map();

  function addTech(techId, evidence) {
    if (!MITRE_TECHNIQUES[techId]) return;
    if (!techniques.has(techId)) {
      techniques.set(techId, { id: techId, ...MITRE_TECHNIQUES[techId], evidence: [] });
    }
    if (evidence) techniques.get(techId).evidence.push(evidence);
  }

  // Evasion indicators
  for (const ind of signals.evasionIndicators || []) {
    const techs = CATEGORY_TO_TECHNIQUE[ind.category] || [];
    for (const t of techs) addTech(t, ind.description);

    if (ind.category === 'dangerous_imports') {
      for (const imp of ind.matches || []) {
        for (const t of (IMPORT_TO_TECHNIQUE[imp] || [])) {
          addTech(t, `Import: ${imp}`);
        }
      }
    }
  }

  // Sub-byte injection
  if (signals.injectionResult) {
    if (signals.injectionResult.codeCaves?.length > 0) {
      addTech('T1055.002', `${signals.injectionResult.codeCaves.length} code caves detected`);
    }
    if (signals.injectionResult.appendedPayloads?.length > 0) {
      for (const t of CATEGORY_TO_TECHNIQUE.appended_payload) {
        addTech(t, `Payload appended after EOF`);
      }
    }
    if (signals.injectionResult.polyglot?.length > 0) {
      for (const t of CATEGORY_TO_TECHNIQUE.polyglot) {
        addTech(t, `Polyglot file format`);
      }
    }
  }

  // Entropy
  if (signals.entropyResult?.verdict === 'likely_encrypted_or_packed') {
    addTech('T1027.002', `Entropy ${signals.entropyResult.overall}/8.0 indicates packing`);
  }

  // String decoder
  for (const dec of signals.stringDecoded || []) {
    const techs = CATEGORY_TO_TECHNIQUE[`${dec.encoding}_encoded`] || ['T1140'];
    for (const t of techs) addTech(t, `${dec.encoding.toUpperCase()} encoded string detected`);
  }

  // Script obfuscation
  for (const obf of signals.scriptObfuscation || []) {
    const techs = CATEGORY_TO_TECHNIQUE[`${obf.language}_obfuscation`] || [];
    for (const t of techs) addTech(t, obf.description);
  }

  // IOCs
  if (signals.iocs?.urls?.length > 0 || signals.iocs?.ips?.length > 0) {
    addTech('T1071', `${(signals.iocs.urls?.length || 0) + (signals.iocs.ips?.length || 0)} network indicators`);
  }

  // Ransomware
  if (signals.massWriteEvent) {
    addTech('T1486', `Mass file write detected: ${signals.massWriteEvent.fileCount} files in ${signals.massWriteEvent.windowSec}s`);
  }

  return Array.from(techniques.values());
}

/**
 * Returnează matricea MITRE completă (pentru UI, gridul gol).
 */
function getMitreMatrix() {
  const tactics = {};
  for (const [id, tech] of Object.entries(MITRE_TECHNIQUES)) {
    if (!tactics[tech.tacticId]) {
      tactics[tech.tacticId] = { id: tech.tacticId, name: tech.tactic, techniques: [] };
    }
    tactics[tech.tacticId].techniques.push({ id, name: tech.name });
  }
  return Object.values(tactics);
}

module.exports = { mapToMitre, getMitreMatrix, MITRE_TECHNIQUES };
