/**
 * Hex Signature Engine — Anti-Obfuscation Detection Layer
 *
 * Scanează buffer-ul raw al fișierelor pentru semnături hexazecimale
 * cunoscute, indiferent de extensie sau encoding. Detectează:
 *  - Header-e binare suspecte (PE/ELF/Mach-O)
 *  - Shellcode indicators (NOP sled, INT3 breakpoints)
 *  - Semnătura EICAR în format hex
 *  - Fragmente de packer / obfuscator comun
 */

const CHUNK_SIZE = 64 * 1024; // 64 KB per chunk — evită blocarea RAM

/**
 * Catalog de semnături hex. Fiecare intrare conține:
 *  - pattern: Buffer cu octeții de căutat
 *  - name: numele semnăturii (afișat în raport)
 *  - severity: 'critical' | 'warning' | 'info'
 *  - description: detalii tehnice pentru raport
 */
const HEX_SIGNATURES = [
  {
    pattern: Buffer.from('4D5A', 'hex'),            // MZ header
    name: 'PE_Executable_Header',
    severity: 'warning',
    description: 'Windows PE (MZ) executable header detected in file body.',
  },
  {
    pattern: Buffer.from('7F454C46', 'hex'),         // ELF magic
    name: 'ELF_Binary_Header',
    severity: 'warning',
    description: 'Linux ELF binary header found — possible embedded binary payload.',
  },
  {
    pattern: Buffer.from('CAFEBABE', 'hex'),         // Mach-O / Java class
    name: 'MachO_Java_Magic',
    severity: 'warning',
    description: 'Mach-O or Java .class magic bytes detected.',
  },
  {
    pattern: Buffer.from('9090909090', 'hex'),       // NOP x5 sled
    name: 'Shellcode_NOP_Sled',
    severity: 'critical',
    description: 'NOP sled (5+ consecutive 0x90) detected — common shellcode padding.',
  },
  {
    pattern: Buffer.from('CCCCCCCC', 'hex'),         // INT3 x4
    name: 'Debugger_Trap_Sequence',
    severity: 'warning',
    description: 'INT3 breakpoint sequence (0xCC x4) found — possible anti-debug stub.',
  },
  {
    pattern: Buffer.from('5858455153415220414e54495649525553542054455354', 'hex'), // EICAR core hex
    name: 'EICAR_Hex_Signature',
    severity: 'critical',
    description: 'EICAR anti-virus test signature detected in raw byte stream.',
  },
  {
    pattern: Buffer.from('UEsDB', 'ascii'),          // PK ZIP / docx embedded
    name: 'Embedded_ZIP_Archive',
    severity: 'info',
    description: 'PK ZIP signature found — file contains or is an archive.',
  },
  {
    pattern: Buffer.from('d0cf11e0a1b11ae1', 'hex'), // OLE2 Compound Document (Office macro)
    name: 'OLE2_Compound_Document',
    severity: 'warning',
    description: 'OLE2 Compound Document signature — may contain embedded macros.',
  },
  {
    pattern: Buffer.from('526172211a0700', 'hex'),   // RAR archive
    name: 'RAR_Archive_Header',
    severity: 'info',
    description: 'RAR archive signature found in file body.',
  },
  {
    pattern: Buffer.from('377abcaf271c', 'hex'),     // 7-Zip
    name: '7Zip_Archive_Header',
    severity: 'info',
    description: '7-Zip archive signature detected.',
  },
];

/**
 * Caută un pattern Buffer în interiorul unui alt Buffer.
 * Returnează primul offset găsit sau -1.
 *
 * @param {Buffer} haystack
 * @param {Buffer} needle
 * @returns {number}
 */
function indexOfBuffer(haystack, needle) {
  if (needle.length === 0 || needle.length > haystack.length) {
    return -1;
  }

  for (let i = 0; i <= haystack.length - needle.length; i++) {
    let found = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        found = false;
        break;
      }
    }

    if (found) {
      return i;
    }
  }

  return -1;
}

/**
 * Scanează un Buffer în chunk-uri de CHUNK_SIZE pentru toate semnăturile
 * cunoscute. Raportează primul hit per semnătură, cu offset-ul exact.
 *
 * @param {Buffer} fileBuffer
 * @returns {{ detected: boolean, matches: Array<{ name, severity, description, offset }> }}
 */
function scanBufferForHexSignatures(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    return { detected: false, matches: [] };
  }

  const matches = [];

  for (const sig of HEX_SIGNATURES) {
    let globalOffset = -1;

    // Scanare chunk cu chunk; păstrăm overlap de (pattern.length - 1) octeți
    // între chunk-uri consecutive ca să nu ratăm semnături la granițe.
    const overlap = sig.pattern.length - 1;
    let chunkStart = 0;

    while (chunkStart < fileBuffer.length) {
      const chunkEnd = Math.min(chunkStart + CHUNK_SIZE, fileBuffer.length);
      const chunk = fileBuffer.slice(chunkStart, chunkEnd);
      const localOffset = indexOfBuffer(chunk, sig.pattern);

      if (localOffset !== -1) {
        globalOffset = chunkStart + localOffset;
        break;
      }

      if (chunkEnd >= fileBuffer.length) {
        break;
      }

      chunkStart = chunkEnd - overlap;
      if (chunkStart < 0) {
        chunkStart = 0;
      }
    }

    if (globalOffset !== -1) {
      matches.push({
        name: sig.name,
        severity: sig.severity,
        description: sig.description,
        offset: globalOffset,
        offsetHex: `0x${globalOffset.toString(16).toUpperCase()}`,
      });
    }
  }

  const criticalMatches = matches.filter((m) => m.severity === 'critical');
  const detected = criticalMatches.length > 0;

  return { detected, matches };
}

/**
 * Construiește un sumar text pentru semnăturile găsite.
 * Folosit în câmpul `signature` al rezultatului de scan.
 *
 * @param {Array} matches
 * @returns {string|null}
 */
function buildSignatureSummary(matches) {
  if (!matches || matches.length === 0) {
    return null;
  }

  const critical = matches.filter((m) => m.severity === 'critical');
  const warnings = matches.filter((m) => m.severity === 'warning');

  if (critical.length > 0) {
    return `HEX:${critical.map((m) => m.name).join('+')}`;
  }

  if (warnings.length > 0) {
    return `HEX_WARN:${warnings.map((m) => m.name).join('+')}`;
  }

  return `HEX_INFO:${matches.map((m) => m.name).join('+')}`;
}

module.exports = {
  scanBufferForHexSignatures,
  buildSignatureSummary,
  HEX_SIGNATURES,
  CHUNK_SIZE,
};
