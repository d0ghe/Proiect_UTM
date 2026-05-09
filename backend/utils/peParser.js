/**
 * Portable Executable (PE) Parser
 *
 * Parser propriu pentru fișiere PE Windows (.exe, .dll, .sys).
 * Extrage:
 *  - DOS header → e_lfanew (offset NT headers)
 *  - NT headers (signature "PE\0\0", File header, Optional header)
 *  - Section table cu nume, dimensiuni, characteristics
 *  - Import Address Table (DLL-uri + funcții)
 *  - Anomalii: secțiuni Write+Execute, entry point în secțiune non-code, etc.
 *
 * Nu folosește biblioteci externe — citire pură din Buffer.
 */

const SECTION_FLAG = {
  CODE:                0x00000020,
  INITIALIZED_DATA:    0x00000040,
  UNINITIALIZED_DATA:  0x00000080,
  MEM_EXECUTE:         0x20000000,
  MEM_READ:            0x40000000,
  MEM_WRITE:           0x80000000,
};

const MACHINE_TYPE = {
  0x014c: 'i386',
  0x8664: 'AMD64',
  0x01c0: 'ARM',
  0xaa64: 'ARM64',
  0x0200: 'IA64',
};

function safeReadUInt32LE(buf, offset) {
  if (offset < 0 || offset + 4 > buf.length) return 0;
  return buf.readUInt32LE(offset);
}

function safeReadUInt16LE(buf, offset) {
  if (offset < 0 || offset + 2 > buf.length) return 0;
  return buf.readUInt16LE(offset);
}

function readNullTerminatedString(buf, offset, maxLen = 256) {
  let end = offset;
  while (end < buf.length && end < offset + maxLen && buf[end] !== 0) end++;
  return buf.slice(offset, end).toString('latin1');
}

/**
 * Parsează un buffer ca PE și returnează informații despre header-e și secțiuni.
 *
 * @param {Buffer} buffer
 * @returns {Object|null} - obiect cu detalii PE sau null dacă nu e PE valid.
 */
function parsePE(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 64) return null;

  // DOS header: MZ
  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) return null;

  const e_lfanew = safeReadUInt32LE(buffer, 0x3c);
  if (e_lfanew < 0x40 || e_lfanew + 24 > buffer.length) return null;

  // NT signature: "PE\0\0"
  if (buffer[e_lfanew] !== 0x50 || buffer[e_lfanew + 1] !== 0x45) return null;

  const fileHeaderOffset = e_lfanew + 4;
  const machine = safeReadUInt16LE(buffer, fileHeaderOffset);
  const numberOfSections = safeReadUInt16LE(buffer, fileHeaderOffset + 2);
  const timeDateStamp = safeReadUInt32LE(buffer, fileHeaderOffset + 4);
  const sizeOfOptionalHeader = safeReadUInt16LE(buffer, fileHeaderOffset + 16);
  const characteristics = safeReadUInt16LE(buffer, fileHeaderOffset + 18);

  const optionalHeaderOffset = fileHeaderOffset + 20;
  const magic = safeReadUInt16LE(buffer, optionalHeaderOffset);
  const is64bit = magic === 0x20b;

  let entryPoint = 0;
  let imageBase = 0;
  let importTableRVA = 0;
  let importTableSize = 0;
  let numberOfRvaAndSizes = 0;

  if (sizeOfOptionalHeader >= 24) {
    entryPoint = safeReadUInt32LE(buffer, optionalHeaderOffset + 16);
    if (is64bit) {
      const lo = safeReadUInt32LE(buffer, optionalHeaderOffset + 24);
      const hi = safeReadUInt32LE(buffer, optionalHeaderOffset + 28);
      imageBase = hi * 0x100000000 + lo;
    } else {
      imageBase = safeReadUInt32LE(buffer, optionalHeaderOffset + 28);
    }

    const dataDirOffset = is64bit ? optionalHeaderOffset + 112 : optionalHeaderOffset + 96;
    numberOfRvaAndSizes = safeReadUInt32LE(buffer, dataDirOffset - 4);

    if (numberOfRvaAndSizes >= 2) {
      importTableRVA = safeReadUInt32LE(buffer, dataDirOffset + 8);
      importTableSize = safeReadUInt32LE(buffer, dataDirOffset + 12);
    }
  }

  // Secțiuni
  const sectionsOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sections = [];
  const anomalies = [];

  for (let i = 0; i < numberOfSections && i < 32; i++) {
    const sOff = sectionsOffset + i * 40;
    if (sOff + 40 > buffer.length) break;

    const name = readNullTerminatedString(buffer, sOff, 8).replace(/\0+$/, '');
    const virtualSize = safeReadUInt32LE(buffer, sOff + 8);
    const virtualAddress = safeReadUInt32LE(buffer, sOff + 12);
    const sizeOfRawData = safeReadUInt32LE(buffer, sOff + 16);
    const pointerToRawData = safeReadUInt32LE(buffer, sOff + 20);
    const flags = safeReadUInt32LE(buffer, sOff + 36);

    const isCode = (flags & SECTION_FLAG.CODE) !== 0;
    const isWrite = (flags & SECTION_FLAG.MEM_WRITE) !== 0;
    const isExecute = (flags & SECTION_FLAG.MEM_EXECUTE) !== 0;
    const isRead = (flags & SECTION_FLAG.MEM_READ) !== 0;

    const section = {
      name: name || `(unnamed-${i})`,
      virtualSize,
      virtualAddress,
      virtualAddressHex: `0x${virtualAddress.toString(16).toUpperCase()}`,
      sizeOfRawData,
      pointerToRawData,
      characteristics: flags,
      isCode,
      isWrite,
      isExecute,
      isRead,
      permissions: [
        isRead ? 'R' : '-',
        isWrite ? 'W' : '-',
        isExecute ? 'X' : '-',
      ].join(''),
    };

    sections.push(section);

    // Anomalii
    if (isWrite && isExecute) {
      anomalies.push({
        severity: 'critical',
        section: section.name,
        description: `Secțiune cu permisiuni WRITE+EXECUTE (${section.permissions}) — indicator de cod auto-modificabil sau injecție.`,
      });
    }

    const standardNames = ['.text', '.rdata', '.data', '.bss', '.idata', '.edata', '.pdata', '.rsrc', '.reloc', '.tls', '.debug', '.CRT', '.xdata', '.gfids', '.didat'];
    if (name && !standardNames.includes(name) && !name.startsWith('/')) {
      anomalies.push({
        severity: 'warning',
        section: section.name,
        description: `Nume secțiune non-standard: "${name}" — packer-ele și malware-ul folosesc des nume custom.`,
      });
    }

    if (sizeOfRawData === 0 && virtualSize > 0 && isExecute) {
      anomalies.push({
        severity: 'warning',
        section: section.name,
        description: `Secțiune executabilă fără date raw — posibil cod allocat la runtime (unpacking).`,
      });
    }
  }

  // Verifică dacă entry point este într-o secțiune executabilă
  if (entryPoint > 0) {
    const epSection = sections.find((s) =>
      entryPoint >= s.virtualAddress && entryPoint < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData),
    );
    if (epSection && !epSection.isExecute) {
      anomalies.push({
        severity: 'critical',
        section: epSection.name,
        description: `Entry point 0x${entryPoint.toString(16)} este în secțiune non-executabilă "${epSection.name}".`,
      });
    } else if (!epSection) {
      anomalies.push({
        severity: 'warning',
        section: 'header',
        description: `Entry point 0x${entryPoint.toString(16)} nu se află în nicio secțiune mapată.`,
      });
    }
  }

  // Verifică timestamp suspicious
  if (timeDateStamp > 0) {
    const date = new Date(timeDateStamp * 1000);
    const year = date.getFullYear();
    if (year < 2000 || year > new Date().getFullYear() + 1) {
      anomalies.push({
        severity: 'warning',
        section: 'header',
        description: `Timestamp build suspicious: ${date.toISOString()} (an ${year}).`,
      });
    }
  }

  // Import table — extragem doar numele DLL-urilor (parsing simplificat)
  const importedDlls = [];
  if (importTableRVA > 0 && importTableSize > 0) {
    const importFileOffset = rvaToFileOffset(importTableRVA, sections);
    if (importFileOffset > 0) {
      for (let i = 0; i < 256; i++) {
        const descOff = importFileOffset + i * 20;
        if (descOff + 20 > buffer.length) break;
        const nameRVA = safeReadUInt32LE(buffer, descOff + 12);
        if (nameRVA === 0) break;
        const nameOff = rvaToFileOffset(nameRVA, sections);
        if (nameOff > 0 && nameOff < buffer.length) {
          const dllName = readNullTerminatedString(buffer, nameOff, 64);
          if (dllName) importedDlls.push(dllName);
        }
      }
    }
  }

  return {
    isValidPE: true,
    architecture: MACHINE_TYPE[machine] || `0x${machine.toString(16)}`,
    is64bit,
    numberOfSections,
    timeDateStamp,
    timeDateStampISO: timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : null,
    characteristics,
    entryPoint,
    entryPointHex: `0x${entryPoint.toString(16).toUpperCase()}`,
    imageBase: `0x${imageBase.toString(16).toUpperCase()}`,
    sections,
    anomalies,
    importedDlls,
  };
}

/**
 * Converteste un RVA (relative virtual address) la offset în fișier.
 */
function rvaToFileOffset(rva, sections) {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData)) {
      return s.pointerToRawData + (rva - s.virtualAddress);
    }
  }
  return 0;
}

module.exports = { parsePE };
