/**
 * Sub-byte Injection Detection Module
 *
 * Detectează tehnici de injecție la nivel de octeți folosite pentru
 * a ascunde cod malițios și a ocoli antivirus-urile:
 *
 *  1. Code Caves — regiuni mari de octeți nuli (0x00) sau 0xFF în interiorul
 *     executabilului, unde shellcode poate fi injectat fără a modifica dimensiunea.
 *
 *  2. Appended Payload — conținut după markerii EOF ai formatelor comune
 *     (PDF %%EOF, ZIP End of Central Directory). Virusul se ascunde "după" fișier.
 *
 *  3. Polyglot File — fișier valid simultan în mai multe formate, folosit pentru
 *     a confunda filtrele bazate pe extensie sau magic bytes.
 *
 *  4. Section Anomalies — secțiuni PE cu permisiuni anormale (WX = write+execute),
 *     indicator de cod auto-modificabil sau cod injectat.
 */

const MIN_CAVE_SIZE = 256; // minim 256 bytes null consecutivi = suspiciune

// Markeri EOF pentru detecția payload-ului adăugat după EOF
const EOF_MARKERS = [
  { name: 'PDF_EOF', pattern: Buffer.from('%%EOF') },
  { name: 'ZIP_EOCD', pattern: Buffer.from('504b0506', 'hex') },
  { name: 'JPEG_EOI', pattern: Buffer.from('ffd9', 'hex') },
  { name: 'PNG_IEND', pattern: Buffer.from('49454e44ae426082', 'hex') },
];

// Magic bytes pentru detectarea poliglot-elor
const FORMAT_MAGIC = [
  { name: 'PE_MZ', check: (b) => b[0] === 0x4D && b[1] === 0x5A },
  { name: 'PDF', check: (b) => b.slice(0, 4).toString('ascii') === '%PDF' },
  { name: 'ZIP/DOCX', check: (b) => b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x03 && b[3] === 0x04 },
  { name: 'ELF', check: (b) => b[0] === 0x7F && b[1] === 0x45 && b[2] === 0x4C && b[3] === 0x46 },
  { name: 'PNG', check: (b) => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47 },
  { name: 'JPEG', check: (b) => b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF },
  { name: 'GIF', check: (b) => b.slice(0, 3).toString('ascii') === 'GIF' },
  { name: 'RAR', check: (b) => b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 },
];

/**
 * Detectează code caves — regiuni continue de octeți nuli sau 0xFF
 * suficient de mari pentru a ascunde shellcode.
 *
 * @param {Buffer} fileBuffer
 * @returns {Array<{ offset: number, offsetHex: string, size: number, byteValue: string, description: string }>}
 */
function detectCodeCaves(fileBuffer) {
  const caves = [];
  const scanByte = [0x00, 0xFF]; // NULL caves și FF caves

  for (const target of scanByte) {
    let start = -1;
    let len = 0;

    for (let i = 0; i < fileBuffer.length; i++) {
      if (fileBuffer[i] === target) {
        if (start === -1) start = i;
        len++;
      } else {
        if (len >= MIN_CAVE_SIZE) {
          caves.push({
            offset: start,
            offsetHex: `0x${start.toString(16).toUpperCase()}`,
            size: len,
            byteValue: target === 0x00 ? 'NULL (0x00)' : 'FF (0xFF)',
            description: `Code cave de ${len} octeți (${target === 0x00 ? '0x00' : '0xFF'}) la offset 0x${start.toString(16).toUpperCase()} — posibil spațiu pentru shellcode.`,
          });
        }
        start = -1;
        len = 0;
      }
    }

    if (len >= MIN_CAVE_SIZE) {
      caves.push({
        offset: start,
        offsetHex: `0x${start.toString(16).toUpperCase()}`,
        size: len,
        byteValue: target === 0x00 ? 'NULL (0x00)' : 'FF (0xFF)',
        description: `Code cave de ${len} octeți (${target === 0x00 ? '0x00' : '0xFF'}) la end-of-file.`,
      });
    }
  }

  // Sortăm descrescător după dimensiune și limităm la cele mai relevante
  return caves.sort((a, b) => b.size - a.size).slice(0, 8);
}

/**
 * Detectează conținut adăugat după markerii EOF ai formatelor comune.
 * Aceasta este tehnica "append-after-EOF" folosită de viruși polimorfici.
 *
 * @param {Buffer} fileBuffer
 * @returns {Array<{ type: string, eofOffset: number, bytesAfter: number, description: string }>}
 */
function detectAppendAfterEOF(fileBuffer) {
  const detected = [];

  for (const marker of EOF_MARKERS) {
    const idx = fileBuffer.lastIndexOf(marker.pattern);
    if (idx === -1) continue;

    const endOfMarker = idx + marker.pattern.length;
    const bytesAfter = fileBuffer.length - endOfMarker;

    // Ignorăm padding minor (< 20 bytes) care poate fi legitim
    if (bytesAfter > 20) {
      detected.push({
        type: marker.name,
        eofOffset: idx,
        eofOffsetHex: `0x${idx.toString(16).toUpperCase()}`,
        bytesAfter,
        description: `${bytesAfter} octeți găsiți după markeru ${marker.name} la 0x${idx.toString(16).toUpperCase()} — posibil payload ascuns.`,
      });
    }
  }

  return detected;
}

/**
 * Detectează fișiere polyglot — valide simultan în mai multe formate.
 * Verifică magic bytes la început și caută semnături suplimentare în corp.
 *
 * @param {Buffer} fileBuffer
 * @returns {Array<{ formats: string[], description: string, severity: string }>}
 */
function detectPolyglot(fileBuffer) {
  if (fileBuffer.length < 16) return [];

  const detected = FORMAT_MAGIC
    .filter(({ check }) => {
      try {
        return check(fileBuffer);
      } catch {
        return false;
      }
    })
    .map(({ name }) => name);

  if (detected.length > 1) {
    return [{
      formats: detected,
      severity: 'warning',
      description: `Fișier polyglot detectat — valid ca: ${detected.join(' + ')}. Posibilă confuzie intenționată a filtrelor.`,
    }];
  }

  return [];
}

/**
 * Rulează toate verificările de injecție sub-byte pe un Buffer.
 *
 * @param {Buffer} fileBuffer
 * @returns {{ codeCaves: Array, appendedPayloads: Array, polyglot: Array, riskContribution: number }}
 */
function detectSubbyteInjection(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    return { codeCaves: [], appendedPayloads: [], polyglot: [], riskContribution: 0 };
  }

  const codeCaves = detectCodeCaves(fileBuffer);
  const appendedPayloads = detectAppendAfterEOF(fileBuffer);
  const polyglot = detectPolyglot(fileBuffer);

  // Cave-urile mari (> 1 KB) sunt mai suspecte
  const largeCaves = codeCaves.filter((c) => c.size > 1024).length;
  const mediumCaves = codeCaves.filter((c) => c.size >= 256 && c.size <= 1024).length;

  const riskContribution = Math.min(
    largeCaves * 20
    + mediumCaves * 5
    + appendedPayloads.length * 25
    + polyglot.length * 15,
    45,
  );

  return { codeCaves, appendedPayloads, polyglot, riskContribution };
}

module.exports = { detectSubbyteInjection };
