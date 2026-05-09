/**
 * Multi-Layer String Decoder
 *
 * Detectează și decodează string-uri ascunse cu encoding-uri comune:
 *  - Base64 (A-Za-z0-9+/=)
 *  - Hex (0-9A-Fa-f)
 *  - ROT13
 *  - XOR cu key 1-byte (brute-force)
 *
 * Returnează doar rezultatele care decodează în text printable cu lungime utilă,
 * pentru a evita zgomot. Foarte util pentru detecția C2 URLs ascunse.
 */

const PRINTABLE_RATIO_THRESHOLD = 0.85;
const MIN_DECODED_LENGTH = 8;

const BASE64_REGEX = /[A-Za-z0-9+/]{20,}={0,2}/g;
const HEX_REGEX = /[0-9A-Fa-f]{20,}/g;

function isPrintableAscii(s) {
  if (!s || s.length < MIN_DECODED_LENGTH) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
  }
  return printable / s.length >= PRINTABLE_RATIO_THRESHOLD;
}

function tryBase64(input) {
  const decoded = [];
  const matches = input.match(BASE64_REGEX) || [];
  for (const m of matches.slice(0, 50)) {
    if (m.length % 4 !== 0 && !m.endsWith('=')) continue;
    try {
      const buf = Buffer.from(m, 'base64');
      const text = buf.toString('utf8');
      if (isPrintableAscii(text)) {
        decoded.push({ encoding: 'base64', original: m.slice(0, 80), decoded: text.slice(0, 200), severity: 'warning' });
      }
    } catch {
      // ignore
    }
  }
  return decoded;
}

function tryHex(input) {
  const decoded = [];
  const matches = input.match(HEX_REGEX) || [];
  for (const m of matches.slice(0, 50)) {
    if (m.length % 2 !== 0) continue;
    try {
      const buf = Buffer.from(m, 'hex');
      const text = buf.toString('utf8');
      if (isPrintableAscii(text)) {
        decoded.push({ encoding: 'hex', original: m.slice(0, 80), decoded: text.slice(0, 200), severity: 'warning' });
      }
    } catch {
      // ignore
    }
  }
  return decoded;
}

function tryRot13(input) {
  // Caută segmente de litere de min 12 char și verifică dacă ROT13 produce cuvinte comune
  const segments = input.match(/[A-Za-z]{12,80}/g) || [];
  const commonWords = ['http', 'https', 'cmd', 'powershell', 'system', 'admin', 'process', 'kernel', 'windows', 'shell'];
  const decoded = [];

  for (const seg of segments.slice(0, 100)) {
    const rotated = seg.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
    if (commonWords.some((w) => rotated.toLowerCase().includes(w))) {
      decoded.push({ encoding: 'rot13', original: seg.slice(0, 80), decoded: rotated.slice(0, 200), severity: 'warning' });
    }
  }
  return decoded;
}

function tryXorBruteForce(buffer) {
  // Brute-force XOR keys 0x01-0xFF pe primele 4KB. Caută "http", "cmd", "powershell" în output.
  const decoded = [];
  const sampleSize = Math.min(4096, buffer.length);
  const sample = buffer.slice(0, sampleSize);
  const targets = ['http', 'cmd.exe', 'powershell', 'kernel32', 'CreateProcess'];

  for (let key = 1; key < 256; key++) {
    const xored = Buffer.alloc(sample.length);
    for (let i = 0; i < sample.length; i++) xored[i] = sample[i] ^ key;
    const text = xored.toString('latin1');

    const hit = targets.find((t) => text.includes(t));
    if (hit) {
      // Extrage o porțiune semnificativă în jurul hit-ului
      const idx = text.indexOf(hit);
      const snippet = text.slice(Math.max(0, idx - 20), idx + 80);
      if (isPrintableAscii(snippet)) {
        decoded.push({
          encoding: 'xor',
          key: `0x${key.toString(16).padStart(2, '0').toUpperCase()}`,
          decoded: snippet,
          severity: 'critical',
          description: `XOR cheie ${key.toString(16)} a revelat: ${hit}`,
        });
      }
    }
  }
  return decoded;
}

/**
 * Rulează toate decoderele pe un Buffer.
 *
 * @param {Buffer} buffer
 * @returns {{ findings: Array, totalDecoded: number, riskContribution: number }}
 */
function decodeStrings(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { findings: [], totalDecoded: 0, riskContribution: 0 };
  }

  const text = buffer.toString('latin1');
  const findings = [
    ...tryBase64(text),
    ...tryHex(text),
    ...tryRot13(text),
    ...tryXorBruteForce(buffer),
  ];

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const warningCount = findings.filter((f) => f.severity === 'warning').length;
  const riskContribution = Math.min(criticalCount * 20 + warningCount * 5, 35);

  return { findings: findings.slice(0, 25), totalDecoded: findings.length, riskContribution };
}

module.exports = { decodeStrings };
