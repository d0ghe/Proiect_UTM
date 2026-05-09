/**
 * Entropy Analysis Module
 *
 * Calculează entropia Shannon per bloc de fișier.
 * Entropia ridicată (> 7.0 din 8.0) indică date criptate sau împachetate (packed),
 * ceea ce este un indicator tipic de malware obfuscat sau comprimat cu UPX/etc.
 */

const BLOCK_SIZE = 4096; // 4 KB per bloc de analiză

/**
 * Calculează entropia Shannon a unui Buffer.
 * Returnează o valoare între 0 (toți octeții identici) și 8 (distribuție uniformă).
 *
 * @param {Buffer} buf
 * @returns {number}
 */
function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;

  const freq = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / buf.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Analizează entropia unui fișier pe blocuri de BLOCK_SIZE octeți.
 * Returnează entropia generală, lista de blocuri, și un verdict calitativ.
 *
 * @param {Buffer} fileBuffer
 * @returns {{ overall: number, blocks: Array, highEntropyRatio: number, verdict: string }}
 */
function analyzeEntropy(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    return { overall: 0, blocks: [], highEntropyRatio: 0, verdict: 'normal' };
  }

  const overall = shannonEntropy(fileBuffer);
  const blocks = [];

  for (let i = 0; i < fileBuffer.length && blocks.length < 64; i += BLOCK_SIZE) {
    const chunk = fileBuffer.slice(i, Math.min(i + BLOCK_SIZE, fileBuffer.length));
    blocks.push({
      offset: i,
      offsetHex: `0x${i.toString(16).toUpperCase()}`,
      size: chunk.length,
      entropy: parseFloat(shannonEntropy(chunk).toFixed(3)),
    });
  }

  const highBlocks = blocks.filter((b) => b.entropy > 7.0).length;
  const highEntropyRatio = blocks.length > 0 ? highBlocks / blocks.length : 0;

  let verdict = 'normal';
  if (overall > 7.5) {
    verdict = 'likely_encrypted_or_packed';
  } else if (overall > 6.5) {
    verdict = 'suspicious_high_entropy';
  } else if (overall < 1.0 && fileBuffer.length > 512) {
    verdict = 'low_entropy_repetitive';
  }

  return {
    overall: parseFloat(overall.toFixed(3)),
    blocks,
    highEntropyRatio: parseFloat(highEntropyRatio.toFixed(3)),
    verdict,
  };
}

module.exports = { shannonEntropy, analyzeEntropy };
