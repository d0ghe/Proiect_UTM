'use strict';

/**
 * Archive Scanner — recursive ZIP extraction and scanning
 *
 * Reads ZIP archives using pure Node.js Buffer parsing (no external deps).
 * Supports nested ZIPs (zip-in-zip) up to MAX_DEPTH levels.
 * Each extracted entry is passed to the provided scanFn callback.
 */

const MAX_DEPTH      = 3;
const MAX_ENTRIES    = 200;
const MAX_ENTRY_SIZE = 10 * 1024 * 1024; // 10 MB per entry

/* ── ZIP format constants ─────────────────────────────────────────────────── */
const LOCAL_FILE_SIG   = 0x04034b50;
const CENTRAL_DIR_SIG  = 0x02014b50;
const EOCD_SIG         = 0x06054b50;

function readUInt16LE(buf, off) { return buf.readUInt16LE(off); }
function readUInt32LE(buf, off) { return buf.readUInt32LE(off); }

/**
 * Detects whether a buffer is a ZIP archive (PK magic bytes).
 */
function isZip(buffer) {
  return buffer.length >= 4 && readUInt32LE(buffer, 0) === LOCAL_FILE_SIG;
}

/**
 * Parses a ZIP buffer and yields { name, data } for each entry.
 * Uses Local File Header iteration (simpler than Central Directory for our use).
 */
function* extractZipEntries(buffer) {
  let offset = 0;
  let count  = 0;

  while (offset + 30 < buffer.length && count < MAX_ENTRIES) {
    const sig = readUInt32LE(buffer, offset);
    if (sig !== LOCAL_FILE_SIG) break;

    const compression    = readUInt16LE(buffer, offset + 8);
    const compressedSize = readUInt32LE(buffer, offset + 18);
    const nameLen        = readUInt16LE(buffer, offset + 26);
    const extraLen       = readUInt16LE(buffer, offset + 28);
    const name           = buffer.slice(offset + 30, offset + 30 + nameLen).toString('utf8');

    const dataStart = offset + 30 + nameLen + extraLen;
    const dataEnd   = dataStart + compressedSize;

    if (dataEnd > buffer.length) break;

    const compressedData = buffer.slice(dataStart, dataEnd);

    // Only handle stored (0) and deflated (8) — most common
    if (compressedSize > 0 && compressedSize <= MAX_ENTRY_SIZE && !name.endsWith('/')) {
      let data = null;
      if (compression === 0) {
        data = compressedData;
      } else if (compression === 8) {
        try {
          const zlib = require('zlib');
          data = zlib.inflateRawSync(compressedData);
        } catch {
          data = null;
        }
      }
      if (data) {
        yield { name, data };
        count++;
      }
    }

    offset = dataEnd;
  }
}

/**
 * Recursively scan a ZIP buffer.
 * scanFn(buffer, filename) → { status, signature, deepAnalysis, ... }
 *
 * Returns array of scan results, one per extracted entry.
 */
async function scanArchive(buffer, archiveName, scanFn, depth = 0) {
  if (depth >= MAX_DEPTH || !isZip(buffer)) return [];

  const results = [];

  for (const entry of extractZipEntries(buffer)) {
    const entryName = `${archiveName}::${entry.name}`;

    // Nested archive — recurse
    if (isZip(entry.data) && depth + 1 < MAX_DEPTH) {
      const nested = await scanArchive(entry.data, entryName, scanFn, depth + 1);
      results.push(...nested);
      continue;
    }

    // Scan the entry
    try {
      const result = await scanFn(entry.data, entry.name);
      results.push({ ...result, filename: entryName, extractedFrom: archiveName });
    } catch {
      results.push({
        filename: entryName,
        extractedFrom: archiveName,
        status: 'ERROR',
        message: 'Could not scan archive entry.',
      });
    }
  }

  return results;
}

module.exports = { isZip, scanArchive };
