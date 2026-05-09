/**
 * EML / RFC 822 Email Parser
 *
 * Parser propriu (fără dependențe) pentru fișiere .eml:
 *  - Extrage From, To, Subject, Date
 *  - Detectează atașamente MIME (Content-Disposition: attachment)
 *  - Decodează atașamente Base64 / Quoted-Printable în Buffer
 *
 * Atașamentele extrase sunt apoi rulate prin pipeline-ul standard de scan.
 */

function decodeQuotedPrintable(text) {
  return text
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function parseHeaders(headerBlock) {
  const headers = {};
  const lines = headerBlock.split(/\r?\n/);
  let currentKey = null;

  for (const line of lines) {
    if (/^[\s\t]/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
      continue;
    }
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    headers[key] = value;
    currentKey = key;
  }

  return headers;
}

function extractBoundary(contentType = '') {
  const m = contentType.match(/boundary\s*=\s*"?([^";]+)"?/i);
  return m ? m[1] : null;
}

function splitParts(body, boundary) {
  const sep = `--${boundary}`;
  const parts = body.split(sep);
  return parts.slice(1, -1).map((p) => p.replace(/^\r?\n/, '').replace(/\r?\n$/, ''));
}

function parsePart(rawPart) {
  const splitIdx = rawPart.indexOf('\r\n\r\n');
  const altIdx = splitIdx === -1 ? rawPart.indexOf('\n\n') : splitIdx;
  if (altIdx === -1) return null;

  const headerBlock = rawPart.slice(0, altIdx);
  const bodyBlock = rawPart.slice(altIdx + (rawPart[altIdx] === '\r' ? 4 : 2));
  const headers = parseHeaders(headerBlock);

  return { headers, body: bodyBlock };
}

function extractAttachment(part) {
  const ct = part.headers['content-type'] || '';
  const cd = part.headers['content-disposition'] || '';
  const cte = (part.headers['content-transfer-encoding'] || '').toLowerCase();

  const isAttachment = /attachment/i.test(cd) || /name\s*=/i.test(ct);
  if (!isAttachment) return null;

  const nameMatch = cd.match(/filename\s*=\s*"?([^";]+)"?/i) || ct.match(/name\s*=\s*"?([^";]+)"?/i);
  const filename = nameMatch ? nameMatch[1] : 'attachment.bin';

  let buffer;
  if (cte === 'base64') {
    const cleaned = part.body.replace(/[\r\n\s]/g, '');
    try {
      buffer = Buffer.from(cleaned, 'base64');
    } catch {
      return null;
    }
  } else if (cte === 'quoted-printable') {
    buffer = Buffer.from(decodeQuotedPrintable(part.body), 'latin1');
  } else {
    buffer = Buffer.from(part.body, 'latin1');
  }

  return {
    filename,
    contentType: ct.split(';')[0].trim(),
    encoding: cte,
    size: buffer.length,
    buffer,
  };
}

/**
 * Parsează un buffer .eml și returnează headers + atașamente.
 *
 * @param {Buffer} emlBuffer
 * @returns {{ headers, attachments, summary }}
 */
function parseEml(emlBuffer) {
  if (!Buffer.isBuffer(emlBuffer) || emlBuffer.length === 0) {
    return { headers: {}, attachments: [], summary: 'Empty input' };
  }

  const raw = emlBuffer.toString('latin1');
  const splitIdx = raw.indexOf('\r\n\r\n');
  const altIdx = splitIdx === -1 ? raw.indexOf('\n\n') : splitIdx;
  if (altIdx === -1) {
    return { headers: {}, attachments: [], summary: 'Not a valid EML' };
  }

  const headers = parseHeaders(raw.slice(0, altIdx));
  const body = raw.slice(altIdx + (raw[altIdx] === '\r' ? 4 : 2));

  const contentType = headers['content-type'] || '';
  const boundary = extractBoundary(contentType);
  const attachments = [];

  if (boundary) {
    const parts = splitParts(body, boundary);
    for (const rawPart of parts) {
      const parsed = parsePart(rawPart);
      if (!parsed) continue;

      // Multi-part nested
      const innerCT = parsed.headers['content-type'] || '';
      const innerBoundary = extractBoundary(innerCT);
      if (innerBoundary) {
        for (const subRaw of splitParts(parsed.body, innerBoundary)) {
          const subParsed = parsePart(subRaw);
          if (!subParsed) continue;
          const att = extractAttachment(subParsed);
          if (att) attachments.push(att);
        }
        continue;
      }

      const att = extractAttachment(parsed);
      if (att) attachments.push(att);
    }
  }

  const summary = `From: ${headers.from || '?'} | Subject: ${headers.subject || '(no subject)'} | Attachments: ${attachments.length}`;

  return {
    headers: {
      from: headers.from,
      to: headers.to,
      subject: headers.subject,
      date: headers.date,
      messageId: headers['message-id'],
      replyTo: headers['reply-to'],
    },
    attachments,
    summary,
  };
}

module.exports = { parseEml };
