const crypto = require('crypto');

function toBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value) {
  return Buffer.from(String(value || ''), 'base64url');
}

function getSigningSecret() {
  const secret = process.env.PLATFORM_TOKEN_SECRET;
  if (!secret) {
    throw new Error('PLATFORM_TOKEN_SECRET is not configured.');
  }

  return secret;
}

function signValue(value) {
  return crypto
    .createHmac('sha256', getSigningSecret())
    .update(value)
    .digest('base64url');
}

function issueToken(payload = {}, options = {}) {
  const now = Date.now();
  const tokenPayload = {
    aud: 'sentinel-local-ui',
    iat: now,
    exp: now + (options.ttlMs || 12 * 60 * 60 * 1000),
    jti: crypto.randomUUID(),
    scope: options.scope || 'ui',
    sub: options.subject || 'local-operator',
    ...payload,
  };
  const serializedPayload = toBase64Url(JSON.stringify(tokenPayload));
  const signature = signValue(serializedPayload);
  return `${serializedPayload}.${signature}`;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''));
  const rightBuffer = Buffer.from(String(right || ''));

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) {
    return { valid: false, reason: 'Malformed token.' };
  }

  const [serializedPayload, receivedSignature] = token.split('.');
  const expectedSignature = signValue(serializedPayload);
  if (!safeEqual(receivedSignature, expectedSignature)) {
    return { valid: false, reason: 'Invalid token signature.' };
  }

  try {
    const payload = JSON.parse(fromBase64Url(serializedPayload).toString('utf8'));
    if (!payload?.exp || Number(payload.exp) <= Date.now()) {
      return { valid: false, reason: 'Token expired.' };
    }

    return {
      valid: true,
      payload,
    };
  } catch (error) {
    return {
      valid: false,
      reason: error.message,
    };
  }
}

module.exports = {
  issueToken,
  verifyToken,
};
