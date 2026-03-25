const express = require('express');

const { issueToken } = require('../utils/authTokens');

const router = express.Router();

function normalizeRemoteAddress(req) {
  const forwardedFor = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)[0];
  const candidate = forwardedFor || req.ip || req.socket?.remoteAddress || '';
  return candidate.replace(/^::ffff:/, '');
}

function isPrivateIpv4(address) {
  if (/^127\./.test(address) || /^10\./.test(address) || /^192\.168\./.test(address)) {
    return true;
  }

  const match = address.match(/^172\.(\d{1,3})\./);
  if (!match) {
    return false;
  }

  const secondOctet = Number(match[1]);
  return secondOctet >= 16 && secondOctet <= 31;
}

function isLocalRequest(req) {
  const address = normalizeRemoteAddress(req);
  return (
    address === '::1'
    || address === 'localhost'
    || isPrivateIpv4(address)
  );
}

router.get('/session', (req, res) => {
  if (!isLocalRequest(req)) {
    return res.status(403).json({
      success: false,
      message: 'Runtime session bootstrap is only available from local or private-network clients.',
    });
  }

  const ttlMs = Number(process.env.PLATFORM_SESSION_TTL_MS || 12 * 60 * 60 * 1000);
  const token = issueToken({
    clientIp: normalizeRemoteAddress(req),
    kind: 'runtime-session',
  }, {
    subject: 'local-bootstrap',
    ttlMs,
  });

  return res.json({
    success: true,
    token,
    expiresAt: new Date(Date.now() + ttlMs).toISOString(),
  });
});

router.post('/login', (req, res) => {
  const adminUsername = process.env.PLATFORM_ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.PLATFORM_ADMIN_PASSWORD;
  const { username, password } = req.body || {};

  if (!adminPassword) {
    return res.status(503).json({
      success: false,
      message: 'PLATFORM_ADMIN_PASSWORD is not configured on this backend.',
    });
  }

  if (username !== adminUsername || password !== adminPassword) {
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials.',
    });
  }

  const ttlMs = Number(process.env.PLATFORM_SESSION_TTL_MS || 12 * 60 * 60 * 1000);
  const token = issueToken({
    clientIp: normalizeRemoteAddress(req),
    kind: 'password-session',
  }, {
    subject: adminUsername,
    ttlMs,
  });

  return res.status(200).json({
    success: true,
    token,
    expiresAt: new Date(Date.now() + ttlMs).toISOString(),
  });
});

module.exports = router;
