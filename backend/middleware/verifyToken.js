const { verifyToken: verifySignedToken } = require('../utils/authTokens');

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Missing Authorization header.',
    });
  }

  const [scheme, token] = authHeader.split(' ');
  if (String(scheme || '').toLowerCase() !== 'bearer' || !token) {
    return res.status(401).json({
      success: false,
      message: 'Authorization header must use the Bearer scheme.',
    });
  }

  const verification = verifySignedToken(token);
  if (!verification.valid) {
    return res.status(401).json({
      success: false,
      message: verification.reason || 'Token invalid or expired.',
    });
  }

  req.auth = verification.payload;
  return next();
}

module.exports = verifyToken;
