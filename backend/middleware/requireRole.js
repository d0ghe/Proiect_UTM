/**
 * RBAC Middleware
 *
 * Verifică că tokenul JWT include un rol care permite acțiunea.
 * Roluri: admin > analyst > viewer.
 *
 * - admin: tot (CRUD reguli, plant honeypots, modifică controale, șterge log-uri)
 * - analyst: scan, vizualizare deep analysis, vizualizare IOC/MITRE, rulare reguli
 * - viewer: doar GET pe dashboard, stats, status (read-only)
 */

const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };

function requireRole(minimumRole) {
  const minRank = ROLE_RANK[minimumRole] || 0;

  return function (req, res, next) {
    const userRole = req.auth?.role || req.auth?.kind === 'runtime-session' ? 'analyst' : 'viewer';
    const userRank = ROLE_RANK[userRole] || 1;

    if (userRank < minRank) {
      return res.status(403).json({
        success: false,
        message: `This action requires '${minimumRole}' role. Current role: '${userRole}'.`,
      });
    }
    return next();
  };
}

module.exports = { requireRole, ROLE_RANK };
