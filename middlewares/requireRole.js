const { normalizeRole } = require('../constants/roles')

function flattenRoles(input) {
  if (Array.isArray(input)) return input
  return [input]
}

module.exports = function requireRole(rolesInput) {
  const allowedRoles = new Set(
    flattenRoles(rolesInput)
      .map((r) => normalizeRole(r))
      .filter(Boolean)
  )

  return function roleGuard(req, res, next) {
    if (!req.auth?.userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    const actorRole = normalizeRole(req.auth.role)
    if (!allowedRoles.size || allowedRoles.has(actorRole)) {
      return next()
    }

    return res.status(403).json({ success: false, message: 'Forbidden' })
  }
}
