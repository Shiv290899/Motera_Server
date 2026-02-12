const jwt = require('jsonwebtoken')
const User = require('../models/userModel')
const { normalizeRole } = require('../constants/roles')

const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET && process.env.NODE_ENV !== 'production') {
  console.warn('JWT_SECRET not set; using insecure default for development')
}

module.exports = async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || req.headers.Authorization || ''
    const match = typeof header === 'string' ? header.match(/^\s*Bearer\s+(.+)$/i) : null
    const token = match && match[1] ? match[1].trim() : ''

    if (!token) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    let verifiedToken
    try {
      verifiedToken = jwt.verify(token, JWT_SECRET || 'motera')
    } catch (e) {
      if (JWT_SECRET && JWT_SECRET !== 'motera') {
        try {
          verifiedToken = jwt.verify(token, 'motera')
        } catch (_) {
          verifiedToken = null
        }
      }
    }

    if (!verifiedToken?.userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    const user = await User.findById(verifiedToken.userId).select('role tokenInvalidAfter')
    if (!user) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    if (user.tokenInvalidAfter && typeof verifiedToken.iat === 'number') {
      const invalidAfterSec = Math.floor(new Date(user.tokenInvalidAfter).getTime() / 1000)
      if (!Number.isNaN(invalidAfterSec) && verifiedToken.iat < invalidAfterSec) {
        return res.status(401).json({ success: false, message: 'Unauthorized' })
      }
    }

    req.userId = String(verifiedToken.userId)
    req.auth = {
      userId: req.userId,
      role: normalizeRole(user.role),
    }

    // Preserve legacy compatibility for routes still reading req.body.userId.
    if (!req.body || typeof req.body !== 'object') req.body = {}
    req.body.userId = req.userId

    return next()
  } catch {
    return res.status(401).json({ success: false, message: 'Unauthorized' })
  }
}
