function getClientIp(req) {
  return String(req.ip || req.connection?.remoteAddress || 'unknown')
}

module.exports = function createRateLimiter(options = {}) {
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : 15 * 60 * 1000
  const max = Number(options.max) > 0 ? Number(options.max) : 100
  const keyPrefix = String(options.keyPrefix || 'rate')
  const keyGenerator = typeof options.keyGenerator === 'function'
    ? options.keyGenerator
    : (req) => getClientIp(req)

  const bucket = new Map()

  return function rateLimit(req, res, next) {
    const now = Date.now()
    const baseKey = String(keyGenerator(req) || 'unknown')
    const key = `${keyPrefix}:${baseKey}`

    const current = bucket.get(key)
    if (!current || current.resetAt <= now) {
      bucket.set(key, { count: 1, resetAt: now + windowMs })
      return next()
    }

    if (current.count >= max) {
      const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000))
      res.set('Retry-After', String(retryAfter))
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please try again later.',
      })
    }

    current.count += 1
    bucket.set(key, current)

    if (bucket.size > 10000) {
      for (const [k, v] of bucket.entries()) {
        if (v.resetAt <= now) bucket.delete(k)
      }
    }

    return next()
  }
}
