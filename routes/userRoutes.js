const express = require('express')
const router = express.Router()
const User = require('../models/userModel')
const Branch = require('../models/branchModel')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const createRateLimiter = require('../middlewares/rateLimit')
const crypto = require('crypto')
const axios = require('axios')
const { sendMail, isMailConfigured } = require('../utils/mailer')
const { ROLES, normalizeRole } = require('../constants/roles')

const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '60d'
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10)
const RESET_TOKEN_EXP_MINUTES = parseInt(process.env.RESET_TOKEN_EXP_MINUTES || '30', 10)
const INVITE_TOKEN_EXP_DAYS = parseInt(process.env.INVITE_TOKEN_EXP_DAYS || '7', 10)
const APP_URL = (process.env.APP_URL || 'http://localhost:5174').replace(/\/$/, '')
if (!JWT_SECRET && process.env.NODE_ENV !== 'production') {
  console.warn('JWT_SECRET not set; using insecure default for development')
}

const registerWindowMs = Math.max(60 * 1000, parseInt(process.env.REGISTER_RATE_LIMIT_WINDOW_MS || `${15 * 60 * 1000}`, 10) || 15 * 60 * 1000)
const registerMax = Math.max(1, parseInt(process.env.REGISTER_RATE_LIMIT_MAX || '5', 10) || 5)
const registerRateLimit = createRateLimiter({
  windowMs: registerWindowMs,
  max: registerMax,
  keyPrefix: 'register',
})
const registerRateLimitEnabled = process.env.NODE_ENV === 'production' || String(process.env.REGISTER_RATE_LIMIT_ENABLE_DEV || '').toLowerCase() === 'true'
const registerRateLimitMiddleware = registerRateLimitEnabled ? registerRateLimit : (req, res, next) => next()

function resolveTenantOwnerId(userDoc) {
  const role = normalizeRole(userDoc?.role)
  if (role === ROLES.ADMIN) return null
  if (role === ROLES.OWNER) return String(userDoc?._id || '')
  return userDoc?.owner ? String(userDoc.owner) : null
}

function canViewWebhookUrls(roleInput) {
  const role = normalizeRole(roleInput)
  return role === ROLES.STAFF || role === ROLES.OWNER || role === ROLES.ADMIN
}

function sanitizeOwnerConfigForRole(ownerConfig, roleInput) {
  if (!ownerConfig || typeof ownerConfig !== 'object') return ownerConfig
  const clean = { ...ownerConfig }
  if (!canViewWebhookUrls(roleInput)) {
    delete clean.webhookUrl
  }
  return clean
}

function sanitizeUserForViewer(userObj, viewerRole) {
  if (!userObj || typeof userObj !== 'object') return userObj
  const copy = { ...userObj }
  copy.role = normalizeRole(copy.role)
  if (copy.ownerConfig) {
    copy.ownerConfig = sanitizeOwnerConfigForRole(copy.ownerConfig, viewerRole)
  }
  return copy
}

const GOOGLE_IMAGE_HOST_ALLOWLIST = new Set([
  'lh3.googleusercontent.com',
  'drive.google.com',
  'docs.google.com',
  'drive.usercontent.google.com',
])

const isAllowedGoogleImageHost = (host) => {
  const h = String(host || '').trim().toLowerCase()
  if (!h) return false
  if (GOOGLE_IMAGE_HOST_ALLOWLIST.has(h)) return true
  return h.endsWith('.googleusercontent.com')
}

// Proxy Google-hosted images to avoid browser-side CORP/CSP embedding issues.
router.get('/image-proxy', async (req, res) => {
  try {
    const raw = String(req.query.url || '').trim()
    if (!raw) return res.status(400).json({ success: false, message: 'url is required' })
    let parsed
    try {
      parsed = new URL(raw)
    } catch (_) {
      return res.status(400).json({ success: false, message: 'invalid url' })
    }
    if (parsed.protocol !== 'https:') {
      return res.status(400).json({ success: false, message: 'only https urls are allowed' })
    }
    if (!isAllowedGoogleImageHost(parsed.hostname)) {
      return res.status(403).json({ success: false, message: 'host not allowed' })
    }

    const upstream = await axios.get(parsed.toString(), {
      responseType: 'arraybuffer',
      timeout: 20000,
      maxRedirects: 5,
      validateStatus: (s) => s >= 200 && s < 400,
      headers: {
        'User-Agent': 'Mozilla/5.0 MoteraImageProxy',
        'Accept': 'image/*,*/*;q=0.8',
      },
    })

    const ctype = String(upstream.headers['content-type'] || '').toLowerCase()
    if (!ctype.startsWith('image/')) {
      return res.status(415).json({ success: false, message: 'upstream is not an image' })
    }
    const cc = String(upstream.headers['cache-control'] || '').trim() || 'public, max-age=86400'
    res.setHeader('Content-Type', ctype)
    res.setHeader('Cache-Control', cc)
    return res.status(200).send(Buffer.from(upstream.data))
  } catch (err) {
    const status = Number(err?.response?.status) || 502
    return res.status(status).json({ success: false, message: 'image proxy failed' })
  }
})

// Create invite link for staff/mechanic/callboy under an owner
router.post('/invite', auth, requireRole([ROLES.ADMIN, ROLES.OWNER]), async (req, res) => {
  try {
    const body = req.body || {}
    const actorRole = normalizeRole(req.auth?.role)
    const inviteRole = normalizeRole(body.role || ROLES.STAFF)
    const allowed = new Set([ROLES.STAFF])
    if (!allowed.has(inviteRole)) {
      return res.status(400).json({ success: false, message: 'Invalid role for invite' })
    }

    let ownerId = ''
    if (actorRole === ROLES.OWNER) {
      ownerId = String(req.auth?.userId || '')
    } else {
      ownerId = String(body.ownerId || '')
      if (!mongoose.Types.ObjectId.isValid(ownerId)) {
        return res.status(400).json({ success: false, message: 'ownerId is required' })
      }
    }

    const ownerDoc = await User.findById(ownerId).select('_id role')
    if (!ownerDoc || normalizeRole(ownerDoc.role) !== ROLES.OWNER) {
      return res.status(400).json({ success: false, message: 'Invalid ownerId' })
    }

    const branchIdRaw = body.branchId ? String(body.branchId) : ''
    const branchId = mongoose.Types.ObjectId.isValid(branchIdRaw) ? branchIdRaw : undefined
    if (branchId) {
      const branchDoc = await Branch.findById(branchId).select('_id owner status')
      if (!branchDoc) {
        return res.status(400).json({ success: false, message: 'Invalid branchId' })
      }
      if (String(branchDoc.owner || '') !== String(ownerId)) {
        return res.status(403).json({ success: false, message: 'Branch does not belong to owner' })
      }
    }

    const expiresIn = `${Math.max(1, INVITE_TOKEN_EXP_DAYS)}d`
    const token = jwt.sign({ type: 'invite', role: inviteRole, ownerId, ...(branchId ? { branchId } : {}) }, JWT_SECRET || 'motera', { expiresIn })
    const params = new URLSearchParams({ invite: token })
    if (branchId) params.set('branchId', branchId)
    const inviteUrl = `${APP_URL}/register?${params.toString()}`
    return res.json({ success: true, data: { inviteUrl, token, role: inviteRole, ownerId, branchId, expiresIn } })
  } catch (err) {
    console.error('POST /users/invite failed', err)
    return res.status(500).json({ success: false, message: 'Failed to create invite' })
  }
})

// Verify invite token (optional helper for UI)
router.get('/invite/verify', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim()
    if (!token) return res.status(400).json({ success: false, message: 'token is required' })
    const decoded = jwt.verify(token, JWT_SECRET || 'motera')
    if (decoded?.type !== 'invite') return res.status(400).json({ success: false, message: 'Invalid invite' })
    return res.json({ success: true, data: decoded })
  } catch (err) {
    return res.status(400).json({ success: false, message: 'Invalid or expired invite' })
  }
})


router.post('/register', registerRateLimitMiddleware, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim()
    const email = String(req.body.email || '').trim().toLowerCase()
    const phone = req.body.phone ? String(req.body.phone).trim() : undefined
    const inviteToken = String(req.body?.inviteToken || '').trim()

    if (!name || !email || !req.body.password) {
      return res.status(400).send({
        success: false,
        message: 'Name, email and password are required.',
      })
    }

    if (Object.prototype.hasOwnProperty.call(req.body || {}, 'role')) {
      return res.status(400).json({
        success: false,
        message: 'Role assignment is not allowed during signup.',
      })
    }

    // Build a safe payload — do not allow role/status/branch escalation via public register
    const incomingPassword = String(req.body.password)
    const safeBody = {
      name,
      email,
      ...(phone ? { phone } : {}),
      role: ROLES.USER,
    }

    // Optional invite flow: attach owner + staff role safely from signed token.
    if (inviteToken) {
      let decoded
      try {
        decoded = jwt.verify(inviteToken, JWT_SECRET || 'motera')
      } catch (_) {
        return res.status(400).json({ success: false, message: 'Invalid or expired invite token.' })
      }
      if (!decoded || decoded.type !== 'invite') {
        return res.status(400).json({ success: false, message: 'Invalid invite token.' })
      }

      const inviteOwnerId = String(decoded.ownerId || '')
      if (!mongoose.Types.ObjectId.isValid(inviteOwnerId)) {
        return res.status(400).json({ success: false, message: 'Invite missing owner information.' })
      }

      const ownerDoc = await User.findById(inviteOwnerId).select('_id role primaryBranch branches')
      if (!ownerDoc || normalizeRole(ownerDoc.role) !== ROLES.OWNER) {
        return res.status(400).json({ success: false, message: 'Invite owner not found.' })
      }

      let branchId = decoded.branchId && mongoose.Types.ObjectId.isValid(String(decoded.branchId))
        ? String(decoded.branchId)
        : ''

      if (!branchId) {
        branchId = String(ownerDoc.primaryBranch || (Array.isArray(ownerDoc.branches) ? ownerDoc.branches[0] : '') || '')
      }
      if (!branchId || !mongoose.Types.ObjectId.isValid(branchId)) {
        return res.status(400).json({ success: false, message: 'Invite is missing a valid branch.' })
      }

      const branchDoc = await Branch.findById(branchId).select('_id owner status')
      if (!branchDoc || String(branchDoc.owner || '') !== inviteOwnerId) {
        return res.status(400).json({ success: false, message: 'Invite branch is invalid.' })
      }
      if (String(branchDoc.status || '').toLowerCase() !== 'active') {
        return res.status(400).json({ success: false, message: 'Invite branch is inactive.' })
      }

      safeBody.role = normalizeRole(decoded.role || ROLES.STAFF)
      safeBody.owner = inviteOwnerId
      safeBody.primaryBranch = branchId
      safeBody.branches = [branchId]
    }

    const duplicate = await User.findOne({
      $or: [
        { email },
        ...(phone ? [{ phone }] : []),
      ],
    })

    if (duplicate) {
      const sameEmail = duplicate.email === email
      const samePhone = phone && duplicate.phone === phone
      let message = 'An account with these details already exists.'
      if (sameEmail && samePhone) {
        message = 'Both email and mobile number are already registered.'
      } else if (sameEmail) {
        message = 'Email is already registered.'
      } else if (samePhone) {
        message = 'Mobile number is already registered.'
      }

      return res.status(409).send({
        success: false,
        message,
      })
    }

    const hashedPassword = await bcrypt.hash(incomingPassword, BCRYPT_SALT_ROUNDS)
    const newUser = new User({ ...safeBody, password: hashedPassword })
    await newUser.save()

    return res.status(201).send({
      success: true,
      message: 'User registered successfully.',
    })
  } catch (err) {
    if (err?.code === 11000) {
      const keys = Object.keys(err.keyPattern || {})
      let message = 'Account already exists.'
      if (keys.includes('email')) message = 'Email is already registered.'
      else if (keys.includes('phone')) message = 'Mobile number is already registered.'
      return res.status(409).send({ success: false, message })
    }

    console.error(err)
    return res.status(500).send({
      success: false,
      message: 'Could not complete registration. Please try again later.',
    })
  }
})

router.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase()
    const user = await User.findOne({ email })

    if (!user) {
      return res.status(404).send({
        success: false,
        message: 'User does not exist. Please register.',
      })
    }

    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    )

    if (!validPassword) {
      return res.status(401).send({
        success: false,
        message: 'Sorry, invalid password entered!',
      })
    }

    const jwtToken = jwt.sign({ userId: user._id }, JWT_SECRET || 'motera', {
      expiresIn: JWT_EXPIRES_IN,
    })

    // Update last login timestamp (for dashboard visibility) and clear any forced logout flag
    try {
      await User.updateOne(
        { _id: user._id },
        { $set: { lastLoginAt: new Date() }, $unset: { tokenInvalidAfter: 1 } }
      )
    } catch { /* non-blocking */ }

    const userDoc = await User.findById(user._id)
      .select('-password')
      .populate('primaryBranch', 'name code owner')
      .populate({ path: 'branches', select: 'name code owner', options: { limit: 3 } })
    const full = userDoc ? sanitizeUserForViewer(userDoc.toJSON(), userDoc.role) : null
    let branchName = null
    let branchCode = null
    if (userDoc?.primaryBranch && userDoc.primaryBranch.name) {
      branchName = userDoc.primaryBranch.name
      branchCode = userDoc.primaryBranch.code || null
    } else if (Array.isArray(userDoc?.branches) && userDoc.branches.length) {
      branchName = userDoc.branches[0]?.name || null
      branchCode = userDoc.branches[0]?.code || null
    }
    if (full) {
      full.formDefaults = full.formDefaults || {}
      if (!full.formDefaults.staffName) full.formDefaults.staffName = full.name || ''
      if (!full.formDefaults.branchId) full.formDefaults.branchId = userDoc.primaryBranch?._id || (Array.isArray(userDoc.branches) ? userDoc.branches[0]?._id : undefined)
      if (branchName) full.formDefaults.branchName = branchName
      if (branchCode) full.formDefaults.branchCode = String(branchCode).toUpperCase()
    }
    // For non-owner/admin users, surface ownerConfig from their owner.
    // Fallback to branch.owner when user.owner is missing (legacy staff rows).
    try {
      const roleLc = normalizeRole(userDoc?.role)
      if (roleLc !== ROLES.OWNER && roleLc !== ROLES.ADMIN) {
        let ownerId = userDoc?.owner ? String(userDoc.owner) : ''
        if (!ownerId) {
          const primaryOwner = userDoc?.primaryBranch?.owner
          if (primaryOwner) ownerId = String(primaryOwner?._id || primaryOwner)
        }
        if (!ownerId && Array.isArray(userDoc?.branches)) {
          const bOwner = userDoc.branches.find((b) => b?.owner)?.owner
          if (bOwner) ownerId = String(bOwner?._id || bOwner)
        }
        if (!ownerId && userDoc?.primaryBranch?._id) {
          const br = await Branch.findById(userDoc.primaryBranch._id).select('owner')
          if (br?.owner) ownerId = String(br.owner)
        }
        if (ownerId && !userDoc?.owner) {
          await User.updateOne({ _id: userDoc._id }, { $set: { owner: ownerId } })
        }
        if (!ownerId || !mongoose.Types.ObjectId.isValid(ownerId)) {
          ownerId = ''
        }
        const ownerDoc = ownerId ? await User.findById(ownerId).select('ownerConfig name') : null
        if (ownerDoc?.ownerConfig) {
          full.ownerConfig = sanitizeOwnerConfigForRole(ownerDoc.ownerConfig, roleLc)
        }
        if (ownerDoc?._id) {
          full.owner = ownerDoc._id
        }
      }
    } catch { /* non-blocking */ }

    return res.send({
      success: true,
      message: "You've successfully logged in!",
      token: jwtToken,
      user: full || {
        name: user.name,
        email: user.email,
        role: normalizeRole(user.role),
        phone: user.phone,
        id: String(user._id),
      },
    })
  } catch (error) {
    console.error(error)
    return res.status(500).send({
      success: false,
      message: 'Unable to process login right now. Please try again later.',
    })
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase()

    if (!email) {
      return res.status(400).send({
        success: false,
        message: 'Email is required.',
      })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(404).send({
        success: false,
        message: 'We could not find an account with that email.',
      })
    }

    const rawToken = crypto.randomBytes(32).toString('hex')
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex')

    user.resetPasswordToken = hashedToken
    user.resetPasswordExpiresAt = new Date(Date.now() + RESET_TOKEN_EXP_MINUTES * 60 * 1000)
    await user.save()

    const resetLink = `${APP_URL}/login?resetToken=${rawToken}`

    const responsePayload = {
      success: true,
      message: 'If the account exists, we have sent password reset instructions.',
    }

    if (isMailConfigured()) {
      try {
        await sendMail({
          to: email,
          subject: 'Reset your Motera password',
          text: `You requested a password reset. Use the link below to set a new password.\n\n${resetLink}\n\nIf you did not request this, you can ignore this email.`,
          html: `
            <p>You requested a password reset for Motera.</p>
            <p><a href="${resetLink}" target="_blank" rel="noopener">Click here to choose a new password</a>.</p>
            <p>If the button doesn't work, paste this link in your browser:</p>
            <p><code>${resetLink}</code></p>
            <p>This link expires in ${RESET_TOKEN_EXP_MINUTES} minutes.</p>
          `,
        })
        responsePayload.emailSent = true
      } catch (mailError) {
        console.error('Failed to send reset email:', mailError)
        return res.status(500).send({
          success: false,
          message: 'Could not send reset email. Please try again later.',
        })
      }
    } else if (process.env.NODE_ENV !== 'production') {
      responsePayload.devResetToken = rawToken
      responsePayload.devResetExpiry = user.resetPasswordExpiresAt
    }

    return res.send(responsePayload)
  } catch (error) {
    console.error(error)
    return res.status(500).send({
      success: false,
      message: 'Unable to start password reset. Please try again later.',
    })
  }
})

router.post('/reset-password', async (req, res) => {
  try {
    const token = String(req.body.token || '').trim()
    const password = req.body.password

    if (!token || !password) {
      return res.status(400).send({
        success: false,
        message: 'Token and new password are required.',
      })
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpiresAt: { $gt: new Date() },
    })

    if (!user) {
      return res.status(400).send({
        success: false,
        message: 'Reset link is invalid or has expired.',
      })
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS)
    user.password = hashedPassword
    user.resetPasswordToken = undefined
    user.resetPasswordExpiresAt = undefined
    await user.save()

    return res.send({
      success: true,
      message: 'Password has been reset successfully.',
    })
  } catch (error) {
    console.error(error)
    return res.status(500).send({
      success: false,
      message: 'Unable to reset password. Please try again later.',
    })
  }
})

// List users (admin/owner only)
router.get('/', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { q, role, status, branch, limit = 100, page = 1 } = req.query || {}
    const filter = {}
    const me = await User.findById(req.userId).select('role owner')
    const roleMe = normalizeRole(me?.role)
    const ownerId = resolveTenantOwnerId(me)
    if (roleMe === ROLES.OWNER && ownerId) {
      filter.$or = [{ owner: ownerId }, { _id: ownerId }]
    }
    if (q) {
      const re = new RegExp(String(q), 'i')
      filter.$or = [
        { name: re },
        { email: re },
        { phone: re },
        { jobTitle: re },
        { employeeCode: re },
      ]
    }
    if (role) filter.role = normalizeRole(role)
    if (status) filter.status = status
    if (branch && mongoose.Types.ObjectId.isValid(String(branch))) {
      const b = new mongoose.Types.ObjectId(String(branch))
      filter.$or = [...(filter.$or || []), { primaryBranch: b }, { branches: b }]
    }
    const skip = (Math.max(parseInt(page, 10), 1) - 1) * Math.max(parseInt(limit, 10), 1)
    const [items, total] = await Promise.all([
      User.find(filter)
        .select('-password -resetPasswordToken -resetPasswordExpiresAt')
        .populate('primaryBranch', 'name code')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit, 10)),
      User.countDocuments(filter),
    ])
    const safeItems = items.map((item) => sanitizeUserForViewer(item.toJSON ? item.toJSON() : item, roleMe))
    return res.json({ success: true, data: { items: safeItems, total } })
  } catch (err) {
    console.error('GET /users failed', err)
    return res.status(500).json({ success: false, message: 'Failed to fetch users' })
  }
})

// Public read-only list (no auth). Mirrors filters of the secured list.
router.get('/public', async (req, res) => {
  try {
    const { q, role, status, branch, limit = 100, page = 1, ownerId } = req.query || {}
    const filter = {}
    if (!ownerId || !mongoose.Types.ObjectId.isValid(String(ownerId))) {
      return res.json({ success: true, data: { items: [], total: 0 }, public: true })
    }
    filter.$or = [{ owner: ownerId }, { _id: ownerId }]
    if (q) {
      const re = new RegExp(String(q), 'i')
      filter.$or = [
        { name: re },
        { email: re },
        { phone: re },
        { jobTitle: re },
        { employeeCode: re },
      ]
    }
    if (role) filter.role = normalizeRole(role)
    if (status) filter.status = status
    if (branch && mongoose.Types.ObjectId.isValid(String(branch))) {
      const b = new mongoose.Types.ObjectId(String(branch))
      filter.$or = [...(filter.$or || []), { primaryBranch: b }, { branches: b }]
    }
    const skip = (Math.max(parseInt(page, 10), 1) - 1) * Math.max(parseInt(limit, 10), 1)
    const projection = '-password -resetPasswordToken -resetPasswordExpiresAt'
    const [items, total] = await Promise.all([
      User.find(filter)
        .select(projection)
        .populate('primaryBranch', 'name code')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit, 10)),
      User.countDocuments(filter),
    ])
    const safeItems = items.map((item) => sanitizeUserForViewer(item.toJSON ? item.toJSON() : item, ROLES.USER))
    return res.json({ success: true, data: { items: safeItems, total }, public: true })
  } catch (err) {
    console.error('GET /users/public failed', err)
    return res.status(500).json({ success: false, message: 'Failed to fetch users' })
  }
})

// Admin create user
router.post('/', auth, requireRole([ROLES.ADMIN]), async (req, res) => {
  try {
    const body = req.body || {}
    const name = String(body.name || '').trim()
    const email = String(body.email || '').trim().toLowerCase()
    const role = normalizeRole(body.role || ROLES.USER)
    const passwordPlain = String(body.password || '')

    if (!name || !email || !passwordPlain) {
      return res.status(400).json({ success: false, message: 'name, email, password are required' })
    }

    // Unique checks for email/phone
    const dup = await User.findOne({ $or: [{ email }, ...(body.phone ? [{ phone: String(body.phone).trim() }] : [])] })
    if (dup) {
      const sameEmail = dup.email === email
      const samePhone = body.phone && dup.phone === String(body.phone).trim()
      return res.status(409).json({ success: false, message: sameEmail ? 'Email already exists' : samePhone ? 'Phone already exists' : 'User already exists' })
    }

    const payload = {
      name,
      email,
      password: await bcrypt.hash(passwordPlain, BCRYPT_SALT_ROUNDS),
      role,
      status: body.status || 'active',
      ...(body.phone ? { phone: String(body.phone).trim() } : {}),
      ...(body.jobTitle ? { jobTitle: String(body.jobTitle).trim() } : {}),
      ...(body.employeeCode ? { employeeCode: String(body.employeeCode).trim() } : {}),
      ...(body.primaryBranch && mongoose.Types.ObjectId.isValid(String(body.primaryBranch)) ? { primaryBranch: body.primaryBranch } : {}),
      ...(Array.isArray(body.branches) ? { branches: body.branches.filter(v => mongoose.Types.ObjectId.isValid(String(v))) } : {}),
      ...(typeof body.canSwitchBranch === 'boolean' ? { canSwitchBranch: body.canSwitchBranch } : {}),
    }

    if (role === ROLES.STAFF) {
      if (!body.owner || !mongoose.Types.ObjectId.isValid(String(body.owner))) {
        return res.status(400).json({ success: false, message: 'owner is required for STAFF' })
      }
      payload.owner = body.owner
    }

    const created = await User.create(payload)
    if (normalizeRole(created.role) === ROLES.OWNER && !created.owner) {
      created.owner = created._id
      await created.save()
    }
    return res.status(201).json({ success: true, message: 'User created', data: sanitizeUserForViewer(created.toJSON(), ROLES.ADMIN) })
  } catch (err) {
    if (err?.code === 11000) {
      const keys = Object.keys(err.keyPattern || {})
      const msg = keys.includes('email') ? 'Email already exists' : keys.includes('phone') ? 'Phone already exists' : 'Duplicate key'
      return res.status(409).json({ success: false, message: msg })
    }
    if (err?.name === 'ValidationError') {
      const details = Object.values(err.errors || {}).map(e => e?.message).join('; ')
      return res.status(400).json({ success: false, message: details || 'Validation failed' })
    }
    console.error('POST /users failed', err)
    return res.status(500).json({ success: false, message: 'Failed to create user' })
  }
})

// Admin/Owner update user
router.put('/:id', auth, requireRole([ROLES.ADMIN, ROLES.OWNER]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid user id' })
    }
    const actorRole = normalizeRole(req.auth?.role)
    const actorUserId = String(req.auth?.userId || '')
    const body = { ...req.body }
    delete body.userId
    if (body.email) body.email = String(body.email).trim().toLowerCase()
    if (body.name) body.name = String(body.name).trim()
    if (body.phone != null) body.phone = body.phone === '' ? undefined : String(body.phone).trim()
    if (typeof body.canSwitchBranch !== 'undefined') body.canSwitchBranch = !!body.canSwitchBranch
    if (Object.prototype.hasOwnProperty.call(body, 'role')) {
      body.role = normalizeRole(body.role)
    }
    const targetUser = await User.findById(id).select('_id role owner')
    if (!targetUser) return res.status(404).json({ success: false, message: 'User not found' })
    const targetRole = normalizeRole(targetUser.role)
    const targetOwnerId = String(targetUser.owner || '')

    if (actorRole === ROLES.OWNER) {
      // Owner can update self or users belonging to this owner only.
      const ownsTarget = String(targetUser._id) === actorUserId || targetOwnerId === actorUserId
      if (!ownsTarget) {
        return res.status(403).json({ success: false, message: 'Forbidden' })
      }
      // Owner must not alter tenant-control fields.
      delete body.ownerLimits
      delete body.role
      delete body.owner
      // Owner cannot edit another owner record.
      if (targetRole === ROLES.OWNER && String(targetUser._id) !== actorUserId) {
        return res.status(403).json({ success: false, message: 'Forbidden' })
      }
    }

    if (body.role === ROLES.STAFF) {
      const ownerId = String(body.owner || '').trim()
      if (!mongoose.Types.ObjectId.isValid(ownerId)) {
        return res.status(400).json({ success: false, message: 'owner is required for STAFF' })
      }
    }

    if (actorRole === ROLES.ADMIN && body.ownerLimits && typeof body.ownerLimits === 'object') {
      const limitRaw = body.ownerLimits.branchLimit
      const limitNum = limitRaw === '' || limitRaw == null ? undefined : Number(limitRaw)
      body.ownerLimits = { branchLimit: Number.isFinite(limitNum) ? Math.max(0, Math.floor(limitNum)) : undefined }
      if (body.ownerLimits.branchLimit == null) delete body.ownerLimits
    } else {
      delete body.ownerLimits
    }

    // When owner sets branch mappings, ensure branches belong to this owner.
    if (actorRole === ROLES.OWNER) {
      const branchIds = []
      if (body.primaryBranch && mongoose.Types.ObjectId.isValid(String(body.primaryBranch))) {
        branchIds.push(String(body.primaryBranch))
      }
      if (Array.isArray(body.branches)) {
        branchIds.push(...body.branches.map((v) => String(v)).filter((v) => mongoose.Types.ObjectId.isValid(v)))
      }
      const uniqBranchIds = Array.from(new Set(branchIds))
      if (uniqBranchIds.length) {
        const count = await Branch.countDocuments({ _id: { $in: uniqBranchIds }, owner: actorUserId })
        if (count !== uniqBranchIds.length) {
          return res.status(400).json({ success: false, message: 'One or more selected branches do not belong to this owner' })
        }
      }
    }

    if (body.password) {
      body.password = await bcrypt.hash(String(body.password), BCRYPT_SALT_ROUNDS)
    } else {
      delete body.password
    }


    const updated = await User.findByIdAndUpdate(
      id,
      body,
      { new: true, runValidators: true, allowRoleUpdate: true }
    )
    if (!updated) return res.status(404).json({ success: false, message: 'User not found' })
    return res.json({ success: true, message: 'User updated', data: sanitizeUserForViewer(updated.toJSON(), actorRole) })
  } catch (err) {
    if (err?.code === 11000) {
      const keys = Object.keys(err.keyPattern || {})
      const msg = keys.includes('email') ? 'Email already exists' : keys.includes('phone') ? 'Phone already exists' : 'Duplicate key'
      return res.status(409).json({ success: false, message: msg })
    }
    if (err?.name === 'ValidationError') {
      const details = Object.values(err.errors || {}).map(e => e?.message).join('; ')
      return res.status(400).json({ success: false, message: details || 'Validation failed' })
    }
    console.error('PUT /users/:id failed', err)
    return res.status(500).json({ success: false, message: 'Failed to update user' })
  }
})

// Admin force logout (invalidate tokens)
router.post('/:id/force-logout', auth, requireRole([ROLES.ADMIN]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid user id' })
    }
    const now = new Date()
    const updated = await User.findByIdAndUpdate(
      id,
      { $set: { tokenInvalidAfter: now } },
      { new: true }
    )
    if (!updated) return res.status(404).json({ success: false, message: 'User not found' })
    return res.json({ success: true, message: 'User will be logged out shortly.' })
  } catch (err) {
    console.error('POST /users/:id/force-logout failed', err)
    return res.status(500).json({ success: false, message: 'Failed to force logout user' })
  }
})

// Admin delete user
router.delete('/:id', auth, requireRole([ROLES.ADMIN]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid user id' })
    }
    const deleted = await User.findByIdAndDelete(id)
    if (!deleted) return res.status(404).json({ success: false, message: 'User not found' })
    return res.json({ success: true, message: 'User deleted' })
  } catch (err) {
    console.error('DELETE /users/:id failed', err)
    return res.status(500).json({ success: false, message: 'Failed to delete user' })
  }
})

// Owner self-service profile update (logo/webhook/name)
router.patch('/me', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const userId = String(req.body.userId || '')
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user id' })
    }
    const me = await User.findById(userId).select('role name ownerConfig ownerLimits')
    if (!me) return res.status(404).json({ success: false, message: 'User not found' })
    const role = normalizeRole(me.role)

    const body = req.body || {}
    const update = {}
    if (body.name) update.name = String(body.name).trim()

    const ownerConfig = {}
    if (Object.prototype.hasOwnProperty.call(body, 'orgName')) {
      const v = String(body.orgName || '').trim()
      ownerConfig.orgName = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameRegional')) {
      const v = String(body.orgNameRegional || '').trim()
      ownerConfig.orgNameRegional = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameFontFamily')) {
      const v = String(body.orgNameFontFamily || '').trim()
      ownerConfig.orgNameFontFamily = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameRegionalFontFamily')) {
      const v = String(body.orgNameRegionalFontFamily || '').trim()
      ownerConfig.orgNameRegionalFontFamily = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameFontWeight')) {
      const raw = body.orgNameFontWeight
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgNameFontWeight = Number.isFinite(num) ? Math.min(900, Math.max(100, Math.round(num / 100) * 100)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameRegionalFontWeight')) {
      const raw = body.orgNameRegionalFontWeight
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgNameRegionalFontWeight = Number.isFinite(num) ? Math.min(900, Math.max(100, Math.round(num / 100) * 100)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameFontSizePt')) {
      const raw = body.orgNameFontSizePt
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgNameFontSizePt = Number.isFinite(num) ? Math.min(64, Math.max(8, num)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameRegionalFontSizePt')) {
      const raw = body.orgNameRegionalFontSizePt
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgNameRegionalFontSizePt = Number.isFinite(num) ? Math.min(64, Math.max(8, num)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgNameFontColor')) {
      const v = String(body.orgNameFontColor || '').trim()
      ownerConfig.orgNameFontColor = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(v) ? v : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgAddress')) {
      const v = String(body.orgAddress || '').trim()
      ownerConfig.orgAddress = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'mechanics')) {
      const raw = body.mechanics
      const list = Array.isArray(raw) ? raw : []
      ownerConfig.mechanics = list
        .map((item) => {
          const name = String(item?.name || item || '').trim()
          const phone = String(item?.phone || item?.mobile || item?.contact || '').replace(/\D/g, '').slice(-10)
          return name ? { name, ...(phone ? { phone } : {}) } : null
        })
        .filter(Boolean)
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgAddressFontWeight')) {
      const raw = body.orgAddressFontWeight
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgAddressFontWeight = Number.isFinite(num) ? Math.min(900, Math.max(100, Math.round(num / 100) * 100)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgAddressFontSizePt')) {
      const raw = body.orgAddressFontSizePt
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.orgAddressFontSizePt = Number.isFinite(num) ? Math.min(64, Math.max(8, num)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'orgMobiles')) {
      const raw = body.orgMobiles
      let list = []
      if (Array.isArray(raw)) {
        list = raw
      } else if (typeof raw === 'string') {
        list = raw.split(/[,\n;/|]+/g)
      }
      ownerConfig.orgMobiles = list
        .map((x) => String(x || '').trim())
        .filter(Boolean)
    }
    if (Object.prototype.hasOwnProperty.call(body, 'logoUrl')) {
      const v = String(body.logoUrl || '').trim()
      ownerConfig.logoUrl = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'locationQrUrl')) {
      const v = String(body.locationQrUrl || '').trim()
      ownerConfig.locationQrUrl = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'webhookUrl') && canViewWebhookUrls(role)) {
      const v = String(body.webhookUrl || '').trim()
      ownerConfig.webhookUrl = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'processingFee')) {
      const raw = body.processingFee
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.processingFee = Number.isFinite(num) ? Math.max(0, num) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'flatInterestRate')) {
      const raw = body.flatInterestRate
      const num = raw === '' || raw === null || raw === undefined ? undefined : Number(raw)
      ownerConfig.flatInterestRate = Number.isFinite(num) ? Math.min(100, Math.max(0, num)) : undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaGreetingLine')) {
      const v = String(body.quotationWaGreetingLine || '').trim()
      ownerConfig.quotationWaGreetingLine = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaIntroLine')) {
      const v = String(body.quotationWaIntroLine || '').trim()
      ownerConfig.quotationWaIntroLine = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaContactLine')) {
      const v = String(body.quotationWaContactLine || '').trim()
      ownerConfig.quotationWaContactLine = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaLocationsTitle')) {
      const v = String(body.quotationWaLocationsTitle || '').trim()
      ownerConfig.quotationWaLocationsTitle = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaLocations')) {
      const raw = body.quotationWaLocations
      let list = []
      if (Array.isArray(raw)) {
        list = raw
      } else if (typeof raw === 'string') {
        list = raw.split(/\r?\n/g)
      }
      ownerConfig.quotationWaLocations = list
        .map((x) => String(x || '').trim())
        .filter(Boolean)
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaNoteLine')) {
      const v = String(body.quotationWaNoteLine || '').trim()
      ownerConfig.quotationWaNoteLine = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'quotationWaClosingLine')) {
      const v = String(body.quotationWaClosingLine || '').trim()
      ownerConfig.quotationWaClosingLine = v || undefined
    }
    if (Object.prototype.hasOwnProperty.call(body, 'freeFittingsOptions')) {
      const raw = body.freeFittingsOptions
      const list = Array.isArray(raw) ? raw : []
      ownerConfig.freeFittingsOptions = list
        .map((x) => String(x || '').trim())
        .filter(Boolean)
    }
    if (Object.prototype.hasOwnProperty.call(body, 'freeFittingsDefaultSelected')) {
      const raw = body.freeFittingsDefaultSelected
      const list = Array.isArray(raw) ? raw : []
      ownerConfig.freeFittingsDefaultSelected = list
        .map((x) => String(x || '').trim())
        .filter(Boolean)
    }
    if (Object.keys(ownerConfig).length) {
      update.ownerConfig = { ...(me.ownerConfig || {}), ...ownerConfig }
    }

    if (!Object.keys(update).length) {
      return res.json({ success: true, message: 'No changes', data: me.toJSON() })
    }

    const saved = await User.findByIdAndUpdate(me._id, update, { new: true, runValidators: true })
    return res.json({ success: true, message: 'Profile updated', data: sanitizeUserForViewer(saved.toJSON(), role) })
  } catch (err) {
    console.error('PATCH /users/me failed', err)
    return res.status(500).json({ success: false, message: 'Failed to update profile' })
  }
})

router.get('/get-valid-user', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const userDoc = await User.findById(req.body.userId)
      .select('-password')
      .populate('primaryBranch', 'name code owner')
      .populate({ path: 'branches', select: 'name code owner' })

    if (!userDoc) {
      return res.status(404).send({ success: false, message: 'User not found' })
    }

    // Soft-touch: bump lastLoginAt if missing or stale (10 min) so dashboards reflect activity
    try {
      const now = new Date()
      const last = userDoc.lastLoginAt ? new Date(userDoc.lastLoginAt) : null
      const stale = !last || (now.getTime() - last.getTime() > 10 * 60 * 1000)
      if (stale) {
        await User.updateOne({ _id: userDoc._id }, { $set: { lastLoginAt: now } })
        // Also reflect in the serialized object we return
        userDoc.lastLoginAt = now
      }
    } catch { /* non-blocking */ }

    // Ensure owners have owner=self for tenant filtering
    try {
      const roleLc = normalizeRole(userDoc?.role)
      if (roleLc === ROLES.OWNER && !userDoc.owner) {
        await User.updateOne({ _id: userDoc._id }, { $set: { owner: userDoc._id } })
        userDoc.owner = userDoc._id
      }
    } catch { /* non-blocking */ }

    const actorRole = normalizeRole(userDoc.role)
    const user = sanitizeUserForViewer(userDoc.toJSON(), actorRole)
    let branchName = null
    let branchCode = null
    if (userDoc?.primaryBranch && userDoc.primaryBranch.name) {
      branchName = userDoc.primaryBranch.name
      branchCode = userDoc.primaryBranch.code || null
    } else if (Array.isArray(userDoc?.branches) && userDoc.branches.length) {
      const b0 = userDoc.branches[0]
      branchName = b0?.name || null
      branchCode = b0?.code || null
    }

    if (!user.formDefaults) user.formDefaults = {}
    if (!user.formDefaults.staffName) user.formDefaults.staffName = user.name || ''
    if (branchName) user.formDefaults.branchName = branchName
    if (branchCode) user.formDefaults.branchCode = String(branchCode).toUpperCase()

    // For non-owner/admin users, surface ownerConfig from their owner.
    // Fallback to branch.owner when user.owner is missing (legacy staff rows).
    try {
      const roleLc = normalizeRole(userDoc?.role)
      if (roleLc !== ROLES.OWNER && roleLc !== ROLES.ADMIN) {
        let ownerId = userDoc?.owner ? String(userDoc.owner) : ''
        if (!ownerId) {
          const primaryOwner = userDoc?.primaryBranch?.owner
          if (primaryOwner) ownerId = String(primaryOwner?._id || primaryOwner)
        }
        if (!ownerId && Array.isArray(userDoc?.branches)) {
          const bOwner = userDoc.branches.find((b) => b?.owner)?.owner
          if (bOwner) ownerId = String(bOwner?._id || bOwner)
        }
        if (!ownerId && userDoc?.primaryBranch?._id) {
          const br = await Branch.findById(userDoc.primaryBranch._id).select('owner')
          if (br?.owner) ownerId = String(br.owner)
        }
        if (ownerId && !userDoc?.owner) {
          await User.updateOne({ _id: userDoc._id }, { $set: { owner: ownerId } })
        }
        if (!ownerId || !mongoose.Types.ObjectId.isValid(ownerId)) {
          ownerId = ''
        }
        const ownerDoc = ownerId ? await User.findById(ownerId).select('ownerConfig name') : null
        if (ownerDoc?.ownerConfig) {
          user.ownerConfig = sanitizeOwnerConfigForRole(ownerDoc.ownerConfig, roleLc)
        }
        if (ownerDoc?._id) {
          user.owner = ownerDoc._id
        }
      }
    } catch { /* non-blocking */ }

    return res.send({
      success: true,
      message: 'You are authorized to go to the protected route!',
      data: user,
    })
  } catch (err) {
    console.error('GET /users/get-valid-user failed', err)
    return res.status(500).send({ success: false, message: 'Could not fetch current user' })
  }
})

module.exports = router;
