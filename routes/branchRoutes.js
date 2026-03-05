const express = require('express')
const router = express.Router()
const Branch = require('../models/branchModel')
const User = require('../models/userModel')
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const { ROLES, normalizeRole } = require('../constants/roles')

function resolveTenantOwnerId(userDoc) {
  const role = normalizeRole(userDoc?.role)
  if (role === ROLES.ADMIN) return null
  if (role === ROLES.OWNER) return String(userDoc?._id || '')
  return userDoc?.owner ? String(userDoc.owner) : null
}

// List branches with basic filters (auth)
router.get('/', auth, requireRole([ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { q, city, status, type, limit = 100, page = 1 } = req.query
    const filter = {}
    const me = await User.findById(req.userId).select('role owner')
    const ownerId = resolveTenantOwnerId(me)
    if (ownerId) filter.owner = ownerId
    if (city) filter['address.city'] = new RegExp(String(city), 'i')
    if (status) filter.status = status
    if (type) filter.type = type
    if (q) {
      const re = new RegExp(String(q), 'i')
      filter.$or = [
        { code: re },
        { name: re },
        { phone: re },
        { email: re },
        { 'address.city': re },
        { 'address.area': re },
      ]
    }

    const skip = (Math.max(parseInt(page, 10), 1) - 1) * Math.max(parseInt(limit, 10), 1)
    const [items, total] = await Promise.all([
      Branch.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)),
      Branch.countDocuments(filter),
    ])
    return res.send({ success: true, data: { items, total } })
  } catch (err) {
    console.error('GET /branches failed', err)
    return res.status(500).send({ success: false, message: 'Failed to fetch branches' })
  }
})

// Public list (no auth) — same filters; read-only access
router.get('/public', async (req, res) => {
  try {
    const { q, city, status, type, limit = 100, page = 1, ownerId } = req.query
    const filter = {}
    if (!ownerId || !/^[0-9a-fA-F]{24}$/.test(String(ownerId))) {
      return res.send({ success: true, data: { items: [], total: 0 }, public: true })
    }
    filter.owner = ownerId
    if (city) filter['address.city'] = new RegExp(String(city), 'i')
    if (status) filter.status = status
    if (type) filter.type = type
    if (q) {
      const re = new RegExp(String(q), 'i')
      filter.$or = [
        { code: re },
        { name: re },
        { phone: re },
        { email: re },
        { 'address.city': re },
        { 'address.area': re },
      ]
    }

    const skip = (Math.max(parseInt(page, 10), 1) - 1) * Math.max(parseInt(limit, 10), 1)
    const [items, total] = await Promise.all([
      Branch.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)),
      Branch.countDocuments(filter),
    ])
    return res.send({ success: true, data: { items, total } })
  } catch (err) {
    console.error('GET /branches/public failed', err)
    return res.status(500).send({ success: false, message: 'Failed to fetch branches' })
  }
})

// Get one
router.get('/:id', auth, requireRole([ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const item = await Branch.findById(req.params.id)
    if (!item) return res.status(404).send({ success: false, message: 'Branch not found' })
    const me = await User.findById(req.userId).select('role owner')
    const ownerId = resolveTenantOwnerId(me)
    if (ownerId && String(item.owner || '') !== ownerId) {
      return res.status(403).send({ success: false, message: 'Forbidden' })
    }
    return res.send({ success: true, data: item })
  } catch (err) {
    console.error('GET /branches/:id failed', err)
    return res.status(500).send({ success: false, message: 'Failed to fetch branch' })
  }
})

// Create
router.post('/', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const body = req.body || {}
    const me = await User.findById(req.userId).select('role ownerLimits')
    const role = String(req.auth?.role || '')
    if (role === ROLES.OWNER) {
      const limit = Number.isFinite(me?.ownerLimits?.branchLimit) ? Math.max(0, Math.floor(me.ownerLimits.branchLimit)) : 1
      const count = await Branch.countDocuments({ owner: req.userId })
      if (count >= limit) {
        return res.status(403).send({ success: false, message: `Branch limit reached (${limit}). Contact admin to increase.` })
      }
      body.owner = req.userId
      if (count === 0) body.isDefault = true
    } else if (role === ROLES.ADMIN) {
      if (!body.owner || !/^[0-9a-fA-F]{24}$/.test(String(body.owner))) {
        return res.status(400).send({ success: false, message: 'owner is required' })
      }
    }
    // Basic normalization
    if (body.code) body.code = String(body.code).trim().toUpperCase()
    if (body.name) body.name = String(body.name).trim()
    if (body.email) body.email = String(body.email).trim().toLowerCase()

    // Geo coordinates: accept lat/lng in body and map to GeoJSON
    const lat = body.lat ?? body.latitude
    const lng = body.lng ?? body.longitude
    if (!body.location && lat != null && lng != null) {
      body.location = { type: 'Point', coordinates: [Number(lng), Number(lat)] }
    }

    // People associations: accept manager (single) and staff/boys/mechanics arrays of ObjectIds
    const isObjId = (v) => typeof v === 'string' && /^[0-9a-fA-F]{24}$/.test(v)
    if (body.manager && !isObjId(String(body.manager))) delete body.manager
    if (Array.isArray(body.staff)) {
      body.staff = Array.from(new Set(body.staff.map(String))).filter(isObjId)
    }
    if (Array.isArray(body.boys)) {
      body.boys = Array.from(new Set(body.boys.map(String))).filter(isObjId)
    }
    if (Array.isArray(body.mechanics)) {
      body.mechanics = Array.from(new Set(body.mechanics.map(String))).filter(isObjId)
    }

    const created = await Branch.create(body)
    if (body.isDefault && body.owner) {
      await Branch.updateMany({ owner: body.owner, _id: { $ne: created._id } }, { $set: { isDefault: false } })
    }
    return res.status(201).send({ success: true, message: 'Branch created', data: created })
  } catch (err) {
    const dupCode = err?.code === 11000 || err?.name === 'MongoServerError' && String(err?.message || '').includes('E11000')
    if (dupCode) {
      return res.status(409).send({ success: false, message: 'Branch code already exists' })
    }
    if (err?.name === 'ValidationError') {
      const details = Object.values(err.errors || {}).map(e => e?.message).join('; ')
      return res.status(400).send({ success: false, message: details || 'Validation failed' })
    }
    if (err?.name === 'CastError') {
      return res.status(400).send({ success: false, message: `Invalid ${err?.path || 'value'}: ${err?.value}` })
    }
    console.error('POST /branches failed', err)
    const details = String(err?.message || '').trim()
    return res.status(500).send({
      success: false,
      message: details ? `Failed to create branch: ${details}` : 'Failed to create branch',
    })
  }
})

// Update
router.put('/:id', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const body = { ...req.body }
    const role = String(req.auth?.role || '')
    if (role === ROLES.OWNER) {
      const existing = await Branch.findById(req.params.id).select('owner')
      if (!existing) return res.status(404).send({ success: false, message: 'Branch not found' })
      if (String(existing.owner || '') !== String(req.userId)) {
        return res.status(403).send({ success: false, message: 'Forbidden: cannot edit this branch' })
      }
      body.owner = req.userId
    }
    delete body.userId // do not overwrite
    if (body.code) body.code = String(body.code).trim().toUpperCase()
    if (body.name) body.name = String(body.name).trim()
    if (body.email) body.email = String(body.email).trim().toLowerCase()
    const lat = body.lat ?? body.latitude
    const lng = body.lng ?? body.longitude
    if (lat != null && lng != null) {
      body.location = { type: 'Point', coordinates: [Number(lng), Number(lat)] }
      delete body.lat
      delete body.lng
      delete body.latitude
      delete body.longitude
    }

    // People associations normalization
    const isObjId = (v) => typeof v === 'string' && /^[0-9a-fA-F]{24}$/.test(v)
    if (Object.prototype.hasOwnProperty.call(body, 'manager')) {
      if (!body.manager || !isObjId(String(body.manager))) delete body.manager
    }
    if (Object.prototype.hasOwnProperty.call(body, 'staff')) {
      if (Array.isArray(body.staff)) {
        body.staff = Array.from(new Set(body.staff.map(String))).filter(isObjId)
      } else if (body.staff == null) {
        // allow clearing via null
        body.staff = []
      } else {
        delete body.staff
      }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'boys')) {
      if (Array.isArray(body.boys)) {
        body.boys = Array.from(new Set(body.boys.map(String))).filter(isObjId)
      } else if (body.boys == null) {
        body.boys = []
      } else {
        delete body.boys
      }
    }
    if (Object.prototype.hasOwnProperty.call(body, 'mechanics')) {
      if (Array.isArray(body.mechanics)) {
        body.mechanics = Array.from(new Set(body.mechanics.map(String))).filter(isObjId)
      } else if (body.mechanics == null) {
        body.mechanics = []
      } else {
        delete body.mechanics
      }
    }

    const updated = await Branch.findByIdAndUpdate(req.params.id, body, { new: true })
    if (!updated) return res.status(404).send({ success: false, message: 'Branch not found' })
    if (body.isDefault && updated.owner) {
      await Branch.updateMany({ owner: updated.owner, _id: { $ne: updated._id } }, { $set: { isDefault: false } })
    }
    return res.send({ success: true, message: 'Branch updated', data: updated })
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).send({ success: false, message: 'Branch code already exists' })
    }
    if (err?.name === 'ValidationError') {
      const details = Object.values(err.errors || {}).map(e => e?.message).join('; ')
      return res.status(400).send({ success: false, message: details || 'Validation failed' })
    }
    if (err?.name === 'CastError') {
      return res.status(400).send({ success: false, message: `Invalid ${err?.path || 'value'}: ${err?.value}` })
    }
    console.error('PUT /branches/:id failed', err)
    return res.status(500).send({ success: false, message: 'Failed to update branch' })
  }
})

// Delete
router.delete('/:id', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const role = String(req.auth?.role || '')
    if (role === ROLES.OWNER) {
      const existing = await Branch.findById(req.params.id).select('owner')
      if (!existing) return res.status(404).send({ success: false, message: 'Branch not found' })
      if (String(existing.owner || '') !== String(req.userId)) {
        return res.status(403).send({ success: false, message: 'Forbidden: cannot delete this branch' })
      }
    }
    const deleted = await Branch.findByIdAndDelete(req.params.id)
    if (!deleted) return res.status(404).send({ success: false, message: 'Branch not found' })
    if (deleted?.owner && deleted?.isDefault) {
      const next = await Branch.findOne({ owner: deleted.owner }).sort({ createdAt: -1 })
      if (next) await Branch.updateOne({ _id: next._id }, { $set: { isDefault: true } })
    }
    return res.send({ success: true, message: 'Branch deleted' })
  } catch (err) {
    console.error('DELETE /branches/:id failed', err)
    return res.status(500).send({ success: false, message: 'Failed to delete branch' })
  }
})

module.exports = router
