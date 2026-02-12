const express = require('express')
const router = express.Router()
const Announcement = require('../models/announcementModel')
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const { ROLES } = require('../constants/roles')

// Public list for client tabs (no auth): active + not expired
router.get('/public', async (req, res) => {
  try {
    const now = new Date()
    const q = { active: true, $or: [{ expiresAt: { $exists: false } }, { expiresAt: null }, { expiresAt: { $gt: now } }] }
    const limit = Math.max(parseInt(req.query.limit || '50', 10) || 50, 1)
    const items = await Announcement.find(q).sort({ createdAt: -1 }).limit(limit).select('title body type createdAt expiresAt')
    return res.json({ success: true, data: items })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch announcements' })
  }
})

// Admin/owner list (manage)
router.get('/', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const items = await Announcement.find({}).sort({ createdAt: -1 })
    return res.json({ success: true, data: items })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch announcements' })
  }
})

// Create announcement
router.post('/', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { title, body, type, expiresInDays } = req.body || {}
    const tp = String(type || 'info').toLowerCase()
    if (!['info', 'warning', 'alert'].includes(tp)) {
      return res.status(400).json({ success: false, message: 'type must be info|warning|alert' })
    }
    if (!title || !body) return res.status(400).json({ success: false, message: 'title and body are required' })
    let exp = null
    const days = parseInt(expiresInDays || '0', 10)
    if (days && Number.isFinite(days) && days > 0) {
      exp = new Date(Date.now() + days * 24 * 60 * 60 * 1000)
    }
    const created = await Announcement.create({ title: String(title).trim(), body: String(body).trim(), type: tp, createdBy: req.userId, expiresAt: exp })
    return res.status(201).json({ success: true, data: created })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to create announcement' })
  }
})

// Acknowledge an announcement (optional)
router.post('/:id/ack', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!/^[0-9a-fA-F]{24}$/.test(id)) return res.status(400).json({ success: false, message: 'Invalid id' })
    await Announcement.updateOne({ _id: id }, { $addToSet: { acknowledgedBy: req.userId } })
    return res.json({ success: true })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to acknowledge' })
  }
})

// Update announcement
router.put('/:id', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!/^[0-9a-fA-F]{24}$/.test(id)) return res.status(400).json({ success: false, message: 'Invalid id' })
    const body = { ...req.body }
    if (body.type && !['info','warning','alert'].includes(String(body.type).toLowerCase())) delete body.type
    const updated = await Announcement.findByIdAndUpdate(id, body, { new: true })
    if (!updated) return res.status(404).json({ success: false, message: 'Not found' })
    return res.json({ success: true, data: updated })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to update announcement' })
  }
})

// Delete/Disable announcement
router.delete('/:id', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const id = String(req.params.id || '')
    if (!/^[0-9a-fA-F]{24}$/.test(id)) return res.status(400).json({ success: false, message: 'Invalid id' })
    await Announcement.findByIdAndUpdate(id, { active: false })
    return res.json({ success: true })
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to delete announcement' })
  }
})

module.exports = router
