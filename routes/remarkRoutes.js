const express = require('express')
const router = express.Router()
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const { ROLES } = require('../constants/roles')
const Remark = require('../models/remarkModel')
const User = require('../models/userModel')

// Upsert a remark for a record
router.post('/upsert', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { kind, refId, level, text } = req.body || {}
    const k = String(kind || '').toLowerCase()
    if (!['quotation','jobcard','booking'].includes(k)) return res.status(400).json({ success: false, message: 'kind must be quotation|jobcard|booking' })
    const id = String(refId || '').trim()
    if (!id) return res.status(400).json({ success: false, message: 'refId is required' })
    const lv = String(level || '').toLowerCase()
    if (!['ok','warning','alert'].includes(lv)) return res.status(400).json({ success: false, message: 'level must be ok|warning|alert' })

    const actor = await User.findById(req.userId).select('name')
    const update = {
      level: lv,
      text: String(text || '').trim().slice(0, 240),
      updatedBy: req.userId,
      updatedByName: actor?.name || 'System',
    }
    const doc = await Remark.findOneAndUpdate({ kind: k, refId: id }, { $set: update }, { upsert: true, new: true, setDefaultsOnInsert: true })
    return res.json({ success: true, data: doc })
  } catch (err) {
    console.error('POST /remarks/upsert failed', err)
    return res.status(500).json({ success: false, message: 'Failed to save remark' })
  }
})

// Bulk read remarks for a list of refIds
router.get('/bulk', auth, async (req, res) => {
  try {
    const kind = String(req.query.kind || '').toLowerCase()
    const ids = String(req.query.ids || '').split(',').map(s => s.trim()).filter(Boolean)
    if (!['quotation','jobcard','booking'].includes(kind)) return res.status(400).json({ success: false, message: 'Invalid kind' })
    if (!ids.length) return res.json({ success: true, items: [] })
    const items = await Remark.find({ kind, refId: { $in: ids } }).select('kind refId level text updatedAt updatedByName')
    return res.json({ success: true, items })
  } catch (err) {
    console.error('GET /remarks/bulk failed', err)
    return res.status(500).json({ success: false, message: 'Failed to load remarks' })
  }
})

module.exports = router
