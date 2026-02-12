const express = require('express')
const axios = require('axios')
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const { ROLES } = require('../constants/roles')

const router = express.Router()

// Point this to your deployed Apps Script Web App URL
const DEFAULT_GAS_URL =
  process.env.UNIFIED_GAS_URL
    ? `${process.env.UNIFIED_GAS_URL}${process.env.UNIFIED_GAS_URL.includes('?') ? '&' : '?'}module=stocks`
    : (process.env.STOCKS_GAS_URL || 'https://script.google.com/macros/s/AKfycbz_DoNoD0XTx3RNMOSZfypbMqWVN4yTy3ct96aE4LhJ9yb_YvKr0GRbO_GA3Fgkwptb/exec?module=stocks')

// GET proxy (list/current/pending)
router.get('/', auth, requireRole([ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const params = { ...req.query }
    if (!params.action) params.action = 'list'
    const gasUrl = params.gasUrl || DEFAULT_GAS_URL
    delete params.gasUrl
    const { data } = await axios.get(gasUrl, { params })
    return res.json(data)
  } catch (err) {
    const status = err?.response?.status || 500
    return res.status(status).json({ ok: false, message: 'Failed to reach GAS (GET)', detail: err?.message || String(err) })
  }
})

// POST proxy (create/update/delete/admit/reject)
router.post('/', auth, requireRole([ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const payload = req.body || {}
    if (!payload.action) payload.action = 'create'
    const gasUrl = payload.gasUrl || DEFAULT_GAS_URL
    delete payload.gasUrl
    const { data } = await axios.post(gasUrl, payload)
    return res.json(data)
  } catch (err) {
    const status = err?.response?.status || 500
    return res.status(status).json({ ok: false, message: 'Failed to reach GAS (POST)', detail: err?.message || String(err) })
  }
})

module.exports = router
