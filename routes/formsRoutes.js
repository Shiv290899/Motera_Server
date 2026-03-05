const express = require('express')
const axios = require('axios')
const http = require('http')
const https = require('https')
const auth = require('../middlewares/auth')
const requireRole = require('../middlewares/requireRole')
const { ROLES } = require('../constants/roles')

const router = express.Router()
const Branch = require('../models/branchModel')

const GOOGLE_FORM_DEFAULTS = {
  fvv: '1',
  draftResponse: '[]',
  pageHistory: '0',
}

const WEBHOOK_UPSTREAM_TIMEOUT_MS = Number(process.env.WEBHOOK_UPSTREAM_TIMEOUT_MS || 15000)
const webhookHttp = axios.create({
  timeout: WEBHOOK_UPSTREAM_TIMEOUT_MS,
  httpAgent: new http.Agent({ keepAlive: true, maxSockets: 100 }),
  httpsAgent: new https.Agent({ keepAlive: true, maxSockets: 100 }),
})

function normalizeString(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value.trim()
  return String(value).trim()
}

function normalizeMobile10(raw) {
  const d = String(raw || '').replace(/\D/g, '').slice(-10)
  return d.length === 10 ? d : ''
}

function shortId6() {
  try {
    const { ulid } = require('ulid')
    const id = ulid() // Crockford base32, 26 chars
    return id.slice(-6)
  } catch (e) {
    const crypto = require('crypto')
    return crypto.randomBytes(4).toString('hex').slice(-6).toUpperCase()
  }
}

// No DB reservation: generate a human-friendly serial per request
function buildSerial(kind, branchCode) {
  const bc = String(branchCode || '').trim().toUpperCase()
  const prefix = kind === 'jobcard' ? 'JC' : 'Q'
  return `${prefix}-${bc}-${shortId6()}`
}

function ensureEntries(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return {}
  }
  return obj
}

function buildFormUrl(formId) {
  return `https://docs.google.com/forms/d/e/${formId}/formResponse`
}

function safeErrorMessage(error) {
  return error?.message || 'Unknown error'
}

async function submitToGoogleForm(formId, entriesInput) {
  const entries = { ...GOOGLE_FORM_DEFAULTS, ...ensureEntries(entriesInput) }
  const params = new URLSearchParams()
  Object.entries(entries).forEach(([key, value]) => {
    if (value === undefined || value === null) return
    params.append(key, value === '' ? '' : String(value))
  })

  await axios.post(buildFormUrl(formId), params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
}

// --- CSV helpers (no DB persistence) ---
const parseCsv = (text) => {
  const rows = []
  let row = [], col = '', inQuotes = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1]
    if (c === '"' && !inQuotes) { inQuotes = true; continue }
    if (c === '"' && inQuotes) { if (n === '"') { col += '"'; i++; continue } inQuotes = false; continue }
    if (c === ',' && !inQuotes) { row.push(col); col = ''; continue }
    if ((c === '\n' || c === '\r') && !inQuotes) { if (col !== '' || row.length) { row.push(col); rows.push(row); row = []; col = '' } if (c === '\r' && n === '\n') i++; continue }
    col += c
  }
  if (col !== '' || row.length) { row.push(col); rows.push(row) }
  return rows
}

const findSerialIdx = (headers = [], kind = 'quotation') => {
  const rxQ = /^(quotation\s*no\.?|quotation\s*number|serial\s*no\.?|serial|quote\s*id)$/i
  const rxJ = /^(jc\s*no\.?|jc\s*number|job\s*card\s*no\.?|job\s*card\s*number|serial(?:\s*no\.?)?)$/i
  const rx = kind === 'jobcard' ? rxJ : rxQ
  let idx = headers.findIndex((h) => rx.test(String(h || '').trim()))
  if (idx >= 0) return idx
  idx = headers.findIndex((h) => /serial/i.test(String(h || '')))
  return idx >= 0 ? idx : -1
}

const parseIntStrict = (s) => {
  const t = String(s || '').trim()
  return /^\d+$/.test(t) ? parseInt(t, 10) : null
}

async function fetchCsv(url) {
  const res = await axios.get(url, { responseType: 'text', validateStatus: () => true })
  if (String(res.status).startsWith('2')) return res.data
  throw new Error(`CSV fetch failed with status ${res.status}`)
}

async function nextSerialFromCsv(url, kind = 'quotation') {
  const csv = await fetchCsv(url)
  const rows = parseCsv(csv)
  if (!rows.length) return '1'
  const header = rows[0] || []
  const idx = findSerialIdx(header, kind)
  if (idx < 0) return '1'
  for (let i = rows.length - 1; i >= 1; i--) {
    const n = parseIntStrict(rows[i][idx])
    if (n !== null && Number.isFinite(n)) return String(n + 1)
  }
  let max = 0
  for (let i = 1; i < rows.length; i++) {
    const n = parseIntStrict(rows[i][idx])
    if (n !== null && n > max) max = n
  }
  return String(max + 1 || 1)
}

async function serialExistsInCsv(url, serial, kind = 'quotation') {
  if (!serial) return false
  const csv = await fetchCsv(url)
  const rows = parseCsv(csv)
  if (!rows.length) return false
  const header = rows[0] || []
  const idx = findSerialIdx(header, kind)
  if (idx < 0) return false
  return rows.slice(1).some(r => String(r[idx]).trim() === String(serial).trim())
}

router.get('/quotation/next-serial', async (req, res) => {
  try {
    const csvUrl = req.query.csv || process.env.QUOTATION_RESPONSES_CSV_URL
    if (!csvUrl) return res.json({ success: true, nextSerial: '1', source: 'fallback' })
    const nextSerial = await nextSerialFromCsv(csvUrl, 'quotation')
    return res.json({ success: true, nextSerial, source: 'csv' })
  } catch (error) {
    console.error('Failed to fetch next quotation serial:', error)
    return res.status(500).json({ success: false, message: 'Unable to fetch next serial number.' })
  }
})

// Reserve a server-issued quotation serial for a given mobile (idempotent per mobile)
router.post('/quotation/serial/reserve', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const m10 = normalizeMobile10(req.body?.mobile)
    let bc = String(req.body?.branchCode || '').trim().toUpperCase()
    const branchId = req.body?.branchId
    if (!bc && branchId) {
      try {
        const br = await Branch.findById(branchId).lean()
        if (br?.code) bc = String(br.code).toUpperCase()
      } catch {}
    }
    if (!m10) return res.status(400).json({ success: false, message: 'Valid 10-digit mobile is required' })
    if (!bc) return res.status(400).json({ success: false, message: 'branchCode is required' })
    const serial = buildSerial('quotation', bc)
    return res.json({ success: true, serial })
  } catch (error) {
    console.error('Failed to reserve quotation serial:', error)
    return res.status(500).json({ success: false, message: 'Unable to reserve serial' })
  }
})

router.post('/quotation', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { formId, entries: rawEntries, payload, serialNo, serialEntryId, responsesCsvUrl } = req.body || {}
    if (!formId) {
      return res.status(400).json({ success: false, message: 'formId is required.' })
    }
    const entries = ensureEntries(rawEntries)
    let serial = normalizeString(serialNo)
    if (!serial && serialEntryId) serial = normalizeString(entries[serialEntryId])
    if (!serial) serial = normalizeString(entries.serial || entries.serialNo)
    if (!serial) {
      return res.status(400).json({ success: false, message: 'serialNo is required.' })
    }

    const csvUrl = responsesCsvUrl || process.env.QUOTATION_RESPONSES_CSV_URL
    if (csvUrl) {
      try {
        if (await serialExistsInCsv(csvUrl, serial, 'quotation')) {
          return res.json({ success: true, duplicate: true, message: 'Quotation already exists in sheet.' })
        }
      } catch (e) { /* continue if CSV not reachable */ }
    }

    await submitToGoogleForm(formId, entries)
    return res.json({ success: true, submittedToGoogle: true, message: 'Quotation saved to Google Sheet.' })
  } catch (error) {
    console.error('Failed to save quotation:', error.response?.data || error)
    return res.status(500).json({ success: false, message: 'Failed to save quotation.', detail: error.message })
  }
})

router.get('/jobcard/next-serial', async (req, res) => {
  try {
    const csvUrl = req.query.csv || process.env.JOBCARD_RESPONSES_CSV_URL || process.env.JOBCARD_SHEET_CSV_URL
    if (!csvUrl) return res.json({ success: true, nextSerial: '1', source: 'fallback' })
    const nextSerial = await nextSerialFromCsv(csvUrl, 'jobcard')
    return res.json({ success: true, nextSerial, source: 'csv' })
  } catch (error) {
    console.error('Failed to fetch next job card serial:', error)
    return res.status(500).json({ success: false, message: 'Unable to fetch next job card number.' })
  }
})

// Reserve a server-issued jobcard serial for a given mobile (idempotent per mobile)
router.post('/jobcard/serial/reserve', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const m10 = normalizeMobile10(req.body?.mobile)
    let bc = String(req.body?.branchCode || '').trim().toUpperCase()
    const branchId = req.body?.branchId
    if (!bc && branchId) {
      try {
        const br = await Branch.findById(branchId).lean()
        if (br?.code) bc = String(br.code).toUpperCase()
      } catch {}
    }
    if (!m10) return res.status(400).json({ success: false, message: 'Valid 10-digit mobile is required' })
    if (!bc) return res.status(400).json({ success: false, message: 'branchCode is required' })
    const csvUrl = process.env.JOBCARD_RESPONSES_CSV_URL || process.env.JOBCARD_SHEET_CSV_URL
    let serial = buildSerial('jobcard', bc)
    if (csvUrl) {
      for (let i = 0; i < 3; i++) {
        try {
          // Re-roll if the serial already exists in the sheet.
          if (!(await serialExistsInCsv(csvUrl, serial, 'jobcard'))) break
          serial = buildSerial('jobcard', bc)
        } catch {
          break
        }
      }
    }
    return res.json({ success: true, serial })
  } catch (error) {
    console.error('Failed to reserve jobcard serial:', error)
    return res.status(500).json({ success: false, message: 'Unable to reserve serial' })
  }
})

router.post('/jobcard', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { formId, entries: rawEntries, metadata, jcNo, jcEntryId, responsesCsvUrl } = req.body || {}
    if (!formId) {
      return res.status(400).json({ success: false, message: 'formId is required.' })
    }
    const entries = ensureEntries(rawEntries)
    let jobCardNo = normalizeString(jcNo)
    if (!jobCardNo && jcEntryId) jobCardNo = normalizeString(entries[jcEntryId])
    if (!jobCardNo) jobCardNo = normalizeString(entries.jcNo)
    if (!jobCardNo) {
      return res.status(400).json({ success: false, message: 'jcNo is required.' })
    }

    const csvUrl = responsesCsvUrl || process.env.JOBCARD_RESPONSES_CSV_URL || process.env.JOBCARD_SHEET_CSV_URL
    if (csvUrl) {
      try {
        if (await serialExistsInCsv(csvUrl, jobCardNo, 'jobcard')) {
          return res.json({ success: true, duplicate: true, message: 'Job Card already exists in sheet.' })
        }
      } catch (e) { /* continue if CSV not reachable */ }
    }

    await submitToGoogleForm(formId, entries)
    return res.json({ success: true, submittedToGoogle: true, message: 'Job Card saved to Google Sheet.' })
  } catch (error) {
    console.error('Failed to save job card:', error.response?.data || error)
    return res.status(500).json({ success: false, message: 'Failed to save job card.', detail: error.message })
  }
})

// Booking: simple pass-through to Google Form. No serial checks.
router.post('/booking', auth, requireRole([ROLES.USER, ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { formId, entries: rawEntries } = req.body || {}
    if (!formId) {
      return res.status(400).json({ success: false, message: 'formId is required.' })
    }
    const entries = ensureEntries(rawEntries)
    await submitToGoogleForm(formId, entries)
    return res.json({ success: true, submittedToGoogle: true, message: 'Booking saved to Google Sheet.' })
  } catch (error) {
    console.error('Failed to save booking:', error.response?.data || error)
    return res.status(500).json({ success: false, message: 'Failed to save booking.', detail: error.message })
  }
})

// --- Simple in-memory idempotency for webhook saves ---
// Prevent duplicate forwards when users click Print/Save multiple times.
// Keyed by serial (quotation/jobcard). TTL keeps memory bounded across time.
const IDEMPOTENCY_TTL_MS = 10 * 60 * 1000; // 10 minutes
const recentSerials = new Map(); // key -> timestamp

// Lightweight cache for GET webhook proxy responses to reduce perceived latency
// Especially useful for staff/account views that poll frequently.
const WEBHOOK_CACHE = new Map(); // key -> { t:number, data:any }
const WEBHOOK_INFLIGHT_GET = new Map(); // key -> Promise<any>
const CACHE_TTL_MS = 8 * 1000; // 8s TTL (short, safe for near‑real‑time)
function stableStringify(value) {
  if (value === null || value === undefined) return ''
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value)
}
function cacheKey(webhookUrl, payload){
  try { return `${webhookUrl}|${stableStringify(payload || {})}` } catch { return String(webhookUrl||'') }
}
function cacheGet(webhookUrl, payload){
  const k = cacheKey(webhookUrl, payload)
  const e = WEBHOOK_CACHE.get(k)
  if (e && (Date.now() - e.t) < CACHE_TTL_MS) return e.data
  if (e) WEBHOOK_CACHE.delete(k)
  return null
}
function cachePut(webhookUrl, payload, data){
  const k = cacheKey(webhookUrl, payload)
  WEBHOOK_CACHE.set(k, { t: Date.now(), data })
  if (WEBHOOK_CACHE.size > 500) {
    const arr = Array.from(WEBHOOK_CACHE.entries()).sort((a,b)=>a[1].t-b[1].t).slice(0,50)
    for (const [kk] of arr) WEBHOOK_CACHE.delete(kk)
  }
}
async function getOrJoinInFlightGet(webhookUrl, payload, fetcher){
  const key = cacheKey(webhookUrl, payload)
  const existing = WEBHOOK_INFLIGHT_GET.get(key)
  if (existing) return existing
  const p = (async () => {
    const data = await fetcher()
    cachePut(webhookUrl, payload, data)
    return data
  })().finally(() => {
    WEBHOOK_INFLIGHT_GET.delete(key)
  })
  WEBHOOK_INFLIGHT_GET.set(key, p)
  return p
}

function extractRowsFromWebhookData(data) {
  if (!data) return []
  if (Array.isArray(data)) return data
  if (Array.isArray(data.rows)) return data.rows
  if (Array.isArray(data.data)) return data.data
  return []
}

function extractTotalFromWebhookData(data) {
  if (!data || typeof data !== 'object') return null
  const keys = ['total', 'count', 'totalRows', 'totalCount']
  for (const key of keys) {
    const n = Number(data[key])
    if (Number.isFinite(n) && n >= 0) return n
  }
  if (data.meta && typeof data.meta === 'object') {
    for (const key of keys) {
      const n = Number(data.meta[key])
      if (Number.isFinite(n) && n >= 0) return n
    }
  }
  return null
}

function mergeRowsIntoWebhookData(data, rows) {
  const out = (data && typeof data === 'object' && !Array.isArray(data))
    ? { ...data }
    : {}
  if (Array.isArray(data)) return rows
  if (Array.isArray(out.rows)) out.rows = rows
  else if (Array.isArray(out.data)) out.data = rows
  else out.rows = rows
  const total = rows.length
  if ('total' in out || out.total === undefined) out.total = total
  if ('count' in out) out.count = total
  if ('totalRows' in out) out.totalRows = total
  if ('totalCount' in out) out.totalCount = total
  if ('page' in out) out.page = 1
  if ('pageNo' in out) out.pageNo = 1
  return out
}

function extractSerial(obj) {
  try {
    if (!obj) return null;
    // common shapes from client: { action:'save', data:{ serialNo, formValues, payload } }
    if (obj.data?.serialNo) return String(obj.data.serialNo);
    if (obj.data?.jcNo) return String(obj.data.jcNo);
    if (obj.serialNo) return String(obj.serialNo);
    if (obj.jcNo) return String(obj.jcNo);
    if (obj.formValues?.serialNo) return String(obj.formValues.serialNo);
    if (obj.formValues?.jcNo) return String(obj.formValues.jcNo);
    if (obj.payload?.formValues?.serialNo) return String(obj.payload.formValues.serialNo);
    if (obj.payload?.formValues?.jcNo) return String(obj.payload.formValues.jcNo);
  } catch {}
  return null;
}

function normalizeForDedupe(value) {
  if (Array.isArray(value)) return value.map(normalizeForDedupe)
  if (!value || typeof value !== 'object') return value
  const out = {}
  const keys = Object.keys(value).sort()
  for (const k of keys) {
    // Ignore volatile clock fields so immediate retries stay suppressible.
    if (
      k === 'updatedAt' ||
      k === 'savedAt' ||
      k === 'timestamp' ||
      k === 'ts' ||
      k === '_ts'
    ) continue
    out[k] = normalizeForDedupe(value[k])
  }
  return out
}

function buildDedupeKey(payload) {
  const serial = extractSerial(payload)
  if (!serial) return null
  try {
    const norm = normalizeForDedupe(payload || {})
    return `${String(serial).trim()}::${JSON.stringify(norm)}`
  } catch {
    return String(serial).trim()
  }
}

function isDuplicateSerial(key) {
  if (!key) return false;
  const ts = recentSerials.get(key);
  const now = Date.now();
  if (ts && now - ts < IDEMPOTENCY_TTL_MS) return true;
  return false;
}

function markSerial(key) {
  if (!key) return;
  recentSerials.set(key, Date.now());
  // prune occasionally
  if (recentSerials.size > 2000) {
    const cutoff = Date.now() - IDEMPOTENCY_TTL_MS;
    for (const [k, v] of recentSerials.entries()) { if (v < cutoff) recentSerials.delete(k); }
  }
}

// Booking via generic webhook (e.g., Google Apps Script Web App)
router.post('/booking/webhook', auth, requireRole([ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { webhookUrl, payload, headers, method } = req.body || {}
    if (!webhookUrl) {
      return res.status(400).json({ success: false, message: 'webhookUrl is required.' })
    }
    const httpMethod = (method || 'POST').toUpperCase()
    const action = String(payload?.action || '').toLowerCase()
    const shouldCheckDuplicate = httpMethod !== 'GET' && (!action || action === 'save')
    if (shouldCheckDuplicate) {
      const serialKey = buildDedupeKey(payload)
      if (serialKey && isDuplicateSerial(serialKey)) {
        return res.json({ success: true, duplicateSuppressed: true, message: 'Duplicate save suppressed' })
      }
    }
    const config = {
      headers: { 'Content-Type': 'application/json', ...(headers || {}) },
      validateStatus: () => true,
      // allow large JSON payloads (e.g., base64 PDF) to pass through
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }
    let resp
    if (httpMethod === 'GET') {
      const cached = cacheGet(webhookUrl, payload)
      if (cached) return res.json({ success: true, forwarded: true, status: 200, data: cached })
      const getPage = async (pagePayload) => {
        const pageCached = cacheGet(webhookUrl, pagePayload)
        if (pageCached) return pageCached
        return getOrJoinInFlightGet(webhookUrl, pagePayload, async () => {
          const u = new URL(webhookUrl)
          Object.entries(pagePayload || {}).forEach(([k, v]) => u.searchParams.append(k, String(v)))
          const pageResp = await webhookHttp.get(u.toString(), config)
          if (!String(pageResp.status).startsWith('2')) {
            const err = new Error(`Webhook call failed with status ${pageResp.status}`)
            err.status = pageResp.status
            err.data = pageResp.data
            throw err
          }
          return pageResp.data
        })
      }

      const requestedPage = Math.max(parseInt(payload?.page || '1', 10) || 1, 1)
      const requestedPageSize = Math.max(parseInt(payload?.pageSize || payload?.pagesize || '0', 10) || 0, 0)
      const shouldAutoPaginate = action === 'list' && requestedPage === 1 && requestedPageSize > 100

      if (!shouldAutoPaginate) {
        const data = await getPage(payload || {})
        return res.json({ success: true, forwarded: true, status: 200, data })
      }

      const basePayload = { ...(payload || {}) }
      let page = 1
      let allRows = []
      let firstData = null
      let total = null
      const MAX_PAGES = Math.max(1, Math.ceil(requestedPageSize / 100))

      while (page <= MAX_PAGES && allRows.length < requestedPageSize) {
        const pagePayload = { ...basePayload, page }
        const pageData = await getPage(pagePayload)
        if (page === 1) firstData = pageData
        if (total === null) total = extractTotalFromWebhookData(pageData)
        const pageRows = extractRowsFromWebhookData(pageData)
        if (!pageRows.length) break
        allRows = allRows.concat(pageRows)
        if (total !== null && allRows.length >= total) break
        if (pageRows.length < 100) break
        page += 1
      }

      if (allRows.length > requestedPageSize) allRows = allRows.slice(0, requestedPageSize)
      const merged = mergeRowsIntoWebhookData(firstData, allRows)
      cachePut(webhookUrl, payload, merged)
      return res.json({ success: true, forwarded: true, status: 200, data: merged })
    } else {
      resp = await webhookHttp.post(webhookUrl, payload || {}, config)
    }
    if (String(resp.status).startsWith('2')) {
      if (shouldCheckDuplicate) {
        const serialKey = buildDedupeKey(payload)
        if (serialKey) markSerial(serialKey)
      }
      if (httpMethod === 'GET') cachePut(webhookUrl, payload, resp.data)
      return res.json({ success: true, forwarded: true, status: resp.status, data: resp.data })
    }
    return res.status(502).json({ success: false, message: 'Webhook call failed', status: resp.status, data: resp.data })
  } catch (error) {
    console.error('Failed to post booking via webhook:', safeErrorMessage(error))
    return res.status(500).json({ success: false, message: 'Failed to post to webhook.', detail: error.message })
  }
})

// Jobcard via generic webhook (separate route to avoid confusion with booking)
router.post('/jobcard/webhook', auth, requireRole([ROLES.STAFF, ROLES.OWNER, ROLES.ADMIN]), async (req, res) => {
  try {
    const { webhookUrl, payload, headers, method } = req.body || {}
    if (!webhookUrl) {
      return res.status(400).json({ success: false, message: 'webhookUrl is required.' })
    }
    const httpMethod = (method || 'POST').toUpperCase()
    const action = String(payload?.action || '').toLowerCase()
    const shouldCheckDuplicate = httpMethod !== 'GET' && (!action || action === 'save')
    if (shouldCheckDuplicate) {
      const serialKey = buildDedupeKey(payload)
      if (serialKey && isDuplicateSerial(serialKey)) {
        return res.json({ success: true, duplicateSuppressed: true, message: 'Duplicate save suppressed' })
      }
    }
    const config = {
      headers: { 'Content-Type': 'application/json', ...(headers || {}) },
      validateStatus: () => true,
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    }
    let resp
    if (httpMethod === 'GET') {
      const cached = cacheGet(webhookUrl, payload)
      if (cached) return res.json({ success: true, forwarded: true, status: 200, data: cached })
      const getPage = async (pagePayload) => {
        const pageCached = cacheGet(webhookUrl, pagePayload)
        if (pageCached) return pageCached
        return getOrJoinInFlightGet(webhookUrl, pagePayload, async () => {
          const u = new URL(webhookUrl)
          Object.entries(pagePayload || {}).forEach(([k, v]) => u.searchParams.append(k, String(v)))
          const pageResp = await webhookHttp.get(u.toString(), config)
          if (!String(pageResp.status).startsWith('2')) {
            const err = new Error(`Webhook call failed with status ${pageResp.status}`)
            err.status = pageResp.status
            err.data = pageResp.data
            throw err
          }
          return pageResp.data
        })
      }

      const requestedPage = Math.max(parseInt(payload?.page || '1', 10) || 1, 1)
      const requestedPageSize = Math.max(parseInt(payload?.pageSize || payload?.pagesize || '0', 10) || 0, 0)
      const shouldAutoPaginate = action === 'list' && requestedPage === 1 && requestedPageSize > 100

      if (!shouldAutoPaginate) {
        const data = await getPage(payload || {})
        return res.json({ success: true, forwarded: true, status: 200, data })
      }

      const basePayload = { ...(payload || {}) }
      let page = 1
      let allRows = []
      let firstData = null
      let total = null
      const MAX_PAGES = Math.max(1, Math.ceil(requestedPageSize / 100))

      while (page <= MAX_PAGES && allRows.length < requestedPageSize) {
        const pagePayload = { ...basePayload, page }
        const pageData = await getPage(pagePayload)
        if (page === 1) firstData = pageData
        if (total === null) total = extractTotalFromWebhookData(pageData)
        const pageRows = extractRowsFromWebhookData(pageData)
        if (!pageRows.length) break
        allRows = allRows.concat(pageRows)
        if (total !== null && allRows.length >= total) break
        if (pageRows.length < 100) break
        page += 1
      }

      if (allRows.length > requestedPageSize) allRows = allRows.slice(0, requestedPageSize)
      const merged = mergeRowsIntoWebhookData(firstData, allRows)
      cachePut(webhookUrl, payload, merged)
      return res.json({ success: true, forwarded: true, status: 200, data: merged })
    } else {
      resp = await webhookHttp.post(webhookUrl, payload || {}, config)
    }
    if (String(resp.status).startsWith('2')) {
      if (shouldCheckDuplicate) {
        const serialKey = buildDedupeKey(payload)
        if (serialKey) markSerial(serialKey)
      }
      if (httpMethod === 'GET') cachePut(webhookUrl, payload, resp.data)
      return res.json({ success: true, forwarded: true, status: resp.status, data: resp.data })
    }
    return res.status(502).json({ success: false, message: 'Webhook call failed', status: resp.status, data: resp.data })
  } catch (error) {
    console.error('Failed to post jobcard via webhook:', safeErrorMessage(error))
    return res.status(500).json({ success: false, message: 'Failed to post to webhook.', detail: error.message })
  }
})

// Note: Stock movements are handled via the GAS proxy (/api/stocks/gas). MongoDB stock routes were removed.

module.exports = router
