const DEFAULT_CC = (process.env.WHATSAPP_DEFAULT_CC || '91').replace(/\D/g, '')

function normalizeE164NoPlus(raw) {
  const digits = String(raw || '').replace(/\D/g, '')
  if (!digits) return ''
  // If already with country code (e.g., 91xxxxxxxxxx), pass through
  if (digits.length >= 11 && !digits.startsWith('0')) return digits
  // If 10 digits, assume default CC
  if (digits.length === 10) return `${DEFAULT_CC}${digits}`
  // Fallback: return raw digits
  return digits
}

async function sendWhatsappText({ to, text, preview_url = false }) {
  const token = process.env.WHATSAPP_ACCESS_TOKEN
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID

  if (!token || !phoneNumberId) {
    const why = !token ? 'WHATSAPP_ACCESS_TOKEN missing' : 'WHATSAPP_PHONE_NUMBER_ID missing'
    const err = new Error(`WhatsApp API not configured: ${why}`)
    err.code = 'WA_NOT_CONFIGURED'
    throw err
  }

  const toE164 = normalizeE164NoPlus(to)
  if (!toE164) {
    const err = new Error('Invalid destination number')
    err.code = 'INVALID_TO'
    throw err
  }

  const url = `https://graph.facebook.com/v21.0/${phoneNumberId}/messages`
  const payload = {
    messaging_product: 'whatsapp',
    to: toE164,
    type: 'text',
    text: { body: String(text || ''), preview_url: !!preview_url },
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = data?.error?.message || `WhatsApp API error (${res.status})`
    const err = new Error(msg)
    err.code = 'WA_API_ERROR'
    err.details = data
    throw err
  }

  return data
}

module.exports = { sendWhatsappText, normalizeE164NoPlus }

