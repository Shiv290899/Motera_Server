const crypto = require('crypto')

const WEBHOOK_CIPHER_PREFIX = 'enc:v1'
const WEBHOOK_KEY_SOURCE = String(process.env.WEBHOOK_URL_ENCRYPTION_KEY || '').trim()

function hasWebhookEncryptionKey() {
  return Boolean(WEBHOOK_KEY_SOURCE)
}

function getWebhookEncryptionKey() {
  if (!WEBHOOK_KEY_SOURCE) {
    throw new Error('WEBHOOK_URL_ENCRYPTION_KEY is not configured')
  }
  return crypto.createHash('sha256').update(WEBHOOK_KEY_SOURCE, 'utf8').digest()
}

function isEncryptedWebhookValue(value) {
  return String(value || '').startsWith(`${WEBHOOK_CIPHER_PREFIX}:`)
}

function encryptWebhookUrl(value) {
  const plain = String(value || '').trim()
  if (!plain) return undefined
  if (!hasWebhookEncryptionKey()) return plain
  if (isEncryptedWebhookValue(plain)) return plain

  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', getWebhookEncryptionKey(), iv)
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return [
    WEBHOOK_CIPHER_PREFIX,
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':')
}

function decryptWebhookUrl(value) {
  const raw = String(value || '').trim()
  if (!raw) return ''
  if (!isEncryptedWebhookValue(raw)) return raw
  if (!hasWebhookEncryptionKey()) return ''

  const parts = raw.split(':')
  if (parts.length !== 5) {
    throw new Error('Invalid encrypted webhook value format')
  }

  const iv = Buffer.from(parts[2], 'base64')
  const tag = Buffer.from(parts[3], 'base64')
  const encrypted = Buffer.from(parts[4], 'base64')
  const decipher = crypto.createDecipheriv('aes-256-gcm', getWebhookEncryptionKey(), iv)
  decipher.setAuthTag(tag)
  const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8')
  return plain.trim()
}

function readWebhookUrlForApp(ownerConfig) {
  if (!ownerConfig || typeof ownerConfig !== 'object') return ''
  try {
    return decryptWebhookUrl(ownerConfig.webhookUrl)
  } catch (err) {
    console.error('Failed to decrypt owner webhook URL:', err.message)
    return ''
  }
}

function serializeOwnerConfigForViewer(ownerConfig, roleInput, canViewWebhookUrls) {
  if (!ownerConfig || typeof ownerConfig !== 'object') return ownerConfig
  const clean = { ...ownerConfig }
  if (!canViewWebhookUrls(roleInput)) {
    delete clean.webhookUrl
    return clean
  }
  const resolvedWebhookUrl = readWebhookUrlForApp(ownerConfig)
  if (resolvedWebhookUrl) {
    clean.webhookUrl = resolvedWebhookUrl
  } else {
    delete clean.webhookUrl
  }
  return clean
}

module.exports = {
  decryptWebhookUrl,
  encryptWebhookUrl,
  hasWebhookEncryptionKey,
  isEncryptedWebhookValue,
  readWebhookUrlForApp,
  serializeOwnerConfigForViewer,
}
