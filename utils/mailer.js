const nodemailer = require('nodemailer')
hedTransporter = null

function isMailConfigured() {
  return Boolean(SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS && SMTP_FROM)
}

function getTransporter() {
  if (!isMailConfigured()) {
    throw new Error('SMTP settings are not configured')
  }
  if (!cachedTransporter) {
    cachedTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: SMTP_SECURE === 'true',
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
      },
    })
  }
  return cachedTransporter
}

async function sendMail(options) {
  const transporter = getTransporter()
  const info = await transporter.sendMail({
    from: SMTP_FROM,
    ...options,
  })
  return info
}

module.exports = {
  sendMail,
  isMailConfigured,
}
