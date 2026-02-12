// Load environment variables from server/.env regardless of CWD
const path = require('path')
// Primary: server/.env
const serverEnvPath = path.resolve(__dirname, '.env')
require('dotenv').config({ path: serverEnvPath })
// Fallback: project root .env (useful if you placed it at repo root)
const rootEnvPath = path.resolve(process.cwd(), '.env')
if (rootEnvPath !== serverEnvPath) {
  require('dotenv').config({ path: rootEnvPath, override: false })
}

const express = require('express')
const app = express()
const dbConfig = require('./config/dbConfig')
const userRoutes = require('./routes/userRoutes')
const formsRoutes = require('./routes/formsRoutes')
const branchRoutes = require('./routes/branchRoutes')
const stocksGasProxyRoutes = require('./routes/stocksGasProxy')
const announcementRoutes = require('./routes/announcementRoutes')
const cors = require('cors')


// CORS configuration via env
const rawOrigins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean)
const corsCredentials = String(process.env.CORS_CREDENTIALS).toLowerCase() === 'true'

// More permissive, device-friendly origin check. Allows:
// - Explicit origins from env
// - Local dev (localhost/127.0.0.1)
// - LAN IPs (192.168.x.x / 10.x.x.x / 172.16-31.x.x)
// - Common preview domains (netlify.app/vercel.app/ngrok-free.app)
const allowOrigin = (origin) => {
  if (!origin) return true // non-browser or same-origin
  try {
    if (rawOrigins.includes(origin)) return true
    const o = String(origin || '').toLowerCase()
    if (/(^|:\/\/)(localhost|127\.0\.0\.1)([:/]|$)/.test(o)) return true
    const h = new URL(o).hostname
    if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(h)) return true
    if (/(^|\.)netlify\.app$/.test(h)) return true
    if (/(^|\.)vercel\.app$/.test(h)) return true
    if (/(^|\.)ngrok-free\.app$/.test(h)) return true
  } catch {}
  return false
}

app.use(cors({
  origin: (origin, cb) => cb(null, allowOrigin(origin)),
  credentials: corsCredentials,
  methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'],
}))

// Increase body size limit to allow PDF base64 uploads from Booking form
// Default increased to 25mb to avoid intermittent 413s on some devices
const bodyLimit = process.env.JSON_BODY_LIMIT || '25mb'
app.use(express.json({ limit: bodyLimit }))
app.use(express.urlencoded({ extended: true, limit: bodyLimit }))
// Basic health checks
app.get('/', (req, res) => res.status(200).send('OK'))
app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok' }))
app.use('/api/users', userRoutes)

app.use('/api/forms', formsRoutes)
app.use('/api/branches', branchRoutes)
app.use('/api/stocks/gas', stocksGasProxyRoutes)
app.use('/api/announcements', announcementRoutes)



const PORT = parseInt(process.env.PORT || '8082', 10)
app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`)
})
