const mongoose = require('mongoose')
mongoose.set('strictQuery', true)

// Support both MONGO_URI and MONGODB_URI env names
const uri = process.env.MONGO_URI || process.env.MONGODB_URI
if (!uri) {
  console.error('MONGO_URI/MONGODB_URI is not set. Please configure it in server/.env')
  throw new Error('Missing MONGO_URI')
}

mongoose.connect(uri, {
  serverSelectionTimeoutMS: 10000,
})

const connection = mongoose.connection

connection.on('connected', () => {
  console.log('MongoDB connection successful')
})

connection.on('error', (err) => {
  console.error('MongoDB connection error', err?.message || err)
})
