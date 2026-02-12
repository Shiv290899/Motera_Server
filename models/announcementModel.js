const mongoose = require('mongoose')

const { Schema } = mongoose

const announcementSchema = new Schema(
  {
    title: { type: String, required: true, trim: true },
    body: { type: String, required: true, trim: true },
    type: { type: String, enum: ['info', 'warning', 'alert'], required: true, default: 'info' },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
    active: { type: Boolean, default: true },
    expiresAt: { type: Date },
    acknowledgedBy: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  },
  {
    timestamps: { createdAt: true, updatedAt: true },
    strict: true,
    strictQuery: true,
  }
)

announcementSchema.index({ active: 1, createdAt: -1 })
announcementSchema.index({ expiresAt: 1 })

const Announcement = mongoose.model('Announcement', announcementSchema)

module.exports = Announcement
