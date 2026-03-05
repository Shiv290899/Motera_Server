const mongoose = require('mongoose')
const { Schema } = mongoose

const BRANCH_TYPE_OPTIONS = ['sales', 'service', 'sales & services']
const BRANCH_STATUS_OPTIONS = ['active', 'inactive', 'under_maintenance']

const branchSchema = new Schema(
  {
    code: { type: String, required: true, unique: true, trim: true, uppercase: true },
    name: { type: String, required: true, trim: true },
    type: { type: String, enum: BRANCH_TYPE_OPTIONS, required: true, default: 'sales & services' },

    // Contact
    phone: { type: String, trim: true },
    email: { type: String, trim: true, lowercase: true },

    // Address
    address: {
      line1: { type: String, trim: true },
      line2: { type: String, trim: true },
      area: { type: String, trim: true },
      city: { type: String, required: true, trim: true },
      state: { type: String, trim: true },
      pincode: { type: String, trim: true },
    },

    // GeoJSON location: [lng, lat]
    location: {
      type: {
        type: String,
        enum: ['Point'],
        default: 'Point',
      },
      coordinates: {
        type: [Number],
        validate: {
          validator: function (v) {
            return !v || v.length === 2
          },
          message: 'location.coordinates must be [lng, lat]',
        },
      },
    },

    // ---- New: People associations ----
    // One accountable person (optional); useful for approvals/escalations
    manager: { type: Schema.Types.ObjectId, ref: 'User' },
    // Staff members who operate from this branch (sales/service desk)
    staff: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    // Boys/helpers/field runners associated to this branch
    boys: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    // Mechanics associated to this branch
    mechanics: [{ type: Schema.Types.ObjectId, ref: 'User' }],

    // Ops
    status: { type: String, enum: BRANCH_STATUS_OPTIONS, default: 'active' },
    // Owner association (for multi-tenant isolation)
    owner: { type: Schema.Types.ObjectId, ref: 'User' },
    // Single default branch per owner
    isDefault: { type: Boolean, default: false },
    // Optional structured opening hours (for future UI)
    openingHours: {
      mon: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      tue: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      wed: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      thu: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      fri: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      sat: { open: { type: String, trim: true }, close: { type: String, trim: true } },
      sun: { open: { type: String, trim: true }, close: { type: String, trim: true } },
    },

    metadata: { type: Schema.Types.Mixed },
  },
  {
    timestamps: true,
    strict: true,
    strictQuery: true,
  }
)

// ---- Indexes (kept + a couple more for common filters) ----
branchSchema.index({ code: 1 }, { unique: true })
branchSchema.index({ 'address.city': 1, type: 1 })
branchSchema.index({ status: 1 })
branchSchema.index({ location: '2dsphere' })
branchSchema.index({ manager: 1 })
branchSchema.index({ status: 1, type: 1 })

// ---- Virtuals ----
branchSchema.virtual('activeStaffCount').get(function () {
  return Array.isArray(this.staff) ? this.staff.length : 0
})
branchSchema.virtual('activeBoysCount').get(function () {
  return Array.isArray(this.boys) ? this.boys.length : 0
})
branchSchema.virtual('activeMechanicsCount').get(function () {
  return Array.isArray(this.mechanics) ? this.mechanics.length : 0
})
branchSchema.virtual('isSales').get(function () {
  return this.type === 'sales' || this.type === 'sales & services'
})
branchSchema.virtual('isService').get(function () {
  return this.type === 'service' || this.type === 'sales & services'
})

// ---- Small guards/normalizers ----
branchSchema.pre('save', function (next) {
  // If coordinates are missing/invalid, drop location entirely.
  // This prevents 2dsphere index errors for documents with { location: { type: 'Point' } } only.
  if (!this.location || !Array.isArray(this.location.coordinates) || this.location.coordinates.length !== 2) {
    this.location = undefined
    return next()
  }
  const [lngRaw, latRaw] = this.location.coordinates
  const lng = Number(lngRaw)
  const lat = Number(latRaw)
  if (!Number.isFinite(lng) || !Number.isFinite(lat)) {
    this.location = undefined
    return next()
  }

  // If someone accidentally provides [lat, lng], swap to [lng, lat]
  if (this.location && Array.isArray(this.location.coordinates) && this.location.coordinates.length === 2) {
    const [a, b] = this.location.coordinates
    // crude heuristic: lat in [-90,90], lng in [-180,180]
    const looksLikeLatLng = Math.abs(a) <= 90 && Math.abs(b) <= 180
    if (looksLikeLatLng) {
      // expecting [lng, lat]; if [lat, lng] was given, swap
      this.location.coordinates = [b, a]
    }
  }
  this.location.type = 'Point'
  next()
})

// Clean JSON output (hide internal fields)
branchSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    ret.id = ret._id
    delete ret._id
    delete ret.__v
    return ret
  },
})

const Branch = mongoose.model('Branch', branchSchema)
module.exports = Branch
