const mongoose = require('mongoose')
const { ROLES, SYSTEM_ROLES, normalizeRole } = require('../constants/roles')

const { Schema } = mongoose

const STATUS_OPTIONS = ['active', 'inactive', 'suspended']

// Helper: roles that must be tied to a branch
const BRANCH_BOUND_ROLES = new Set([ROLES.STAFF])

const userSchema = new Schema(
  {
    // Identity
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    phone: { type: String, unique: true, sparse: true, trim: true }, // optional but unique when present

    // Auth (password is already hashed in route; do not hash here again)
    password: { type: String, required: true },

    // Password reset flow
    resetPasswordToken: { type: String },
    resetPasswordExpiresAt: { type: Date },

    // Employment / Access control
    role: {
      type: String,
      enum: SYSTEM_ROLES,
      required: true,
      default: ROLES.USER,
      set: normalizeRole,
    },
    jobTitle: { type: String, trim: true },
    employeeCode: { type: String, trim: true }, // unique within a primary branch

    // Branch association
    primaryBranch: { type: Schema.Types.ObjectId, ref: 'Branch' },
    branches: [{ type: Schema.Types.ObjectId, ref: 'Branch' }], // optional multi-branch support
    // For admins/owners who can operate across locations (UI can show a branch switcher)
    canSwitchBranch: { type: Boolean, default: false },
    // Tenant owner (self for owners; owner user id for staff/mechanic/callboy)
    owner: { type: Schema.Types.ObjectId, ref: 'User' },

    // Operational
    status: { type: String, enum: STATUS_OPTIONS, default: 'active' },
    lastLoginAt: { type: Date },
    tokenInvalidAfter: { type: Date },
    metadata: { type: Schema.Types.Mixed },

    // Owner-specific configuration
    ownerConfig: {
      orgName: { type: String, trim: true },
      orgNameRegional: { type: String, trim: true },
      orgNameFontFamily: { type: String, trim: true },
      orgNameRegionalFontFamily: { type: String, trim: true },
      orgNameFontWeight: { type: Number, min: 100, max: 900 },
      orgNameRegionalFontWeight: { type: Number, min: 100, max: 900 },
      orgNameFontSizePt: { type: Number, min: 8, max: 64 },
      orgNameRegionalFontSizePt: { type: Number, min: 8, max: 64 },
      orgNameFontColor: { type: String, trim: true },
      orgAddress: { type: String, trim: true },
      orgAddressFontWeight: { type: Number, min: 100, max: 900 },
      orgAddressFontSizePt: { type: Number, min: 8, max: 64 },
      mechanics: [{
        name: { type: String, trim: true },
        phone: { type: String, trim: true },
      }],
      orgMobiles: [{ type: String, trim: true }],
      logoUrl: { type: String, trim: true },
      locationQrUrl: { type: String, trim: true },
      webhookUrl: { type: String, trim: true },
      processingFee: { type: Number, min: 0 },
      flatInterestRate: { type: Number, min: 0, max: 100 },
      quotationWaGreetingLine: { type: String, trim: true },
      quotationWaIntroLine: { type: String, trim: true },
      quotationWaContactLine: { type: String, trim: true },
      quotationWaLocationsTitle: { type: String, trim: true },
      quotationWaLocations: [{ type: String, trim: true }],
      quotationWaNoteLine: { type: String, trim: true },
      quotationWaClosingLine: { type: String, trim: true },
      freeFittingsOptions: [{ type: String, trim: true }],
      freeFittingsDefaultSelected: [{ type: String, trim: true }],
      labourScooterBase: [{
        desc: { type: String, trim: true },
        rate: { type: Number, min: 0 },
      }],
      labourMotorcycleBase: [{
        desc: { type: String, trim: true },
        rate: { type: Number, min: 0 },
      }],
      labourPaidAddons: [{
        desc: { type: String, trim: true },
        rate: { type: Number, min: 0 },
      }],
    },
    ownerLimits: {
      branchLimit: { type: Number, min: 0 },
    },
  },
  {
    timestamps: true,
    strict: true,
    strictQuery: true,
  }
)

/**
 * Validation: Branch-bound roles must have a primaryBranch set.
 * Also helpful when creating staff accounts to prevent missing branch linkage.
 */
userSchema.path('primaryBranch').validate(function (value) {
  if (BRANCH_BOUND_ROLES.has(this.role)) {
    return !!value
  }
  return true
}, 'primaryBranch is required for STAFF role')

userSchema.path('owner').validate(function (value) {
  const role = normalizeRole(this.role)
  if (role === ROLES.OWNER || role === ROLES.ADMIN || role === ROLES.USER) return true
  return role !== ROLES.STAFF || !!value
}, 'owner is required for STAFF role')

userSchema.pre('validate', function normalizeRoleBeforeValidate(next) {
  this.role = normalizeRole(this.role)
  next()
})

function stripUnauthorizedRoleUpdate(next) {
  const update = this.getUpdate() || {}
  const opts = this.getOptions ? this.getOptions() : {}
  const allowRoleUpdate = opts && opts.allowRoleUpdate === true
  const touchesRole =
    Object.prototype.hasOwnProperty.call(update, 'role') ||
    Object.prototype.hasOwnProperty.call(update.$set || {}, 'role')

  if (touchesRole && !allowRoleUpdate) {
    return next(new Error('Role updates are restricted to ADMIN APIs'))
  }

  if (update.role) {
    update.role = normalizeRole(update.role)
  }
  if (update.$set && update.$set.role) {
    update.$set.role = normalizeRole(update.$set.role)
  }
  this.setUpdate(update)
  return next()
}

userSchema.pre('updateOne', stripUnauthorizedRoleUpdate)
userSchema.pre('findOneAndUpdate', stripUnauthorizedRoleUpdate)
userSchema.pre('updateMany', stripUnauthorizedRoleUpdate)

/**
 * Virtual: defaultBranch
 * - Returns primaryBranch if available, otherwise the first in branches[].
 * - Lets downstream code uniformly read "the branch to use by default".
 */
userSchema.virtual('defaultBranch').get(function () {
  if (this.primaryBranch) return this.primaryBranch
  if (Array.isArray(this.branches) && this.branches.length > 0) return this.branches[0]
  return null
})

/**
 * Virtual: formDefaults
 * - Minimal payload your forms need to auto-fill:
 *   { staffName, branchId }
 * - Consume this in your controllers or client after /me:
 *   const { staffName, branchId } = user.formDefaults
 */
userSchema.virtual('formDefaults').get(function () {
  return {
    staffName: this.name || '',
    branchId: this.defaultBranch || null,
  }
})

// Indexes
userSchema.index({ email: 1 }, { unique: true })
userSchema.index({ primaryBranch: 1 })
userSchema.index({ role: 1 })
// Ensure employeeCode is unique within a primary branch (when both exist)
userSchema.index(
  { employeeCode: 1, primaryBranch: 1 },
  {
    unique: true,
    partialFilterExpression: {
      employeeCode: { $type: 'string' },
      primaryBranch: { $type: 'objectId' },
    },
  }
)

/**
 * Clean JSON output (hide internal fields)
 * Keep password in DB but don't expose it in toJSON.
 * (Your login route can still fetch it with .select('+password') if you later set select:false)
 */
userSchema.set('toJSON', {
  virtuals: true, // include virtuals like formDefaults/defaultBranch in JSON
  transform: function (doc, ret) {
    ret.id = ret._id
    delete ret._id
    delete ret.__v
    delete ret.password
    delete ret.resetPasswordToken
    delete ret.resetPasswordExpiresAt
    return ret
  },
})

const User = mongoose.model('User', userSchema)

module.exports = User
