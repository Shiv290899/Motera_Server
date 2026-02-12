const ROLES = Object.freeze({
  USER: 'USER',
  STAFF: 'STAFF',
  OWNER: 'OWNER',
  ADMIN: 'ADMIN',
})

const SYSTEM_ROLES = Object.freeze(Object.values(ROLES))

const LEGACY_ROLE_ALIAS = Object.freeze({
  user: ROLES.USER,
  staff: ROLES.STAFF,
  mechanic: ROLES.STAFF,
  employees: ROLES.STAFF,
  callboy: ROLES.STAFF,
  owner: ROLES.OWNER,
  admin: ROLES.ADMIN,
  backend: ROLES.ADMIN,
})

function normalizeRole(input) {
  const value = String(input || '').trim()
  if (!value) return ROLES.USER
  const upper = value.toUpperCase()
  if (SYSTEM_ROLES.includes(upper)) return upper
  const mapped = LEGACY_ROLE_ALIAS[value.toLowerCase()]
  return mapped || ROLES.USER
}

module.exports = {
  ROLES,
  SYSTEM_ROLES,
  normalizeRole,
}
