export type Role = 'owner' | 'admin' | 'manager' | 'user'

// Roles with implicit full ('domain_admin') access to every domain
export const GLOBAL_ROLES: Role[] = ['owner', 'admin', 'manager']

// Levels that may be granted through delegation. Ordered by capability:
// each level implies all capabilities below it.
export const PERMISSION_HIERARCHY: Record<string, number> = {
  'read': 1,
  'add': 2,
  'edit_own': 3,
  'edit': 4,
  'delete_own': 5,
  'delete': 6,
  'domain_admin': 7
}

export const LEVEL_KEYS = Object.keys(PERMISSION_HIERARCHY)

// Record-level clearances are a separate, finer-grained ladder
export const RECORD_LEVEL_KEYS = ['read', 'edit', 'delete'] as const

const ROLE_VALUES: Role[] = ['user', 'manager', 'admin']

export function isValidLevel(level: string) {
  return level in PERMISSION_HIERARCHY
}

export function can(userLevel: string | null | undefined, requiredLevel: string) {
  if (!userLevel) return false
  return (PERMISSION_HIERARCHY[userLevel] ?? 0) >= (PERMISSION_HIERARCHY[requiredLevel] ?? Infinity)
}

/**
 * Effective domain-wide clearance for a user.
 * Global roles implicitly hold 'domain_admin' everywhere; everyone else
 * falls back to their delegated permission row for that domain.
 */
export async function getPermissionLevel(db: D1Database, user: { id: number; role: string } | null | undefined, domainId: number): Promise<string | null> {
  if (!user) return null
  if (GLOBAL_ROLES.includes(user.role as Role)) return 'domain_admin'
  const perm = await db.prepare('SELECT level FROM permissions WHERE user_id = ? AND domain_id = ?').bind(user.id, domainId).first<{ level: string }>()
  return perm?.level ?? null
}

/** True when the actor may view this domain's (filtered) record list. */
export function canViewDomain(role: string, userLevel: string | null, hasRecordPerms: boolean) {
  return GLOBAL_ROLES.includes(role as Role) || !!userLevel || hasRecordPerms
}

/** True when the actor may manage delegations (grant/revoke clearances) on this domain. */
export function canManageDelegation(role: string, userLevel: string | null) {
  return GLOBAL_ROLES.includes(role as Role) || userLevel === 'domain_admin'
}

export function canAddRecords(role: string, userLevel: string | null) {
  return GLOBAL_ROLES.includes(role as Role) || can(userLevel, 'add')
}

/**
 * Edit rights over one specific record, combining domain-level and
 * record-level clearances with record ownership (`_own` levels).
 */
export function canEditRecord(opts: {
  role: string
  userLevel: string | null
  recordLevel?: string | null
  isCreatorOfRecord: boolean
}) {
  const { role, userLevel, recordLevel, isCreatorOfRecord } = opts
  if (GLOBAL_ROLES.includes(role as Role)) return true
  if (can(userLevel, 'edit')) return true
  if (userLevel === 'edit_own' && isCreatorOfRecord) return true
  if (recordLevel === 'edit' || recordLevel === 'delete') return true
  return false
}

/**
 * Delete rights over one specific record.
 * Note: 'edit_own' deliberately does NOT imply delete rights.
 */
export function canDeleteRecord(opts: {
  role: string
  userLevel: string | null
  recordLevel?: string | null
  isCreatorOfRecord: boolean
}) {
  const { role, userLevel, recordLevel, isCreatorOfRecord } = opts
  if (GLOBAL_ROLES.includes(role as Role)) return true
  if (can(userLevel, 'delete')) return true
  if (userLevel === 'delete_own' && isCreatorOfRecord) return true
  if (recordLevel === 'delete') return true
  return false
}
