export type Settings = Record<string, string>

// Only these keys may ever be written through the setup form.
// Anything else posted to /setup is ignored (prevents e.g. overwriting SYSTEM_SECRET).
export const SETTING_KEYS = ['CF_API_TOKEN', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'] as const

const SECRET_KEYS = ['CF_API_TOKEN', 'GOOGLE_CLIENT_SECRET']

export async function ensureSystemSecret(db: D1Database): Promise<string> {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('SYSTEM_SECRET').first<{ value: string }>()
  if (row?.value) return row.value

  const newSecret = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  await db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING').bind('SYSTEM_SECRET', newSecret).run()
  return newSecret
}

export async function getSettings(db: D1Database): Promise<Settings> {
  const { results } = await db.prepare('SELECT key, value FROM settings').all<{ key: string; value: string }>()
  return results.reduce((acc, row) => {
    acc[row.key] = row.value
    return acc
  }, {} as Settings)
}

/** True once every credential required for normal operation is present. */
export function isConfigured(settings: Settings) {
  return !!(settings.CF_API_TOKEN && settings.GOOGLE_CLIENT_ID && settings.GOOGLE_CLIENT_SECRET)
}

/**
 * Mask secret values before rendering them back into HTML:
 * saved values are never echoed to the client, only their existence.
 */
export function maskSecret(settings: Settings, key: string) {
  return SECRET_KEYS.includes(key) && settings[key] ? '' : (settings[key] || '')
}

export function hasSavedSecret(settings: Settings, key: string) {
  return !!settings[key]
}

export async function logAudit(db: D1Database, userEmail: string, action: string, resourceType: string, resourceName: string, details?: any) {
  await db.prepare(
    'INSERT INTO audit_logs (user_email, action, resource_type, resource_name, details) VALUES (?, ?, ?, ?, ?)'
  ).bind(userEmail, action, resourceType, resourceName, details ? JSON.stringify(details) : null).run()
}

/**
 * Blacklist patterns support '*' as a wildcard and are matched case-insensitively
 * against the full record name. Patterns are validated on insert so that the
 * regex built here can never throw or blow up on metacharacters.
 */
const PATTERN_MAX = 100

export function isValidBlacklistPattern(pattern: string) {
  return pattern.length > 0 && pattern.length <= PATTERN_MAX && /^[a-zA-Z0-9_*.-]+$/.test(pattern)
}

export async function isBlacklisted(db: D1Database, name: string) {
  const { results } = await db.prepare('SELECT pattern FROM blacklist').all<{ pattern: string }>()
  // Cloudflare treats "foo.example.com." and "foo.example.com" as the same
  // record, so a trailing dot must not slip past the anchored match.
  const lowerName = name.toLowerCase().replace(/\.+$/, '')
  return results.some(row => {
    // Patterns are validated on insert, but rows written before that guard
    // existed may hold raw metacharacters — skip them rather than let one
    // legacy row 500 every record write forever.
    try {
      const pattern = row.pattern.toLowerCase().replace(/\.+$/, '')
      const escaped = pattern
        .replace(/\*/g, '\x00')
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\x00/g, '.*')
      return new RegExp('^' + escaped + '$', 'i').test(lowerName)
    } catch {
      return false
    }
  })
}
