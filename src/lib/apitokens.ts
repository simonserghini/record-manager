/**
 * API token issuance and Bearer authentication.
 *
 * Secrets are shown exactly once at creation; only the SHA-256 hash is
 * stored, so a D1 leak cannot be replayed against the API. A token inherits
 * the exact permission set of its owning user.
 */

export function generateApiToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return 'rm_' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export async function hashApiToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Resolves an Authorization header to the token's owning user.
 * Returns null for missing/malformed headers, unknown hashes, and revoked
 * tokens; also stamps last_used_at so owners can spot live credentials.
 */
export async function resolveApiToken(
  db: D1Database,
  authHeader: string | undefined
): Promise<{ user: { id: number; email: string; role: string }; tokenId: number } | null> {
  if (!authHeader) return null
  const match = /^Bearer\s+(\S+)$/i.exec(authHeader.trim())
  if (!match) return null

  const tokenHash = await hashApiToken(match[1])
  const row = await db.prepare(
    `SELECT t.id AS token_id, u.id AS user_id, u.email, u.role, u.session_epoch
     FROM api_tokens t JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.revoked_at IS NULL`
  ).bind(tokenHash).first<any>()
  if (!row) return null

  // Best-effort usage stamp — never block the request on it.
  try {
    await db.prepare('UPDATE api_tokens SET last_used_at = datetime(\'now\') WHERE id = ?').bind(row.token_id).run()
  } catch { /* ignore */ }

  return { user: { id: row.user_id, email: row.email, role: row.role }, tokenId: row.token_id }
}
