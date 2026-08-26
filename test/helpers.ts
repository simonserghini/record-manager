/**
 * Test helpers: forge signed session cookies exactly the way Hono's
 * setSignedCookie does (value = `${email}|${epoch}`, signature = base64
 * HMAC-SHA256 over the raw value), and seed user/token rows.
 */
import { SELF } from 'cloudflare:test'

// Must equal the SYSTEM_SECRET upserted by test/setup.ts — the middleware
// signs and verifies session cookies with it.
const COOKIE_SECRET = 'test-system-secret'

export async function signValue(value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(COOKIE_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value))
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
}

export async function forgeSessionCookie(email: string, epoch = 0): Promise<string> {
  const value = epoch === 0 ? email : `${email}|${epoch}`
  const signed = `${value}.${await signValue(value)}`
  return `user=${encodeURIComponent(signed)}`
}

/**
 * Forges a cookie for the user's CURRENT session_epoch — earlier tests may
 * have bumped it (logout-all, ownership transfer), and stale epochs are
 * (correctly) treated as signed-out.
 */
export async function freshSessionCookie(db: D1Database, email: string): Promise<string> {
  const row = await db.prepare('SELECT session_epoch FROM users WHERE email = ?').bind(email).first<{ session_epoch: number }>()
  return forgeSessionCookie(email, row?.session_epoch ?? 0)
}

export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

type SeedUser = { id?: number; email: string; role: string }
/** Inserts a user row and returns its id. */
export async function seedUser(db: D1Database, user: SeedUser): Promise<number> {
  await db.prepare(
    'INSERT INTO users (email, role) VALUES (?, ?) ON CONFLICT(email) DO UPDATE SET role = excluded.role'
  ).bind(user.email, user.role).run()
  const row = await db.prepare('SELECT id FROM users WHERE email = ?').bind(user.email).first<{ id: number }>()
  return row!.id
}

export async function seedApiToken(db: D1Database, userId: number, token: string, name = 'test-token'): Promise<number> {
  const result = await db.prepare(
    'INSERT INTO api_tokens (user_id, name, token_hash) VALUES (?, ?, ?)'
  ).bind(userId, name, await hashToken(token)).run()
  return Number(result.meta.last_row_id)
}

const ORIGIN = 'http://localhost'

/**
 * All requests use redirect: 'manual' — auth failures ARE redirects here,
 * and a followed redirect would mask them as 200s from the sign-in page.
 */
/** GET through the worker under test. */
export function get(path: string, cookie?: string, extraHeaders: Record<string, string> = {}) {
  return SELF.fetch(`${ORIGIN}${path}`, {
    method: 'GET',
    redirect: 'manual',
    headers: { ...(cookie ? { cookie } : {}), ...extraHeaders }
  })
}

/** POST (form or JSON) through the worker under test, Origin set for CSRF. */
export function post(path: string, opts: { cookie?: string; form?: Record<string, string>; json?: unknown } = {}) {
  const headers: Record<string, string> = { origin: ORIGIN }
  if (opts.cookie) headers.cookie = opts.cookie
  let body: string | undefined
  if (opts.form) {
    headers['content-type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(opts.form).toString()
  } else if (opts.json !== undefined) {
    headers['content-type'] = 'application/json'
    body = JSON.stringify(opts.json)
  }
  return SELF.fetch(`${ORIGIN}${path}`, { method: 'POST', redirect: 'manual', headers, body })
}

export { SELF }
