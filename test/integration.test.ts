import { describe, it, expect, afterAll } from 'vitest'
import { env } from 'cloudflare:test'
import {
  SELF, get, post, forgeSessionCookie, freshSessionCookie, seedUser, seedApiToken
} from './helpers'

const OWNER = 'owner@it.test'
const ADMIN = 'admin@it.test'
const USER = 'user@it.test'

async function seedWorld() {
  await seedUser(env.record_manager_db, { email: OWNER, role: 'owner' })
  const adminId = await seedUser(env.record_manager_db, { email: ADMIN, role: 'admin' })
  const userId = await seedUser(env.record_manager_db, { email: USER, role: 'user' })
  return { adminId, userId }
}

/** Registers both CF mock zones in the local domains table. */
async function seedDomains(): Promise<{ exampleId: number; otherId: number }> {
  await env.record_manager_db.prepare(
    "INSERT INTO domains (zone_id, zone_name) VALUES ('zone-aaa','example.com') ON CONFLICT(zone_id) DO NOTHING"
  ).run()
  await env.record_manager_db.prepare(
    "INSERT INTO domains (zone_id, zone_name) VALUES ('zone-bbb','other.org') ON CONFLICT(zone_id) DO NOTHING"
  ).run()
  const row = async (name: string) =>
    (await env.record_manager_db.prepare('SELECT id FROM domains WHERE zone_name = ?').bind(name).first<any>()).id
  return { exampleId: await row('example.com'), otherId: await row('other.org') }
}

const cleanup: string[] = [OWNER, ADMIN, USER, 'tokener@test.local', 'transferred@it.test']
afterAll(async () => {
  // FK cascades remove permissions/tokens/domains tied to these users.
  for (const email of cleanup) {
    await env.record_manager_db.prepare('DELETE FROM users WHERE email = ?').bind(email).run()
  }
  await env.record_manager_db.prepare("DELETE FROM domains WHERE zone_id IN ('zone-aaa','zone-bbb')").run()
})

describe('public surface', () => {
  it('serves a healthy healthz', async () => {
    const res = await get('/healthz')
    expect(res.status).toBe(200)
    expect(((await res.json()) as any).ok).toBe(true)
  })

  it('redirects anonymous users from protected pages to sign-in', async () => {
    const res = await get('/dashboard')
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/')
  })

  it('ships hardened security headers on every response, errors included', async () => {
    const res = await get('/definitely-not-a-page')
    expect(res.status).toBe(404)
    expect(res.headers.get('content-security-policy')).toContain("script-src 'self'")
    expect(res.headers.get('content-security-policy')).not.toContain('unsafe-inline')
    expect(res.headers.get('strict-transport-security')).toBeTruthy()
    expect(res.headers.get('x-frame-options')).toBe('SAMEORIGIN')
  })
})

describe('session authentication', () => {
  it('accepts a forged signed cookie with matching epoch', async () => {
    const { exampleId } = await seedWorldAndDomains()
    const cookie = await freshSessionCookie(env.record_manager_db, OWNER)
    const res = await get('/dashboard', cookie)
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('example.com')
  })

  it('rejects cookies whose signature does not verify (privilege escalation attempt)', async () => {
    // Sign as a plain user, then tamper the role claim — role is not part of
    // the cookie at all, so the only thing an attacker can forge is their own
    // identity. A bad MAC must yield zero access.
    const value = `${ADMIN}|0`
    const badMac = `${value}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`
    const res = await get('/dashboard', `user=${encodeURIComponent(badMac)}`)
    expect(res.status).toBe(302)
  })

  it('rejects cookies stamped with a stale session epoch after logout-all', async () => {
    const { userId } = await seedWorldAndDomains()
    const epochRow = await bumpAndGetEpoch(userId)

    // Cookie minted for epoch N works…
    const freshCookie = await forgeSessionCookie(USER, epochRow)
    expect((await get('/dashboard', freshCookie)).status).toBe(200)

    // …then "sign out everywhere" bumps the epoch and kills every old cookie.
    const logoutRes = await post('/auth/logout-all', { cookie: freshCookie })
    expect(logoutRes.status).toBe(302)
    expect((await get('/dashboard', freshCookie)).status).toBe(302)
  })

  it('blocks mutating form posts without an Origin header (CSRF)', async () => {
    await seedWorldAndDomains()
    const cookie = await freshSessionCookie(env.record_manager_db, OWNER)
    const csrfless = await SELF.fetch(`http://localhost/domains/${await exampleZoneId()}/records`, {
      method: 'POST',
      headers: { cookie },
      body: new URLSearchParams({ type: 'A', name: 'csrf', content: '192.0.2.1' }).toString()
    })
    expect(csrfless.status).toBe(403)
  })
})

describe('role-based access control', () => {
  it('lets plain users see nothing but their permitted zones on the dashboard', async () => {
    const { userId, exampleId } = await seedWorldAndDomains()
    const cookie = await freshSessionCookie(env.record_manager_db, USER)

    const none = await (await get('/dashboard', cookie)).text()
    expect(none).not.toContain('example.com')

    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'read')"
    ).bind(userId, exampleId).run()

    const granted = await (await get('/dashboard', cookie)).text()
    expect(granted).toContain('example.com')

    // Read-only: the record create form must be absent.
    const zonePage = await (await get(`/domains/${exampleId}`, cookie)).text()
    expect(zonePage).not.toContain('Add Record')
  })

  it('forbids plain users from user management but allows admins to view it', async () => {
    await seedWorldAndDomains()
    const ownerRes = await get('/users', await freshSessionCookie(env.record_manager_db, OWNER))
    expect(ownerRes.status).toBe(200)

    const adminRes = await get('/users', await freshSessionCookie(env.record_manager_db, ADMIN))
    expect(adminRes.status).toBe(200)

    const userRes = await get('/users', await freshSessionCookie(env.record_manager_db, USER))
    expect(userRes.status).toBe(302)
  })

  it('rejects clearance grants for unsynced domains with a flash, not a 500', async () => {
    const { userId } = await seedWorldAndDomains()
    const res = await post(`/users/${userId}/permissions`, {
      cookie: await freshSessionCookie(env.record_manager_db, OWNER),
      form: { domain_id: '999999', level: 'read' }
    })
    expect(res.status).toBe(302)
    const perms = await env.record_manager_db.prepare(
      'SELECT COUNT(*) AS n FROM permissions WHERE user_id = ? AND domain_id = 999999'
    ).bind(userId).first<any>()
    expect(perms.n).toBe(0)
  })

  it('only owners may transfer ownership', async () => {
    const world = await seedWorldAndDomains()
    const targetId = await seedUser(env.record_manager_db, { email: 'transferred@it.test', role: 'user' })
    const adminAttempt = await post(`/users/${targetId}/transfer-ownership`, {
      cookie: await freshSessionCookie(env.record_manager_db, ADMIN)
    })
    expect(adminAttempt.status).toBe(403)

    const ownerMove = await post(`/users/${world.adminId}/transfer-ownership`, {
      cookie: await freshSessionCookie(env.record_manager_db, OWNER)
    })
    expect(ownerMove.status).toBe(302)

    const roles = await env.record_manager_db.prepare(
      'SELECT email, role FROM users WHERE email IN (?, ?, ?)'
    ).bind(OWNER, ADMIN, 'transferred@it.test').all<any>()
    const byEmail = new Map(roles.results.map(r => [r.email, r.role]))
    expect(byEmail.get(ADMIN)).toBe('owner')
    expect(byEmail.get(OWNER)).toBe('admin')
    expect(byEmail.get('transferred@it.test')).toBe('user')

    // Restore the fixture: transfer bumped epochs and swapped roles, which
    // would invalidate the forged cookies used by the remaining tests.
    await env.record_manager_db.batch([
      env.record_manager_db.prepare("UPDATE users SET role = 'owner', session_epoch = 0 WHERE email = ?").bind(OWNER),
      env.record_manager_db.prepare("UPDATE users SET role = 'admin', session_epoch = 0 WHERE email = ?").bind(ADMIN),
      env.record_manager_db.prepare("UPDATE users SET role = 'user', session_epoch = 0 WHERE email = ?").bind('transferred@it.test')
    ])
  })
})

describe('JSON API + bearer tokens', () => {
  const TOKEN = `rm_${'a'.repeat(64)}`

  it('answers 401 JSON without a token and scopes zone listings to permissions', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()

    const noAuth = await get('/api/v1/zones')
    expect(noAuth.status).toBe(401)
    expect((await noAuth.json() as any).error).toBeTruthy()

    await seedApiToken(env.record_manager_db, userId, TOKEN)
    const headers = { authorization: `Bearer ${TOKEN}` }

    // Plain user sees no zones until delegated. (Earlier describes may have
    // granted this user read access — reset their delegations first.)
    await env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ?').bind(userId).run()
    await env.record_manager_db.prepare('DELETE FROM record_permissions WHERE user_id = ?').bind(userId).run()
    expect(((await (await get('/api/v1/zones', undefined, headers)).json() as any).zones)).toHaveLength(0)

    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'add')"
    ).bind(userId, exampleId).run()

    const zones = await (await get('/api/v1/zones', undefined, headers)).json() as any
    expect(zones.zones).toHaveLength(1)
    expect(zones.zones[0].id).toBe(exampleId)
  })

  it('creates, updates and deletes a record end-to-end through the API', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    // 'delete' implies edit in the hierarchy; without it the DELETE step
    // would (correctly) be refused.
    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'delete') ON CONFLICT(user_id, domain_id) DO UPDATE SET level = 'delete'"
    ).bind(userId, exampleId).run()
    if (!(await tokenExists(TOKEN))) await seedApiToken(env.record_manager_db, userId, TOKEN)
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }

    const created = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ type: 'A', name: 'api-test', content: '198.51.100.4', ttl: 300 })
    })
    expect(created.status).toBe(201)
    const record = ((await created.json()) as any).record
    expect(record.id).toMatch(/^rec-/)

    const updated = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records/${record.id}`, {
      method: 'PUT',
      redirect: 'manual',
      headers,
      body: JSON.stringify({ type: 'A', name: 'api-test', content: '198.51.100.5', ttl: 60 })
    })
    expect(updated.status).toBe(200)

    const deleted = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records/${record.id}`, {
      method: 'DELETE',
      redirect: 'manual',
      headers: { authorization: `Bearer ${TOKEN}` }
    })
    expect(deleted.status).toBe(200)

    // History keeps all three events; metadata/permission rows are gone.
    const history = await env.record_manager_db.prepare(
      'SELECT action FROM record_history WHERE record_id = ? ORDER BY id'
    ).bind(record.id).all<any>()
    expect(history.results.map(h => h.action)).toEqual(['CREATE', 'UPDATE', 'DELETE'])
    const meta = await env.record_manager_db.prepare(
      'SELECT * FROM record_metadata WHERE record_id = ?'
    ).bind(record.id).first()
    expect(meta).toBeNull()
  })

  it('answers structured JSON errors even on early-exit failure paths', async () => {
    const TOKEN2 = `rm_${'b'.repeat(64)}`
    await seedWorldAndDomains()
    const ownerId = await seedUser(env.record_manager_db, { email: OWNER, role: 'owner' })
    await seedApiToken(env.record_manager_db, ownerId, TOKEN2)
    const headers = { authorization: `Bearer ${TOKEN2}`, 'content-type': 'application/json' }

    // Unknown zone id: PUT/DELETE must return JSON 404 — an earlier version
    // fell through these branches and crashed with an empty handler result.
    for (const method of ['PUT', 'DELETE'] as const) {
      const res = await SELF.fetch(`http://localhost/api/v1/zones/999999/records/rec-x`, {
        method, redirect: 'manual', headers,
        ...(method === 'PUT' ? { body: JSON.stringify({ type: 'A', name: 'x', content: '1.1.1.1' }) } : {})
      })
      expect(res.status).toBe(404)
      expect((await res.json() as any).error).toContain('Zone not found')
    }
    const noBody = await SELF.fetch(`http://localhost/api/v1/zones/999999/records/rec-x`, {
      method: 'DELETE', redirect: 'manual', headers: { authorization: `Bearer ${TOKEN2}` }
    })
    expect(noBody.status).toBe(404)
  })

  it('rejects invalid input and blacklisted names, then refuses read-level writers', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    // Gates run in order: permission first, validation second — so invalid
    // payloads are only judged once the caller may write at all.
    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'add') ON CONFLICT(user_id, domain_id) DO UPDATE SET level = 'add'"
    ).bind(userId, exampleId).run()
    if (!(await tokenExists(TOKEN))) await seedApiToken(env.record_manager_db, userId, TOKEN)
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }
    const createRecord = (body: any) => SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST', redirect: 'manual', headers, body: JSON.stringify(body)
    })

    const invalid = await createRecord({ type: 'BOGUS', name: '', content: '' })
    expect(invalid.status).toBe(400)
    expect(((await invalid.json()) as any).error).toContain('Record type')

    await env.record_manager_db.prepare(
      'INSERT INTO blacklist (pattern) VALUES (?) ON CONFLICT(pattern) DO NOTHING'
    ).bind('protected.example.com').run()
    try {
      const blocked = await createRecord({ type: 'A', name: 'protected.example.com', content: '192.0.2.9' })
      expect(blocked.status).toBe(403)

      // The web form path enforces the same protection for the same actor.
      const cookie = await freshSessionCookie(env.record_manager_db, OWNER)
      const formBlocked = await post(`/domains/${exampleId}/records`, {
        cookie,
        form: { type: 'A', name: 'protected.example.com', content: '192.0.2.9', ttl: '300' }
      })
      expect(formBlocked.status).toBe(302) // back to the page with an error flash

      const audit = await env.record_manager_db.prepare(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'CREATE_BLOCKED'"
      ).first<any>()
      expect(audit.n).toBeGreaterThan(0)
    } finally {
      await env.record_manager_db.prepare("DELETE FROM blacklist WHERE pattern = 'protected.example.com'").run()
    }

    // Downgrade to read-only: even a perfectly valid write is now refused.
    await env.record_manager_db.prepare(
      "UPDATE permissions SET level = 'read' WHERE user_id = ? AND domain_id = ?"
    ).bind(userId, exampleId).run()
    const forbidden = await createRecord({ type: 'TXT', name: 'nope', content: 'x' })
    expect(forbidden.status).toBe(403)
  })

  it('PUT inherits omitted optional fields instead of resetting them', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'delete') ON CONFLICT(user_id, domain_id) DO UPDATE SET level = 'delete'"
    ).bind(userId, exampleId).run()
    const token = `rm_${'c'.repeat(64)}`
    if (!(await tokenExists(token))) await seedApiToken(env.record_manager_db, userId, token)
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }

    const created = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'MX', name: 'merge-test', content: 'mail.example.com', ttl: 300, priority: 25 })
    })
    expect(created.status).toBe(201)
    const { id } = ((await created.json()) as any).record

    // Only the content changes — no ttl, priority or proxied in the body.
    const updated = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records/${id}`, {
      method: 'PUT', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'MX', name: 'merge-test', content: 'mail2.example.com' })
    })
    expect(updated.status).toBe(200)

    const list = await (await get(`/api/v1/zones/${exampleId}/records`, undefined, { authorization: `Bearer ${token}` })).json() as any
    const record = list.records.find((r: any) => r.id === id)
    expect(record.content).toBe('mail2.example.com')
    expect(record.ttl).toBe(300)
    expect(record.priority).toBe(25)

    // A missing record now 404s before any mutation is attempted.
    const ghost = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records/rec-does-not-exist`, {
      method: 'PUT', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'A', name: 'x', content: '192.0.2.1' })
    })
    expect(ghost.status).toBe(404)
  })

  it('hides records from API clients whose clearance was revoked', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'delete') ON CONFLICT(user_id, domain_id) DO UPDATE SET level = 'delete'"
    ).bind(userId, exampleId).run()
    const token = `rm_${'d'.repeat(64)}`
    if (!(await tokenExists(token))) await seedApiToken(env.record_manager_db, userId, token)
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }

    const keep = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'A', name: 'revoke-keep', content: '192.0.2.10' })
    })
    const drop = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'A', name: 'revoke-drop', content: '192.0.2.11' })
    })
    const keepId = ((await keep.json()) as any).record.id
    const dropId = ((await drop.json()) as any).record.id

    // Revoke all domain access, re-grant on exactly one record.
    await env.record_manager_db.batch([
      env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ?').bind(userId),
      env.record_manager_db.prepare(
        "INSERT INTO record_permissions (user_id, domain_id, record_id, level) VALUES (?, ?, ?, 'read')"
      ).bind(userId, exampleId, keepId)
    ])

    const list = await (await get(`/api/v1/zones/${exampleId}/records`, undefined, { authorization: `Bearer ${token}` })).json() as any
    const names = list.records.map((r: any) => r.name)
    expect(names).toContain('revoke-keep')
    // The second record was created by this very token, but creation must not
    // imply visibility once the clearance is gone.
    expect(names).not.toContain('revoke-drop')
    expect(list.records.find((r: any) => r.id === dropId)).toBeUndefined()
  })

  it('answers 404 (not 403) for zones an uncleared user cannot view', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    await env.record_manager_db.batch([
      env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ?').bind(userId),
      env.record_manager_db.prepare('DELETE FROM record_permissions WHERE user_id = ?').bind(userId)
    ])

    // Web UI: domain detail must not leak existence via a 403.
    const web = await get(`/domains/${exampleId}`, await freshSessionCookie(env.record_manager_db, USER))
    expect(web.status).toBe(404)

    // JSON API: same policy.
    const token = `rm_${'e'.repeat(64)}`
    if (!(await tokenExists(token))) await seedApiToken(env.record_manager_db, userId, token)
    const apiRes = await get(`/api/v1/zones/${exampleId}`, undefined, { authorization: `Bearer ${token}` })
    expect(apiRes.status).toBe(404)
  })

  it('creates and edits less-common record types (NS, SRV, CAA)', async () => {
    const { exampleId, userId } = await seedWorldAndDomains()
    await env.record_manager_db.prepare(
      "INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, 'edit') ON CONFLICT(user_id, domain_id) DO UPDATE SET level = 'edit'"
    ).bind(userId, exampleId).run()
    const token = `rm_${'f'.repeat(64)}`
    if (!(await tokenExists(token))) await seedApiToken(env.record_manager_db, userId, token)
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' }
    const create = (body: any) => SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records`, {
      method: 'POST', redirect: 'manual', headers, body: JSON.stringify(body)
    })

    // NS: proxied is forced off even when requested (Cloudflare rejects it).
    const ns = await create({ type: 'NS', name: 'example.com', content: 'ns1.example.com', ttl: 3600, proxied: true })
    expect(ns.status).toBe(201)
    expect(((await ns.json()) as any).record.proxied).toBe(false)

    // SRV: structured rdata rides inside content.
    const srv = await create({ type: 'SRV', name: '_sip._tcp.example.com', content: '10 60 5060 sip.example.com', ttl: 300 })
    expect(srv.status).toBe(201)
    const srvId = ((await srv.json()) as any).record.id

    const caa = await create({ type: 'CAA', name: 'example.com', content: '0 issue "letsencrypt.org"', ttl: 3600 })
    expect(caa.status).toBe(201)

    // Updating an SRV keeps its rdata intact when only TTL changes.
    const updated = await SELF.fetch(`http://localhost/api/v1/zones/${exampleId}/records/${srvId}`, {
      method: 'PUT', redirect: 'manual', headers,
      body: JSON.stringify({ type: 'SRV', name: '_sip._tcp.example.com', content: '10 60 5060 sip.example.com', ttl: 600 })
    })
    expect(updated.status).toBe(200)

    const list = await (await get(`/api/v1/zones/${exampleId}/records`, undefined, { authorization: `Bearer ${token}` })).json() as any
    const types = list.records.map((r: any) => r.type)
    expect(types).toContain('NS')
    expect(types).toContain('SRV')
    expect(types).toContain('CAA')
  })
})

// --- shared fixtures -------------------------------------------------------

let seeded: Promise<{ exampleId: number; userId: number; adminId: number }>
function seedWorldAndDomains() {
  // Idempotent: every test needs the same base state, first call seeds it.
  seeded ??= (async () => {
    const ids = await seedWorld()
    const domains = await seedDomains()
    return { ...ids, ...domains }
  })()
  return seeded
}

async function bumpAndGetEpoch(userId: number): Promise<number> {
  await env.record_manager_db.prepare(
    'UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?'
  ).bind(userId).run()
  const row = await env.record_manager_db.prepare('SELECT session_epoch FROM users WHERE id = ?').bind(userId).first<any>()
  return row.session_epoch
}

async function exampleZoneId(): Promise<string> {
  const w = await seedWorldAndDomains()
  return String(w.exampleId)
}

async function tokenExists(token: string): Promise<boolean> {
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))))
    .map(b => b.toString(16).padStart(2, '0')).join('')
  const row = await env.record_manager_db.prepare('SELECT id FROM api_tokens WHERE token_hash = ?').bind(digest).first()
  return !!row
}
