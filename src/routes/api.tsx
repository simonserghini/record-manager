import { Hono } from 'hono'
import { CloudflareClient } from '../cloudflare'
import {
  getPermissionLevel, canViewDomain, canAddRecords, canEditRecord, canDeleteRecord
} from '../lib/auth'
import { isBlacklisted, logAudit, writeRecordHistory } from '../lib/db'
import { validateRecordInput } from '../lib/validation'
import type { RecordInput } from '../lib/validation'
import { rateLimit } from '../lib/ratelimit'
import { resolveApiToken } from '../lib/apitokens'

type Bindings = { record_manager_db: D1Database }
type Variables = { settings: any; user: any; flash: any }

const api = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Burst protection per token owner — best-effort, in-isolate.
const READ_LIMIT = { limit: 120, windowMs: 60_000 }
const WRITE_LIMIT = { limit: 30, windowMs: 60_000 }

function fail(c: any, status: number, message: string) {
  return c.json({ error: message }, status as any)
}

// Every /api request must present a valid Bearer token; the token inherits
// the exact permission set of its owning user.
api.use('*', async (c, next) => {
  const resolved = await resolveApiToken(c.env.record_manager_db, c.req.header('authorization'))
  if (!resolved) return fail(c, 401, 'Provide a valid API token via "Authorization: Bearer <token>".')
  c.set('user', resolved.user)
  await next()
})

api.use('*', async (c, next) => {
  const user = c.get('user')
  const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)
  const budget = mutating ? WRITE_LIMIT : READ_LIMIT
  if (!rateLimit(`api:${user.id}:${mutating ? 'w' : 'r'}`, budget.limit, budget.windowMs)) {
    return fail(c, 429, 'Rate limit exceeded. Slow down and retry shortly.')
  }
  await next()
})

/** Loads a managed domain by local id, or null. */
async function loadDomain(db: D1Database, rawId: string) {
  const id = parseInt(rawId, 10)
  if (!Number.isSafeInteger(id) || id <= 0) return null
  return db.prepare('SELECT * FROM domains WHERE id = ?').bind(id).first<any>()
}

/**
 * Permission context for one record, mirroring the web UI's loadRecordContext:
 * domain-level clearance + record-level clearance + creatorship.
 */
async function recordContext(db: D1Database, user: any, domainId: number, recordId: string) {
  const userLevel = await getPermissionLevel(db, user, domainId)
  const rpRow = await db.prepare(
    'SELECT level FROM record_permissions WHERE user_id = ? AND domain_id = ? AND record_id = ?'
  ).bind(user.id, domainId, recordId).first<{ level: string }>()
  const metaRow = await db.prepare(
    'SELECT created_by_email FROM record_metadata WHERE record_id = ?'
  ).bind(recordId).first<{ created_by_email: string }>()

  const recordLevel = rpRow?.level ?? null
  const isCreatorOfRecord = metaRow?.created_by_email === user.email

  const canSee = ['owner', 'admin', 'manager'].includes(user.role) || !!userLevel || !!recordLevel || isCreatorOfRecord
  return { userLevel, recordLevel, isCreatorOfRecord, canSee }
}

/**
 * Parses a JSON body and maps it onto the same validation the forms use.
 * `provided` records which optional fields the caller actually sent, so the
 * update path can inherit current values for the rest instead of resetting
 * them to defaults.
 */
async function parseRecordBody(c: any): Promise<{ error: string } | { record: RecordInput; provided: { ttl: boolean; proxied: boolean; priority: boolean } }> {
  let body: any
  try {
    body = await c.req.json()
  } catch {
    return { error: 'Request body must be valid JSON.' }
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { error: 'Request body must be a JSON object.' }
  }

  const { errors, value: record } = validateRecordInput({
    type: String(body.type ?? ''),
    name: String(body.name ?? ''),
    content: String(body.content ?? ''),
    ttl: String(body.ttl ?? '1'),
    priority: body.priority === undefined || body.priority === null ? '' : String(body.priority),
    proxied: body.proxied ? 'on' : ''
  })
  if (!record) return { error: errors.join(' ') }
  return {
    record,
    provided: {
      ttl: body.ttl !== undefined,
      proxied: body.proxied !== undefined,
      priority: body.priority !== undefined && body.priority !== null
    }
  }
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

// Lists the zones this token's owner can see (local registry only — no
// Cloudflare round-trip). The `id` field feeds the records endpoints below.
api.get('/v1/zones', async (c) => {
  const user = c.get('user')
  const db = c.env.record_manager_db

  if (['owner', 'admin', 'manager'].includes(user.role)) {
    const { results } = await db.prepare('SELECT id, zone_id, zone_name, created_at FROM domains ORDER BY zone_name').all()
    return c.json({ zones: results })
  }

  const [{ results: perms }, { results: recPerms }] = await db.batch([
    db.prepare('SELECT domain_id FROM permissions WHERE user_id = ?').bind(user.id),
    db.prepare('SELECT DISTINCT domain_id FROM record_permissions WHERE user_id = ?').bind(user.id)
  ]) as any
  const allowed = new Set([...perms, ...recPerms].map((p: any) => p.domain_id))
  const { results } = await db.prepare('SELECT id, zone_id, zone_name, created_at FROM domains ORDER BY zone_name').all()
  return c.json({ zones: (results as any[]).filter(d => allowed.has(d.id)) })
})

api.get('/v1/zones/:id', async (c) => {
  const user = c.get('user')
  const domain = await loadDomain(c.env.record_manager_db, c.req.param('id'))
  if (!domain) return fail(c, 404, 'Zone not found.')

  const userLevel = await getPermissionLevel(c.env.record_manager_db, user, domain.id)
  const { results: rpRows } = await c.env.record_manager_db.prepare(
    'SELECT DISTINCT domain_id FROM record_permissions WHERE user_id = ? AND domain_id = ?'
  ).bind(user.id, domain.id).all()
  // 404 rather than 403: an uncleared caller must not learn the zone exists.
  if (!canViewDomain(user.role, userLevel, rpRows.length > 0)) return fail(c, 404, 'Zone not found.')

  return c.json({ zone: { id: domain.id, zone_id: domain.zone_id, name: domain.zone_name } })
})

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

api.get('/v1/zones/:id/records', async (c) => {
  const user = c.get('user')
  const db = c.env.record_manager_db
  const domain = await loadDomain(db, c.req.param('id'))
  if (!domain) return fail(c, 404, 'Zone not found.')

  const userLevel = await getPermissionLevel(db, user, domain.id)
  const { results: rpRows } = await db.prepare(
    'SELECT DISTINCT domain_id FROM record_permissions WHERE user_id = ? AND domain_id = ?'
  ).bind(user.id, domain.id).all()
  const hasRecordPerms = rpRows.length > 0
  if (!canViewDomain(user.role, userLevel, hasRecordPerms)) return fail(c, 404, 'Zone not found.')

  let records: any[]
  try {
    records = await new CloudflareClient(c.get('settings').CF_API_TOKEN).listRecords(domain.zone_id)
  } catch (e: any) {
    return fail(c, 502, `Cloudflare API error: ${e?.message || 'unknown'}`)
  }

  // Record-level-only viewers see just their cleared records — exactly the
  // policy the web UI enforces. Records the user once *created* do NOT stay
  // visible after their clearance is revoked: revoke means revoke.
  const fullZoneView = canViewDomain(user.role, userLevel, false)
  if (!fullZoneView) {
    const { results: mine } = await db.prepare(
      'SELECT DISTINCT record_id FROM record_permissions WHERE user_id = ? AND domain_id = ?'
    ).bind(user.id, domain.id).all()
    const allowedIds = new Set((mine as any[]).map(r => r.record_id))
    records = records.filter(r => allowedIds.has(r.id))
  }

  return c.json({ records })
})

api.post('/v1/zones/:id/records', async (c) => {
  const user = c.get('user')
  const db = c.env.record_manager_db
  const domain = await loadDomain(db, c.req.param('id'))
  if (!domain) return fail(c, 404, 'Zone not found.')

  const userLevel = await getPermissionLevel(db, user, domain.id)
  if (!canAddRecords(user.role, userLevel)) return fail(c, 403, 'Forbidden.')

  const parsed = await parseRecordBody(c)
  if ('error' in parsed) return fail(c, 400, parsed.error!)
  const record = parsed.record!

  if (await isBlacklisted(db, record.name)) {
    await logAudit(db, user.email, 'CREATE_BLOCKED', 'RECORD', record.name, { domain: domain.zone_name, reason: 'blacklisted', via: 'api' })
    return fail(c, 403, `"${record.name}" is protected by a blacklist rule.`)
  }

  let result: any
  try {
    result = await new CloudflareClient(c.get('settings').CF_API_TOKEN).createRecord(domain.zone_id, record)
  } catch (e: any) {
    return fail(c, 502, `Cloudflare rejected the record: ${e?.message || 'unknown'}`)
  }

  await logAudit(db, user.email, 'CREATE', 'RECORD', record.name, { domain: domain.zone_name, type: record.type, via: 'api' })
  if (result?.id) {
    await db.batch([
      db.prepare('INSERT INTO record_metadata (record_id, domain_id, created_by_email) VALUES (?, ?, ?)')
        .bind(result.id, domain.id, user.email),
      db.prepare("INSERT INTO record_history (domain_id, record_id, name, type, content, ttl, action, actor_email) VALUES (?, ?, ?, ?, ?, ?, 'CREATE', ?)")
        .bind(domain.id, result.id, record.name, record.type, record.content, record.ttl ?? null, user.email)
    ])
  } else {
    await writeRecordHistory(db, domain.id, '', record, 'CREATE', user.email)
  }

  return c.json({ record: result }, 201)
})

/**
 * Returns either the JSON error Response to send as-is, or the loaded
 * context. Every failure path RETURNS its response — an earlier version
 * fired fail() as a statement and fell through, leaving the handler with
 * nothing to return.
 */
async function loadRecordForMutation(
  c: any, needEdit: boolean, needDelete: boolean
): Promise<Response | { user: any; domain: any; recordId: string }> {
  const user = c.get('user')
  const db = c.env.record_manager_db
  const domain = await loadDomain(db, c.req.param('id'))
  if (!domain) return fail(c, 404, 'Zone not found.')

  const recordId = c.req.param('recordId') || ''
  const ctx = await recordContext(db, user, domain.id, recordId)
  if (!ctx.canSee) return fail(c, 403, 'Forbidden.')
  if (needEdit && !canEditRecord({ role: user.role, userLevel: ctx.userLevel, recordLevel: ctx.recordLevel, isCreatorOfRecord: ctx.isCreatorOfRecord })) {
    return fail(c, 403, 'Forbidden.')
  }
  if (needDelete && !canDeleteRecord({ role: user.role, userLevel: ctx.userLevel, recordLevel: ctx.recordLevel, isCreatorOfRecord: ctx.isCreatorOfRecord })) {
    return fail(c, 403, 'Forbidden.')
  }
  return { user, domain, recordId }
}

api.put('/v1/zones/:id/records/:recordId', async (c) => {
  const loaded = await loadRecordForMutation(c, true, false)
  if (loaded instanceof Response) return loaded
  const { user, domain, recordId } = loaded

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let existing: any
  try {
    existing = (await cf.listRecords(domain.zone_id)).find((r: any) => r.id === recordId)
  } catch (e: any) {
    return fail(c, 502, `Cloudflare API error: ${e?.message || 'unknown'}`)
  }
  if (!existing) return fail(c, 404, 'Record not found.')

  const parsed = await parseRecordBody(c)
  if ('error' in parsed) return fail(c, 400, parsed.error!)
  const record = parsed.record!

  // PUT replaces the record, but optional fields the caller omitted inherit
  // their current values — otherwise every update would silently unproxy the
  // record and reset its TTL to Auto / drop its MX priority.
  if (!parsed.provided.ttl) record.ttl = existing.ttl
  if (!parsed.provided.proxied) record.proxied = !!existing.proxied
  if (!parsed.provided.priority && record.type === 'MX' && existing.type === 'MX') {
    record.priority = existing.priority ?? null
  }

  if (await isBlacklisted(c.env.record_manager_db, record.name)) {
    await logAudit(c.env.record_manager_db, user.email, 'UPDATE_BLOCKED', 'RECORD', record.name, { domain: domain.zone_name, reason: 'blacklisted', via: 'api' })
    return fail(c, 403, `"${record.name}" is protected by a blacklist rule.`)
  }

  try {
    await cf.updateRecord(domain.zone_id, recordId, record)
  } catch (e: any) {
    return fail(c, 502, `Cloudflare rejected the update: ${e?.message || 'unknown'}`)
  }

  await logAudit(c.env.record_manager_db, user.email, 'UPDATE', 'RECORD', record.name, { domain: domain.zone_name, type: record.type, via: 'api' })
  await writeRecordHistory(c.env.record_manager_db, domain.id, recordId, record, 'UPDATE', user.email)
  return c.json({ ok: true, record })
})

api.delete('/v1/zones/:id/records/:recordId', async (c) => {
  const loaded = await loadRecordForMutation(c, false, true)
  if (loaded instanceof Response) return loaded
  const { user, domain, recordId } = loaded

  let deletedName = recordId
  let deletedSnapshot: any = null
  try {
    const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
    const existing = (await cf.listRecords(domain.zone_id)).find((r: any) => r.id === recordId)
    if (existing) {
      deletedName = existing.name
      deletedSnapshot = existing
      await cf.deleteRecord(domain.zone_id, recordId)
    }
  } catch (e: any) {
    return fail(c, 502, `Cloudflare rejected the deletion: ${e?.message || 'unknown'}`)
  }

  await c.env.record_manager_db.batch([
    c.env.record_manager_db.prepare('DELETE FROM record_metadata WHERE record_id = ?').bind(recordId),
    c.env.record_manager_db.prepare('DELETE FROM record_permissions WHERE record_id = ?').bind(recordId)
  ])
  await writeRecordHistory(
    c.env.record_manager_db, domain.id, recordId,
    deletedSnapshot ?? { name: deletedName, type: 'UNKNOWN', content: '', ttl: undefined },
    'DELETE', user.email
  )
  await logAudit(c.env.record_manager_db, user.email, 'DELETE', 'RECORD', deletedName, { domain: domain.zone_name, record_id: recordId, via: 'api' })
  return c.json({ ok: true })
})

export default api
