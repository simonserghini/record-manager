import { Hono } from 'hono'
import type { Context } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'
import { CloudflareClient } from '../cloudflare'
import { logAudit, isBlacklisted, matchBlacklist, writeRecordHistory } from '../lib/db'
import {
  getPermissionLevel, can, canViewDomain, canManageDelegation, canAddRecords,
  canEditRecord, canDeleteRecord, GLOBAL_ROLES, isValidLevel, RECORD_LEVEL_KEYS,
  LEVEL_KEYS
} from '../lib/auth'
import type { Role } from '../lib/auth'
import { setFlash } from '../lib/session'
import { rateLimit } from '../lib/ratelimit'
import { Badge, Button } from '../templates/components'
import { parseId, validateRecordInput, RECORD_TYPES } from '../lib/validation'
import { parseBindZoneFile, parseCsv, formatRecordsBind, formatRecordsCsv, IMPORT_MAX_ENTRIES } from '../lib/zonefiles'

type Bindings = {
  record_manager_db: D1Database
}

type Variables = {
  settings: any
  user: any
  systemSecret: string
  flash: any
}

type Env = { Bindings: Bindings; Variables: Variables }
type AppContext = Context<Env>

const domains = new Hono<Env>()

const LEVELS = [
  { key: 'read', short: 'READ', desc: 'Read-only access' },
  { key: 'add', short: 'ADD', desc: 'Create new records' },
  { key: 'edit_own', short: 'EDIT OWN', desc: 'Everything below + edit your own records' },
  { key: 'edit', short: 'EDIT ANY', desc: 'Everything below + edit any record' },
  // Each rung implies the ones under it, so DEL OWN also grants editing of
  // every record on the zone — the copy must not hide that.
  { key: 'delete_own', short: 'DEL OWN', desc: 'Edit any record + delete your own' },
  { key: 'delete', short: 'DEL ANY', desc: 'Full control of every record' },
  { key: 'domain_admin', short: 'ADMIN', desc: 'All of the above + delegate access' }
]

/** Authenticated user or a redirect response. */
function requireUser(c: AppContext): { user: any } | { denied: Response } {
  const user = c.get('user')
  if (!user) return { denied: c.redirect('/') }
  return { user }
}

async function loadDomain(c: AppContext, rawId: string | undefined) {
  const domainId = parseId(rawId ?? '')
  if (!domainId) return null
  return c.env.record_manager_db.prepare('SELECT * FROM domains WHERE id = ?').bind(domainId).first<any>()
}

/**
 * Guard for delegation management within one domain: global roles qualify,
 * as does an explicit 'domain_admin' clearance on that specific domain.
 */
async function requireDelegationRights(c: AppContext, domainId: number): Promise<{ user: any } | { denied: Response }> {
  const user = c.get('user')
  if (!user) return { denied: c.text('Unauthorized', 401) }
  const level = await getPermissionLevel(c.env.record_manager_db, user, domainId)
  if (!canManageDelegation(user.role, level)) return { denied: c.text('Forbidden', 403) }
  return { user }
}

// ---------------------------------------------------------------------------
// Zone listing & sync management (owner-only mutations)
// ---------------------------------------------------------------------------

domains.get('/', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let zones: any[] = []
  try {
    zones = await cf.listZones()
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Could not reach Cloudflare: ${e.message}` })
  }

  const db = c.env.record_manager_db
  const [{ results: syncedDomains }, { results: myPerms }, { results: myRecordPerms }] = await db.batch([
    db.prepare('SELECT zone_id FROM domains'),
    db.prepare('SELECT domain_id FROM permissions WHERE user_id = ?').bind(user.id),
    db.prepare('SELECT DISTINCT domain_id FROM record_permissions WHERE user_id = ?').bind(user.id)
  ]) as any

  // Regular users only see zones they hold some clearance for.
  const isGlobal = GLOBAL_ROLES.includes(user.role as Role)
  const syncedRows = syncedDomains as any[]
  const allowedDomainIds = new Set([...(myPerms as any[]), ...(myRecordPerms as any[])].map((p: any) => p.domain_id))
  const { results: visibleDomains } = isGlobal
    ? { results: syncedRows }
    : { results: syncedRows.filter((d: any) => allowedDomainIds.has(d.id)) }

  const syncedIds = new Set(syncedRows.map((d: any) => d.zone_id))
  const visibleZoneIds = new Set(visibleDomains.map((d: any) => d.zone_id))

  const visibleZones = isGlobal ? zones : zones.filter(z => visibleZoneIds.has(z.id))

  return c.html(layout('Cloudflare Zones', (
    <Fragment>
    <div class="mb-8 border-b border-slate-200 pb-5">
      <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Account Zones</h2>
      <p class="text-slate-500 text-sm">Enable or disable DNS synchronization for Cloudflare active domains.</p>
    </div>

    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-slate-200">
        <thead class="table-header rounded-lg">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Zone Name</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">ID</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Status</th>
            <th class="px-4 py-3 text-right text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Management</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-transparent">
          {visibleZones.map((z: any) => (
            <tr class="hover:bg-slate-50/50 transition-colors" key={z.id}>
              <td class="px-4 py-4 whitespace-nowrap text-sm font-semibold text-slate-900">{z.name}</td>
              <td class="px-4 py-4 whitespace-nowrap text-xs text-slate-400 font-mono">{z.id}</td>
              <td class="px-4 py-4 whitespace-nowrap">
                <Badge type={z.status === 'active' ? 'success' : 'warning'}>{z.status}</Badge>
              </td>
              <td class="px-4 py-4 whitespace-nowrap text-right text-sm font-bold">
                {user.role === 'owner' ? (
                  syncedIds.has(z.id)
                    ? <form method="post" action="/domains/unsync" class="inline"><input type="hidden" name="id" value={z.id} /><button type="submit" class="text-rose-500 hover:text-rose-600 font-bold transition">Disable Sync</button></form>
                    : <form method="post" action="/domains/sync" class="inline"><input type="hidden" name="id" value={z.id} /><input type="hidden" name="name" value={z.name} /><button type="submit" class="text-indigo-600 hover:text-indigo-500 font-bold transition">Enable Sync</button></form>
                ) : <span class="text-slate-400 italic text-xs font-mono">Owner Required</span>}
              </td>
            </tr>
          ))}
          {visibleZones.length === 0 && (
            <tr><td colspan={4} class="px-4 py-10 text-center text-xs text-slate-400 italic font-mono">No zones available for your account.</td></tr>
          )}
        </tbody>
      </table>
    </div>
    </Fragment>
  ), user, c.get('flash')))
})

// Both routes were registered twice before; single definitions now, with the
// zone verified against the live account instead of trusting the form.
domains.post('/sync', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user
  if (user.role !== 'owner') return c.text('Forbidden', 403)

  const body = await c.req.parseBody() as Record<string, string>
  const zoneId = String(body.id || '')

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let zone: any
  try {
    zone = (await cf.listZones()).find((z: any) => z.id === zoneId)
  } catch {
    zone = null
  }
  if (!zone) {
    await setFlash(c, { type: 'error', text: 'That zone does not exist on the connected Cloudflare account.' })
    return c.redirect('/domains')
  }

  await c.env.record_manager_db.prepare(
    'INSERT INTO domains (zone_id, zone_name) VALUES (?, ?) ON CONFLICT(zone_id) DO UPDATE SET zone_name = excluded.zone_name'
  ).bind(zone.id, zone.name).run()

  await logAudit(c.env.record_manager_db, user.email, 'SYNC', 'DOMAIN', zone.name, { zone_id: zone.id })
  await setFlash(c, { type: 'success', text: `Domain ${zone.name} is now synced.` })
  return c.redirect('/domains')
})

domains.post('/unsync', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user
  if (user.role !== 'owner') return c.text('Forbidden', 403)

  const body = await c.req.parseBody() as Record<string, string>
  const zoneId = String(body.id || '')
  const domain = await c.env.record_manager_db.prepare('SELECT id, zone_name FROM domains WHERE zone_id = ?').bind(zoneId).first<any>()

  if (!domain) {
    await setFlash(c, { type: 'error', text: 'That zone is not currently synced.' })
    return c.redirect('/domains')
  }

  await c.env.record_manager_db.prepare('DELETE FROM domains WHERE zone_id = ?').bind(zoneId).run()

  await logAudit(c.env.record_manager_db, user.email, 'UNSYNC', 'DOMAIN', domain.zone_name, { zone_id: zoneId })
  await setFlash(c, { type: 'info', text: `Sync disabled for ${domain.zone_name}.` })
  return c.redirect('/domains')
})

// ---------------------------------------------------------------------------
// Domain detail: record browser + delegation console
// ---------------------------------------------------------------------------

domains.get('/:id', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  const domainId = parseId(c.req.param('id'))
  const domain = domainId ? await loadDomain(c, c.req.param('id')) : null
  if (!domain) return c.text('Domain not found', 404)

  const db = c.env.record_manager_db

  const userLevel = await getPermissionLevel(db, user, domainId!)

  const { results: recordPerms } = await db.prepare(
    'SELECT record_id, level FROM record_permissions WHERE user_id = ? AND domain_id = ?'
  ).bind(user.id, domainId!).all()

  const recordPermMap = new Map((recordPerms as any[]).map(rp => [rp.record_id, rp.level]))
  // Visitors without any clearance get 404, not 403 — a Forbidden tells them
  // the internal domain id exists; "not found" hides it entirely.
  if (!canViewDomain(user.role, userLevel, recordPermMap.size > 0)) return c.text('Domain not found', 404)

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let records: any[] = []
  try {
    records = await cf.listRecords(domain.zone_id)
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Could not load DNS records: ${e.message}` })
  }

  const isGlobal = GLOBAL_ROLES.includes(user.role as Role)

  // Record-level-only users see nothing beyond their granted records.
  if (!isGlobal && !userLevel) {
    records = records.filter(r => recordPermMap.has(r.id))
  }

  const { results: ownership } = await db.prepare(
    'SELECT record_id, created_by_email FROM record_metadata WHERE domain_id = ?'
  ).bind(domainId!).all()
  const ownershipMap = new Map((ownership as any[]).map(o => [o.record_id, o.created_by_email]))

  const canAdd = canAddRecords(user.role, userLevel)
  const isDomainAdmin = canManageDelegation(user.role, userLevel)

  let domainPermissionsList: any[] = []
  let recordPermissionsList: any[] = []
  let allUsersList: any[] = []

  if (isDomainAdmin) {
    const [{ results: dp }, { results: rp }, { results: uList }] = await db.batch([
      db.prepare('SELECT p.*, u.email FROM permissions p JOIN users u ON p.user_id = u.id WHERE p.domain_id = ? ORDER BY u.email ASC').bind(domainId!),
      db.prepare('SELECT rp.*, u.email FROM record_permissions rp JOIN users u ON rp.user_id = u.id WHERE rp.domain_id = ? ORDER BY u.email ASC').bind(domainId!),
      db.prepare("SELECT id, email, role FROM users WHERE role = 'user' ORDER BY email ASC")
    ]) as any
    domainPermissionsList = dp as any[]
    recordPermissionsList = rp as any[]
    allUsersList = uList as any[]
  }

  const recordNameById = new Map(records.map(r => [r.id, r.name]))
  const presentTypes = Array.from(new Set(records.map(r => r.type))).sort()

  return c.html(layout(`Manage ${domain.zone_name}`, (
    <Fragment>
    <div class="flex justify-between items-center mb-8 pb-4 border-b border-slate-200">
      <div>
        <h2 class="text-2xl font-bold text-slate-900 tracking-tight">{domain.zone_name}</h2>
        <p class="text-sm text-slate-500">Configure real-time DNS records on Cloudflare edge servers.</p>
      </div>
      <div class="flex gap-2 items-center flex-wrap">
        <a href={`/domains/${domainId}/export?format=bind`} title="Download zone file" class="px-3 py-2 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-bold text-xs tracking-wider transition bg-white">Export BIND</a>
        <a href={`/domains/${domainId}/export?format=csv`} title="Download CSV" class="px-3 py-2 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-bold text-xs tracking-wider transition bg-white">Export CSV</a>
        {canAdd && (
          <Button data-toggle-target="#import-panel" variant="secondary">Import</Button>
        )}
        <a href={`/domains/${domainId}/history`} class="px-5 py-2.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-50 font-bold text-xs tracking-wider transition bg-white flex items-center">
          <svg class="h-4 w-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          History
        </a>
        {canAdd && (
          <Button data-toggle-target="#add-record-panel">
            <svg class="h-4 w-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" /></svg>
            Add Record
          </Button>
        )}
      </div>
    </div>

    {/* Add Record Panel */}
    {canAdd && (
      <div id="add-record-panel" class="hidden mb-8 bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <h3 class="text-xs font-bold text-slate-700 font-mono mb-4 uppercase tracking-wider">Create New DNS Record</h3>
        <form method="post" action={`/domains/${domainId}/records`}>
          <div class="grid grid-cols-1 md:grid-cols-6 gap-4 items-end">
            <div class="md:col-span-1">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">Type</label>
              <select name="type" class="w-full text-xs">
                {RECORD_TYPES.map(t => <option value={t} key={t}>{t}</option>)}
              </select>
            </div>
            <div class="md:col-span-2">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">Name</label>
              <input type="text" name="name" placeholder="sub.example.com" required maxlength={255} class="w-full text-xs font-mono" />
            </div>
            <div class="md:col-span-3">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">Content</label>
              <input type="text" name="content" placeholder="203.0.113.10" required maxlength={2048} class="w-full text-xs font-mono" />
              <p class="mt-1.5 text-[10px] text-slate-400 font-mono" data-content-hint></p>
            </div>
            <div class="md:col-span-1">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">TTL</label>
              <select name="ttl" class="w-full text-xs font-mono">
                <option value="1">Auto</option>
                <option value="60">1 min</option>
                <option value="300">5 min</option>
                <option value="600">10 min</option>
                <option value="1800">30 min</option>
                <option value="3600">1 hour</option>
                <option value="7200">2 hours</option>
                <option value="86400">1 day</option>
              </select>
            </div>
            <div class="md:col-span-1">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">MX Priority</label>
              <input type="number" name="priority" min="0" max="65535" placeholder="10" class="w-full text-xs font-mono" />
            </div>
            <div class="md:col-span-1 flex flex-col items-center pb-2.5">
               <label class="block text-xs font-bold text-slate-500 mb-1.5 uppercase font-mono">Proxied</label>
               <input type="checkbox" name="proxied" class="h-4 w-4" />
            </div>
            <div class="hidden md:block md:col-span-2"></div>
            <div class="md:col-span-1">
              <button type="submit" class="w-full btn-primary py-2 rounded-lg font-bold text-xs">Create</button>
            </div>
          </div>
        </form>
      </div>
    )}

    {canAdd && (
      <div id="import-panel" class="hidden mb-8 bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <h3 class="text-xs font-bold text-slate-700 font-mono mb-1 uppercase tracking-wider">Import Records</h3>
        <p class="text-[10px] text-slate-400 mb-4 font-mono">Paste a BIND zone file or CSV (name,type,content,ttl,priority,proxied). Max {500} entries — every entry is validated and checked against the blacklist before it reaches Cloudflare.</p>
        <form method="post" action={`/domains/${domainId}/import`} class="space-y-4">
          <div class="flex gap-4 items-end">
            <div class="w-40">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">Format</label>
              <select name="format" class="w-full text-xs">
                <option value="bind">BIND zone file</option>
                <option value="csv">CSV</option>
              </select>
            </div>
            <button type="submit" class="btn-primary px-5 py-2 rounded-lg font-bold text-xs">Import Records</button>
          </div>
          <textarea name="zonefile" rows={8} required placeholder={'www.example.com.\t3600\tIN\tA\t203.0.113.10\nmx.example.com.\t3600\tIN\tMX\t10 mail.example.com.'} class="w-full text-xs font-mono"></textarea>
        </form>
      </div>
    )}

    <div class="mb-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 w-full lg:w-auto">
        <div class="relative w-full sm:max-w-xs">
          <input type="text" id="record-search" placeholder="Filter records…" aria-label="Filter records by name, type or content" data-record-search class="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg text-sm placeholder-slate-400 font-mono" />
          <svg class="absolute left-3 top-3 h-4 w-4 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
        {presentTypes.length > 1 && (
          <div class="flex items-center gap-1.5 flex-wrap" data-type-filters>
            <button type="button" data-type-filter="*" class="type-chip type-chip-active">All</button>
            {presentTypes.map(t => (
              <button type="button" data-type-filter={t} class="type-chip" key={t} aria-label={`Show only ${t} records`}>
                {t} <span class="opacity-60">{records.filter(r => r.type === t).length}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <div id="record-count" class="text-xs text-slate-500 font-mono whitespace-nowrap">Showing {records.length} of {records.length} records</div>
    </div>

    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-slate-200">
        <thead class="table-header rounded-lg">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Type</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Name</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Content</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">TTL</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Proxy</th>
            <th class="px-4 py-3 text-right text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Actions</th>
          </tr>
        </thead>
        <tbody id="record-table-body" class="bg-transparent divide-y divide-slate-100">
          {records.map((r: any) => {
            const creator = ownershipMap.get(r.id)
            const isCreatorOfRecord = creator === user.email
            const rPerm = recordPermMap.get(r.id)

            const editable = canEditRecord({ role: user.role, userLevel, recordLevel: rPerm, isCreatorOfRecord })
            const deletable = canDeleteRecord({ role: user.role, userLevel, recordLevel: rPerm, isCreatorOfRecord })

            return (
              <tr class="record-row hover:bg-slate-50/80 transition-colors" data-search={`${r.type} ${r.name} ${r.content}`} data-type={r.type} key={r.id}>
                <td class="px-4 py-4 whitespace-nowrap">
                  <div class="flex flex-col">
                    <Badge type="user">{r.type}</Badge>
                    {creator && <span class="text-[9px] text-slate-400 font-mono mt-1">{creator.split('@')[0]}</span>}
                  </div>
                </td>
                <td class="px-4 py-4 whitespace-nowrap">
                  <div class="text-sm font-semibold text-slate-900">{r.name}</div>
                </td>
                <td class="px-4 py-4 text-xs text-slate-600 font-mono break-all max-w-xs">{r.content}</td>
                <td class="px-4 py-4 whitespace-nowrap text-xs text-slate-600 font-mono">{r.ttl === 1 ? 'Auto' : r.ttl}</td>
                <td class="px-4 py-4 whitespace-nowrap">
                  {r.proxied ? (
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
                      <svg class="h-2 w-2 mr-1.5 text-amber-500" fill="currentColor" viewBox="0 0 8 8"><circle cx="4" cy="4" r="3" /></svg> Proxied
                    </span>
                  ) : (
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
                      <svg class="h-2 w-2 mr-1.5 text-slate-400" fill="currentColor" viewBox="0 0 8 8"><circle cx="4" cy="4" r="3" /></svg> DNS Only
                    </span>
                  )}
                </td>
                <td class="px-4 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div class="flex justify-end gap-2">
                    {editable && <a href={`/domains/${domainId}/records/${r.id}/edit`} class="text-indigo-600 hover:text-indigo-500 p-1.5 rounded transition hover:bg-indigo-50" title="Edit" aria-label={`Edit ${r.name}`}><svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg></a>}
                    {deletable && (
                      <form method="post" action={`/domains/${domainId}/records/${r.id}/delete`} class="inline" data-confirm="Are you sure?">
                        <button type="submit" class="text-rose-500 hover:text-rose-600 p-1.5 rounded transition hover:bg-rose-50" title="Delete" aria-label={`Delete ${r.name}`}>
                          <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                        </button>
                      </form>
                    )}
                  </div>
                </td>
              </tr>
            )
          })}
          {records.length === 0 && (
            <tr><td colspan={6} class="px-4 py-10 text-center text-xs text-slate-400 italic font-mono">No records visible for your access level.</td></tr>
          )}
          <tr data-no-matches class="hidden"><td colspan={6} class="px-4 py-10 text-center text-xs text-slate-400 italic font-mono">No records match your filters.</td></tr>
        </tbody>
      </table>
    </div>

    {isDomainAdmin && (
      <div class="mt-12 pt-8 border-t border-slate-200">
        <h3 class="text-xl font-bold text-slate-900 mb-2 tracking-tight">Zone Access Delegation</h3>
        <p class="text-slate-500 text-sm mb-6">Manage clearances and grant specific record privileges for this zone.</p>

        <div class="flex flex-col gap-8">
          {/* Domain-wide clearance matrix */}
          <div class="bg-white border border-slate-200 rounded-2xl p-6 w-full shadow-sm">
            <h4 class="text-xs font-bold text-slate-700 mb-4 uppercase tracking-wider font-mono">Domain Access Matrix</h4>
            <div class="divide-y divide-slate-200">
              {allUsersList.map((u: any) => {
                const currentPerm = domainPermissionsList.find(p => p.user_id === u.id)
                const currentLevel = currentPerm ? currentPerm.level : 'none'

                return (
                  <div class="py-3 flex flex-col xl:flex-row xl:items-center justify-between gap-3" key={u.id}>
                    <div class="flex flex-col">
                      <span class="text-slate-800 font-bold text-xs">{u.email}</span>
                      <span class="text-[9px] text-slate-400 font-mono">System Role: {u.role}</span>
                    </div>
                    <div class="inline-flex flex-wrap items-center bg-slate-100 p-1 rounded-xl border border-slate-200 gap-1">
                      <form method="post" action={`/domains/${domainId}/delegation/revoke-domain`} class="m-0">
                        <input type="hidden" name="user_id" value={u.id} />
                        <button type="submit" class={`px-2.5 py-1 text-[9px] font-bold rounded-lg transition-all ${currentLevel === 'none' ? 'bg-rose-500 text-white shadow-sm' : 'text-slate-500 hover:text-rose-600 hover:bg-slate-200/80'}`} title="No access">
                          NONE
                        </button>
                      </form>

                      {LEVELS.map(lvl => {
                        const isActive = currentLevel === lvl.key
                        return (
                          <form method="post" action={`/domains/${domainId}/delegation/grant-domain`} class="m-0" key={lvl.key}>
                            <input type="hidden" name="user_id" value={u.id} />
                            <input type="hidden" name="level" value={lvl.key} />
                            <button type="submit" class={`px-2.5 py-1 text-[9px] font-bold rounded-lg transition-all ${isActive ? 'bg-indigo-600 text-white shadow-sm' : 'text-slate-500 hover:text-indigo-600 hover:bg-slate-200/80'}`} title={lvl.desc}>
                              {lvl.short}
                            </button>
                          </form>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
              {allUsersList.length === 0 && (
                <p class="py-6 text-center text-xs text-slate-400 italic font-mono">No standard users provisioned yet.</p>
              )}
            </div>
          </div>

          {/* Record-level clearances */}
          <div class="bg-white border border-slate-200 rounded-2xl p-6 w-full shadow-sm">
            <h4 class="text-xs font-bold text-slate-700 mb-1 uppercase tracking-wider font-mono">Record-Level Clearances</h4>
            <p class="text-[10px] text-slate-400 mb-4 font-mono">Grant a user access to exactly one record — they will see nothing else in this zone.</p>

            {allUsersList.length > 0 && records.length > 0 ? (
              <form method="post" action={`/domains/${domainId}/delegation/grant-record`} class="flex flex-col md:flex-row gap-3 items-end pb-4 border-b border-slate-200">
                <div class="flex-1 w-full md:max-w-[220px]">
                  <label class="block text-[9px] font-bold text-slate-500 mb-1 uppercase font-mono">User</label>
                  <select name="user_id" class="w-full text-xs" required>
                    {allUsersList.map(u => <option value={u.id} key={u.id}>{u.email}</option>)}
                  </select>
                </div>
                <div class="flex-1 w-full md:max-w-[280px]">
                  <label class="block text-[9px] font-bold text-slate-500 mb-1 uppercase font-mono">Record</label>
                  <select name="record_id" class="w-full text-xs font-mono" required>
                    {records.map(r => <option value={r.id} key={r.id}>{r.type} · {r.name}</option>)}
                  </select>
                </div>
                <div class="w-full md:w-32">
                  <label class="block text-[9px] font-bold text-slate-500 mb-1 uppercase font-mono">Clearance</label>
                  <select name="level" class="w-full text-xs" required>
                    {RECORD_LEVEL_KEYS.map(lvl => (
                      <option value={lvl} key={lvl} title={lvl === 'delete' ? 'Delete includes edit rights on this record' : undefined}>
                        {lvl === 'delete' ? 'DELETE (incl. EDIT)' : lvl.toUpperCase()}
                      </option>
                    ))}
                  </select>
                </div>
                <button type="submit" class="btn-primary text-xs px-4 py-2 rounded-lg font-bold">Grant Access</button>
              </form>
            ) : (
              <p class="py-3 text-xs text-slate-400 italic font-mono">Provision standard users and sync records first.</p>
            )}

            <div class="divide-y divide-slate-100">
              {recordPermissionsList.map(rp => (
                <div class="py-2.5 flex items-center justify-between gap-3" key={`${rp.user_id}-${rp.record_id}`}>
                  <div class="min-w-0">
                    <span class="text-slate-800 font-bold text-xs">{rp.email}</span>
                    <span class="ml-2 text-[10px] text-slate-400 font-mono truncate">{recordNameById.get(rp.record_id) ?? rp.record_id}</span>
                  </div>
                  <div class="flex items-center gap-2 shrink-0">
                    <Badge type="user">{rp.level}</Badge>
                    <form method="post" action={`/domains/${domainId}/delegation/revoke-record`} class="m-0">
                      <input type="hidden" name="user_id" value={rp.user_id} />
                      <input type="hidden" name="record_id" value={rp.record_id} />
                      <button type="submit" class="text-rose-500 hover:text-rose-600 text-[10px] font-bold transition">Revoke</button>
                    </form>
                  </div>
                </div>
              ))}
              {recordPermissionsList.length === 0 && (
                <p class="py-4 text-center text-[10px] text-slate-400 italic font-mono">No record-level clearances granted.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    )}

    </Fragment>
  ), user, c.get('flash')))
})

// ---------------------------------------------------------------------------
// Delegation mutations
// ---------------------------------------------------------------------------

async function resolveDelegationTarget(c: AppContext, rawUserId: string) {
  const userId = parseId(String(rawUserId || ''))
  if (!userId) return null
  const target = await c.env.record_manager_db.prepare('SELECT id, email, role FROM users WHERE id = ?').bind(userId).first<{ id: number; email: string; role: string }>()
  // Clearances only apply to standard users; privileged roles have implicit access.
  return target && target.role === 'user' ? target : null
}

domains.post('/:id/delegation/grant-domain', async (c) => {
  const domainId = parseId(c.req.param('id'))

  // Authenticate/authorize before confirming whether the domain exists.
  const auth = domainId ? await requireDelegationRights(c, domainId) : { denied: c.text('Unauthorized', 401) }
  if ('denied' in auth) return auth.denied
  const actor = auth.user

  const domain = domainId ? await loadDomain(c, c.req.param('id')) : null
  if (!domain) return c.text('Domain not found', 404)

  const body = await c.req.parseBody() as Record<string, string>
  const target = await resolveDelegationTarget(c, body.user_id)
  const level = String(body.level || '')

  if (!target) {
    await setFlash(c, { type: 'error', text: 'Clearances apply to standard users only.' })
    return c.redirect(`/domains/${domainId}`)
  }
  if (!isValidLevel(level)) {
    await setFlash(c, { type: 'error', text: 'Unknown clearance level.' })
    return c.redirect(`/domains/${domainId}`)
  }

  await c.env.record_manager_db.prepare(
    'INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, ?) ON CONFLICT(user_id, domain_id) DO UPDATE SET level = excluded.level'
  ).bind(target.id, domainId!, level).run()

  await logAudit(c.env.record_manager_db, actor.email, 'GRANT_DOMAIN_PERM', 'PERMISSION', target.email, { domain: domain.zone_name, level })
  await setFlash(c, { type: 'success', text: `${target.email} now holds "${level}" on ${domain.zone_name}.` })
  return c.redirect(`/domains/${domainId}`)
})

// This handler was previously missing entirely — the NONE button posted to a 404.
domains.post('/:id/delegation/revoke-domain', async (c) => {
  const domainId = parseId(c.req.param('id'))

  // Authenticate/authorize before confirming whether the domain exists.
  const auth = domainId ? await requireDelegationRights(c, domainId) : { denied: c.text('Unauthorized', 401) }
  if ('denied' in auth) return auth.denied
  const actor = auth.user

  const domain = domainId ? await loadDomain(c, c.req.param('id')) : null
  if (!domain) return c.text('Domain not found', 404)

  const body = await c.req.parseBody() as Record<string, string>
  const target = await resolveDelegationTarget(c, body.user_id)

  if (!target) {
    await setFlash(c, { type: 'error', text: 'Clearances apply to standard users only.' })
    return c.redirect(`/domains/${domainId}`)
  }

  await c.env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ? AND domain_id = ?').bind(target.id, domainId!).run()

  await logAudit(c.env.record_manager_db, actor.email, 'REVOKE_DOMAIN_PERM', 'PERMISSION', target.email, { domain: domain.zone_name })
  await setFlash(c, { type: 'info', text: `All domain clearances revoked for ${target.email}.` })
  return c.redirect(`/domains/${domainId}`)
})

domains.post('/:id/delegation/grant-record', async (c) => {
  const domainId = parseId(c.req.param('id'))

  // Authenticate/authorize before confirming whether the domain exists.
  const auth = domainId ? await requireDelegationRights(c, domainId) : { denied: c.text('Unauthorized', 401) }
  if ('denied' in auth) return auth.denied
  const actor = auth.user

  const domain = domainId ? await loadDomain(c, c.req.param('id')) : null
  if (!domain) return c.text('Domain not found', 404)

  const body = await c.req.parseBody() as Record<string, string>
  const target = await resolveDelegationTarget(c, body.user_id)
  const recordId = String(body.record_id || '').trim()
  const level = String(body.level || '')

  if (!target) {
    await setFlash(c, { type: 'error', text: 'Clearances apply to standard users only.' })
    return c.redirect(`/domains/${domainId}`)
  }
  if (!RECORD_LEVEL_KEYS.includes(level as any)) {
    await setFlash(c, { type: 'error', text: 'Unknown record clearance.' })
    return c.redirect(`/domains/${domainId}`)
  }

  // Only allow granting access to records that actually exist in the zone.
  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let record: any
  try {
    record = (await cf.listRecords(domain.zone_id)).find(r => r.id === recordId)
  } catch { /* fallthrough */ }
  if (!record) {
    await setFlash(c, { type: 'error', text: 'That record no longer exists in this zone.' })
    return c.redirect(`/domains/${domainId}`)
  }

  await c.env.record_manager_db.prepare(
    'INSERT INTO record_permissions (user_id, domain_id, record_id, level) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, domain_id, record_id) DO UPDATE SET level = excluded.level'
  ).bind(target.id, domainId!, recordId, level).run()

  await logAudit(c.env.record_manager_db, actor.email, 'GRANT_RECORD_PERM', 'PERMISSION', target.email, { domain: domain.zone_name, record: record.name, level })
  await setFlash(c, { type: 'success', text: `${target.email} now holds "${level}" on ${record.name}.` })
  return c.redirect(`/domains/${domainId}`)
})

domains.post('/:id/delegation/revoke-record', async (c) => {
  const domainId = parseId(c.req.param('id'))

  // Authenticate/authorize before confirming whether the domain exists.
  const auth = domainId ? await requireDelegationRights(c, domainId) : { denied: c.text('Unauthorized', 401) }
  if ('denied' in auth) return auth.denied
  const actor = auth.user

  const domain = domainId ? await loadDomain(c, c.req.param('id')) : null
  if (!domain) return c.text('Domain not found', 404)

  const body = await c.req.parseBody() as Record<string, string>
  const userId = parseId(String(body.user_id || ''))
  const recordId = String(body.record_id || '').trim()

  if (!userId || !recordId) return c.text('Bad Request', 400)

  await c.env.record_manager_db.prepare(
    'DELETE FROM record_permissions WHERE user_id = ? AND domain_id = ? AND record_id = ?'
  ).bind(userId, domainId!, recordId).run()

  await logAudit(c.env.record_manager_db, actor.email, 'REVOKE_RECORD_PERM', 'PERMISSION', `#${userId}`, { domain: domain.zone_name, record_id: recordId })
  await setFlash(c, { type: 'info', text: 'Record clearance revoked.' })
  return c.redirect(`/domains/${domainId}`)
})

// ---------------------------------------------------------------------------
// DNS record CRUD
// ---------------------------------------------------------------------------

domains.post('/:id/records', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  const domain = await loadDomain(c, c.req.param('id'))
  if (!domain) return c.text('Domain not found', 404)

  const userLevel = await getPermissionLevel(c.env.record_manager_db, user, domain.id)
  if (!canAddRecords(user.role, userLevel)) return c.text('Forbidden', 403)

  const body = await c.req.parseBody() as Record<string, string>
  const { errors, value: record } = validateRecordInput(body)
  if (!record) {
    await setFlash(c, { type: 'error', text: errors.join(' ') })
    return c.redirect(`/domains/${domain.id}`)
  }

  // Protected namespace enforcement — the blacklist is finally active here.
  if (await isBlacklisted(c.env.record_manager_db, record.name)) {
    await logAudit(c.env.record_manager_db, user.email, 'CREATE_BLOCKED', 'RECORD', record.name, { domain: domain.zone_name, reason: 'blacklisted' })
    await setFlash(c, { type: 'error', text: `"${record.name}" is protected by a blacklist rule.` })
    return c.redirect(`/domains/${domain.id}`)
  }

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let result: any
  try {
    result = await cf.createRecord(domain.zone_id, record)
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Cloudflare rejected the record: ${e.message}` })
    return c.redirect(`/domains/${domain.id}`)
  }

  await logAudit(c.env.record_manager_db, user.email, 'CREATE', 'RECORD', record.name, { domain: domain.zone_name, type: record.type })

  if (result?.id) {
    await c.env.record_manager_db.batch([
      c.env.record_manager_db.prepare(
        'INSERT INTO record_metadata (record_id, domain_id, created_by_email) VALUES (?, ?, ?)'
      ).bind(result.id, domain.id, user.email),
      // History rows keep the pre-image of every change for the zone's trail.
      c.env.record_manager_db.prepare(
        "INSERT INTO record_history (domain_id, record_id, name, type, content, ttl, action, actor_email) VALUES (?, ?, ?, ?, ?, ?, 'CREATE', ?)"
      ).bind(domain.id, result.id, record.name, record.type, record.content, record.ttl ?? null, user.email)
    ])
  } else {
    await writeRecordHistory(c.env.record_manager_db, domain.id, '', record, 'CREATE', user.email)
  }

  await setFlash(c, { type: 'success', text: `Record ${record.name} created successfully.` })
  return c.redirect(`/domains/${domain.id}`)
})

/**
 * Shared loader for single-record operations: verifies the actor may at least
 * view this record before rendering the edit form or mutating anything.
 */
async function loadRecordContext(c: AppContext, needEdit: boolean, needDelete: boolean) {
  const auth = requireUser(c)
  if ('denied' in auth) return auth

  const user = auth.user
  const domain = await loadDomain(c, c.req.param('id'))
  if (!domain) return { denied: c.text('Domain not found', 404) }

  const db = c.env.record_manager_db
  const userLevel = await getPermissionLevel(db, user, domain.id)
  const recordId = c.req.param('recordId') ?? ''

  const { results: rpRows } = await db.prepare(
    'SELECT level FROM record_permissions WHERE user_id = ? AND domain_id = ? AND record_id = ?'
  ).bind(user.id, domain.id, recordId).all()
  const recordLevel = (rpRows as any[])[0]?.level ?? null

  const { results: metaRows } = await db.prepare(
    'SELECT created_by_email FROM record_metadata WHERE record_id = ?'
  ).bind(recordId).all()
  const creatorEmail = (metaRows as any[])[0]?.created_by_email ?? null
  const isCreatorOfRecord = creatorEmail === user.email

  // Viewing requires any visibility into the record; mutating re-checks below.
  const canSee = GLOBAL_ROLES.includes(user.role as Role) || !!userLevel || !!recordLevel || isCreatorOfRecord
  if (!canSee) return { denied: c.text('Forbidden', 403) }

  if (needEdit && !canEditRecord({ role: user.role, userLevel, recordLevel, isCreatorOfRecord })) {
    return { denied: c.text('Forbidden', 403) }
  }
  if (needDelete && !canDeleteRecord({ role: user.role, userLevel, recordLevel, isCreatorOfRecord })) {
    return { denied: c.text('Forbidden', 403) }
  }

  return { user, domain, recordId, userLevel }
}

domains.get('/:id/records/:recordId/edit', async (c) => {
  const ctx = await loadRecordContext(c, true, false)
  if ('denied' in ctx) return ctx.denied

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let record: any
  try {
    record = (await cf.listRecords(ctx.domain.zone_id)).find(r => r.id === ctx.recordId)
  } catch { /* handled below */ }
  if (!record) return c.text('Record not found', 404)

  return c.html(layout(`Edit Record - ${ctx.domain.zone_name}`, (
    <div class="max-w-2xl mx-auto py-4">
      <div class="mb-8 border-b border-slate-200 pb-5">
        <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Edit DNS Record</h2>
        <p class="text-slate-500 text-sm">Update DNS configurations for <span class="font-mono text-indigo-600 font-bold">{record.name}</span>.</p>
      </div>

      <form method="post" action={`/domains/${ctx.domain.id}/records/${ctx.recordId}`} class="space-y-6 bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Record Type</label>
            <select name="type" class="w-full text-xs font-mono">
              {RECORD_TYPES.map(t => <option value={t} selected={record.type === t} key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">TTL (seconds, 1 = Auto)</label>
            <input type="number" name="ttl" value={record.ttl} min="1" max="86400" class="w-full text-xs font-mono" />
          </div>
          <div>
            <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">MX Priority (MX only)</label>
            <input type="number" name="priority" value={record.priority ?? ''} min="0" max="65535" placeholder="10" class="w-full text-xs font-mono" />
          </div>
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Record Name</label>
          <input type="text" name="name" value={record.name} required maxlength={255} class="w-full text-xs font-mono font-bold" />
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Content</label>
          <input type="text" name="content" value={record.content} required maxlength={2048} class="w-full text-xs font-mono" />
          <p class="mt-1.5 text-[10px] text-slate-400 font-mono" data-content-hint></p>
        </div>

        <div class="flex items-center gap-2.5 py-2">
          <input type="checkbox" id="edit-proxied" name="proxied" checked={record.proxied} class="h-4 w-4" />
          <label for="edit-proxied" class="text-xs font-bold text-slate-600 uppercase font-mono cursor-pointer">Proxy through Cloudflare Edge</label>
        </div>

        <div class="pt-6 border-t border-slate-100 flex gap-4 justify-end">
          <a href={`/domains/${ctx.domain.id}`} class="px-5 py-2.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 font-bold text-xs tracking-wider transition bg-white">Cancel</a>
          <button type="submit" class="btn-primary text-xs px-5 py-2.5 rounded-lg font-bold tracking-wider shadow-md">Update Configuration</button>
        </div>
      </form>
    </div>
  ), ctx.user, c.get('flash')))
})

domains.post('/:id/records/:recordId', async (c) => {
  const ctx = await loadRecordContext(c, true, false)
  if ('denied' in ctx) return ctx.denied
  const { user, domain, recordId } = ctx

  const body = await c.req.parseBody() as Record<string, string>
  const { errors, value: record } = validateRecordInput(body)
  if (!record) {
    await setFlash(c, { type: 'error', text: errors.join(' ') })
    return c.redirect(`/domains/${domain.id}`)
  }

  // Renaming into a protected namespace is blocked just like creating one.
  if (await isBlacklisted(c.env.record_manager_db, record.name)) {
    await logAudit(c.env.record_manager_db, user.email, 'UPDATE_BLOCKED', 'RECORD', record.name, { domain: domain.zone_name, reason: 'blacklisted' })
    await setFlash(c, { type: 'error', text: `"${record.name}" is protected by a blacklist rule.` })
    return c.redirect(`/domains/${domain.id}`)
  }

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  try {
    await cf.updateRecord(domain.zone_id, recordId, record)
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Cloudflare rejected the update: ${e.message}` })
    return c.redirect(`/domains/${domain.id}`)
  }

  await logAudit(c.env.record_manager_db, user.email, 'UPDATE', 'RECORD', record.name, { domain: domain.zone_name, type: record.type })
  await writeRecordHistory(c.env.record_manager_db, domain.id, recordId, record, 'UPDATE', user.email)
  await setFlash(c, { type: 'success', text: `DNS configuration for ${record.name} deployed.` })
  return c.redirect(`/domains/${domain.id}`)
})

domains.post('/:id/records/:recordId/delete', async (c) => {
  const ctx = await loadRecordContext(c, false, true)
  if ('denied' in ctx) return ctx.denied
  const { user, domain, recordId } = ctx

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let deletedName = recordId
  let deletedSnapshot: any = null
  try {
    // Capture the real record first so the audit trail isn't "UNKNOWN" and
    // history keeps the final state of what was removed.
    const existing = (await cf.listRecords(domain.zone_id)).find(r => r.id === recordId)
    if (existing) {
      deletedName = existing.name
      deletedSnapshot = existing
      await cf.deleteRecord(domain.zone_id, recordId)
    }
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Cloudflare rejected the deletion: ${e.message}` })
    return c.redirect(`/domains/${domain.id}`)
  }

  // Clean up local ownership + record-level clearances for the removed record.
  await c.env.record_manager_db.batch([
    c.env.record_manager_db.prepare('DELETE FROM record_metadata WHERE record_id = ?').bind(recordId),
    c.env.record_manager_db.prepare('DELETE FROM record_permissions WHERE record_id = ?').bind(recordId)
  ])
  await writeRecordHistory(
    c.env.record_manager_db, domain.id, recordId,
    deletedSnapshot ?? { name: deletedName, type: 'UNKNOWN', content: '', ttl: undefined },
    'DELETE', user.email
  )

  await logAudit(c.env.record_manager_db, user.email, 'DELETE', 'RECORD', deletedName, { domain: domain.zone_name, record_id: recordId })
  await setFlash(c, { type: 'info', text: `DNS record ${deletedName} has been purged.` })
  return c.redirect(`/domains/${domain.id}`)
})

// ---------------------------------------------------------------------------
// Import & export (BIND zone files / CSV)
// ---------------------------------------------------------------------------

domains.get('/:id/export', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  const domain = await loadDomain(c, c.req.param('id'))
  if (!domain) return c.text('Domain not found', 404)

  // Export exposes the whole zone, so record-level clearance alone is not
  // enough — full zone visibility is required.
  const userLevel = await getPermissionLevel(c.env.record_manager_db, user, domain.id)
  if (!canViewDomain(user.role, userLevel, false)) return c.text('Domain not found', 404)

  const format = c.req.query('format') === 'csv' ? 'csv' : 'bind'
  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let records: any[]
  try {
    records = await cf.listRecords(domain.zone_id)
  } catch (e: any) {
    await setFlash(c, { type: 'error', text: `Could not load DNS records: ${e.message}` })
    return c.redirect(`/domains/${domain.id}`)
  }

  const body = format === 'csv'
    ? formatRecordsCsv(records)
    : formatRecordsBind(domain.zone_name, records)

  return new Response(body, {
    headers: {
      'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${domain.zone_name}.${format}"`
    }
  })
})

domains.post('/:id/import', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  // One import can fan out into hundreds of Cloudflare writes — keep it rare.
  if (!rateLimit(`import:${user.id}`, 10, 5 * 60_000)) {
    await setFlash(c, { type: 'error', text: 'Import rate limit reached (10 per 5 minutes). Try again shortly.' })
    return c.redirect(`/domains`)
  }

  const domain = await loadDomain(c, c.req.param('id'))
  if (!domain) return c.text('Domain not found', 404)

  const userLevel = await getPermissionLevel(c.env.record_manager_db, user, domain.id)
  if (!canAddRecords(user.role, userLevel)) return c.text('Forbidden', 403)

  const body = await c.req.parseBody() as Record<string, string>
  const text = String(body.zonefile || '')
  const entries = String(body.format || 'bind') === 'csv' ? parseCsv(text) : parseBindZoneFile(text)

  if (entries.length === 0) {
    await setFlash(c, { type: 'error', text: 'Nothing to import — no usable entries found.' })
    return c.redirect(`/domains/${domain.id}`)
  }
  if (entries.length > IMPORT_MAX_ENTRIES) {
    await setFlash(c, { type: 'error', text: `Import is capped at ${IMPORT_MAX_ENTRIES} entries per batch.` })
    return c.redirect(`/domains/${domain.id}`)
  }

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let created = 0
  let blocked = 0
  let invalid = 0
  const failures: string[] = []

  // Load blacklist patterns once: one isBlacklisted() call per entry meant a
  // D1 round-trip (and subrequest) per imported record — at 500 entries the
  // import blew past the Worker subrequest budget and died mid-way.
  const { results: patternRows } = await c.env.record_manager_db.prepare('SELECT pattern FROM blacklist').all<{ pattern: string }>()
  const patterns = patternRows.map(r => r.pattern)

  // Bookkeeping writes are batched and flushed in chunks: per-entry batches
  // waste subrequests, and one giant end-of-run batch can exceed D1's
  // per-batch statement limits.
  const db = c.env.record_manager_db
  const pending: D1PreparedStatement[] = []
  const flushBookkeeping = async () => {
    if (pending.length === 0) return
    const chunk = pending.splice(0, pending.length)
    try {
      await db.batch(chunk)
    } catch {
      if (failures.length < 5) failures.push('local bookkeeping (ownership/history) failed for some created records')
    }
  }

  for (const entry of entries) {
    // Parser errors come back as pseudo-entries with an empty name.
    if (!entry.name && entry.content) {
      invalid++
      if (failures.length < 5) failures.push(`line ${entry.line}: ${entry.content}`)
      continue
    }

    const { errors, value: record } = validateRecordInput({
      type: entry.type,
      name: entry.name,
      content: entry.content,
      ttl: String(entry.ttl),
      priority: entry.priority != null ? String(entry.priority) : ''
    })
    if (!record) {
      invalid++
      if (failures.length < 5) failures.push(`line ${entry.line}: ${errors.join(' ')}`)
      continue
    }

    if (matchBlacklist(patterns, record.name)) {
      blocked++
      continue
    }

    try {
      const result = await cf.createRecord(domain.zone_id, record)
      if (result?.id) {
        pending.push(
          db.prepare(
            'INSERT INTO record_metadata (record_id, domain_id, created_by_email) VALUES (?, ?, ?)'
          ).bind(result.id, domain.id, user.email),
          db.prepare(
            "INSERT INTO record_history (domain_id, record_id, name, type, content, ttl, action, actor_email) VALUES (?, ?, ?, ?, ?, ?, 'CREATE', ?)"
          ).bind(domain.id, result.id, record.name, record.type, record.content, record.ttl ?? null, user.email)
        )
        if (pending.length >= 50) await flushBookkeeping()
      }
      created++
    } catch (e: any) {
      if (failures.length < 5) failures.push(`${record.name}: ${e.message}`)
    }
  }
  await flushBookkeeping()

  await logAudit(c.env.record_manager_db, user.email, 'IMPORT_RECORDS', 'DOMAIN', domain.zone_name,
    { created, blocked, invalid, total: entries.length })

  const parts = [`${created} created`]
  if (blocked) parts.push(`${blocked} blocked by blacklist`)
  if (invalid) parts.push(`${invalid} invalid`)
  parts.push(...failures.slice(0, 3))
  await setFlash(c, {
    type: created > 0 ? 'success' : 'error',
    text: `Import finished — ${parts.join('; ')}.`
  })
  return c.redirect(`/domains/${domain.id}`)
})

// ---------------------------------------------------------------------------
// Record change history
// ---------------------------------------------------------------------------

const HISTORY_PAGE_SIZE = 50

domains.get('/:id/history', async (c) => {
  const auth = requireUser(c)
  if ('denied' in auth) return auth.denied
  const user = auth.user

  const domain = await loadDomain(c, c.req.param('id'))
  if (!domain) return c.text('Domain not found', 404)

  const db = c.env.record_manager_db
  const userLevel = await getPermissionLevel(db, user, domain.id)
  const { results: myRecordPerms } = await db.prepare(
    'SELECT COUNT(*) AS n FROM record_permissions WHERE user_id = ? AND domain_id = ?'
  ).bind(user.id, domain.id).all()
  const hasRecordPerms = ((myRecordPerms as any[])[0]?.n ?? 0) > 0
  // 404 rather than 403 — same hide-don't-reveal policy as the zone page.
  if (!canViewDomain(user.role, userLevel, hasRecordPerms)) return c.text('Domain not found', 404)

  const pageRaw = parseInt(c.req.query('page') || '1', 10)
  const page = Number.isSafeInteger(pageRaw) && pageRaw > 0 ? pageRaw : 1
  const offset = (page - 1) * HISTORY_PAGE_SIZE

  const [pageResult, countResult] = await db.batch([
    db.prepare(
      'SELECT * FROM record_history WHERE domain_id = ? ORDER BY id DESC LIMIT ? OFFSET ?'
    ).bind(domain.id, HISTORY_PAGE_SIZE + 1, offset),
    db.prepare('SELECT COUNT(*) AS total FROM record_history WHERE domain_id = ?').bind(domain.id)
  ]) as any
  const entries: any[] = pageResult.results
  const total = Number((countResult.results[0] as any)?.total ?? 0)
  const rows = entries.slice(0, HISTORY_PAGE_SIZE)
  const hasPrev = page > 1
  const hasNext = entries.length > HISTORY_PAGE_SIZE
  const pageCount = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE))

  return c.html(layout(`Change History - ${domain.zone_name}`, (
    <div class="max-w-5xl mx-auto py-4">
      <div class="mb-8 border-b border-slate-200 pb-5 flex flex-col md:flex-row justify-between md:items-end gap-3">
        <div>
          <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Change History</h2>
          <p class="text-slate-500 text-sm">Every create, update and deletion in <span class="font-mono text-indigo-600 font-bold">{domain.zone_name}</span> — kept even after records are removed. Page {page} of {pageCount} ({total} events).</p>
        </div>
        <a href={`/domains/${domain.id}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition text-xs font-bold whitespace-nowrap">&larr; Back to records</a>
      </div>

      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200">
          <thead class="table-header rounded-lg">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">When</th>
              <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Action</th>
              <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Record</th>
              <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Content</th>
              <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">By</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 bg-transparent">
            {rows.map(h => (
              <tr class="hover:bg-slate-50/50 transition-colors" key={h.id}>
                <td class="px-4 py-3 whitespace-nowrap text-xs text-slate-500 font-mono">{h.created_at}</td>
                <td class="px-4 py-3 whitespace-nowrap">
                  <Badge type={h.action === 'CREATE' ? 'success' : h.action === 'DELETE' ? 'error' : 'warning'}>{h.action}</Badge>
                </td>
                <td class="px-4 py-3">
                  <div class="text-sm font-semibold text-slate-900 font-mono">{h.name}</div>
                  <div class="text-[10px] text-slate-400 font-mono uppercase">{h.type}{h.ttl && h.ttl !== 1 ? ` · TTL ${h.ttl}s` : ''}</div>
                </td>
                <td class="px-4 py-3 max-w-[320px]"><span class="text-xs text-slate-700 font-mono break-all line-clamp-2">{h.content || <span class="text-slate-400 italic">—</span>}</span></td>
                <td class="px-4 py-3 whitespace-nowrap text-xs text-slate-600 font-mono">{h.actor_email}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colspan={5} class="px-4 py-10 text-center text-xs text-slate-400 italic font-mono">No changes recorded for this zone yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {(hasPrev || hasNext) && (
        <div class="mt-6 flex gap-2 justify-center text-xs font-bold">
          {hasPrev && <a href={`/domains/${domain.id}/history?page=${page - 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">&larr; Newer</a>}
          {hasNext && <a href={`/domains/${domain.id}/history?page=${page + 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">Older &rarr;</a>}
        </div>
      )}
    </div>
  ), user, c.get('flash')))
})

export default domains
