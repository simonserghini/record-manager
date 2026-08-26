import { Hono } from 'hono'
import type { Context } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'
import { CloudflareClient } from '../cloudflare'
import { logAudit, isBlacklisted } from '../lib/db'
import {
  getPermissionLevel, can, canViewDomain, canManageDelegation, canAddRecords,
  canEditRecord, canDeleteRecord, GLOBAL_ROLES, isValidLevel, RECORD_LEVEL_KEYS,
  LEVEL_KEYS
} from '../lib/auth'
import type { Role } from '../lib/auth'
import { setFlash } from '../lib/session'
import { Badge, Button } from '../templates/components'
import { parseId, validateRecordInput, RECORD_TYPES } from '../lib/validation'

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
                    ? <form method="post" action="/domains/unsync" style="display:inline;"><input type="hidden" name="id" value={z.id} /><button type="submit" class="text-rose-500 hover:text-rose-600 font-bold transition">Disable Sync</button></form>
                    : <form method="post" action="/domains/sync" style="display:inline;"><input type="hidden" name="id" value={z.id} /><input type="hidden" name="name" value={z.name} /><button type="submit" class="text-indigo-600 hover:text-indigo-500 font-bold transition">Enable Sync</button></form>
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
  if (!canViewDomain(user.role, userLevel, recordPermMap.size > 0)) return c.text('Forbidden', 403)

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

  return c.html(layout(`Manage ${domain.zone_name}`, (
    <Fragment>
    <div class="flex justify-between items-center mb-8 pb-4 border-b border-slate-200">
      <div>
        <h2 class="text-2xl font-bold text-slate-900 tracking-tight">{domain.zone_name}</h2>
        <p class="text-sm text-slate-500">Configure real-time DNS records on Cloudflare edge servers.</p>
      </div>
      <div class="flex gap-2">
        {canAdd && (
          <Button onclick="document.getElementById('add-record-panel').classList.toggle('hidden')">
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
            <div class="md:col-span-2">
              <label class="block text-xs font-bold text-slate-500 mb-1 uppercase font-mono">Content</label>
              <input type="text" name="content" placeholder="1.2.3.4" required maxlength={2048} class="w-full text-xs font-mono" />
            </div>
            <div class="md:col-span-1 flex flex-col items-center pb-2">
               <label class="block text-xs font-bold text-slate-500 mb-1.5 uppercase font-mono">Proxied</label>
               <input type="checkbox" name="proxied" class="h-4 w-4" />
            </div>
            <div class="md:col-span-5">
               <input type="hidden" name="ttl" value="1" />
            </div>
            <div class="md:col-span-1">
              <button type="submit" class="w-full btn-primary py-2 rounded-lg font-bold text-xs">Create</button>
            </div>
          </div>
        </form>
      </div>
    )}

    <div class="mb-6 flex justify-between items-center gap-4">
      <div class="relative w-full max-w-sm">
        <input type="text" id="record-search" placeholder="Filter records..." class="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg text-sm placeholder-slate-400 font-mono" onkeyup="filterRecords()" />
        <svg class="absolute left-3 top-3 h-4 w-4 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>
      <div class="text-xs text-slate-500 font-mono whitespace-nowrap">Showing {records.length} records</div>
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
              <tr class="record-row hover:bg-slate-50/80 transition-colors" data-search={`${r.type} ${r.name} ${r.content}`} key={r.id}>
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
                    {editable && <a href={`/domains/${domainId}/records/${r.id}/edit`} class="text-indigo-600 hover:text-indigo-500 p-1 rounded transition hover:bg-indigo-50" title="Edit"><svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg></a>}
                    {deletable && (
                      <form method="post" action={`/domains/${domainId}/records/${r.id}/delete`} style="display:inline;" onsubmit="return confirm('Are you sure?')">
                        <button type="submit" class="text-rose-500 hover:text-rose-600 p-1 rounded transition hover:bg-rose-50" title="Delete">
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
                      <form method="post" action={`/domains/${domainId}/delegation/revoke-domain`} style="margin:0;">
                        <input type="hidden" name="user_id" value={u.id} />
                        <button type="submit" class={`px-2.5 py-1 text-[9px] font-bold rounded-lg transition-all ${currentLevel === 'none' ? 'bg-rose-500 text-white shadow-sm' : 'text-slate-500 hover:text-rose-600 hover:bg-slate-200/80'}`} title="No access">
                          NONE
                        </button>
                      </form>

                      {LEVELS.map(lvl => {
                        const isActive = currentLevel === lvl.key
                        return (
                          <form method="post" action={`/domains/${domainId}/delegation/grant-domain`} style="margin:0;" key={lvl.key}>
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
                    <form method="post" action={`/domains/${domainId}/delegation/revoke-record`} style="margin:0;">
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

    <script dangerouslySetInnerHTML={{ __html: `
      function filterRecords() {
        const query = document.getElementById('record-search').value.toLowerCase();
        const rows = document.querySelectorAll('.record-row');
        rows.forEach(row => {
          const content = row.getAttribute('data-search').toLowerCase();
          row.style.display = content.includes(query) ? '' : 'none';
        });
      }
    `}} />
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
    await c.env.record_manager_db.prepare(
      'INSERT INTO record_metadata (record_id, domain_id, created_by_email) VALUES (?, ?, ?)'
    ).bind(result.id, domain.id, user.email).run()
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
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
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
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Record Name</label>
          <input type="text" name="name" value={record.name} required maxlength={255} class="w-full text-xs font-mono font-bold" />
        </div>

        <div>
          <label class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Content</label>
          <input type="text" name="content" value={record.content} required maxlength={2048} class="w-full text-xs font-mono" />
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
  await setFlash(c, { type: 'success', text: `DNS configuration for ${record.name} deployed.` })
  return c.redirect(`/domains/${domain.id}`)
})

domains.post('/:id/records/:recordId/delete', async (c) => {
  const ctx = await loadRecordContext(c, false, true)
  if ('denied' in ctx) return ctx.denied
  const { user, domain, recordId } = ctx

  const cf = new CloudflareClient(c.get('settings').CF_API_TOKEN)
  let deletedName = recordId
  try {
    // Capture the real name first so the audit trail isn't "UNKNOWN".
    const existing = (await cf.listRecords(domain.zone_id)).find(r => r.id === recordId)
    if (existing) {
      deletedName = existing.name
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

  await logAudit(c.env.record_manager_db, user.email, 'DELETE', 'RECORD', deletedName, { domain: domain.zone_name, record_id: recordId })
  await setFlash(c, { type: 'info', text: `DNS record ${deletedName} has been purged.` })
  return c.redirect(`/domains/${domain.id}`)
})

export default domains
