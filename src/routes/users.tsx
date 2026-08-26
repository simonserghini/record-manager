import { Hono } from 'hono'
import type { Context } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'
import { Badge, Button } from '../templates/components'
import { setFlash, bumpSessionEpoch } from '../lib/session'
import { logAudit, isValidBlacklistPattern } from '../lib/db'
import { isValidLevel } from '../lib/auth'
import type { Role } from '../lib/auth'
import { parseId } from '../lib/validation'

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

const users = new Hono<Env>()

// Roles that may be granted through the provisioning form. 'owner' is never
// assignable here — ownership transfers are out of scope for this endpoint.
const ASSIGNABLE_ROLES: Role[] = ['user', 'manager', 'admin']

function isGlobalAdmin(role: string) {
  return role === 'owner' || role === 'admin'
}

users.get('/', async (c) => {
  const user = c.get('user')
  if (!user || !['owner', 'admin', 'manager'].includes(user.role)) return c.redirect('/')

  const db = c.env.record_manager_db
  const [{ results: userResults }, { results: domains }, { results: permissions }] = await db.batch([
    db.prepare('SELECT id, email, role FROM users ORDER BY created_at ASC'),
    db.prepare('SELECT id, zone_name FROM domains ORDER BY zone_name ASC'),
    db.prepare('SELECT user_id, domain_id, level FROM permissions')
  ]) as any

  const admin = isGlobalAdmin(user.role)

  const levels = [
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

  return c.html(layout('User Management', (
    <Fragment>
    <div class="mb-8 border-b border-slate-200 pb-5">
      <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Identity Management</h2>
      <p class="text-slate-500 text-sm">Delegate domain access levels to trusted operators.</p>
    </div>

    {admin && (
      <div class="mb-8">
        <h3 class="text-xs font-bold text-slate-700 mb-4 uppercase tracking-wider font-mono">Provision Team Member</h3>
        <form method="post" action="/users" class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
          <div class="flex flex-col md:flex-row gap-4 items-end">
            <div class="flex-1 w-full">
              <label class="block text-xs font-bold text-slate-500 mb-1.5 uppercase font-mono">Email Address</label>
              <input type="email" name="email" placeholder="user@example.com" required class="w-full text-xs font-mono" />
            </div>
            <div class="w-full md:w-64">
              <label class="block text-xs font-bold text-slate-500 mb-1.5 uppercase font-mono">System Role</label>
              <select name="role" class="w-full text-xs">
                <option value="user">User (Governed by permissions)</option>
                <option value="manager">Manager (Manage records &amp; perms)</option>
                <option value="admin">Admin (Full global access)</option>
              </select>
            </div>
            <Button type="submit">Add Identity</Button>
          </div>
        </form>
      </div>
    )}

    <div class="overflow-x-auto mt-10">
      <table class="min-w-full divide-y divide-slate-200 font-mono text-xs">
        <thead class="table-header rounded-lg">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">User</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Role</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider">Access Clearances</th>
            <th class="px-4 py-3 text-right text-xs font-bold text-slate-500 uppercase tracking-wider">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-transparent">
          {(userResults as any[]).map((u: any) => {
            const canManageTarget = admin && u.role !== 'owner' && u.id !== user.id
            const canEditClearances = admin && u.role === 'user'
            return (
              <tr class="hover:bg-slate-50/50 transition-colors" key={u.id}>
                <td class="px-4 py-4 whitespace-nowrap text-sm font-semibold text-slate-900">{u.email}</td>
                <td class="px-4 py-4 whitespace-nowrap">
                  <Badge type={u.role}>{u.role}</Badge>
                </td>
                <td class="px-4 py-4 text-xs text-slate-700">
                  {u.role !== 'user' ? <span class="text-slate-500 italic">Full administrative clearance</span> : (
                    <div class="space-y-3">
                      {(domains as any[]).map((d: any) => {
                        const currentPerm = (permissions as any[]).find((p: any) => p.user_id === u.id && p.domain_id === d.id)
                        const currentLevel = currentPerm ? currentPerm.level : 'none'
                        if (!canEditClearances) {
                          return (
                            <div class="flex items-center justify-between gap-3 p-2 bg-slate-50 border border-slate-200 rounded-xl" key={`${u.id}-${d.id}`}>
                              <span class="font-bold text-slate-800 text-[10px] truncate max-w-[120px]">{d.zone_name}</span>
                              {currentPerm
                                ? <Badge type="user">{currentLevel}</Badge>
                                : <span class="text-[9px] text-slate-400 font-mono italic">no access</span>}
                            </div>
                          )
                        }
                        return (
                          <div class="flex items-center justify-between gap-3 p-2 bg-slate-50 border border-slate-200 rounded-xl" key={`${u.id}-${d.id}`}>
                            <span class="font-bold text-slate-800 text-[10px] truncate max-w-[120px]">{d.zone_name}</span>
                            <div class="inline-flex flex-wrap items-center bg-slate-200/50 p-0.5 rounded-lg border border-slate-200 gap-0.5">
                              <form method="post" action={`/users/${u.id}/permissions/revoke`} style="margin:0;">
                                <input type="hidden" name="domain_id" value={d.id} />
                                <button type="submit" class={`px-1.5 py-0.5 text-[8px] font-bold rounded ${currentLevel === 'none' ? 'bg-rose-500 text-white' : 'text-slate-500 hover:text-rose-600'}`}>NONE</button>
                              </form>
                              {levels.map(lvl => (
                                <form method="post" action={`/users/${u.id}/permissions`} style="margin:0;" key={lvl.key}>
                                  <input type="hidden" name="domain_id" value={d.id} />
                                  <input type="hidden" name="level" value={lvl.key} />
                                  <button type="submit" title={lvl.desc} class={`px-1.5 py-0.5 text-[8px] font-bold rounded ${currentLevel === lvl.key ? 'bg-indigo-600 text-white' : 'text-slate-500 hover:text-indigo-600'}`}>{lvl.short}</button>
                                </form>
                              ))}
                            </div>
                          </div>
                        )
                      })}
                      {(domains as any[]).length === 0 && <span class="text-slate-400 italic font-mono text-[10px]">No synced domains yet.</span>}
                    </div>
                  )}
                </td>
                <td class="px-4 py-4 whitespace-nowrap text-right text-xs font-bold">
                  {user.role === 'owner' && u.id !== user.id && (
                    <form method="post" action={`/users/${u.id}/transfer-ownership`} style="display:inline; margin-right:1rem;" data-confirm={`Transfer ownership to ${u.email}? You will become an admin.`}>
                      <button type="submit" class="text-indigo-600 hover:text-indigo-500 font-bold transition">Make Owner</button>
                    </form>
                  )}
                  {canManageTarget && (
                    <form method="post" action={`/users/${u.id}/delete`} style="display:inline;" data-confirm="Are you sure?">
                      <button type="submit" class="text-rose-500 hover:text-rose-600 font-bold transition">Remove Identity</button>
                    </form>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
    </Fragment>
  ), user, c.get('flash')))
})

/**
 * Shared guard for every mutating route below. These endpoints previously had
 * NO authorization at all — any signed-in user could create admins, grant
 * themselves clearances, or delete the owner.
 */
async function requireGlobalAdmin(c: AppContext): Promise<Response | null> {
  const user = c.get('user')
  if (!user) return c.text('Unauthorized', 401)
  if (!isGlobalAdmin(user.role)) return c.text('Forbidden', 403)
  return null
}

/** Resolves a user by id, or null when the id is malformed / user missing. */
async function findTargetUser(c: AppContext, rawId: string) {
  const id = parseId(rawId)
  if (!id) return null
  return c.env.record_manager_db.prepare('SELECT id, email, role FROM users WHERE id = ?').bind(id).first<{ id: number; email: string; role: string }>()
}

users.post('/', async (c) => {
  const denied = await requireGlobalAdmin(c)
  if (denied) return denied

  const actor = c.get('user')
  const body = await c.req.parseBody() as Record<string, string>
  const email = String(body.email || '').trim().toLowerCase()
  const role = String(body.role || '').trim()

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255) {
    await setFlash(c, { type: 'error', text: 'A valid email address is required.' })
    return c.redirect('/users')
  }
  if (!ASSIGNABLE_ROLES.includes(role as Role)) {
    await setFlash(c, { type: 'error', text: 'Invalid role requested.' })
    return c.redirect('/users')
  }

  // Never demote or overwrite an existing privileged account through provisioning.
  const existing = await c.env.record_manager_db.prepare('SELECT id, role FROM users WHERE email = ?').bind(email).first<{ id: number; role: string }>()
  if (existing && existing.role !== 'user') {
    await setFlash(c, { type: 'error', text: `${email} already exists with the role "${existing.role}" and cannot be modified here.` })
    return c.redirect('/users')
  }

  await c.env.record_manager_db.prepare(
    'INSERT INTO users (email, role) VALUES (?, ?) ON CONFLICT(email) DO UPDATE SET role = excluded.role'
  ).bind(email, role).run()
  // A role change revokes every session the account already holds.
  if (existing) await bumpSessionEpoch(c.env.record_manager_db, existing.id)

  await logAudit(c.env.record_manager_db, actor.email, existing ? 'UPDATE_USER' : 'CREATE_USER', 'USER', email, { role })
  await setFlash(c, { type: 'success', text: `Identity ${email} provisioned.` })
  return c.redirect('/users')
})

users.post('/:id/permissions', async (c) => {
  const denied = await requireGlobalAdmin(c)
  if (denied) return denied

  const actor = c.get('user')
  const target = await findTargetUser(c, c.req.param('id'))
  const { domain_id, level } = await c.req.parseBody() as Record<string, string>
  const domainId = parseId(String(domain_id || ''))

  if (!target || target.role !== 'user') {
    await setFlash(c, { type: 'error', text: 'Clearances can only be managed for standard users.' })
    return c.redirect('/users')
  }
  if (!domainId || !isValidLevel(level)) {
    await setFlash(c, { type: 'error', text: 'Invalid clearance request.' })
    return c.redirect('/users')
  }

  await c.env.record_manager_db.prepare(
    'INSERT INTO permissions (user_id, domain_id, level) VALUES (?, ?, ?) ON CONFLICT(user_id, domain_id) DO UPDATE SET level = excluded.level'
  ).bind(target.id, domainId, level).run()

  await logAudit(c.env.record_manager_db, actor.email, 'GRANT_PERMISSION', 'PERMISSION', target.email, { domain_id: domainId, level })
  await setFlash(c, { type: 'success', text: `Clearance updated for ${target.email}.` })
  return c.redirect('/users')
})

users.post('/:id/permissions/revoke', async (c) => {
  const denied = await requireGlobalAdmin(c)
  if (denied) return denied

  const actor = c.get('user')
  const target = await findTargetUser(c, c.req.param('id'))
  const { domain_id } = await c.req.parseBody() as Record<string, string>
  const domainId = parseId(String(domain_id || ''))

  if (!target || target.role !== 'user') {
    await setFlash(c, { type: 'error', text: 'Clearances can only be managed for standard users.' })
    return c.redirect('/users')
  }
  if (!domainId) {
    await setFlash(c, { type: 'error', text: 'Invalid revoke request.' })
    return c.redirect('/users')
  }

  await c.env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ? AND domain_id = ?').bind(target.id, domainId).run()

  await logAudit(c.env.record_manager_db, actor.email, 'REVOKE_PERMISSION', 'PERMISSION', target.email, { domain_id: domainId })
  await setFlash(c, { type: 'success', text: `Clearance revoked for ${target.email}.` })
  return c.redirect('/users')
})

users.post('/:id/delete', async (c) => {
  const denied = await requireGlobalAdmin(c)
  if (denied) return denied

  const actor = c.get('user')
  const target = await findTargetUser(c, c.req.param('id'))

  if (!target) {
    await setFlash(c, { type: 'error', text: 'User not found.' })
    return c.redirect('/users')
  }
  if (target.role === 'owner') {
    await setFlash(c, { type: 'error', text: 'The owner account cannot be removed.' })
    return c.redirect('/users')
  }
  if (target.id === actor.id) {
    await setFlash(c, { type: 'error', text: 'You cannot remove your own account.' })
    return c.redirect('/users')
  }

  // Clean up delegated access alongside the identity.
  await c.env.record_manager_db.batch([
    c.env.record_manager_db.prepare('DELETE FROM permissions WHERE user_id = ?').bind(target.id),
    c.env.record_manager_db.prepare('DELETE FROM record_permissions WHERE user_id = ?').bind(target.id),
    c.env.record_manager_db.prepare('DELETE FROM users WHERE id = ?').bind(target.id)
  ])

  await logAudit(c.env.record_manager_db, actor.email, 'DELETE_USER', 'USER', target.email, {})
  await setFlash(c, { type: 'info', text: `Identity ${target.email} revoked.` })
  return c.redirect('/users')
})

/**
 * Ownership transfer: the current owner hands the crown to another existing
 * account. Atomic role swap in one batch; both accounts have their session
 * epoch bumped so every previously issued cookie is dead afterwards.
 */
users.post('/:id/transfer-ownership', async (c) => {
  const denied = await requireGlobalAdmin(c)
  if (denied) return denied

  const actor = c.get('user')
  if (actor.role !== 'owner') return c.text('Forbidden', 403)

  const target = await findTargetUser(c, c.req.param('id'))
  if (!target || target.role === 'owner' || target.id === actor.id) {
    await setFlash(c, { type: 'error', text: 'Ownership can only be transferred to a different existing account.' })
    return c.redirect('/users')
  }

  const db = c.env.record_manager_db
  await db.batch([
    db.prepare("UPDATE users SET role = 'admin', session_epoch = session_epoch + 1 WHERE id = ?").bind(actor.id),
    db.prepare("UPDATE users SET role = 'owner', session_epoch = session_epoch + 1 WHERE id = ?").bind(target.id)
  ])

  await logAudit(db, actor.email, 'TRANSFER_OWNERSHIP', 'USER', target.email, { from: actor.email })
  await setFlash(c, { type: 'success', text: `${target.email} is now the owner. You have been made an admin.` })
  return c.redirect('/users')
})

export const blacklist = new Hono<{ Bindings: Bindings; Variables: Variables }>()

blacklist.get('/', async (c) => {
  const user = c.get('user')
  if (!user || user.role !== 'owner') return c.redirect('/')
  const { results: patterns } = await c.env.record_manager_db.prepare('SELECT * FROM blacklist ORDER BY created_at DESC').all()

  return c.html(layout('Blacklist', (
    <Fragment>
    <div class="mb-8 border-b border-slate-200 pb-5">
      <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Access Blacklist</h2>
      <p class="text-slate-500 text-sm">Designate protected subdomains — matching record names can no longer be created or renamed, even by privileged operators. Use <code class="font-mono bg-slate-100 px-1 rounded">*</code> as a wildcard.</p>
    </div>

    <div class="mb-8">
      <form method="post" action="/blacklist" class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
        <div class="flex flex-col md:flex-row gap-4 items-end">
          <div class="flex-1 w-full">
            <label class="block text-xs font-bold text-slate-500 mb-1.5 uppercase font-mono">Pattern</label>
            <input type="text" name="pattern" placeholder="*.dev.example.com" required class="w-full text-xs font-mono" />
          </div>
          <Button type="submit">Deploy Rule</Button>
        </div>
      </form>
    </div>

    <div class="overflow-x-auto mt-10">
      <table class="min-w-full divide-y divide-slate-200">
        <thead class="table-header rounded-lg">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Pattern</th>
            <th class="px-4 py-3 text-right text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-transparent">
          {(patterns as any[]).map((p: any) => (
            <tr class="hover:bg-slate-50/50 transition-colors" key={p.id}>
              <td class="px-4 py-4 whitespace-nowrap font-mono text-xs text-indigo-600 font-bold">{p.pattern}</td>
              <td class="px-4 py-4 whitespace-nowrap text-right text-xs font-bold">
                <form method="post" action={`/blacklist/${p.id}/delete`} style="display:inline;">
                  <button type="submit" class="text-rose-500 hover:text-rose-600 font-bold transition">Remove Rule</button>
                </form>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    </Fragment>
  ), user, c.get('flash')))
})

blacklist.post('/', async (c) => {
  const user = c.get('user')
  if (!user) return c.text('Unauthorized', 401)
  if (user.role !== 'owner') return c.text('Forbidden', 403)

  const { pattern: rawPattern } = await c.req.parseBody() as Record<string, string>
  const pattern = String(rawPattern || '').trim().toLowerCase()

  // Validate before storing — these patterns are compiled into a RegExp on
  // every record write, so junk input would throw at runtime forever after.
  if (!isValidBlacklistPattern(pattern)) {
    await setFlash(c, { type: 'error', text: 'Patterns may only contain letters, numbers, dots, dashes, underscores and * wildcards (max 100 chars).' })
    return c.redirect('/blacklist')
  }

  await c.env.record_manager_db.prepare('INSERT INTO blacklist (pattern) VALUES (?) ON CONFLICT(pattern) DO NOTHING').bind(pattern).run()
  await logAudit(c.env.record_manager_db, user.email, 'CREATE_BLACKLIST_RULE', 'BLACKLIST', pattern, {})
  await setFlash(c, { type: 'success', text: `Protection rule ${pattern} deployed.` })
  return c.redirect('/blacklist')
})

blacklist.post('/:id/delete', async (c) => {
  const user = c.get('user')
  if (!user) return c.text('Unauthorized', 401)
  if (user.role !== 'owner') return c.text('Forbidden', 403)

  const id = parseId(c.req.param('id'))
  if (!id) return c.text('Bad Request', 400)

  await c.env.record_manager_db.prepare('DELETE FROM blacklist WHERE id = ?').bind(id).run()
  await logAudit(c.env.record_manager_db, user.email, 'DELETE_BLACKLIST_RULE', 'BLACKLIST', `#${id}`, {})
  return c.redirect('/blacklist')
})

export default users
