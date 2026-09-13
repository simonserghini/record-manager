import { Hono } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'
import { Badge, Button } from '../templates/components'
import { setFlash } from '../lib/session'
import { logAudit } from '../lib/db'
import { generateApiToken, hashApiToken } from '../lib/apitokens'

type Bindings = { record_manager_db: D1Database }
type Variables = { settings: any; user: any; flash: any }

const tokens = new Hono<{ Bindings: Bindings; Variables: Variables }>()

const TOKEN_NAME_MAX = 100

// Every signed-in user manages their OWN tokens; the token then inherits
// whatever this account is allowed to do.
tokens.get('/', async (c) => {
  const user = c.get('user')
  if (!user) return c.redirect('/')

  const db = c.env.record_manager_db
  const { results } = await db.prepare(
    'SELECT id, name, created_at, last_used_at, revoked_at FROM api_tokens WHERE user_id = ? ORDER BY id DESC'
  ).bind(user.id).all()
  const rows: any[] = results

  return c.html(layout('API Tokens', (
    <Fragment>
      <div class="mb-8 border-b border-slate-200 pb-5">
        <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">API Tokens</h2>
        <p class="text-slate-500 text-sm">Bearer credentials for the JSON API. A token can do everything <em>you</em> can do — no more, no less.</p>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div class="main-card rounded-xl p-6 shadow-sm lg:col-span-1">
          <h3 class="text-sm font-bold text-slate-900 uppercase tracking-wider font-mono mb-4">Create Token</h3>
          <form method="post" action="/tokens" class="space-y-4">
            <div>
              <label for="name" class="block text-xs font-bold text-slate-500 mb-2 uppercase font-mono">Label</label>
              <input type="text" id="name" name="name" required maxlength={TOKEN_NAME_MAX} placeholder="ci-deploy" class="w-full text-xs font-mono" />
              <p class="text-[11px] text-slate-400 mt-2">Shown in your token list so you can tell credentials apart.</p>
            </div>
            <Button type="submit" variant="primary">Generate Token</Button>
          </form>
          <div class="mt-6 pt-4 border-t border-slate-100 space-y-1.5 text-xs text-slate-500 leading-relaxed">
            <p><span class="font-bold text-slate-700">The secret is shown once</span> at creation and never again — store it somewhere safe.</p>
            <p>Revoking a token takes effect immediately. It cannot be un-revoked; create a new one instead.</p>
          </div>
        </div>

        <div class="lg:col-span-2">
          <div class="overflow-x-auto main-card rounded-xl shadow-sm">
            <table class="min-w-full divide-y divide-slate-200">
              <thead class="table-header">
                <tr>
                  <th class="px-5 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Label</th>
                  <th class="px-5 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Created</th>
                  <th class="px-5 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Last Used</th>
                  <th class="px-5 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Status</th>
                  <th class="px-5 py-3 text-right text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100">
                {rows.length === 0 ? (
                  <tr><td colspan={5} class="px-5 py-10 text-center text-sm text-slate-400">No API tokens yet. Generate one to start automating.</td></tr>
                ) : rows.map(t => (
                  <tr key={t.id}>
                    <td class="px-5 py-3.5 text-sm font-semibold text-slate-900">{t.name}</td>
                    <td class="px-5 py-3.5 text-xs text-slate-500 font-mono">{t.created_at}</td>
                    <td class="px-5 py-3.5 text-xs text-slate-500 font-mono">{t.last_used_at || 'never'}</td>
                    <td class="px-5 py-3.5">
                      {t.revoked_at
                        ? <Badge type="error">revoked</Badge>
                        : <Badge type="success">active</Badge>}
                    </td>
                    <td class="px-5 py-3.5 text-right">
                      {!t.revoked_at && (
                        <form method="post" action={`/tokens/${t.id}/revoke`} class="m-0" data-confirm={`Revoke "${t.name}"? Any automation using it will stop working immediately.`}>
                          <button type="submit" class="text-xs font-bold text-rose-600 hover:text-rose-500 transition cursor-pointer">Revoke</button>
                        </form>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div class="mt-6 bg-slate-900 rounded-xl p-5 text-slate-300 overflow-x-auto">
            <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono mb-3">Quickstart</h3>
            <pre class="font-mono text-[11px] leading-relaxed whitespace-pre">{`# List zones visible to your account
curl -H "Authorization: Bearer rm_..." ${''}\\
     https://<your-worker>/api/v1/zones

# Create a record — any Cloudflare type (A, AAAA, CNAME, TXT, MX, NS, SRV, …)
curl -X POST -H "Authorization: Bearer rm_..." \\
     -H "Content-Type: application/json" \\
     -d '{"type":"A","name":"www","content":"203.0.113.7","ttl":300}' \\
     https://<your-worker>/api/v1/zones/<zone-id>/records`}</pre>
          </div>
          <p class="mt-3 text-[11px] text-slate-400">Rate limits per token owner: 120 requests/min for reads, 30/min for writes.</p>
        </div>
      </div>
    </Fragment>
  ), user, c.get('flash')))
})

tokens.post('/', async (c) => {
  const user = c.get('user')
  if (!user) return c.redirect('/')

  const body = await c.req.parseBody() as Record<string, string>
  const name = String(body.name || '').trim().slice(0, TOKEN_NAME_MAX)
  if (!name) {
    await setFlash(c, { type: 'error', text: 'A label is required.' })
    return c.redirect('/tokens')
  }

  const secret = generateApiToken()
  const tokenHash = await hashApiToken(secret)

  // Cap active tokens per account so the list cannot grow without bound.
  const db = c.env.record_manager_db
  const { results: active } = await db.prepare(
    'SELECT id FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL'
  ).bind(user.id).all()
  if ((active as any[]).length >= 20) {
    await setFlash(c, { type: 'error', text: 'Token limit reached (20 active). Revoke one before creating another.' })
    return c.redirect('/tokens')
  }

  const result = await db.prepare(
    'INSERT INTO api_tokens (user_id, name, token_hash) VALUES (?, ?, ?)'
  ).bind(user.id, name, tokenHash).run()

  await logAudit(db, user.email, result.success ? 'TOKEN_CREATED' : 'TOKEN_CREATE_FAILED', 'API_TOKEN', name, { via: 'ui' })
  // PRG with the secret riding along in the one-shot flash cookie — it is
  // httpOnly, signed, expires in a minute, and is never stored server-side.
  await setFlash(c, {
    type: 'success',
    text: `Token "${name}" created. Copy your secret now — it will not be shown again:\n${secret}`
  })
  return c.redirect('/tokens')
})

tokens.post('/:id/revoke', async (c) => {
  const user = c.get('user')
  if (!user) return c.redirect('/')

  const id = parseInt(c.req.param('id'), 10)
  if (!Number.isSafeInteger(id)) return c.redirect('/tokens')

  const db = c.env.record_manager_db
  // The user_id predicate makes cross-account revocation impossible.
  const result = await db.prepare(
    'UPDATE api_tokens SET revoked_at = datetime(\'now\') WHERE id = ? AND user_id = ? AND revoked_at IS NULL'
  ).bind(id, user.id).run()

  if (!result.success || result.meta.changes === 0) {
    await setFlash(c, { type: 'error', text: 'That token does not exist or is already revoked.' })
    return c.redirect('/tokens')
  }

  await logAudit(db, user.email, 'TOKEN_REVOKED', 'API_TOKEN', `#${id}`, { via: 'ui' })
  await setFlash(c, { type: 'info', text: 'Token revoked. Requests using it now receive 401.' })
  return c.redirect('/tokens')
})

export default tokens
