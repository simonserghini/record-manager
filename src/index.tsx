import { Hono } from 'hono'
import { getSignedCookie } from 'hono/cookie'
import { csrf } from 'hono/csrf'
import { secureHeaders } from 'hono/secure-headers'
import { Fragment } from 'hono/jsx'
import { HTTPException } from 'hono/http-exception'
import { CloudflareClient } from './cloudflare'
import { getSettings, ensureSystemSecret, isConfigured, logAudit } from './lib/db'
import type { Settings } from './lib/db'
import { getFlash, FlashMessage, parseSessionValue } from './lib/session'
import { layout } from './templates/layout'

// Routes
import auth from './routes/auth'
import setup from './routes/setup'
import domains from './routes/domains'
import users, { blacklist } from './routes/users'
import logs from './routes/logs'
import tokens from './routes/tokens'
import api from './routes/api'

type Bindings = {
  record_manager_db: D1Database
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  COOKIE_SECRET?: string
  OWNER_EMAIL?: string
}

type Variables = {
  settings: Settings
  user: any
  systemSecret: string
  flash: FlashMessage | null
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Registered first so its post-response code runs last: authenticated HTML
// must never be storable by intermediaries or the back/forward cache.
app.use('*', async (c, next) => {
  await next()
  if (c.get('user') && (c.res.headers.get('content-type') || '').includes('text/html')) {
    c.res.headers.set('Cache-Control', 'no-store')
  }
})

// Global Middleware — security headers first.
// All app CSS/JS is bundled and served from /public via Workers Static
// Assets, so scripts need nothing beyond 'self'; only Google Fonts remain
// as an external origin (stylesheets + font files).
const securityHeaders = secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    frameAncestors: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"]
  }
})
app.use('*', securityHeaders)
// CSRF protection guards cookie-session form posts only. The JSON API under
// /api authenticates via explicit Bearer tokens — there are no ambient
// credentials to forge, and requiring form-style Origin headers there would
// break every body-less curl -X DELETE.
const csrfProtection = csrf()
app.use('*', async (c, next) => {
  if (c.req.path.startsWith('/api/')) return next()
  return csrfProtection(c, next)
})

app.use('*', async (c, next) => {
  const url = new URL(c.req.url)
  const db = c.env.record_manager_db

  // One settings query covers both the signing secret and app configuration;
  // this used to be a separate round-trip per request for each.
  const settings = await getSettings(db)
  const secret = c.env.COOKIE_SECRET || settings.SYSTEM_SECRET || await ensureSystemSecret(db)
  c.set('systemSecret', secret)
  c.set('settings', settings)

  const userEmail = await getSignedCookie(c, secret, 'user')
  if (userEmail) {
    // Look the user up on every request so deleted/blacklisted accounts lose
    // access immediately instead of when their cookie expires. The cookie
    // also carries a session_epoch — bumped to revoke all previously
    // issued sessions for that account.
    const session = parseSessionValue(userEmail)
    const user = await db.prepare('SELECT id, email, role, session_epoch FROM users WHERE email = ?').bind(session.email).first<any>()
    c.set('user', user && user.session_epoch === session.epoch ? user : null)
  }

  c.set('flash', await getFlash(c))

  if (url.pathname === '/setup' || url.pathname === '/healthz' || url.pathname.startsWith('/auth')) {
    return next()
  }
  // API routes authenticate via Bearer token inside src/routes/api.tsx and
  // answer in JSON — cookie sessions and the HTML setup redirect don't apply.
  if (url.pathname.startsWith('/api/')) {
    return next()
  }

  if (!isConfigured(settings)) {
    return c.redirect('/setup')
  }

  await next()
})

// Root Route (Welcome or Redirect to Dashboard)
app.get('/', (c) => {
  const user = c.get('user')
  const flash = c.get('flash')
  if (user) {
    return c.redirect('/dashboard')
  }
  return c.html(layout('Welcome', (
    <div class="w-full max-w-md mx-auto py-12">
      <div class="bg-white border border-slate-200 rounded-xl p-8 shadow-sm">
        <div class="flex items-center gap-3 mb-8">
          <div class="h-9 w-9 rounded bg-slate-900 flex items-center justify-center text-white font-bold text-sm">
            R
          </div>
          <div>
            <h2 class="text-sm font-bold text-slate-900 tracking-tight">Record Manager</h2>
            <p class="text-[10px] text-slate-500 font-mono uppercase tracking-wider">Cloudflare DNS Console</p>
          </div>
        </div>

        <h3 class="text-xl font-semibold text-slate-900 tracking-tight mb-2">Sign in to your account</h3>
        <p class="text-sm text-slate-600 mb-8">
          Manage domains, sync DNS zones, delegate fine-grained permission layers, and maintain audit trails.
        </p>

        <a href="/auth/google" class="w-full flex items-center justify-center gap-3 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-medium px-5 py-3 rounded-lg shadow-sm transition-all duration-150 text-sm">
          <svg class="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 12-4.53z" fill="#EA4335"/>
          </svg>
          Sign in with Google
        </a>
      </div>

      <div class="mt-8 space-y-4 text-xs text-slate-500 border-t border-slate-200/60 pt-6 px-1">
        <div class="flex gap-3">
          <div class="h-5 w-5 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 font-bold shrink-0 text-[10px]">✓</div>
          <div>
            <p class="font-semibold text-slate-800">Direct Cloudflare Sync</p>
            <p class="text-slate-500 mt-0.5">Integrates with official Cloudflare Edge endpoints to pull and push updates dynamically.</p>
          </div>
        </div>
        <div class="flex gap-3">
          <div class="h-5 w-5 rounded-full bg-slate-100 flex items-center justify-center text-slate-500 font-bold shrink-0 text-[10px]">✓</div>
          <div>
            <p class="font-semibold text-slate-800">Secure Access Controls</p>
            <p class="text-slate-500 mt-0.5">Define granular team permissions for records without exposing primary API tokens.</p>
          </div>
        </div>
      </div>
    </div>
  ), user, flash))
})

// Dashboard (Main Overview)
app.get('/dashboard', async (c) => {
  const user = c.get('user')
  if (!user) return c.redirect('/')
  const flash = c.get('flash')

  const settings = c.get('settings')
  const cf = new CloudflareClient(settings.CF_API_TOKEN)

  try {
    const allZones = await cf.listZones()
    const { results: syncedDomains } = await c.env.record_manager_db.prepare('SELECT * FROM domains').all()
    const syncedMap = new Map((syncedDomains as any[]).map(d => [d.zone_id, d]))

    let displayZones = allZones
    if (user.role !== 'owner' && user.role !== 'admin' && user.role !== 'manager') {
      const [{ results: permissions }, { results: recordPermissions }] = await c.env.record_manager_db.batch([
        c.env.record_manager_db.prepare('SELECT domain_id FROM permissions WHERE user_id = ?').bind(user.id),
        c.env.record_manager_db.prepare('SELECT DISTINCT domain_id FROM record_permissions WHERE user_id = ?').bind(user.id)
      ]) as any
      const allowedDomainIds = new Set([...permissions, ...recordPermissions].map((p: any) => p.domain_id))
      displayZones = allZones.filter((z: any) => {
        const synced = syncedMap.get(z.id) as any
        return synced && allowedDomainIds.has(synced.id)
      })
    }

    return c.html(layout('Dashboard', (
      <Fragment>
      <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8 pb-5 border-b border-slate-200">
        <div>
          <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Overview</h2>
          <p class="text-slate-500 text-sm">Authenticated clearance: <span class="text-indigo-600 font-bold uppercase font-mono text-xs px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200">{user.role}</span>. Scanned {displayZones.length} domains.</p>
        </div>
        <div class="relative w-full md:w-64">
          <input type="text" id="domain-search" placeholder="Search domains..." data-filter-target="#domain-grid .domain-card" class="w-full pl-10 pr-4 py-2.5 border border-slate-200 rounded-lg text-sm placeholder-slate-400 font-mono" />
          <svg class="absolute left-3 top-3.5 h-4 w-4 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>

      {displayZones.length === 0 ? (
        <div class="bg-amber-50 border border-amber-200 rounded-2xl p-8 text-center">
          <div class="inline-flex items-center justify-center h-16 w-16 rounded-full bg-white text-amber-500 mb-4 border border-amber-200 shadow-sm">
            <svg class="h-8 w-8" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 class="text-xl font-bold text-slate-900 mb-2">No Registered Domains</h3>
          <p class="text-slate-500 mb-6 max-w-md mx-auto leading-relaxed text-sm">Cloudflare returned no zones visible to your account. Verify your configuration scopes or token status.</p>
          <a href={user.role === 'owner' ? '/setup' : '/domains'} class="btn-primary text-xs px-6 py-3 rounded-lg font-bold inline-block shadow-md">{user.role === 'owner' ? 'Update Configuration' : 'View Zones'}</a>
        </div>
      ) : (
        <div id="domain-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {displayZones.map((z: any) => {
            const synced = syncedMap.get(z.id) as any
            return (
              <div class="domain-card group relative bg-white border border-slate-200 rounded-2xl p-5 hover:border-indigo-300 transition-all cursor-pointer shadow-sm" data-navigate={synced ? `/domains/${synced.id}` : '#'} data-name={z.name} key={z.id}>
                <div class="flex justify-between items-start mb-4">
                  <div class="h-10 w-10 bg-indigo-50 rounded-lg flex items-center justify-center text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition-colors duration-300">
                    <svg class="h-6 w-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                  </div>
                  <div class="flex flex-col items-end gap-1.5">
                    <span class={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border ${z.status === 'active' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-amber-50 border-amber-200 text-amber-700'}`}>{z.status}</span>
                    {synced
                      ? <span class="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-600">Synced</span>
                      : <span class="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-500">Unregistered</span>}
                  </div>
                </div>
                <h3 class="text-base font-bold text-slate-900 mb-1 truncate" title={z.name}>{z.name}</h3>
                <p class="text-[11px] text-slate-400 font-mono mb-4 truncate">{z.id}</p>
                <div class="flex items-center justify-between pt-4 border-t border-slate-100">
                  {synced ? (
                    <a href={`/domains/${synced.id}`} class="text-xs font-bold text-indigo-600 hover:text-indigo-500 transition">Manage DNS &rarr;</a>
                  ) : (
                    user.role === 'owner' ? (
                      <form method="post" action="/domains/sync" class="m-0">
                        <input type="hidden" name="id" value={z.id} />
                        <input type="hidden" name="name" value={z.name} />
                        <button type="submit" class="text-xs font-bold text-slate-400 hover:text-indigo-600 transition">Register for Management</button>
                      </form>
                    ) : <span class="text-xs text-slate-400 font-mono italic">Access Restricted</span>)}
                </div>
              </div>
            )
          })}
        </div>
      )}
      </Fragment>
    ), user, flash))
  } catch (e: any) {
    return c.html(layout('Error', (
      <div class="text-center py-12">
        <div class="inline-flex items-center justify-center h-16 w-16 rounded-full bg-rose-50 text-rose-500 mb-4 border border-rose-200 shadow-sm">
          <svg class="h-8 w-8" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <h2 class="text-xl font-bold text-slate-900 mb-2">Cloudflare Connection Failed</h2>
        <p class="text-slate-500 mb-6 max-w-md mx-auto text-sm leading-relaxed">Could not reach the Cloudflare API with the stored credentials: {e?.message || 'unknown error'}. Check API token settings.</p>
        <a href={user.role === 'owner' ? '/setup' : '/'} class="btn-primary text-xs px-6 py-3 rounded-lg font-bold inline-block shadow-md">{user.role === 'owner' ? 'Update Credentials' : 'Back to Sign In'}</a>
      </div>
    ), user, flash))
  }
})

// Friendly fallbacks instead of raw stack traces / blank 500s.
app.notFound((c) => {
  return c.html(layout('Not Found', (
    <div class="text-center py-12">
      <p class="text-6xl font-bold text-slate-200 mb-4">404</p>
      <h2 class="text-lg font-bold text-slate-900 mb-2">Page not found</h2>
      <p class="text-sm text-slate-500 mb-6">The page you requested does not exist.</p>
      <a href="/" class="btn-primary text-xs px-5 py-2.5 rounded-lg font-bold inline-block">Return Home</a>
    </div>
  ), c.get('user'), c.get('flash')), 404)
})

app.onError(async (err, c) => {
  // Middleware like csrf() raises HTTPException with a ready-made response
  // (403 etc.) — pass those through instead of masking them as 500s.
  if (err instanceof HTTPException) {
    c.res = err.getResponse()
  } else {
    console.error('Unhandled error:', err)
    c.res = await c.html(layout('Error', (
      <div class="text-center py-12">
        <p class="text-6xl font-bold text-slate-200 mb-4">!</p>
        <h2 class="text-lg font-bold text-slate-900 mb-2">Something went wrong</h2>
        <p class="text-sm text-slate-500 mb-6 max-w-md mx-auto">An unexpected error occurred. It has been logged. Please try again.</p>
        <a href="/" class="btn-primary text-xs px-5 py-2.5 rounded-lg font-bold inline-block">Return Home</a>
      </div>
    ), c.get('user'), c.get('flash')), 500)
  }
  // The middleware stack has already unwound, so responses rendered here would
  // otherwise ship without any security headers — apply them explicitly.
  await securityHeaders(c, async () => {})
  // Errors also skip the no-store middleware above (the throw unwinds past
  // its post-response code), yet the error page still renders the signed-in
  // layout — keep it uncached the same way.
  if (c.get('user') && (c.res.headers.get('content-type') || '').includes('text/html')) {
    c.res.headers.set('Cache-Control', 'no-store')
  }
  return c.res
})

// Health check — exempt from the configured-redirect so monitors can hit it
// on a fresh deployment. Verifies D1 reachability without leaking detail.
app.get('/healthz', async (c) => {
  try {
    await c.env.record_manager_db.prepare('SELECT 1').first()
    return c.json({ ok: true, time: new Date().toISOString() })
  } catch {
    return c.json({ ok: false }, 503)
  }
})

// Mount Routes
app.route('/auth', auth)
app.route('/setup', setup)
app.route('/domains', domains)
app.route('/users', users)
app.route('/blacklist', blacklist)
app.route('/logs', logs)
app.route('/tokens', tokens)
app.route('/api', api)

// Nightly cron: drop local management state for domains whose zone has been
// removed from the Cloudflare account, so stale zones don't linger forever.
async function reconcileOrphanedDomains(env: Bindings) {
  const settings = await getSettings(env.record_manager_db)
  if (!settings.CF_API_TOKEN) return
  const cf = new CloudflareClient(settings.CF_API_TOKEN)

  let zones: any[] = []
  try {
    zones = await cf.listZones()
  } catch {
    return // unreachable API — retry tomorrow rather than unsync everything
  }
  const liveZoneIds = new Set(zones.map((z: any) => z.id))

  const { results: synced } = await env.record_manager_db.prepare('SELECT id, zone_id, zone_name FROM domains').all()
  const orphans = (synced as any[]).filter(d => !liveZoneIds.has(d.zone_id))

  // A token scope change or account move makes EVERY zone vanish at once.
  // Unserving that would cascade-delete all domains, permissions and record
  // history on a false positive — only reconcile partial disappearances and
  // leave a total wipe for a human to confirm via manual unsync.
  if (orphans.length > 0 && orphans.length === (synced as any[]).length) {
    await logAudit(env.record_manager_db, 'system@cron', 'CRON_UNSYNC_SKIPPED', 'DOMAIN', 'ALL', {
      synced: orphans.length,
      reason: 'no zones visible to the API token — possible scope change'
    })
    return
  }

  for (const d of orphans) {
    // FKs cascade the permission/metadata cleanup, mirroring manual unsync.
    await env.record_manager_db.prepare('DELETE FROM domains WHERE id = ?').bind(d.id).run()
    await logAudit(env.record_manager_db, 'system@cron', 'CRON_UNSYNC_ORPHANED', 'DOMAIN', d.zone_name, { zone_id: d.zone_id })
  }
}

export default {
  fetch: app.fetch,
  scheduled: async (_event: unknown, env: Bindings, _ctx: ExecutionContext) => {
    try {
      await reconcileOrphanedDomains(env)
    } catch (e) {
      console.error('cron reconciliation failed:', e)
    }
  }
}
