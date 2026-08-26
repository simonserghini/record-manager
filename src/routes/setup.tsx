import { Hono } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'
import { getSettings, isConfigured, maskSecret, hasSavedSecret, SETTING_KEYS, logAudit } from '../lib/db'
import type { Settings } from '../lib/db'
import { setFlash } from '../lib/session'

type Bindings = {
  record_manager_db: D1Database
}

type Variables = {
  settings: any
  user: any
  systemSecret: string
  flash: any
}

const setup = new Hono<{ Bindings: Bindings; Variables: Variables }>()

/**
 * Setup is only writable during initial bootstrap (no user signed in and the
 * system is not yet configured) or by the owner afterwards. Once configured,
 * anonymous visitors are redirected away — previously this page echoed the
 * live API token and OAuth client secret back to anyone who asked.
 */
function guardSetup(c: any, settings: Settings) {
  const user = c.get('user')
  if (user && user.role !== 'owner') return c.text('Forbidden', 403)
  if (!user && isConfigured(settings)) return c.redirect('/')
  return null
}

setup.get('/', async (c) => {
  const user = c.get('user')
  const settings = c.get('settings')

  const denied = guardSetup(c, settings)
  if (denied) return denied

  const permissions = JSON.stringify([
    { key: 'zone_read', type: 'zone' },
    { key: 'dns_edit', type: 'zone' }
  ])
  const cfTokenUrl = `https://dash.cloudflare.com/profile/api-tokens?name=Record-Manager&permissionGroupKeys=${encodeURIComponent(permissions)}&accountId=*&zoneId=all`

  const url = new URL(c.req.url)
  const redirectUri = `${url.protocol}//${url.host}/auth/google`
  const tokenSaved = hasSavedSecret(settings, 'CF_API_TOKEN')

  return c.html(layout('System Settings', (
    <div class="max-w-4xl mx-auto py-4">
      <div class="mb-10 border-b border-slate-200 pb-6 flex flex-col md:flex-row justify-between items-start md:items-center">
        <div>
          <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Configuration Wizard</h2>
          <p class="text-slate-500 text-sm">Deploy keys to authenticate Cloudflare DNS and Google Identity accounts.</p>
        </div>
        <span class="text-xs font-mono font-bold uppercase tracking-widest px-2.5 py-1 rounded bg-indigo-50 text-indigo-600 border border-indigo-200 mt-3 md:mt-0">Setup</span>
      </div>

      <form id="setup-form" method="post" action="/setup" class="space-y-12">
        {/* Cloudflare Section */}
        <section class="relative bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm">
          <div class="absolute -top-3.5 left-6 px-3 bg-white text-xs font-bold text-indigo-600 tracking-widest uppercase border border-slate-200 rounded-full flex items-center gap-1.5 shadow-sm">
            <span class="h-4 w-4 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center text-[10px]">1</span>
            Cloudflare Connection
          </div>

          <div class="bg-indigo-50/60 border border-indigo-200 rounded-xl p-5 mb-6 mt-2">
            <h4 class="font-bold text-slate-900 mb-2 text-sm">Step A: Provision your API Token</h4>
            <p class="text-slate-500 text-sm mb-4 leading-relaxed">Instantiate a secure scoped API token on Cloudflare with pre-defined Zone:Read and DNS:Edit permissions.</p>
            <a href={cfTokenUrl} target="_blank" rel="noopener noreferrer" class="btn-primary text-xs px-5 py-2.5 rounded-lg font-bold inline-flex items-center gap-2 shadow-md">
              Create Token on Cloudflare
              <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
            </a>
          </div>

          <div class="bg-slate-50 border border-slate-200 rounded-xl p-5">
            <label class="block text-xs font-bold text-slate-500 mb-2.5 uppercase tracking-wider font-mono">Step B: Paste Created Token</label>
            <input type="password" id="cf-token" name="CF_API_TOKEN"
                   placeholder={tokenSaved ? 'Saved — leave blank to keep current token' : 'Paste your token here'} required={!tokenSaved}
                   class="w-full text-sm font-mono" />
            <p class="mt-2 text-[10px] text-slate-500 italic font-mono">{tokenSaved ? 'A token is already stored securely.' : '(Form automatically saves on valid paste)'}</p>
          </div>
        </section>

        {/* Google OAuth Section */}
        <section class="relative bg-white border border-slate-200 rounded-2xl p-6 md:p-8 shadow-sm">
          <div class="absolute -top-3.5 left-6 px-3 bg-white text-xs font-bold text-indigo-600 tracking-widest uppercase border border-slate-200 rounded-full flex items-center gap-1.5 shadow-sm">
            <span class="h-4 w-4 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center text-[10px]">2</span>
            Google OAuth Authentication
          </div>

          <div class="grid grid-cols-1 gap-6 mt-2">
            <div class="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <div class="flex flex-col gap-1 mb-4">
                <label class="block text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Redirect URI</label>
                <p class="text-[10px] text-slate-500 italic leading-tight">Whitelist this exact URI in your Google Cloud Console (APIs &amp; Services &gt; Credentials).</p>
              </div>
              <div class="flex items-center gap-2">
                <input type="text" readonly value={redirectUri} class="flex-1 text-[10px] font-mono bg-white border-slate-200 text-slate-600 cursor-default" />
                <button type="button" onclick={`navigator.clipboard.writeText('${redirectUri}')`} class="p-2 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-lg transition-colors">
                  <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
                </button>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div class="bg-slate-50 border border-slate-200 rounded-xl p-5">
                <label class="block text-xs font-bold text-slate-500 mb-2.5 uppercase tracking-wider font-mono">Client ID</label>
                <input type="text" name="GOOGLE_CLIENT_ID" value={settings.GOOGLE_CLIENT_ID || ''} placeholder="...-....apps.googleusercontent.com" required class="w-full text-[11px] font-mono" />
              </div>
              <div class="bg-slate-50 border border-slate-200 rounded-xl p-5">
                <label class="block text-xs font-bold text-slate-500 mb-2.5 uppercase tracking-wider font-mono">Client Secret</label>
                <input type="password" name="GOOGLE_CLIENT_SECRET" placeholder={hasSavedSecret(settings, 'GOOGLE_CLIENT_SECRET') ? 'Saved — leave blank to keep current secret' : 'GOCSPX-...'} required={!hasSavedSecret(settings, 'GOOGLE_CLIENT_SECRET')} class="w-full text-[11px] font-mono" />
                {hasSavedSecret(settings, 'GOOGLE_CLIENT_SECRET') && <p class="mt-2 text-[10px] text-emerald-600 italic font-mono">Client secret is stored securely.</p>}
              </div>
            </div>
          </div>
        </section>

        <div class="flex items-center justify-end gap-4 pt-4">
          <button type="submit" class="btn-primary px-10 py-3 font-bold rounded-xl shadow-lg transition-all">
            Deploy Configuration
          </button>
        </div>
      </form>
    </div>
  ), user, c.get('flash')))
})

setup.post('/', async (c) => {
  const user = c.get('user')
  const settings = c.get('settings')

  const denied = guardSetup(c, settings)
  if (denied) return denied

  const body = await c.req.parseBody()
  const db = c.env.record_manager_db

  // Only whitelisted keys can be written — never trust arbitrary form keys.
  for (const key of SETTING_KEYS) {
    const value = body[key]
    if (typeof value === 'string' && value.trim()) {
      await db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        .bind(key, value.trim())
        .run()
    }
  }

  if (user) {
    await logAudit(db, user.email, 'UPDATE_SETTINGS', 'SYSTEM', 'CONFIG', { keys: SETTING_KEYS.filter(k => typeof body[k] === 'string' && (body[k] as string).trim()) })
  }

  await setFlash(c, { type: 'success', text: 'System configuration deployed successfully.' })
  return c.redirect('/setup')
})

export default setup
