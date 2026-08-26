import { Hono } from 'hono'
import { setSignedCookie, deleteCookie } from 'hono/cookie'
import { googleAuth } from '@hono/oauth-providers/google'
import { layout } from '../templates/layout'

type Bindings = {
  record_manager_db: D1Database
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  COOKIE_SECRET?: string
  OWNER_EMAIL?: string
}

type Variables = {
  settings: any
  user: any
  systemSecret: string
}

const auth = new Hono<{ Bindings: Bindings; Variables: Variables }>()

const SESSION_MAX_AGE = 60 * 60 * 24 * 30 // 30 days

function deniedPage(c: any, heading: string, message: string) {
  return c.html(layout(heading, (
    <div class="text-center py-8">
      <div class="inline-flex items-center justify-center h-14 w-14 rounded-full bg-rose-50 text-rose-500 mb-4 border border-rose-200">
        <svg class="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
      </div>
      <h3 class="text-lg font-bold text-slate-900 mb-2">{heading}</h3>
      <p class="text-sm text-slate-500 max-w-sm mx-auto leading-relaxed">{message}</p>
      <a href="/" class="mt-6 inline-block btn-primary text-xs px-5 py-2.5 rounded-lg font-bold">Back to sign in</a>
    </div>
  )))
}

auth.use('/google', (c, next) => {
  const settings = c.get('settings')
  if (!settings.GOOGLE_CLIENT_ID || !settings.GOOGLE_CLIENT_SECRET) {
    return c.text('Google OAuth not configured', 400)
  }

  const googleAuthMiddleware = googleAuth({
    client_id: settings.GOOGLE_CLIENT_ID,
    client_secret: settings.GOOGLE_CLIENT_SECRET,
    scope: ['email', 'profile']
  })
  return (googleAuthMiddleware as any)(c, next)
})

auth.get('/google', async (c) => {
  const oauthUser: any = c.get('user-google')

  if (!oauthUser?.email) return c.redirect('/')
  // Ownership and identity hinge entirely on the email claim, so only trust
  // addresses Google itself has verified.
  if (oauthUser.email_verified === false) {
    return deniedPage(c, 'Unverified email', 'Your Google account email address is not verified. Verify it at accounts.google.com and sign in again.')
  }
  const email = String(oauthUser.email).toLowerCase()

  const db = c.env.record_manager_db
  let dbUser = await db.prepare('SELECT id, email, role FROM users WHERE email = ?').bind(email).first<{ id: number; email: string; role: string }>()

  if (!dbUser) {
    const countRow = await db.prepare('SELECT COUNT(*) as count FROM users').first<{ count: number }>()

    // The first account becomes the system owner. When OWNER_EMAIL is
    // configured, only that address may claim it — otherwise anyone who
    // finds the worker URL first would gain full control.
    if ((countRow?.count ?? 0) === 0 && c.env.OWNER_EMAIL && c.env.OWNER_EMAIL.toLowerCase() !== email) {
      return deniedPage(c, 'Registration locked', 'This instance reserves its initial owner account. Ask your administrator for access, or sign in with the configured owner address.')
    }

    // Claim ownership atomically — two concurrent first-time sign-ins must not
    // both read "no owner yet" and each walk away with the role.
    const inserted = await db.prepare(`
      INSERT INTO users (email, role)
      SELECT ?, CASE WHEN EXISTS (SELECT 1 FROM users WHERE role = 'owner') THEN 'user' ELSE 'owner' END
      FROM (SELECT 1) WHERE true
      ON CONFLICT(email) DO NOTHING
      RETURNING id, email, role
    `).bind(email).first<{ id: number; email: string; role: string }>()
    dbUser = inserted ?? await db.prepare('SELECT id, email, role FROM users WHERE email = ?').bind(email).first<{ id: number; email: string; role: string }>()
  }

  await setSignedCookie(c, 'user', email, c.get('systemSecret'), {
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
    maxAge: SESSION_MAX_AGE
  })

  return c.redirect('/dashboard')
})

// Logout is POST-only — a GET would let any page force users out (and signal
// their session state) via a bare <img src="/auth/logout">.
auth.post('/logout', (c) => {
  deleteCookie(c, 'user', { path: '/' })
  return c.redirect('/')
})

export default auth
