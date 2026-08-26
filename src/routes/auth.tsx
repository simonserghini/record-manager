import { Hono } from 'hono'
import { setSignedCookie, deleteCookie } from 'hono/cookie'
import { googleAuth } from '@hono/oauth-providers/google'
import { layout } from '../templates/layout'
import { buildSessionValue, bumpSessionEpoch } from '../lib/session'
import { logAudit } from '../lib/db'
import { rateLimit, clientIp } from '../lib/ratelimit'

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

auth.use('/google', async (c, next) => {
  const settings = c.get('settings')
  if (!settings.GOOGLE_CLIENT_ID || !settings.GOOGLE_CLIENT_SECRET) {
    return c.text('Google OAuth not configured', 400)
  }

  // Brake on OAuth-start hammering (state churn, upstream rate limits).
  // 10 starts/min per client IP is far above any human's cadence.
  if (!rateLimit(`auth:${clientIp(c)}`, 10, 60_000)) {
    return c.text('Too many sign-in attempts. Try again in a minute.', 429)
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
  let dbUser = await db.prepare('SELECT id, email, role, session_epoch FROM users WHERE email = ?').bind(email).first<{ id: number; email: string; role: string; session_epoch: number }>()

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
      RETURNING id, email, role, session_epoch
    `).bind(email).first<{ id: number; email: string; role: string; session_epoch: number }>()
    dbUser = inserted ?? await db.prepare('SELECT id, email, role, session_epoch FROM users WHERE email = ?').bind(email).first<{ id: number; email: string; role: string; session_epoch: number }>()
  }

  if (!dbUser) return deniedPage(c, 'Sign-in failed', 'Could not create or load your account. Please try again.')

  // The signed value embeds the account's current session epoch so bumped
  // epochs invalidate older cookies.
  await setSignedCookie(c, 'user', buildSessionValue(email, dbUser.session_epoch ?? 0), c.get('systemSecret'), {
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

// Signs out EVERY device by bumping the account's session epoch, which
// invalidates all previously issued cookies at once.
auth.post('/logout-all', async (c) => {
  const user = c.get('user')
  if (user) {
    await bumpSessionEpoch(c.env.record_manager_db, user.id)
    await logAudit(c.env.record_manager_db, user.email, 'LOGOUT_ALL', 'USER', user.email, {})
  }
  deleteCookie(c, 'user', { path: '/' })
  return c.redirect('/')
})

export default auth
