import { Context } from 'hono'
import { getSignedCookie, setSignedCookie, deleteCookie } from 'hono/cookie'

export type FlashMessage = {
  type: 'success' | 'error' | 'info'
  text: string
}

export async function setFlash(c: Context, message: FlashMessage) {
  const secret = c.get('systemSecret')
  await setSignedCookie(c, 'flash', JSON.stringify(message), secret, {
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
    maxAge: 60 // 1 minute
  })
}

export async function getFlash(c: Context): Promise<FlashMessage | null> {
  const secret = c.get('systemSecret')
  const flash = await getSignedCookie(c, secret, 'flash')
  if (flash) {
    deleteCookie(c, 'flash')
    try {
      return JSON.parse(flash)
    } catch (e) {
      return null
    }
  }
  return null
}

/**
 * The session cookie's signed value is "<email>|<session_epoch>". Bumping a
 * user's session_epoch (role change, forced sign-out) instantly invalidates
 * every cookie issued before it. Cookies from before epochs existed carry no
 * "|" and are treated as epoch 0, which still matches untouched accounts.
 */
export function buildSessionValue(email: string, epoch: number) {
  return `${email}|${epoch}`
}

export function parseSessionValue(value: string): { email: string; epoch: number } {
  const sep = value.lastIndexOf('|')
  if (sep === -1) return { email: value, epoch: 0 }
  const epoch = parseInt(value.slice(sep + 1), 10)
  return {
    email: value.slice(0, sep),
    epoch: Number.isSafeInteger(epoch) && epoch >= 0 ? epoch : -1
  }
}

/** Invalidate every session for one user by bumping their epoch. */
export async function bumpSessionEpoch(db: D1Database, userId: number) {
  await db.prepare('UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?').bind(userId).run()
}
