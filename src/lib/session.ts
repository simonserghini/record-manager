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
