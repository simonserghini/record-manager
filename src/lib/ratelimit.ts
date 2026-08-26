/**
 * Best-effort in-isolate sliding-window rate limiter.
 *
 * Workers isolates are ephemeral and per-colo, so this caps request BURSTS
 * arriving at one isolate — a cheap brake against runaway loops and brute
 * force, not a hard global quota. For strict guarantees, front the worker
 * with Cloudflare WAF rate-limiting rules.
 */
const buckets = new Map<string, number[]>()
let lastSweep = 0

/** Records one hit; returns false when the caller has exceeded the budget. */
export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  const recent = (buckets.get(key) ?? []).filter(t => now - t < windowMs)

  if (recent.length >= limit) {
    buckets.set(key, recent)
    return false
  }
  recent.push(now)
  buckets.set(key, recent)

  // Occasionally drop dead keys so the map cannot grow without bound.
  if (now - lastSweep > 60_000) {
    lastSweep = now
    for (const [k, times] of buckets) {
      const alive = times.filter(t => now - t < windowMs)
      if (alive.length === 0) buckets.delete(k)
      else buckets.set(k, alive)
    }
  }
  return true
}

/** Stable per-client key; falls back gracefully when headers are absent. */
export function clientIp(c: { req: { header: (name: string) => string | undefined } }): string {
  return c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'
}
