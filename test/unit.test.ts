import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'
import { parseSessionValue } from '../src/lib/session'
import { isBlacklisted, isValidBlacklistPattern } from '../src/lib/db'
import { parseBindZoneFile, parseCsv, formatRecordsBind, formatRecordsCsv } from '../src/lib/zonefiles'
import { validateRecordInput, RECORD_TYPES } from '../src/lib/validation'
import { generateApiToken, hashApiToken, resolveApiToken } from '../src/lib/apitokens'
import { rateLimit } from '../src/lib/ratelimit'

describe('session value encoding', () => {
  it('round-trips email and epoch', () => {
    const session = parseSessionValue(build('a@b.c', 7))
    expect(session.email).toBe('a@b.c')
    expect(session.epoch).toBe(7)
  })

  it('treats legacy cookies without a separator as epoch 0', () => {
    expect(parseSessionValue('legacy@b.c').epoch).toBe(0)
    expect(parseSessionValue('legacy@b.c').email).toBe('legacy@b.c')
  })

  it('rejects garbage epochs as -1', () => {
    expect(parseSessionValue(build('a@b.c', 3) + '|notanint').epoch).toBe(-1)
  })

  it('keeps emails containing pipes intact (last separator wins)', () => {
    // Emails cannot contain "|", but a crafted cookie must not shift epochs.
    const session = parseSessionValue('x|y@z.c|12')
    expect(session.email).toBe('x|y@z.c')
    expect(session.epoch).toBe(12)
  })
})

function build(email: string, epoch: number) {
  return `${email}|${epoch}`
}

describe('blacklist matching', () => {
  async function withPatterns(patterns: string[], fn: () => Promise<void>) {
    await env.record_manager_db.prepare("DELETE FROM blacklist").run()
    for (const p of patterns) {
      await env.record_manager_db.prepare('INSERT INTO blacklist (pattern) VALUES (?)').bind(p).run()
    }
    try { await fn() } finally {
      await env.record_manager_db.prepare('DELETE FROM blacklist').run()
    }
  }

  it('matches wildcard patterns', async () => {
    await withPatterns(['*.internal.example.com'], async () => {
      await expect(isBlacklisted(env.record_manager_db, 'secret.internal.example.com')).resolves.toBe(true)
      await expect(isBlacklisted(env.record_manager_db, 'example.com')).resolves.toBe(false)
    })
  })

  it('ignores trailing dots on both sides', async () => {
    await withPatterns(['admin.example.com.'], async () => {
      await expect(isBlacklisted(env.record_manager_db, 'admin.example.com.')).resolves.toBe(true)
      await expect(isBlacklisted(env.record_manager_db, 'ADMIN.example.com')).resolves.toBe(true)
    })
  })

  it('never treats pattern dots/dashes as regex metacharacters', async () => {
    await withPatterns(['a.b-c.example.com'], async () => {
      // "b" alone would match regex /a.b-c.../? No — '.' matches any char,
      // which is why escaping matters: axb must NOT match.
      await expect(isBlacklisted(env.record_manager_db, 'axb-c.example.com')).resolves.toBe(false)
      await expect(isBlacklisted(env.record_manager_db, 'a.b-c.example.com')).resolves.toBe(true)
    })
  })

  it('skips legacy rows containing raw regex without crashing', async () => {
    await withPatterns(['(bad(pattern'], async () => {
      await expect(isBlacklisted(env.record_manager_db, 'anything.example.com')).resolves.toBe(false)
    })
  })

  it('validates new patterns strictly', () => {
    expect(isValidBlacklistPattern('good.*.example.com')).toBe(true)
    expect(isValidBlacklistPattern('')).toBe(false)
    expect(isValidBlacklistPattern('bad (parens)')).toBe(false)
    expect(isValidBlacklistPattern('x'.repeat(101))).toBe(false)
  })
})

describe('BIND zone file parsing', () => {
  it('parses canonical lines with TTL and IN', () => {
    const entries = parseBindZoneFile([
      '; comment',
      '$TTL 3600',
      'www.example.com. 300 IN A 192.0.2.5',
      'mx.example.com. 600 MX 10 backup.example.com.',
      'txt.example.com. 3600 TXT "v=spf1 -all"'
    ].join('\n'))
    expect(entries).toHaveLength(3)
    expect(entries[0]).toMatchObject({ name: 'www.example.com', type: 'A', content: '192.0.2.5', ttl: 300 })
    expect(entries[1]).toMatchObject({ type: 'MX', priority: 10, content: 'backup.example.com' })
    expect(entries[2]).toMatchObject({ type: 'TXT', content: 'v=spf1 -all' })
  })

  it('flags malformed lines as errors instead of throwing', () => {
    const entries = parseBindZoneFile('onlyonefield')
    expect(entries[0].name).toBe('')
    expect(entries[0].type).toBe('')
    expect(entries[0].content).toContain('not enough fields')
  })

  it('imports NS and SRV lines', () => {
    const entries = parseBindZoneFile([
      'example.com. 3600 IN NS ns1.example.com.',
      '_sip._tcp.example.com. 300 IN SRV 10 60 5060 sip.example.com.'
    ].join('\n'))
    expect(entries[0]).toMatchObject({ type: 'NS', content: 'ns1.example.com' })
    expect(entries[1]).toMatchObject({ type: 'SRV', content: '10 60 5060 sip.example.com' })
  })
})

describe('CSV round trip', () => {
  it('re-parses its own export output', () => {
    const records = [
      { name: 'a.example.com', type: 'A', content: '203.0.113.9', ttl: 120 },
      { name: 'm.example.com', type: 'MX', content: 'backup.example.com', ttl: 60, priority: 20 }
    ]
    const csv = formatRecordsCsv(records as any)
    const entries = parseCsv(csv)
    expect(entries).toHaveLength(2)
    expect(entries[0]).toMatchObject({ name: 'a.example.com', type: 'A', content: '203.0.113.9', ttl: 120 })
    expect(entries[1]).toMatchObject({ type: 'MX', priority: 20 })
  })

  it('serializes CNAME/MX targets as absolute FQDNs in BIND', () => {
    const bind = formatRecordsBind('example.com', [
      { name: 'www', type: 'CNAME', content: 'host.example.com', ttl: 1 }
    ] as any)
    expect(bind).toContain('www.\t1\tIN\tCNAME\thost.example.com.')
  })

  it('round-trips TXT rdata with quotes and backslashes through BIND', () => {
    const content = 'say "hi" \\ back'
    const bind = formatRecordsBind('example.com', [
      { name: 't', type: 'TXT', content, ttl: 300 }
    ] as any)
    const entries = parseBindZoneFile(bind)
    expect(entries[0].content).toBe(content)
  })

  it('round-trips CSV cells containing quotes, commas and newlines', () => {
    const records = [
      { name: 'q.example.com', type: 'TXT', content: 'she said "hi\\ok"', ttl: 300 },
      { name: 'n.example.com', type: 'TXT', content: 'line1\nline2, comma', ttl: 300 }
    ]
    const entries = parseCsv(formatRecordsCsv(records as any))
    expect(entries).toHaveLength(2)
    expect(entries[0].content).toBe('she said "hi\\ok"')
    expect(entries[1].content).toBe('line1\nline2, comma')
  })
})

describe('API tokens', () => {
  it('generates rm_-prefixed secrets whose hash resolves back to the user', async () => {
    const secret = generateApiToken()
    expect(secret.startsWith('rm_')).toBe(true)
    expect(secret).toHaveLength(67)

    await env.record_manager_db.prepare(
      "INSERT INTO users (email, role) VALUES ('tokener@test.local','user') ON CONFLICT(email) DO NOTHING"
    ).run()
    const user = await env.record_manager_db.prepare("SELECT id FROM users WHERE email = 'tokener@test.local'").first<any>()
    await env.record_manager_db.prepare(
      'INSERT INTO api_tokens (user_id, name, token_hash) VALUES (?, ?, ?)'
    ).bind(user.id, 'unit', await hashApiToken(secret)).run()

    const resolved = await resolveApiToken(env.record_manager_db, `Bearer ${secret}`)
    expect(resolved?.user.email).toBe('tokener@test.local')

    // Wrong token, wrong scheme, revoked token → null
    await expect(resolveApiToken(env.record_manager_db, `Bearer ${generateApiToken()}`)).resolves.toBeNull()
    await expect(resolveApiToken(env.record_manager_db, `Basic ${secret}`)).resolves.toBeNull()
    await env.record_manager_db.prepare(
      "UPDATE api_tokens SET revoked_at = datetime('now') WHERE user_id = ?"
    ).bind(user.id).run()
    await expect(resolveApiToken(env.record_manager_db, `Bearer ${secret}`)).resolves.toBeNull()
  })
})

describe('record validation', () => {
  it('accepts every Cloudflare record type with flat content', () => {
    for (const type of RECORD_TYPES) {
      const { errors, value } = validateRecordInput({ type, name: 'x.example.com', content: 'ns1.example.com', ttl: '300' })
      expect(errors).toHaveLength(0)
      expect(value!.type).toBe(type)
    }
  })

  it('still rejects unknown types', () => {
    expect(validateRecordInput({ type: 'BOGUS', name: 'x.example.com', content: 'y', ttl: '1' }).value).toBeUndefined()
  })

  it('forces the proxy off for non-proxiable types', () => {
    const ns = validateRecordInput({ type: 'NS', name: 'example.com', content: 'ns1.example.com', ttl: '3600', proxied: 'on' })
    expect(ns.value!.proxied).toBe(false)
    const a = validateRecordInput({ type: 'A', name: 'x.example.com', content: '203.0.113.1', ttl: '300', proxied: 'on' })
    expect(a.value!.proxied).toBe(true)
  })
})

describe('rate limiter', () => {
  it('admits up to the limit then refuses within the window', () => {
    const key = `burst-${Date.now()}` // unique per run so reruns start clean
    let ok = 0
    for (let i = 0; i < 6; i++) if (rateLimit(key, 4, 60_000)) ok++
    expect(ok).toBe(4)
  })

  it('keys buckets independently', () => {
    expect(rateLimit('key-a', 1, 1000)).toBe(true)
    expect(rateLimit('key-a', 1, 1000)).toBe(false)
    expect(rateLimit('key-b', 1, 1000)).toBe(true)
  })
})
