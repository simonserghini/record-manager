import path from 'node:path'
import { defineConfig } from 'vitest/config'
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers'

/**
 * In-process stand-in for api.cloudflare.com. Stateful: DNS records created
 * through POST live in a Map keyed by zone, so create → list → delete flows
 * behave like the real API without any network access.
 */
type MockRecord = { id: string; name: string; type: string; content: string; ttl: number; proxied?: boolean; priority?: number | null }
const mockZones = [
  { id: 'zone-aaa', name: 'example.com', status: 'active' },
  { id: 'zone-bbb', name: 'other.org', status: 'active' }
]
const recordsByZone = new Map<string, MockRecord[]>([
  ['zone-aaa', [{ id: 'rec-1', name: 'example.com', type: 'A', content: '203.0.113.10', ttl: 300 }]],
  ['zone-bbb', []]
])
let nextRecordId = 100

function cfJson(result: unknown, status = 200) {
  return new Response(JSON.stringify({ success: true, errors: [], messages: [], result }), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

function cfApiMock(request: Request): Response | Promise<Response> {
  const url = new URL(request.url)
  if (url.hostname !== 'api.cloudflare.com') {
    return new Response(`unexpected outbound fetch: ${request.method} ${url}`, { status: 599 })
  }

  if (url.pathname === '/client/v4/zones' && request.method === 'GET') {
    return cfJson(mockZones)
  }

  const match = url.pathname.match(/^\/client\/v4\/zones\/([^/]+)\/dns_records(?:\/([^/]+))?$/)
  if (!match) return cfJson(null, 404)
  const [, zoneId, recordId] = match
  const records = recordsByZone.get(zoneId) ?? []

  if (request.method === 'GET') {
    const record = recordId ? records.find(r => r.id === recordId) ?? null : records
    return cfJson(record)
  }
  if (request.method === 'POST') {
    return request.json().then((body: any) => {
      const created: MockRecord = { id: `rec-${nextRecordId++}`, ttl: 1, ...body }
      records.push(created)
      return cfJson(created)
    })
  }
  if (request.method === 'PUT' && recordId) {
    return request.json().then((body: any) => {
      const idx = records.findIndex(r => r.id === recordId)
      if (idx === -1) return cfJson(null, 404)
      records[idx] = { ...records[idx], ...body }
      return cfJson(records[idx])
    })
  }
  if (request.method === 'DELETE' && recordId) {
    const idx = records.findIndex(r => r.id === recordId)
    if (idx === -1) return cfJson(null, 404)
    const [removed] = records.splice(idx, 1)
    return cfJson({ id: removed.id })
  }

  return cfJson(null, 405)
}

// The cookie-signing secret is NOT injected as a var here — the plugin's
// handling of vars overrides proved unreliable. Instead setup.ts upserts a
// known SYSTEM_SECRET into the settings table, and both the worker
// middleware and test/helpers.ts derive their secret from that single value.
export default defineConfig(async () => ({
  test: {
    // Migrations ride in as a JSON binding so setup code inside the worker
    // can apply them via applyD1Migrations() before anything else runs.
    setupFiles: ['./test/setup.ts']
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        outboundService: cfApiMock,
        bindings: { TEST_MIGRATIONS: await readD1Migrations(path.resolve(process.cwd(), 'migrations')) }
      } as never
    })
  ]
}))
