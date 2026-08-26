const CF_API_BASE = 'https://api.cloudflare.com/client/v4'

type CFApiError = { errors?: { message?: string }[] }

async function cfError(response: Response): Promise<Error> {
  let message = `Cloudflare API error (HTTP ${response.status})`
  try {
    const body = await response.json() as CFApiError
    if (body.errors?.[0]?.message) message = body.errors[0].message
  } catch {
    // keep the generic message
  }
  return new Error(message)
}

async function cfRequest(token: string, path: string, options: RequestInit = {}) {
  const response = await fetch(`${CF_API_BASE}${path}`, {
    ...options,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) throw await cfError(response)
  return (await response.json() as any).result
}

/**
 * Fetches every page of a paginated Cloudflare collection endpoint.
 * Without this, zones/records beyond the first page were silently dropped.
 */
async function cfListAll(token: string, basePath: string): Promise<any[]> {
  const all: any[] = []
  let page = 1

  for (;;) {
    const response = await fetch(`${CF_API_BASE}${basePath}?page=${page}&per_page=100`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) throw await cfError(response)

    const data = await response.json() as any
    all.push(...(data.result ?? []))

    // Stop when this page came back short or we have reached total_pages.
    const info = data.result_info
    const totalPages = info?.total_pages ?? Math.ceil((info?.total_count ?? all.length) / (info?.per_page || 100))
    if ((info && all.length >= info.total_count) || page >= totalPages) break
    page++
  }

  return all
}

async function sha256Hex(input: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export class CloudflareClient {
  private token: string;

  constructor(token: string) {
    this.token = token;
  }

  /**
   * Lists every zone on the account. Results are cached at the edge for 60s
   * (keyed by a hash of the token) so page views don't hit the Cloudflare
   * API on every request.
   */
  async listZones(): Promise<any[]> {
    const cacheKey = new Request(`https://cache.internal/zones/${await sha256Hex(this.token)}`)
    const cache = caches.default

    const cached = await cache.match(cacheKey)
    if (cached) return cached.json()

    const zones = await cfListAll(this.token, '/zones')
    await cache.put(cacheKey, new Response(JSON.stringify(zones), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' }
    }))
    return zones
  }

  async getZone(zoneId: string) {
    return cfRequest(this.token, `/zones/${zoneId}`)
  }

  async listRecords(zoneId: string) {
    return cfListAll(this.token, `/zones/${zoneId}/dns_records`)
  }

  async createRecord(zoneId: string, record: { type: string; name: string; content: string; ttl?: number; proxied?: boolean; priority?: number | null }) {
    return cfRequest(this.token, `/zones/${zoneId}/dns_records`, {
      method: 'POST',
      body: JSON.stringify(record),
    });
  }

  async updateRecord(zoneId: string, recordId: string, record: { type: string; name: string; content: string; ttl?: number; proxied?: boolean; priority?: number | null }) {
    return cfRequest(this.token, `/zones/${zoneId}/dns_records/${recordId}`, {
      method: 'PUT',
      body: JSON.stringify(record),
    });
  }

  async deleteRecord(zoneId: string, recordId: string) {
    return cfRequest(this.token, `/zones/${zoneId}/dns_records/${recordId}`, {
      method: 'DELETE',
    });
  }
}
