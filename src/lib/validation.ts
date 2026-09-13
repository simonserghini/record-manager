// Every record type the Cloudflare API accepts through a flat name/content
// pair (https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/).
// Types with structured rdata carry it inside `content`:
//   SRV: "priority weight port target"   CAA: "flags tag \"value\""
export const RECORD_TYPES = [
  'A', 'AAAA', 'CAA', 'CERT', 'CNAME', 'DNSKEY', 'DS', 'HTTPS', 'LOC', 'MX',
  'NAPTR', 'NS', 'PTR', 'SMIMEA', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI'
] as const

// Types eligible for Cloudflare's proxy (orange cloud). The API rejects
// proxied=true for everything else, so validation forces it off here instead
// of letting the write fail downstream.
const PROXIABLE_TYPES: readonly string[] = ['A', 'AAAA', 'CNAME']

// TTL 1 means "Auto" in the Cloudflare API; otherwise the minimum is 60s
const TTL_AUTO = 1
const TTL_MIN = 60
const TTL_MAX = 86400

const NAME_MAX = 255
const CONTENT_MAX = 2048

export type RecordInput = {
  type: string
  name: string
  content: string
  ttl: number
  proxied: boolean
  priority?: number | null
}

/**
 * Validates and normalizes DNS record form input. Returns a list of
 * human-readable errors instead of throwing, so callers can surface them
 * as flash messages.
 */
export function validateRecordInput(body: Record<string, string | File>): { errors: string[]; value?: RecordInput } {
  const errors: string[] = []

  const type = String(body.type || '').toUpperCase().trim()
  if (!RECORD_TYPES.includes(type as any)) {
    errors.push(`Record type must be one of: ${RECORD_TYPES.join(', ')}.`)
  }

  const name = String(body.name || '').trim()
  if (!name || name.length > NAME_MAX) {
    errors.push(`Record name is required (max ${NAME_MAX} characters).`)
  }

  const content = String(body.content || '').trim()
  if (!content || content.length > CONTENT_MAX) {
    errors.push(`Record content is required (max ${CONTENT_MAX} characters).`)
  }

  let ttl = parseInt(String(body.ttl ?? '1'), 10)
  if (!Number.isFinite(ttl)) ttl = TTL_AUTO
  if (ttl !== TTL_AUTO && (ttl < TTL_MIN || ttl > TTL_MAX)) {
    errors.push(`TTL must be ${TTL_MIN}–${TTL_MAX} seconds, or Auto.`)
    ttl = TTL_AUTO
  }

  // Priority only means something for MX records.
  let priority: number | null = null
  if (type === 'MX' && body.priority !== undefined && String(body.priority).trim() !== '') {
    priority = parseInt(String(body.priority), 10)
    if (!Number.isSafeInteger(priority) || priority < 0 || priority > 65535) {
      errors.push('MX priority must be between 0 and 65535.')
      priority = null
    }
  }

  if (errors.length > 0) return { errors }

  return {
    errors,
    value: {
      type,
      name,
      content,
      ttl,
      proxied: body.proxied === 'on' && PROXIABLE_TYPES.includes(type),
      priority
    }
  }
}

/** Parses an integer route param, returning null when it is not a valid ID. */
export function parseId(raw: string): number | null {
  const id = parseInt(raw, 10)
  return Number.isSafeInteger(id) && id > 0 ? id : null
}
