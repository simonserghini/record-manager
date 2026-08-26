import type { RecordInput } from './validation'

/**
 * BIND zone-file and CSV serialization/parsing for record import & export.
 *
 * The BIND dialect here is deliberately small and line-based — exactly what
 * this tool exports, plus the common shapes people paste by hand:
 *
 *   ; full-line comments are ignored
 *   name.example.com.  3600  IN  A      1.2.3.4
 *   www.example.com.   1     IN  CNAME  host.example.com.
 *   mx.example.com.    3600  IN  MX     10 backup.example.com.
 *   txt.example.com.   3600  IN  TXT    "v=spf1 -all"
 *
 * $DIRECTIVES ($ORIGIN/$TTL/...) are skipped; names are used verbatim
 * (Cloudflare treats bare names as relative to the zone).
 */

export type ParsedEntry = {
  line: number
  name: string
  type: string
  content: string
  ttl: number
  priority?: number | null
}

export const IMPORT_MAX_ENTRIES = 500

/** Whitespace tokenizer that keeps quoted strings (for TXT rdata) intact. */
function splitRespectingQuotes(line: string): string[] {
  const tokens: string[] = []
  let current = ''
  let inQuotes = false
  for (const ch of line) {
    if (ch === '"') {
      inQuotes = !inQuotes
      current += ch
    } else if (!inQuotes && /\s/.test(ch)) {
      if (current) tokens.push(current)
      current = ''
    } else {
      current += ch
    }
  }
  if (current) tokens.push(current)
  return tokens
}

function unquote(value: string) {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/"\s+"/g, ' ')
  }
  return value
}

function stripTrailingDot(name: string) {
  return name.replace(/\.+$/, '')
}

/** Parses one non-empty, non-comment, non-directive BIND line. */
function parseBindLine(line: string, lineNumber: number): ParsedEntry | { error: string } {
  const tokens = splitRespectingQuotes(line)
  // name ttl [IN] type rdata...  OR  name [IN] type rdata...
  if (tokens.length < 3) return { error: `not enough fields` }

  let idx = 1
  let ttl = 1
  const maybeTtl = parseInt(tokens[idx], 10)
  if (Number.isSafeInteger(maybeTtl) && String(maybeTtl) === tokens[idx]) {
    ttl = maybeTtl === 0 ? 1 : maybeTtl
    idx++
  }
  if ((tokens[idx] || '').toUpperCase() === 'IN') idx++

  const type = (tokens[idx] || '').toUpperCase()
  const rdataTokens = tokens.slice(idx + 1)
  if (!type || rdataTokens.length === 0) return { error: `missing record type or content` }

  const rawType = type
  let content: string
  let priority: number | null = null

  if (rawType === 'MX' && rdataTokens.length >= 2) {
    const prio = parseInt(rdataTokens[0], 10)
    if (Number.isSafeInteger(prio)) {
      priority = prio
      content = stripTrailingDot(unquote(rdataTokens.slice(1).join(' ')))
    } else {
      content = stripTrailingDot(unquote(rdataTokens.join(' ')))
    }
  } else if (rawType === 'TXT') {
    content = unquote(rdataTokens.join(' '))
  } else {
    content = stripTrailingDot(unquote(rdataTokens.join(' ')))
  }

  return {
    line: lineNumber,
    name: stripTrailingDot(tokens[0]),
    type,
    content,
    ttl,
    priority
  }
}

/** Parses a pasted/uploaded zone file into entries with per-line errors. */
export function parseBindZoneFile(text: string): ParsedEntry[] {
  const entries: ParsedEntry[] = []
  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length && entries.length <= IMPORT_MAX_ENTRIES; i++) {
    const raw = lines[i].trim()
    if (!raw || raw.startsWith(';') || raw.startsWith('$') || raw.startsWith('#')) continue

    const parsed = parseBindLine(raw, i + 1)
    if ('error' in parsed) {
      entries.push({ line: i + 1, name: '', type: '', content: parsed.error, ttl: 1 })
      continue
    }
    entries.push(parsed)
    if (entries.length > IMPORT_MAX_ENTRIES) break
  }
  return entries
}

/** Parses CSV in the exact shape exportRecordsCsv produces. */
export function parseCsv(text: string): ParsedEntry[] {
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0)
  const entries: ParsedEntry[] = []
  const startIdx = lines[0]?.toLowerCase().startsWith('name,type,content') ? 1 : 0

  for (let i = startIdx; i < lines.length && entries.length <= IMPORT_MAX_ENTRIES; i++) {
    const cells = splitCsvLine(lines[i])
    if (cells.length < 3) {
      entries.push({ line: i + 1, name: '', type: '', content: 'expected at least name,type,content', ttl: 1 })
      continue
    }
    const ttl = parseInt(cells[3] ?? '1', 10)
    const priority = cells[4] ? parseInt(cells[4], 10) : null
    entries.push({
      line: i + 1,
      name: stripTrailingDot(cells[0]),
      type: cells[1].toUpperCase(),
      content: cells[2],
      ttl: Number.isSafeInteger(ttl) && ttl > 0 ? ttl : 1,
      priority: Number.isSafeInteger(priority!) ? priority : null
    })
    if (entries.length > IMPORT_MAX_ENTRIES) break
  }
  return entries
}

function splitCsvLine(line: string): string[] {
  const cells: string[] = []
  let current = ''
  let inQuotes = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { current += '"'; i++ }
      else if (ch === '"') inQuotes = false
      else current += ch
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === ',') {
      cells.push(current); current = ''
    } else {
      current += ch
    }
  }
  cells.push(current)
  return cells.map(c => c.trim())
}

function csvEscape(value: string | number | null | undefined) {
  const s = String(value ?? '')
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

type ExportRecord = { name: string; type: string; content: string; ttl: number; priority?: number | null; proxied?: boolean }

/** Serializes records as a BIND zone file body. */
export function formatRecordsBind(zoneName: string, records: ExportRecord[]) {
  const lines = [
    `;; ${zoneName} — exported by Record Manager on ${new Date().toISOString()}`,
    '',
    ...records.map(r => {
      const rdata = r.type === 'MX' && r.priority != null
        ? `${r.priority} ${r.content}.`
        : r.type === 'TXT' ? `"${r.content.replace(/"/g, '\\"')}"` : `${r.content}${needsDot(r) ? '.' : ''}`
      return `${r.name}.\t${r.ttl}\tIN\t${r.type}\t${rdata}`
    })
  ]
  return lines.join('\n') + '\n'
}

// CNAME/MX targets must be absolute FQDNs in a zone file.
function needsDot(record: ExportRecord) {
  return ['CNAME', 'MX', 'NS', 'SRV'].includes(record.type) && !record.content.endsWith('.')
}

/** Serializes records as CSV (name,type,content,ttl,priority,proxied). */
export function formatRecordsCsv(records: ExportRecord[]) {
  const rows = [
    'name,type,content,ttl,priority,proxied',
    ...records.map(r => [
      csvEscape(r.name),
      csvEscape(r.type),
      csvEscape(r.content),
      csvEscape(r.ttl),
      csvEscape(r.priority ?? ''),
      csvEscape(r.proxied ? 'true' : 'false')
    ].join(','))
  ]
  return rows.join('\n') + '\n'
}
