import { Hono } from 'hono'
import { Fragment } from 'hono/jsx'
import { layout } from '../templates/layout'

type Bindings = {
  record_manager_db: D1Database
}

type Variables = {
  settings: any
  user: any
  flash: any
}

const LOG_PAGE_SIZE = 100

const logs = new Hono<{ Bindings: Bindings; Variables: Variables }>()

logs.get('/', async (c) => {
  const user = c.get('user')
  if (!user || (user.role !== 'owner' && user.role !== 'admin')) return c.redirect('/')

  const pageRaw = parseInt(c.req.query('page') || '1', 10)
  const page = Number.isSafeInteger(pageRaw) && pageRaw > 0 ? pageRaw : 1
  const offset = (page - 1) * LOG_PAGE_SIZE

  const db = c.env.record_manager_db
  const [logResult, countResult] = await db.batch([
    db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?').bind(LOG_PAGE_SIZE + 1, offset),
    db.prepare('SELECT COUNT(*) AS total FROM audit_logs')
  ]) as any
  const results: any[] = logResult.results
  const total = Number((countResult.results[0] as any)?.total ?? 0)

  const rows = results.slice(0, LOG_PAGE_SIZE)
  const hasPrev = page > 1
  const hasNext = results.length > LOG_PAGE_SIZE
  const pageCount = Math.max(1, Math.ceil(total / LOG_PAGE_SIZE))

  return c.html(layout('Audit Logs', (
    <Fragment>
    <div class="mb-8 border-b border-slate-200 pb-5 flex flex-col md:flex-row justify-between md:items-end gap-3">
      <div>
        <h2 class="text-2xl font-bold text-slate-900 mb-2 tracking-tight">Audit Logs</h2>
        <p class="text-slate-500 text-sm">Chronological registry of DNS deployments and system alterations. Page {page} of {pageCount} ({total} events).</p>
      </div>
      <div class="flex gap-2 text-xs font-bold">
        {hasPrev && <a href={`/logs?page=${page - 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">&larr; Newer</a>}
        {hasNext && <a href={`/logs?page=${page + 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">Older &rarr;</a>}
      </div>
    </div>

    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-slate-200">
        <thead class="table-header rounded-lg">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Operator</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Action</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Target Resource</th>
            <th class="px-4 py-3 text-left text-xs font-bold text-slate-500 uppercase tracking-wider font-mono">Timestamp</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 bg-transparent">
          {rows.map((l: any) => (
            <tr class="hover:bg-slate-50/50 transition-colors" key={l.id}>
              <td class="px-4 py-4 whitespace-nowrap text-xs text-slate-600 font-mono">{l.user_email}</td>
              <td class="px-4 py-4 whitespace-nowrap">
                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-50 text-indigo-600 border border-indigo-200 uppercase tracking-wider font-mono">{l.action}</span>
              </td>
              <td class="px-4 py-4 whitespace-nowrap">
                <div class="text-sm font-semibold text-slate-900">{l.resource_name}</div>
                <div class="text-xs text-slate-400 font-mono uppercase">{l.resource_type}</div>
              </td>
              <td class="px-4 py-4 whitespace-nowrap text-xs text-slate-500 font-mono">{l.created_at}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr><td colspan={4} class="px-4 py-10 text-center text-xs text-slate-400 italic font-mono">No audit events recorded yet.</td></tr>
          )}
        </tbody>
      </table>
    </div>

    {(hasPrev || hasNext) && (
      <div class="mt-6 flex gap-2 justify-center text-xs font-bold">
        {hasPrev && <a href={`/logs?page=${page - 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">&larr; Newer</a>}
        {hasNext && <a href={`/logs?page=${page + 1}`} class="px-4 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 transition">Older &rarr;</a>}
      </div>
    )}
    </Fragment>
  ), user, c.get('flash')))
})

export default logs
