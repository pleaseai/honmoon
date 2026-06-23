/**
 * @honmoon/api — audit-log query API.
 *
 * The durable, queryable view over the local audit log the Rust gateway writes
 * (`honmoon gateway --audit-log <file>`). Interactive approvals are served by
 * the in-process management API (`honmoon-mgmt`), which must share the data
 * plane's runtime; this service is the read/historical layer over the JSONL log.
 *
 * Endpoints:
 *   GET /healthz
 *   GET /api/audit?limit=&decision=&since=&domain=
 *   GET /api/audit/stats
 */
import type { AuditEvent } from '@honmoon/policy'
import { auditStats, queryAudit, queryFromParams, readAuditFile } from './audit'

const port = Number(process.env.HONMOON_API_PORT ?? 8445)
const auditPath = process.env.HONMOON_AUDIT_LOG ?? 'honmoon-audit.jsonl'

// Polling clients hit these endpoints frequently; re-reading and re-parsing the
// whole JSONL log per request is O(file-size) and grows hot as the log does.
// A short TTL coalesces bursts into one read while staying near-real-time.
const CACHE_MS = 1000
let cache: { loadedAt: number, events: AuditEvent[] } | null = null

async function loadEvents(): Promise<AuditEvent[]> {
  const now = Date.now()
  if (cache && now - cache.loadedAt < CACHE_MS) {
    return cache.events
  }
  const events = await readAuditFile(auditPath)
  cache = { loadedAt: now, events }
  return events
}

const server = Bun.serve({
  port,
  async fetch(req) {
    const url = new URL(req.url)

    if (url.pathname === '/healthz') {
      return Response.json({ status: 'ok' })
    }

    if (url.pathname === '/api/audit') {
      const events = await loadEvents()
      return Response.json(queryAudit(events, queryFromParams(url.searchParams)))
    }

    if (url.pathname === '/api/audit/stats') {
      const events = await loadEvents()
      return Response.json(auditStats(events))
    }

    return new Response('Not found', { status: 404 })
  },
})

console.log(
  `honmoon api listening on http://localhost:${server.port} (audit log: ${auditPath})`,
)
