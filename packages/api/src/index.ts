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
import { auditStats, queryAudit, queryFromParams, readAuditFile } from './audit'

const port = Number(process.env.HONMOON_API_PORT ?? 8445)
const auditPath = process.env.HONMOON_AUDIT_LOG ?? 'honmoon-audit.jsonl'

const server = Bun.serve({
  port,
  async fetch(req) {
    const url = new URL(req.url)

    if (url.pathname === '/healthz') {
      return Response.json({ status: 'ok' })
    }

    if (url.pathname === '/api/audit') {
      const events = await readAuditFile(auditPath)
      return Response.json(queryAudit(events, queryFromParams(url.searchParams)))
    }

    if (url.pathname === '/api/audit/stats') {
      const events = await readAuditFile(auditPath)
      return Response.json(auditStats(events))
    }

    return new Response('Not found', { status: 404 })
  },
})

console.log(
  `honmoon api listening on http://localhost:${server.port} (audit log: ${auditPath})`,
)
