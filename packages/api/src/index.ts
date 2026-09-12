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
 *
 * Every route but `/healthz` requires the management token as
 * `Authorization: Bearer <token>` (#173) — the same token the Rust gateway
 * requires, resolved from the same places. See `./auth`.
 */
import type { AuditEvent } from '@honmoon/policy'
import { readAuditFile } from './audit'
import { resolveToken } from './auth'
import { createFetchHandler } from './routes'

const port = Number(process.env.HONMOON_API_PORT ?? 8445)
const auditPath = process.env.HONMOON_AUDIT_LOG ?? 'honmoon-audit.jsonl'
const credential = resolveToken()

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
  fetch: createFetchHandler({ token: credential.token, loadEvents }),
})

console.log(
  `honmoon api listening on http://localhost:${server.port} (audit log: ${auditPath})`,
)
// The token itself is never printed: unlike the gateway, this service has no
// browser login flow that would leave an operator unable to find it, and its
// callers can read the environment variable or the file directly.
console.log(
  credential.path === undefined
    ? 'honmoon api: management token from the environment'
    : `honmoon api: management token ${credential.source} at ${credential.path}`,
)
