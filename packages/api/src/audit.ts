/**
 * Audit-log query layer.
 *
 * The Rust data plane appends every verdict to a JSONL file (one
 * {@link AuditEvent} per line, `honmoon gateway --audit-log`). This module reads
 * and queries that durable log — the historical/offline counterpart to the
 * in-memory ring the management API serves. Pure functions here are unit-tested;
 * the Bun server in `index.ts` wires them to HTTP.
 */
import type { AuditEvent, Decision } from '@honmoon/policy'

export interface AuditQuery {
  /** Max events to return, newest first (default 200). */
  limit?: number
  /** Keep only events with this final decision. */
  decision?: Decision
  /** Keep only events at or after this RFC 3339 timestamp. */
  since?: string
  /** Keep only events whose target domain contains this substring. */
  domain?: string
}

const DECISIONS: Decision[] = ['allowed', 'denied', 'paused', 'approved', 'rejected']

/** Parse a JSONL audit log, skipping blank or malformed lines. */
export function parseJsonl(text: string): AuditEvent[] {
  const out: AuditEvent[] = []
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) {
      continue
    }
    try {
      out.push(JSON.parse(trimmed) as AuditEvent)
    }
    catch {
      // A partially-written trailing line is expected while the gateway runs.
    }
  }
  return out
}

/** Apply filters and return events newest-first, capped at `limit`. */
export function queryAudit(events: AuditEvent[], q: AuditQuery = {}): AuditEvent[] {
  let result = events
  if (q.decision) {
    result = result.filter(e => e.decision === q.decision)
  }
  if (q.since) {
    const floor = Date.parse(q.since)
    if (!Number.isNaN(floor)) {
      result = result.filter(e => Date.parse(e.timestamp) >= floor)
    }
  }
  if (q.domain) {
    const needle = q.domain.toLowerCase()
    result = result.filter(e => e.facts.domain?.toLowerCase().includes(needle))
  }
  // Sort by timestamp, not id: ids are process-local and restart from 1 after
  // a gateway restart, so a reused JSONL file would otherwise misorder events
  // and `limit` could hide the genuinely newest entries. id breaks ties.
  const sorted = [...result].sort((a, b) => {
    const at = Date.parse(a.timestamp)
    const bt = Date.parse(b.timestamp)
    if (!Number.isNaN(at) && !Number.isNaN(bt) && at !== bt) {
      return bt - at
    }
    return b.id - a.id
  })
  const limit = q.limit && q.limit > 0 ? q.limit : 200
  return sorted.slice(0, limit)
}

/** Count events by decision (handy for an overview / report). */
export function auditStats(events: AuditEvent[]): Record<Decision, number> {
  const stats = Object.fromEntries(DECISIONS.map(d => [d, 0])) as Record<Decision, number>
  for (const e of events) {
    if (e.decision in stats) {
      stats[e.decision] += 1
    }
  }
  return stats
}

/** Parse an `AuditQuery` from URL search params. */
export function queryFromParams(params: URLSearchParams): AuditQuery {
  const q: AuditQuery = {}
  const limit = params.get('limit')
  if (limit) {
    q.limit = Number(limit)
  }
  const decision = params.get('decision')
  if (decision && (DECISIONS as string[]).includes(decision)) {
    q.decision = decision as Decision
  }
  const since = params.get('since')
  if (since) {
    q.since = since
  }
  const domain = params.get('domain')
  if (domain) {
    q.domain = domain
  }
  return q
}

/** Read and parse the JSONL audit log; returns `[]` if the file is absent. */
export async function readAuditFile(path: string): Promise<AuditEvent[]> {
  const file = Bun.file(path)
  if (!(await file.exists())) {
    return []
  }
  return parseJsonl(await file.text())
}
