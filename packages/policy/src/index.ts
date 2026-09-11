/**
 * @honmoon/policy — policy types and validation shared across the control plane.
 *
 * Mirrors the Rust model in `crates/honmoon-core`. Keep the two in sync.
 */

export type Verdict = 'allow' | 'deny' | 'pause'

export interface Egress {
  /** Verdict when no allow/deny entry matches. Defaults to `deny`. */
  default?: Verdict
  allow?: string[]
  deny?: string[]
}

/** A protocol-aware rule evaluated against protocol facts via a CEL condition. */
export interface Rule {
  name: string
  endpoint: string
  /** CEL expression over protocol facts, e.g. `"sql.verb == 'DROP'"`. */
  condition: string
  verdict: Verdict
}

/** The wire protocol spoken at an endpoint. Defaults to `tcp`. */
export type EndpointProtocol = 'postgres' | 'kubernetes' | 'tcp'

/** A named network target a `Rule.endpoint` can refer to. */
export interface Endpoint {
  host: string
  port: number
  protocol?: EndpointProtocol
}

export interface Policy {
  version?: number
  egress?: Egress
  /** Named network targets, keyed by name. */
  endpoints?: Record<string, Endpoint>
  rules?: Rule[]
}

export const DEFAULT_EGRESS_VERDICT: Verdict = 'deny'

// --- Runtime decision model (Phase 4) ---------------------------------------
// Mirrors `honmoon-core::audit` and `honmoon-proxy::approval`. Serialized by the
// management API; consumed by the dashboard and `@honmoon/api` query layer.

/**
 * What an audit entry records: the disposition of a request, or — for
 * `degraded` — a security property the engine is running without. Honmoon's
 * degradations are fail-open and look identical from the outside, so `degraded`
 * is how one stops being silent (see `RedactionFacts`).
 */
export type Decision = 'allowed' | 'denied' | 'paused' | 'approved' | 'rejected' | 'degraded'

export interface HttpFacts {
  method: string
  host: string
  path: string
  body_size: number
}

export interface SqlFacts {
  verb: string
  table: string
}

export interface K8sFacts {
  verb: string
  resource: string
  namespace: string
}

/**
 * Why placeholder minting is or is not keyed by a private secret. Present only
 * on a `degraded` event.
 *
 * A `fallback` key is the constant compiled into the binary and published in
 * this repository's source: redaction keeps working and placeholders stay
 * byte-stable, but anyone can mint the placeholder a guessed secret would
 * produce and check it against a redacted transcript.
 */
export interface RedactionFacts {
  /** `persisted` (the private per-machine secret) or `fallback` (public). */
  key_source: string
  /** `hook` (the `honmoon hook` subprocess) or `gateway`. */
  transport: string
  /** Why the persisted key was unavailable. */
  reason: string
}

/** Compact snapshot of the facts a decision was made on. */
export interface FactsSummary {
  domain?: string
  endpoint?: string
  http?: HttpFacts
  sql?: SqlFacts
  k8s?: K8sFacts
  redaction?: RedactionFacts
}

/** One recorded decision (`GET /api/audit`). */
export interface AuditEvent {
  id: number
  /** RFC 3339 / ISO 8601 UTC timestamp. */
  timestamp: string
  decision: Decision
  verdict: Verdict
  /** Name of the rule that fired, or absent for an egress-list decision. */
  rule?: string
  facts: FactsSummary
  /** Links a `paused` event to its later `approved`/`rejected` event. */
  approval_id?: number
}

/** A request held awaiting human approval (`GET /api/approvals`). */
export interface PendingApproval {
  id: number
  /** RFC 3339 time the request was held. */
  created_at: string
  endpoint?: string
  domain?: string
  rule?: string
  /** Human-readable one-liner describing what is being approved. */
  summary: string
}
