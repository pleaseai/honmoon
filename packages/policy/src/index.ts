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
  /**
   * CEL expression over protocol facts, e.g. `"sql.verb == 'DROP'"`.
   *
   * Must not be blank. A blank condition is not "always" (that is the literal
   * `"true"`) and not a disabled rule either: it carries no expression, so the
   * rule can never match and is silently inert. `Policy::from_yaml` rejects
   * the whole policy rather than load it that way.
   *
   * The JSON Schema rejects exactly the same set. Its `pattern` is not a plain
   * `\S`: over the whole of Unicode, ECMAScript `\s` differs from Rust's
   * `char::is_whitespace` in precisely two code points — it omits `U+0085` and
   * adds `U+FEFF` — so the class corrects for both and the two layers agree
   * character for character. `policy.schema.test.ts` pins that.
   *
   * Neither check validates CEL. A condition can be non-blank and still fail
   * to compile — a lone `@`, `§`, or zero-width space is not a CEL expression
   * — in which case the engine declines the rule and the egress default
   * answers. Passing this check only means the field is not empty.
   */
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
 * What the engine knows about the key behind placeholder minting. Present only
 * on a `degraded` event.
 *
 * Two independent things can be wrong with that key, and the event's `rule` says
 * which: `hook-salt-fallback` for a key that is not the persisted one,
 * `hook-salt-exposed` for a key that *is* the persisted one but whose file was
 * left readable beyond its owner and could not be restricted to `0600`. So do
 * not read `key_source: 'persisted'` here as healthy — exposure is a different
 * axis from provenance, and on that rule the provenance is genuinely fine.
 */
export interface RedactionFacts {
  /**
   * Where the HMAC key came from. `unpersisted` is still private and therefore
   * unforgeable, but never reached disk, so placeholders stop being stable
   * across turns; `fallback` is the public compiled-in constant, where
   * unforgeability is gone rather than weakened. `persisted` appears on the
   * `hook-salt-exposed` rule, where the bytes came from the salt file as usual
   * but that file is readable by other local users.
   */
  key_source: 'persisted' | 'unpersisted' | 'fallback'
  /**
   * `hook` is the `honmoon hook` subprocess; `gateway` covers wire redaction
   * and the management hook endpoint, which share one key read at startup.
   */
  transport: 'hook' | 'gateway'
  /**
   * What the loader observed, in its own words: why the persisted key was
   * unavailable, or the mode a salt file it could not restrict was left with.
   */
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
