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
   * — and passing this check only means the field is not empty. Since #191 the
   * Rust loader is where such a condition is caught: `Policy::from_yaml` fails
   * the load and names every rule responsible, rather than loading the policy
   * with those rules inert.
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
 * which: `hook-salt-fallback` for a key that is not the persisted one, or one of
 * two exposure rules for a key that *is* the persisted one but whose file was
 * readable beyond its owner — `hook-salt-exposed` when it still is after the
 * loader tried to restrict it, `hook-salt-was-exposed` when the loader found it
 * that way and the restriction took. Those two are split because their remedies
 * are: a file that is loose now can be tightened, while one that was is a key
 * that may already be copied. So do not read `key_source: 'persisted'` here as
 * healthy — exposure is a different axis from provenance, and on *both* of the
 * exposure rules the provenance is genuinely fine. (Not on `hook-salt-fallback`,
 * where the provenance is exactly what is broken: `key_source` there is
 * `unpersisted` or `fallback`, never `persisted`.)
 *
 * A fourth rule is not about the key in use at all: `hook-salt-replaced-unread`
 * says the loader discarded a salt file it could not read, so what it held — and
 * whether any invocation had been adopting it as a key — is unknown. Its
 * `key_source` still names the key *in use*, so read `rule` before `reason`
 * here: the reason describes the file that was discarded, not the key the rest
 * of the record is about. That is `persisted` where the replacement landed and
 * `fallback` where the loader destroyed the file and could not write one, in
 * which case this rule accompanies `hook-salt-fallback`.
 */
export interface RedactionFacts {
  /**
   * Where the HMAC key came from. `unpersisted` is still private and therefore
   * unforgeable, but never reached disk, so placeholders stop being stable
   * across turns; `fallback` is the public compiled-in constant, where
   * unforgeability is gone rather than weakened. `persisted` appears on the
   * `hook-salt-exposed` and `hook-salt-was-exposed` rules, where the bytes came
   * from the salt file as usual but that file is — or was, until the loader
   * tightened it — readable by other local users, and on
   * `hook-salt-replaced-unread` where the replacement landed, in which case the
   * bytes are a fresh secret and the event is about the file they replaced.
   */
  key_source: 'persisted' | 'unpersisted' | 'fallback'
  /**
   * `hook` is the `honmoon hook` subprocess; `gateway` covers wire redaction
   * and the management hook endpoint, which share one key read at startup.
   */
  transport: 'hook' | 'gateway'
  /**
   * What the loader observed, in its own words: why the persisted key was
   * unavailable, or the modes it saw on a salt file readable beyond its owner —
   * the one it was left with under `hook-salt-exposed`, the one it was found with
   * under `hook-salt-was-exposed`. Under `hook-salt-replaced-unread` it describes
   * a different file from the key in use: the one the loader discarded without
   * reading, the error that stopped it reading, and the mode that file carried
   * when the loader last looked at it.
   *
   * **Deliberately untrimmed** (issue #162), so it may carry a local path and a
   * raw OS error. For the `honmoon hook` transport this record is the only
   * durable channel — a fresh process per invocation, no ring to query,
   * `tracing` filtered out without `RUST_LOG` (issue #131) — which makes "which
   * file, and what did the OS say" most of what it is for. The salt loader
   * resolves its directory first, so the path identifies one file rather than
   * being relative to a working directory no field records.
   *
   * Renderers must not summarise or drop it: on an exposure event `key_source`
   * stays `persisted` and reads healthy on its own, leaving this the only field
   * carrying the bad news. The disclosure that prompted the question was the
   * missing auth layer on the management reads, which issue #173 closed: every
   * management read now requires the management token, so this content no
   * longer reaches an unauthenticated caller. It was never this field, and
   * trimming it was never a substitute.
   */
  reason: string
}

/**
 * What the audit sink open observed about who else can reach the audit file
 * (issue #161). Present only on a `degraded` event, and the event's `rule` says
 * which observation it is: `audit-sink-exposed` for a mode that admits local
 * users other than the owner, `audit-sink-foreign-owner` for a file another uid
 * owns, `audit-sink-hard-linked` for an inode named by more than one directory
 * entry. Honmoon reports these and changes nothing — the path is an operator
 * flag, plausibly read by a log shipper on purpose — so the record carries what
 * was observed, never what was done, and one open can produce all three.
 */
export interface AuditSinkFacts {
  /**
   * The sink as the operator configured it (`--audit-log` / `HONMOON_AUDIT_LOG`),
   * not resolved: the record is appended to that same file, so a reader holding
   * the log already holds the resolution the string lacks.
   */
  path: string
  /**
   * What the `fstat` on the opened descriptor showed, in its own words — the
   * mode, the owning uid, or the link count. Like `RedactionFacts.reason`, it
   * is the only field carrying the bad news, so renderers must not drop it.
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
  /** Set only on a `degraded` event about the audit sink itself. */
  sink?: AuditSinkFacts
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
