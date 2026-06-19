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

export interface Policy {
  version?: number
  egress?: Egress
  rules?: Rule[]
}

export const DEFAULT_EGRESS_VERDICT: Verdict = 'deny'
