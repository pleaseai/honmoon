---
title: Policy Authoring
description: Write Honmoon policies — egress allow/deny lists and CEL protocol rules.
---

# Policy Authoring

A Honmoon policy is a single YAML document with three sections: an `egress` block (domain
allow/deny lists — the common case), an optional `endpoints` map (named network targets), and a
list of `rules` (protocol-aware CEL conditions — the fine-grained case). The same field structure
is described by the Rust model
([lib.rs:44-117](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L44-L117)),
the TypeScript types ([index.ts:7-45](https://github.com/pleaseai/honmoon/blob/main/packages/policy/src/index.ts#L7-L45)),
and the JSON Schema ([policy.schema.json](https://github.com/pleaseai/honmoon/blob/main/packages/policy/schema/policy.schema.json)) —
though their *validation* differs: the JSON Schema is the strict one (`additionalProperties: false`,
`version ≥ 1`), while the Rust loader tolerates and defaults missing fields and the TS types are
compile-time only. Keeping the three aligned is tracked as TD-001.

## At a glance

| Field | Type | Default | Meaning | Source |
|-------|------|---------|---------|--------|
| `version` | integer ≥ 1 | `0` | Policy schema version | [policy.schema.json:8](https://github.com/pleaseai/honmoon/blob/main/packages/policy/schema/policy.schema.json#L8) |
| `egress.default` | verdict | `deny` | Verdict when no allow/deny entry matches | [lib.rs:86-88](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L86-L88) |
| `egress.allow` | string[] | `[]` | Domain patterns to allow | [lib.rs:89-90](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L89-L90) |
| `egress.deny` | string[] | `[]` | Domain patterns to deny (wins over allow) | [lib.rs:91-92](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L91-L92) |
| `endpoints` | map&lt;name, endpoint&gt; | `{}` | Named network targets a rule can bind to | [lib.rs:51-55](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L51-L55) |
| `rules[]` | rule[] | `[]` | Ordered protocol-aware rules | [lib.rs:109-117](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L109-L117) |

A **verdict** is one of `allow`, `deny`, `pause` ([policy.schema.json:24-27](https://github.com/pleaseai/honmoon/blob/main/packages/policy/schema/policy.schema.json#L24-L27)).

## The shipped example

```yaml
# policies/agent.yaml
# yaml-language-server: $schema=../packages/policy/schema/policy.schema.json
version: 1

egress:
  default: deny
  allow:
    - github.com
    - '*.githubusercontent.com'
    - api.anthropic.com
    - k8s.internal # endpoint hosts need an allow entry of their own
    - db.internal
  deny:
    - '*.internal.corp'

endpoints:
  k8s-prod: {host: k8s.internal, port: 6443, protocol: kubernetes}
  postgres-prod: {host: db.internal, port: 5432, protocol: postgres}

rules:
  - name: k8s-no-secret-delete
    endpoint: k8s-prod
    condition: "k8s.resource == 'secrets' && k8s.verb == 'delete'"
    verdict: deny

  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"
    verdict: pause

  - name: http-block-large-upload
    endpoint: '*'
    condition: "http.method == 'POST' && http.body_size > 10485760"
    verdict: deny
```

The first line is a `yaml-language-server` modeline so editors validate against the JSON Schema
as you type ([agent.yaml:1](https://github.com/pleaseai/honmoon/blob/main/policies/agent.yaml#L1)).

## Egress domain matching

Domain patterns support an exact match or a single leading `*.` wildcard. Matching is
case-insensitive on both sides ([engine.rs:56-64](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L56-L64)):

| Pattern | Matches | Does **not** match |
|---------|---------|--------------------|
| `github.com` | `github.com`, `GitHub.com` | `api.github.com` |
| `*.githubusercontent.com` | `raw.githubusercontent.com`, `githubusercontent.com` | `evilgithubusercontent.com` |

The `*.suffix` form matches the bare `suffix` **and** any `*.suffix` subdomain
([engine.rs:59-60](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L59-L60)).
Within the egress block, **deny wins over allow**, and an unmatched domain falls through to
`egress.default` ([engine.rs:147-162](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L147-L162)):

```mermaid
flowchart TD
  start["domain"] --> deny{"matches a deny pattern?"}
  deny -->|yes| D["Deny"]
  deny -->|no| allow{"matches an allow pattern?"}
  allow -->|yes| A["Allow"]
  allow -->|no| def["egress.default<br>(deny by default)"]
  style start fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style deny fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style allow fill:#2d333b,stroke:#6d5dfc,color:#e6edf3
  style D fill:#161b22,stroke:#f85149,color:#e6edf3
  style A fill:#161b22,stroke:#3fb950,color:#e6edf3
  style def fill:#161b22,stroke:#d29922,color:#e6edf3
```
<!-- Sources: crates/honmoon-core/src/engine.rs:30-64 -->

## Named endpoints

`endpoints` maps a name to the network target a client dials. A rule's `endpoint` field refers to
one of these names, so a rule like `k8s.resource == 'secrets'` applies to *that cluster* rather
than to every host that happens to serve a similar path.

```yaml
endpoints:
  k8s-prod: {host: k8s.internal, port: 6443, protocol: kubernetes}
  postgres-prod: {host: db.internal, port: 5432, protocol: postgres}
  cache: {host: redis.internal, port: 6379} # protocol defaults to tcp
```

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `host` | string | required | Hostname the client dials |
| `port` | integer 1–65535 | required | Port the client dials |
| `protocol` | `postgres` / `kubernetes` / `tcp` | `tcp` | Which protocol facts to parse |

**Matching is exact**: the host must be equal (case-insensitive, with a trailing FQDN dot
trimmed) *and* the port must be equal. There is no IP resolution and no wildcard host in v0.1.0
([lib.rs:255-272](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L255-L272)).
The port comes from what the client dialed — the CONNECT authority for an HTTPS tunnel, defaulting
to 443 (or 80 for a cleartext forward-proxy request) when the authority carries no explicit port,
or the SOCKS5 handshake's own `host:port` for a non-HTTP protocol.

What each `protocol` does today:

| Value | Effect |
|-------|--------|
| `kubernetes` | Intercepted HTTPS requests to this endpoint get `k8s` facts (`verb`, `resource`, `namespace`) parsed from the method and path |
| `postgres` | Connections that reach this endpoint **through the SOCKS5 listener** are inspected inline: every `Q` (simple query) and `P` (Parse) frame gets `sql` facts and its own verdict ([ADR-0007](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md)) |
| `tcp` | Name only — the endpoint can be referenced by a rule, but no protocol facts are parsed |

### Reaching a `postgres` endpoint

SQL rules only fire on a connection that arrives through the **SOCKS5 listener** — the CONNECT
proxy carries HTTP and TLS, and a PostgreSQL client speaks neither. Run the gateway with the
listener bound (it is on by default) and point the client at it:

```bash
honmoon gateway --config policies/agent.yaml --socks-addr 127.0.0.1:1080
```

```bash
# A client that speaks SOCKS5 dials the endpoint through the listener
ALL_PROXY=socks5h://127.0.0.1:1080 <your-tool>
```

`psql` does not speak SOCKS5 itself, so wrap it in a SOCKS-aware launcher (`proxychains4`,
`tsocks`) or point it at a local forwarder. Use `sslmode=prefer` or `sslmode=disable`: inline
inspection needs plaintext between the client and honmoon, so `SSLRequest` is declined and
`sslmode=require` cannot connect. A refused statement comes back as SQLSTATE `42501`
(insufficient privilege) naming the rule, and the session stays open.

A connection to a host with **no** declared endpoint (or one declared `protocol: tcp`) is a raw
tunnel through the same listener, gated once on `domain` by the `egress` block — no SQL is parsed.

A rule referencing an endpoint that `endpoints` does not declare is a **load-time warning, not an
error**: `Facts.endpoint` may be set by other means, and refusing the whole policy over one
dangling name would fail open for every other rule
([lib.rs:274-290](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L274-L290)).

That tolerance covers *undefined references only*. An unusable `endpoints` entry is a **load-time
error** — the policy is rejected outright
([lib.rs:199-224](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L199-L224)):

| Mistake | Why it fails the load |
|---------|-----------------------|
| `port: 0` | Not a dialable port; the JSON Schema requires 1–65535 |
| Two names on the same `(host, port)` | Lookup would silently pick one and shadow the other, so only one of the author's rules would ever fire (hosts compared case-insensitively with a trailing dot trimmed) |

## Protocol rules with CEL

Each rule binds a [CEL](https://github.com/google/cel-spec) condition to a named `endpoint`.
Rules are evaluated **in order**; the first rule whose endpoint matches and whose condition
evaluates to `true` wins ([engine.rs:100-136](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L100-L136)).
If no rule matches, the egress block decides.

| Rule field | Meaning | Example | Source |
|-----------|---------|---------|--------|
| `name` | Human label | `sql-no-prod-drop` | [lib.rs:112](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L112) |
| `endpoint` | Named target; `*` matches any | `postgres-prod` | [lib.rs:113](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L113), [engine.rs:48-50](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L48-L50) |
| `condition` | CEL over protocol facts | `sql.verb == 'DROP'` | [lib.rs:114-115](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L114-L115) |
| `verdict` | `allow` / `deny` / `pause` | `pause` | [lib.rs:116](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L116) |

### Rule order and unreachable rules

Because the first match wins, an **unconditional** rule — `condition: "true"` — answers every
request its `endpoint` covers, and nothing below it on that endpoint is ever reached.

That matters most for the shape an `egress.default: deny` policy needs around a `postgres`
endpoint. The connection itself is gated before any statement exists, so the endpoint needs a
connection-level `allow`; but a `sql.*` condition cannot match a connection that carries no
statement yet, so that `allow` has to come **after** the statement rules
([ADR-0007](https://github.com/pleaseai/honmoon/blob/main/.please/docs/decisions/0007-inline-postgresql-runtime-semantics.md)):

```yaml
rules:
  # Statement rules first — they only match once a statement exists.
  - name: sql-no-prod-drop
    endpoint: postgres-prod
    condition: "sql.verb == 'DROP' || sql.verb == 'TRUNCATE'"
    verdict: pause

  # The connection-level allow last, so it gates the connect and nothing else.
  - name: postgres-connect
    endpoint: postgres-prod
    condition: "true"
    verdict: allow
```

Write those two the other way round and `postgres-connect` answers every *statement* too — a
`DROP` is allowed, and the rule meant to stop it never runs. `Policy::from_yaml` warns at load
when it finds that ordering, naming both rules
([lib.rs:292-384](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L292-L384)):

```
WARN policy rule is unreachable: an earlier unconditional rule always matches first
  rule="sql-no-prod-drop" shadowed_by="postgres-connect" endpoint="postgres-prod"
```

Two details worth knowing when you read (or don't read) that warning:

- **`endpoint: '*'` covers everything.** An unconditional `*` rule makes *every* rule below it
  unreachable, whatever endpoint those rules name. The reverse does not hold — an unconditional
  rule on one endpoint leaves a later `*` rule reachable through all the others.
- **Only the literal `true` is recognised.** An expression that merely happens to be always true
  (`1 == 1`) is not flagged: Honmoon does not try to prove a CEL expression total, and a warning
  that guessed would be one you learned to ignore.

::: danger Never leave `condition` blank
`condition: ""` is not a way to say "always", and it is not a safe no-op either. A blank string
carries no expression, so the rule can never match — it would sit in your policy looking active
while doing nothing, and an inert rule is indistinguishable from a rule that simply did not match.
So Honmoon refuses to load a policy containing one, where you see it, rather than letting it go
unnoticed in production ([#151](https://github.com/pleaseai/honmoon/issues/151)):

```
Error: rule `blank` (rules[0]) has a blank `condition`; write `"true"` for a rule that always matches
```

Whitespace does not help — `" "`, `"\n"` and a non-breaking or ideographic space are rejected the
same way. A condition made only of **zero-width** characters is not blank, though: it looks empty
in an editor but is not whitespace. It fails the load one step later instead, at the compile check,
with the message for a condition that is not valid CEL (see
[Fail-closed semantics](#fail-closed-semantics)). Either way you find out at startup. Give every
rule a real condition; write `"true"` when you mean always.
:::

### Facts available to conditions

Conditions reference protocol facts as CEL variables of the same name. Each is only populated
when the corresponding parser has run ([lib.rs:129-148](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L129-L148)):

| Variable | Fields | Populated by | Status |
|----------|--------|--------------|--------|
| `http` | `method`, `host`, `path`, `body_size` | CONNECT proxy sets `host` only today | `host` <span class="status-done">live</span> · rest <span class="status-planned">needs TLS termination</span> |
| `sql` | `verb`, `table` | `parse_postgres_query` / `parse_sql` | <span class="status-done">live on SOCKS5 connections to a `postgres` endpoint</span> |
| `k8s` | `verb`, `resource`, `namespace` | `parse_k8s_request` | <span class="status-done">live on intercepted HTTPS to a `kubernetes` endpoint</span> |

### Example conditions

```cel
# Block dangerous DDL against the production database
sql.verb == 'DROP' || sql.verb == 'TRUNCATE'

# Deny deletion of Kubernetes secrets in prod
k8s.resource == 'secrets' && k8s.verb == 'delete'

# Block large uploads (needs HTTP body facts → TLS termination)
http.method == 'POST' && http.body_size > 10485760
```

## Fail-closed semantics

Honmoon is designed to **fail closed**, in two layers.

At **evaluation**, a rule whose condition fails to compile, or which references a fact that has not
been populated, simply **does not match** — it can never turn a `deny` into an `allow`. Combined
with the `deny`-by-default egress verdict, an absent or broken rule is always the safe outcome
([engine.rs:53-58](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L53-L58), [engine.rs:321-353](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs#L321-L353)).
Read "fails to compile" there literally: the CEL compiler **returns an error**, and every outcome
other than `true` means "no match".

At **load**, a condition that fails to compile does not get that far. Conditions are compiled when
the policy is loaded rather than on each request, and since
[#191](https://github.com/pleaseai/honmoon/issues/191) a condition the compiler rejects is a
**load failure**, not a warning: `Policy::from_yaml` refuses the policy and names every rule
responsible
([lib.rs:292-337](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L292-L337)).
So the evaluation layer above is not what you meet when you start a gateway — it is what answers
for a `Policy` built in code, which the library API accepts without going through the loader, and
for a `condition` reassigned on a policy after it loaded.

This used to carry an exception worth knowing about. On the previous CEL crate a whole class of
malformed condition **panicked** rather than returning an error — crashing the decision path
instead of failing closed — and the class was wide: any single character the lexer could not begin
a token with, including invisible ones such as `U+200B` or a stray byte-order mark that render as
nothing in an editor. That was tracked as
[#154](https://github.com/pleaseai/honmoon/issues/154) and is **fixed**: every one of those inputs
now returns an error and declines like any other unparseable condition.

Two things are worth keeping in mind when authoring:

- A **blank** condition is rejected at load, with its own message. `Policy::from_yaml` refuses a
  policy containing one, because a rule with no expression can never match and would sit in your
  policy looking active. See
  [Rule order and unreachable rules](#rule-order-and-unreachable-rules) above.
- **Invalid CEL is rejected at load too — but the JSON Schema still does not catch it.** A
  non-blank condition that is not a valid expression — `"&&"`, a stray `"@"`, a condition made only
  of zero-width characters — fails the load with a message naming the rule and quoting the
  condition. Your editor will not flag it first: the schema checks shape, not CEL, so the loader is
  where you find out. Every offending rule is named in one go, so a policy with three of them takes
  one run to diagnose, not three. `honmoon policy validate <file>` runs that loader on its own, so
  finding out does not mean starting a gateway.

::: warning Breaking change in #191: a gateway that starts today may stop starting
Before [#191](https://github.com/pleaseai/honmoon/issues/191) a policy carrying an uncompilable
condition **loaded**, and you found out the rule was inert from a `warn` line — if anyone read the
log. Now the gateway refuses to start. That is the point: an inert rule looks active in the file
and answers nothing, so an operator who never read that warning was running a policy weaker than
the one they wrote. But it does mean a deployment whose policy has a rule nobody noticed was inert
will fail to boot on upgrade.

The error names every rule and quotes what it carries. Both author-written values are printed the
way Rust prints a string, not in backticks, so a condition made only of invisible characters is
still visible in the message:

```
Error: rule "secrets" (rules[1]) has a `condition` that is not a valid CEL expression: "&&"
```

Check the policy before you upgrade, with `honmoon policy validate` — it loads the file through
this same loader and exits without starting anything (see
[Validating a policy](#validating-a-policy) below):

```bash
honmoon policy validate policies/agent.yaml
```

Nothing else answers this question. The JSON Schema does not parse CEL, `honmoonctl validate` is
still a stub, and starting the gateway is not a dry run: `honmoon gateway --config <file>` refuses
a bad policy before it binds anything, but on a good one it goes on to serve until you stop it —
and it resolves the management token first, so it creates `~/.honmoon/mgmt-token` even on the run
where the policy is what fails.
:::

```mermaid
sequenceDiagram
  autonumber
  participant L as load (Policy::from_yaml)
  participant E as decide()
  participant R as rule.condition (CEL)
  L->>R: compile("sql.verb == 'DROP'")
  alt compile fails
    R-->>L: Err → load fails, naming every rule that carries an uncompilable condition
  else compiles
    R-->>L: Program, kept for every later request
  end
  E->>R: execute the rule's program against facts
  alt inert / facts missing / error / not Bool(true)
    R-->>E: no match → fall through
  else Bool(true)
    R-->>E: match → return rule.verdict
  end
```
<!-- Sources: crates/honmoon-core/src/lib.rs:199-224, crates/honmoon-core/src/lib.rs:292-337, crates/honmoon-core/src/engine.rs:287-353, crates/honmoon-core/src/engine.rs:398-444 -->

This behavior is locked by tests: `unknown_fact_reference_does_not_match` proves a condition
referencing an unpopulated `sql` fact falls through to the egress default, and
`a_condition_that_does_not_compile_fails_the_load_for_the_whole_policy` proves a policy carrying
`"&&"` is refused — sound rules and all — while the same policy with the condition repaired loads
and decides. On the loader side,
`names_every_rule_whose_condition_does_not_compile` pins that all three of a three-fault policy are
reported at once, and `a_blank_condition_is_still_reported_as_blank` pins that a blank condition
keeps its own message rather than being folded into the compile error.

## Validating a policy

| Method | Status | Notes |
|--------|--------|-------|
| `honmoon policy validate <file>` | <span class="status-done">works</span> | The CLI check. Runs the same loader the gateway does, binds nothing, writes nothing |
| Editor (`yaml-language-server` + JSON Schema) | <span class="status-done">works</span> | Live validation via the modeline — shape only, never CEL |
| `Policy::from_yaml` (Rust) | <span class="status-done">works</span> | The loader itself: what `honmoon run` / `gateway` and the command above all call |
| `honmoonctl validate <file>` | <span class="status-planned">stub</span> | Reads the file but YAML parse + schema check are a `TODO` ([cli/src/index.ts:14-23](https://github.com/pleaseai/honmoon/blob/main/packages/cli/src/index.ts#L14-L23)). Prefer `honmoon policy validate` — see below |

### `honmoon policy validate`

```bash
honmoon policy validate policies/agent.yaml
# honmoon: policies/agent.yaml: policy is valid (3 rules, 2 endpoints)
```

It is a load-and-exit check, so what it accepts is what a gateway accepts:

| | |
|---|---|
| **Exit 0** | The policy loads. The gateway would start on it |
| **Exit non-zero** | The policy does not load, and the loader's diagnosis is on stderr |
| **stdout** | Empty. Everything it says goes to stderr, so a CI step can pipe stdout without catching diagnostics |

How much of that diagnosis you get depends on the fault, because that is how the loader reports.
Every rule whose `condition` does not compile is named in one go
([lib.rs:321-337](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L321-L337)), so three of them take one run to
find. The loader's other checks — an unusable `endpoints` entry
([lib.rs:240-257](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L240-L257)), a blank `condition`
([lib.rs:280-290](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L280-L290)) — return on the first offender, so
those take one run each.

Two properties are worth stating outright, because they are what make it usable.

**It is the gateway's own loader, not a second opinion.** The command reads the file and calls
`Policy::from_yaml` ([main.rs:1027-1052](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L1027-L1052)) — the same
two steps `honmoon gateway --config` performs ([main.rs:562-564](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L562-L564)),
compiled conditions and all ([lib.rs:215-224](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L215-L224)). A check
that could accept a policy the gateway then refused would be worse than no check, so there is no
separate implementation here to drift from that one. Two integration tests run both paths over one
file and require the same verdict — `validate_and_the_gateway_report_the_same_refusal` on a policy
both refuse, and `validate_and_the_gateway_accept_the_same_policy` on one both accept
([tests/policy_validate.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/tests/policy_validate.rs)).

There is exactly one thing the check says in its own words, and it refuses nothing extra: a file
whose top level is not a mapping — plain text, a list, a single value — is named as *not a policy
document* rather than handed to the parser
([main.rs:976-1006](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L976-L1006)). The loader refuses those too; what changes is that the
parser would have quoted the file to say so, and for a document that is one plain scalar the quote
is the whole file. Pointed at a token file, an SSH key or a `.env` by a mistyped path, that lands
in the CI log.

An empty file is **not** in this class — it is a valid policy. YAML reads it as `null`, and every
`Policy` field carries `#[serde(default)]`
([lib.rs:51-80](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L51-L80)),
so a document with no fields in it loads as deny-by-default with no rules. `honmoon gateway
--config` starts on one, and `a_file_that_is_not_a_policy_is_named_rather_than_quoted` pins that
`validate` accepts it — the shape guard has to let `null` through, because refusing it would refuse
a policy the gateway runs.

**It has no side effects.** No listener is bound, no audit log is opened, no CA is read or
generated, and — the one that is easy to miss — the management token is never resolved. All four
live inside the `gateway` function, which this path never enters. Starting a gateway resolves that
token at [main.rs:556](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L556), *before* it reads the policy at
[main.rs:562](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L562), so `honmoon gateway --config <bad file>`
creates `~/.honmoon/mgmt-token` on its way to telling you the policy is broken. Checking a policy should
not mint a credential, least of all on the run where the policy is what failed, so this path never
reaches that code (`validating_a_bad_policy_creates_nothing_under_home` pins it, against a control
that shows the gateway doing exactly that).

It reports the loader's **warnings** too — an unreachable rule
([lib.rs:388-397](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L388-L397)), a rule naming an endpoint
`endpoints` does not declare ([lib.rs:364-374](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L364-L374)) —
which `tracing` filters out of an ordinary gateway run, because this command asks for a `warn`
default and its own stderr writer ([main.rs:391-414](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-cli/src/main.rs#L391-L414)). They do not
change the exit code: the gateway starts on a policy carrying one, so this accepts it too.

They arrive through `tracing`, and the `warn` level this command asks for is only a *default*. A
`RUST_LOG` you export for other reasons replaces it, and one that is stricter (`RUST_LOG=error`,
`off`) silences these warnings with nothing on screen to say so. If a policy you expected a warning
about comes back clean, check `RUST_LOG` first — `RUST_LOG=warn` puts them back.

```yaml
# .github/workflows/policy.yml
- run: honmoon policy validate policies/agent.yaml
```

A policy that loads is summarised by a count of what loaded, never by its contents. An endpoint map
names the hosts an operator cares most about, and a CI log is not somewhere they chose to put them.
What a *problem* prints is the problem: a rejected rule is quoted, and a warning names the rule and
the endpoint it is about, because that is the diagnosis and the thing to go and fix. So a clean run
says nothing about your policy, and a run with a warning names the rules the warning is about —
worth knowing before you make that log public.

`honmoonctl validate` remains the stub it was. Making it real is its own job
([#198](https://github.com/pleaseai/honmoon/issues/198) deliberately left it alone), and it could
not share this implementation anyway: it is TypeScript, so filling it in would mean a second
validator against the second policy model that **TD-001** already tracks. Until then, the command
above is the one that answers the question.

::: warning Dual model, kept in sync by hand
The Rust model (`honmoon-core`) and the TS model (`@honmoon/policy`) describe the same policy
but are maintained separately — a change to one must update the other (**TD-001**). The JSON
Schema is the intended future single source of truth.
See [lib.rs:1-4](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs#L1-L4) and [index.ts:1-5](https://github.com/pleaseai/honmoon/blob/main/packages/policy/src/index.ts#L1-L5).
:::

## Related Pages

- [Policy Model & Decision Engine](/deep-dive/policy-engine) — the full precedence algorithm.
- [Protocol-Aware Parsing](/deep-dive/protocol-parsing) — how `sql` / `k8s` facts are produced.
- [Quick Start](/getting-started/quick-start) — run a policy.

## References

- [policies/agent.yaml](https://github.com/pleaseai/honmoon/blob/main/policies/agent.yaml)
- [packages/policy/schema/policy.schema.json](https://github.com/pleaseai/honmoon/blob/main/packages/policy/schema/policy.schema.json)
- [packages/policy/src/index.ts](https://github.com/pleaseai/honmoon/blob/main/packages/policy/src/index.ts)
- [crates/honmoon-core/src/lib.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/lib.rs)
- [crates/honmoon-core/src/engine.rs](https://github.com/pleaseai/honmoon/blob/main/crates/honmoon-core/src/engine.rs)
