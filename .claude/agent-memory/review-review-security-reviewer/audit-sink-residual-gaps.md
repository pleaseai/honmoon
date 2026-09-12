---
name: audit-sink-residual-gaps
description: 'What the audit-sink open still accepts after #138/#179/#161 — a loose mode, a foreign owner and a hard link are accepted and *reported* as degraded events (report-don''t-enforce, settled in #161), a symlinked parent is refused (#179), and an untrusted plain-directory component is accepted with no event; check the in-code list matches before re-reporting any of them'
metadata:
  type: project
---

`open_sink`'s doc comment (`crates/honmoon-core/src/audit.rs`) has a "**Still accepted,
deliberately:**" section. **Every item there is named in the code and either closed,
reported, or tracked; report one as a new finding only if the prose stops matching.**

1. **A symlinked parent directory** — closed by #179 (issue #160): a component-by-component
   `openat` walk refuses a symlink at every step, following one only when the directory
   holding it is root- or euid-owned with no group/other write bit. That trust test reads
   `st_mode` only, so a macOS extended ACL is invisible to it — issue #181, open.
2. **The mode of a file that already exists** — still accepted, **now reported**. `mode`
   applies on creation only, so a log created by a pre-#138 honmoon at the umask default
   stays loose; #161 settled report-don't-enforce and `observe_sink` raises an
   `audit-sink-exposed` degraded event carrying `FactsSummary::sink` (`AuditSinkFacts`).
   Not re-tightened, because the path is an operator flag a log shipper may read on
   purpose; `an_existing_sink_keeps_the_mode_it_had` pins both halves (mode kept, event
   recorded).
3. **A final inode chosen by means other than a symlink** — still accepted, **now
   reported** off the same `fstat`: `audit-sink-foreign-owner` (`st_uid != geteuid()`)
   and `audit-sink-hard-linked` (`st_nlink > 1`). The walk decides which directory the
   last `openat` runs in, not who owns what it finds there. Refusing was weighed and
   rejected in #161 for the same reason as re-tightening: a sink an administrator
   provisioned for a service account reads identically to a hostile pre-creation.
4. **An untrusted plain-directory component** — accepted with **no event**. The
   owner-and-mode test fires only on the symlink branch, so an actor who controls a
   directory on the path can create the rest of the subtree as ordinary directories of
   their own. The `open_sink` doc says so; nothing observes it.

The recursion — the event about the sink is written *to* that sink — is accepted and
argued in the `AuditSinkFacts` doc: the operator reads it through `/api/audit` or a
shipper, it is the only durable channel `honmoon hook` has (no `RUST_LOG`, #131), and a
sink another user can write was never a guarantee. The hook opens the sink only when it
has a degraded key to record (`audit_machine_key_status` returns early otherwise), so the
sink events repeat per invocation only alongside a `hook-salt-*` event.

**How to apply:** on any audit-sink review, check the in-code list still has these items
and that events 2–3 are still *observed, not corrected* — a `set_permissions` on the sink
path would be the regression, not the fix. Item 4 is the only unreported one; a finding
there is new only if it proposes something the doc comment does not already concede.
Related: [[audit-sink-open-hardening]], [[enumerate-from-the-wrong-side]].
