//! Structured audit log: every verdict the engine reaches, recorded.
//!
//! [`AuditLog`] is the single-node, in-process record of decisions. It keeps a
//! bounded in-memory ring (so the management API can render recent activity
//! cheaply) and optionally mirrors every event to a JSONL file (the durable
//! local audit log the `@honmoon/api` query layer reads).
//!
//! It is transport-agnostic on purpose — the data plane (`honmoon-proxy`) and
//! the management API (`honmoon-mgmt`) share one `Arc<AuditLog>`.
//!
//! The **ring** is per process; the **JSONL file** is not. `honmoon hook` runs
//! as its own short-lived process and appends its degradation events to the
//! same path (see [`Decision::Degraded`]), so one file can hold the output of
//! several `AuditLog`s. Ids are therefore process-local and repeat across
//! writers — readers order by `timestamp` (`@honmoon/api`'s `queryAudit` says
//! so) — and only what reached *this* process's ring is visible through
//! `/api/audit`.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Facts, HttpFacts, K8sFacts, PiiFacts, SqlFacts, Verdict};

/// What an audit entry records: the disposition of a request, or — for
/// [`Decision::Degraded`] — a security property the engine is running without.
///
/// A `Pause` verdict produces a `Paused` event when the request is held, then a
/// second `Approved`/`Rejected` event (sharing the same `approval_id`) once a
/// human resolves it — so the log is append-only and the full lifecycle is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Request was allowed through.
    Allowed,
    /// Request was blocked.
    Denied,
    /// Request was held pending human approval.
    Paused,
    /// A held request was approved by a human and allowed through.
    Approved,
    /// A held request was rejected by a human (or timed out) and blocked.
    Rejected,
    /// Not a request disposition: the engine is running with a security
    /// property it normally provides switched off, and said so here.
    ///
    /// Honmoon's degradations are deliberately fail-open — a hook that hard-fails
    /// breaks the agent it runs inside — which makes them invisible from the
    /// outside: the degraded path produces the same shape of output as the
    /// working one. This variant is how a fail-open path stops being silent, so
    /// `?decision=degraded` answers "was this transcript redacted under a real
    /// key?" from the log rather than from a stderr line nobody read. The
    /// accompanying `verdict` describes what happened to the traffic (`allow`:
    /// fail-open let it through), not the degradation itself, and [`FactsSummary`]
    /// carries the specifics — see [`RedactionFacts`] for the placeholder key and
    /// [`AuditSinkFacts`] for the audit file this log is written to.
    Degraded,
}

/// What the engine knows about the key behind placeholder minting, recorded on a
/// [`Decision::Degraded`] event.
///
/// Two independent things can be wrong with that key, and the event's `rule`
/// says which: `hook-salt-fallback` for a key that is not the persisted one
/// (`key_source` then names what was lost), or one of two exposure rules for a
/// key that *is* the persisted one but whose file was readable beyond its owner
/// — `hook-salt-exposed` when it still is after the loader tried to restrict it
/// (issue #141), `hook-salt-was-exposed` when the loader found it that way and
/// the restriction took (issue #143). The two are separate because the remedies
/// are: a file that is loose now can be tightened, while one that was is a key
/// that may already be copied. Both keep `key_source` at
/// [`RedactionKeySource::Persisted`] deliberately — exposure and provenance are
/// different axes, and the bytes really did come from `~/.honmoon/hook-salt`.
///
/// A fourth rule is not about the key in use at all. `hook-salt-replaced-unread`
/// says the loader discarded a salt file it could not read, so what it held —
/// and whether any invocation had been adopting it as a key — is unknown (issue
/// #171). `key_source` there still names the key *in use*, which is why `rule`
/// has to be read before `reason` on these events: the reason is about the file
/// that was discarded, not about the key the rest of the record describes. That
/// is `persisted` where the replacement landed and `fallback` where the loader
/// destroyed the file and then could not write one, in which case this rule and
/// `hook-salt-fallback` both describe the same invocation.
///
/// Placeholders are `HMAC(salt, secret)`, and the salt is derived from a machine
/// key the transports read from disk. When that key cannot be read or created the
/// transports fall back to a constant compiled into the binary and published in
/// this repository's source: redaction keeps working and placeholders stay
/// byte-stable, but anyone can mint the placeholder a guessed secret would produce
/// and check it against a redacted transcript, so unforgeability is not weakened —
/// it is gone (issue #131). Nothing about the redacted output distinguishes the
/// two paths, which is why the provenance is recorded here instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionFacts {
    /// Where the HMAC key came from.
    pub key_source: RedactionKeySource,
    /// Which transport derived it.
    pub transport: RedactionTransport,
    /// What the loader observed, in its own words: why the persisted key was
    /// unavailable, or the modes it saw on a salt file readable beyond its owner
    /// — the one it was left with under `hook-salt-exposed`, the one it was found
    /// with under `hook-salt-was-exposed`. Under `hook-salt-replaced-unread` it
    /// is about a *different* file from the key in use: the one the loader
    /// discarded without reading, the error that stopped it reading, and the mode
    /// that file carried when the loader last looked at it.
    ///
    /// **Deliberately untrimmed** (issue #162). For the `honmoon hook` transport
    /// this record is the only durable channel — a fresh process per invocation,
    /// so no ring anyone can query, and `tracing` filtered out without
    /// `RUST_LOG` (issue #131) — which makes "which file, and what did the OS
    /// say" most of what it is for. A producer may therefore leave a local path
    /// and a raw OS error here.
    ///
    /// The salt loader resolves its directory against the working directory
    /// before building any of these strings, so a `HOME`-less hook does not
    /// record a `.honmoon/…` that identifies nothing — it falls back to the path
    /// as given only where that resolution has no working directory to read
    /// (issue #176). Nor does every reason name the salt file at all: the
    /// fallback arm carries an error chain, which on a CSPRNG failure names
    /// `/dev/urandom` and no salt path.
    ///
    /// That resolution is a deliberate trade, not a neutral change. Where `HOME`
    /// is unset the prefix it fills in is the *working* directory, and unlike a
    /// home directory — which a local reader gets from `passwd` — nothing else
    /// in this response reveals where the process was started. So on that one
    /// path the field discloses more than it did before, bought with a path the
    /// reader can actually follow; every other path already named `$HOME`.
    ///
    /// The question that prompted this (issue #162) was whether an
    /// unauthenticated `GET /api/audit` should be handing out the operator's
    /// home-directory layout. The exposure there was the missing auth layer
    /// rather than this field: the same response already serves every domain
    /// contacted, request path seen, SQL table named and PII category detected,
    /// and trimming this one field would cost the hook its diagnostics while
    /// leaving those in the same body. Issue #173 closed that layer — every
    /// management read now requires the management token — so this content no
    /// longer reaches an unauthenticated caller at all.
    ///
    /// **What is settled is this content — a local salt path and an OS error —
    /// not the field.** Do not re-raise those two as a finding, and do not trim
    /// them as a substitute for issue #173. A *future* producer that starts
    /// putting something else in this `String` has never been reviewed and is
    /// fair game.
    pub reason: String,
}

/// Whether placeholder minting was keyed by a private secret.
///
/// A closed two-value domain, so it is an enum rather than a string, matching
/// every other wire-serialized domain in this crate ([`Verdict`],
/// [`Decision`], `PathResolution`): a typo then fails to compile here instead
/// of failing to match on the query side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionKeySource {
    /// The random secret persisted at `~/.honmoon/hook-salt`.
    ///
    /// Says where the bytes came from, not who else can read them — that is the
    /// event's `rule`, which is `hook-salt-exposed` when the loader found the
    /// file readable beyond its owner and could not restrict it, and
    /// `hook-salt-was-exposed` when it found it that way and the restriction
    /// took. So this value does appear on a degraded event, and an event carrying
    /// it is about something other than the key's provenance: those two rules are
    /// about the file's permissions, and `hook-salt-replaced-unread` is not about
    /// this key at all but about the one it discarded unseen — a rule this value
    /// carries only where the replacement actually landed.
    Persisted,
    /// A private random secret that never reached disk, so it is unforgeable
    /// but lives and dies with one process: placeholders stop being stable
    /// across turns and across transports (the property issue #20 exists for),
    /// and no other process can reproduce them.
    Unpersisted,
    /// The public constant compiled into the binary. Unforgeability is not
    /// weakened here but absent — see [`Decision::Degraded`].
    Fallback,
}

/// Which transport recorded a [`RedactionFacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionTransport {
    /// The `honmoon hook` subprocess, which derives per invocation.
    Hook,
    /// The gateway process — wire redaction and the management hook endpoint,
    /// which share one key read once at startup.
    Gateway,
}

/// What the sink open observed about who else can reach the audit file, recorded
/// on a [`Decision::Degraded`] event.
///
/// The event's `rule` says which observation this is, and each is its own rule
/// rather than one rule with the detail in `reason`, because `rule` is what an
/// operator filters a query on and the three call for different responses:
///
/// - `audit-sink-exposed` — the mode admits local users other than the
///   owner. A `chmod` is the remedy, and it may also be a mode the operator set
///   on purpose.
/// - `audit-sink-foreign-owner` — the file belongs to another user, so
///   honmoon did not create it.
/// - `audit-sink-hard-linked` — more than one directory entry names the
///   inode, so every record also lands under a name honmoon never configured.
///
/// The last two have no mode to correct: the sink is a file honmoon did not make,
/// and the fix is a different path rather than a different mode. Folding them into
/// the first would put the rare, urgent case inside the common, usually benign one
/// — a deployment that ran honmoon before issue #138 created its audit log at the
/// umask default, which is group-readable on most hosts.
///
/// **Honmoon reports these and changes nothing** (issue #161). Unlike the hook
/// salt, which `restrict_to_owner_only` re-tightens on every read
/// (`honmoon-cli/src/hook.rs`), this path is an operator flag rather than a
/// honmoon-owned secret, and is plausibly collected by a log shipper that was
/// granted group read deliberately; re-tightening it on every gateway start and
/// every `honmoon hook` invocation would break that collection with no signal at
/// all. Refusing the open outright would break it harder, and would also refuse
/// every audit log that predates issue #138. So this carries what was *observed*,
/// never what was done — the shape `SaltExposure` settled for the salt (issues
/// #141, #143, #170), one step further out.
///
/// **The event about the sink is written to that sink**, which is the recursion
/// issue #161 asks about. It is the right channel anyway, and the limits are worth
/// stating rather than working around:
///
/// - It tells the reader something they did not know. A local user the loose mode
///   admits can already `stat` the file; the *operator*, who reads this log through
///   `/api/audit` or a shipper, is the one who learns from it.
/// - It is the only durable channel `honmoon hook` has — a fresh process per
///   invocation, no ring anyone can query, and `tracing` filtered out without
///   `RUST_LOG` (issue #131). A `tracing::warn!` is emitted too, but that reaches
///   the gateway's terminal alone, and the gateway is the path that needed it least.
/// - A sink another local user can *write* is one they can also truncate, so this
///   record is a signal rather than a guarantee. That is true of every other record
///   in the same file, and writing nothing does not improve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSinkFacts {
    /// The sink this observation is about, **as the operator configured it**
    /// (`--audit-log` / `HONMOON_AUDIT_LOG`) — not resolved against the working
    /// directory the way the hook salt's paths are since issue #174. Rendered with
    /// `Path::display`, so the one thing it does not preserve is a byte that is
    /// not UTF-8, which becomes U+FFFD.
    ///
    /// A relative path here names no file on its own, and that is deliberate in
    /// both directions: the record is appended to that same file, so a reader
    /// holding the log already holds the resolution the string lacks, and the
    /// string the operator typed is the one they can act on. The reader that
    /// covers is the one holding the file; the same event is also served from
    /// the gateway's ring through `GET /api/audit`, where a relative string
    /// identifies a file only against a working directory the response does not
    /// carry. The operator who typed it can still resolve it; nobody else can.
    pub path: String,
    /// What the `fstat` on the opened descriptor showed, in its own words: the
    /// mode, the owning uid, or the link count that made this reportable.
    ///
    /// A claim about what the kernel allowed at the instant the sink was opened,
    /// never about who actually read or wrote it.
    pub reason: String,
}

/// `rule` on a [`Decision::Degraded`] event whose sink is accessible to local
/// users other than its owner (issue #161).
///
/// Fires on **any** permission beyond the owner, not only a read bit — a log
/// another local user can write is one they can forge records into or truncate —
/// and the `reason` names the mode observed rather than assuming which access was
/// meant. Same rule as the salt's exposure events use.
const AUDIT_SINK_EXPOSED_RULE: &str = "audit-sink-exposed";

/// `rule` on a [`Decision::Degraded`] event whose sink is owned by a uid other
/// than this process's effective one (issue #161).
///
/// The creation mode in [`open_leaf`] applies only when the open creates the file,
/// and the type check in [`open_sink`] passes for any regular file, so a path
/// pre-created by whoever can write the audit directory is appended to exactly as
/// one honmoon made itself. This is what says so.
///
/// It is an observation, not an accusation: a sink an administrator created for a
/// service account reads the same way, which is why it is reported rather than
/// refused.
const AUDIT_SINK_FOREIGN_OWNER_RULE: &str = "audit-sink-foreign-owner";

/// `rule` on a [`Decision::Degraded`] event whose sink inode is named by more than
/// one directory entry (issue #161).
///
/// `O_NOFOLLOW` constrains *symbolic* links only. An actor who can write the audit
/// directory can `link(2)` the configured path onto a file of their own, and the
/// result is an ordinary regular file the open accepts; on macOS, which has no
/// `protected_hardlinks` equivalent, they can also link a file they may only read.
/// A link count above one is what that leaves behind.
const AUDIT_SINK_HARD_LINKED_RULE: &str = "audit-sink-hard-linked";

/// A compact, serializable snapshot of the [`Facts`] a decision was made on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactsSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<SqlFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s: Option<K8sFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<PiiFacts>,
    /// Set only on a [`Decision::Degraded`] event; never derived from [`Facts`],
    /// which describes a request rather than the engine's own posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionFacts>,
    /// Set only on a [`Decision::Degraded`] event, and for the same reason as
    /// `redaction`: it describes the engine's own posture rather than a request.
    /// A separate field rather than a variant of `redaction`, which is about the
    /// HMAC key behind placeholder minting and nothing else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<AuditSinkFacts>,
}

impl From<&Facts> for FactsSummary {
    fn from(f: &Facts) -> Self {
        Self {
            domain: f.domain.clone(),
            endpoint: f.endpoint.clone(),
            http: f.http.clone(),
            sql: f.sql.clone(),
            k8s: f.k8s.clone(),
            pii: f.pii.clone(),
            redaction: None,
            sink: None,
        }
    }
}

/// One recorded decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic per-process event id.
    pub id: u64,
    /// RFC 3339 / ISO 8601 UTC timestamp.
    pub timestamp: String,
    pub decision: Decision,
    /// The policy verdict that drove this event (`pause` for both the hold and
    /// its later resolution).
    pub verdict: Verdict,
    /// Name of the rule that fired, or `None` for an egress-list decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub facts: FactsSummary,
    /// Links a `Paused` event to the later `Approved`/`Rejected` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<u64>,
}

/// What the caller knows at record time; `id`/`timestamp` are assigned by the log.
#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub decision: Decision,
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub facts: FactsSummary,
    pub approval_id: Option<u64>,
}

struct Ring {
    events: VecDeque<AuditEvent>,
    next_id: u64,
}

/// A bounded in-memory audit log with an optional durable JSONL mirror.
pub struct AuditLog {
    ring: Mutex<Ring>,
    capacity: usize,
    /// Optional append-only JSONL sink (one event per line).
    sink: Option<Mutex<std::fs::File>>,
    sink_path: Option<PathBuf>,
}

impl AuditLog {
    /// An in-memory-only log holding up to `capacity` recent events.
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(Ring {
                events: VecDeque::with_capacity(capacity.min(1024)),
                next_id: 1,
            }),
            capacity,
            sink: None,
            sink_path: None,
        }
    }

    /// Like [`new`](Self::new), additionally appending every event to a JSONL
    /// file at `path` (created if absent, mode `0600` on Unix). Existing event
    /// ids in the file are not re-read; the in-memory ring starts empty.
    ///
    /// `path` is operator-supplied (`--audit-log` / `HONMOON_AUDIT_LOG`) and,
    /// since issue #137, opened by `honmoon hook` as well as by the gateway.
    /// [`open_sink`] documents exactly which hostile targets the open refuses
    /// and which it still accepts.
    ///
    /// **Why this crate performs the open** (issue #166, following #163).
    /// `crates/AGENTS.md` holds `honmoon-core` to no async runtime, no socket and
    /// no network client; this sink is the one file it opens, and the boundary
    /// section there says so rather than claiming the crate does no I/O. The
    /// hardening [`open_sink`] performs enforces an invariant of *this type*, not
    /// of whoever calls it: `append_jsonl` writes synchronously on the decision
    /// path, so what the descriptor turns out to be decides whether a record
    /// blocks the process that opened it or lands somewhere a local actor reads.
    /// Taking an already-open `File` instead would leave this constructor as an
    /// unhardened path every caller has to know not to use — the shape issue
    /// #138 was, and the reason it is not offered.
    ///
    /// What it accepts, it now *reports*: a sink reachable by more than this
    /// process's own user produces a [`Decision::Degraded`] event per observation,
    /// carrying [`AuditSinkFacts`], before this returns. The mode, the owner and
    /// the link count are left exactly as they were found — see [`AuditSinkFacts`]
    /// for why honmoon does not correct an operator's file (issue #161).
    ///
    /// Those events go through [`record`](Self::record), so a sink that will not
    /// take them leaves them in this log's ring with a `tracing` warning rather
    /// than failing the constructor: a report that cannot be written is not a
    /// reason to refuse a sink the operator asked for. On the hook transport
    /// neither the ring nor the warning reaches anyone (issue #131), so an
    /// observation whose append fails there is lost as such — what survives is
    /// the salt record that follows on the same descriptor, which goes through
    /// [`record_durable`](Self::record_durable) and reports the refusing sink
    /// on the hook response by path and error (issue #182), without saying what
    /// was observed about it. An observation lost while that salt record
    /// succeeds is issue #184.
    pub fn with_file(capacity: usize, path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let (file, meta) = open_sink(&path)?;
        let observed = observe_sink(&meta, &path);
        let mut log = Self::new(capacity);
        log.sink = Some(Mutex::new(file));
        log.sink_path = Some(path);
        for draft in observed {
            log.record(draft);
        }
        Ok(log)
    }

    /// Path of the JSONL mirror, if one is configured.
    pub fn sink_path(&self) -> Option<&PathBuf> {
        self.sink_path.as_ref()
    }

    /// Record a decision; returns the stored event (with its assigned id).
    ///
    /// A sink write failure is logged and swallowed: it must not break
    /// enforcement, and the event still sits in this process's ring, so the
    /// management API can serve it. A caller whose process has neither — no
    /// `tracing` subscriber at that level, and no later reader of its ring —
    /// wants [`record_durable`](Self::record_durable) instead.
    pub fn record(&self, draft: AuditDraft) -> AuditEvent {
        let (event, sink) = self.record_durable(draft);
        if let Err(e) = sink {
            // A sink write failure must not break enforcement — log and carry on.
            tracing::warn!(error = %e, "audit sink write failed");
        }
        event
    }

    /// [`record`](Self::record), additionally handing back whether the durable
    /// JSONL sink took the event (`Ok(())` when there is no sink configured).
    ///
    /// For a short-lived writer the distinction is the whole point: `honmoon
    /// hook` is a fresh process per invocation with no ring anyone will query
    /// and, under a plugin dispatcher, no `RUST_LOG`, so `EnvFilter` drops a
    /// `warn!` before it is written — a swallowed sink failure there would make
    /// a degradation record vanish with no trace at all, which is the one
    /// outcome the degradation record exists to prevent (issue #131).
    pub fn record_durable(&self, draft: AuditDraft) -> (AuditEvent, std::io::Result<()>) {
        // Assign the id and update the ring under the lock, then release it
        // *before* any file I/O. Holding the ring lock across a synchronous
        // sink write would stall the gateway hot path (and serialize all audit
        // operations) behind a slow disk.
        let event = {
            let mut ring = self.ring.lock().expect("audit ring poisoned");
            let id = ring.next_id;
            ring.next_id += 1;
            let event = AuditEvent {
                id,
                timestamp: now_rfc3339(),
                decision: draft.decision,
                verdict: draft.verdict,
                rule: draft.rule,
                facts: draft.facts,
                approval_id: draft.approval_id,
            };
            ring.events.push_back(event.clone());
            while ring.events.len() > self.capacity {
                ring.events.pop_front();
            }
            event
        };

        // The sink has its own lock (writes stay ordered) and no longer contends
        // with the ring.
        let written = match &self.sink {
            Some(sink) => append_jsonl(sink, &event),
            None => Ok(()),
        };

        (event, written)
    }

    /// The most recent events, newest first, capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let ring = self.ring.lock().expect("audit ring poisoned");
        ring.events.iter().rev().take(limit).cloned().collect()
    }

    /// Total number of events currently held in memory.
    pub fn len(&self) -> usize {
        self.ring.lock().expect("audit ring poisoned").events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Open the JSONL sink at `path` for appending, creating it owner-only on Unix.
///
/// "Owner-only", not "exactly `0600`": the creation mode is filtered through the
/// process umask, so `0600` is the ceiling the operator's umask can only narrow
/// (`umask 0200` yields `0400`). Narrower is never a weaker guarantee, so the mode
/// is passed as-is rather than forced with a `chmod` — which would also override a
/// deliberately restrictive umask.
///
/// The path comes from an operator flag, but the *directory* it sits in may not be
/// one only the honmoon user can write, and since issue #137 a second, short-lived
/// process (`honmoon hook`, spawned per agent invocation) opens the same path.
///
/// **Refused here:**
/// - A **symlink as the final path component**, via `O_NOFOLLOW` (open fails
///   `ELOOP`). A symlink pre-planted by another local user can no longer redirect
///   the append onto a file the honmoon user happens to be able to write, and a
///   *dangling* one can no longer quietly become the place the records go. This
///   refusal is unconditional: the trusted-directory exception below applies to
///   directory components only, never to the file honmoon writes.
/// - A **symlink as a parent component, in a directory somebody else can write**
///   (issue #160). `O_NOFOLLOW` on a single `open` constrains the final component
///   only, so every directory above it used to be resolved through symlinks and an
///   actor who controlled any directory *on* the path still chose where the log
///   landed. The path is now walked component by component with `openat`, each step
///   carrying `O_NOFOLLOW | O_DIRECTORY`, from the trusted root named below.
///   `openat2(RESOLVE_NO_SYMLINKS)` would do it in one call but is Linux-only and
///   `ENOSYS` on kernels before 5.6; the walk is the portable form, so Linux and
///   macOS run the same code and the same tests rather than a fast path and an
///   under-exercised fallback.
/// - **Anything that is not a regular file** — a FIFO, socket, device or
///   directory. The type is read with `fstat` on the descriptor this function is
///   already holding, never with a `stat` of the path, so nothing can be swapped
///   in between the check and the open. The FIFO is the case that matters:
///   `O_NOFOLLOW` does not refuse one, and a *blocking* open of one inside
///   `honmoon hook` stalls a process the agent will time out — after which the
///   invocation proceeds redacted by nothing at all. `O_NONBLOCK` is what stops
///   that open from blocking (a FIFO with no reader fails `ENXIO` at once); it
///   stays set on the descriptor afterwards, which is inert. POSIX specifies that
///   for a regular file "the `O_NONBLOCK` flag shall have no effect", and Linux
///   `write(2)` scopes its `EAGAIN` to a file *other than a socket* — pipes, FIFOs
///   and devices — so the flag cannot reach a write here, a regular file being all
///   this function returns. (The one historical exception, Linux mandatory locking
///   under `mount -o mand`, was removed in 5.15. Were it to fire anyway,
///   `append_jsonl` hands the error back to `record_durable` rather than losing the
///   record.)
///
/// **The trusted root.** A walk is only as good as where it starts. For an absolute
/// path it is `/`, which cannot itself be a symlink. For a relative one it is the
/// process's own working directory, opened as `.`: what lies above it is the
/// process's own context rather than anything the configured path selects, and
/// `getcwd` would resolve it through exactly the symlinks this function refuses to
/// trust. Everything from that root down is walked.
///
/// **What the walk holds, stated no more strongly than it is true.** Each directory
/// the walk opens is pinned by the descriptor the next `openat` resolves against, so
/// a directory cannot be exchanged for another after it has been opened. That is a
/// property of the *directories*, not of the entries inside them: classifying a
/// refused component ([`is_symlink_at`]) and reading a symlink's target
/// ([`read_link_at`]) both act on a name inside a held descriptor, and the entry at
/// that name is not pinned between those calls. The safety there comes from
/// somewhere else, and `is_symlink_at` says where: an entry swapped in mid-sequence
/// is still opened under `O_NOFOLLOW`, and a symlink is followed only when the
/// *directory holding it* — which is pinned — passed the trust test. So the
/// resolution never traverses an untrusted link; it is not the case that nothing
/// can change underneath it.
///
/// **Still accepted, deliberately:**
/// - A **symlink in a directory only root or this process's own effective user can
///   write** (owner `root` or our euid, and no group or other write bit). It is
///   followed, and its target is then walked under this same rule rather than
///   handed to the kernel whole, so a link planted further along the target's own
///   path is still caught. Refusing every symlinked parent outright was the
///   alternative and it is not shippable: macOS resolves `/var`, `/tmp` and `/etc`
///   through root-owned symlinks into `/private`, so the default `TMPDIR` and any
///   `/var/log/...` audit path would be refused on that platform, and a
///   root-installed `/var/log -> /mnt/log` is an ordinary Linux deployment. The
///   issue raised that risk explicitly. This is a trusted-path assumption, not a
///   proof: it reads owner and write bits only, and says nothing about a root-owned
///   directory reachable some other way, or about what root itself does. Nor about
///   ACLs — and that one is not symmetric between the platforms. A Linux POSIX ACL
///   granting write to a named user needs the ACL mask to carry write, and the mask
///   is what `st_mode`'s group bits report, so `0o020` catches it; macOS NFSv4-style
///   ACLs (`chmod +a`) do not appear in `st_mode` at all, so a root-owned `0755`
///   directory carrying `user:mallory allow write` reads as trusted here. Tracked in
///   issue #181.
/// - The **mode of a file that already exists**. `mode` applies only when this
///   call creates the file, so a log left group- or world-readable by an earlier
///   honmoon (which created it at the umask default) or by the operator keeps
///   that mode. Unlike the hook salt, which `restrict_to_owner_only` re-tightens
///   on every read (`honmoon-cli/src/hook.rs`), this path is chosen by the operator
///   and may be collected by a log shipper that was granted group read
///   deliberately; silently re-tightening it every time the gateway or a hook
///   process opens it would break that collection with no signal. Accepted, then,
///   but **no longer silent**: issue #161 settled it as report-don't-enforce, and
///   [`observe_sink`] raises an `audit-sink-exposed` degradation event off the same
///   `fstat` this function already performs.
/// - **A final inode the attacker chose by means other than a symlink.** The
///   bullets above are what `O_NOFOLLOW` and the type check cover; this one is the
///   same list read from the other side, because enumerating refused *link types*
///   hides everything that is not a link. An actor who can write the directory can
///   pre-create the path as an ordinary `0666` file, or `link(2)` it onto a file of
///   their own: both are regular files owned by nobody this code checks, so the
///   `fstat` passes, the creation mode never applies, and every record lands
///   somewhere they read. The walk does not touch this — it decides which directory
///   the last `openat` runs in, not who owns what it finds there. **And the same
///   holds one level up, with no link involved at all**: a directory component that
///   opens successfully is accepted whoever owns it, because the owner-and-mode test
///   fires only on the symlink branch. An actor who controls a directory on the path
///   can simply create the rest of the subtree as ordinary directories of their own.
///   Said positively, because a list of refused *link types* hides everything that is
///   not a link: the walk asserts that no component below the trusted root was a
///   symlink it did not trust — not that any component is owned by someone honmoon
///   trusts. The payload is
///   what makes that matter — the gateway's records name hosts, SQL tables and PII
///   categories, and a hook's degradation record carries the absolute `$HOME` path
///   of the salt it could not use. Issue #161 weighed refusing such a sink — the
///   `uid`/`nlink` test is free off the same `fstat` — against reporting it, and
///   settled on reporting for the reason the bullet above gives: a refusal breaks
///   the operator whose sink is legitimately not honmoon-created, and it breaks
///   them at gateway start. So this stays accepted, and [`observe_sink`] raises
///   `audit-sink-foreign-owner` and `audit-sink-hard-linked` against it. **The
///   directory case one level up is not covered by either** — a component honmoon
///   opened successfully is still accepted whoever owns it, and no event says so;
///   the `fstat` this function holds describes the sink, not the path above it.
fn open_sink(path: &Path) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    let file = open_sink_file(path)?;

    // `File::metadata` is `fstat` on the descriptor above, not a fresh lookup of
    // `path`, so this is the type of the object actually opened.
    let meta = file.metadata()?;
    let file_type = meta.file_type();
    if !file_type.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "audit log {} is {}, not a regular file",
                path.display(),
                describe_file_type(&file_type)
            ),
        ));
    }
    // Handed back rather than re-read by the caller: [`observe_sink`] reports on
    // the same `fstat` this refusal was decided from, so the two cannot disagree
    // about the object, and there is no second call that could fail and leave the
    // report silently skipped.
    Ok((file, meta))
}

/// Turn what [`open_sink`]'s `fstat` said about the sink into the degradation
/// events [`AuditLog::with_file`] records — see [`AuditSinkFacts`] for why honmoon
/// reports this rather than correcting or refusing it.
///
/// `meta` describes the descriptor honmoon holds, not a fresh lookup of `path`, so
/// nothing can be swapped in between the check and the open. The `tracing::warn!`
/// here is the gateway's fast channel — an operator watching a terminal sees it at
/// startup — and is deliberately not the only one: under a plugin dispatcher
/// `honmoon hook` has no `RUST_LOG`, so `EnvFilter` drops it before it is written
/// (issue #131, issue #165), which is what the durable record is for.
#[cfg(unix)]
fn observe_sink(meta: &std::fs::Metadata, path: &Path) -> Vec<AuditDraft> {
    use std::os::unix::fs::MetadataExt as _;

    // SAFETY: `geteuid` reads process credentials, takes no arguments and is
    // documented as always succeeding.
    let euid = unsafe { libc::geteuid() };
    sink_exposure(meta.mode(), meta.uid(), meta.nlink(), euid)
        .into_iter()
        .map(|(rule, reason)| {
            tracing::warn!(
                rule,
                reason = %reason,
                path = %path.display(),
                "the audit sink is reachable by more than this process's own user"
            );
            AuditDraft {
                decision: Decision::Degraded,
                // What happened to the traffic, not to the guarantee: the sink
                // opened and every record still reaches it. The `degraded`
                // decision carries the bad news, as it does for the hook salt.
                verdict: Verdict::Allow,
                rule: Some(rule.to_string()),
                facts: FactsSummary {
                    sink: Some(AuditSinkFacts {
                        path: path.display().to_string(),
                        reason,
                    }),
                    ..Default::default()
                },
                approval_id: None,
            }
        })
        .collect()
}

/// Non-Unix hosts have neither a POSIX mode nor a uid to read, so there is nothing
/// to observe and nothing is recorded. Split by `cfg` rather than branched inside
/// one body, matching [`open_sink_file`].
#[cfg(not(unix))]
fn observe_sink(_meta: &std::fs::Metadata, _path: &Path) -> Vec<AuditDraft> {
    Vec::new()
}

/// Which of the three sink observations the `fstat` fields carry, each with the
/// `reason` its event will report.
///
/// Takes the four numbers rather than a `Metadata` so every branch — including the
/// foreign owner, which needs a second uid to exist on the machine — is reachable
/// from a test. All three are independent, so all three can fire at once: an actor
/// who hard-links the audit path onto a `0666` file of their own trips every one,
/// and each is separately true.
#[cfg(unix)]
fn sink_exposure(mode: u32, uid: u32, nlink: u64, euid: u32) -> Vec<(&'static str, String)> {
    let mut observed = Vec::new();
    if mode & 0o077 != 0 {
        observed.push((
            AUDIT_SINK_EXPOSED_RULE,
            format!(
                "the audit sink is mode {:04o}, which admits local users other than its owner",
                mode & 0o7777
            ),
        ));
    }
    if uid != euid {
        observed.push((
            AUDIT_SINK_FOREIGN_OWNER_RULE,
            format!(
                "the audit sink is owned by uid {uid} and this process runs as uid {euid}, \
                 so honmoon did not create it"
            ),
        ));
    }
    // `> 1`, not `!= 1`: a count of zero means the entry was unlinked between the
    // `openat` and this `fstat`, which is a sink that no longer exists rather than
    // one that exists under a second name. Nothing here reports that — an unlink
    // a moment later is the same loss, and no check at open time sees either.
    if nlink > 1 {
        observed.push((
            AUDIT_SINK_HARD_LINKED_RULE,
            format!(
                "{nlink} directory entries name the audit sink's inode, so every record \
                 also lands under a name honmoon was not given"
            ),
        ));
    }
    observed
}

/// How many symlinks one audit path may resolve through before the walk gives up.
/// Matches Linux's `SYMLOOP_MAX`, which is what an ordinary `open` of the same path
/// would have allowed.
#[cfg(unix)]
const MAX_SYMLINK_HOPS: u32 = 40;

/// Walk `path` from its trusted root and open the final component for appending,
/// refusing a symlink at every step — see [`open_sink`] for which ones survive that
/// and why.
///
/// The loop carries the components still to resolve in a queue rather than
/// iterating the path once, because following a trusted symlink splices that
/// link's own components onto the front of the remaining work.
#[cfg(unix)]
fn open_sink_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let mut absolute = false;
    let mut pending: VecDeque<OsString> = VecDeque::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => pending.push_back(OsString::from("..")),
            Component::Normal(name) => pending.push_back(name.to_os_string()),
            // Windows-only; `cfg(unix)` never reaches it, and an error beats a panic.
            Component::Prefix(_) => return Err(unusable_path(path, "is not a Unix path")),
        }
    }

    // A path naming a *directory* must be refused, not turned into a request to
    // create a file. `components()` cannot be asked this question: it normalises
    // away both a trailing separator and a trailing `.`, so `/var/log/honmoon/`,
    // `/var/log/honmoon/.` and `/var/log/honmoon` all arrive as the same four
    // components — and the first two would then create the *file* `honmoon` where
    // the operator named a directory and the previous single `open` reported
    // `ENOTDIR` or `EISDIR`. Only `..` survives normalisation, so a check written
    // against the components catches one of the three shapes and silently passes
    // the other two.
    //
    // So the test runs on the configured bytes instead. Whatever follows the last
    // separator is the only thing that can name a file to append to, and the empty
    // string, `.` and `..` are none of them.
    let bytes = path.as_os_str().as_bytes();
    let final_segment = match bytes.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => &bytes[separator + 1..],
        None => bytes,
    };
    if matches!(final_segment, [] | [b'.'] | [b'.', b'.']) {
        return Err(unusable_path(
            path,
            "names a directory, not a file to append to",
        ));
    }
    let Some(leaf) = pending.pop_back() else {
        return Err(unusable_path(path, "has no final file-name component"));
    };

    let mut dir = open_walk_root(absolute)?;
    let mut hops = 0u32;
    while let Some(name) = pending.pop_front() {
        let failure = match open_directory(&dir, &name) {
            Ok(next) => {
                dir = next;
                continue;
            }
            Err(e) => e,
        };
        // The two platforms disagree about how `openat` refuses a symlink under
        // `O_DIRECTORY | O_NOFOLLOW`: Linux reports `ELOOP` (`O_NOFOLLOW` spoke
        // first), macOS reports `ENOTDIR` (a symlink is not a directory, and
        // `O_DIRECTORY` spoke first). Neither errno is exclusive to a symlink —
        // `ENOTDIR` is also an ordinary file mid-path — so the component is
        // classified with `fstatat(AT_SYMLINK_NOFOLLOW)` rather than read off the
        // errno, and anything that is not a symlink is handed back untouched.
        if !is_symlink_at(&dir, &name) {
            return Err(failure);
        }
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Err(unusable_path(
                path,
                "resolves through more symbolic links than the walk will follow",
            ));
        }
        require_link_in_a_trusted_directory(path, &dir, &name)?;
        let target = read_link_at(path, &dir, &name)?;
        if target.is_absolute() {
            dir = open_walk_root(true)?;
        }
        for component in target.components().rev() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => pending.push_front(OsString::from("..")),
                Component::Normal(name) => pending.push_front(name.to_os_string()),
                Component::Prefix(_) => return Err(unusable_path(path, "is not a Unix path")),
            }
        }
    }

    open_leaf(&dir, &leaf).map_err(|e| explain_refusal(path, e))
}

/// Non-Unix hosts have neither `O_NOFOLLOW` nor `openat`, so the sink is opened as
/// it always was and the regular-file check in [`open_sink`] is all the hardening
/// that applies there. Split by `cfg` rather than branched inside one body,
/// matching `describe_file_type` below.
#[cfg(not(unix))]
fn open_sink_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// Open the directory the walk starts from: `/` for an absolute audit path, the
/// process's working directory for a relative one. Neither can be a symlink, so
/// neither needs `O_NOFOLLOW`.
#[cfg(unix)]
fn open_walk_root(absolute: bool) -> std::io::Result<std::fs::File> {
    let root = if absolute { c"/" } else { c"." };
    let open = |access| {
        // SAFETY: `root` is a `'static` NUL-terminated C string, `AT_FDCWD` is the
        // documented "resolve against the working directory" sentinel, and the
        // returned descriptor is handed straight to `File`, which closes it on drop.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                access | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        from_raw_fd(fd)
    };
    // Retried for the same reason as a component (see `open_directory`): `/` is
    // readable on any sane host, but a relative audit path starts at the working
    // directory, and nothing says a process cannot be running in a search-only one.
    match open(libc::O_RDONLY) {
        Err(denied) if denied.raw_os_error() == Some(libc::EACCES) => open(O_TRAVERSE),
        attempt => attempt,
    }
}

/// The flag that opens a directory for *traversal* rather than for reading: the
/// descriptor is usable as an `openat`/`fstatat`/`readlinkat` starting point, and
/// asking for it needs only search (`x`) permission, not read (`r`).
///
/// Both platforms have one under a different name, and neither name exists on the
/// other. Where there is no such flag the constant is `O_RDONLY`, which makes the
/// retry in [`open_directory`] a repeat of the attempt that just failed — correct,
/// because that host genuinely cannot open a search-only directory, and the second
/// `EACCES` is the honest answer rather than a worse one.
#[cfg(target_os = "macos")]
const O_TRAVERSE: libc::c_int = libc::O_SEARCH;
#[cfg(target_os = "linux")]
const O_TRAVERSE: libc::c_int = libc::O_PATH;
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
const O_TRAVERSE: libc::c_int = libc::O_RDONLY;

/// Open `name` inside `dir` as a directory, refusing a symlink.
///
/// The caller must not read *which* errno that refusal carries: it is `ELOOP` on
/// Linux and `ENOTDIR` on macOS, and neither is exclusive to a symlink. The walk
/// classifies a refused component with [`is_symlink_at`] instead, and this
/// function reports whatever the OS said.
///
/// **Why the `EACCES` retry exists.** Resolving a path needs only search permission
/// on the directories along it; *opening* one with `O_RDONLY` needs read permission
/// as well. A directory that is `0711` — searchable by everyone, readable by its
/// owner — is an ordinary deployment shape and a Debian/Ubuntu default for `/home`,
/// and the whole-path `open` this walk replaced traversed it without a thought. Left
/// at `O_RDONLY` the walk would refuse it with `EACCES`, which on the gateway means
/// a configuration that worked yesterday aborts startup today. So a denied open is
/// re-attempted for traversal alone.
///
/// The first attempt is kept as it was rather than replaced outright, so the flags
/// every existing test exercises are still the ones almost every open uses, and
/// [`O_TRAVERSE`] is reached only where the alternative is a hard failure. That also
/// keeps a symlink away from it: a symlinked component is refused by `O_NOFOLLOW`
/// with `ELOOP`/`ENOTDIR` before any read permission is consulted, so the retry sees
/// real directories only, never an entry whose type is still in question.
#[cfg(unix)]
fn open_directory(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    let c_name = c_component(name)?;
    match openat_directory(dir, &c_name, libc::O_RDONLY) {
        Err(denied) if denied.raw_os_error() == Some(libc::EACCES) => {
            openat_directory(dir, &c_name, O_TRAVERSE)
        }
        attempt => attempt,
    }
}

/// One `openat` of a directory component, under `access` plus the flags that make
/// the walk what it is: `O_DIRECTORY` so nothing else can be opened, `O_NOFOLLOW` so
/// a symlink is refused rather than traversed.
#[cfg(unix)]
fn openat_directory(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    access: libc::c_int,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;

    // SAFETY: `name` is a valid NUL-terminated path for the duration of the call,
    // `dir` outlives it and owns the descriptor being resolved against, and the
    // returned descriptor is handed straight to `File`, which closes it on drop.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    from_raw_fd(fd)
}

/// Is `name` inside `dir` a symlink? Answered with `fstatat(AT_SYMLINK_NOFOLLOW)`,
/// which describes the entry itself rather than what it points at.
///
/// This runs only after an `openat` has already refused the component, to tell a
/// symlink apart from the other things the same errno covers — never to decide
/// whether the *next* open is safe. That decision stays with `O_NOFOLLOW` on the
/// open itself, so the classification carrying no lock on the entry costs nothing:
/// a component swapped between the two calls is still opened under `O_NOFOLLOW`,
/// and a symlink followed from here is still gated on the directory holding it,
/// which the walk pins by descriptor.
///
/// A failing `fstatat` answers "not a symlink", which returns the original open
/// error to the caller — the honest outcome when the entry can no longer be
/// described at all.
#[cfg(unix)]
fn is_symlink_at(dir: &std::fs::File, name: &std::ffi::OsStr) -> bool {
    use std::os::unix::io::AsRawFd as _;

    let Ok(c_name) = c_component(name) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `c_name` is a valid NUL-terminated path for the duration of the call,
    // `dir` owns the descriptor resolved against, and `stat` is a live, correctly
    // sized allocation the call writes into only on success.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return false;
    }
    // SAFETY: `fstatat` returned 0, so it initialised `stat`.
    let stat = unsafe { stat.assume_init() };
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// How many times the sink open may be re-attempted after a spurious `ENOENT` —
/// see [`open_leaf`] for what makes one spurious. One extra attempt has always been
/// enough in practice; the bound is four so a loaded machine has room, and it is a
/// bound rather than a loop because a *real* `ENOENT` must still be reported.
#[cfg(unix)]
const SINK_OPEN_ATTEMPTS: u32 = 4;

/// Open `name` inside `dir` as the sink itself — the same flags and creation mode
/// the single `OpenOptions` call used before the walk existed, so the `O_NOFOLLOW`
/// refusal, the `O_NONBLOCK` FIFO guard and the `0600` ceiling are unchanged; only
/// the directory they are resolved against is now one this function walked to.
///
/// **The retry is not defensive padding.** On macOS, `openat` with `O_CREAT` racing
/// another creation of the same name loses that race with `ENOENT` instead of
/// returning the file the winner made; the equivalent `open` of the whole path
/// never does, which is why the single open this replaced never saw it. Measured
/// here on Darwin 24: eight threads creating one name through `openat` failed two
/// to six times out of eight, through `open` zero times out of eight, and with
/// unique names or no concurrency zero either way. That is not a test artefact —
/// `honmoon hook` is a separate short-lived process per agent invocation appending
/// to the same `--audit-log` as the gateway (issue #137), so two processes creating
/// that file at once is the ordinary case, and losing the race would mean an
/// invocation whose records went nowhere.
///
/// Only `ENOENT` is retried, and only while attempts remain: with `O_CREAT` set and
/// a directory this function holds a descriptor to, the durable reading of `ENOENT`
/// is that the directory itself was removed — and then every attempt fails and the
/// error is returned as the OS wrote it. Each attempt carries the same `O_NOFOLLOW`
/// against the same pinned descriptor, so retrying weakens nothing.
#[cfg(unix)]
fn open_leaf(dir: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;

    let c_name = c_component(name)?;
    let mut attempts = 0;
    loop {
        // SAFETY: as `openat_directory` above; the trailing `mode` argument is the
        // variadic one `openat` reads only when `O_CREAT` is set, which it is.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_APPEND
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd >= 0 {
            return from_raw_fd(fd);
        }
        let failure = std::io::Error::last_os_error();
        attempts += 1;
        if failure.raw_os_error() != Some(libc::ENOENT) || attempts >= SINK_OPEN_ATTEMPTS {
            return Err(failure);
        }
    }
}

/// Take ownership of a descriptor an `openat` just returned, or report why it did
/// not return one.
#[cfg(unix)]
fn from_raw_fd(fd: libc::c_int) -> std::io::Result<std::fs::File> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, positive descriptor from `openat` that nothing else
    // owns, so `File` is its sole owner from here on.
    Ok(unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) })
}

/// Refuse a symlink the walk found in a directory somebody other than root or this
/// process's own user can write — the case issue #160 is about.
///
/// The test is owner and write bits on the directory *holding* the link, read by
/// `fstat` on the descriptor the walk already has rather than by a fresh `stat`, so
/// it describes the directory the next `openat` will actually run in. A
/// group-writable directory counts as untrusted even where the group is one this
/// process belongs to: honmoon cannot tell that group's members apart from an
/// attacker, and refusing is the fail-closed side.
#[cfg(unix)]
fn require_link_in_a_trusted_directory(
    path: &Path,
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let meta = dir.metadata()?;
    // SAFETY: `geteuid` reads process credentials, takes no arguments and is
    // documented as always succeeding.
    let euid = unsafe { libc::geteuid() };
    if (meta.uid() == 0 || meta.uid() == euid) && meta.mode() & 0o022 == 0 {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "audit log {}: the path component {} is a symlink, and the directory holding it \
             is uid {} mode {:04o} — writable by someone other than root or this process's \
             own user, so the link may have been planted to choose where the records land",
            path.display(),
            Path::new(name).display(),
            meta.uid(),
            meta.mode() & 0o7777,
        ),
    ))
}

/// Read the target of the symlink `name` inside `dir`, without a path `std::fs`
/// could follow behind the walk's back.
#[cfg(unix)]
fn read_link_at(
    path: &Path,
    dir: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::io::AsRawFd as _;

    let c_name = c_component(name)?;
    let mut buf = vec![0u8; 256];
    loop {
        // SAFETY: `c_name` is a valid NUL-terminated path for the duration of the
        // call, `dir` owns the descriptor resolved against, and `buf` is a live
        // allocation of exactly the length passed as the bound.
        let written = unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                c_name.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
            )
        };
        if written < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // `readlinkat` does not NUL-terminate and silently truncates, so a result
        // that filled the buffer may have been cut short: grow and ask again.
        let written = usize::try_from(written).unwrap_or(buf.len());
        if written < buf.len() {
            buf.truncate(written);
            return Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)));
        }
        if buf.len() >= 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "audit log {}: the symlink at path component {} has an implausibly long \
                     target",
                    path.display(),
                    Path::new(name).display()
                ),
            ));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Turn one path component into a C string, refusing the interior NUL that
/// `OsStr` permits and the kernel does not.
#[cfg(unix)]
fn c_component(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;

    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "audit log path component {} contains an interior NUL byte",
                Path::new(name).display()
            ),
        )
    })
}

/// Report a configured path the walk cannot use as a sink path at all.
///
/// Not all of these are decided up front, so the message deliberately says nothing
/// about when the walk gave up: the shape checks on the configured path run before
/// any syscall, while the symlink-hop bound is reached only after the walk has
/// already made a good many, and a `Component::Prefix` can arrive from a symlink
/// target resolved mid-walk.
#[cfg(unix)]
fn unusable_path(path: &Path, why: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("audit log path {} {why}", path.display()),
    )
}

/// Rewrite the one open error whose wording actively misleads, and pass every
/// other one through in the OS's own words.
///
/// `O_NOFOLLOW` reports a refused symlink as `ELOOP` — "Too many levels of symbolic
/// links" — which describes a link *cycle*. An operator whose audit path is one
/// ordinary symlink (a rotation `current -> audit-2026-09-12.jsonl`, say) reads that
/// and learns nothing about why honmoon refused it, on a flag whose failure aborts
/// gateway startup.
///
/// Only the final component reaches here. It is opened with one `openat` against a
/// directory the walk already holds, so `ELOOP` from it cannot mean a parent — that
/// was true of the single whole-path `open` this replaced, and the message no
/// longer hedges about it. A symlinked *parent* is refused by
/// [`require_link_in_a_trusted_directory`], in its own words.
#[cfg(unix)]
fn explain_refusal(path: &Path, e: std::io::Error) -> std::io::Error {
    if e.raw_os_error() != Some(libc::ELOOP) {
        return e;
    }
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "audit log {} was refused with ELOOP: the audit sink is opened with O_NOFOLLOW, \
             so a symlink as the final path component is refused — the sink must be the file \
             the operator named, not a link to one",
            path.display()
        ),
    )
}

/// Name what [`open_sink`] found at the audit path, so the operator is told which
/// kind of wrong target they configured rather than only that it was wrong.
///
/// The list is short because it names only what a write-mode open can actually
/// succeed on. A directory (`EISDIR`), a socket (`ENXIO` on Linux, `EOPNOTSUPP`
/// on macOS) and a symlink (`O_NOFOLLOW` → `ELOOP`) never reach here: the open
/// has already failed with its own errno, which is what the caller reports.
#[cfg(unix)]
fn describe_file_type(file_type: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_fifo() {
        "a FIFO"
    } else if file_type.is_char_device() {
        "a character device"
    } else if file_type.is_block_device() {
        "a block device"
    } else {
        "not a regular file"
    }
}

/// Non-Unix hosts have no `FileTypeExt`, and [`open_sink`] has no `O_NOFOLLOW`
/// there either — the regular-file check is all of the hardening that applies,
/// so the message stays generic. Split by `cfg` rather than branched inside one
/// body, matching `random_bytes` in `honmoon-cli/src/hook.rs`.
#[cfg(not(unix))]
fn describe_file_type(_file_type: &std::fs::FileType) -> &'static str {
    "not a regular file"
}

fn append_jsonl(sink: &Mutex<std::fs::File>, event: &AuditEvent) -> std::io::Result<()> {
    // Terminator appended in-buffer, because the sink is no longer single-writer:
    // `honmoon hook` runs as its own short-lived process and appends its own
    // degradation events to the same path (issue #131). Writing the newline
    // separately guaranteed a second syscall, and `O_APPEND` positions each one
    // at EOF independently, so a concurrent appender could land between an event
    // and its terminator and fuse two objects onto a line the reader drops as
    // malformed. One buffer removes that gap for the ordinary case — it is not a
    // hard guarantee: `write_all` loops on a short write, and atomic append is a
    // local-filesystem property NFS does not provide. A reader that must not lose
    // a record should treat a malformed line as a signal, not as noise.
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    let mut file = sink.lock().expect("audit sink poisoned");
    file.write_all(line.as_bytes())?;
    file.flush()
}

/// Current UTC time as an RFC 3339 string (shared timestamp source for events
/// and pending-approval records).
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(decision: Decision) -> AuditDraft {
        AuditDraft {
            decision,
            verdict: Verdict::Deny,
            rule: Some("r".into()),
            facts: FactsSummary {
                domain: Some("evil.com".into()),
                ..Default::default()
            },
            approval_id: None,
        }
    }

    #[test]
    fn assigns_monotonic_ids_and_orders_newest_first() {
        let log = AuditLog::new(10);
        let a = log.record(draft(Decision::Denied));
        let b = log.record(draft(Decision::Allowed));
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, 2, "newest first");
        assert_eq!(recent[1].id, 1);
    }

    #[test]
    fn ring_is_bounded_to_capacity() {
        let log = AuditLog::new(3);
        for _ in 0..10 {
            log.record(draft(Decision::Denied));
        }
        assert_eq!(log.len(), 3);
        let recent = log.recent(100);
        assert_eq!(recent.len(), 3);
        // The three newest ids survive (8, 9, 10).
        assert_eq!(recent[0].id, 10);
        assert_eq!(recent[2].id, 8);
    }

    #[test]
    fn concurrent_writers_never_fuse_two_events_onto_one_line() {
        // The sink gained a second writer process (`honmoon hook`), which is why
        // `append_jsonl` emits the terminator in the same buffer as the record.
        // Threads here stand in for those processes: distinct `AuditLog`s over
        // one path, as two processes would have. Every line must still parse —
        // a fused line is one the reader drops, and the record most likely to be
        // lost is the `degraded` one that exists to be seen.
        let dir = std::env::temp_dir().join(format!(
            "honmoon-audit-concurrent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        const WRITERS: usize = 8;
        const PER_WRITER: usize = 40;
        let handles: Vec<_> = (0..WRITERS)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let log = AuditLog::with_file(4, &path).expect("open sink");
                    for _ in 0..PER_WRITER {
                        log.record(draft(Decision::Denied));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer panicked");
        }

        let contents = std::fs::read_to_string(&path).expect("read sink");
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), WRITERS * PER_WRITER, "no record was lost");
        for line in &lines {
            serde_json::from_str::<AuditEvent>(line)
                .unwrap_or_else(|e| panic!("line is not one whole event ({e}): {line}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every writer of the sink may be the one creating it: `honmoon hook` is a
    /// fresh process per agent invocation appending to the same `--audit-log` as the
    /// gateway (issue #137), so two creations of that file can race. Threads stand
    /// in for those processes, as in the test above.
    ///
    /// This is the property the retry in `open_leaf` exists for, and on macOS it is
    /// not hypothetical: `openat` with `O_CREAT` loses that race with `ENOENT`
    /// instead of returning the file the winner made, where the whole-path `open`
    /// the walk replaced did not — so this failed several openers out of eight
    /// before the retry, and the failure arrived as a gateway that would not start.
    /// Repeated, so a machine that happens to serialise one round still exercises it.
    #[test]
    fn concurrent_opens_of_one_new_sink_all_succeed() {
        let dir = scratch_dir("concurrent-create");
        for round in 0..3 {
            let path = dir.join(format!("audit-{round}.jsonl"));
            let openers: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || AuditLog::with_file(4, &path).map(|_| ()))
                })
                .collect();
            for opener in openers {
                opener
                    .join()
                    .expect("opener panicked")
                    .expect("every concurrent creation of one sink must succeed");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_durable_reports_a_healthy_sink_and_an_absent_one_as_success() {
        // The two success arms: a sink that takes the record, and no sink at all
        // (nothing was refused, so it is not a failure). The refusal arm needs a
        // sink that fails *after* a successful open, which is below.
        let dir = std::env::temp_dir().join(format!("honmoon-audit-nosink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = AuditLog::with_file(4, dir.join("audit.jsonl")).expect("open sink");
        let (_, written) = log.record_durable(draft(Decision::Denied));
        assert!(written.is_ok(), "a healthy sink takes the record");

        let memory_only = AuditLog::new(4);
        let (event, written) = memory_only.record_durable(draft(Decision::Degraded));
        assert!(written.is_ok(), "no sink is not a refusal");
        assert_eq!(event.decision, Decision::Degraded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/dev/full` accepts an open and fails every write with `ENOSPC`, which is
    /// the one portable-enough way to get a sink that refuses *after* opening —
    /// the case `record_durable` exists for (issue #131). Linux-only; macOS has
    /// no equivalent, so the assertion runs in CI's Linux job.
    ///
    /// The sink is installed directly rather than through
    /// [`AuditLog::with_file`], because that constructor now refuses a character
    /// device along with every other non-regular target (issue #138). The refusal
    /// is asserted by `with_file_refuses_a_character_device`; what is under test
    /// *here* is unchanged — a write that fails after a successful open has to
    /// come back to the caller.
    #[cfg(target_os = "linux")]
    #[test]
    fn record_durable_hands_back_a_sink_that_refuses_the_write() {
        let dev_full = std::fs::OpenOptions::new()
            .append(true)
            .open("/dev/full")
            .expect("/dev/full opens for append");
        let mut log = AuditLog::new(4);
        log.sink = Some(Mutex::new(dev_full));
        let (event, written) = log.record_durable(draft(Decision::Degraded));
        assert!(
            written.is_err(),
            "a refused write must come back to the caller, not be swallowed"
        );
        assert_eq!(
            log.len(),
            1,
            "the ring still holds it — only the durable copy was lost"
        );
        assert_eq!(event.decision, Decision::Degraded);
    }

    #[test]
    fn a_degraded_event_round_trips_with_its_redaction_facts() {
        // The wire shape the dashboard and `@honmoon/api` read: `redaction` is
        // present only here, and absent — not null — on every other event.
        let log = AuditLog::new(4);
        let event = log.record(AuditDraft {
            decision: Decision::Degraded,
            verdict: Verdict::Allow,
            rule: Some("hook-salt-fallback".into()),
            facts: FactsSummary {
                redaction: Some(RedactionFacts {
                    key_source: RedactionKeySource::Fallback,
                    transport: RedactionTransport::Hook,
                    reason: "unwritable HOME".into(),
                }),
                ..Default::default()
            },
            approval_id: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""decision":"degraded""#), "{json}");
        assert!(json.contains(r#""key_source":"fallback""#), "{json}");
        assert!(json.contains(r#""transport":"hook""#), "{json}");
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.facts.redaction, event.facts.redaction);

        // An ordinary decision carries no `redaction` key at all.
        let ordinary = serde_json::to_string(&log.record(draft(Decision::Denied))).unwrap();
        assert!(!ordinary.contains("redaction"), "{ordinary}");
    }

    /// A unique directory under the system temp dir, matching the ad-hoc style
    /// the sink tests above already use. Named after the caller so parallel
    /// tests in one process do not collide.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "honmoon-audit-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// The audit path is operator-supplied and may sit in a directory another
    /// local user can write. A symlink planted there must not redirect the
    /// append onto the file it names (CWE-59, issue #138).
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_symlinked_target() {
        let dir = scratch_dir("symlink");
        let victim = dir.join("victim.conf");
        std::fs::write(&victim, "original\n").expect("seed victim");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");

        let Err(err) = AuditLog::with_file(4, &link) else {
            panic!("a symlinked sink must be refused");
        };
        assert_eq!(
            std::fs::read_to_string(&victim).expect("victim still readable"),
            "original\n",
            "the refused open must not have appended through the link: {err}"
        );
        // Pin *why* it was refused. `is_err()` alone would also pass if the open
        // failed for an unrelated reason, which would not prove `O_NOFOLLOW` is
        // what is doing the work.
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("opened with O_NOFOLLOW"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A *dangling* symlink is the quieter half of the same defect: the open
    /// would create the file the link names, so every record lands somewhere the
    /// operator is not looking.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_dangling_symlink() {
        let dir = scratch_dir("dangling");
        let elsewhere = dir.join("elsewhere.jsonl");
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("plant dangling symlink");

        let Err(err) = AuditLog::with_file(4, &link) else {
            panic!("a dangling symlinked sink must be refused");
        };
        assert!(err.to_string().contains("opened with O_NOFOLLOW"), "{err}");
        assert!(
            !elsewhere.exists(),
            "the refused open must not have created the link's target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A world-writable directory that another local user can plant a symlink in
    /// is the whole of issue #160: `O_NOFOLLOW` on a single `open` guards the final
    /// component only, so before the walk this redirected every record into a
    /// directory of the attacker's choosing and the open reported nothing wrong.
    ///
    /// The directory is made `0777` deliberately — that is the precondition the
    /// attack needs, and it is what makes the link untrusted. A symlinked parent in
    /// a directory only its owner can write is a different case, pinned by
    /// `with_file_follows_a_symlinked_parent_only_its_owner_can_write` below.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_symlinked_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-parent");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("make the directory one another local user could write");
        let attacker = dir.join("attacker");
        std::fs::create_dir(&attacker).expect("create the attacker's directory");
        std::os::unix::fs::symlink(&attacker, dir.join("logs")).expect("plant symlink");

        let sink = dir.join("logs").join("audit.jsonl");
        let Err(err) = AuditLog::with_file(4, &sink) else {
            panic!("a sink under a symlinked parent directory must be refused");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("is a symlink"), "{err}");
        assert!(
            !attacker.join("audit.jsonl").exists(),
            "the refused open must not have created the sink through the link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same refusal two components up, so a walk that only checked the sink's
    /// immediate parent would fail here. Nothing about the check is positional.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_symlinked_grandparent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-grandparent");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))
            .expect("make the directory one another local user could write");
        let attacker = dir.join("attacker");
        std::fs::create_dir_all(attacker.join("honmoon")).expect("create the attacker's tree");
        std::os::unix::fs::symlink(&attacker, dir.join("logs")).expect("plant symlink");

        let sink = dir.join("logs").join("honmoon").join("audit.jsonl");
        let Err(err) = AuditLog::with_file(4, &sink) else {
            panic!("a sink under a symlinked grandparent directory must be refused");
        };
        assert!(err.to_string().contains("is a symlink"), "{err}");
        assert!(
            !attacker.join("honmoon").join("audit.jsonl").exists(),
            "the refused open must not have created the sink through the link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The deliberate limit of the two tests above, and not a soft edge: a symlink
    /// in a directory only root or this process's own user can write is *followed*.
    ///
    /// Refusing every symlinked parent would be unshippable rather than merely
    /// strict. macOS reaches `/var`, `/tmp` and `/etc` through root-owned symlinks
    /// into `/private` — so the default `TMPDIR` every sink test above runs in, and
    /// any `/var/log/...` an operator configures, would be refused on that platform
    /// — and a root-installed `/var/log -> /mnt/log` is an ordinary Linux
    /// deployment. The mode is set explicitly because a machine whose umask is `0`
    /// would otherwise hand `create_dir_all` a `0777` scratch directory and quietly
    /// turn this into a copy of the test above.
    #[cfg(unix)]
    #[test]
    fn with_file_follows_a_symlinked_parent_only_its_owner_can_write() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-parent-trusted");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("make the directory one only its owner can write");
        let real = dir.join("real");
        std::fs::create_dir(&real).expect("create the target directory");
        std::os::unix::fs::symlink(&real, dir.join("logs")).expect("plant symlink");

        let log = AuditLog::with_file(4, dir.join("logs").join("audit.jsonl"))
            .expect("a symlink only its owner could have planted is followed");
        log.record(draft(Decision::Allowed));

        let contents = std::fs::read_to_string(real.join("audit.jsonl"))
            .expect("the sink is the file the link resolves to");
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink target may be *relative*, and that is a different splice: the walk
    /// keeps the directory holding the link and prepends the target's components,
    /// where an absolute target resets it to the walk root first.
    ///
    /// Left to the other tests this branch's coverage is platform-dependent in a way
    /// that reads backwards. Every symlink they plant has an absolute target, so on
    /// Linux — where `temp_dir()` is `/tmp`, a real directory — the relative branch
    /// is never taken at all. On macOS it is taken by *every* sink test in this file,
    /// including the ones with nothing to do with symlinks, because `temp_dir()` is
    /// `/var/folders/...` and `/var` is itself a symlink whose target `private/var`
    /// is relative. Planting a relative link explicitly makes the branch covered on
    /// both platforms instead of on whichever one CI happens to be running.
    #[cfg(unix)]
    #[test]
    fn with_file_follows_a_relative_symlink_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-relative-target");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("make the directory one only its owner can write");
        std::fs::create_dir(dir.join("real")).expect("create the target directory");
        // `real`, not `dir.join("real")`: the target is resolved against the
        // directory holding the link, so this is the branch that must not reset.
        std::os::unix::fs::symlink("real", dir.join("logs")).expect("plant relative symlink");

        let log = AuditLog::with_file(4, dir.join("logs").join("audit.jsonl"))
            .expect("a relative symlink target resolves against the link's own directory");
        log.record(draft(Decision::Allowed));

        let contents = std::fs::read_to_string(dir.join("real").join("audit.jsonl"))
            .expect("the sink is the file the relative link resolves to");
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `require_link_in_a_trusted_directory` masks `0o022`, not `0o002` — a
    /// group-writable directory is untrusted even where the group is one this process
    /// belongs to, because honmoon cannot tell that group's members from an attacker.
    ///
    /// The other trust tests use `0o777` and `0o755`, which a mask narrowed to
    /// `0o002` would classify identically — `0o777` has both write bits and `0o755`
    /// has neither. `0o770` is the mode that separates them: group-write set, and
    /// world-write clear, so it is refused under `0o022` and accepted under `0o002`.
    #[cfg(unix)]
    #[cfg(unix)]
    #[test]
    fn with_file_opens_a_sink_under_a_search_only_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("search-only-parent");
        let parent = dir.join("deploy");
        std::fs::create_dir(&parent).expect("create the parent the walk must traverse");
        // `0o311` is searchable by everyone and readable by nobody — the shape a
        // deployment directory takes when its listing is meant to stay private.
        // Resolving a path through it is allowed; opening it `O_RDONLY` is not.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o311))
            .expect("make the parent searchable but not readable");

        // Prove the host actually enforces that, so a pass here means the walk
        // traversed a directory it could not read rather than one that was never
        // restricted. Root bypasses the permission bits, so say so instead.
        // SAFETY: `geteuid` reads process credentials, takes no arguments and is
        // always successful.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("running as root: the search-only restriction is not enforced");
        } else {
            assert!(
                std::fs::File::open(&parent).is_err(),
                "a `0o311` directory must not be openable for reading, or this test proves nothing"
            );
        }

        let sink = parent.join("audit.jsonl");
        let log = AuditLog::with_file(4, &sink).expect("open a sink under a search-only parent");
        log.record(draft(Decision::Allowed));

        let contents = std::fs::read_to_string(&sink).expect("the sink took the event");
        assert_eq!(contents.lines().count(), 1);

        let _ = std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_file_refuses_a_symlinked_parent_in_a_group_writable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-parent-group");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))
            .expect("make the directory group-writable but not world-writable");
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("create the link's target");
        std::os::unix::fs::symlink(&elsewhere, dir.join("logs")).expect("plant symlink");

        let Err(err) = AuditLog::with_file(4, dir.join("logs").join("audit.jsonl")) else {
            panic!("a symlink in a group-writable directory must be refused");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("is a symlink"), "{err}");
        assert!(
            !elsewhere.join("audit.jsonl").exists(),
            "the refused open must not have created the sink through the link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The hop budget, which nothing else reaches. Without it a cyclic chain would
    /// not hang — every hop still passes through `readlinkat`, so the walk makes
    /// progress — but it would resolve without bound, and an off-by-one in
    /// `hops > MAX_SYMLINK_HOPS` would go unnoticed.
    ///
    /// The chain is built in an owner-only directory on purpose: a link the trust
    /// test refuses never reaches the budget, so an untrusted chain would pass this
    /// test for the wrong reason.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_symlink_chain_longer_than_the_hop_budget() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("symlink-chain");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("make the directory one only its owner can write");
        std::fs::create_dir(dir.join("real")).expect("create the chain's destination");
        // `hop0 -> real`, then `hop{n} -> hop{n-1}`: 48 links, comfortably past the
        // 40 the walk will follow, all of them relative and all in a trusted place.
        std::os::unix::fs::symlink("real", dir.join("hop0")).expect("plant the first link");
        for hop in 1..48 {
            std::os::unix::fs::symlink(format!("hop{}", hop - 1), dir.join(format!("hop{hop}")))
                .expect("extend the chain");
        }

        let Err(err) = AuditLog::with_file(4, dir.join("hop47").join("audit.jsonl")) else {
            panic!("a symlink chain past the hop budget must be refused");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(
            err.to_string().contains("more symbolic links"),
            "the refusal must name the budget, not some incidental failure: {err}"
        );
        assert!(
            !dir.join("real").join("audit.jsonl").exists(),
            "the refused open must not have created the sink at the chain's end"
        );

        // The budget is a bound on the walk, not a refusal of every chain: a short
        // one still resolves, so this test cannot pass by refusing symlinks outright.
        let log = AuditLog::with_file(4, dir.join("hop3").join("audit.jsonl"))
            .expect("a chain within the budget still resolves");
        log.record(draft(Decision::Allowed));
        assert!(dir.join("real").join("audit.jsonl").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The walk resolves the path itself rather than handing it to one `open`, so
    /// the two shapes that have no file to append to are refused explicitly instead
    /// of falling through to a component the operator did not write. A trailing
    /// separator is the one that matters: `path.components()` drops it, which would
    /// otherwise turn the *directory* `…/logs/` into a request to create the file
    /// `logs`.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_path_that_names_no_file() {
        let dir = scratch_dir("no-file-name");
        let trailing = PathBuf::from(format!("{}/logs/", dir.join("x").display()));

        let Err(err) = AuditLog::with_file(4, &trailing) else {
            panic!("a path with a trailing separator names a directory");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("names a directory"), "{err}");
        assert!(
            !dir.join("x").exists(),
            "the refused path must not have created the component before it"
        );

        let Err(err) = AuditLog::with_file(4, dir.join("..")) else {
            panic!("a path ending in `..` names a directory");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("names a directory"), "{err}");

        // The shape that slipped past the first version of this guard, which tested
        // for a trailing separator: `components()` normalises a trailing `.` away
        // entirely, so `<dir>/nested/.` arrived indistinguishable from
        // `<dir>/nested` and would have *created* `nested` as a regular file.
        let Err(err) = AuditLog::with_file(4, dir.join("nested").join(".")) else {
            panic!("a path ending in `.` names a directory");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("names a directory"), "{err}");
        assert!(
            !dir.join("nested").exists(),
            "a path naming a directory must not create a file where the directory was named"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The trap `O_NOFOLLOW` alone does not close: a FIFO is not a symlink, and
    /// opening one for append *blocks* until a reader arrives. Inside `honmoon
    /// hook` — a process the agent times out — that stall means the invocation
    /// goes through redacted by nothing at all (issue #138).
    ///
    /// The open runs on its own thread with a deadline, so a regression fails
    /// this test instead of hanging the suite until CI's job timeout.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_fifo_without_blocking_on_it() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = scratch_dir("fifo");
        let fifo = dir.join("audit.jsonl");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .expect("path has no interior NUL");
        // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the
        // call, and `mkfifo` only creates a filesystem entry.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let (tx, rx) = mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(AuditLog::with_file(4, &probe).err().map(|e| e.to_string()));
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO audit sink must not block");
        assert!(
            outcome.is_some(),
            "a FIFO audit sink must be refused, not accepted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The half of the FIFO refusal the test above cannot reach. With no reader,
    /// `O_NONBLOCK` makes `open` itself fail `ENXIO` before `fstat` ever runs — so
    /// that test proves the sink does not block, and proves nothing about the
    /// regular-file check. Attach a reader first and the open *succeeds*; only the
    /// `fstat` refuses it.
    ///
    /// That is the adversarial ordering, not a curiosity: `O_NONBLOCK` alone is
    /// defeated by anyone who can hold the FIFO open for reading, and this check is
    /// the backstop. Without this test a regression that dropped
    /// `!file_type.is_file()` would still pass the suite.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_fifo_that_already_has_a_reader() {
        use std::os::unix::fs::OpenOptionsExt;

        let dir = scratch_dir("fifo-reader");
        let fifo = dir.join("audit.jsonl");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .expect("path has no interior NUL");
        // SAFETY: `c_path` is a valid NUL-terminated path for the duration of the
        // call, and `mkfifo` only creates a filesystem entry.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        // `O_RDONLY | O_NONBLOCK` on a FIFO returns at once instead of waiting for
        // a writer, so the reader is attached before the open under test runs.
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .expect("attach a reader to the FIFO");

        let Err(err) = AuditLog::with_file(4, &fifo) else {
            panic!("a FIFO with a reader opens successfully and must be refused by the type check");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("a FIFO"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A character device is not a durable audit sink either — and unlike a FIFO
    /// or a socket it opens *successfully*, so this is the one refusal that can
    /// only come from the post-open `fstat`. `/dev/null` rather than `/dev/full`
    /// because it exists on every Unix; this is also the constructor half of
    /// `record_durable_hands_back_a_sink_that_refuses_the_write`, which installs
    /// its sink directly because of this refusal.
    #[cfg(unix)]
    #[test]
    fn with_file_refuses_a_character_device() {
        let Err(err) = AuditLog::with_file(4, "/dev/null") else {
            panic!("a character device is not a regular file");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(err.to_string().contains("a character device"), "{err}");
    }

    /// The sink is created owner-only: the gateway's records name hosts, SQL
    /// tables and PII categories, and a hook's degradation record carries the
    /// absolute `$HOME` path of the salt it could not use.
    ///
    /// The assertion is `mode & 0o077 == 0`, not `mode == 0o600`, because the
    /// creation mode is filtered through the process umask — `0600` is a ceiling
    /// the operator's umask can only narrow (`umask 0200` yields `0400`, `umask
    /// 0777` yields `0000`). Owner-only is the property this test exists to hold;
    /// asserting the exact value would fail the suite on a machine whose umask is
    /// *stricter* than required, which is not a defect.
    #[cfg(unix)]
    #[test]
    fn a_created_sink_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("mode");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::with_file(4, &path).expect("open sink");
        log.record(draft(Decision::Denied));

        let mode = std::fs::metadata(&path)
            .expect("stat sink")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "created sink is {mode:04o}, want no access beyond its owner"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stated limit of the line above: the open mode applies on creation
    /// only, so a sink an operator (or an older honmoon, at the umask default)
    /// already left group-readable keeps that mode. Pinned so the decision is a
    /// tested behaviour rather than a claim in a doc comment. Issue #161 settled
    /// what to do about it — report, never correct — so the assertion on the mode
    /// stays exactly as it was and the test now also holds the other half: the
    /// open says so, once, ahead of anything the caller records.
    #[cfg(unix)]
    #[test]
    fn an_existing_sink_keeps_the_mode_it_had() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("existing-mode");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, "").expect("seed sink");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen sink");

        let log = AuditLog::with_file(4, &path).expect("open sink");
        log.record(draft(Decision::Denied));

        let mode = std::fs::metadata(&path)
            .expect("stat sink")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "an existing sink must keep its mode, not be silently re-tightened"
        );

        let recent = log.recent(10);
        assert_eq!(recent.len(), 2, "one observation, then the caller's event");
        let observed = &recent[1];
        assert_eq!(
            observed.id, 1,
            "the observation is recorded before anything else"
        );
        assert_eq!(observed.decision, Decision::Degraded);
        assert_eq!(observed.verdict, Verdict::Allow);
        assert_eq!(observed.rule.as_deref(), Some(AUDIT_SINK_EXPOSED_RULE));
        let facts = observed
            .facts
            .sink
            .as_ref()
            .expect("sink facts on the observation");
        assert_eq!(facts.path, path.display().to_string());
        assert!(facts.reason.contains("mode 0644"), "{}", facts.reason);
        assert!(observed.facts.redaction.is_none(), "not a key degradation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The observation is one line in the sink like any other event, and the
    /// `sink` facts survive the round trip a reader of the file performs.
    #[cfg(unix)]
    #[test]
    fn a_sink_observation_round_trips_through_the_sink() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("observation-jsonl");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, "").expect("seed sink");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("loosen sink");

        let _log = AuditLog::with_file(4, &path).expect("open sink");

        let contents = std::fs::read_to_string(&path).expect("read sink");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1, "{contents}");
        let event: AuditEvent = serde_json::from_str(lines[0]).expect("one whole event");
        assert_eq!(event.decision, Decision::Degraded);
        assert_eq!(event.rule.as_deref(), Some(AUDIT_SINK_EXPOSED_RULE));
        let facts = event.facts.sink.expect("sink facts survive serialisation");
        assert!(facts.reason.contains("mode 0660"), "{}", facts.reason);
        // Absent facts are omitted rather than written as `null`, as every other
        // `FactsSummary` field is — a reader of an older log sees the same shape.
        assert!(!lines[0].contains("\"redaction\""), "{}", lines[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `fstat` fields alone decide what is reported, so every branch is
    /// reachable here — including the foreign owner, which the filesystem tests
    /// cannot stage without a second uid on the machine.
    #[cfg(unix)]
    #[test]
    fn sink_exposure_reports_each_observation_independently() {
        const REG: u32 = 0o100000;
        let rules = |observed: Vec<(&'static str, String)>| -> Vec<&'static str> {
            observed.into_iter().map(|(rule, _)| rule).collect()
        };

        // Owner-only, own uid, one name: nothing to say. `0o600` and stricter alike.
        assert!(sink_exposure(REG | 0o600, 501, 1, 501).is_empty());
        assert!(sink_exposure(REG | 0o400, 501, 1, 501).is_empty());
        assert!(
            sink_exposure(REG, 501, 1, 501).is_empty(),
            "mode 0000 is owner-only too"
        );

        // Any group or other bit is exposure, not only read.
        assert_eq!(
            rules(sink_exposure(REG | 0o640, 501, 1, 501)),
            [AUDIT_SINK_EXPOSED_RULE]
        );
        assert_eq!(
            rules(sink_exposure(REG | 0o602, 501, 1, 501)),
            [AUDIT_SINK_EXPOSED_RULE]
        );
        let (_, reason) = sink_exposure(REG | 0o644, 501, 1, 501).remove(0);
        assert_eq!(
            reason,
            "the audit sink is mode 0644, which admits local users other than its owner"
        );

        // Owned by someone else, and the reason names both uids.
        let mut foreign = sink_exposure(REG | 0o600, 0, 1, 501);
        assert_eq!(foreign.len(), 1);
        let (rule, reason) = foreign.remove(0);
        assert_eq!(rule, AUDIT_SINK_FOREIGN_OWNER_RULE);
        assert!(reason.contains("owned by uid 0"), "{reason}");
        assert!(reason.contains("runs as uid 501"), "{reason}");

        // A second name on the inode. Zero is an unlinked file, not a linked one.
        assert_eq!(
            rules(sink_exposure(REG | 0o600, 501, 2, 501)),
            [AUDIT_SINK_HARD_LINKED_RULE]
        );
        assert!(sink_exposure(REG | 0o600, 501, 0, 501).is_empty());

        // All three are separately true of a hard link onto another user's 0666 file.
        assert_eq!(
            rules(sink_exposure(REG | 0o666, 502, 2, 501)),
            [
                AUDIT_SINK_EXPOSED_RULE,
                AUDIT_SINK_FOREIGN_OWNER_RULE,
                AUDIT_SINK_HARD_LINKED_RULE
            ]
        );
    }

    /// An ordinary regular-file sink still opens, appends, and reports its path
    /// exactly as before the open was hardened.
    #[test]
    fn a_regular_file_sink_still_opens_and_appends() {
        let dir = scratch_dir("regular");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::with_file(4, &path).expect("a regular file is a valid sink");
        assert_eq!(log.sink_path(), Some(&path));
        log.record(draft(Decision::Allowed));

        let contents = std::fs::read_to_string(&path).expect("read sink");
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_sink_appends_one_line_per_event() {
        let dir = std::env::temp_dir().join(format!("honmoon-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::with_file(10, &path).unwrap();
        log.record(draft(Decision::Denied));
        log.record(draft(Decision::Paused));

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line round-trips back to an AuditEvent.
        let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(first.decision, Decision::Denied);
        let _ = std::fs::remove_file(&path);
    }
}
