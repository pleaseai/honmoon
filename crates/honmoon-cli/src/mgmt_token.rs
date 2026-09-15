//! The management API credential (#173).
//!
//! Every `/api/*` route on the management listener requires a bearer token, and
//! there is no unauthenticated mode to fall back to — `honmoon-mgmt`'s
//! `AppState` holds a `String`, not an `Option`. So when the operator supplies
//! no token this module mints one and persists it at `~/.honmoon/mgmt-token`
//! (`0600`), the way `hook.rs` persists the machine salt: on by default must not
//! mean broken by default, and a gateway that refused to start without a flag
//! would be exactly that.
//!
//! The persisted file is also what `@honmoon/api` reads, so one token covers
//! both servers over the same audit data.
//!
//! This file deliberately re-implements the few filesystem primitives it shares
//! with [`crate::hook`] (random bytes, exclusive `0600` create) rather than
//! widening that module's private helpers: what it needs is ~20 lines, and
//! `hook.rs`'s versions are entangled with the salt's fallback-key and exposure-
//! reporting contracts (#141/#143), which a credential that must never silently
//! degrade does not want.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// File under the honmoon directory holding a generated token.
const FILE_NAME: &str = "mgmt-token";

/// Bytes of entropy in a generated token (rendered as 64 hex characters).
const TOKEN_BYTES: usize = 32;

/// Sentinel that makes replacing an empty `mgmt-token` single-winner (#189).
///
/// The name, the directory and the protocol below are shared with
/// `packages/api`'s `auth.ts` — two processes only interlock if they agree on
/// all three, and a fix in one language alone is not a fix, because the
/// divergence this closes is *between* the two services.
const LOCK_FILE_NAME: &str = "mgmt-token.lock";

/// How the loser of the lock paces itself. Injectable so the tests can drive
/// the abandoned-lock and exhausted-budget paths without sleeping for real;
/// [`LockTiming::DEFAULT`] is what `resolve` uses.
#[derive(Clone, Copy)]
struct LockTiming {
    /// Age past which a waiter treats the lock as left behind by a crashed
    /// holder. The critical section it guards is one read and one short write,
    /// so this is about five orders of magnitude of headroom.
    stale_after: Duration,
    /// Total time a waiter will spend before giving up. It never mints on
    /// expiry — minting is exactly the divergence this path exists to prevent —
    /// so it fails with the lock's path instead.
    budget: Duration,
    /// Gap between polls of the token file and the lock.
    poll_interval: Duration,
}

impl LockTiming {
    const DEFAULT: Self = Self {
        stale_after: Duration::from_secs(10),
        budget: Duration::from_secs(30),
        poll_interval: Duration::from_millis(20),
    };
}

/// A resolved management token and where it came from — which decides whether
/// honmoon may print it (see [`Source::printable`]).
pub struct Resolved {
    pub token: String,
    pub source: Source,
}

pub enum Source {
    /// `--mgmt-token` / `--hook-token` / the environment. The operator already
    /// holds these bytes.
    Operator,
    /// Read from a file honmoon wrote on an earlier run.
    Persisted(PathBuf),
    /// Minted and persisted on this run.
    Generated(PathBuf),
}

impl Source {
    /// Whether honmoon may print this token in its startup banner.
    ///
    /// Only for a token honmoon minted itself: otherwise nobody could find it,
    /// and the alternative — no dashboard login at all — is the "broken by
    /// default" this module exists to avoid. An operator-supplied token is never
    /// echoed: they already have it, so printing would add an exposure (a
    /// supervisor shipping stderr to a log aggregator) that they did not choose.
    pub fn printable(&self) -> bool {
        !matches!(self, Self::Operator)
    }

    /// The file backing this token, when there is one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Operator => None,
            Self::Persisted(path) | Self::Generated(path) => Some(path),
        }
    }
}

/// Resolve the token the management API will require: the operator's if they
/// supplied one, otherwise the persisted one in `dir`, otherwise a fresh one.
/// Characters stripped from a token, and which therefore cannot constitute one.
///
/// Spelled out rather than delegated to `str::trim`, because `str::trim` and
/// JavaScript's `String.prototype.trim` do not agree and this token crosses
/// between them. Rust trims Unicode `White_Space`, which includes U+0085 (NEL)
/// and excludes U+FEFF; JavaScript trims its own `WhiteSpace` production, which
/// is the reverse on both counts. So `"\u{FEFF}"` was a valid token to the
/// gateway and an empty one to `@honmoon/api`, and `"\u{85}"` the other way
/// round — two services disagreeing about whether a credential exists.
///
/// The union of both sets, applied identically here and in `auth.ts`'s
/// `trimToken`, so the two always reach the same verdict.
fn is_token_padding(c: char) -> bool {
    c.is_whitespace() || c == '\u{FEFF}'
}

/// Strip [`is_token_padding`] from both ends. The counterpart of `auth.ts`'s
/// `trimToken`.
pub fn trim_token(token: &str) -> &str {
    token.trim_matches(is_token_padding)
}

pub fn resolve(explicit: Option<String>, dir: &Path) -> Result<Resolved> {
    if let Some(token) = explicit {
        if trim_token(&token).is_empty() {
            bail!(
                "--mgmt-token must not be empty — an empty credential authenticates every caller"
            );
        }
        return Ok(Resolved {
            token,
            source: Source::Operator,
        });
    }
    load_or_create(dir)
}

/// Default directory for honmoon's persisted local material (`$HOME/.honmoon`,
/// else `.honmoon` — mirroring `hook.rs` and the CA directory in `main.rs`).
pub fn default_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".honmoon"),
        None => PathBuf::from(".honmoon"),
    }
}

fn load_or_create(dir: &Path) -> Result<Resolved> {
    load_or_create_with(dir, LockTiming::DEFAULT)
}

fn load_or_create_with(dir: &Path, timing: LockTiming) -> Result<Resolved> {
    let path = dir.join(FILE_NAME);
    // An *empty* file is the only unusable state worth recovering from by
    // overwriting: there is no token in it for anything else to already hold.
    // An unreadable one aborts startup instead of quietly minting a second
    // token — `@honmoon/api`, a bookmarked login URL and any operator tooling
    // read this same file, and a gateway that disagrees with all of them while
    // reporting success is worse than one that refuses to start.
    if let OnDisk::Token(resolved) = read_on_disk(&path).with_context(|| {
        format!(
            "reading the management token {} (delete it to mint a new one)",
            path.display()
        )
    })? {
        // The persisted path is the common one — every restart after the first —
        // so checking the directory only where a token is minted would mean
        // never checking it in practice. It matters most here: a writable
        // directory lets another local user substitute a well-moded file, which
        // the file check inside `read_on_disk` then approves.
        warn_if_writable_beyond_owner(dir);
        return Ok(resolved);
    }

    create_private_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    warn_if_writable_beyond_owner(dir);
    mint_or_adopt_under_lock(dir, &path, timing)
}

/// What the token file holds, for the two callers that have to tell "there is a
/// token" from "there is nothing usable" — and, for the second, tell an absent
/// file from an empty one, which is the difference between a first start and the
/// recovery #189 is about.
enum OnDisk {
    Absent,
    Empty,
    Token(Resolved),
}

/// Read the token file, warning about its mode if it holds a token.
///
/// A file that vanished reads as [`OnDisk::Absent`] rather than an error: a
/// start that removed it is about to create it exclusively, so the answer is
/// the same as for a path that was never there. Every other read error
/// propagates, because minting past a file honmoon cannot read hands this
/// process a credential nothing else holds.
fn read_on_disk(path: &Path) -> std::io::Result<OnDisk> {
    let (contents, mode) = match read_token_and_mode(path) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OnDisk::Absent),
        Err(e) => return Err(e),
    };
    let token = trim_token(&contents);
    if token.is_empty() {
        return Ok(OnDisk::Empty);
    }
    warn_if_readable_beyond_owner(path, mode);
    Ok(OnDisk::Token(Resolved {
        token: token.to_string(),
        source: Source::Persisted(path.to_path_buf()),
    }))
}

/// Mint the token, or adopt the one a concurrent start minted, under a
/// single-winner lock (#189).
///
/// Both paths into here used to have their own protocol and neither was
/// actually single-winner.
///
/// Replacing an *empty* file could not reuse `O_CREAT|O_EXCL` at all, because
/// `create_new` on a path that exists only reports that it exists — so it minted
/// and truncated unconditionally, and two starts that both saw the empty file
/// both minted, both wrote, and each returned the token it had minted. The file
/// then authenticated exactly one of them: a gateway and an `@honmoon/api`
/// holding different credentials over the same audit data.
///
/// The fresh-create path looked safe and was not, which
/// `concurrent_first_starts_all_hold_the_token_on_disk` is what caught.
/// `create_secret_file_exclusive` *creates* the file and then writes it, so
/// between those two syscalls the path exists with nothing in it. A loser that
/// takes `AlreadyExists` as its cue to re-read lands in that window and reads
/// zero bytes, and the old code turned that into "empty after a lost create
/// race" and aborted — a plain concurrent first start, failing.
///
/// One lock covers both. A start that finds no usable token takes an `O_EXCL`
/// sentinel beside it, re-reads the token file *while holding it*, and mints
/// only if there is still nothing there; every other start waits for the
/// sentinel and re-reads rather than minting. A waiter never mints, which is
/// what makes this single-winner rather than merely serialised: minting is the
/// only action that can produce a second live token. Publishing under the lock
/// also closes the create-then-write window, because no other start reads the
/// file until the lock is released.
///
/// **What the lock does not cover, stated rather than implied.** A sentinel is
/// advisory, so the exclusion is only as good as the agreement to use it — and
/// [`break_abandoned_lock`] deliberately breaks that agreement for a lock left
/// behind by a crashed holder, because a gateway that will not start until an
/// operator deletes a file is worse than the divergence being closed. That
/// leaves one window: a waiter observes an abandoned lock, and between its
/// `stale_after` check and its rename another waiter breaks the same lock and
/// takes a fresh one, which the first then renames away. Both would mint. It
/// needs the holder to have been frozen inside a one-read-one-write critical
/// section for [`LockTiming::stale_after`] *and* two waiters to interleave
/// inside a rename — against the original race, which needs only two starts in
/// the same millisecond. Narrowed by orders of magnitude, not eliminated;
/// closing it fully needs a real advisory lock (`flock`), which Bun does not
/// expose and so cannot be spelled the same way on both sides.
fn mint_or_adopt_under_lock(dir: &Path, path: &Path, timing: LockTiming) -> Result<Resolved> {
    let lock_path = dir.join(LOCK_FILE_NAME);
    // Minted before the lock is taken, so the critical section is only the
    // re-read and the publish. `random_bytes` opens `/dev/urandom`, and an open
    // can block; a token that is never published costs nothing.
    let minted = hex_encode(&random_bytes(TOKEN_BYTES)?);

    let started = Instant::now();
    loop {
        match acquire_lock(&lock_path) {
            Ok(guard) => {
                // Re-read under the lock. A start that held it before us
                // published before it released, so anything here now is the
                // winner's and minting over it would be the divergence itself.
                match read_on_disk(path).with_context(|| {
                    format!(
                        "re-reading the management token {} under {}",
                        path.display(),
                        lock_path.display()
                    )
                })? {
                    OnDisk::Token(resolved) => return Ok(resolved),
                    OnDisk::Empty => eprintln!(
                        "honmoon: management token {} is empty — minting a new one",
                        path.display()
                    ),
                    OnDisk::Absent => {}
                }
                publish_token(path, &minted)
                    .with_context(|| format!("writing {}", path.display()))?;
                drop(guard);
                return Ok(Resolved {
                    token: minted,
                    source: Source::Generated(path.to_path_buf()),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("creating the management token lock {}", lock_path.display())
                });
            }
        }

        // Lost the lock: wait for the winner rather than minting.
        if let OnDisk::Token(resolved) = read_on_disk(path).with_context(|| {
            format!(
                "re-reading the management token {} while another start holds {}",
                path.display(),
                lock_path.display()
            )
        })? {
            return Ok(resolved);
        }
        if started.elapsed() >= timing.budget {
            bail!(
                "no management token in {} after waiting {}s for the start holding {} \
                 — delete the lock if no other honmoon is running",
                path.display(),
                timing.budget.as_secs(),
                lock_path.display()
            );
        }
        if lock_is_abandoned(&lock_path, timing.stale_after) {
            break_abandoned_lock(&lock_path, timing.stale_after);
            continue;
        }
        std::thread::sleep(timing.poll_interval);
    }
}

/// Write the minted token, under the lock.
///
/// Exclusively first, so a *fresh* create neither follows nor clobbers a
/// pre-planted symlink or file — the property `create_secret_file_exclusive`
/// exists for, and the reason this is not simply a truncating write. The
/// fallback is for the one case `create_new` cannot express: replacing the empty
/// file, where it would only report that the path exists. The lock is what makes
/// that truncation safe, and it is the whole of #189.
fn publish_token(path: &Path, token: &str) -> std::io::Result<()> {
    match create_secret_file_exclusive(path, token.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            write_secret_file(path, token.as_bytes())
        }
        other => other,
    }
}

/// The lock, held for `0600` and released by [`Drop`] on every exit from
/// [`recover_empty_token_file`] — including the `?` on a failed publish, which
/// would otherwise leave every other start waiting out the full budget.
struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0) {
            eprintln!(
                "honmoon: warning: could not release the management token lock {}: {e} \
                 — other starts will wait for it to look abandoned",
                self.0.display()
            );
        }
    }
}

/// Take the lock, or report `AlreadyExists` if another start holds it.
fn acquire_lock(lock_path: &Path) -> std::io::Result<LockGuard> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(lock_path)?;
    // Held from here on, so a failure below still releases it.
    let guard = LockGuard(lock_path.to_path_buf());
    // Diagnostic only — for an operator reading a lock the budget message named.
    // Staleness is decided by the file's age and never by this pid: pids are
    // reused, and one from another mount namespace names a different process
    // here or no process at all.
    if let Err(e) = writeln!(file, "{}", std::process::id()) {
        eprintln!(
            "honmoon: warning: could not record the holder of the management token lock {}: {e}",
            lock_path.display()
        );
    }
    Ok(guard)
}

/// Whether the lock has been held past `stale_after` — the signature of a
/// holder that crashed between taking it and releasing it.
///
/// Wall-clock, because that is the only timestamp a second process can read.
/// A modification time in the future (a clock stepped backwards, a file copied
/// off a host that is ahead) makes `elapsed` fail, and that counts as *not*
/// abandoned: waiting is always safe, and breaking a live lock is the one thing
/// this must not do on a bad reading.
fn lock_is_abandoned(lock_path: &Path, stale_after: Duration) -> bool {
    let Ok(metadata) = std::fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified.elapsed().is_ok_and(|age| age >= stale_after)
}

/// Remove a lock whose holder is gone, so a crash mid-mint does not wedge every
/// later start.
///
/// By rename rather than `remove_file`, because the waiters that judge one lock
/// abandoned all judge it abandoned at once: several `remove_file` calls would
/// each delete whatever is at the path, so the second would delete the *fresh*
/// lock a faster waiter had already taken and two starts would mint together.
/// A path holds one file, so of several renames exactly one moves it and the
/// rest get `NotFound` — the removal becomes a claim. See
/// [`recover_empty_token_file`] for the window this still leaves open.
fn break_abandoned_lock(lock_path: &Path, stale_after: Duration) {
    let claimed =
        lock_path.with_file_name(format!("{LOCK_FILE_NAME}.abandoned.{}", std::process::id()));
    match std::fs::rename(lock_path, &claimed) {
        Ok(()) => {
            eprintln!(
                "honmoon: warning: management token lock {} had been held for over {}s — \
                 treating it as abandoned by a start that crashed while minting",
                lock_path.display(),
                stale_after.as_secs()
            );
            if let Err(e) = std::fs::remove_file(&claimed) {
                eprintln!(
                    "honmoon: warning: could not remove the broken management token lock {}: {e}",
                    claimed.display()
                );
            }
        }
        // Another waiter claimed it first, which is the protocol working.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "honmoon: warning: could not break the abandoned management token lock {}: {e}",
            lock_path.display()
        ),
    }
}

/// Create the token directory owner-only.
///
/// `create_dir_all` asks for `0777` and lets the umask subtract from it, so the
/// directory it produces depends on a setting that has nothing to do with this
/// credential: `0755` under the usual `022`, but `0775` under the `002` some
/// distributions ship and `0777` under a `0` umask. The last two are the ones
/// that matter, because directory *write* permission is what decides who may
/// replace a file inside it. Another local user who can write here can unlink
/// `mgmt-token` and drop in a `0600` file of their own choosing — and
/// [`warn_if_readable_beyond_owner`] would find that substitute perfectly
/// well-moded and say nothing, after which the gateway authenticates every
/// management route against a token the attacker picked.
///
/// Asking for `0700` closes it, because a umask can only clear bits, never set
/// them: whatever it subtracts, the result stays owner-only. `packages/api`'s
/// `resolveToken` already passed `mode: 0o700` to `mkdirSync`; this side was
/// the one relying on the umask, and the two now agree.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Report — but do not correct — a token directory the mode leaves writable
/// beyond its owner.
///
/// [`create_private_dir`] only governs a directory this process creates. One
/// that already existed keeps whatever mode it has, and the same reasoning as
/// [`warn_if_readable_beyond_owner`] applies to correcting it: the operator may
/// have widened `~/.honmoon` deliberately, and silently narrowing a directory
/// they share with their own tooling is a surprise this loader has no standing
/// to spring. Unlike the file case the remedy is not to replace the token —
/// a fresh one lands in the same writable directory — so the warning names the
/// directory mode as the thing to fix.
fn warn_if_writable_beyond_owner(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = match std::fs::metadata(dir) {
            Ok(metadata) => metadata,
            Err(e) => {
                eprintln!(
                    "honmoon: warning: could not read the mode of the management token directory {}: {e}",
                    dir.display()
                );
                return;
            }
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            eprintln!(
                "honmoon: warning: management token directory {} is mode {mode:04o} — writable beyond its owner. \
                 Any local user it admits can substitute the token file and authenticate to the whole management API; \
                 chmod 700 it.",
                dir.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Report — but do not correct — a token file the mode leaves readable beyond
/// its owner.
///
/// Deliberately narrower than `hook.rs`'s salt handling, which chmods and audits
/// the two exposure windows separately (#141/#143). The remedy here is different
/// and tightening the mode is not it: a token another local user could already
/// have read has to be *replaced*, and only the operator can decide when to do
/// that (it invalidates their bookmarked login URL and any tooling holding the
/// old value). Saying so on stderr is the honest action.
fn warn_if_readable_beyond_owner(path: &Path, mode: Option<u32>) {
    #[cfg(unix)]
    {
        let Some(mode) = mode else {
            return;
        };
        if mode & 0o077 != 0 {
            eprintln!(
                "honmoon: warning: management token {} is mode {mode:04o} — readable beyond its owner. \
                 Any local user it admits can read the whole management API; delete the file to mint a new one.",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Read the token and its mode through a single descriptor.
///
/// Two resolutions of the same path — `read_to_string(path)` then
/// `metadata(path)` — can land on two different inodes, and in a directory
/// another local user can write, that is not theoretical: they supply an
/// attacker-chosen token for the read, then swap in a private-looking file
/// before the mode is inspected. The loader would adopt the first value and
/// report nothing, because the mode it checked belongs to the replacement.
/// Opening once makes the bytes and the mode describe the same inode by
/// construction. `packages/api`'s `readTokenAndMode` is the counterpart, fixed
/// for the same reason.
///
/// The mode is `None` where there is nothing to report — a non-Unix host, or a
/// `fstat` that failed on an already-open descriptor, which is warned about
/// here rather than silently dropped.
fn read_token_and_mode(path: &Path) -> std::io::Result<(String, Option<u32>)> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;

    let mut mode = None;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        match file.metadata() {
            Ok(metadata) => mode = Some(metadata.permissions().mode() & 0o777),
            // Not fatal — the token itself still reads — but never silent:
            // saying nothing here reads identically to "checked, and it was
            // fine", which is the one thing this must not imply.
            Err(e) => eprintln!(
                "honmoon: warning: could not read the mode of the management token {}: {e}",
                path.display()
            ),
        }
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok((contents, mode))
}

#[cfg(unix)]
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf).context("reading /dev/urandom")?;
    Ok(buf)
}

/// Non-Unix hosts have no `/dev/urandom`. Unlike the hook salt — which falls
/// back to a published key rather than stop redacting — there is no safe
/// fallback for a credential, so this is a hard error and the operator must
/// supply `--mgmt-token`.
#[cfg(not(unix))]
fn random_bytes(_n: usize) -> Result<Vec<u8>> {
    anyhow::bail!("/dev/urandom CSPRNG is unavailable on non-Unix hosts — pass --mgmt-token")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Create `path` exclusively (`O_CREAT|O_EXCL`, mode `0600` on Unix), so the
/// write neither follows nor clobbers a pre-planted symlink or file.
fn create_secret_file_exclusive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

/// Truncating `0600` write, for replacing a file already known to be unusable.
///
/// `OpenOptionsExt::mode` applies only to a file the open *creates*, so
/// truncating one that already exists would otherwise keep whatever mode it
/// had — a `0644` empty placeholder would receive a live credential and stay
/// world-readable. The explicit `set_permissions` is what makes the `0600` in
/// this function's name true on the replace path, and it runs *before* the
/// bytes so there is no window where the new token sits at the old mode.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Throwaway temp dir under the OS temp root, removed on drop (no
    /// `tempfile` dev-dependency in this workspace — mirrors `honmoon-mgmt`).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("honmoon-mgmt-token-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creating temp dir");
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_explicit_token_is_used_verbatim_and_never_persisted() {
        let tmp = TempDir::new("explicit");
        let resolved = resolve(Some("operator-token".to_string()), tmp.path()).unwrap();
        assert_eq!(resolved.token, "operator-token");
        assert!(
            !resolved.source.printable(),
            "must not echo an operator token"
        );
        assert!(!tmp.path().join(FILE_NAME).exists());
    }

    #[test]
    fn an_empty_explicit_token_is_refused() {
        let tmp = TempDir::new("empty-explicit");
        assert!(resolve(Some("   ".to_string()), tmp.path()).is_err());
    }

    #[test]
    fn a_generated_token_is_persisted_owner_only_and_reused() {
        let tmp = TempDir::new("generated");
        let first = resolve(None, tmp.path()).unwrap();
        assert_eq!(first.token.len(), TOKEN_BYTES * 2, "64 hex characters");
        assert!(first.token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(matches!(first.source, Source::Generated(_)));
        assert!(first.source.printable());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(tmp.path().join(FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "a credential must not be readable by others");
        }

        // A second run adopts the same token: `@honmoon/api` and a bookmarked
        // login URL read this same file, so minting a second one would silently
        // disagree with both.
        let second = resolve(None, tmp.path()).unwrap();
        assert_eq!(second.token, first.token);
        assert!(matches!(second.source, Source::Persisted(_)));
    }

    #[test]
    fn an_unreadable_token_file_aborts_rather_than_minting_a_second_token() {
        // A directory where the file should be: `read_to_string` fails with
        // something other than `NotFound`, which must not be recovered from by
        // generating a token that disagrees with whatever holds the real one.
        let tmp = TempDir::new("unreadable");
        std::fs::create_dir_all(tmp.path().join(FILE_NAME)).unwrap();
        assert!(resolve(None, tmp.path()).is_err());
    }

    #[test]
    fn an_empty_token_file_is_replaced() {
        let tmp = TempDir::new("empty-file");
        std::fs::write(tmp.path().join(FILE_NAME), "\n").unwrap();
        let resolved = resolve(None, tmp.path()).unwrap();
        assert_eq!(resolved.token.len(), TOKEN_BYTES * 2);
        assert!(matches!(resolved.source, Source::Generated(_)));
    }

    /// Replacing an empty file must not inherit that file's mode.
    ///
    /// `OpenOptionsExt::mode` applies only to a file the open creates, so a
    /// `0644` placeholder — a `touch` under a default umask, or a
    /// configuration-management stub — would otherwise be handed a live
    /// credential and stay readable by every other local user on the host,
    /// which is the whole population the token exists to exclude.
    #[cfg(unix)]
    #[test]
    fn a_padding_only_token_file_is_replaced_the_same_way_on_both_runtimes() {
        // U+FEFF is the case `str::trim` gets wrong: it is not Unicode
        // `White_Space`, so the bare `.trim()` this used to call left it intact
        // and served it as a credential — while `@honmoon/api`, whose
        // JavaScript `\s` does cover U+FEFF, saw an empty file and minted a
        // different token. Two services, one file, two answers.
        for padding in ["\u{FEFF}", "\u{85}", "\u{FEFF} \u{85}\n"] {
            let tmp = TempDir::new("padding-token");
            let path = tmp.path().join(FILE_NAME);
            std::fs::write(&path, padding).unwrap();

            let resolved = resolve(None, tmp.path()).unwrap();
            assert!(
                matches!(resolved.source, Source::Generated(_)),
                "a token of only padding ({padding:?}) must be replaced, not served"
            );
            assert!(!resolved.token.is_empty());
        }
    }

    #[test]
    fn a_created_token_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        // Not the `TempDir` itself — that one already exists, and the point is
        // the mode `resolve` gives a directory it creates for the first time.
        let tmp = TempDir::new("dir-mode");
        let dir = tmp.path().join("nested").join(".honmoon");

        let resolved = resolve(None, &dir).unwrap();
        assert!(matches!(resolved.source, Source::Generated(_)));

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "a created token directory must be owner-only, was {mode:04o}"
        );
    }

    /// Fast enough that a waiting test does not sleep for the real budget,
    /// slow enough that nothing looks abandoned while the test is running.
    const TEST_TIMING: LockTiming = LockTiming {
        stale_after: Duration::from_secs(3600),
        budget: Duration::from_secs(5),
        poll_interval: Duration::from_millis(5),
    };

    /// Run `starts` resolutions against one directory at once and return what
    /// each of them ended up holding, together with what is on disk.
    ///
    /// A [`std::sync::Barrier`] rather than bare spawns: the race needs every
    /// start to have read the token file before any of them writes it, and
    /// spawning alone lets the first finish before the last has begun.
    fn concurrent_resolutions(dir: &Path, starts: usize) -> (Vec<String>, String) {
        use std::sync::{Arc, Barrier};

        let barrier = Arc::new(Barrier::new(starts));
        let handles: Vec<_> = (0..starts)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let dir = dir.to_path_buf();
                std::thread::spawn(move || {
                    barrier.wait();
                    resolve(None, &dir).expect("resolving concurrently").token
                })
            })
            .collect();

        let tokens = handles
            .into_iter()
            .map(|handle| handle.join().expect("a concurrent start panicked"))
            .collect();
        let on_disk = std::fs::read_to_string(dir.join(FILE_NAME)).expect("reading the token file");
        (tokens, trim_token(&on_disk).to_string())
    }

    /// The race #189 is about: an empty file used to be replaced with an
    /// unconditional truncating write, so every start that saw it minted, wrote,
    /// and returned *its own* token. The file then authenticated exactly one of
    /// them — a gateway that works and an `@honmoon/api` that 401s, or the
    /// reverse, with nothing on stderr.
    #[test]
    fn concurrent_starts_over_an_empty_token_file_all_hold_the_token_on_disk() {
        let tmp = TempDir::new("empty-file-race");
        std::fs::write(tmp.path().join(FILE_NAME), "\n").unwrap();

        let (tokens, on_disk) = concurrent_resolutions(tmp.path(), 16);

        assert_eq!(
            on_disk.len(),
            TOKEN_BYTES * 2,
            "exactly one token was minted"
        );
        for token in &tokens {
            assert_eq!(
                *token, on_disk,
                "a start held a token the persisted file does not authenticate"
            );
        }
        assert!(
            !tmp.path().join(LOCK_FILE_NAME).exists(),
            "the lock must not outlive the start that took it"
        );
    }

    /// The create race had no test either, though the `O_CREAT|O_EXCL` protocol
    /// has always covered it. Asserted here so the two paths that both have to
    /// be single-winner are held to it by the same kind of test.
    #[test]
    fn concurrent_first_starts_all_hold_the_token_on_disk() {
        let tmp = TempDir::new("create-race");

        let (tokens, on_disk) = concurrent_resolutions(tmp.path(), 16);

        assert_eq!(on_disk.len(), TOKEN_BYTES * 2);
        for token in &tokens {
            assert_eq!(*token, on_disk);
        }
    }

    /// A waiter adopts what the holder publishes. It must never mint: a second
    /// token is the divergence, and waiting is the only safe thing to do with
    /// an empty file somebody else has claimed.
    #[test]
    fn a_waiter_adopts_the_token_the_lock_holder_publishes() {
        let tmp = TempDir::new("waiter-adopts");
        let path = tmp.path().join(FILE_NAME);
        let lock = tmp.path().join(LOCK_FILE_NAME);
        std::fs::write(&path, "\n").unwrap();
        // Stand in for a concurrent start that has taken the lock and not yet
        // published.
        std::fs::write(&lock, "1\n").unwrap();

        let dir = tmp.path().to_path_buf();
        let waiter = std::thread::spawn(move || load_or_create_with(&dir, TEST_TIMING));

        std::thread::sleep(Duration::from_millis(30));
        std::fs::write(&path, "the-holders-token\n").unwrap();
        std::fs::remove_file(&lock).unwrap();

        let resolved = waiter.join().unwrap().unwrap();
        assert_eq!(resolved.token, "the-holders-token");
        assert!(
            matches!(resolved.source, Source::Persisted(_)),
            "an adopted token is not this start's to print"
        );
    }

    /// A lock nobody releases must not become a mint. Refusing names the lock
    /// and leaves the file untouched, so the operator can see what to delete;
    /// minting would hand this start a credential nothing else holds.
    #[test]
    fn a_waiter_refuses_rather_than_minting_when_the_lock_is_never_released() {
        let tmp = TempDir::new("waiter-budget");
        std::fs::write(tmp.path().join(FILE_NAME), "\n").unwrap();
        std::fs::write(tmp.path().join(LOCK_FILE_NAME), "1\n").unwrap();

        let timing = LockTiming {
            budget: Duration::from_millis(100),
            ..TEST_TIMING
        };
        // Destructured rather than `unwrap_err`, which would need `Resolved:
        // Debug` — a derive that puts the credential in any panic message.
        let Err(err) = load_or_create_with(tmp.path(), timing) else {
            panic!("a waiter must not resolve a token while the lock is held");
        };
        assert!(
            err.to_string().contains(LOCK_FILE_NAME),
            "the refusal must name the lock to delete, was {err}"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(FILE_NAME)).unwrap(),
            "\n",
            "a start that gave up must not have published a token"
        );
    }

    /// A holder that crashes between taking the lock and releasing it leaves the
    /// sentinel behind. Waiting for it forever would turn a rare divergence into
    /// a gateway that never starts again, so an aged lock is broken.
    #[test]
    fn an_abandoned_lock_is_broken_rather_than_wedging_the_next_start() {
        let tmp = TempDir::new("abandoned-lock");
        let lock = tmp.path().join(LOCK_FILE_NAME);
        std::fs::write(tmp.path().join(FILE_NAME), "\n").unwrap();
        std::fs::write(&lock, "999999\n").unwrap();

        // `stale_after: 0` makes the lock just written look like one a crashed
        // start left behind, without the test waiting out a real staleness bound.
        let timing = LockTiming {
            stale_after: Duration::ZERO,
            ..TEST_TIMING
        };
        let resolved = load_or_create_with(tmp.path(), timing).unwrap();
        assert!(matches!(resolved.source, Source::Generated(_)));
        assert_eq!(resolved.token.len(), TOKEN_BYTES * 2);
        assert!(!lock.exists(), "the broken lock must not be left behind");
    }

    #[test]
    fn replacing_an_empty_token_file_tightens_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new("empty-file-mode");
        let path = tmp.path().join(FILE_NAME);
        std::fs::write(&path, "\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let resolved = resolve(None, tmp.path()).unwrap();
        assert!(matches!(resolved.source, Source::Generated(_)));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a replaced token file must be owner-only, was {mode:04o}"
        );
    }
}
