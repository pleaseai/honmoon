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

use anyhow::{Context, Result, bail};

/// File under the honmoon directory holding a generated token.
const FILE_NAME: &str = "mgmt-token";

/// Bytes of entropy in a generated token (rendered as 64 hex characters).
const TOKEN_BYTES: usize = 32;

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
pub fn resolve(explicit: Option<String>, dir: &Path) -> Result<Resolved> {
    if let Some(token) = explicit {
        if token.trim().is_empty() {
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
    let path = dir.join(FILE_NAME);
    // An *empty* file is the only unusable state worth recovering from by
    // overwriting: there is no token in it for anything else to already hold.
    // An unreadable one aborts startup instead of quietly minting a second
    // token — `@honmoon/api`, a bookmarked login URL and any operator tooling
    // read this same file, and a gateway that disagrees with all of them while
    // reporting success is worse than one that refuses to start.
    let existing = match std::fs::read_to_string(&path) {
        Ok(contents) => Some(contents),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "reading the management token {} (delete it to mint a new one)",
                    path.display()
                )
            });
        }
    };

    if let Some(contents) = &existing {
        let token = contents.trim();
        if !token.is_empty() {
            warn_if_readable_beyond_owner(&path);
            return Ok(Resolved {
                token: token.to_string(),
                source: Source::Persisted(path),
            });
        }
        eprintln!(
            "honmoon: management token {} is empty — minting a new one",
            path.display()
        );
    }

    let token = hex_encode(&random_bytes(TOKEN_BYTES)?);
    create_private_dir(dir).with_context(|| format!("creating {}", dir.display()))?;
    warn_if_writable_beyond_owner(dir);

    if existing.is_some() {
        // Replacing a known-empty file: `create_new` would only report that it
        // exists. Truncating open at `0600` is the same write the exclusive
        // create performs.
        write_secret_file(&path, token.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        return Ok(Resolved {
            token,
            source: Source::Generated(path),
        });
    }

    match create_secret_file_exclusive(&path, token.as_bytes()) {
        Ok(()) => Ok(Resolved {
            token,
            source: Source::Generated(path),
        }),
        // A concurrent first run won the create. Its token is the one on disk,
        // so adopt it rather than serving one nobody else can present.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {} after a lost create race", path.display()))?;
            let winner = contents.trim();
            if winner.is_empty() {
                bail!(
                    "management token {} is empty after a lost create race",
                    path.display()
                );
            }
            warn_if_readable_beyond_owner(&path);
            Ok(Resolved {
                token: winner.to_string(),
                source: Source::Persisted(path),
            })
        }
        Err(e) => Err(e).with_context(|| format!("writing {}", path.display())),
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
fn warn_if_readable_beyond_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            // This function exists to never be quiet about the mode. Saying it
            // could not be read is the honest form of that, and silence here
            // reads identically to "checked, and it was fine".
            Err(e) => {
                eprintln!(
                    "honmoon: warning: could not read the mode of the management token {}: {e}",
                    path.display()
                );
                return;
            }
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "honmoon: warning: management token {} is mode {mode:04o} — readable beyond its owner. \
                 Any local user it admits can read the whole management API; delete the file to mint a new one.",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
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
