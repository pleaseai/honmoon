//! `honmoon` — policy-based firewall gateway CLI.

mod hook;
mod isolate;
mod mgmt_token;

use std::io::IsTerminal as _;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use honmoon_core::{AuditLog, Policy};
use honmoon_mgmt::{AppState, HookSalt};
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{
    DEFAULT_PAUSE_TIMEOUT, GatewayState, InterceptPolicy, PiiMode, RedactionState, SignedBodyMode,
};

/// Salt context wire redaction keys on when the operator pins none.
const DEFAULT_SALT_CONTEXT: &str = "default";

#[derive(Parser)]
#[command(
    name = "honmoon",
    version,
    about = "Policy-based firewall gateway for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command with its egress routed through a policy-enforcing proxy.
    Run {
        #[arg(long, value_name = "FILE")]
        policy: PathBuf,
        /// Command to execute (after `--`).
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Run the central gateway proxy plus its management API + dashboard.
    Gateway {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Address the egress proxy listens on.
        #[arg(long, default_value = "127.0.0.1:8443", value_name = "HOST:PORT")]
        addr: String,
        /// Address the SOCKS5 listener binds — the transport for non-HTTP
        /// protocols (a `protocol: postgres` endpoint is inspected inline).
        /// `off` disables the listener entirely; the CONNECT proxy keeps running.
        #[arg(long, default_value = "127.0.0.1:1080", value_name = "HOST:PORT")]
        socks_addr: String,
        /// Address the management API + dashboard listens on.
        #[arg(long, default_value = "127.0.0.1:8444", value_name = "HOST:PORT")]
        mgmt_addr: String,
        /// Append every verdict to this JSONL audit log (default: in-memory only).
        ///
        /// Must name a regular file: the sink is opened with `O_NOFOLLOW`, so a
        /// symlink as the final path component is refused, as is a FIFO, socket,
        /// device or directory (issue #138) — `--audit-log /dev/stdout` and a
        /// rotation symlink included. Created owner-only (`0600` before the umask)
        /// when absent; an existing file keeps the mode it has. A refusal aborts
        /// startup rather than running without the audit trail.
        ///
        /// The *directories* on the path are checked too (issue #160): honmoon walks
        /// them one at a time rather than letting the OS resolve the path whole, and
        /// refuses a symlinked parent directory unless the directory holding that
        /// symlink is writable by nobody but `root` or honmoon's own user. A
        /// symlinked `/var`, `/tmp` or `/var/log` installed by root is followed
        /// normally; one reachable through a directory anyone else can write is not,
        /// because whoever can write that directory chooses where the records land.
        /// If this refuses a path you intend, point the flag at the resolved location
        /// instead — the refusal names the component it stopped on.
        #[arg(long, value_name = "FILE")]
        audit_log: Option<PathBuf>,
        /// Bearer token required by every management API route (`/api/*`): the
        /// audit, approval and policy reads as well as the Claude Code hook
        /// endpoint (#173).
        ///
        /// Unset (the default), honmoon mints one on first use and persists it
        /// at `~/.honmoon/mgmt-token` (mode `0600`), then prints the dashboard
        /// login URL at startup. Auth is on by default; the generated credential
        /// is what keeps that from meaning broken by default.
        ///
        /// Prefer `HONMOON_MGMT_TOKEN` to this flag: a command line can be read
        /// by other local users through `ps` — how far that reaches is platform
        /// and configuration dependent — where a token file honmoon created is
        /// `0600`. A pre-existing file with a wider mode is reported at startup
        /// rather than tightened, so that contrast holds for the file honmoon
        /// mints and not for one it merely found. `@honmoon/api` cannot see
        /// this flag either — it
        /// reads the environment variable or the file — so a token supplied
        /// here must be given to that service by one of those two routes, or
        /// the two will not agree.
        /// May also be supplied through `HONMOON_MGMT_TOKEN`.
        #[arg(
            long,
            value_name = "TOKEN",
            env = "HONMOON_MGMT_TOKEN",
            hide_env_values = true
        )]
        mgmt_token: Option<String>,
        /// Deprecated alias for `--mgmt-token`, kept working for operators who
        /// set it while it guarded only `POST /api/hooks/claude-code`. The same
        /// token now authenticates the whole management plane — strictly more
        /// protection, in the direction setting it asked for.
        /// May also be supplied through `HONMOON_HOOK_TOKEN`; `--mgmt-token`
        /// wins when both are set.
        #[arg(
            long,
            value_name = "TOKEN",
            env = "HONMOON_HOOK_TOKEN",
            hide_env_values = true
        )]
        hook_token: Option<String>,
        /// Pin the salt context for hook redaction instead of keying it on each
        /// hook payload's `session_id`.
        ///
        /// Unset (the default), `POST /api/hooks/claude-code` derives its salt
        /// from the session exactly as `honmoon hook` does, so a session that
        /// mixes the two transports mints one placeholder per secret (#98). Pin
        /// it — matching `honmoon hook --salt-context` / the same
        /// `HONMOON_HOOK_SALT_CONTEXT` on the agent side — to instead share one
        /// salt with wire redaction, which is process-scoped and always keys on
        /// this context (`default` when unset). Domain-separation input only:
        /// unforgeability and per-machine uniqueness come from the random
        /// `~/.honmoon/hook-salt` secret that keys the HMAC it is mixed into.
        /// May also be supplied through `HONMOON_HOOK_SALT_CONTEXT`.
        #[arg(long, value_name = "CONTEXT", env = "HONMOON_HOOK_SALT_CONTEXT")]
        hook_salt_context: Option<String>,
        /// Terminate TLS (MITM) to inspect request bodies for PII. Agents must
        /// trust the CA certificate. See --pii-mode to choose audit or enforcement.
        #[arg(long)]
        tls_intercept: bool,
        /// Rewrite intercepted request bodies: detected secrets and Tier-1 PII are
        /// replaced with stable placeholder tokens before forwarding upstream, and
        /// placeholders appearing in responses are restored (detokenized) so the
        /// agent keeps working. Placeholder minting is deterministic per salt, so
        /// re-redacted conversation history stays byte-identical across turns
        /// (prompt-cache safe). Fail modes: bodies over the 2 MiB inspection cap,
        /// non-UTF-8/binary bodies, and bodies whose declared encoding cannot be
        /// decoded are forwarded UNREDACTED (matching scan behavior); compressed
        /// responses are not detokenized (the proxy requests identity encoding).
        #[arg(long, requires = "tls_intercept")]
        redact_secrets: bool,
        /// What to do with a request whose authentication signature covers its
        /// body (AWS SigV4, RFC 9421 message signatures over a content-digest,
        /// draft-cavage over a digest) when redaction would rewrite that body,
        /// or covers a header that replacing the body has to change —
        /// re-framed (Content-Length, Content-Encoding, Transfer-Encoding) or
        /// stripped as a stale validator (Content-MD5, Digest, Content-Digest,
        /// Repr-Digest); an AWS SDK upload signs content-length, and an S3
        /// upload may sign content-md5, even under UNSIGNED-PAYLOAD. Honmoon
        /// holds no signing credentials, so it cannot re-sign either: block
        /// rejects the request locally with 403, so the secret is never sent and
        /// the failure is explained instead of surfacing as an opaque upstream
        /// signature error; forward sends the original bytes unredacted (fail
        /// open) for operators who trust the signed upstream. Signed requests
        /// with nothing to redact are never affected.
        #[arg(
            long,
            value_enum,
            default_value_t = SignedBodyArg::Block,
            requires = "redact_secrets"
        )]
        signed_body: SignedBodyArg,
        /// How detected PII policy verdicts are handled: detect audits the
        /// would-be verdict; block enforces allow/deny/pause inline.
        /// Detect only downgrades verdicts caused by PII findings; endpoint and
        /// Kubernetes rules are always enforced.
        #[arg(long, value_enum, default_value_t = PiiModeArg::Detect)]
        pii_mode: PiiModeArg,
        /// CA certificate path (PEM). Auto-generated on first run if missing.
        /// Install this in agents' trust store to enable TLS termination.
        /// Must be given together with --ca-key and --tls-intercept.
        #[arg(
            long,
            value_name = "FILE",
            requires = "ca_key",
            requires = "tls_intercept"
        )]
        ca_cert: Option<PathBuf>,
        /// CA private key path (PEM). Auto-generated on first run if missing.
        /// Must be given together with --ca-cert and --tls-intercept.
        #[arg(
            long,
            value_name = "FILE",
            requires = "ca_cert",
            requires = "tls_intercept"
        )]
        ca_key: Option<PathBuf>,
    },
    /// Policy tooling that runs no gateway and binds no listener.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Join a gateway and route host traffic through it.
    Join {
        #[arg(long, value_name = "HOST:PORT")]
        gateway: String,
    },
    /// Redact a Claude Code hook payload (read on stdin, verdict on stdout).
    ///
    /// The command-transport backend for the honmoon Claude Code plugin (#19):
    /// scans `Read` output / prompts for secrets + PII and emits the hook JSON
    /// verdict. Reads the event JSON on stdin and always exits 0.
    Hook {
        /// Stable session/salt context. Overrides `HONMOON_HOOK_SALT_CONTEXT`
        /// and the payload's `session_id` when set.
        #[arg(long, value_name = "CONTEXT")]
        salt_context: Option<String>,
        /// Append security degradations to this JSONL audit log — the same file
        /// `honmoon gateway --audit-log` writes and `@honmoon/api` queries.
        ///
        /// Only a degradation is recorded here, never a per-invocation verdict.
        /// Today that is one of three, and they lose different guarantees: the
        /// key is the constant compiled into the binary, so anyone can forge
        /// placeholders (issue #131); the key is random and private but never
        /// reached disk, so it stays unforgeable while placeholders stop being
        /// stable across turns and transports (issues #20, #98); or the key is
        /// the persisted one and its salt file is accessible beyond its owner
        /// (issue #141). The event's `rule` and `key_source` say which. All
        /// three look identical from the outside. Unset, they reach stderr
        /// alone — which a non-interactive hook process discards. Set it
        /// through the environment: the plugin's dispatcher runs `honmoon hook`
        /// with no arguments.
        ///
        /// Same constraint as `honmoon gateway --audit-log`: a regular file, never
        /// a symlink, FIFO, socket or device (issue #138), and no symlinked parent
        /// directory except one only `root` or honmoon's own user could have planted
        /// (issue #160). A refused path does not stop the hook: the degradation
        /// it could not record goes back on the hook response as `systemMessage`,
        /// which Claude Code shows to the user and keeps out of the model's
        /// context (issue #165) — a trace, not a durable one, so the parent-
        /// directory rule is worth re-checking against a path that worked before.
        /// It is the same file the gateway writes, so a path the gateway starts
        /// on is one the hook takes too.
        #[arg(long, value_name = "FILE", env = "HONMOON_AUDIT_LOG")]
        audit_log: Option<PathBuf>,
    },
    /// Internal: the in-namespace half of enforced `run` isolation (ADR-0005).
    ///
    /// Hidden because it is not a user-facing command — `run` re-execs the
    /// binary into it after entering the namespace, since a `pre_exec` hook can
    /// only be followed by an `exec`.
    #[cfg(target_os = "linux")]
    #[command(name = isolate::linux::SUPERVISE_SUBCOMMAND, hide = true)]
    SuperviseSandbox {
        /// Host-side Unix socket that bridges to the CONNECT proxy.
        #[arg(long, value_name = "PATH")]
        bridge_socket: PathBuf,
        /// Host-side Unix socket that bridges to the SOCKS5 listener.
        #[arg(long, value_name = "PATH")]
        socks_bridge_socket: PathBuf,
        /// Command to execute (after `--`).
        #[arg(last = true)]
        argv: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Check a policy file and exit, without starting anything.
    ///
    /// Loads the file through exactly the loader `honmoon gateway --config`
    /// uses, so a policy this accepts is one the gateway will accept: the
    /// point is the check, not a second opinion. Exits 0 when the policy loads
    /// and non-zero when it does not, with what the loader found on stderr.
    ///
    /// How much of it you get depends on the fault, because that is how the
    /// loader reports: every rule whose `condition` does not compile is named
    /// in one go (#197), while its other checks — an unusable `endpoints`
    /// entry, a blank `condition` — stop at the first offender. The loader's
    /// warnings (a rule an earlier unconditional rule makes unreachable, a
    /// rule naming an endpoint `endpoints` does not declare) are printed here
    /// rather than filtered away, since reporting what the loader found is the
    /// whole job. They come through `tracing`, so a `RUST_LOG` you have set
    /// for other reasons replaces this command's `warn` default and can
    /// silence them — `RUST_LOG=warn` puts them back.
    ///
    /// A warning is not a refusal. The gateway starts on a policy carrying
    /// one, so this exits 0 on one too — a check that disagreed with the
    /// gateway in either direction would be worse than no check at all.
    ///
    /// Nothing is written and no listener is bound. In particular the
    /// management token is never resolved, so checking a policy cannot create
    /// `~/.honmoon/mgmt-token` the way starting a gateway does (#198).
    ///
    /// A policy that loads is summarised by the count of what loaded, never by
    /// its contents — a CI log is not somewhere an operator chose to put their
    /// endpoint names. What a *problem* prints is the problem: a rejected rule
    /// is quoted, and a warning names the rule and endpoint it is about,
    /// because that is the diagnosis and the thing to go and fix.
    Validate {
        /// Policy file to check.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.command);

    match cli.command {
        Command::Run { policy, argv } => run(policy, argv),
        Command::Gateway {
            config,
            addr,
            socks_addr,
            mgmt_addr,
            audit_log,
            mgmt_token,
            hook_token,
            hook_salt_context,
            tls_intercept,
            redact_secrets,
            signed_body,
            pii_mode,
            ca_cert,
            ca_key,
        } => gateway(GatewayArgs {
            config,
            addr,
            socks_addr,
            mgmt_addr,
            audit_log,
            mgmt_token,
            hook_token,
            hook_salt_context,
            tls_intercept,
            redact_secrets,
            signed_body,
            pii_mode,
            ca_cert,
            ca_key,
        }),
        Command::Policy { command } => match command {
            PolicyCommand::Validate { file } => policy_validate(&file),
        },
        Command::Join { gateway } => {
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
        Command::Hook {
            salt_context,
            audit_log,
        } => hook::run(salt_context.as_deref(), audit_log.as_deref()),
        #[cfg(target_os = "linux")]
        Command::SuperviseSandbox {
            bridge_socket,
            socks_bridge_socket,
            argv,
        } => {
            let status = isolate::linux::supervise(&bridge_socket, &socks_bridge_socket, &argv)
                .context("supervising the sandboxed command")?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

/// Install the tracing subscriber, with the defaults `command` needs.
///
/// Runs after `Cli::parse()` rather than before it — nothing logs during
/// parsing, and the command is what decides the two settings below.
///
/// **Level.** Every command keeps the historical default of `ERROR` when
/// `RUST_LOG` is unset, which is why `gateway` and `run` print the lines an
/// operator must read with `eprintln!` rather than `tracing`. `policy validate`
/// defaults to `WARN` instead: two of the loader's diagnostics — an unreachable
/// rule, a rule naming an undeclared endpoint — are `tracing::warn!` inside
/// `honmoon-core`, and a check that exists to report what the loader found
/// cannot be the one place they are filtered out.
///
/// A default is all it is. `with_default_directive` applies only when
/// `RUST_LOG` parses to no directives at all, so an operator who already
/// exports `RUST_LOG=error` to quiet something else gets a `policy validate`
/// with its warnings silenced and nothing on screen saying so. That is
/// `RUST_LOG` doing its job — it is the explicit setting and this is the
/// fallback — but it is worth knowing, so `--help` says it too.
///
/// **Stream.** `tracing_subscriber::fmt` writes to stdout by default, which is
/// right for a long-running gateway whose log *is* its output and wrong for a
/// command run in a CI step: a warning on stdout lands in whatever the caller
/// is piping. So `policy validate` sends its diagnostics to stderr, where the
/// error for a policy it refuses already goes, and leaves stdout empty.
fn init_tracing(command: &Command) {
    use tracing::level_filters::LevelFilter;

    // One test of the discriminant, held in a named binding, because the level
    // and the writer are two halves of one decision. Asking twice would let a
    // command added later answer the two questions differently by omission.
    let policy_tooling = matches!(command, Command::Policy { .. });

    let default = if policy_tooling {
        LevelFilter::WARN
    } else {
        LevelFilter::ERROR
    };
    let builder = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(default.into())
            .from_env_lossy(),
    );
    if policy_tooling {
        builder.with_writer(std::io::stderr).init();
    } else {
        builder.init();
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PiiModeArg {
    Detect,
    Block,
}

impl From<PiiModeArg> for PiiMode {
    fn from(mode: PiiModeArg) -> Self {
        match mode {
            PiiModeArg::Detect => Self::Detect,
            PiiModeArg::Block => Self::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SignedBodyArg {
    Block,
    Forward,
}

impl From<SignedBodyArg> for SignedBodyMode {
    fn from(mode: SignedBodyArg) -> Self {
        match mode {
            SignedBodyArg::Block => Self::Block,
            SignedBodyArg::Forward => Self::Forward,
        }
    }
}

/// Parsed `honmoon gateway` arguments.
struct GatewayArgs {
    config: PathBuf,
    addr: String,
    socks_addr: String,
    mgmt_addr: String,
    audit_log: Option<PathBuf>,
    mgmt_token: Option<String>,
    hook_token: Option<String>,
    hook_salt_context: Option<String>,
    tls_intercept: bool,
    redact_secrets: bool,
    signed_body: SignedBodyArg,
    pii_mode: PiiModeArg,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
}

/// Default directory for persisted CA material (`$HOME/.honmoon`, else `.honmoon`).
/// The authority to print in the dashboard URL for a listener bound to `addr`.
///
/// `local_addr()` reports the *bind* address, which for a wildcard bind
/// (`--mgmt-addr 0.0.0.0:8444`, or `[::]:8444`) is not an address anyone can
/// open: `http://0.0.0.0:8444/` resolves to the client itself, so the one-click
/// login this banner advertises would be broken for exactly the deployment that
/// chose to listen broadly.
///
/// A wildcard says "every interface", and the one interface certain to reach
/// this process is the loopback one, so that is what gets printed. Nothing
/// guesses a routable public address: honmoon is not told one, and inventing a
/// hostname the operator never configured would trade a URL that visibly fails
/// for one that fails somewhere less obvious.
fn dashboard_authority(addr: std::net::SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        match addr {
            std::net::SocketAddr::V4(_) => format!("127.0.0.1:{}", addr.port()),
            std::net::SocketAddr::V6(_) => format!("[::1]:{}", addr.port()),
        }
    } else {
        addr.to_string()
    }
}

/// Percent-encode a token for use as a query-string value.
///
/// A generated token is hex, which needs no encoding — but a *persisted* token
/// is whatever the operator put in the file, and `Source::Persisted` is
/// printable. An `&` or `#` in it would otherwise end the parameter: the
/// browser would send `/login` a truncated prefix, and the one-click login this
/// URL advertises would 401 with nothing on screen to explain why.
///
/// Encodes everything outside RFC 3986's unreserved set rather than enumerating
/// what is special, so a character no one thought of is escaped by default
/// rather than missed by omission.
fn percent_encode_query_value(value: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                // Writing to a String cannot fail.
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn default_ca_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".honmoon"),
        None => PathBuf::from(".honmoon"),
    }
}

/// `honmoon gateway` — run the egress proxy and the management API (audit query,
/// approval queue, embedded dashboard) together, sharing one runtime and one set
/// of audit/approval state so held requests can be approved from the dashboard.
fn gateway(args: GatewayArgs) -> Result<()> {
    let GatewayArgs {
        config,
        addr,
        socks_addr,
        mgmt_addr,
        audit_log,
        mgmt_token,
        hook_token,
        hook_salt_context,
        tls_intercept,
        redact_secrets,
        signed_body,
        pii_mode,
        ca_cert,
        ca_key,
    } = args;

    if hook_token.is_some() {
        // Printed, not logged: `RUST_LOG` is unset in an ordinary run, so a
        // `tracing::warn!` would be silent exactly where a deprecation has to be
        // read (same reason as the isolation warning in `run`).
        eprintln!(concat!(
            "honmoon: warning: --hook-token / HONMOON_HOOK_TOKEN is deprecated — use ",
            "--mgmt-token / HONMOON_MGMT_TOKEN. The token now authenticates every ",
            "management API route, not just the Claude Code hook endpoint (#173)."
        ));
    }
    let mgmt = mgmt_token::resolve(mgmt_token.or(hook_token), &mgmt_token::default_dir())?;

    if !tls_intercept && matches!(pii_mode, PiiModeArg::Block) {
        anyhow::bail!("--pii-mode block requires --tls-intercept");
    }

    let (policy, policy_yaml) = load_policy(&config)?;
    tracing::info!(rules = policy.rules.len(), %addr, %socks_addr, %mgmt_addr, "starting gateway");

    let audit = match &audit_log {
        Some(path) => Arc::new(AuditLog::with_file(1024, path).with_context(|| {
            format!(
                "opening audit log {} (it must name a regular file — a symlink, \
                     FIFO, socket, device or directory is refused)",
                path.display()
            )
        })?),
        None => Arc::new(AuditLog::new(1024)),
    };

    let (ca, intercept) = if tls_intercept {
        let ca_cert_path = ca_cert.unwrap_or_else(|| default_ca_dir().join("ca.cer"));
        let ca_key_path = ca_key.unwrap_or_else(|| default_ca_dir().join("ca.key"));
        let ca = CaMaterial::load_or_generate(&ca_cert_path, &ca_key_path)
            .with_context(|| format!("loading CA from {}", ca_cert_path.display()))?;
        tracing::info!(
            ca_cert = %ca_cert_path.display(),
            pii_mode = ?pii_mode,
            "TLS termination enabled; agents must trust this CA certificate"
        );
        (ca, InterceptPolicy::All)
    } else {
        // No interception → no tunnel is ever terminated, so don't create (or
        // depend on) persisted CA files; an ephemeral in-memory CA satisfies
        // the proxy builder, same as `GatewayState::new`.
        (
            CaMaterial::generate().context("generate ephemeral CA")?,
            InterceptPolicy::None,
        )
    };

    // Wire redaction is process-scoped — the proxy sees connections, not agent
    // sessions — so it always keys on the configured context.
    // The key's status outlives its bytes: the key is consumed into the hook
    // salt below, but where it came from — and who else can read it — is
    // recorded only once startup has succeeded.
    let (machine_key, key_status) = hook::machine_key().into_parts();
    let wire_salt = honmoon_core::derive_hook_salt(
        &machine_key,
        hook_salt_context.as_deref().unwrap_or(DEFAULT_SALT_CONTEXT),
    );
    let redaction = redact_secrets
        .then(|| RedactionState::new(wire_salt.clone()).with_signed_body(signed_body.into()));
    let state = GatewayState {
        policy: Arc::new(policy),
        audit: Arc::clone(&audit),
        approvals: Arc::new(honmoon_proxy::approval::ApprovalRegistry::new()),
        pause_timeout: DEFAULT_PAUSE_TIMEOUT,
        ca: Arc::new(ca),
        intercept,
        pii_mode: pii_mode.into(),
        redaction,
    };

    // Bind every listener up front so a bind error is reported before we spawn.
    let proxy_listener =
        TcpListener::bind(&addr).with_context(|| format!("binding proxy {addr}"))?;
    // `off` turns the SOCKS5 transport off entirely: it is a second egress path
    // (raw for anything that is not a `protocol: postgres` endpoint), so a
    // deployment that only wants the inspecting CONNECT proxy must be able to
    // decline it — and must not fail to start because :1080 is taken.
    let socks_listener = match socks_addr.as_str() {
        "off" | "none" | "disabled" => None,
        socks_addr => Some(
            TcpListener::bind(socks_addr)
                .with_context(|| format!("binding SOCKS5 listener {socks_addr}"))?,
        ),
    };
    let mgmt_listener = TcpListener::bind(&mgmt_addr)
        .with_context(|| format!("binding management API {mgmt_addr}"))?;

    let hook_salt = hook_salt_for(hook_salt_context.as_deref(), wire_salt, machine_key);
    let app_state =
        AppState::with_hook_config(state.clone(), policy_yaml, hook_salt, mgmt.token.clone());

    // Printed for the same reason the deprecation above is: an operator who
    // cannot find the credential cannot open the dashboard, and `RUST_LOG` is
    // unset in an ordinary run.
    //
    // The token itself is echoed only when honmoon owns it (never an
    // `--mgmt-token` the operator chose — see `mgmt_token::Source::printable`)
    // *and* stderr is a terminal. A terminal is a person who is about to click
    // the link; a pipe is a journal, a Docker log driver or a log aggregator,
    // where the same line would persist a long-lived credential somewhere far
    // more readable than the `0600` file. The path is printed either way, so
    // the redirected case still says where to read it.
    let mgmt_url = format!(
        "http://{}",
        dashboard_authority(mgmt_listener.local_addr()?)
    );
    let token_path = mgmt.source.path();
    if mgmt.source.printable() && std::io::stderr().is_terminal() {
        eprintln!(
            "honmoon: dashboard: {mgmt_url}/login?token={}",
            percent_encode_query_value(&mgmt.token)
        );
    } else if mgmt.source.printable() {
        eprintln!(
            "honmoon: dashboard: {mgmt_url}/login?token=<the token in {}>",
            token_path
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "your token file".to_string())
        );
    } else {
        eprintln!("honmoon: dashboard: {mgmt_url}/login?token=<your --mgmt-token>");
    }
    if let Some(path) = token_path {
        eprintln!("honmoon: management token: {}", path.display());
    }

    let runtime = tokio::runtime::Runtime::new().context("build tokio runtime")?;

    // Recorded here, not at the key read: every listener is bound and the runtime
    // exists, so this gateway is going to serve. Recording earlier would leave a
    // durable "this process minted degraded placeholders" event behind a startup
    // that died on a taken port having minted nothing at all. The key is read once
    // per process and shared by wire redaction and the management hook endpoint,
    // so this single record covers every placeholder the process goes on to mint.
    if let Err(e) = hook::record_machine_key_status(
        &audit,
        honmoon_core::RedactionTransport::Gateway,
        &key_status,
    ) {
        tracing::warn!(error = %e, "could not record the degraded redaction key in the audit log");
    }
    runtime.block_on(async move {
        // Run both servers and surface unexpected proxy termination — otherwise
        // the process would keep serving the management API while egress
        // filtering is silently down.
        let socks_state = state.clone();
        let proxy_task =
            tokio::spawn(async move { honmoon_proxy::gateway::serve(state, proxy_listener).await });
        let socks_task = socks_listener.map(|socks_listener| {
            tokio::spawn(async move {
                honmoon_proxy::socks::serve_socks(socks_state, socks_listener).await
            })
        });
        // With the listener off there is nothing to join on, so the arm waits
        // forever instead of firing immediately and killing the gateway.
        let socks_task = async move {
            match socks_task {
                Some(task) => task.await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            mgmt = honmoon_mgmt::serve(app_state, mgmt_listener) => {
                mgmt.context("management API server failed")
            }
            proxy = proxy_task => {
                anyhow::bail!("proxy server task exited unexpectedly: {proxy:?}")
            }
            socks = socks_task => {
                anyhow::bail!("SOCKS5 listener task exited unexpectedly: {socks:?}")
            }
        }
    })?;
    Ok(())
}

/// `honmoon run` — start an ephemeral egress proxy, then exec the child with
/// its proxy env pointed at us. The child's exit code is propagated.
fn run(policy: PathBuf, argv: Vec<String>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("no command given; usage: honmoon run --policy P -- <cmd> [args]")?;

    let (policy, _) = load_policy(&policy)?;

    // Bind the proxy socket here and hand it to the proxy thread. Binding in one
    // place (rather than allocating a port, dropping it, and rebinding) closes
    // the TOCTOU window where another process could steal the port.
    let (http_v4, http_v6) = bind_loopback_pair().context("binding egress proxy")?;
    // A second pair, on its own port: the CONNECT proxy and the SOCKS5 listener
    // speak different protocols on the first byte, so they cannot share one.
    // SOCKS5 is what carries a non-HTTP protocol — a `postgres` endpoint is
    // inspected inline behind it — and it is the transport ADR-0005 names for
    // everything `CONNECT` cannot express.
    let (socks_v4, socks_v6) = bind_loopback_pair().context("binding the SOCKS5 listener")?;
    let addr = http_v4.local_addr()?;
    let socks_addr = socks_v4.local_addr()?;
    // Built here rather than inside the thread, because a failure to build one
    // is not a failure the thread can report. `expect` there would unwind the
    // closure, dropping the listeners it captured and handing the proxy port
    // back to the first process that asked for it — while `run` carried on to
    // spawn the child under a profile that opens `localhost:<that port>`. A
    // silent panic on a background thread would have turned a startup error
    // into an unowned port inside the sandbox's one hole. Here it is a `?`.
    let runtime = tokio::runtime::Runtime::new().context("building the proxy runtime")?;
    {
        // One `GatewayState` behind every listener rather than one each: it is
        // `Arc`s throughout, and splitting it would split the audit ring and the
        // approval registry with it, so a verdict's visibility would depend on
        // which loopback family — or which protocol — the client happened to
        // use.
        let state = GatewayState::new(policy.clone());
        std::thread::spawn(move || {
            runtime.block_on(async move {
                // `select!` rather than `tokio::spawn` for the halves beyond the
                // first, and the reason is the whole point of binding them.
                // `serve` ends only by panicking, and a panic inside a spawned
                // task is caught by tokio and parked in a `JoinHandle` nobody
                // joins — so an accept loop could die, drop its listener, and
                // hand that address back to the first process that asked for
                // it, while `run` carried on serving the others and still
                // reported `Enforced`. That is the reopened hole, arrived at
                // silently.
                //
                // Polled in one task, any loop failing takes the whole proxy
                // down with it: the child is then pointed at dead ports and
                // fails closed, which is the honest outcome. It does not leave
                // a live child talking to a boundary with part of it missing.
                tokio::select! {
                    _ = serve_connect(state.clone(), Some(http_v4)) => {}
                    _ = serve_connect(state.clone(), http_v6) => {}
                    _ = serve_socks(state.clone(), Some(socks_v4)) => {}
                    _ = serve_socks(state, socks_v6) => {}
                }
            });
        });
    }

    let proxy_url = format!("http://{addr}");
    // `socks5h`, not `socks5`: the `h` keeps name resolution on honmoon's side,
    // so the hostname the client asked for arrives in the SOCKS5 handshake and
    // can select an endpoint. A client that resolved the name itself would hand
    // over a bare address and every `endpoints:` entry would stop matching.
    let socks_url = format!("socks5h://{socks_addr}");
    tracing::info!(%proxy_url, %socks_url, "egress proxy ready");

    // Only Linux and macOS can actually hold the child; `mut` carries a
    // downgrade if that path turns out to be unusable at spawn time.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(unused_mut))]
    let mut isolation = isolate::Isolation::probe();

    // Enforced: the child is left with no network route that avoids the proxy —
    // an empty namespace on Linux, a Seatbelt profile on macOS. It never returns
    // on success: the sandboxed command's exit code is this process's exit code.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if isolation == isolate::Isolation::Enforced {
        match isolate::run_confined(addr, socks_addr, program, args) {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(error) => {
                // Fail open, per ADR-0005. `run_confined` reports only setup
                // failures, so the command has not run yet and falling through
                // cannot run it twice. The downgrade is announced below rather
                // than swallowed — a silent drop to advisory is the worst of
                // both worlds.
                isolation = isolate::Isolation::Advisory {
                    reason: format!("enforced isolation could not start ({error})"),
                };
            }
        }
    }

    // Say out loud how much this wrapper is worth on this host. Where isolation
    // is advisory, the proxy env vars below are a request to the child, not a
    // constraint on it.
    //
    // Printed rather than logged: the subscriber above filters on `RUST_LOG`,
    // which is unset in an ordinary run and leaves only ERROR enabled, so a
    // `tracing::warn!` here would be silent exactly when the operator most
    // needs to read it.
    if let Some(warning) = isolation.warning() {
        eprintln!("honmoon: warning: {warning}");
    }

    let mut command = std::process::Command::new(program);
    command.args(args);
    for (key, value) in isolate::proxy_env(&proxy_url, &socks_url) {
        command.env(key, value);
    }
    let status = command
        .status()
        .with_context(|| format!("failed to spawn `{program}`"))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Serve `listener` as a CONNECT proxy, or wait forever when there is none.
///
/// The `Option` is the absent IPv6 half of a [`bind_loopback_pair`]: a host with
/// no `::1` has nothing to serve there and nothing for a squatter to take, so
/// the branch simply never resolves rather than ending the `select!` above and
/// taking the live listeners down with it.
async fn serve_connect(state: GatewayState, listener: Option<TcpListener>) {
    match listener {
        Some(listener) => honmoon_proxy::gateway::serve(state, listener).await,
        None => std::future::pending().await,
    }
}

/// The same, for the SOCKS5 listener.
async fn serve_socks(state: GatewayState, listener: Option<TcpListener>) {
    match listener {
        Some(listener) => honmoon_proxy::socks::serve_socks(state, listener).await,
        None => std::future::pending().await,
    }
}

/// How many ports to try before giving up on finding one free on both loopbacks.
const LOOPBACK_PORT_ATTEMPTS: u32 = 16;

/// Bind the ephemeral proxy on `127.0.0.1` **and** `::1`, at one shared port.
///
/// Why both, when the child is only ever handed the IPv4 address: macOS's
/// Seatbelt dialect cannot express a literal address in a `remote ip` filter, so
/// the hole the profile opens for the proxy is `localhost:<port>` — and
/// `localhost` there covers `::1` as well as `127.0.0.1`. Binding only IPv4
/// would leave the IPv6 half of that hole pointing at whatever unrelated process
/// happened to hold the same port number on `::1`, which a confined child could
/// then reach with no policy in the way. Owning both makes the profile's single
/// exception mean exactly what its comment claims.
///
/// The retry is here because the two binds cannot be made atomic: the kernel
/// chooses the port when the IPv4 socket binds, and `::1` may already be taken
/// at that number. A host with no IPv6 loopback at all is not a failure — if
/// nothing can bind `::1`, there is no second half of the hole to close.
fn bind_loopback_pair() -> Result<(TcpListener, Option<TcpListener>)> {
    let mut taken = None;
    for _ in 0..LOOPBACK_PORT_ATTEMPTS {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = v4.local_addr()?.port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
            Ok(v6) => return Ok((v4, Some(v6))),
            // Occupied on `::1`. Drop this pair and let the kernel pick again;
            // holding the IPv4 half would only make it likelier to recur.
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => taken = Some(error),
            // Only a *proven absent* IPv6 loopback may downgrade to IPv4 alone:
            // if nothing on this host can bind `::1`, no squatter can either, so
            // there is no second half of the hole to close. Every other failure
            // — descriptor pressure, a sandbox refusing the socket — leaves
            // `::1:<port>` unowned while macOS still opens the profile's
            // `localhost:<port>` exception, which is precisely the state this
            // function exists to prevent. Those fail closed.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
                ) =>
            {
                return Ok((v4, None));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow::anyhow!(
        "could not find a port free on both 127.0.0.1 and ::1 in \
         {LOOPBACK_PORT_ATTEMPTS} attempts (last: {})",
        taken
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ))
}

/// Choose how the management hook endpoint keys placeholder minting.
///
/// Unpinned — the default — it follows each payload's `session_id`, which is
/// what makes it byte-identical to `honmoon hook` and is the whole of #98. A
/// pinned context instead shares wire redaction's one salt, which is already
/// derived from that same context.
///
/// Named and separate from `gateway` so the choice can be tested: swapping the
/// two arms leaves every transport-level test passing while parity is dead in
/// the shipped binary, because those tests are handed the variant rather than
/// selecting it.
fn hook_salt_for(context: Option<&str>, wire_salt: Vec<u8>, machine_key: Vec<u8>) -> HookSalt {
    match context {
        Some(_) => HookSalt::fixed(wire_salt),
        None => HookSalt::per_session(machine_key),
    }
}

/// Read a policy file and parse it — the one path every command that takes a
/// policy path goes through: `honmoon run --policy`, `honmoon gateway --config`
/// and `honmoon policy validate`.
///
/// The source comes back alongside the `Policy` because `gateway` needs both —
/// the policy to run on, and the text the management API serves verbatim at
/// `GET /api/policy` for the dashboard's read-only policy view. It reaches that
/// route through `AppState::with_hook_config`, whose name is about the salt
/// argument beside it and not about this one: nothing on the hook endpoint reads
/// `policy_yaml`. The other two callers drop it.
///
/// [`not_a_policy_document`] runs here rather than in any one command, which is
/// the whole of #202: classifying the file's shape belongs to the *read*, since
/// the file a mistyped path resolves to is the same file whichever flag named it
/// and serde quotes it the same way. With the check in `policy validate` alone
/// after #201, the other two printed the file whole.
///
/// [`mapping_names_no_policy_field`] runs beside it and is a different kind of
/// check, which is worth saying plainly because the two read alike here. The
/// first only rewords — every shape it names fails [`Policy::from_yaml`] anyway,
/// and `every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway` holds it
/// to that. The second **moves a verdict on purpose**, and that is the whole of
/// #220: a Kubernetes `Secret`, a `DB_PASSWORD:` file and a service-account JSON
/// key are all mappings, so every `Policy` field took its default and
/// `policy validate` answered `policy is valid (0 rules, 0 endpoints)` on a
/// credential file. Nothing was quoted because nothing went wrong.
///
/// It refuses here rather than in [`Policy::from_yaml`] because the rule belongs
/// where the *path* is. The defect is a mistyped `--config` / `--policy`; the
/// library is handed a string and has no path to name in the refusal; and a
/// `Policy` built from YAML in a test, a bench or `honmoon-mgmt` is not a file
/// anybody mistyped. Putting it here also keeps `Policy` itself untouched, which
/// is what keeps this off the `crates/AGENTS.md` **Ask first** list and out of
/// TD-001's TS-type and JSON Schema sync.
fn load_policy(path: &Path) -> Result<(Policy, String)> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;

    if let Some(shape) = not_a_policy_document(&src) {
        anyhow::bail!(
            "{} is not a policy document: its top level is {shape}, not a mapping of \
             policy fields. Contents withheld — check the path.",
            path.display()
        );
    }

    if mapping_names_no_policy_field(&src) {
        anyhow::bail!(
            "{} is not a policy document: it is a mapping, but none of its keys is a \
             policy field ({}). Contents withheld — check the path.",
            path.display(),
            POLICY_FIELDS.join(", ")
        );
    }

    let policy = Policy::from_yaml(&src)?;
    Ok((policy, src))
}

/// A top-level shape a policy can never have, named without quoting what it
/// held.
///
/// `None` means "hand it to the loader", and covers three cases: a mapping (an
/// ordinary policy), a null document (an empty file, which *is* a valid policy
/// — every field at its default), and text YAML itself cannot parse, where
/// serde's own syntax diagnostic is the useful one: it names what it stopped on
/// rather than reproducing the document, and carries a line and column once the
/// scanner got past the start. (Not always — a reserved indicator as the very
/// first character has no position to report relative to. The half that holds
/// unconditionally is the one that matters, and
/// `a_syntax_error_keeps_serdes_positional_diagnostic` asserts both, marking
/// which inputs carry a position.)
///
/// A multi-document stream is **not** a fourth case. It is classified by its
/// first document like any other file, because that is the document the loader
/// tries to deserialize first and therefore the one it can quote. A stream whose
/// first document is a mapping still passes through *this* guard, and is refused
/// content-free either way past it — by [`mapping_names_no_policy_field`] when
/// that mapping declares no policy field, and by the loader, for being a stream,
/// when it declares one. Which of the two answers is not incidental: a
/// Kubernetes manifest carries both a `---` line and no policy key, so the
/// mistyped-path case gets the message about the path rather than one about
/// streams. `a_secrets_mapping_before_a_second_document_is_refused_for_the_path`
/// pins that, because before #220 the loader answered for both.
///
/// The remaining shapes are why this exists. serde renders a top-level type
/// mismatch as `invalid type: string "<value>"`, and when the top level is a
/// plain scalar that value is **the whole file** — YAML folds its lines into one
/// scalar, so a PEM key arrives entire. `policy validate` is documented for CI,
/// where the path it is given comes from the repository under test, so a
/// mistyped path or a branch that replaces `policy.yaml` with a symlink to
/// `~/.honmoon/mgmt-token`, an SSH key or a `.env` would put that file in the
/// log. `run --policy` and `gateway --config` take a path from an operator
/// rather than a repository, which is why #201 fixed the CI-facing one first —
/// but their stderr is not always read by the person who typed the path: a
/// supervisor ships it to a journal or a log aggregator. Classifying the shape
/// first says what is wrong without reading the contents out.
///
/// No verdict moves: every shape named here fails [`Policy::from_yaml`] as
/// well, so the guard and the loader refuse the same files and only the message
/// differs. That is a claim about this function, so it is checked rather than
/// asserted — and since #202 lifted the guard into [`load_policy`], it cannot be
/// checked by running one command against another, because all three now run
/// this. The loader is the independent witness that is left, and
/// `every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway` asks it
/// directly, in both directions. The pass-through direction is the one that
/// caught a real bug: this over-refused a tagged mapping once already.
///
/// It is a bound, not a blanket. A *mapping* carrying a long string still
/// reaches serde's quoting (`version: "<…>"`) — but that is a file shaped like
/// a policy, and the value quoted is the author's own field, which is the
/// diagnosis they need.
fn not_a_policy_document(src: &str) -> Option<&'static str> {
    shape_unfit_for_a_policy(&first_document(src)?)
}

/// The document [`Policy::from_yaml`] will try to deserialize, parsed as an
/// untyped value — or `None` when there is nothing for a guard to classify.
///
/// Shared by [`not_a_policy_document`] and [`mapping_names_no_policy_field`] so
/// that *which* document gets classified cannot drift between them. That choice
/// is the security-critical half and it is not obvious; the parse itself is not,
/// and is simply done twice on a file read once per process.
///
/// `None` says "hand it to the loader" in both cases it covers: a file YAML
/// cannot parse, and the measured-unreachable one below.
fn first_document(src: &str) -> Option<serde_yaml::Value> {
    use serde::Deserialize as _;

    // The *first* document, not the stream. `serde_yaml::from_str::<Value>`
    // refuses a multi-document stream outright rather than handing back the
    // first document, so asking it would send every file carrying a `---` line
    // down the `None` arm below and on to the loader — and the loader
    // deserializes the first document *before* it notices the second, so a file
    // whose first document is a plain scalar has that scalar quoted whole. A
    // `---` line under a PEM key was enough to leak the key on every one of the
    // three commands. Reading one document at a time removes the distinction:
    // what gets classified is the document the loader will try to deserialize.
    let mut documents = serde_yaml::Deserializer::from_str(src);
    // `documents.next()` returning `None` is defensive, and measured as
    // unreachable rather than assumed to be the empty-file case: `serde_yaml`
    // 0.9 yields a first document for every `&str`, an empty one included, so an
    // empty file arrives at the callers as `Value::Null` and is passed through
    // there. Kept because the only correct reading of "no document" is that
    // there is nothing to classify, and deferring is what these guards do when
    // they cannot classify — a `unreachable!()` here would turn a `serde_yaml`
    // change into a panic in a binary whose job is to refuse things safely. It
    // is the one branch here no test covers, for the same reason.
    let first = documents.next()?;

    // `Err` is not a YAML document at all. serde's own syntax diagnostic is the
    // useful one there — it names what it stopped on rather than reproducing the
    // document — so this defers to the loader rather than replacing it. That the
    // deferred text cannot come back out is the claim the deferral rests on, and
    // it is asserted rather than assumed:
    // `a_syntax_error_keeps_serdes_positional_diagnostic`.
    serde_yaml::Value::deserialize(first).ok()
}

/// The recursive half of [`not_a_policy_document`], split out for the tag.
///
/// A tag does not change what a document *is*. serde looks straight through it
/// — `!Foo {version: 1}` deserializes as the mapping underneath, and the loader
/// accepts it — so refusing every tagged node would refuse a policy the gateway
/// runs, which is the drift this command exists to rule out, pointing the other
/// way. Recursion is bounded by the parsed value: YAML gives a node one tag.
fn shape_unfit_for_a_policy(value: &serde_yaml::Value) -> Option<&'static str> {
    use serde_yaml::Value;

    match value {
        // A mapping is a policy's shape; null is an empty document, which is a
        // valid policy with every field at its default.
        Value::Mapping(_) | Value::Null => None,
        Value::Sequence(_) => Some("a list"),
        Value::String(_) => Some("plain text"),
        Value::Bool(_) | Value::Number(_) => Some("a single value"),
        Value::Tagged(tagged) => shape_unfit_for_a_policy(&tagged.value),
    }
}

/// Every top-level key `Policy` declares, and the whole of what
/// [`mapping_names_no_policy_field`] recognises.
///
/// Written out rather than read off the struct, because `serde` exposes no field
/// list at runtime. So it can go stale, and a stale list is the one way this
/// rule turns into an outage: a policy using only the field missing here would
/// be refused. `policy_fields_are_exactly_the_ones_policy_declares` is what
/// stops that — it serializes a `Policy` and requires its keys to be exactly
/// these, so adding a field to `Policy` fails this crate's tests until the field
/// is named here too.
const POLICY_FIELDS: [&str; 4] = ["version", "egress", "endpoints", "rules"];

/// A mapping that declares none of [`POLICY_FIELDS`] — a file shaped like a
/// policy that says nothing a policy says (#220).
///
/// Every `Policy` field carries `#[serde(default)]` and the struct has no
/// `deny_unknown_fields`, so *any* mapping deserializes: a Kubernetes `Secret`
/// manifest, a `DB_PASSWORD: …` file and a service-account JSON key (JSON is
/// valid YAML) each loaded as deny-by-default with no rules, and
/// `honmoon policy validate` reported success. Under `gateway --config` the
/// file's whole text then reached `AppState.policy_yaml` and `GET /api/policy`.
///
/// The rule is deliberately **"a mapping with no recognised key"**, not "a
/// document with no recognised key", and the two boundaries either side of that
/// are the point of the check rather than details of it:
///
/// - An empty file parses as `Value::Null`, not as a mapping. It is a valid
///   policy today — every field at its default — and stays one. The gateway
///   starts on it.
/// - A mapping carrying **at least one** recognised key is accepted whatever
///   else it carries, so forward-compatibility is untouched: a policy written
///   for a newer honmoon that names a field this build does not know still
///   loads, exactly as it did. That property is why `deny_unknown_fields` was
///   rejected for this, so it is the property most worth pinning —
///   `an_unknown_sibling_of_a_recognised_key_still_loads`.
///
/// An explicitly empty mapping (`{}`) is refused, and that is the literal rule
/// rather than an oversight: it is a mapping, and none of [`POLICY_FIELDS`]
/// appears in it. Exempting it would buy a spelling of "no policy" that an empty
/// file already spells, at the cost of a special case in a one-sentence rule.
/// `an_explicitly_empty_mapping_is_refused_and_an_empty_file_is_not` pins both
/// halves so the two cannot be confused for each other later. A templating step
/// that renders an empty policy as `{}` rather than as an empty file fails the
/// read from here on — fail-closed, and the operator is told which keys are
/// missing, but it is a behaviour change and not only a refusal of bad input.
///
/// **The residual, stated because the rule looks tighter than it is.** This is a
/// name-only test, and `version` is the one of the four that is not
/// honmoon-specific: a `docker-compose.yml` opens with an unquoted `version: 3`,
/// so it is admitted and still loads as a 0-rule policy whose source `gateway`
/// serves. Measured, and pinned by
/// `version_alone_admits_a_file_no_operator_wrote_as_a_policy` so it cannot drift
/// unnoticed. It is not closed here because the alternative — dropping `version`
/// from the admission set — refuses a file containing only `version: 1`, which is
/// a policy the gateway starts on, and over-refusal is the failure that costs an
/// operator an outage rather than a diagnosis. The quoted spelling
/// (`version: "3.8"`) does not even reach this rule: `version` is a `u32`, so the
/// loader refuses it and quotes only the author's own three characters. Narrowing
/// the ticket is its own decision, filed rather than taken in passing.
fn mapping_names_no_policy_field(src: &str) -> bool {
    first_document(src).is_some_and(|value| names_no_policy_field(&value))
}

/// The recursive half of [`mapping_names_no_policy_field`], split out for the
/// tag exactly as [`shape_unfit_for_a_policy`] is, and for the same reason:
/// serde looks straight through a tag, so `!Foo {version: 1}` is a policy and
/// `!Secret {apiVersion: v1}` is not.
fn names_no_policy_field(value: &serde_yaml::Value) -> bool {
    use serde_yaml::Value;

    match value {
        Value::Mapping(mapping) => !mapping.keys().any(|key| {
            // A non-string key — YAML allows a sequence or a mapping there —
            // cannot be a policy field, and `as_str` says so without a panic.
            key.as_str().is_some_and(|key| POLICY_FIELDS.contains(&key))
        }),
        Value::Tagged(tagged) => names_no_policy_field(&tagged.value),
        // Not a mapping, so this rule has nothing to say. `Null` is the empty
        // file, which is a valid policy; every other shape here is one
        // `not_a_policy_document` has already named, since it runs first.
        _ => false,
    }
}

/// `honmoon policy validate` — load a policy the way the gateway does, say what
/// the loader found, and exit.
///
/// The body is deliberately thin: [`load_policy`] — the same call `gateway` and
/// `honmoon run` make — and then a count. Everything that decides whether a
/// policy is acceptable lives in that one function, so there is no second
/// implementation here to drift from the one that matters. Its error travels up
/// unwrapped for the same reason: `main`'s `Result` prints it, so a rejected
/// policy reads the way the gateway would have reported it.
///
/// That now covers [`not_a_policy_document`] too. It was this path's own words
/// when #201 added it, and the other two callers went on quoting the file;
/// #202 moved it into the shared read, so the three commands refuse a
/// non-policy in the same words and not merely with the same verdict.
///
/// What this function *adds* is everything the gateway does around that load and
/// this one must not: no management token is resolved (the side effect #198 is
/// about), no audit log is opened, no CA is read or generated, no listener is
/// bound. Not suppressing those — never reaching them.
fn policy_validate(path: &Path) -> Result<()> {
    let (policy, _) = load_policy(path)?;

    // Counts, not contents: enough to see the file that loaded was the one
    // meant, without putting an operator's endpoint names in a CI log.
    // On stderr, like every other line this binary addresses a human with, so
    // stdout stays empty for a caller that is piping it.
    eprintln!(
        "honmoon: {}: policy is valid ({} rules, {} endpoints)",
        path.display(),
        policy.rules.len(),
        policy.endpoints.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::percent_encode_query_value;

    /// The guard's central claim, checked where it cannot be circular.
    ///
    /// `not_a_policy_document` exists to reword serde's diagnostic, never to
    /// change a verdict. Before #202 that was checked by running
    /// `policy validate` and `gateway --config` over the same file and requiring
    /// them to agree — which stopped meaning anything the moment the guard moved
    /// into the read they share. `Policy::from_yaml` is the independent witness
    /// that is left, so it is asked directly.
    ///
    /// The claim is one-directional, and the loops below say so rather than
    /// overstating it. **Refusing** is where a verdict could move, so every shape
    /// the guard names must be one the loader refuses anyway. Passing a shape
    /// through cannot move a verdict at all — the loader simply decides, as it
    /// did before — so the second loop is not "everything it passes through
    /// loads": it is the narrower and more useful claim that the shapes a
    /// *policy* arrives in still reach the loader and still load. A mapping with
    /// a mistyped field passes the guard and is refused by the loader, which is
    /// the documented bound, and `a_documented_bound_still_reaches_the_loader`
    /// pins it separately.
    ///
    /// The second loop is the direction that matters more. A guard that refuses
    /// a policy the gateway would have run turns a diagnostic improvement into
    /// an outage, and it has happened once here already: an earlier version
    /// refused every tagged node, and serde looks straight through a tag.
    #[test]
    fn every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway() {
        use super::not_a_policy_document;
        use honmoon_core::Policy;

        for src in [
            // The mistyped-path shapes: a token file, a PEM, and the scalars a
            // stray value lands as.
            "ghp_notarealcredential\n",
            "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----\n",
            "- one\n- two\n",
            "true\n",
            "42\n",
            // A tag over a scalar is still a scalar.
            "!Secret ghp_notarealcredential\n",
            // The same PEM with a second document after it (#202). `serde_yaml`
            // refuses a multi-document stream rather than handing back its first
            // document, so classifying the stream deferred this to the loader —
            // which deserializes the first document before it notices the second
            // and quoted the key whole.
            "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----\n---\nsecond\n",
            // The minimal form of the same shape: a scalar and a `---` line.
            "ghp_notarealcredential\n---\n",
        ] {
            assert!(
                not_a_policy_document(src).is_some(),
                "the guard must name this shape rather than quote it: {src:?}"
            );
            assert!(
                Policy::from_yaml(src).is_err(),
                "…and the loader must refuse it too, or the guard has moved a \
                 verdict rather than reworded one: {src:?}"
            );
        }

        for src in [
            // Empty: a policy with every field at its default.
            "",
            "version: 1\n",
            // An explicit document-start marker is one document, not two. A
            // policy file beginning `---` is ordinary YAML, and a guard that
            // counted it as a stream would refuse one the gateway runs.
            "---\nversion: 1\n",
            // A tagged mapping is a mapping.
            "!Foo {version: 1}\n",
        ] {
            assert!(
                not_a_policy_document(src).is_none(),
                "the guard must hand this to the loader: {src:?}"
            );
            assert!(
                Policy::from_yaml(src).is_ok(),
                "…and the loader must accept it, so refusing it early would \
                 refuse a policy the gateway runs: {src:?}"
            );
        }
    }

    /// The guard's deferral arm, which is a security claim and was not checked.
    ///
    /// For text YAML cannot parse, `not_a_policy_document` returns `None` on
    /// purpose: serde's own syntax diagnostic names what it stopped on rather
    /// than reproducing the document, and carries a line and column wherever the
    /// scanner got past the start — which is more useful to whoever is fixing a
    /// real policy than "this is not a policy document". #202 is what
    /// makes `run --policy` and `gateway --config` depend on that being true, so
    /// it is asserted rather than assumed — the arm is the one place the guard
    /// hands a file's own text to serde by choice.
    ///
    /// Pinned as an absence, like the integration test: the distinctive lines of
    /// the input must not appear in what the loader renders.
    #[test]
    fn a_syntax_error_keeps_serdes_positional_diagnostic() {
        use super::not_a_policy_document;
        use honmoon_core::Policy;

        // Each of these is a single document YAML cannot parse, carrying a line
        // that would be a disclosure if it were echoed. The flag is whether
        // serde's message carries a position: it does once the scanner has
        // advanced, and does not when the very first character is what stopped
        // it — which is why the doc comments here claim a position "where the
        // scanner got past the start" rather than always.
        for (src, has_position) in [
            // A tab where indentation is expected.
            ("rules:\n\tghp_notarealcredential: 1\n", true),
            // An unterminated quoted scalar — two positions, in fact.
            ("version: \"ghp_notarealcredential\n", true),
            // A reserved indicator as the first character: nothing to report a
            // position relative to.
            ("@ghp_notarealcredential\n", false),
        ] {
            assert!(
                not_a_policy_document(src).is_none(),
                "this is the deferral arm — the guard must hand it to serde: {src:?}"
            );
            let error = Policy::from_yaml(src)
                .expect_err("YAML this malformed cannot load")
                .to_string();
            // The security property, and the whole reason deferring is allowed.
            assert!(
                !error.contains("ghp_notarealcredential"),
                "the deferral only holds while serde's syntax diagnostic names \
                 what it stopped on rather than reproducing the document: {error}"
            );
            assert_eq!(
                error.contains("line") && error.contains("column"),
                has_position,
                "the position half of the claim moved for {src:?}: {error}"
            );
        }
    }

    /// The bound the guard draws on purpose, pinned so a later change has to
    /// move it deliberately.
    ///
    /// A file that *is* a mapping but carries a mistyped field value reaches
    /// serde's quoting, and the value quoted is the author's own field — which
    /// is the diagnosis they need, with a line and column. Widening the guard to
    /// suppress it would turn a useful error into a useless one; narrowing the
    /// guard so it stopped passing mappings through would refuse policies the
    /// gateway runs. Neither direction should happen without this test saying so.
    #[test]
    fn a_documented_bound_still_reaches_the_loader() {
        use super::not_a_policy_document;
        use honmoon_core::Policy;

        let src = "version: not-a-number\n";
        assert!(
            not_a_policy_document(src).is_none(),
            "a mapping is a policy's shape — the guard passes it through"
        );
        let error = Policy::from_yaml(src)
            .expect_err("`version` is a u32")
            .to_string();
        assert!(
            error.contains("not-a-number"),
            "the author's own field value is the diagnosis, and is quoted on \
             purpose — this is the stated bound of the guard, not a leak: {error}"
        );
    }

    /// The one way #220's rule turns into an outage, held shut mechanically.
    ///
    /// [`POLICY_FIELDS`] mirrors `Policy`'s top-level keys by hand, because
    /// `serde` exposes no field list at runtime. If a field is added to `Policy`
    /// and not added here, a policy that uses only that field declares no
    /// recognised key and the read refuses it — a file the gateway would have
    /// run, rejected by a guard meant to catch credential files.
    ///
    /// So the list is checked against the struct rather than against a second
    /// copy of itself: a `Policy` is serialized and its keys read back off the
    /// document. Order is asserted too, because `serde` writes fields in
    /// declaration order and an equality that ignored it would be the weaker
    /// claim for no gain.
    ///
    /// `compiled` is absent by construction — it is `#[serde(skip)]`, which is
    /// what keeps it out of the YAML and JSON shapes TD-001 syncs. If it ever
    /// appears here, that is the finding, not a fixture to update.
    #[test]
    fn policy_fields_are_exactly_the_ones_policy_declares() {
        use super::POLICY_FIELDS;
        use honmoon_core::Policy;

        let document = serde_yaml::to_value(Policy::default()).expect("a Policy serializes");
        let keys: Vec<&str> = document
            .as_mapping()
            .expect("a Policy serializes as a mapping")
            .keys()
            .map(|key| key.as_str().expect("a Policy's field names are strings"))
            .collect();

        assert_eq!(
            keys, POLICY_FIELDS,
            "`Policy`'s top-level fields have moved and `POLICY_FIELDS` has not. \
             A policy using only the field missing from that list would now be \
             refused by `load_policy` as declaring no policy field — add it there \
             rather than editing this test"
        );
    }

    /// #220's rule, checked on both sides: the mappings a mistyped path lands
    /// on are refused, and the mappings a policy arrives in are not.
    ///
    /// The second loop carries the weight, exactly as it does in
    /// `every_shape_the_guard_refuses_is_one_the_loader_refuses_anyway`. This
    /// check *moves* a verdict by design, so "does it refuse the right files" is
    /// only half of it; refusing a file the gateway would have run is the failure
    /// that costs an operator an outage, and every entry below is asked of the
    /// loader as well so the two cannot part company.
    #[test]
    fn a_mapping_that_declares_no_policy_field_is_refused_and_a_policy_is_not() {
        use super::mapping_names_no_policy_field;
        use honmoon_core::Policy;

        for src in [
            // A Kubernetes Secret, a colon-style secrets file and a
            // service-account JSON key: the three the issue measured.
            "apiVersion: v1\nkind: Secret\ndata:\n  password: dGhyb3dhd2F5\n",
            "DB_PASSWORD: throwaway-not-a-real-value\n",
            r#"{"type": "service_account", "project_id": "throwaway"}"#,
            // A tag does not make a mapping a policy any more than it stops one
            // being a policy — the same reading `shape_unfit_for_a_policy` takes.
            "!Secret {apiVersion: v1, kind: Secret}\n",
            // A near miss, and the reason the list is exact rather than fuzzy:
            // `rule` is not `rules`, so this declares nothing honmoon reads and
            // would have started a gateway that enforced none of it.
            "rule:\n  - name: sql-no-drop\n",
        ] {
            assert!(
                mapping_names_no_policy_field(src),
                "a mapping declaring no policy field must be refused: {src:?}"
            );
            // The measured starting point: the loader takes every one of these.
            // Without this, the assertion above could pass against a loader that
            // had already refused them, and the test would be pinning nothing.
            assert!(
                Policy::from_yaml(src).is_ok(),
                "…and #220 is precisely that the loader accepts it, so this must \
                 stay the read's own refusal: {src:?}"
            );
        }

        for src in [
            // One recognised key each, so every name in `POLICY_FIELDS` is
            // exercised as an admission ticket rather than only the first.
            "version: 1\n",
            "egress:\n  default: deny\n",
            "endpoints: {}\n",
            "rules: []\n",
            // A tagged mapping is a mapping.
            "!Foo {version: 1}\n",
            // Not a mapping at all: `not_a_policy_document` owns these, and this
            // check must not answer for them. The empty document is the one that
            // matters — it is a valid policy. The rest reach the catch-all arm,
            // which defers; they are here so that arm is exercised by something
            // other than `Null`, since deferring is only safe while the guard
            // that runs first still names them.
            "",
            "ghp_notarealcredential\n",
            "- one\n- two\n",
            "true\n",
            "42\n",
        ] {
            assert!(
                !mapping_names_no_policy_field(src),
                "this must reach the loader: {src:?}"
            );
        }
    }

    /// The boundary the rule is written on, with both halves in one test so
    /// neither can be read as the other.
    ///
    /// An empty *file* is a valid policy and stays one: YAML reads it as `null`,
    /// not as a mapping, so the rule never applies. An empty *mapping* is a
    /// mapping in which none of `POLICY_FIELDS` appears, so it is refused — the
    /// literal rule, kept literal rather than given a special case for a
    /// spelling of "no policy" that the empty file already has.
    #[test]
    fn an_explicitly_empty_mapping_is_refused_and_an_empty_file_is_not() {
        use super::mapping_names_no_policy_field;
        use honmoon_core::Policy;

        assert!(
            !mapping_names_no_policy_field(""),
            "an empty file is `null`, not a mapping — it is a policy with every \
             field at its default and the gateway starts on one"
        );
        assert!(
            Policy::from_yaml("").is_ok(),
            "…which is only true while the loader still takes it"
        );

        for empty_mapping in ["{}\n", "{}"] {
            assert!(
                mapping_names_no_policy_field(empty_mapping),
                "an explicitly empty mapping declares no policy field: \
                 {empty_mapping:?}"
            );
        }
    }

    /// Forward-compatibility, asked of the function directly.
    ///
    /// `#[serde(deny_unknown_fields)]` was rejected for #220 because it breaks
    /// this, so the option that was taken has to keep it exactly. One recognised
    /// key admits the document and nothing about its siblings is consulted.
    #[test]
    fn an_unknown_sibling_of_a_recognised_key_still_loads() {
        use super::mapping_names_no_policy_field;
        use honmoon_core::Policy;

        for src in [
            // A field a newer honmoon writes and this build has never heard of.
            "version: 2\ntelemetry:\n  exporter: otlp\n",
            // The recognised key last, so admission cannot depend on position.
            "telemetry:\n  exporter: otlp\nrules: []\n",
        ] {
            assert!(
                !mapping_names_no_policy_field(src),
                "one recognised key admits the document whatever else it \
                 carries — that is the forward-compatibility this option was \
                 chosen to keep: {src:?}"
            );
            assert!(
                Policy::from_yaml(src).is_ok(),
                "…and the loader goes on ignoring the unknown field: {src:?}"
            );
        }
    }

    /// Three mapping shapes the rule has to answer for, each measured against
    /// the loader rather than reasoned about — the two that look like
    /// over-refusals are not, and the third moved which guard answers.
    ///
    /// A **top-level merge key** (`<<: *anchor`) is the one that looks worst. It
    /// is refused, and `Policy::from_yaml` "accepts" the same file — but what it
    /// accepts is a policy with `version` at 0 and no rules, because `serde_yaml`
    /// does not apply a merge on the way into a struct (`Value::apply_merge` is
    /// opt-in and nothing here calls it). The merge never took, so the file was
    /// already a silently-empty policy: refusing it is #220's case exactly, not a
    /// regression against one. An **alias** is different and is not affected —
    /// `egress: *defaults` resolves, and `egress` is a recognised key, so the
    /// document is admitted on it like any other.
    ///
    /// A **nested-only** recognised key is refused for the same reason: `rules`
    /// under `spec` declares nothing honmoon reads, and the gateway would have
    /// started enforcing none of it.
    #[test]
    fn a_merge_key_or_a_nested_only_key_declares_nothing_at_the_top_level() {
        use super::mapping_names_no_policy_field;
        use honmoon_core::Policy;

        for (label, src) in [
            (
                "a top-level merge key",
                "base: &b\n  version: 1\n  egress:\n    default: allow\n<<: *b\n",
            ),
            (
                "a nested-only recognised key",
                "spec:\n  rules:\n    - name: x\n",
            ),
        ] {
            assert!(
                mapping_names_no_policy_field(src),
                "{label} declares no policy field at the top level"
            );
            let policy = Policy::from_yaml(src)
                .unwrap_or_else(|error| panic!("the loader takes {label}: {error}"));
            assert_eq!(
                (policy.version, policy.rules.len()),
                (0, 0),
                "…and what it takes is an empty policy, which is why refusing \
                 {label} is #220's case rather than an over-refusal"
            );
        }

        // The control, and the half that must not move: an alias is resolved, so
        // a document admitted on a recognised key stays admitted.
        let aliased = "defaults: &d\n  default: allow\negress: *d\n";
        assert!(
            !mapping_names_no_policy_field(aliased),
            "`egress` is a recognised key however its value is spelled"
        );
        assert_eq!(
            Policy::from_yaml(aliased)
                .expect("an aliased egress loads")
                .egress
                .default,
            honmoon_core::Verdict::Allow,
            "the alias must still resolve — otherwise this control passes \
             vacuously against a policy that lost its egress"
        );
    }

    /// The shape that moved which guard answers, pinned because #217's account of
    /// it is now only half true.
    ///
    /// `not_a_policy_document` passes a stream whose first document is a mapping
    /// through, and before #220 the loader then refused it for being a stream.
    /// It still does when that mapping declares a policy field — but a Kubernetes
    /// manifest carries both a `---` line and no policy key, and that is the
    /// mistyped-path case, so it now gets the message about the path instead.
    /// Both refusals carry no content; which one answers is the point.
    #[test]
    fn a_secrets_mapping_before_a_second_document_is_refused_for_the_path() {
        use super::{mapping_names_no_policy_field, not_a_policy_document};
        use honmoon_core::Policy;

        let secrets_first =
            "apiVersion: v1\nkind: Secret\ndata:\n  p: dGhyb3dhd2F5\n---\nsecond: doc\n";
        assert!(
            not_a_policy_document(secrets_first).is_none(),
            "a mapping first document passes the shape guard, stream or not"
        );
        assert!(
            mapping_names_no_policy_field(secrets_first),
            "…and the recognised-key rule answers it, because the mistyped path \
             is the useful diagnosis for a manifest carrying a `---` line"
        );

        // The other half of the old claim, still true: a *policy* before a second
        // document is admitted here and refused by the loader for being a stream.
        let policy_first = "version: 1\negress:\n  default: deny\n---\nsecond: doc\n";
        assert!(
            !mapping_names_no_policy_field(policy_first),
            "one recognised key admits it past this rule"
        );
        let error = Policy::from_yaml(policy_first)
            .expect_err("a stream is not a policy")
            .to_string();
        assert!(
            error.contains("more than one document"),
            "…and the loader refuses it for being a stream: {error}"
        );
        assert!(
            !error.contains("second: doc"),
            "that refusal must carry no content either: {error}"
        );
    }

    /// The rule's residual, measured rather than left to be discovered.
    ///
    /// The admission test is by *name*, and `version` is the one of the four keys
    /// that other config formats also use. A `docker-compose.yml` opens with an
    /// unquoted `version: 3`, so it is admitted, loads as a 0-rule policy, and
    /// under `gateway --config` its source — inline environment secrets included —
    /// is what `GET /api/policy` serves. That is #220's consequence on a narrower
    /// file class than the three the issue measured, and this test exists so the
    /// gap is a recorded fact with a failing test behind any change to it, rather
    /// than a surprise for whoever finds it next.
    ///
    /// Kept rather than closed on purpose: dropping `version` from
    /// [`POLICY_FIELDS`] would refuse a file containing only `version: 1`, a
    /// policy the gateway starts on, and refusing a policy the gateway runs is the
    /// worse direction. If this test ever starts failing because the ticket was
    /// narrowed deliberately, delete it — do not weaken it.
    #[test]
    fn version_alone_admits_a_file_no_operator_wrote_as_a_policy() {
        use super::mapping_names_no_policy_field;
        use honmoon_core::Policy;

        let compose = "version: 3\nservices:\n  db:\n    environment:\n      \
                       POSTGRES_PASSWORD: throwaway-not-a-real-value\n";
        assert!(
            !mapping_names_no_policy_field(compose),
            "`version` is a recognised key, so this is admitted — the residual, \
             not a bug in the check"
        );
        let policy = Policy::from_yaml(compose).expect("and it loads");
        assert_eq!(
            (policy.rules.len(), policy.endpoints.len()),
            (0, 0),
            "as a policy that enforces nothing anybody wrote"
        );

        // The spelling that does not reach this rule at all, and the reason the
        // residual is narrower than "every compose file": `version` is a `u32`,
        // so the loader refuses the quoted form and quotes only those three
        // characters — the author's own field value, which is the documented
        // bound rather than a leak.
        let quoted = "version: \"3.8\"\nservices:\n  db:\n    image: postgres\n";
        assert!(
            !mapping_names_no_policy_field(quoted),
            "still admitted by name — the refusal below is the loader's"
        );
        let error = Policy::from_yaml(quoted)
            .expect_err("`version` is a u32")
            .to_string();
        assert!(
            error.contains("3.8") && !error.contains("postgres"),
            "the loader quotes the offending value and not the rest of the \
             file: {error}"
        );
    }

    #[test]
    fn a_wildcard_bind_is_not_advertised_as_a_dashboard_url() {
        use super::dashboard_authority;

        // A wildcard bind is not openable: http://0.0.0.0:8444/ resolves to the
        // client, so printing it breaks the one-click login for exactly the
        // deployment that chose to listen broadly.
        assert_eq!(
            dashboard_authority("0.0.0.0:8444".parse().unwrap()),
            "127.0.0.1:8444"
        );
        assert_eq!(
            dashboard_authority("[::]:8444".parse().unwrap()),
            "[::1]:8444"
        );
        // A concrete bind is printed exactly as it is.
        assert_eq!(
            dashboard_authority("127.0.0.1:8444".parse().unwrap()),
            "127.0.0.1:8444"
        );
        assert_eq!(
            dashboard_authority("192.168.1.5:8444".parse().unwrap()),
            "192.168.1.5:8444"
        );
    }

    #[test]
    fn a_login_url_token_survives_reserved_characters() {
        // A generated token is hex and unchanged by encoding...
        assert_eq!(percent_encode_query_value("a0f9"), "a0f9");
        // ...but an operator-written one is arbitrary, and `&`/`#` would
        // otherwise end the query parameter and truncate what `/login` sees.
        assert_eq!(
            percent_encode_query_value("a&b#c d"),
            "a%26b%23c%20d",
            "reserved characters must not end the token parameter"
        );
    }

    use super::*;

    /// #98: an unpinned gateway must hand the endpoint a *session*-derived salt,
    /// since that is the only variant that matches what `honmoon hook` derives.
    /// The transport tests are given the variant, so this is the only check that
    /// the gateway picks it.
    #[test]
    fn an_unpinned_context_selects_the_per_session_salt() {
        let wire_salt = b"wire-salt-from-the-pinned-context".to_vec();
        let machine_key = b"machine-key".to_vec();

        assert!(
            matches!(
                hook_salt_for(None, wire_salt.clone(), machine_key.clone()),
                HookSalt::PerSession(_)
            ),
            "unpinned must follow the payload's session, not the gateway's context"
        );
        assert!(
            matches!(
                hook_salt_for(Some("pinned"), wire_salt, machine_key),
                HookSalt::Fixed(_)
            ),
            "a pinned context must share wire redaction's one salt"
        );
    }

    /// The macOS Seatbelt hole is `localhost:<port>`, which covers `::1` as well
    /// as `127.0.0.1`. Owning the port on both families is what makes that hole
    /// point at honmoon and nothing else, so it is a security property rather
    /// than a tidiness one.
    #[test]
    fn the_proxy_port_is_owned_on_both_loopback_families() {
        let (v4, v6) = bind_loopback_pair().expect("bind the proxy's loopback pair");
        let port = v4.local_addr().expect("v4 address").port();

        let Some(v6) = v6 else {
            // No IPv6 loopback on this host, so there is no second half of the
            // hole for anyone to occupy either.
            return;
        };
        assert_eq!(
            v6.local_addr().expect("v6 address").port(),
            port,
            "the two listeners must share one port — the profile opens a single \
             port number, not two"
        );
        assert!(
            TcpListener::bind((Ipv6Addr::LOCALHOST, port)).is_err(),
            "::1:{port} was still bindable, so an unrelated process could sit \
             inside the profile's one exception and take traffic the child \
             believes is going to the proxy"
        );
    }
}
