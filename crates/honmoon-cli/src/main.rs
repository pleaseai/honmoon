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

    let policy_yaml = std::fs::read_to_string(&config)
        .with_context(|| format!("reading policy {}", config.display()))?;
    let policy = Policy::from_yaml(&policy_yaml)?;
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

    let policy = load_policy(&policy)?;

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

fn load_policy(path: &Path) -> Result<Policy> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    Ok(Policy::from_yaml(&src)?)
}

/// A top-level shape a policy can never have, named without quoting what it
/// held.
///
/// `None` means "hand it to the loader", and covers three cases: a mapping (an
/// ordinary policy), a null document (an empty file, which *is* a valid policy
/// — every field at its default), and text YAML itself cannot parse, where
/// serde's own syntax diagnostic is the useful one and quotes only the token it
/// stopped on, with a line and column.
///
/// The remaining shapes are why this exists. serde renders a top-level type
/// mismatch as `invalid type: string "<value>"`, and when the top level is a
/// plain scalar that value is **the whole file**. `policy validate` is
/// documented for CI, where the path it is given comes from the repository
/// under test — so a mistyped path, or a branch that replaces `policy.yaml`
/// with a symlink to `~/.honmoon/mgmt-token`, an SSH key or a `.env`, would put
/// that file in the log. Classifying the shape first says what is wrong without
/// reading the contents out.
///
/// No verdict moves: every shape named here fails [`Policy::from_yaml`] as
/// well, so the two paths refuse the same files and only the message differs.
/// That is a claim about this function, so it is checked rather than asserted —
/// `a_file_that_is_not_a_policy_is_named_rather_than_quoted` runs the gateway
/// over the same file, and it caught this over-refusing a tagged mapping once
/// already.
///
/// It is a bound, not a blanket. A *mapping* carrying a long string still
/// reaches serde's quoting (`version: "<…>"`) — but that is a file shaped like
/// a policy, and the value quoted is the author's own field, which is the
/// diagnosis they need.
fn not_a_policy_document(src: &str) -> Option<&'static str> {
    match serde_yaml::from_str::<serde_yaml::Value>(src) {
        Ok(value) => shape_unfit_for_a_policy(&value),
        // Not a YAML document at all. serde's own syntax diagnostic is the
        // useful one here — it carries a line and column and quotes only the
        // token it stopped on — so this defers to the loader rather than
        // replacing it.
        Err(_) => None,
    }
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

/// `honmoon policy validate` — load a policy the way the gateway does, say what
/// the loader found, and exit.
///
/// The body is deliberately thin, and shaped like `gateway`'s own first steps:
/// read the file, then [`Policy::from_yaml`]. Everything that decides whether a
/// policy is acceptable lives in that one call — the same one `gateway` and
/// `honmoon run` reach — so there is no second implementation here to drift
/// from the one that matters. The loader's error travels up unwrapped for the
/// same reason: `main`'s `Result` prints it, so a rejected policy reads the way
/// the gateway would have reported it.
///
/// The one thing this path says in its own words is
/// [`not_a_policy_document`], which refuses a file the loader would refuse
/// anyway, before serde can quote it into a CI log.
///
/// What this function *adds* is everything the gateway does around that load and
/// this one must not: no management token is resolved (the side effect #198 is
/// about), no audit log is opened, no CA is read or generated, no listener is
/// bound. Not suppressing those — never reaching them.
fn policy_validate(path: &Path) -> Result<()> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;

    if let Some(shape) = not_a_policy_document(&src) {
        anyhow::bail!(
            "{} is not a policy document: its top level is {shape}, not a mapping of \
             policy fields. Contents withheld — check the path.",
            path.display()
        );
    }

    let policy = Policy::from_yaml(&src)?;

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
