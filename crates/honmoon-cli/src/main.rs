//! `honmoon` — policy-based firewall gateway CLI.

mod hook;
mod isolate;

use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use honmoon_core::{AuditLog, Policy};
use honmoon_mgmt::AppState;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{
    DEFAULT_PAUSE_TIMEOUT, GatewayState, InterceptPolicy, PiiMode, RedactionState,
};

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
        /// Address the management API + dashboard listens on.
        #[arg(long, default_value = "127.0.0.1:8444", value_name = "HOST:PORT")]
        mgmt_addr: String,
        /// Append every verdict to this JSONL audit log (default: in-memory only).
        #[arg(long, value_name = "FILE")]
        audit_log: Option<PathBuf>,
        /// Bearer token required by `POST /api/hooks/claude-code`.
        /// May also be supplied through `HONMOON_HOOK_TOKEN`.
        #[arg(long, value_name = "TOKEN", env = "HONMOON_HOOK_TOKEN")]
        hook_token: Option<String>,
        /// Stable salt context shared by gateway hook redaction and CLI hooks.
        /// Domain-separation input only: placeholder unforgeability and per-machine
        /// uniqueness come from the random `~/.honmoon/hook-salt` secret, which
        /// keys the HMAC this value is mixed into — so the default is safe. Override
        /// it only to separate instances that deliberately share one machine salt.
        /// May also be supplied through `HONMOON_HOOK_SALT_CONTEXT`.
        #[arg(
            long,
            value_name = "CONTEXT",
            env = "HONMOON_HOOK_SALT_CONTEXT",
            default_value = "default"
        )]
        hook_salt_context: String,
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
        /// How detected PII policy verdicts are handled: detect audits the
        /// would-be verdict; block enforces allow/deny/pause inline.
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
    },
    /// Internal: the in-namespace half of enforced `run` isolation (ADR-0005).
    ///
    /// Hidden because it is not a user-facing command — `run` re-execs the
    /// binary into it after entering the namespace, since a `pre_exec` hook can
    /// only be followed by an `exec`.
    #[cfg(target_os = "linux")]
    #[command(name = isolate::linux::SUPERVISE_SUBCOMMAND, hide = true)]
    SuperviseSandbox {
        /// Host-side Unix socket that bridges to the egress proxy.
        #[arg(long, value_name = "PATH")]
        bridge_socket: PathBuf,
        /// Command to execute (after `--`).
        #[arg(last = true)]
        argv: Vec<String>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { policy, argv } => run(policy, argv),
        Command::Gateway {
            config,
            addr,
            mgmt_addr,
            audit_log,
            hook_token,
            hook_salt_context,
            tls_intercept,
            redact_secrets,
            pii_mode,
            ca_cert,
            ca_key,
        } => gateway(GatewayArgs {
            config,
            addr,
            mgmt_addr,
            audit_log,
            hook_token,
            hook_salt_context,
            tls_intercept,
            redact_secrets,
            pii_mode,
            ca_cert,
            ca_key,
        }),
        Command::Join { gateway } => {
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
        Command::Hook { salt_context } => hook::run(salt_context.as_deref()),
        #[cfg(target_os = "linux")]
        Command::SuperviseSandbox {
            bridge_socket,
            argv,
        } => {
            let status = isolate::linux::supervise(&bridge_socket, &argv)
                .context("supervising the sandboxed command")?;
            std::process::exit(status.code().unwrap_or(1));
        }
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

/// Parsed `honmoon gateway` arguments.
struct GatewayArgs {
    config: PathBuf,
    addr: String,
    mgmt_addr: String,
    audit_log: Option<PathBuf>,
    hook_token: Option<String>,
    hook_salt_context: String,
    tls_intercept: bool,
    redact_secrets: bool,
    pii_mode: PiiModeArg,
    ca_cert: Option<PathBuf>,
    ca_key: Option<PathBuf>,
}

/// Default directory for persisted CA material (`$HOME/.honmoon`, else `.honmoon`).
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
        mgmt_addr,
        audit_log,
        hook_token,
        hook_salt_context,
        tls_intercept,
        redact_secrets,
        pii_mode,
        ca_cert,
        ca_key,
    } = args;

    if !tls_intercept && matches!(pii_mode, PiiModeArg::Block) {
        anyhow::bail!("--pii-mode block requires --tls-intercept");
    }

    let policy_yaml = std::fs::read_to_string(&config)
        .with_context(|| format!("reading policy {}", config.display()))?;
    let policy = Policy::from_yaml(&policy_yaml)?;
    tracing::info!(rules = policy.rules.len(), %addr, %mgmt_addr, "starting gateway");

    let audit = match &audit_log {
        Some(path) => Arc::new(
            AuditLog::with_file(1024, path)
                .with_context(|| format!("opening audit log {}", path.display()))?,
        ),
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

    let salt = hook::derive_salt_context(&hook_salt_context);
    let redaction = redact_secrets.then(|| RedactionState::new(salt.clone()));
    let state = GatewayState {
        policy: Arc::new(policy),
        audit,
        approvals: Arc::new(honmoon_proxy::approval::ApprovalRegistry::new()),
        pause_timeout: DEFAULT_PAUSE_TIMEOUT,
        ca: Arc::new(ca),
        intercept,
        pii_mode: pii_mode.into(),
        redaction,
    };

    // Bind both listeners up front so a bind error is reported before we spawn.
    let proxy_listener =
        TcpListener::bind(&addr).with_context(|| format!("binding proxy {addr}"))?;
    let mgmt_listener = TcpListener::bind(&mgmt_addr)
        .with_context(|| format!("binding management API {mgmt_addr}"))?;

    let app_state = AppState::with_hook_config(state.clone(), policy_yaml, salt, hook_token);

    let runtime = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    runtime.block_on(async move {
        // Run both servers and surface unexpected proxy termination — otherwise
        // the process would keep serving the management API while egress
        // filtering is silently down.
        let proxy_task =
            tokio::spawn(async move { honmoon_proxy::gateway::serve(state, proxy_listener).await });
        tokio::select! {
            mgmt = honmoon_mgmt::serve(app_state, mgmt_listener) => {
                mgmt.context("management API server failed")
            }
            proxy = proxy_task => {
                anyhow::bail!("proxy server task exited unexpectedly: {proxy:?}")
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
    let (v4, v6) = bind_loopback_pair().context("binding egress proxy")?;
    let addr = v4.local_addr()?;
    {
        // One `GatewayState` behind both listeners rather than one each: it is
        // `Arc`s throughout, and splitting it would split the audit ring and the
        // approval registry with it, so a verdict's visibility would depend on
        // which loopback family the client happened to use.
        let state = GatewayState::new(policy.clone());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("build tokio runtime");
            runtime.block_on(async move {
                // `select!` rather than `tokio::spawn` for the IPv6 half, and
                // the reason is the whole point of binding it. `serve` ends
                // only by panicking, and a panic inside a spawned task is
                // caught by tokio and parked in a `JoinHandle` nobody joins —
                // so the IPv6 accept loop could die, drop its listener, and
                // hand `::1:<port>` back to the first process that asked for
                // it, while `run` carried on serving IPv4 and still reported
                // `Enforced`. That is the reopened hole, arrived at silently.
                //
                // Polled in one task, either loop failing takes the proxy down
                // with it: the child is then pointed at a dead port and fails
                // closed, which is the honest outcome. It does not leave a live
                // child talking to a boundary with half of it missing.
                match v6 {
                    Some(v6) => {
                        tokio::select! {
                            _ = honmoon_proxy::gateway::serve(state.clone(), v6) => {}
                            _ = honmoon_proxy::gateway::serve(state, v4) => {}
                        }
                    }
                    None => honmoon_proxy::gateway::serve(state, v4).await,
                }
            });
        });
    }

    let proxy_url = format!("http://{addr}");
    tracing::info!(%proxy_url, "egress proxy ready");

    // Only Linux and macOS can actually hold the child; `mut` carries a
    // downgrade if that path turns out to be unusable at spawn time.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(unused_mut))]
    let mut isolation = isolate::Isolation::probe();

    // Enforced: the child is left with no network route that avoids the proxy —
    // an empty namespace on Linux, a Seatbelt profile on macOS. It never returns
    // on success: the sandboxed command's exit code is this process's exit code.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if isolation == isolate::Isolation::Enforced {
        match isolate::run_confined(addr, program, args) {
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
    for (key, value) in isolate::proxy_env(&proxy_url) {
        command.env(key, value);
    }
    let status = command
        .status()
        .with_context(|| format!("failed to spawn `{program}`"))?;

    std::process::exit(status.code().unwrap_or(1));
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

fn load_policy(path: &PathBuf) -> Result<Policy> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    Ok(Policy::from_yaml(&src)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
