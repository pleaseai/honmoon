//! `honmoon` — policy-based firewall gateway CLI.

mod hook;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use honmoon_core::{AuditLog, Policy};
use honmoon_mgmt::AppState;
use honmoon_proxy::ca::CaMaterial;
use honmoon_proxy::gateway::{DEFAULT_PAUSE_TIMEOUT, GatewayState, InterceptPolicy};

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
        /// Terminate TLS (MITM) to inspect request bodies for PII. Agents must
        /// trust the CA certificate. Detect-only: findings are audited, not blocked.
        #[arg(long)]
        tls_intercept: bool,
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
    Hook,
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
            tls_intercept,
            ca_cert,
            ca_key,
        } => gateway(GatewayArgs {
            config,
            addr,
            mgmt_addr,
            audit_log,
            tls_intercept,
            ca_cert,
            ca_key,
        }),
        Command::Join { gateway } => {
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
        Command::Hook => hook::run(),
    }
}

/// Parsed `honmoon gateway` arguments.
struct GatewayArgs {
    config: PathBuf,
    addr: String,
    mgmt_addr: String,
    audit_log: Option<PathBuf>,
    tls_intercept: bool,
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
        tls_intercept,
        ca_cert,
        ca_key,
    } = args;

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
            "TLS termination enabled (detect-only); agents must trust this CA certificate"
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

    let state = GatewayState {
        policy: Arc::new(policy),
        audit,
        approvals: Arc::new(honmoon_proxy::approval::ApprovalRegistry::new()),
        pause_timeout: DEFAULT_PAUSE_TIMEOUT,
        ca: Arc::new(ca),
        intercept,
    };

    // Bind both listeners up front so a bind error is reported before we spawn.
    let proxy_listener =
        TcpListener::bind(&addr).with_context(|| format!("binding proxy {addr}"))?;
    let mgmt_listener = TcpListener::bind(&mgmt_addr)
        .with_context(|| format!("binding management API {mgmt_addr}"))?;

    let app_state = AppState::new(state.clone(), policy_yaml);

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
    let listener = TcpListener::bind("127.0.0.1:0").context("binding egress proxy")?;
    let addr = listener.local_addr()?;
    {
        let policy = policy.clone();
        std::thread::spawn(move || honmoon_proxy::gateway::serve_listener(policy, listener));
    }

    let proxy_url = format!("http://{addr}");
    tracing::info!(%proxy_url, "egress proxy ready");

    let status = std::process::Command::new(program)
        .args(args)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .status()
        .with_context(|| format!("failed to spawn `{program}`"))?;

    std::process::exit(status.code().unwrap_or(1));
}

fn load_policy(path: &PathBuf) -> Result<Policy> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    Ok(Policy::from_yaml(&src)?)
}
