//! `honmoon` — policy-based firewall gateway CLI.

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use honmoon_core::{AuditLog, Policy};
use honmoon_mgmt::AppState;
use honmoon_proxy::gateway::{DEFAULT_PAUSE_TIMEOUT, GatewayState};

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
    },
    /// Join a gateway and route host traffic through it.
    Join {
        #[arg(long, value_name = "HOST:PORT")]
        gateway: String,
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
        } => gateway(config, addr, mgmt_addr, audit_log),
        Command::Join { gateway } => {
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
    }
}

/// `honmoon gateway` — run the egress proxy and the management API (audit query,
/// approval queue, embedded dashboard) together, sharing one runtime and one set
/// of audit/approval state so held requests can be approved from the dashboard.
fn gateway(
    config: PathBuf,
    addr: String,
    mgmt_addr: String,
    audit_log: Option<PathBuf>,
) -> Result<()> {
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

    let state = GatewayState {
        policy: Arc::new(policy),
        audit,
        approvals: Arc::new(honmoon_proxy::approval::ApprovalRegistry::new()),
        pause_timeout: DEFAULT_PAUSE_TIMEOUT,
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
