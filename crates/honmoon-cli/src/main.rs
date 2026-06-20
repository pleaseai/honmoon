//! `honmoon` — policy-based firewall gateway CLI.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use honmoon_core::Policy;

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
    /// Run the central gateway proxy.
    Gateway {
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8443", value_name = "HOST:PORT")]
        addr: String,
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
        Command::Gateway { config, addr } => {
            let policy = load_policy(&config)?;
            tracing::info!(rules = policy.rules.len(), %addr, "starting gateway");
            honmoon_proxy::gateway::run(policy, &addr)
        }
        Command::Join { gateway } => {
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
    }
}

/// `honmoon run` — start an ephemeral egress proxy, then exec the child with
/// its proxy env pointed at us. The child's exit code is propagated.
fn run(policy: PathBuf, argv: Vec<String>) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("no command given; usage: honmoon run --policy P -- <cmd> [args]")?;

    let policy = load_policy(&policy)?;
    let addr = format!("127.0.0.1:{}", free_port()?);

    {
        let policy = policy.clone();
        let addr = addr.clone();
        std::thread::spawn(move || honmoon_proxy::gateway::run(policy, &addr));
    }
    wait_until_listening(&addr)?;

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

/// Ask the OS for an unused TCP port on loopback.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("allocating a free port")?;
    Ok(listener.local_addr()?.port())
}

/// Block until `addr` accepts connections, or time out.
fn wait_until_listening(addr: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    anyhow::bail!("egress proxy did not start listening on {addr}");
}
