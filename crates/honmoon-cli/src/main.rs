//! `honmoon` — policy-based firewall gateway CLI.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use honmoon_core::Policy;

#[derive(Parser)]
#[command(name = "honmoon", version, about = "Policy-based firewall gateway for AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a single command in network isolation under a policy.
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
        Command::Run { policy, argv } => {
            let policy = load_policy(&policy)?;
            tracing::info!(rules = policy.rules.len(), "loaded policy");
            // TODO: spawn sandbox + proxy, then exec argv.
            anyhow::bail!("`run` not yet implemented (argv: {argv:?})");
        }
        Command::Gateway { config } => {
            let policy = load_policy(&config)?;
            tracing::info!(rules = policy.rules.len(), "loaded policy");
            // TODO: bind listener, serve management API + dashboard.
            anyhow::bail!("`gateway` not yet implemented");
        }
        Command::Join { gateway } => {
            // TODO: establish tunnel to gateway.
            anyhow::bail!("`join` not yet implemented (gateway: {gateway})");
        }
    }
}

fn load_policy(path: &PathBuf) -> Result<Policy> {
    let src = std::fs::read_to_string(path)?;
    Ok(Policy::from_yaml(&src)?)
}
