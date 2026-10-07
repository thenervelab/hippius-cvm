//! `hippius-cdn-agent` service entrypoint.
//!
//! - `run` (default): the agent. Exits non-zero on any start-up failure
//!   (fail closed; systemd restarts it), returns normally on SIGTERM so
//!   every key's destructor runs.
//! - `check-config`: validate the config + identity file and exit.
//! - `cache-size`: print `proxy_cache_path max_size` (`<n>k`) for the
//!   cache volume, for OpenResty's `ExecStartPre`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hippius_cdn_agent::config::{Config, DEFAULT_CONFIG_PATH};
use hippius_cdn_agent::error::Result;
use hippius_cdn_agent::{agent, cache_max_size, shutdown};

#[derive(Parser)]
#[command(name = "hippius-cdn-agent", version)]
struct Cli {
    /// Agent config (baked into the measured image).
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Run,
    CheckConfig,
    CacheSize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hippius-cdn-agent: fail-closed: {}", e.class());
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            // Latch signals before any key is loaded.
            let stop = shutdown::install()?;
            let cfg = Config::load(&cli.config)?;
            agent::run(cfg, stop)?;
            eprintln!("hippius-cdn-agent: shutdown, keys zeroized");
            Ok(())
        }
        Command::CheckConfig => {
            let cfg = Config::load(&cli.config)?;
            println!(
                "ok: node {} region {} backend {}",
                cfg.node.vm_id,
                cfg.node.region,
                cfg.backend.url.as_str()
            );
            Ok(())
        }
        Command::CacheSize => {
            let cfg = Config::load(&cli.config)?;
            let bytes = cache_max_size(&cfg.paths.cache_dir, cfg.data_plane.cache_fill_percent)?;
            println!("{}k", bytes / 1024);
            Ok(())
        }
    }
}
