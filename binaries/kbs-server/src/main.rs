//! `hippius-kbs-server` — Tier-0 KBS production binary entrypoint (§D).
//!
//! ```text
//! hippius-kbs-server --config <path.toml>
//! ```
//!
//! `VAULT_TOKEN` (environment) carries the static MVP Vault token. See
//! `README.md` for the config schema, operator bootstrap, and the
//! transitional-MVP boundaries.
//!
//! Fail-closed: any startup fault — bad arguments, unreadable or invalid
//! config, missing `VAULT_TOKEN`, a wiring error — aborts with a
//! non-zero exit code so the orchestrator restarts the pod rather than
//! running a half-wired KBS.

// Match the lib crate's test-lint posture: `unwrap`/`expect`/`panic` are
// fine inside `#[cfg(test)]` (they surface a failing assertion clearly).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use hippius_kbs_server::config::Config;
use hippius_kbs_server::error::Error;
use hippius_kbs_server::server;
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kbs-server: FATAL: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), Error> {
    let config_path = parse_args()?;
    let cfg = Config::load(&config_path)?;
    // RA-KBS-L3 — in broker mode the static `VAULT_TOKEN` is NEVER used
    // for reads (each release mints a per-VM broker capability token; see
    // `vault_mvp.rs` `prefer_capability_token`), so it is OPTIONAL there:
    // leaving it unset removes the resident Vault credential from the
    // attested KBS pod entirely. Outside broker mode it stays REQUIRED
    // (it IS the read credential) — fail closed.
    let broker_wired = cfg
        .vault
        .broker_url
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    let vault_token = resolve_vault_token(std::env::var("VAULT_TOKEN"), broker_wired)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| Error::Serve(format!("tokio runtime: {e}")))?;
    runtime.block_on(server::run(cfg, vault_token))
}

/// Parse the command line. `--config <path>` is the single required
/// argument; `--help` prints usage and exits 0.
fn parse_args() -> Result<PathBuf, Error> {
    let mut args = std::env::args().skip(1);
    let mut config: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| Error::Config("--config requires a path argument".into()))?;
                config = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                println!("usage: hippius-kbs-server --config <path.toml>");
                std::process::exit(0);
            }
            other => {
                return Err(Error::Config(format!("unexpected argument: {other}")));
            }
        }
    }
    config.ok_or_else(|| Error::Config("missing required --config <path.toml>".into()))
}

/// Resolve `VAULT_TOKEN` into a zeroizing buffer — never logged.
///
/// `broker_wired == false`: a non-empty token is REQUIRED (it is the KV
/// read credential); absent or empty ⇒ fail closed.
/// `broker_wired == true` (RA-KBS-L3): the static token is never used for
/// reads, so absent/empty is fine and yields an empty (unused) token —
/// so the operator can leave `VAULT_TOKEN` unset and keep NO resident
/// Vault credential in the attested KBS pod.
fn resolve_vault_token(
    env: std::result::Result<String, std::env::VarError>,
    broker_wired: bool,
) -> Result<Zeroizing<String>, Error> {
    match env {
        Ok(v) if !v.is_empty() => Ok(Zeroizing::new(v)),
        // Broker mode: absent OR set-but-empty ⇒ no resident credential.
        _ if broker_wired => Ok(Zeroizing::new(String::new())),
        Ok(_) => Err(Error::Config("VAULT_TOKEN is set but empty".into())),
        Err(_) => Err(Error::Config(
            "VAULT_TOKEN environment variable is required".into(),
        )),
    }
}

#[cfg(test)]
mod token_tests {
    use super::resolve_vault_token;
    use std::env::VarError;

    #[test]
    fn non_broker_requires_a_non_empty_token() {
        assert!(resolve_vault_token(Err(VarError::NotPresent), false).is_err());
        assert!(resolve_vault_token(Ok(String::new()), false).is_err());
        assert_eq!(
            &*resolve_vault_token(Ok("hvs.abc".into()), false).expect("resolve"),
            "hvs.abc"
        );
    }

    #[test]
    fn broker_mode_allows_an_absent_or_empty_token() {
        // RA-KBS-L3 — no resident credential required in broker mode.
        assert!(resolve_vault_token(Err(VarError::NotPresent), true)
            .expect("resolve")
            .is_empty());
        assert!(resolve_vault_token(Ok(String::new()), true)
            .expect("resolve")
            .is_empty());
        // A token that IS provided in broker mode is still honoured.
        assert_eq!(
            &*resolve_vault_token(Ok("hvs.xyz".into()), true).expect("resolve"),
            "hvs.xyz"
        );
    }
}
