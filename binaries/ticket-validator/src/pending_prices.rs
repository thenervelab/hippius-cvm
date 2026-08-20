//! `read-pending-prices` subcommand — §23 marketplace price-watch input.
//!
//! The price-migration watcher (`vali_price_watch`) must move a tenant's
//! VM off a miner BEFORE an announced price hike takes effect. This
//! subcommand performs the authoritative read of the on-chain
//! `PendingPriceChange` map (announced-but-not-yet-effective miner price
//! changes) plus the chain head block, and emits it as JSON for the
//! Django watcher.
//!
//! The storage-key derivation + SCALE decode + JSON-RPC client live in
//! the shared [`hippius_onchain_registry`] crate — the SAME reader the
//! `read-miner-status` shell-out uses, so the wire layout has exactly
//! one definition. This module is a thin adapter: it calls
//! [`hippius_onchain_registry::fetch_pending_prices`] and renders the
//! result in the JSON contract the Django side already parses
//! (`apps.scheduler.chain.read_pending_price_changes`).
//!
//! ## Wire contract
//!
//! - stdin: ignored.
//! - the RPC endpoint is read from the `THEBRAIN_RPC_URL` env var — NOT
//!   argv. The URL may embed a credential; keeping it out of argv keeps
//!   it out of `ps` / process listings (§20).
//! - stdout: a single JSON object —
//!   `{"tag":"ok","current_block":N,"changes":[{"node_id_hex":"..",
//!   "new_price_dec":"..","effective_block":N}]}` on success, or
//!   `{"tag":"err","error":"...","category":"..."}` on a structured
//!   read failure. `new_price_dec` is a decimal STRING (u128, outside
//!   JSON's safe integer range).
//! - exit: `0` ok, `2` structured read failure, `1` stdout-write
//!   failure. vali maps any non-zero exit to a fail-closed skip — a
//!   watcher that cannot read the chain MUST NOT migrate.

use std::io;
use std::process::ExitCode;

use hippius_onchain_registry::{fetch_pending_prices, PendingPriceSnapshot};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

#[derive(clap::Args)]
pub struct ReadPendingPricesArgs {
    /// thebrain Substrate JSON-RPC endpoint (e.g.
    /// `http://thebrain-rpc.internal:9933`). Sourced from the
    /// `THEBRAIN_RPC_URL` env var — never passed on argv, so a
    /// credentialed URL stays out of `ps` output.
    #[arg(long, env = "THEBRAIN_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// Pallet name as wired into thebrain's `construct_runtime!`.
    /// Drives the twox-128 storage-prefix derivation; a wrong name
    /// reads zero changes (the watcher then no-ops — never mis-migrates).
    #[arg(long, default_value = "ComputeScoring")]
    pallet_name: String,
}

/// stdout JSON envelope. `tag` discriminates so a future categorical
/// result can extend the schema without breaking the Django side.
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum PendingPricesOutput {
    Ok {
        current_block: u64,
        changes: Vec<PriceChangeJson>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

/// One announced price change in the JSON contract.
#[derive(Serialize)]
struct PriceChangeJson {
    node_id_hex: String,
    /// u128 carried as a decimal STRING (outside JSON's safe int range).
    new_price_dec: String,
    effective_block: u64,
}

fn to_output(snapshot: PendingPriceSnapshot) -> PendingPricesOutput {
    let changes = snapshot
        .changes
        .into_iter()
        .map(|c| PriceChangeJson {
            node_id_hex: hex::encode(c.node_id),
            new_price_dec: c.new_price.to_string(),
            effective_block: c.effective_block,
        })
        .collect();
    PendingPricesOutput::Ok {
        current_block: snapshot.current_block,
        changes,
    }
}

pub fn run(args: ReadPendingPricesArgs) -> ExitCode {
    let output = match fetch_pending_prices(&args.rpc_url, &args.pallet_name) {
        Ok(snapshot) => to_output(snapshot),
        Err(e) => PendingPricesOutput::Err {
            error: e.message,
            category: e.category,
        },
    };
    let exit = match &output {
        PendingPricesOutput::Ok { .. } => EXIT_OK,
        PendingPricesOutput::Err { .. } => EXIT_STRUCTURED,
    };
    match serde_json::to_writer(io::stdout().lock(), &output) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}
