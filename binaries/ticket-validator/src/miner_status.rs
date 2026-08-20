//! `read-miner-status` subcommand — §23 trustless-scheduling input.
//!
//! vali's scheduler (PR-G4) never trusts a miner's self-reported
//! capacity/health (§23: "a hostile miner's self-reported
//! capacity/health is adversarial"). This subcommand performs the
//! *authoritative* read of the on-chain `pallet-compute-scoring`
//! state and emits it as JSON for the Django scheduler.
//!
//! The storage-key derivation + SCALE decode + JSON-RPC client live in
//! the shared [`hippius_onchain_registry`] crate — the SAME reader the
//! Edge gateway's permissionless miner-auth poller uses, so the wire
//! layout has exactly one definition and cannot drift between the two
//! consumers. This module is a thin adapter: it calls
//! [`hippius_onchain_registry::fetch_registry`] and renders the result
//! in the JSON contract the Django side already parses.
//!
//! ## Wire contract
//!
//! - stdin: ignored.
//! - the RPC endpoint is read from the `THEBRAIN_RPC_URL` env var —
//!   NOT argv. The URL may embed a credential; keeping it out of argv
//!   keeps it out of `ps` / process listings (§20).
//! - stdout: a single JSON object —
//!   `{"tag":"ok","current_epoch":N,"miners":[...]}` on success, or
//!   `{"tag":"err","error":"...","category":"..."}` on a structured
//!   read failure.
//! - exit: `0` ok, `2` structured read failure, `1` stdout-write
//!   failure. vali maps **any** non-zero exit to a fail-closed HTTP
//!   503 — a scheduler that cannot read the chain MUST NOT place.

use std::io;
use std::process::ExitCode;

use hippius_onchain_registry::{fetch_registry, RegistrySnapshot};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

#[derive(clap::Args)]
pub struct ReadMinerStatusArgs {
    /// thebrain Substrate JSON-RPC endpoint (e.g.
    /// `http://thebrain-rpc.internal:9933`). Sourced from the
    /// `THEBRAIN_RPC_URL` env var — never passed on argv, so a
    /// credentialed URL stays out of `ps` output.
    #[arg(long, env = "THEBRAIN_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// Pallet name as wired into thebrain's `construct_runtime!`.
    /// Drives the twox-128 storage-prefix derivation; if thebrain
    /// names the pallet differently the read returns zero miners
    /// (vali then fails closed — no false placements).
    #[arg(long, default_value = "ComputeScoring")]
    pallet_name: String,
}

/// stdout JSON envelope. `tag` discriminates so a future categorical
/// result can extend the schema without breaking the Django side.
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum MinerStatusOutput {
    Ok {
        current_epoch: u64,
        /// Is the configured pallet STILL wired into the runtime
        /// (present in `state_getMetadata`)? `false` ⇒ the pallet was
        /// removed by a runtime upgrade but its storage prefix survived,
        /// so every field in this payload is the pallet's last-written
        /// bytes and can never change again. `true` also covers "could
        /// not determine" (the metadata probe failed) — it is never an
        /// alarm raised by an RPC blip.
        pallet_live: bool,
        miners: Vec<MinerJson>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

/// One miner row. `quality_dec` is a decimal **string** because the
/// §23 weight is a `u128` — outside the safe-integer range of a JSON
/// number; the Django side rehydrates via `int(quality_dec)`.
#[derive(Serialize)]
struct MinerJson {
    node_id_hex: String,
    /// `active` | `quarantined` | `decommissioned`.
    status: &'static str,
    /// Epoch of the last on-chain `MinerStatus` transition.
    last_transition_epoch: u64,
    /// Epoch the miner's score/quality genuinely reflects:
    /// `current_epoch` if the validator scored it this epoch
    /// (`EpochWeights` entry present), else `last_transition_epoch`.
    /// vali's stale-epoch gate keys off `current_epoch - data_epoch`.
    data_epoch: u64,
    /// §23 reward weight (the v1 "quality" signal), decimal `u128`.
    quality_dec: String,
    /// The miner's announced price (`MinerPrice[node_id]`, USD per
    /// resource-unit ×1e6), decimal `u128` string. Omitted (`null`) when
    /// the miner has not set a price — the scheduler's price term is then
    /// inert for it. The Django side rehydrates via `int(price_dec)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    price_dec: Option<String>,
}

/// Render a chain snapshot into the JSON rows the Django scheduler
/// reads. The shared reader already returns a deterministically
/// sorted miner list.
fn to_output(snapshot: RegistrySnapshot) -> MinerStatusOutput {
    let miners = snapshot
        .miners
        .into_iter()
        .map(|m| MinerJson {
            node_id_hex: hex::encode(m.node_id),
            status: m.status.label(),
            last_transition_epoch: m.last_transition_epoch,
            data_epoch: m.data_epoch,
            quality_dec: m.quality.to_string(),
            price_dec: m.price.map(|p| p.to_string()),
        })
        .collect();
    MinerStatusOutput::Ok {
        current_epoch: snapshot.current_epoch,
        pallet_live: snapshot.pallet_live,
        miners,
    }
}

/// Entry point for `hippius-ticket-validator read-miner-status`.
pub fn run(args: ReadMinerStatusArgs) -> ExitCode {
    let output = match fetch_registry(&args.rpc_url, &args.pallet_name) {
        Ok(snapshot) => to_output(snapshot),
        Err(e) => MinerStatusOutput::Err {
            error: e.message,
            category: e.category,
        },
    };
    let exit = match &output {
        MinerStatusOutput::Ok { .. } => EXIT_OK,
        MinerStatusOutput::Err { .. } => EXIT_STRUCTURED,
    };
    match serde_json::to_writer(io::stdout().lock(), &output) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_onchain_registry::{MinerRecord, MinerStatus};

    #[test]
    fn to_output_renders_the_json_contract() {
        let snapshot = RegistrySnapshot {
            current_epoch: 7,
            pallet_live: true,
            miners: vec![MinerRecord {
                node_id: [0xabu8; 32],
                status: MinerStatus::Quarantined,
                last_transition_epoch: 3,
                data_epoch: 3,
                quality: 340_282_366_920_938_463_463_374_607_431_768_211_455,
                price: Some(1_500_000),
            }],
        };
        let json = serde_json::to_value(to_output(snapshot)).unwrap();
        assert_eq!(json["tag"], "ok");
        assert_eq!(json["miners"][0]["price_dec"], "1500000");
        assert_eq!(json["current_epoch"], 7);
        // The removed-pallet signal is part of the `ok` contract — vali
        // reads it to tell a live chain from an orphaned storage prefix.
        assert_eq!(json["pallet_live"], true);
        let m = &json["miners"][0];
        assert_eq!(m["node_id_hex"], hex::encode([0xabu8; 32]));
        assert_eq!(m["status"], "quarantined");
        assert_eq!(m["last_transition_epoch"], 3);
        assert_eq!(m["data_epoch"], 3);
        // u128 max survives as a decimal string (not a JSON number).
        assert_eq!(m["quality_dec"], "340282366920938463463374607431768211455");
    }

    #[test]
    fn to_output_carries_a_dead_pallet_through_to_the_json() {
        // The fossil case: the pallet was removed from the runtime but
        // its storage prefix still answers, so the epoch + miners look
        // perfectly healthy. `pallet_live: false` is the ONLY thing in
        // the payload that says so — it must be carried, not defaulted.
        let snapshot = RegistrySnapshot {
            current_epoch: 2702,
            pallet_live: false,
            miners: vec![],
        };
        let json = serde_json::to_value(to_output(snapshot)).unwrap();
        assert_eq!(json["tag"], "ok");
        assert_eq!(json["current_epoch"], 2702);
        assert_eq!(json["pallet_live"], false);
    }
}
