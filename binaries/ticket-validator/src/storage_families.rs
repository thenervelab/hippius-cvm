//! `read-storage-families` subcommand — every compute family and the Arion
//! storage children it lists.
//!
//! vali's storage requirement (a compute family must also run a healthy
//! Arion storage node) needs, per compute family, the Arion children of the
//! same family and what the chain says about each: its registration, the
//! validator-reported node weight, the bucket it was last reported in, and
//! its `NodeQuality`. All of it is read at one finalized block by the shared
//! [`hippius_onchain_registry`] crate; what counts as healthy is vali's to
//! decide (`apps.scheduler.storage_requirement`).
//!
//! ## Wire contract
//!
//! - stdin: ignored.
//! - the RPC endpoint is read from the `THEBRAIN_RPC_URL` env var — NOT
//!   argv (it may embed a credential).
//! - stdout: one JSON object —
//!   `{"tag":"ok","block_hash":"0x…","current_weight_bucket":N,
//!     "stale_child_buckets":N,"families":[{"family_hex":"…",
//!     "compute":[{"node_id_hex":"…","child_hex":"…"}],
//!     "storage":[{"child_hex":"…","registration":{"family_hex":"…",
//!       "node_id_hex":"…","status":"active"|"unbonding"}|null,
//!       "node_weight":N,"last_bucket":N,"quality":{"shard_data_bytes_dec":"…",
//!       "bandwidth_bytes_dec":"…","uptime_permille":N,"strikes":N,
//!       "integrity_fails":N}|null}]}]}`
//!   (u128 byte counts as decimal STRINGS, outside JSON's safe integers), or
//!   `{"tag":"err","error":"…","category":"…"}` on a read failure.
//! - exit: `0` ok, `2` structured read failure, `1` stdout-write failure.
//!   vali keeps its last decision on any non-zero exit.

use std::io;
use std::process::ExitCode;

use hippius_onchain_registry::{fetch_storage_families, StorageFamiliesRead};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

#[derive(clap::Args)]
pub struct ReadStorageFamiliesArgs {
    /// thebrain Substrate JSON-RPC endpoint, from the `THEBRAIN_RPC_URL`
    /// env var — never passed on argv.
    #[arg(long, env = "THEBRAIN_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// The compute pallet as wired into thebrain's `construct_runtime!`.
    #[arg(long, default_value = "ComputeScoring")]
    compute_pallet: String,
    /// The Arion storage pallet as wired into thebrain's `construct_runtime!`.
    #[arg(long, default_value = "Arion")]
    arion_pallet: String,
}

#[derive(Serialize)]
struct ComputeJson {
    node_id_hex: String,
    child_hex: String,
}

#[derive(Serialize)]
struct RegistrationJson {
    family_hex: String,
    node_id_hex: String,
    status: &'static str,
}

#[derive(Serialize)]
struct QualityJson {
    shard_data_bytes_dec: String,
    bandwidth_bytes_dec: String,
    uptime_permille: u16,
    strikes: u32,
    integrity_fails: u32,
}

#[derive(Serialize)]
struct StorageJson {
    child_hex: String,
    registration: Option<RegistrationJson>,
    node_weight: u16,
    last_bucket: u32,
    quality: Option<QualityJson>,
}

#[derive(Serialize)]
struct FamilyJson {
    family_hex: String,
    compute: Vec<ComputeJson>,
    storage: Vec<StorageJson>,
}

#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum Output {
    Ok {
        block_hash: String,
        current_weight_bucket: u32,
        stale_child_buckets: u32,
        families: Vec<FamilyJson>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

fn to_output(read: StorageFamiliesRead) -> Output {
    let families = read
        .families
        .into_iter()
        .map(|f| FamilyJson {
            family_hex: hex::encode(f.family),
            compute: f
                .compute
                .into_iter()
                .map(|c| ComputeJson {
                    node_id_hex: hex::encode(c.node_id),
                    child_hex: hex::encode(c.child),
                })
                .collect(),
            storage: f
                .storage
                .into_iter()
                .map(|s| StorageJson {
                    child_hex: hex::encode(s.child),
                    registration: s.registration.map(|r| RegistrationJson {
                        family_hex: hex::encode(r.family),
                        node_id_hex: hex::encode(r.node_id),
                        status: r.status.label(),
                    }),
                    node_weight: s.node_weight,
                    last_bucket: s.last_bucket,
                    quality: s.quality.map(|q| QualityJson {
                        shard_data_bytes_dec: q.shard_data_bytes.to_string(),
                        bandwidth_bytes_dec: q.bandwidth_bytes.to_string(),
                        uptime_permille: q.uptime_permille,
                        strikes: q.strikes,
                        integrity_fails: q.integrity_fails,
                    }),
                })
                .collect(),
        })
        .collect();
    Output::Ok {
        block_hash: read.block_hash,
        current_weight_bucket: read.current_weight_bucket,
        stale_child_buckets: read.stale_child_buckets,
        families,
    }
}

/// Entry point for `hippius-ticket-validator read-storage-families`.
pub fn run(args: ReadStorageFamiliesArgs) -> ExitCode {
    let output =
        match fetch_storage_families(&args.rpc_url, &args.compute_pallet, &args.arion_pallet) {
            Ok(read) => to_output(read),
            Err(e) => Output::Err {
                error: e.message,
                category: e.category,
            },
        };
    let exit = match &output {
        Output::Ok { .. } => EXIT_OK,
        Output::Err { .. } => EXIT_STRUCTURED,
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
    use hippius_onchain_registry::{
        ChildRegistrationHead, ChildStatus, ComputeNodeRead, FamilyStorageRead, NodeQualityRead,
        StorageChildRead,
    };

    #[test]
    fn renders_the_wire_contract() {
        let read = StorageFamiliesRead {
            block_hash: "0xab".to_string(),
            current_weight_bucket: 42,
            stale_child_buckets: 4,
            families: vec![FamilyStorageRead {
                family: [0xa1; 32],
                compute: vec![ComputeNodeRead {
                    node_id: [0x01; 32],
                    child: [0xc1; 32],
                }],
                storage: vec![
                    StorageChildRead {
                        child: [0xd1; 32],
                        registration: Some(ChildRegistrationHead {
                            family: [0xa1; 32],
                            node_id: [0xe1; 32],
                            status: ChildStatus::Unbonding,
                        }),
                        node_weight: 900,
                        last_bucket: 40,
                        quality: Some(NodeQualityRead {
                            shard_data_bytes: u128::MAX,
                            bandwidth_bytes: 7,
                            uptime_permille: 990,
                            strikes: 1,
                            integrity_fails: 2,
                        }),
                    },
                    StorageChildRead {
                        child: [0xd2; 32],
                        registration: None,
                        node_weight: 0,
                        last_bucket: 0,
                        quality: None,
                    },
                ],
            }],
        };
        let json = serde_json::to_value(to_output(read)).unwrap();
        assert_eq!(json["tag"], "ok");
        assert_eq!(json["current_weight_bucket"], 42);
        assert_eq!(json["stale_child_buckets"], 4);
        let f = &json["families"][0];
        assert_eq!(f["family_hex"], "a1".repeat(32));
        assert_eq!(f["compute"][0]["node_id_hex"], "01".repeat(32));
        assert_eq!(f["compute"][0]["child_hex"], "c1".repeat(32));
        let s = &f["storage"][0];
        assert_eq!(s["registration"]["status"], "unbonding");
        assert_eq!(s["registration"]["node_id_hex"], "e1".repeat(32));
        assert_eq!(s["node_weight"], 900);
        assert_eq!(s["last_bucket"], 40);
        assert_eq!(s["quality"]["shard_data_bytes_dec"], u128::MAX.to_string());
        assert_eq!(s["quality"]["uptime_permille"], 990);
        assert!(f["storage"][1]["registration"].is_null());
        assert!(f["storage"][1]["quality"].is_null());
    }
}
