//! `read-node-family` subcommand — which family runs a compute node.
//!
//! vali's operator storage-config API (docs/design/disk-tier-verification.md
//! §9) is called by the upstream backend on behalf of a signed-in family.
//! Before it serves or changes anything for a node, vali re-checks on
//! chain that the node belongs to the family the caller names:
//! `NodeIdToChild[node_id]` → child, `ChildRegistrations[child]` →
//! `{family, node_id, status}`, both read at the finalized head. The
//! storage-key derivation + SCALE decode live in the shared
//! [`hippius_onchain_registry`] crate.
//!
//! ## Wire contract
//!
//! - stdin: ignored.
//! - the RPC endpoint is read from the `THEBRAIN_RPC_URL` env var — NOT
//!   argv (it may embed a credential).
//! - stdout: one JSON object —
//!   `{"tag":"ok","block_hash":"0x…","node_id_hex":"…","bound":true,
//!     "child_hex":"…","family_hex":"…","status":"active"|"unbonding"}`,
//!   `{"tag":"ok","block_hash":"0x…","node_id_hex":"…","bound":false,
//!     "reason":"no-child"|"no-registration"|"node-mismatch"}`, or
//!   `{"tag":"err","error":"…","category":"…"}` on a read failure.
//! - exit: `0` ok, `2` structured read failure (or a malformed
//!   `--node-id`), `1` stdout-write failure. vali fails closed (503) on
//!   any non-zero exit.

use std::io;
use std::process::ExitCode;

use hippius_onchain_registry::{category, fetch_node_family, NodeFamilyRead};
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

#[derive(clap::Args)]
pub struct ReadNodeFamilyArgs {
    /// thebrain Substrate JSON-RPC endpoint, from the `THEBRAIN_RPC_URL`
    /// env var — never passed on argv.
    #[arg(long, env = "THEBRAIN_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// Pallet name as wired into thebrain's `construct_runtime!`.
    #[arg(long, default_value = "ComputeScoring")]
    pallet_name: String,
    /// The compute node id: exactly 64 lower-case hex characters.
    #[arg(long)]
    node_id: String,
}

#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum NodeFamilyOutput {
    Ok {
        block_hash: String,
        node_id_hex: String,
        bound: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        child_hex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        family_hex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<&'static str>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

/// `--node-id` as 32 bytes: 64 lower-case hex, nothing else.
fn parse_node_id(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let bytes = hex::decode(text).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn to_output(read: NodeFamilyRead) -> NodeFamilyOutput {
    let node_id_hex = hex::encode(read.node_id);
    match read.binding {
        Ok((child, reg)) => NodeFamilyOutput::Ok {
            block_hash: read.block_hash,
            node_id_hex,
            bound: true,
            child_hex: Some(hex::encode(child)),
            family_hex: Some(hex::encode(reg.family)),
            status: Some(reg.status.label()),
            reason: None,
        },
        Err(reason) => NodeFamilyOutput::Ok {
            block_hash: read.block_hash,
            node_id_hex,
            bound: false,
            child_hex: None,
            family_hex: None,
            status: None,
            reason: Some(reason.label()),
        },
    }
}

/// Entry point for `hippius-ticket-validator read-node-family`.
pub fn run(args: ReadNodeFamilyArgs) -> ExitCode {
    let output = match parse_node_id(&args.node_id) {
        None => NodeFamilyOutput::Err {
            error: "node-id must be 64 lower-case hex characters".to_string(),
            category: category::RPC_REQUEST,
        },
        Some(node_id) => match fetch_node_family(&args.rpc_url, &args.pallet_name, &node_id) {
            Ok(read) => to_output(read),
            Err(e) => NodeFamilyOutput::Err {
                error: e.message,
                category: e.category,
            },
        },
    };
    let exit = match &output {
        NodeFamilyOutput::Ok { .. } => EXIT_OK,
        NodeFamilyOutput::Err { .. } => EXIT_STRUCTURED,
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
    use hippius_onchain_registry::{ChildRegistrationHead, ChildStatus, UnboundReason};

    #[test]
    fn parse_node_id_wants_64_lower_case_hex() {
        assert_eq!(parse_node_id(&"ab".repeat(32)), Some([0xabu8; 32]));
        assert_eq!(parse_node_id(&"AB".repeat(32)), None);
        assert_eq!(parse_node_id(&"ab".repeat(31)), None);
        assert_eq!(parse_node_id(&format!("0x{}", "ab".repeat(31))), None);
        assert_eq!(parse_node_id(&"zz".repeat(32)), None);
    }

    #[test]
    fn a_bound_node_renders_its_family_and_status() {
        let read = NodeFamilyRead {
            block_hash: format!("0x{}", "cd".repeat(32)),
            node_id: [0x11u8; 32],
            binding: Ok((
                [0x22u8; 32],
                ChildRegistrationHead {
                    family: [0x33u8; 32],
                    node_id: [0x11u8; 32],
                    status: ChildStatus::Active,
                },
            )),
        };
        let json = serde_json::to_value(to_output(read)).unwrap();
        assert_eq!(json["tag"], "ok");
        assert_eq!(json["bound"], true);
        assert_eq!(json["node_id_hex"], "11".repeat(32));
        assert_eq!(json["child_hex"], "22".repeat(32));
        assert_eq!(json["family_hex"], "33".repeat(32));
        assert_eq!(json["status"], "active");
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn an_unbound_node_renders_why() {
        let read = NodeFamilyRead {
            block_hash: format!("0x{}", "cd".repeat(32)),
            node_id: [0x11u8; 32],
            binding: Err(UnboundReason::NodeMismatch),
        };
        let json = serde_json::to_value(to_output(read)).unwrap();
        assert_eq!(json["bound"], false);
        assert_eq!(json["reason"], "node-mismatch");
        assert!(json.get("family_hex").is_none());
    }
}
