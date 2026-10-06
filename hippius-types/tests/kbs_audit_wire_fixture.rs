//! The shared KBS audit-read wire fixture (`tests/fixtures/kbs_audit_wire_v1.json`),
//! read through the WIRE TYPE alone.
//!
//! `kbs-core/tests/kbs_audit_wire_fixture.rs` produces the file with the
//! real sinks and pins it byte for byte; vali's ingester loads the same
//! file. This pins the other half: every page decodes into
//! [`AdminAuditPageResponse`] (`deny_unknown_fields`) and re-encodes to
//! the SAME bytes, and its chain is internally consistent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_types::admin::{AdminAuditPageResponse, ADMIN_AUDIT_PAGE_MAX};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/kbs_audit_wire_v1.json")).expect("JSON")
}

#[test]
fn every_page_round_trips_and_chains() {
    let f = fixture();
    for chain in [
        "release_epoch_a",
        "admin_epoch_a",
        "release_epoch_b",
        "release_torn",
        "admin_torn",
    ] {
        let mut prev = "00".repeat(32);
        let mut next_seq = 0u64;
        let mut genesis: Option<String> = None;
        for p in f[chain].as_array().unwrap() {
            let text = p["body_text"].as_str().unwrap();
            let page: AdminAuditPageResponse = serde_json::from_str(text).unwrap();
            assert_eq!(serde_json::to_string(&page).unwrap(), text, "{chain}");
            assert_eq!(page.v, 1);
            assert!(page.entries.len() <= ADMIN_AUDIT_PAGE_MAX as usize);
            genesis.get_or_insert(page.genesis_hash_hex.clone().unwrap());
            assert_eq!(page.genesis_hash_hex, genesis);
            for e in &page.entries {
                assert_eq!(e.seq, next_seq, "{chain}");
                assert_eq!(e.prev_hash_hex, prev, "{chain} seq {}", e.seq);
                let body = hex::decode(&e.body_cbor_hex).unwrap();
                assert_eq!(hex::encode(Sha256::digest(&body)), e.sha256_hex);
                prev = e.sha256_hex.clone();
                next_seq += 1;
            }
        }
        let last: AdminAuditPageResponse = serde_json::from_str(
            f[chain].as_array().unwrap().last().unwrap()["body_text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(
            last.entries.is_empty(),
            "{chain} ends with the caught-up page"
        );
        assert_eq!(last.head_seq, Some(next_seq - 1));
        assert_eq!(last.head_hash_hex, prev);
    }
}
