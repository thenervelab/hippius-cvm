//! Integration test for §23 telemetry-key establishment.
//!
//! The telemetry signing key is HKDF-derived from the §7 lifecycle key
//! the KBS released to this attested guest (read from a tmpfs path). The
//! load-bearing invariant: the pubkey the guest derives MUST equal the
//! one vali derives from the SAME lifecycle seed (the shared
//! `hippius_guest::telemetry_key`), or every served-receipt fails
//! verification.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_agent_tenant_telemetry::config::Config;
use hippius_agent_tenant_telemetry::establish::establish;
use hippius_guest::telemetry_key::derive_telemetry_signing_key;

/// A minimal `Config` whose `lifecycle_key_path` points at `path`. The
/// other fields are irrelevant to establishment (they drive the receipt
/// loop) but must be present.
fn config(path: &str) -> Config {
    Config {
        node_id: vec![0x01; 32],
        vm_id: "vm-1".to_string(),
        lease_id: "lease-1".to_string(),
        family_id: vec![0xaa],
        resource_class: "small".to_string(),
        interval_secs: 60,
        receipt_ttl_secs: 300,
        observed_degradation_bps: 0,
        challenge: None,
        vsock_port: 5000,
        lifecycle_key_path: path.to_string(),
    }
}

#[test]
fn establish_derives_the_key_vali_provisions() {
    let path = std::env::temp_dir().join("hippius-it-lifecycle.key");
    let seed = [0x5au8; 32];
    std::fs::write(&path, seed).unwrap();

    let est = establish(&config(path.to_str().unwrap()))
        .expect("establishment from a released lifecycle key must succeed");

    // The signer's public key MUST equal what vali derives from the same
    // lifecycle seed via the shared HKDF — the whole point.
    let vali_side = derive_telemetry_signing_key(&seed).verifying_key();
    assert_eq!(est.signer.verifying_key(), vali_side);

    std::fs::remove_file(&path).ok();
}

#[test]
fn establish_fails_closed_without_a_lifecycle_key() {
    let err = establish(&config("/nonexistent/hippius-lifecycle.key"));
    assert!(err.is_err(), "a missing lifecycle key must fail closed");
}
