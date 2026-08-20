//! End-to-end §23 reward-evidence chain:
//! 1. Tenant VMs sign `ServedDeliveryReceipt`s for their own served work.
//! 2. The validator collects the receipts, computes each one's
//!    `receipt_digest`, builds a `ServedReceiptEntry` for each, and
//!    asks the per-node Audit VM to compute + sign a
//!    `ServedDeliveryAggregate` covering them.
//! 3. The on-chain pallet / scorer re-derives the same `map_root` and
//!    verifies the Audit-VM signature before crediting reward.
//!
//! This test exercises the entire chain to prove the cross-crate +
//! cross-domain wire formats line up byte-for-byte and the audit
//! verifier passes when given the inputs that built the signed body.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use hippius_guest::{
    sign_aggregate, sign_served_receipt, verify_aggregate, verify_receipt_in_aggregate_window,
    verify_served_receipt,
};
use hippius_types::audit_vm::{
    map_root, totals_root, ResourceClassTotal, ServedDeliveryAggregate, ServedReceiptEntry,
};
use hippius_types::served_receipt::{receipt_digest, ServedDeliveryReceipt};

#[test]
fn tenant_receipts_roll_into_audit_vm_aggregate() {
    // Two tenant VMs each emit a receipt.
    let tenant_a_key = SigningKey::from_bytes(&[10u8; 32]);
    let tenant_b_key = SigningKey::from_bytes(&[20u8; 32]);
    // The Audit VM has its own attested key.
    let audit_vm_key = SigningKey::from_bytes(&[30u8; 32]);

    let validator_nonce = [0xAAu8; 32];
    let chain_genesis = [1u8; 32];
    let pallet_instance = [2u8; 32];
    let prev_aggregate_hash = [3u8; 32];

    let receipt_a = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &validator_nonce,
        epoch: 100,
        vm_id: "vm-a",
        lease_id: "lease-a",
        family_id: b"family-1",
        node_id: b"node-1",
        resource_class: "std",
        monotonic_seq: 1,
        observed_degradation_bps: 0,
        period_start: 1_000,
        period_end: 1_060,
        expiry: 2_000,
    };
    let receipt_b = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &validator_nonce,
        epoch: 100,
        vm_id: "vm-b",
        lease_id: "lease-b",
        family_id: b"family-1",
        node_id: b"node-1",
        resource_class: "std",
        monotonic_seq: 1,
        observed_degradation_bps: 0,
        period_start: 1_000,
        period_end: 1_060,
        expiry: 2_000,
    };
    let signed_a = sign_served_receipt(&tenant_a_key, &receipt_a).unwrap();
    let signed_b = sign_served_receipt(&tenant_b_key, &receipt_b).unwrap();
    // Validator verifies each receipt against the tenant's known pubkey.
    verify_served_receipt(&tenant_a_key.verifying_key(), &signed_a, &receipt_a).unwrap();
    verify_served_receipt(&tenant_b_key.verifying_key(), &signed_b, &receipt_b).unwrap();

    // Validator hands the receipt set to the Audit VM, which computes
    // the map_root + totals_root and signs the aggregate body.
    let entries = vec![
        ServedReceiptEntry {
            vm_id: receipt_a.vm_id.into(),
            lease_id: receipt_a.lease_id.into(),
            monotonic_seq: receipt_a.monotonic_seq,
            digest: receipt_digest(&signed_a).to_vec(),
        },
        ServedReceiptEntry {
            vm_id: receipt_b.vm_id.into(),
            lease_id: receipt_b.lease_id.into(),
            monotonic_seq: receipt_b.monotonic_seq,
            digest: receipt_digest(&signed_b).to_vec(),
        },
    ];
    let totals = vec![ResourceClassTotal {
        class: "std".into(),
        served_units: 2 * 60, // both receipts × 60 seconds
    }];
    let mr = map_root(&entries).unwrap();
    let tr = totals_root(&totals).unwrap();
    let agg = ServedDeliveryAggregate {
        chain_genesis: &chain_genesis,
        pallet_instance: &pallet_instance,
        validator_id: b"validator-1",
        family_id: b"family-1",
        node_id: b"node-1",
        audit_vm_key_id: b"audit-vm-key-1",
        epoch: 100,
        challenge_nonce: &validator_nonce,
        interval_start: 1_000,
        interval_end: 1_060,
        map_root: &mr,
        totals_root: &tr,
        prev_aggregate_hash: &prev_aggregate_hash,
        expiry: 2_000,
    };
    let signed_agg = sign_aggregate(&audit_vm_key, &agg).unwrap();

    // The pallet / scorer reconstructs the SAME inputs and verifies.
    verify_aggregate(&audit_vm_key.verifying_key(), &signed_agg, &agg).unwrap();

    // A receipt that wasn't in the entry set fails the digest-inclusion
    // check (the pallet would compute it as the SHA of receipt body and
    // look up against the map_root; here we just assert the entry list
    // does not contain a digest that wasn't passed in).
    let outsider = ServedDeliveryReceipt {
        vm_id: "vm-c",
        lease_id: "lease-c",
        monotonic_seq: 1,
        ..receipt_a
    };
    let signed_outsider = sign_served_receipt(&tenant_a_key, &outsider).unwrap();
    let d_outsider = receipt_digest(&signed_outsider).to_vec();
    assert!(
        !entries.iter().any(|e| e.digest == d_outsider),
        "outsider digest must NOT appear in the committed set"
    );
}

#[test]
fn audit_vm_cannot_lie_about_inputs() {
    // Audit VM signs an aggregate with a `map_root` that doesn't match
    // the entries the validator passed in. The validator's re-derive
    // catches the drift; verify_aggregate rejects.
    let audit_vm_key = SigningKey::from_bytes(&[30u8; 32]);
    let chain_genesis = [1u8; 32];
    let pallet_instance = [2u8; 32];
    let challenge_nonce = [3u8; 32];
    let prev_aggregate_hash = [4u8; 32];

    let entries = [ServedReceiptEntry {
        vm_id: "vm-a".into(),
        lease_id: "lease-a".into(),
        monotonic_seq: 1,
        digest: vec![0xCC; 32],
    }];
    let totals = [ResourceClassTotal {
        class: "std".into(),
        served_units: 100,
    }];
    let real_mr = map_root(&entries).unwrap();
    let real_tr = totals_root(&totals).unwrap();
    // Audit VM signs with a DIFFERENT (lying) map_root.
    let lying_mr = [0xDDu8; 32];
    let lying_agg = ServedDeliveryAggregate {
        chain_genesis: &chain_genesis,
        pallet_instance: &pallet_instance,
        validator_id: b"v",
        family_id: b"f",
        node_id: b"n",
        audit_vm_key_id: b"k",
        epoch: 1,
        challenge_nonce: &challenge_nonce,
        interval_start: 100,
        interval_end: 200,
        map_root: &lying_mr,
        totals_root: &real_tr,
        prev_aggregate_hash: &prev_aggregate_hash,
        expiry: 300,
    };
    let signed_lying = sign_aggregate(&audit_vm_key, &lying_agg).unwrap();
    // Validator re-derives with the TRUE inputs ⇒ rejects.
    let truth = ServedDeliveryAggregate {
        map_root: &real_mr,
        ..lying_agg
    };
    assert!(verify_aggregate(&audit_vm_key.verifying_key(), &signed_lying, &truth).is_err());
}

#[test]
fn empty_aggregate_signs_and_verifies() {
    // §23 admits "no work served this interval" — empty entry/total
    // lists must produce a well-defined signed aggregate.
    let audit_vm_key = SigningKey::from_bytes(&[30u8; 32]);
    let chain_genesis = [1u8; 32];
    let pallet_instance = [2u8; 32];
    let challenge_nonce = [3u8; 32];
    let prev_aggregate_hash = [4u8; 32];
    let mr = map_root(&[]).unwrap();
    let tr = totals_root(&[]).unwrap();
    let agg = ServedDeliveryAggregate {
        chain_genesis: &chain_genesis,
        pallet_instance: &pallet_instance,
        validator_id: b"validator-1",
        family_id: b"family-1",
        node_id: b"node-1",
        audit_vm_key_id: b"audit-vm-key-1",
        epoch: 100,
        challenge_nonce: &challenge_nonce,
        interval_start: 1_000,
        interval_end: 1_060,
        map_root: &mr,
        totals_root: &tr,
        prev_aggregate_hash: &prev_aggregate_hash,
        expiry: 2_000,
    };
    let signed = sign_aggregate(&audit_vm_key, &agg).unwrap();
    verify_aggregate(&audit_vm_key.verifying_key(), &signed, &agg).unwrap();
}

#[test]
fn digest_in_map_but_wrong_nonce_window_rejected() {
    // §23 invariant: a receipt whose digest is inside the aggregate's
    // map_root but whose nonce/window does NOT match the aggregate
    // MUST be rejected at the scorer/pallet layer. This is exactly
    // what `verify_receipt_in_aggregate_window` is for.
    let tenant_key = SigningKey::from_bytes(&[10u8; 32]);
    let audit_vm_key = SigningKey::from_bytes(&[30u8; 32]);

    let validator_nonce_a = [0xAAu8; 32];
    let validator_nonce_b = [0xBBu8; 32]; // different window
    let chain_genesis = [1u8; 32];
    let pallet_instance = [2u8; 32];
    let prev = [3u8; 32];

    // Tenant signed a receipt for nonce_b's window (a DIFFERENT window).
    let receipt = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &validator_nonce_b,
        epoch: 100,
        vm_id: "vm-a",
        lease_id: "lease-a",
        family_id: b"family-1",
        node_id: b"node-1",
        resource_class: "std",
        monotonic_seq: 1,
        observed_degradation_bps: 0,
        period_start: 5_000,
        period_end: 5_060,
        expiry: 6_000,
    };
    let signed_receipt = sign_served_receipt(&tenant_key, &receipt).unwrap();
    let entries = [ServedReceiptEntry {
        vm_id: "vm-a".into(),
        lease_id: "lease-a".into(),
        monotonic_seq: 1,
        digest: receipt_digest(&signed_receipt).to_vec(),
    }];
    let totals = [ResourceClassTotal {
        class: "std".into(),
        served_units: 60,
    }];
    let mr = map_root(&entries).unwrap();
    let tr = totals_root(&totals).unwrap();
    // Hostile audit VM rolls the digest into an aggregate for window A
    // (`validator_nonce_a`, interval 1_000..=1_060) — a DIFFERENT window
    // than the receipt actually attests.
    let agg = ServedDeliveryAggregate {
        chain_genesis: &chain_genesis,
        pallet_instance: &pallet_instance,
        validator_id: b"validator-1",
        family_id: b"family-1",
        node_id: b"node-1",
        audit_vm_key_id: b"audit-vm-key-1",
        epoch: 100,
        challenge_nonce: &validator_nonce_a,
        interval_start: 1_000,
        interval_end: 1_060,
        map_root: &mr,
        totals_root: &tr,
        prev_aggregate_hash: &prev,
        expiry: 2_000,
    };
    let signed_agg = sign_aggregate(&audit_vm_key, &agg).unwrap();
    // Sig + map membership BOTH check out:
    verify_aggregate(&audit_vm_key.verifying_key(), &signed_agg, &agg).unwrap();
    let d = receipt_digest(&signed_receipt).to_vec();
    assert!(entries.iter().any(|e| e.digest == d));
    // …but the window invariant REJECTS the receipt → pallet refuses
    // to credit it. This is the §23 anti-teleportation gate.
    assert!(verify_receipt_in_aggregate_window(&receipt, &agg).is_err());
}
