//! Tenant `ServedDeliveryReceipt` signer + verifier (ARCHITECTURE.md §23).
//!
//! Producer (per-VM telemetry agent inside the attested tenant guest):
//! `sign_served_receipt` Ed25519-signs the canonical-CBOR body.
//!
//! Consumer (validator + Audit VM): `verify_served_receipt` re-derives
//! the canonical bytes from EXPECTED fields and rejects if the wire
//! body differs — the same body-equality discipline the audit-VM
//! verifier uses, for the same reason (a hostile producer cannot
//! smuggle bytes that bypass the field checks).

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::audit_vm::ServedDeliveryAggregate;
use hippius_types::served_receipt::{ServedDeliveryReceipt, SignedServedDeliveryReceipt};
use subtle::ConstantTimeEq;

/// Sign the canonical CBOR body with the tenant guest's telemetry key.
pub fn sign_served_receipt(
    sk: &SigningKey,
    receipt: &ServedDeliveryReceipt,
) -> Result<SignedServedDeliveryReceipt> {
    let body = receipt
        .canonical()
        .map_err(|e| GuestError::Schema(format!("receipt encode: {e}")))?;
    let sig = sk.sign(&body);
    Ok(SignedServedDeliveryReceipt {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

/// Verify a `SignedServedDeliveryReceipt` against expected fields.
/// Body-equality check happens BEFORE signature verification so a
/// hostile producer cannot put garbage in `body`.
pub fn verify_served_receipt(
    vk: &VerifyingKey,
    signed: &SignedServedDeliveryReceipt,
    expected: &ServedDeliveryReceipt,
) -> Result<()> {
    let expected_body = expected
        .canonical()
        .map_err(|e| GuestError::Schema(format!("expected receipt encode: {e}")))?;
    if expected_body != signed.body {
        return Err(GuestError::Schema(
            "receipt body mismatch (expected fields differ from signed body)".into(),
        ));
    }
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| GuestError::Signature(format!("receipt sig decode: {e}")))?;
    vk.verify_strict(&signed.body, &sig)
        .map_err(|e| GuestError::Signature(format!("ed25519 verify: {e}")))?;
    Ok(())
}

/// Enforce the §23 "within its nonce window" rule that gates reward
/// crediting. Spec: "Reward only if every rewarded tenant receipt
/// digest is inside the co-signed digest AND within its nonce window —
/// a valid co-sign cannot be mixed with receipts from another
/// window/node/epoch."
///
/// This helper is what the on-chain pallet (or the validator's scorer)
/// MUST call before crediting any receipt against a signed aggregate.
/// It pins all the cross-document binding the aggregate's signed body
/// alone does not enforce:
/// - `receipt.validator_id` == aggregate validator (ct-eq);
/// - `receipt.validator_nonce` == `aggregate.challenge_nonce` (ct-eq);
/// - `receipt.epoch` == `aggregate.epoch`;
/// - `receipt.family_id` == `aggregate.family_id` (ct-eq);
/// - `receipt.node_id` == `aggregate.node_id` (ct-eq);
/// - `receipt.period_*` ⊆ `aggregate.interval_*`.
///
/// The map_root membership check (digest IN map_root) is the pallet's
/// other invariant — this helper deliberately does NOT recompute the
/// root because callers already do that one independently.
pub fn verify_receipt_in_aggregate_window(
    receipt: &ServedDeliveryReceipt,
    aggregate: &ServedDeliveryAggregate,
) -> Result<()> {
    let ct_match = receipt
        .validator_id
        .ct_eq(aggregate.validator_id)
        .unwrap_u8()
        == 1;
    if !ct_match {
        return Err(GuestError::Binding {
            field: "validator_id",
            expected: format!("len={}", aggregate.validator_id.len()),
            got: format!("len={}", receipt.validator_id.len()),
        });
    }
    if receipt
        .validator_nonce
        .ct_eq(aggregate.challenge_nonce)
        .unwrap_u8()
        != 1
    {
        return Err(GuestError::Binding {
            field: "validator_nonce",
            expected: "aggregate.challenge_nonce".into(),
            got: "receipt.validator_nonce mismatch".into(),
        });
    }
    if receipt.epoch != aggregate.epoch {
        return Err(GuestError::Binding {
            field: "epoch",
            expected: aggregate.epoch.to_string(),
            got: receipt.epoch.to_string(),
        });
    }
    if receipt.family_id.ct_eq(aggregate.family_id).unwrap_u8() != 1 {
        return Err(GuestError::Binding {
            field: "family_id",
            expected: format!("len={}", aggregate.family_id.len()),
            got: format!("len={}", receipt.family_id.len()),
        });
    }
    if receipt.node_id.ct_eq(aggregate.node_id).unwrap_u8() != 1 {
        return Err(GuestError::Binding {
            field: "node_id",
            expected: format!("len={}", aggregate.node_id.len()),
            got: format!("len={}", receipt.node_id.len()),
        });
    }
    if receipt.period_start < aggregate.interval_start
        || receipt.period_end > aggregate.interval_end
    {
        return Err(GuestError::Binding {
            field: "period_window",
            expected: format!("{}..={}", aggregate.interval_start, aggregate.interval_end),
            got: format!("{}..={}", receipt.period_start, receipt.period_end),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[33u8; 32])
    }

    fn receipt<'a>(nonce: &'a [u8; 32]) -> ServedDeliveryReceipt<'a> {
        ServedDeliveryReceipt {
            validator_id: b"validator-1",
            validator_nonce: nonce,
            epoch: 42,
            vm_id: "abc",
            lease_id: "lease-1",
            family_id: b"family-1",
            node_id: b"node-1",
            resource_class: "std",
            monotonic_seq: 7,
            observed_degradation_bps: 0,
            period_start: 1_000,
            period_end: 1_060,
            expiry: 2_000,
        }
    }

    fn agg_for<'a>(
        nonce: &'a [u8; 32],
        cg: &'a [u8; 32],
        pi: &'a [u8; 32],
        mr: &'a [u8; 32],
        tr: &'a [u8; 32],
        ph: &'a [u8; 32],
    ) -> ServedDeliveryAggregate<'a> {
        ServedDeliveryAggregate {
            chain_genesis: cg,
            pallet_instance: pi,
            validator_id: b"validator-1",
            family_id: b"family-1",
            node_id: b"node-1",
            audit_vm_key_id: b"audit-vm-key-1",
            epoch: 42,
            challenge_nonce: nonce,
            interval_start: 1_000,
            interval_end: 1_060,
            map_root: mr,
            totals_root: tr,
            prev_aggregate_hash: ph,
            expiry: 2_000,
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let signed = sign_served_receipt(&sk, &r).unwrap();
        verify_served_receipt(&sk.verifying_key(), &signed, &r).unwrap();
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let signed = sign_served_receipt(&sk, &r).unwrap();
        let mut bumped = r.clone();
        bumped.epoch = 43;
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &bumped).is_err());
    }

    #[test]
    fn monotonic_seq_mismatch_rejected() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let signed = sign_served_receipt(&sk, &r).unwrap();
        let mut bumped = r.clone();
        bumped.monotonic_seq = 8;
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &bumped).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let signed = sign_served_receipt(&attacker, &r).unwrap();
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &r).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let mut signed = sign_served_receipt(&sk, &r).unwrap();
        signed.sig[0] ^= 0xff;
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &r).is_err());
    }

    #[test]
    fn malformed_sig_length_rejected() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let mut signed = sign_served_receipt(&sk, &r).unwrap();
        signed.sig = vec![0; 63]; // Ed25519 sig must be 64 bytes
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &r).is_err());
    }

    #[test]
    fn cross_validator_replay_rejected() {
        // A different validator's body fields produce different bytes,
        // so the original signature does NOT verify under the other
        // validator's expected receipt.
        let n = [3u8; 32];
        let r = receipt(&n);
        let sk = key();
        let signed = sign_served_receipt(&sk, &r).unwrap();
        let mut other = r.clone();
        other.validator_id = b"validator-attacker";
        assert!(verify_served_receipt(&sk.verifying_key(), &signed, &other).is_err());
    }

    #[test]
    fn window_check_happy_path() {
        let n = [3u8; 32];
        let r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        verify_receipt_in_aggregate_window(&r, &agg).unwrap();
    }

    #[test]
    fn window_check_rejects_validator_id_mismatch() {
        let n = [3u8; 32];
        let mut r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        r.validator_id = b"validator-attacker";
        assert!(verify_receipt_in_aggregate_window(&r, &agg).is_err());
    }

    #[test]
    fn window_check_rejects_nonce_mismatch() {
        // Same digest, but different validator_nonce ⇒ window invariant
        // fails; pallet must NOT credit this receipt against the aggregate.
        let n = [3u8; 32];
        let mut r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        let other_nonce = [9u8; 32];
        r.validator_nonce = &other_nonce;
        assert!(verify_receipt_in_aggregate_window(&r, &agg).is_err());
    }

    #[test]
    fn window_check_rejects_period_outside_interval() {
        let n = [3u8; 32];
        let mut r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        // Receipt period extends past aggregate interval_end.
        r.period_end = agg.interval_end + 1;
        assert!(verify_receipt_in_aggregate_window(&r, &agg).is_err());
    }

    #[test]
    fn window_check_rejects_epoch_mismatch() {
        let n = [3u8; 32];
        let mut r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        r.epoch = agg.epoch + 1;
        assert!(verify_receipt_in_aggregate_window(&r, &agg).is_err());
    }

    #[test]
    fn window_check_rejects_node_id_mismatch() {
        let n = [3u8; 32];
        let mut r = receipt(&n);
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let mr = [4u8; 32];
        let tr = [5u8; 32];
        let ph = [6u8; 32];
        let agg = agg_for(&n, &cg, &pi, &mr, &tr, &ph);
        r.node_id = b"node-attacker";
        assert!(verify_receipt_in_aggregate_window(&r, &agg).is_err());
    }
}
