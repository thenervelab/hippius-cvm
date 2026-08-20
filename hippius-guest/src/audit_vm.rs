//! Audit-VM signer (producer) + verifier (consumer) for the §23
//! `ServedDeliveryAggregate`.
//!
//! Producer (inside the attested Audit VM): `sign_aggregate` takes the
//! validator-issued replay-domain fields + locally-computed roots
//! (`map_root` over receipts the audit VM cross-checked,
//! `totals_root` over resource-class totals), encodes the canonical
//! CBOR body, and Ed25519-signs it with the audit-VM key whose pubkey
//! the KBS bound into REPORT_DATA[32..64] at first attestation (§20
//! audit-VM layout).
//!
//! Consumer (validator / on-chain pallet): `verify_aggregate` re-
//! derives the canonical bytes from the EXPECTED fields and verifies
//! signature + body match. A hostile audit VM that put different
//! bytes in `body` than the expected fields cannot bypass the field
//! checks — the validator's re-derive is the source of truth.

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::audit_vm::{ServedDeliveryAggregate, SignedServedDeliveryAggregate};

/// Sign the canonical-CBOR `ServedDeliveryAggregate` body with the
/// Audit VM's Ed25519 lifecycle key. The signing key is generated
/// inside the attested guest; production agents zeroize it on agent
/// shutdown.
pub fn sign_aggregate(
    sk: &SigningKey,
    agg: &ServedDeliveryAggregate,
) -> Result<SignedServedDeliveryAggregate> {
    let body = agg
        .canonical()
        .map_err(|e| GuestError::Schema(format!("aggregate encode: {e}")))?;
    let sig = sk.sign(&body);
    Ok(SignedServedDeliveryAggregate {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

/// Verify a `SignedServedDeliveryAggregate` against a re-derived body.
///
/// The verifier MUST supply the expected fields: the body bytes from
/// the wire are not trusted directly. A hostile audit VM that puts
/// garbage in `body` (different node_id, larger epoch, etc.) cannot
/// bypass field checks because we recompute the canonical body and
/// reject on byte-mismatch BEFORE checking the signature.
pub fn verify_aggregate(
    vk: &VerifyingKey,
    signed: &SignedServedDeliveryAggregate,
    expected: &ServedDeliveryAggregate,
) -> Result<()> {
    let expected_body = expected
        .canonical()
        .map_err(|e| GuestError::Schema(format!("expected encode: {e}")))?;
    if expected_body != signed.body {
        return Err(GuestError::Schema(
            "aggregate body mismatch (expected fields differ from signed body)".into(),
        ));
    }
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| GuestError::Signature(format!("aggregate sig decode: {e}")))?;
    vk.verify_strict(&signed.body, &sig)
        .map_err(|e| GuestError::Signature(format!("ed25519 verify: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::audit_vm::{map_root, totals_root, ResourceClassTotal, ServedReceiptEntry};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn entries() -> Vec<ServedReceiptEntry> {
        vec![ServedReceiptEntry {
            vm_id: "vm-a".into(),
            lease_id: "lease-1".into(),
            monotonic_seq: 1,
            digest: vec![0xAA; 32],
        }]
    }
    fn totals() -> Vec<ResourceClassTotal> {
        vec![ResourceClassTotal {
            class: "std".into(),
            served_units: 12_345,
        }]
    }

    fn agg_at<'a>(
        cg: &'a [u8; 32],
        pi: &'a [u8; 32],
        cn: &'a [u8; 32],
        mr: &'a [u8; 32],
        tr: &'a [u8; 32],
        ph: &'a [u8; 32],
        epoch: u64,
    ) -> ServedDeliveryAggregate<'a> {
        ServedDeliveryAggregate {
            chain_genesis: cg,
            pallet_instance: pi,
            validator_id: b"validator-1",
            family_id: b"family-1",
            node_id: b"node-1",
            audit_vm_key_id: b"audit-vm-key-1",
            epoch,
            challenge_nonce: cn,
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
        let mr = map_root(&entries()).unwrap();
        let tr = totals_root(&totals()).unwrap();
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let cn = [3u8; 32];
        let ph = [4u8; 32];
        let sk = key();
        let agg = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 42);
        let signed = sign_aggregate(&sk, &agg).unwrap();
        verify_aggregate(&sk.verifying_key(), &signed, &agg).unwrap();
    }

    #[test]
    fn epoch_mismatch_rejected() {
        let mr = map_root(&entries()).unwrap();
        let tr = totals_root(&totals()).unwrap();
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let cn = [3u8; 32];
        let ph = [4u8; 32];
        let sk = key();
        let agg = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 42);
        let signed = sign_aggregate(&sk, &agg).unwrap();
        let bumped = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 43);
        assert!(verify_aggregate(&sk.verifying_key(), &signed, &bumped).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let mr = map_root(&entries()).unwrap();
        let tr = totals_root(&totals()).unwrap();
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let cn = [3u8; 32];
        let ph = [4u8; 32];
        let sk = key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let agg = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 42);
        let signed = sign_aggregate(&attacker, &agg).unwrap();
        assert!(verify_aggregate(&sk.verifying_key(), &signed, &agg).is_err());
    }

    #[test]
    fn map_root_drift_rejected() {
        let mr = map_root(&entries()).unwrap();
        let tr = totals_root(&totals()).unwrap();
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let cn = [3u8; 32];
        let ph = [4u8; 32];
        let sk = key();
        let agg = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 42);
        let signed = sign_aggregate(&sk, &agg).unwrap();
        // Validator recomputed the map_root over a DIFFERENT receipt set
        // (different SHA → different root). Verify must reject because
        // the signed body bytes do not match the re-derived body.
        let other = [0u8; 32];
        let drifted = agg_at(&cg, &pi, &cn, &other, &tr, &ph, 42);
        assert!(verify_aggregate(&sk.verifying_key(), &signed, &drifted).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let mr = map_root(&entries()).unwrap();
        let tr = totals_root(&totals()).unwrap();
        let cg = [1u8; 32];
        let pi = [2u8; 32];
        let cn = [3u8; 32];
        let ph = [4u8; 32];
        let sk = key();
        let agg = agg_at(&cg, &pi, &cn, &mr, &tr, &ph, 42);
        let mut signed = sign_aggregate(&sk, &agg).unwrap();
        signed.sig[0] ^= 0xff;
        assert!(verify_aggregate(&sk.verifying_key(), &signed, &agg).is_err());
    }
}
