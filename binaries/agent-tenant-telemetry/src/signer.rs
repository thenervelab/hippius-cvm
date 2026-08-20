//! The Ed25519 telemetry signer key + the [`TelemetrySigner`] trait.
//!
//! The §23 per-VM telemetry signer key is **generated inside the
//! measured guest** (here) and never leaves it — only the public key
//! crosses the wire (folded into `REPORT_DATA`, then certified by the
//! KBS). PR-E2.1 establishes the key; PR-E2.2's receipt loop calls
//! [`TelemetrySigner::sign_served_receipt`] to sign periodic
//! `ServedDeliveryReceipt`s.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::served_receipt::{ServedDeliveryReceipt, SignedServedDeliveryReceipt};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Result, TelemetryError};

/// Length of an Ed25519 seed / public key.
pub const KEY_LEN: usize = 32;

/// The capability of holding the telemetry key and signing with it.
///
/// A trait — like the initramfs agent's `SnpReportProvider` — so
/// PR-E2.2's receipt loop (and the tests) depend on the *capability*,
/// not the concrete key holder. The single production implementation
/// is [`Ed25519TelemetrySigner`].
pub trait TelemetrySigner {
    /// Ed25519-sign `message` with the established telemetry key.
    fn sign(&self, message: &[u8]) -> Signature;
    /// The 32-byte Ed25519 public key — what the KBS certifies and a
    /// receipt verifier checks signatures against.
    fn verifying_key(&self) -> VerifyingKey;
    /// Build the canonical-CBOR body of `receipt` and Ed25519-sign it,
    /// returning the signed wire envelope.
    ///
    /// Encoding and signing happen together: a caller cannot obtain an
    /// unsigned `SignedServedDeliveryReceipt`, and the telemetry key
    /// never leaves the signer. `Err` is a fail-closed `canonical()`
    /// rejection (out-of-range degradation, inverted period) carrying
    /// only a static class.
    fn sign_served_receipt(
        &self,
        receipt: &ServedDeliveryReceipt<'_>,
    ) -> Result<SignedServedDeliveryReceipt>;
}

/// The production [`TelemetrySigner`] — holds the Ed25519 signing key
/// **in RAM only**, never on disk.
///
/// `Box<SigningKey>` — heap-allocated for a stable address, so moving
/// an `Ed25519TelemetrySigner` moves only the box pointer and never
/// copies the secret scalar to a fresh stack slot that would escape
/// the wipe. `ed25519-dalek`'s `zeroize` feature makes `SigningKey`
/// `ZeroizeOnDrop`; dropping the box drops the `SigningKey`, which
/// scrubs the seed.
///
/// `mlock` / core-dump exclusion are handled at the measured-image
/// level (swap off, core dumps off) — the same deployment-layer
/// decision the initramfs agent's keygen documents, and strictly
/// stronger than a per-page `mlock` since it also covers the keygen
/// transient below.
///
/// `Debug` is intentionally **not** derived — the compiler must refuse
/// a `dbg!()` on a key holder.
pub struct Ed25519TelemetrySigner {
    signing_key: Box<SigningKey>,
}

impl Ed25519TelemetrySigner {
    /// Generate a fresh Ed25519 telemetry keypair from the OS CSPRNG.
    ///
    /// The 32-byte seed is drawn straight into a [`Zeroizing`] buffer
    /// and consumed into the `SigningKey`; that buffer is the only
    /// transient and it wipes on drop. From then on the secret lives
    /// solely inside the boxed `ZeroizeOnDrop` `SigningKey`.
    pub fn generate() -> Result<Self> {
        let mut seed: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut seed[..])
            .map_err(|_| TelemetryError::Keygen("os-rng"))?;
        let signing_key = Box::new(SigningKey::from_bytes(&seed));
        Ok(Self { signing_key })
    }

    /// Build the signer from an already-derived `SigningKey` — the §23
    /// telemetry key HKDF-derived from the guest lifecycle key
    /// (`hippius_guest::telemetry_key`). The key lives only inside the
    /// boxed `ZeroizeOnDrop` `SigningKey`.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self {
            signing_key: Box::new(signing_key),
        }
    }
}

impl TelemetrySigner for Ed25519TelemetrySigner {
    fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn sign_served_receipt(
        &self,
        receipt: &ServedDeliveryReceipt<'_>,
    ) -> Result<SignedServedDeliveryReceipt> {
        // Delegate to the canonical guest-side signer — it produces the
        // deterministic-CBOR body and signs it in one step. A failure
        // can only be a `canonical()` rejection; collapse it to a
        // static class so no inner text reaches a log (§20).
        hippius_guest::sign_served_receipt(&self.signing_key, receipt)
            .map_err(|_| TelemetryError::Receipt("receipt-sign"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn generated_key_signs_and_verifies() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let msg = b"served-delivery-receipt-body";
        let sig = signer.sign(msg);
        // The matching public key verifies the signature.
        signer
            .verifying_key()
            .verify(msg, &sig)
            .expect("the signer's own public key must verify its signature");
    }

    #[test]
    fn distinct_generations_yield_distinct_keys() {
        // A regression to a fixed seed would make every guest share one
        // telemetry key — catastrophic for §23 attribution.
        let a = Ed25519TelemetrySigner::generate().unwrap();
        let b = Ed25519TelemetrySigner::generate().unwrap();
        assert_ne!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let other = Ed25519TelemetrySigner::generate().unwrap();
        let msg = b"receipt";
        let sig = signer.sign(msg);
        assert!(other.verifying_key().verify(msg, &sig).is_err());
    }

    /// A representative receipt for the `sign_served_receipt` tests.
    fn sample_receipt(nonce: &[u8; 32]) -> ServedDeliveryReceipt<'_> {
        ServedDeliveryReceipt {
            validator_id: b"validator-1",
            validator_nonce: nonce,
            epoch: 7,
            vm_id: "vm-1",
            lease_id: "lease-1",
            family_id: b"family-1",
            node_id: b"node-1",
            resource_class: "std",
            monotonic_seq: 1,
            observed_degradation_bps: 0,
            period_start: 1_000,
            period_end: 1_060,
            expiry: 2_000,
        }
    }

    #[test]
    fn signs_a_served_receipt_that_verifies() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let nonce = [5u8; 32];
        let receipt = sample_receipt(&nonce);
        let signed = signer.sign_served_receipt(&receipt).unwrap();
        // The signer's own public key + the same expected fields verify.
        hippius_guest::verify_served_receipt(&signer.verifying_key(), &signed, &receipt).unwrap();
        // Signature is the canonical 64-byte Ed25519 length.
        assert_eq!(signed.sig.len(), 64);
        // `body` is the canonical CBOR of the receipt.
        assert_eq!(signed.body, receipt.canonical().unwrap());
    }

    #[test]
    fn sign_served_receipt_fails_closed_on_out_of_range_degradation() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let nonce = [5u8; 32];
        let mut receipt = sample_receipt(&nonce);
        receipt.observed_degradation_bps = 10_001; // > DEGRADATION_MAX_BPS
        let err = signer
            .sign_served_receipt(&receipt)
            .expect_err("an out-of-range receipt must not produce a signature");
        assert_eq!(err.class(), "receipt-sign");
    }
}
