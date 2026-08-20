//! The Ed25519 host-attestor signer key + its HKDF derivation.
//!
//! The attestor's per-boot signer key is **derived**, not randomly
//! generated: its seed is
//!
//! ```text
//! seed = HKDF-SHA256(ikm  = snp_derived_key,
//!                    salt = "",
//!                    info = HIPPIUS_HOST_ATTESTOR_KEY_V1,
//!                    L    = 32)
//! ```
//!
//! where `snp_derived_key` is the measurement-bound VCEK derived key
//! from [`crate::derived_key`]. Because the SNP derived key is
//! reproducible only on this exact measured platform, and HKDF is
//! one-way + domain-separated under the frozen
//! [`HOST_ATTESTOR_KEY_DOMAIN`], the resulting Ed25519 identity is
//! cryptographically pinned to the platform and never persisted to disk.
//!
//! The key lives **only in RAM** and is zeroized on drop. Only the
//! public key crosses the wire (folded into the enrollment `REPORT_DATA`
//! in PR-4, then certified by the KBS). `Debug` is intentionally not
//! derived, and no method or error exposes the secret.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::host_attestor::HOST_ATTESTOR_KEY_DOMAIN;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::derived_key::SnpDerivedKey;
use crate::error::Result;

/// Length of an Ed25519 seed / public key.
pub const KEY_LEN: usize = 32;

/// Length of an Ed25519 signature.
pub const SIG_LEN: usize = 64;

/// Derive the 32-byte host-attestor Ed25519 signing seed from the SNP
/// derived key. Deterministic + pure — the same measured platform always
/// yields the same seed. The returned buffer wipes on drop.
///
/// HKDF `expand` only errors when the requested length exceeds
/// 255·HashLen; 32 ≤ 255·32, so a fixed 32-byte output is infallible.
fn derive_signing_seed(snp_derived_key: &SnpDerivedKey) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, snp_derived_key.as_ref());
    let mut seed: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
    #[allow(clippy::expect_used)]
    hk.expand(HOST_ATTESTOR_KEY_DOMAIN.as_bytes(), seed.as_mut())
        .expect("HKDF expand of 32 bytes <= 255*HashLen is infallible");
    seed
}

/// The host attestor's Ed25519 signer — holds the signing key **in RAM
/// only**, never on disk.
///
/// `Box<SigningKey>` — heap-allocated for a stable address, so moving the
/// signer moves only the box pointer and never copies the secret scalar
/// to a fresh stack slot that would escape the wipe. `ed25519-dalek`'s
/// `zeroize` feature makes `SigningKey` `ZeroizeOnDrop`; dropping the box
/// scrubs the seed. `Debug` is intentionally **not** derived — the
/// compiler must refuse a `dbg!()` on a key holder.
pub struct HostAttestorSigner {
    signing_key: Box<SigningKey>,
}

impl HostAttestorSigner {
    /// Derive the signer from the SNP derived key via HKDF under
    /// [`HOST_ATTESTOR_KEY_DOMAIN`].
    ///
    /// The transient HKDF seed lives in a [`Zeroizing`] buffer and is
    /// consumed into the `SigningKey`; from then on the secret lives
    /// solely inside the boxed `ZeroizeOnDrop` `SigningKey`.
    pub fn from_snp_derived_key(snp_derived_key: &SnpDerivedKey) -> Result<Self> {
        let seed = derive_signing_seed(snp_derived_key);
        let signing_key = Box::new(SigningKey::from_bytes(&seed));
        Ok(Self { signing_key })
    }

    /// Build the signer from an already-derived `SigningKey`. The key
    /// lives only inside the boxed `ZeroizeOnDrop` `SigningKey`.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self {
            signing_key: Box::new(signing_key),
        }
    }

    /// The 32-byte Ed25519 public key — what the KBS certifies (PR-4) and
    /// a beacon verifier checks signatures against.
    pub fn pubkey(&self) -> [u8; KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The typed verifying key (same bytes as [`Self::pubkey`]).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Ed25519-sign `message`, returning the raw 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::derived_key::{fetch_host_attestor_derived_key, MockDerivedKeyProvider};
    use ed25519_dalek::Verifier;

    /// A pinned known-answer vector. The derivation is a wire contract:
    /// the KBS enrols the public key derived here, so its output for a
    /// fixed SNP derived key must NEVER change. If this vector breaks,
    /// every enrolled host's beacons stop verifying.
    #[test]
    fn derivation_is_a_stable_known_answer() {
        let snp_derived_key: SnpDerivedKey = Zeroizing::new([7u8; 32]);
        let seed = derive_signing_seed(&snp_derived_key);
        let signer = HostAttestorSigner::from_snp_derived_key(&snp_derived_key).unwrap();

        // Freeze both the HKDF seed and the derived Ed25519 pubkey so a
        // future refactor cannot silently change the derivation.
        // HKDF-SHA256(ikm=[7;32], salt="", info="HIPPIUS_HOST_ATTESTOR_KEY_V1", 32).
        assert_eq!(
            hex::encode(seed.as_ref()),
            "65a7e2925ee7b006e14ef3ac5c99755d1b9907f500aba00f81c937c9d2bf4066"
        );
        assert_eq!(
            hex::encode(signer.pubkey()),
            "3279b99440bf8000a8d8f0c5ceed6648e0ef060b4c07e16d8c1a86cffeaad451"
        );
    }

    #[test]
    fn signs_and_verifies_with_its_own_pubkey() {
        let snp_derived_key: SnpDerivedKey = Zeroizing::new([3u8; 32]);
        let signer = HostAttestorSigner::from_snp_derived_key(&snp_derived_key).unwrap();
        let msg = b"host-alive-beacon-body";
        let sig_bytes = signer.sign(msg);
        assert_eq!(sig_bytes.len(), SIG_LEN);

        let sig = Signature::from_bytes(&sig_bytes);
        signer
            .verifying_key()
            .verify(msg, &sig)
            .expect("the signer's own public key must verify its signature");
    }

    #[test]
    fn distinct_derived_keys_yield_distinct_signers() {
        // A regression to a fixed/ignored ikm would make every host share
        // one identity — catastrophic for per-host enrollment.
        let a = HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([1u8; 32])).unwrap();
        let b = HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([2u8; 32])).unwrap();
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let signer = HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([4u8; 32])).unwrap();
        let other = HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([5u8; 32])).unwrap();
        let msg = b"beacon";
        let sig = Signature::from_bytes(&signer.sign(msg));
        assert!(other.verifying_key().verify(msg, &sig).is_err());
    }

    /// End-to-end: mock provider -> fetch -> HKDF -> Ed25519, all
    /// deterministic and with no hardware.
    #[test]
    fn mock_provider_through_hkdf_to_ed25519_is_deterministic() {
        let mock = MockDerivedKeyProvider::new([9u8; 32]);
        let dk1 = fetch_host_attestor_derived_key(&mock).unwrap();
        let s1 = HostAttestorSigner::from_snp_derived_key(&dk1).unwrap();

        let dk2 = fetch_host_attestor_derived_key(&mock).unwrap();
        let s2 = HostAttestorSigner::from_snp_derived_key(&dk2).unwrap();

        assert_eq!(
            s1.pubkey(),
            s2.pubkey(),
            "same derived key => same identity"
        );
    }
}
