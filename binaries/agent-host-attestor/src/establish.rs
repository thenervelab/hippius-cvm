//! Host-attestor key establishment.
//!
//! Unlike the tenant telemetry agent (which HKDF-derives its key from a
//! KBS-released lifecycle seed), the host attestor has no released
//! secret to start from: it fetches a **measurement-bound VCEK derived
//! key** from `/dev/sev-guest` ONCE ([`crate::derived_key`]), caches it
//! only long enough to HKDF-stretch it into the per-boot Ed25519
//! [`HostAttestorSigner`], and never re-invokes the device for a key
//! again. The derived key lives in a wiping [`Zeroizing`] buffer that is
//! dropped (and scrubbed) the moment this function returns — from then
//! on the secret exists only inside the signer's boxed
//! `ZeroizeOnDrop` `SigningKey`.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! This is the FIRST of the two `/dev/sev-guest` interactions per boot
//! (the second is the enrollment report in [`crate::enroll`]). They MUST
//! NOT race — a bad request poisons the shared serialized channel. This
//! function fully completes and returns an OWNED [`Established`] (no
//! borrow of the device) before the caller opens the device again for
//! the report, so the transient `Firmware` handle inside the provider is
//! closed first. The single main thread drives both, strictly in order;
//! nothing runs them concurrently.
//!
//! Fail-closed: a derived-key or keygen failure is an `Err` (the agent
//! exits non-zero; it is never restarted into a half-established state,
//! and there is no random-key fallback — that would break the stable
//! per-boot host identity).

use crate::derived_key::{fetch_host_attestor_derived_key, DerivedKeyProvider};
use crate::error::Result;
use crate::signer::HostAttestorSigner;

/// The established host-attestor identity.
pub struct Established {
    /// The per-boot Ed25519 signer, holding the RAM-only key HKDF-derived
    /// from the measurement-bound SNP derived key. Dropping it zeroizes
    /// the key.
    pub signer: HostAttestorSigner,
}

impl Established {
    /// The 32-byte Ed25519 public key the enrollment binds and every
    /// beacon is signed by.
    pub fn pubkey(&self) -> [u8; crate::signer::KEY_LEN] {
        self.signer.pubkey()
    }
}

/// Fetch the SNP derived key ONCE and build the host-attestor signer.
///
/// The `provider` is invoked exactly once (via
/// [`fetch_host_attestor_derived_key`], which pins the R1
/// measurement-bound, `message_version = Some(1)` request); the derived
/// key never leaves this function un-wrapped.
pub fn establish(provider: &dyn DerivedKeyProvider) -> Result<Established> {
    let snp_derived_key = fetch_host_attestor_derived_key(provider)?;
    let signer = HostAttestorSigner::from_snp_derived_key(&snp_derived_key)?;
    // `snp_derived_key` (a `Zeroizing<[u8; 32]>`) drops here — scrubbed.
    Ok(Established { signer })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::derived_key::MockDerivedKeyProvider;

    #[test]
    fn establish_builds_the_signer_for_the_derived_key() {
        let provider = MockDerivedKeyProvider::new([7u8; 32]);
        let est = establish(&provider).unwrap();
        // The established pubkey MUST equal what the signer derives from
        // the same SNP derived key (the KBS enrols this exact key).
        let expected =
            HostAttestorSigner::from_snp_derived_key(&zeroize::Zeroizing::new([7u8; 32])).unwrap();
        assert_eq!(est.pubkey(), expected.pubkey());
        // And the request the provider saw was the R1 measurement-bound one.
        let captured = provider.captured_request().expect("request captured");
        assert!(captured.selects_vcek());
        assert!(captured.measurement_only);
        assert_eq!(captured.message_version, Some(1));
    }

    #[test]
    fn establish_fails_closed_on_a_derive_failure() {
        let provider = MockDerivedKeyProvider::failing();
        assert!(
            establish(&provider).is_err(),
            "a derived-key failure must propagate, never a random-key fallback"
        );
    }

    #[test]
    fn distinct_derived_keys_yield_distinct_identities() {
        let a = establish(&MockDerivedKeyProvider::new([1u8; 32])).unwrap();
        let b = establish(&MockDerivedKeyProvider::new([2u8; 32])).unwrap();
        assert_ne!(a.pubkey(), b.pubkey());
    }
}
