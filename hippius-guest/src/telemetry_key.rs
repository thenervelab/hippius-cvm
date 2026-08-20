//! Derive the tenant telemetry signing key from the guest lifecycle key.
//!
//! Uptime billing needs the tenant guest to sign `ServedDeliveryReceipt`s
//! with a key vali can verify. Rather than mint + release + attest a
//! SECOND per-VM secret, the telemetry signing key is **derived** from the
//! §7 lifecycle key that vali already generates and the KBS already
//! releases to the attested guest:
//!
//! ```text
//! telemetry_seed = HKDF-SHA256(ikm = lifecycle_seed,
//!                              salt = "",
//!                              info = TELEMETRY_KEY_DERIVE_DOMAIN,
//!                              L    = 32)
//! ```
//!
//! Both sides run THIS function on the same 32-byte lifecycle seed, so the
//! keypair is identical without any extra key exchange:
//!
//! - **vali** (via the `derive-telemetry-key` shell-out) derives the
//!   PUBLIC key at launch to provision the telemetry source it verifies
//!   receipts against;
//! - **the guest** (`agent-tenant-telemetry`) derives the SAME key from the
//!   lifecycle seed it received in the §21 release, and signs receipts.
//!
//! HKDF is one-way + domain-separated, so the telemetry key never exposes
//! the lifecycle seed. The untrusted miner holds neither seed and cannot
//! forge a receipt; vali is already the billing authority, so deriving the
//! key it verifies against from a secret it generated changes no trust.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF `info` domain separator — binds the derived key to this exact
/// purpose + version. A different label yields a completely different
/// key, so the telemetry key can never be confused with any other secret
/// derived from the same lifecycle seed.
pub const TELEMETRY_KEY_DERIVE_DOMAIN: &[u8] = b"HIPPIUS_TENANT_TELEMETRY_KEY_V1";

/// Derive the 32-byte telemetry Ed25519 signing seed from the 32-byte
/// lifecycle seed. Deterministic + pure — identical output on vali and in
/// the guest for the same input. The returned seed is secret-bearing
/// (`Zeroizing` wipes it on drop).
pub fn derive_telemetry_signing_seed(lifecycle_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, lifecycle_seed);
    let mut out: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    // `expand` only errors when the requested length exceeds 255·HashLen;
    // 32 ≤ 255·32, so this is infallible for a fixed 32-byte output.
    #[allow(clippy::expect_used)]
    hk.expand(TELEMETRY_KEY_DERIVE_DOMAIN, out.as_mut())
        .expect("HKDF expand of 32 bytes ≤ 255·HashLen is infallible");
    out
}

/// Derive the telemetry `SigningKey` from the lifecycle seed.
pub fn derive_telemetry_signing_key(lifecycle_seed: &[u8; 32]) -> SigningKey {
    let seed = derive_telemetry_signing_seed(lifecycle_seed);
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A pinned known-answer vector: the derivation is a wire contract
    // between vali (shell-out) and the guest, so its output for a fixed
    // lifecycle seed must NEVER change. If this vector breaks, every
    // deployed guest's receipts stop verifying.
    #[test]
    fn derivation_is_a_stable_known_answer() {
        let lifecycle = [7u8; 32];
        let seed = derive_telemetry_signing_seed(&lifecycle);
        // HKDF-SHA256(ikm=[7;32], salt="", info="HIPPIUS_TENANT_TELEMETRY_KEY_V1", 32).
        assert_eq!(
            hex::encode(seed.as_ref()),
            "3d86f59136c2a2b5180b13b78dc3a83a805ae81ea47a0f480e74946311cbd4be",
        );
    }

    #[test]
    fn derivation_is_deterministic_and_domain_separated() {
        let lifecycle = [42u8; 32];
        let a = derive_telemetry_signing_seed(&lifecycle);
        let b = derive_telemetry_signing_seed(&lifecycle);
        assert_eq!(a.as_ref(), b.as_ref(), "same input ⇒ same key");

        // A different lifecycle seed ⇒ a different telemetry key.
        let other = derive_telemetry_signing_seed(&[43u8; 32]);
        assert_ne!(a.as_ref(), other.as_ref());

        // The telemetry seed is NOT the lifecycle seed (one-way).
        assert_ne!(a.as_ref(), &lifecycle);
    }

    #[test]
    fn signing_key_matches_the_seed() {
        let lifecycle = [1u8; 32];
        let seed = derive_telemetry_signing_seed(&lifecycle);
        let key = derive_telemetry_signing_key(&lifecycle);
        assert_eq!(key.to_bytes(), *seed.as_ref());
    }
}
