//! Edge telemetry signing key — Ed25519, boot-generated, in-memory
//! only (PR-H6, §15 / §B Q7).
//!
//! ## Lifecycle (parallels the KBS response-signing key)
//!
//! - **Boot-generated.** [`EdgeSigner::generate`] draws a fresh
//!   keypair from the OS CSPRNG (`getrandom(2)`) at process start.
//!   The private key is NEVER loaded from Vault, never read from
//!   disk, never written anywhere. It is generated in-place on the
//!   Edge instance — the §B Q7 "in-CVM-generated, instance-locked"
//!   pattern. **Rotation = redeploy the instance**: a new boot is a
//!   new key; the old key simply ceases to exist when its process
//!   ends. There is deliberately no rotation endpoint and no key
//!   import path.
//! - **Heap-boxed.** The key lives in a `Box<SigningKey>`, so its
//!   bytes have a stable address: moving an `EdgeSigner` only moves
//!   the box pointer and never leaves a stale copy of the secret at
//!   an old stack/struct slot.
//! - **Zeroized on shutdown.** `ed25519-dalek`'s `zeroize` feature
//!   makes `SigningKey: ZeroizeOnDrop` — the secret bytes are wiped
//!   when the box drops, i.e. on a clean process exit.
//!
//! ## Memory protection — and the `mlock` note
//!
//! Per-page `mlock(2)` / `madvise(MADV_DONTDUMP)` would keep the key
//! off swap and out of core dumps. Both need the raw syscall, and the
//! workspace lint `unsafe_code = "forbid"` makes that a hard compile
//! error in any workspace crate — the same constraint already
//! documented in `agent-initramfs/src/stages/keygen.rs` for the guest
//! keypair. Swap-leak and core-dump exposure are therefore closed at
//! the **deployment layer**: the §F measured Edge image runs with
//! swap disabled and core dumps off. That is strictly stronger than
//! per-allocation `mlock` — it also covers the transient stack copies
//! made during key generation and signing, which `mlock` on the boxed
//! allocation could never reach.
//!
//! ## No plaintext-key path
//!
//! `EdgeSigner` derives **no `Debug`** — the compiler refuses to
//! format it, so it cannot land in a log line. There is **no getter
//! that returns the secret bytes**: the only operations are
//! [`EdgeSigner::sign`] (a detached signature) and the public-key
//! accessors. The private scalar cannot be copied out, logged, or
//! serialised.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;

/// The Edge instance's telemetry signing key.
///
/// Construct exactly once per process via [`EdgeSigner::generate`].
/// Wrap the result in an `Arc` to share it between the telemetry
/// recorder and the `/v1/edge/pubkey` endpoint.
///
/// No `Debug`, no `Clone` — a key is single-instance and unprintable
/// by construction.
pub struct EdgeSigner {
    /// Boxed for address stability (see module docs). `SigningKey`
    /// zeroizes on drop via the `ed25519-dalek` `zeroize` feature.
    /// Private: there is no path from outside this module to the
    /// secret bytes.
    key: Box<SigningKey>,
}

impl EdgeSigner {
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// The only failure mode is `OsRng` itself failing, which
    /// `getrandom` surfaces as a panic — a kernel-entropy failure
    /// that means the host is unusable anyway (same posture as
    /// `agent-initramfs` keygen).
    pub fn generate() -> Self {
        Self {
            key: Box::new(SigningKey::generate(&mut OsRng)),
        }
    }

    /// The 32-byte Ed25519 public key. This is the ONLY part of the
    /// keypair that leaves the process — published via
    /// `/v1/edge/pubkey` for Sentinel + the Validator to verify
    /// telemetry signatures.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The public key as an `ed25519-dalek` [`VerifyingKey`] — for
    /// in-process verification (the integration tests use this).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign `message`, returning the detached 64-byte Ed25519
    /// signature. The private key never leaves this method.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn generated_signature_verifies_under_its_own_pubkey() {
        let signer = EdgeSigner::generate();
        let msg = b"edge-telemetry-body";
        let sig = Signature::from_bytes(&signer.sign(msg));
        assert!(signer.verifying_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn signature_fails_under_a_different_key() {
        let a = EdgeSigner::generate();
        let b = EdgeSigner::generate();
        let msg = b"edge-telemetry-body";
        let sig = Signature::from_bytes(&a.sign(msg));
        assert!(b.verifying_key().verify(msg, &sig).is_err());
    }

    #[test]
    fn distinct_boots_produce_distinct_keys() {
        // "Rotation = redeploy": two `generate()` calls (two boots)
        // must yield different keypairs.
        let a = EdgeSigner::generate();
        let b = EdgeSigner::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn public_key_accessors_agree() {
        let signer = EdgeSigner::generate();
        assert_eq!(signer.public_key_bytes(), signer.verifying_key().to_bytes());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let signer = EdgeSigner::generate();
        let sig = Signature::from_bytes(&signer.sign(b"original"));
        assert!(signer.verifying_key().verify(b"tampered", &sig).is_err());
    }
}
