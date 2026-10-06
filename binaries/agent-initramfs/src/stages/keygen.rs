//! Stage 2 — generate the guest's X25519 ephemeral keypair (§20).
//!
//! The secret half lives in a [`Zeroizing`] wrapper that wipes on
//! drop; the public half is the 32-byte little-endian Curve25519 point
//! copied into `REPORT_DATA[32..64]` ([`crate::stages::snp_report::report_data`]).
//!
//! ## Memory hygiene
//!
//! The secret is a `Box<Zeroizing<[u8; 32]>>` — heap-allocated, so its
//! bytes have a **stable address**: moving an `Ephemeral`, or
//! returning the secret from [`Ephemeral::into_secret`], moves only
//! the box pointer and never copies the scalar to a fresh stack /
//! struct slot that would escape the `Zeroizing` wipe. The one
//! unavoidable transient is the `[u8; 32]` `StaticSecret::to_bytes`
//! yields at generation — consumed straight into the box on the next
//! line.
//!
//! `mlock(2)` / `madvise(MADV_DONTDUMP)` would additionally keep the
//! boxed page off swap and out of core dumps. Both need the raw
//! syscall, which the workspace `unsafe_code = "forbid"` lint makes a
//! compile error in-crate — so swap-leak / core-dump exposure is
//! closed at the deployment layer instead: the §F measured guest image
//! runs with swap disabled and core dumps off (strictly stronger than
//! per-page `mlock`, since it also covers the keygen transient above).
//!
//! Both fields are PRIVATE: downstream code reaches the public half
//! via [`Ephemeral::public_bytes`] and consumes the secret via
//! [`Ephemeral::into_secret`] (only the §21 verify stage).

use crate::pipeline::AgentError;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Guest ephemeral X25519 keypair. The public half is the 32-byte
/// little-endian Curve25519 point that is copied into
/// `REPORT_DATA[32..64]`; the secret half is the scalar used by the
/// guest to HPKE-unwrap the KBS-released secrets.
///
/// `Debug` is intentionally **not** derived — production code must
/// never log a keypair, and the compiler should refuse a `dbg!()` on
/// one.
pub struct Ephemeral {
    /// X25519 public key — sent ONLY via the SNP attestation report
    /// (§20 "Only the 32-byte public key leaves the guest — via
    /// `REPORT_DATA` only"). Private field: downstream code must use
    /// [`Self::public_bytes`].
    public: [u8; 32],
    /// X25519 secret scalar. `Box<Zeroizing<…>>` — heap-allocated for
    /// a stable address (see the module-level "Memory hygiene" docs),
    /// `Zeroizing` so the bytes wipe on drop. Private field; consumed
    /// (and wiped) by [`Self::into_secret`] in the §21 verify stage.
    secret: Box<Zeroizing<[u8; 32]>>,
}

impl Ephemeral {
    /// Non-secret 32-byte public key. Safe to copy / log length / fold
    /// into `REPORT_DATA[32..64]`.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Consume the keypair and surface the wrapped secret scalar. The
    /// returned `Box<Zeroizing<…>>` guarantees a wipe on drop — call
    /// sites MUST let the value drop within the same scope (no
    /// `mem::forget`, no moves into long-lived structs). Returning the
    /// box (not the bare scalar) keeps the bytes address-stable.
    ///
    /// The only intended call site is
    /// [`crate::stages::verify::verify_and_unwrap`].
    pub fn into_secret(self) -> Box<Zeroizing<[u8; 32]>> {
        self.secret
    }
}

/// Generate a fresh single-use X25519 keypair.
///
/// Implementation: [`x25519_dalek::StaticSecret::random_from_rng`]
/// reads 32 raw bytes from [`OsRng`] (kernel CSPRNG via
/// `getrandom(2)`) and stores them unmodified — RFC 7748 clamping
/// is applied internally by `x25519-dalek` at scalar-multiplication
/// time, NOT at construction. The public key is derived via
/// [`PublicKey::from(&StaticSecret)`] (which performs the clamped
/// scalar multiplication).
///
/// We then extract the raw 32-byte secret via `StaticSecret::to_bytes`
/// (a transient stack copy — the `sk` itself drops at end of function
/// scope, and the `zeroize` feature on `x25519-dalek` wipes the inner
/// buffer at that point) and wrap it in our own `Zeroizing` so the
/// same wipe-on-drop guarantee follows the bytes for the rest of the
/// `Ephemeral` lifetime.
///
/// The function returns [`AgentError`] for signature compatibility
/// with the rest of the §21 pipeline, but the only failure path is
/// [`OsRng`] panicking (which would be a kernel-level failure — the
/// guest is unbootable anyway).
pub fn generate_ephemeral() -> Result<Ephemeral, AgentError> {
    let sk = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&sk).to_bytes();
    // `to_bytes()` returns the raw 32-byte secret as `[u8; 32]`
    // (the one unavoidable transient — see the module "Memory
    // hygiene" docs). It is consumed straight into a heap-boxed
    // `Zeroizing` on this line; from here on every move of the
    // `Ephemeral` moves only the box pointer, never the scalar.
    let secret = Box::new(Zeroizing::new(sk.to_bytes()));
    Ok(Ephemeral { public, secret })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_real_x25519_keypair() {
        // Both halves are 32 bytes by construction (the types pin
        // it); the assertion catches a future drift in the
        // x25519-dalek API. The secret is NOT clamped here — RFC 7748
        // clamping is applied internally by x25519-dalek at DH time
        // (see `static_secrets` impl), so the raw bytes round-trip
        // through `into_secret()` unmodified for the HPKE unwrap
        // consumer in `hippius_guest::verify_and_unwrap_release`.
        let k = generate_ephemeral().unwrap();
        assert_eq!(k.public_bytes().len(), 32);
        let secret = k.into_secret();
        assert_eq!(secret.len(), 32);
        // Sanity: a fresh OS-RNG draw is not all-zero (probability
        // ~2⁻²⁵⁶ of false positive — effectively impossible).
        assert_ne!(&secret[..], &[0u8; 32][..]);
    }

    #[test]
    fn distinct_calls_produce_distinct_keypairs() {
        // Two calls must yield different keypairs — a regression to
        // a deterministic RNG / hardcoded seed would catastrophically
        // weaken §20 (every guest would derive the same secret).
        let k1 = generate_ephemeral().unwrap();
        let k2 = generate_ephemeral().unwrap();
        assert_ne!(k1.public_bytes(), k2.public_bytes());
        // Compare secrets too — different pub almost certainly
        // implies different secret, but pin both halves so a
        // pathological RNG can't slip past.
        let s1 = k1.into_secret();
        let s2 = k2.into_secret();
        assert_ne!(&s1[..], &s2[..]);
    }

    #[test]
    fn public_key_matches_secret_scalar() {
        // The pub key MUST be `[sk]·G` — otherwise HPKE unwrap on the
        // KBS-released ciphertext fails. Re-derive from the secret
        // and check equality.
        let k = generate_ephemeral().unwrap();
        let pub_observed = *k.public_bytes();
        let secret = k.into_secret();
        // `**` — deref the `Box`, then the `Zeroizing`, to the `[u8; 32]`.
        let sk = StaticSecret::from(**secret);
        let pub_rederived = PublicKey::from(&sk).to_bytes();
        assert_eq!(pub_observed, pub_rederived);
    }
}
