//! Freshness nonces for enrollment + beacons.
//!
//! ## Enrollment — vali-minted single-use (PR-10)
//!
//! `REPORT_DATA[0..32]` of the **enrollment** SNP report MUST be a
//! **vali-chosen, single-use, freshness-bounded** nonce — never a
//! guest-generated value. Otherwise a guest could pre-generate a valid
//! enrollment report while attested and replay it later from a paused /
//! migrated / rehosted VM. [`ChallengeNonceSource`] pulls that nonce from
//! vali over the miner-agent vsock channel ([`crate::challenge`]) and is
//! **fail-closed**: if no fresh nonce arrives it errors, and the caller
//! fails the enrollment (the process exits non-zero). There is NO local
//! fallback — a self-generated enrollment nonce is exactly the hole this
//! closes.
//!
//! ## Beacons — locally-random (freshness via `seq` + `expiry`)
//!
//! The periodic liveness **beacons** keep a locally-random nonce
//! ([`OsRngNonceSource`]). A beacon's anti-replay does NOT rest on the
//! nonce: every beacon is Ed25519-signed by the enrolled key, carries a
//! strictly-monotonic `seq` (vali rejects a stale / replayed `seq` under a
//! row lock, PR-8) and a hard `expiry`. Minting a fresh vali nonce every
//! beat (default 60 s, per host) would burden the authority for no
//! security gain over `seq` + `expiry`, so the beacon nonce stays local +
//! honest entropy. This scope is deliberate and documented.
//!
//! The [`NonceSource`] trait keeps the enrollment/beacon split a matter of
//! which source is passed where, and lets the loop tests inject
//! deterministic nonces.

use crate::error::{HostAttestorError, Result};

/// Length of a freshness nonce (matches
/// [`hippius_types::host_attestor::DIGEST_LEN`]).
pub const NONCE_LEN: usize = 32;

/// Source of a single-use freshness nonce.
///
/// Enrollment uses [`ChallengeNonceSource`] (the vali-minted single-use
/// nonce, fail-closed); beacons use [`OsRngNonceSource`] (locally-random —
/// beacon freshness rests on `seq` + `expiry`, see the module docs). Every
/// call site depends on this trait, so which source is used where is the
/// only decision.
pub trait NonceSource {
    /// Draw one fresh 32-byte nonce. Fails closed — a nonce source that
    /// cannot produce entropy MUST NOT hand back a predictable value, and
    /// the vali-nonce source MUST NOT fall back to a local value.
    fn fresh_nonce(&self) -> Result<[u8; NONCE_LEN]>;
}

/// Locally-random nonce source — the OS CSPRNG (`getrandom`). Used for
/// the periodic **beacons** ONLY (beacon freshness rests on the monotonic
/// `seq` + hard `expiry`, not the nonce). The **enrollment** nonce is
/// vali-minted — see [`ChallengeNonceSource`].
#[derive(Debug, Default)]
pub struct OsRngNonceSource;

impl OsRngNonceSource {
    pub fn new() -> Self {
        Self
    }
}

impl NonceSource for OsRngNonceSource {
    fn fresh_nonce(&self) -> Result<[u8; NONCE_LEN]> {
        use rand_core::{OsRng, RngCore};

        let mut nonce = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| HostAttestorError::Nonce("os-rng"))?;
        Ok(nonce)
    }
}

/// The **enrollment** challenge source — pulls a fresh, single-use,
/// vali-minted nonce AND the vali-stamped `node_id` over the miner-agent
/// vsock challenge channel ([`crate::challenge`]). Bound to the attestor's
/// signer public key so vali can bind the minted nonce to `{node_id, pk}`
/// and later reject a nonce redirected to another host / key. FAIL-CLOSED:
/// [`fetch`](Self::fetch) errors if the fresh challenge cannot be
/// obtained — NEVER a local fallback (that would reopen the pre-generation
/// replay hole; and a locally-invented `node_id` would never match the
/// nonce binding vali holds).
///
/// Unlike [`OsRngNonceSource`] this is NOT a [`NonceSource`]: it returns a
/// `node_id` alongside the nonce, which the beacon-only nonce trait has no
/// slot for. The enrollment path calls [`fetch`](Self::fetch) directly.
#[derive(Debug, Clone)]
pub struct ChallengeNonceSource {
    /// Host vsock context id — [`crate::vsock_pusher::VSOCK_HOST_CID`].
    cid: u32,
    /// Host vsock port the miner-agent's challenge listener binds.
    port: u32,
    /// The attestor's Ed25519 signer public key the nonce binds to.
    signer_pubkey: [u8; NONCE_LEN],
}

impl ChallengeNonceSource {
    /// Build a source that dials `(cid, port)` and binds `signer_pubkey`.
    pub fn new(cid: u32, port: u32, signer_pubkey: [u8; NONCE_LEN]) -> Self {
        Self {
            cid,
            port,
            signer_pubkey,
        }
    }

    /// Pull one fresh vali-minted enrollment challenge (nonce + node_id).
    /// Fail-closed — no local fallback.
    pub fn fetch(&self) -> Result<crate::challenge::HostChallenge> {
        #[cfg(target_os = "linux")]
        {
            crate::challenge::fetch_challenge_vsock(self.cid, self.port, &self.signer_pubkey)
        }
        // Off-target the vsock family is unavailable — fail closed (the
        // real path only ever runs inside a Linux SEV-SNP guest).
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self.cid, self.port, self.signer_pubkey);
            Err(HostAttestorError::Nonce("challenge-unsupported-target"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn os_rng_yields_distinct_nonces() {
        let src = OsRngNonceSource::new();
        let a = src.fresh_nonce().unwrap();
        let b = src.fresh_nonce().unwrap();
        // Overwhelmingly likely distinct — a fixed/ignored draw would
        // make every enrollment + beacon carry the same nonce.
        assert_ne!(a, b);
    }
}
