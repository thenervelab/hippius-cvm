//! Pinned `allowed_userdata_digest` preimage (ARCHITECTURE.md §20).
//!
//! Authoritative definition: L1 (the minter) and the KBS MUST compute
//! this byte-identically. The implementation streams length-prefixed
//! fields into SHA-256 directly so the user-data plaintext is never
//! copied into a non-zeroizing heap buffer.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use sha2::{Digest, Sha256};

pub const USERDATA_DIGEST_DOMAIN: &str = "HIPPIUS_USERDATA_DIGEST_V1";

#[inline]
fn put_framed(h: &mut Sha256, s: &[u8]) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s);
}

/// Compute the `allowed_userdata_digest` over the canonical preimage.
/// Caller passes a borrowed `plaintext` slice (typically backed by a
/// `Zeroizing<Vec<u8>>` on the KBS side; L1 may zeroize similarly).
///
/// THREE parties compute this, and they must agree byte-for-byte:
/// L1 (vali) mints it into the ticket, the KBS recomputes it over the
/// bytes it unwrapped, and the GUEST re-derives it a third time over the
/// plaintext it receives (`hippius_guest::release`) and refuses the
/// release on a mismatch. The guest half is baked into every tenant
/// image, so the preimage cannot be changed on the server side alone —
/// doing so denies every release, on the KBS or in the guest, until the
/// whole fleet is re-baked.
///
/// It is always the PLAINTEXT, never the Transit ciphertext the value is
/// stored as: the guest never sees the stored form, so it could not
/// verify anything else. The consequence for whoever mints a ticket is
/// that they must hold the plaintext at mint time — see
/// `launch_jobs.start_launch`, which is why vali computes every digest a
/// VM will ever need at intake, while it still has it.
#[allow(clippy::too_many_arguments)]
pub fn userdata_digest(
    tenant_id: &str,
    vm_id: &str,
    ticket_id: &str,
    secret_type: &str,
    path: &str,
    version: u64,
    plaintext: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    put_framed(&mut h, USERDATA_DIGEST_DOMAIN.as_bytes());
    put_framed(&mut h, tenant_id.as_bytes());
    put_framed(&mut h, vm_id.as_bytes());
    put_framed(&mut h, ticket_id.as_bytes());
    put_framed(&mut h, secret_type.as_bytes());
    put_framed(&mut h, path.as_bytes());
    h.update(version.to_le_bytes());
    put_framed(&mut h, plaintext);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let d1 = userdata_digest("t", "v", "tk", "userdata", "/p", 1, b"plain");
        let d2 = userdata_digest("t", "v", "tk", "userdata", "/p", 1, b"plain");
        assert_eq!(d1, d2);
        // Any field change ⇒ different digest.
        assert_ne!(
            d1,
            userdata_digest("OTHER", "v", "tk", "userdata", "/p", 1, b"plain")
        );
        assert_ne!(
            d1,
            userdata_digest("t", "v", "tk", "luks", "/p", 1, b"plain")
        );
        assert_ne!(
            d1,
            userdata_digest("t", "v", "tk", "userdata", "/p", 2, b"plain")
        );
        assert_ne!(
            d1,
            userdata_digest("t", "v", "tk", "userdata", "/p", 1, b"PLAIN")
        );
    }

    #[test]
    fn length_prefix_disambiguates_concatenation_attacks() {
        // Without length-prefix, ("ab","c") and ("a","bc") would collide.
        let a = userdata_digest("ab", "c", "tk", "ud", "/p", 1, b"");
        let b = userdata_digest("a", "bc", "tk", "ud", "/p", 1, b"");
        assert_ne!(a, b);
    }
}
