//! The §23 telemetry-key establishment.
//!
//! The telemetry signing key is NOT a fresh secret and is NOT minted by
//! the KBS: it is **HKDF-derived from the §7 lifecycle key** the KBS
//! already released to this attested guest (written to the tmpfs path in
//! the measured cmdline's `hippius.lifecycle_key_path`). vali — which
//! generated the lifecycle seed — derives the SAME telemetry key with the
//! same shared function (`hippius_guest::telemetry_key`) and provisions
//! the `TelemetrySource` it verifies our receipts against. No second key
//! exchange, no attestation round-trip, no KBS certificate.
//!
//! 1. read the 32-byte lifecycle seed from its tmpfs path;
//! 2. derive the telemetry `SigningKey` (`derive_telemetry_signing_key`);
//! 3. return the established signer.
//!
//! Fail-closed: a missing / malformed lifecycle key is an `Err` (the
//! agent exits non-zero; systemd does not restart it into a
//! half-established state).

use std::fs;

use hippius_guest::telemetry_key::derive_telemetry_signing_key;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::{Result, TelemetryError};
use crate::signer::{Ed25519TelemetrySigner, TelemetrySigner};

/// The established telemetry identity.
pub struct Established {
    /// The telemetry signer, holding the RAM-only Ed25519 key derived
    /// from the lifecycle key. Boxed `dyn` so the receipt loop depends on
    /// the trait. Dropping it zeroizes the key.
    pub signer: Box<dyn TelemetrySigner>,
}

/// Run §23 telemetry-key establishment (see module docs).
pub fn establish(cfg: &Config) -> Result<Established> {
    let seed = read_lifecycle_seed(&cfg.lifecycle_key_path)?;
    let signing_key = derive_telemetry_signing_key(&seed);
    Ok(Established {
        signer: Box::new(Ed25519TelemetrySigner::from_signing_key(signing_key)),
    })
}

/// Read the 32-byte lifecycle seed from `path`. Accepts either the raw
/// 32 bytes or a 64-char hex encoding (trimmed) — whichever the release
/// handler wrote — and fails closed on anything else.
fn read_lifecycle_seed(path: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(
        fs::read(path).map_err(|_| TelemetryError::Config("lifecycle-key-read-failed"))?,
    );

    // Raw 32-byte seed.
    if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
        return Ok(Zeroizing::new(arr));
    }

    // Otherwise try hex (trim trailing whitespace / newline).
    let trimmed = Zeroizing::new(
        String::from_utf8(raw.as_slice().to_vec())
            .map_err(|_| TelemetryError::Config("lifecycle-key-bad-format"))?,
    );
    let decoded = Zeroizing::new(
        hex::decode(trimmed.trim())
            .map_err(|_| TelemetryError::Config("lifecycle-key-bad-format"))?,
    );
    let arr = <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| TelemetryError::Config("lifecycle-key-wrong-length"))?;
    Ok(Zeroizing::new(arr))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_guest::telemetry_key::derive_telemetry_signing_key as derive;

    #[test]
    fn reads_a_raw_32_byte_seed_and_derives_the_shared_key() {
        let path = std::env::temp_dir().join("hippius-test-lifecycle-raw.key");
        let seed = [7u8; 32];
        std::fs::write(&path, seed).unwrap();

        let got = read_lifecycle_seed(path.to_str().unwrap()).unwrap();
        assert_eq!(got.as_ref(), &seed);
        // The derived signer's pubkey MUST equal what vali derives from
        // the same seed — else every receipt fails verification.
        let signer = Ed25519TelemetrySigner::from_signing_key(derive(&seed));
        assert_eq!(signer.verifying_key(), derive(&seed).verifying_key());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn reads_a_hex_encoded_seed() {
        let path = std::env::temp_dir().join("hippius-test-lifecycle-hex.key");
        let seed = [9u8; 32];
        std::fs::write(&path, format!("{}\n", hex::encode(seed))).unwrap();
        let got = read_lifecycle_seed(path.to_str().unwrap()).unwrap();
        assert_eq!(got.as_ref(), &seed);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fails_closed_on_a_missing_key() {
        assert!(read_lifecycle_seed("/nonexistent/hippius-lifecycle.key").is_err());
    }

    #[test]
    fn fails_closed_on_a_wrong_length_key() {
        let path = std::env::temp_dir().join("hippius-test-lifecycle-bad.key");
        std::fs::write(&path, b"not-a-valid-seed").unwrap();
        assert!(read_lifecycle_seed(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).ok();
    }
}
