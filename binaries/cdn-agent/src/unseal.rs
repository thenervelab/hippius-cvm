//! The `cdn-fleet` keyring and libsodium sealed boxes.
//!
//! The KBS releases every live fleet key version at boot (CDN plan K2,
//! G1); `guest-release` writes each X25519 secret to tmpfs as
//! `v<n>.key`, and systemd hands the directory to the agent as
//! credentials (`<id>_v<n>.key`). There is no in-guest rotation: the
//! keyring is read once at start and lives in RAM until exit.
//!
//! The backend seals with PyNaCl's `SealedBox` (`crypto_box_seal`):
//! `ephemeral_pk ‖ XSalsa20-Poly1305(...)`. `crypto_box`'s `seal`
//! feature is byte-compatible; `test_vectors/cdn/vectors.json` pins it.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use crypto_box::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::error::{CdnError, Result};
use crate::identity::read_secret_32;

/// More versions than this in one keyring is a provisioning bug.
const MAX_FLEET_KEYS: usize = 16;

/// Largest sealed blob accepted (a certificate key or a token is far
/// smaller; this bounds memory per entry).
pub const MAX_SEALED_LEN: usize = 64 * 1024;

/// Every fleet key version this node holds. `SecretKey` zeroizes on drop.
pub struct FleetKeyring {
    keys: BTreeMap<u32, SecretKey>,
}

impl FleetKeyring {
    /// Load every `v<n>.key` / `<id>_v<n>.key` in `dir`. Other files are
    /// ignored. Fails closed on an unreadable, loose-mode or malformed key
    /// file, on a duplicated version, and on an empty keyring.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let entries = fs::read_dir(dir).map_err(|_| CdnError::Identity("fleet-dir-read"))?;
        let mut keys = BTreeMap::new();
        for entry in entries {
            let entry = entry.map_err(|_| CdnError::Identity("fleet-dir-read"))?;
            let name = entry.file_name();
            let Some(version) = name.to_str().and_then(parse_key_file_name) else {
                continue;
            };
            let secret = read_secret_32(&entry.path())?;
            if keys
                .insert(version, SecretKey::from_bytes(*secret))
                .is_some()
            {
                return Err(CdnError::Identity("fleet-key-duplicate-version"));
            }
            if keys.len() > MAX_FLEET_KEYS {
                return Err(CdnError::Identity("fleet-key-too-many"));
            }
        }
        if keys.is_empty() {
            return Err(CdnError::Identity("fleet-key-none"));
        }
        Ok(Self { keys })
    }

    /// Build from raw secrets (tests and tools).
    pub fn from_secrets(secrets: impl IntoIterator<Item = (u32, [u8; 32])>) -> Self {
        Self {
            keys: secrets
                .into_iter()
                .map(|(v, s)| (v, SecretKey::from_bytes(s)))
                .collect(),
        }
    }

    pub fn versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }

    pub fn holds(&self, version: u32) -> bool {
        self.keys.contains_key(&version)
    }

    /// The X25519 public half of `version`.
    pub fn public_key(&self, version: u32) -> Option<[u8; 32]> {
        self.keys.get(&version).map(|k| *k.public_key().as_bytes())
    }

    /// Open a sealed box with `version`. The plaintext wipes on drop.
    pub fn open(&self, version: u32, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() > MAX_SEALED_LEN {
            return Err(CdnError::Unseal("sealed-too-large"));
        }
        let key = self
            .keys
            .get(&version)
            .ok_or(CdnError::Unseal("fleet-version-not-held"))?;
        key.unseal(sealed)
            .map(Zeroizing::new)
            .map_err(|_| CdnError::Unseal("open-failed"))
    }

    /// [`open`](Self::open) a standard-base64 blob.
    pub fn open_b64(&self, version: u32, sealed_b64: &str) -> Result<Zeroizing<Vec<u8>>> {
        if sealed_b64.len() > MAX_SEALED_LEN * 4 / 3 + 4 {
            return Err(CdnError::Unseal("sealed-too-large"));
        }
        let sealed = B64
            .decode(sealed_b64)
            .map_err(|_| CdnError::Unseal("sealed-not-base64"))?;
        self.open(version, &sealed)
    }
}

/// Seal `plaintext` to a fleet public key (I4 uploads certificate keys
/// sealed to the active version).
pub fn seal_to(public_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    PublicKey::from(*public_key)
        .seal(&mut rand_core::OsRng, plaintext)
        .map_err(|_| CdnError::Unseal("seal-failed"))
}

/// `v<n>.key` or `<anything>_v<n>.key`, `n` ≥ 1, canonical decimal.
fn parse_key_file_name(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".key")?;
    let tail = match stem.rsplit_once('_') {
        Some((_, t)) => t,
        None => stem,
    };
    let digits = tail.strip_prefix('v')?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn vectors() -> serde_json::Value {
        let raw = include_str!("../../../test_vectors/cdn/vectors.json");
        serde_json::from_str::<serde_json::Value>(raw).unwrap()["sealed_box"].clone()
    }

    fn vector_keyring() -> (FleetKeyring, serde_json::Value) {
        let v = vectors();
        let secret: [u8; 32] = hex::decode(v["fleet_secret_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        (FleetKeyring::from_secrets([(1, secret)]), v)
    }

    #[test]
    fn opens_pynacl_sealed_boxes() {
        let (ring, v) = vector_keyring();
        assert_eq!(
            hex::encode(ring.public_key(1).unwrap()),
            v["fleet_public_hex"].as_str().unwrap()
        );
        let cases = v["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        for case in cases {
            let want = B64.decode(case["plaintext_b64"].as_str().unwrap()).unwrap();
            let got = ring
                .open_b64(1, case["sealed_b64"].as_str().unwrap())
                .unwrap();
            assert_eq!(got.as_slice(), want.as_slice());
        }
    }

    #[test]
    fn refuses_tampered_wrong_version_and_garbage() {
        let (ring, v) = vector_keyring();
        let sealed_b64 = v["cases"][1]["sealed_b64"].as_str().unwrap();
        let mut sealed = B64.decode(sealed_b64).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(ring.open(1, &sealed).unwrap_err().class(), "open-failed");
        assert_eq!(
            ring.open_b64(2, sealed_b64).unwrap_err().class(),
            "fleet-version-not-held"
        );
        assert_eq!(
            ring.open_b64(1, "!!").unwrap_err().class(),
            "sealed-not-base64"
        );
        assert_eq!(ring.open(1, &[0u8; 10]).unwrap_err().class(), "open-failed");
        let big = vec![0u8; MAX_SEALED_LEN + 1];
        assert_eq!(ring.open(1, &big).unwrap_err().class(), "sealed-too-large");
    }

    #[test]
    fn seal_then_open_round_trips() {
        let ring = FleetKeyring::from_secrets([(4, [42u8; 32])]);
        let sealed = seal_to(&ring.public_key(4).unwrap(), b"account key").unwrap();
        assert_eq!(ring.open(4, &sealed).unwrap().as_slice(), b"account key");
    }

    #[test]
    fn key_file_names() {
        assert_eq!(parse_key_file_name("v1.key"), Some(1));
        assert_eq!(parse_key_file_name("cdn-fleet_v12.key"), Some(12));
        for bad in [
            "v0.key",
            "v01.key",
            "v.key",
            "lifecycle.key",
            "v1.pem",
            "x_v1x.key",
        ] {
            assert_eq!(parse_key_file_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn load_dir_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            FleetKeyring::load_dir(dir.path()).err().unwrap().class(),
            "fleet-key-none"
        );
        let write = |name: &str, mode: u32| {
            let p = dir.path().join(name);
            fs::write(&p, [1u8; 32]).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        };
        write("lifecycle.key", 0o400);
        write("cdn-fleet_v1.key", 0o400);
        write("cdn-fleet_v2.key", 0o400);
        let ring = FleetKeyring::load_dir(dir.path()).unwrap();
        assert_eq!(ring.versions(), vec![1, 2]);

        write("v2.key", 0o400);
        assert_eq!(
            FleetKeyring::load_dir(dir.path()).err().unwrap().class(),
            "fleet-key-duplicate-version"
        );
        fs::remove_file(dir.path().join("v2.key")).unwrap();
        write("v3.key", 0o644);
        assert_eq!(
            FleetKeyring::load_dir(dir.path()).err().unwrap().class(),
            "secret-file-permissions"
        );
    }
}
