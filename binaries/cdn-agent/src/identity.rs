//! The per-VM node credential (CDN plan A.6 / G.2).
//!
//! ```text
//! node_seed = HKDF-SHA256(ikm  = lifecycle_seed,
//!                         salt = "",
//!                         info = "HIPPIUS_CDN_NODE_KEY_V1",
//!                         L    = 32)
//! ```
//!
//! The lifecycle seed is the §7 key the KBS releases only to this VM's
//! attested launch. vali runs the same derivation to learn the public
//! key, and its CDN CA signs a 7-day X.509 (Ed25519) certificate over it
//! with the SAN URI `spiffe://<trust-domain>/cdn/<region>/<vm_id>/g<gen>`.
//! The certificate is public and reaches the node through the backend;
//! the node accepts one only if its public key is the derived key and its
//! SAN names this node. Renewal needs no KBS call.
//!
//! This is the same construction as `hippius-guest::telemetry_key` with
//! its own label. It is kept local to the agent so the guest-release
//! crates (folded into the tenant UKI) are not touched; the shared vector
//! lives in `test_vectors/cdn/vectors.json`.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_SIG_ED25519;
use zeroize::Zeroizing;

use crate::config::NodeIdentity;
use crate::error::{CdnError, Result};

/// HKDF `info` for the node key. Changing it changes every node key.
pub const NODE_KEY_DERIVE_DOMAIN: &[u8] = b"HIPPIUS_CDN_NODE_KEY_V1";

/// `SEQUENCE(81) { INTEGER 1, SEQUENCE { OID 1.3.101.112 },
/// OCTET STRING(34) { OCTET STRING(32) {` — then the 32-byte seed.
const PKCS8_V2_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// `[1] IMPLICIT BIT STRING(33) { 0 unused bits,` — then the public key.
const PKCS8_V2_PUBLIC_TAG: [u8; 3] = [0x81, 0x21, 0x00];
const PKCS8_LABEL: &str = "PRIVATE KEY";

/// Clock skew tolerated on a certificate's `notBefore`.
const NOT_BEFORE_SKEW_S: u64 = 300;

/// Largest certificate PEM accepted.
const MAX_CERT_PEM_LEN: usize = 16 * 1024;

/// Derive the 32-byte node signing seed from the lifecycle seed.
pub fn derive_node_seed(lifecycle_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, lifecycle_seed);
    let mut out: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    // `expand` only fails for L > 255·HashLen; 32 bytes cannot.
    #[allow(clippy::expect_used)]
    hk.expand(NODE_KEY_DERIVE_DOMAIN, out.as_mut())
        .expect("HKDF expand of 32 bytes is infallible");
    out
}

/// Read a 32-byte secret (raw, or 64 hex chars with optional trailing
/// whitespace). Refuses a file readable by other, or by a group: the keys
/// come from the release tmpfs (0400/0600) or systemd credentials.
///
/// systemd hands a credential to the unit's user as a root:root 0400 file
/// plus a POSIX ACL entry for that user, and `stat` reports the ACL mask
/// in the group bits: 0440. That one shape is accepted, and only inside
/// the unit's `$CREDENTIALS_DIRECTORY` (systemd's, private to the unit):
/// the mode bits cannot show which users an ACL names.
pub fn read_secret_32(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let meta = fs::metadata(path).map_err(|_| CdnError::Identity("secret-file-missing"))?;
    if !meta.is_file() {
        return Err(CdnError::Identity("secret-file-not-regular"));
    }
    let credential = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(std::path::PathBuf::from)
        .is_some_and(|dir| dir.is_absolute() && path.starts_with(&dir));
    if !secret_mode_ok(
        meta.permissions().mode(),
        meta.uid(),
        meta.gid(),
        credential,
    ) {
        return Err(CdnError::Identity("secret-file-permissions"));
    }
    if meta.len() > 256 {
        return Err(CdnError::Identity("secret-file-length"));
    }
    let raw = Zeroizing::new(fs::read(path).map_err(|_| CdnError::Identity("secret-file-read"))?);
    if let Ok(arr) = <[u8; 32]>::try_from(raw.as_slice()) {
        return Ok(Zeroizing::new(arr));
    }
    let text = std::str::from_utf8(raw.as_slice())
        .map_err(|_| CdnError::Identity("secret-file-format"))?;
    let decoded = Zeroizing::new(
        hex::decode(text.trim_end()).map_err(|_| CdnError::Identity("secret-file-format"))?,
    );
    let arr = <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| CdnError::Identity("secret-file-length"))?;
    Ok(Zeroizing::new(arr))
}

/// See [`read_secret_32`]: nothing for other, no group write or execute,
/// and a group read bit only on a root:root systemd credential.
fn secret_mode_ok(mode: u32, uid: u32, gid: u32, credential: bool) -> bool {
    if mode & 0o037 != 0 {
        return false;
    }
    mode & 0o040 == 0 || (credential && uid == 0 && gid == 0)
}

/// The node's Ed25519 key, in RAM only. `SigningKey` zeroizes on drop.
pub struct NodeKey {
    key: SigningKey,
}

impl NodeKey {
    /// Derive from the lifecycle seed.
    pub fn derive(lifecycle_seed: &[u8; 32]) -> Self {
        let seed = derive_node_seed(lifecycle_seed);
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Read the lifecycle key at `path` and derive.
    pub fn from_lifecycle_file(path: &Path) -> Result<Self> {
        let seed = read_secret_32(path)?;
        Ok(Self::derive(&seed))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// PKCS#8 v2 (RFC 8410 `OneAsymmetricKey`, with the public key) PEM
    /// of the private key, for the TLS client identity. Lives in RAM and
    /// wipes on drop. Encoded by hand: the DER is a fixed 16-byte header,
    /// the seed, a fixed 3-byte tag and the public key (see Cargo.toml for
    /// why the `pkcs8` feature is not used).
    pub fn pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        let mut der: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(83));
        der.extend_from_slice(&PKCS8_V2_ED25519_PREFIX);
        der.extend_from_slice(self.key.as_bytes());
        der.extend_from_slice(&PKCS8_V2_PUBLIC_TAG);
        der.extend_from_slice(&self.public_bytes());
        let b64 = Zeroizing::new(B64.encode(der.as_slice()));
        let mut pem = Zeroizing::new(String::with_capacity(b64.len() + 64));
        pem.push_str(&format!("-----BEGIN {PKCS8_LABEL}-----\n"));
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(
                std::str::from_utf8(line).map_err(|_| CdnError::Identity("pkcs8-encode"))?,
            );
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {PKCS8_LABEL}-----\n"));
        Ok(pem)
    }
}

/// A node certificate that passed [`verify_node_cert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCert {
    pub pem: String,
    pub generation: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Hex SHA-256 of the DER.
    pub fingerprint_hex: String,
}

/// Accept `pem` as this node's certificate only if:
/// - it is exactly one X.509 certificate with an Ed25519 key equal to
///   `public_key`;
/// - it carries exactly one SAN URI, equal to
///   `spiffe://<trust_domain>/cdn/<region>/<vm_id>/g<generation>` for
///   this node's region and vm id;
/// - it is valid at `now` (with a small `notBefore` skew).
///
/// The CA signature is the backend's check, not the node's: a forged
/// certificate over the node's own key gains an attacker nothing.
pub fn verify_node_cert(
    pem: &str,
    public_key: &[u8; 32],
    node: &NodeIdentity,
    trust_domain: &str,
    now: u64,
) -> Result<NodeCert> {
    if pem.len() > MAX_CERT_PEM_LEN || pem.matches("-----BEGIN").count() != 1 {
        return Err(CdnError::Identity("node-cert-shape"));
    }
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| CdnError::Identity("node-cert-pem"))?;
    if block.label != "CERTIFICATE" {
        return Err(CdnError::Identity("node-cert-pem"));
    }
    let (rest, cert) = x509_parser::parse_x509_certificate(&block.contents)
        .map_err(|_| CdnError::Identity("node-cert-der"))?;
    if !rest.is_empty() {
        return Err(CdnError::Identity("node-cert-der"));
    }

    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Err(CdnError::Identity("node-cert-not-ed25519"));
    }
    if spki.subject_public_key.data.as_ref() != public_key.as_slice() {
        return Err(CdnError::Identity("node-cert-key-mismatch"));
    }

    let not_before = u64::try_from(cert.validity().not_before.timestamp())
        .map_err(|_| CdnError::Identity("node-cert-validity"))?;
    let not_after = u64::try_from(cert.validity().not_after.timestamp())
        .map_err(|_| CdnError::Identity("node-cert-validity"))?;
    if not_before > now.saturating_add(NOT_BEFORE_SKEW_S) || not_after <= now {
        return Err(CdnError::Identity("node-cert-expired"));
    }

    let san = cert
        .subject_alternative_name()
        .map_err(|_| CdnError::Identity("node-cert-san"))?
        .ok_or(CdnError::Identity("node-cert-san"))?;
    let uris: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|g| match g {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
        .collect();
    let [uri] = uris.as_slice() else {
        return Err(CdnError::Identity("node-cert-san"));
    };
    let generation = parse_spiffe(uri, trust_domain, node)?;

    Ok(NodeCert {
        pem: pem.to_string(),
        generation,
        not_before,
        not_after,
        fingerprint_hex: hex::encode(Sha256::digest(&block.contents)),
    })
}

/// Parse `spiffe://<td>/cdn/<region>/<vm_id>/g<generation>`.
fn parse_spiffe(uri: &str, trust_domain: &str, node: &NodeIdentity) -> Result<u64> {
    let prefix = format!(
        "spiffe://{trust_domain}/cdn/{}/{}/g",
        node.region, node.vm_id
    );
    let digits = uri
        .strip_prefix(&prefix)
        .ok_or(CdnError::Identity("node-cert-wrong-node"))?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return Err(CdnError::Identity("node-cert-generation"));
    }
    digits
        .parse::<u64>()
        .map_err(|_| CdnError::Identity("node-cert-generation"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    /// Build a self-signed Ed25519 node certificate over `key` (tests).
    pub(crate) fn node_cert_pem(key: &NodeKey, san_uri: &str, days: i64) -> String {
        let pem = key.pkcs8_pem().unwrap();
        let kp = rcgen::KeyPair::from_pem(&pem).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::Ia5String::try_from(san_uri.to_string()).unwrap(),
        )];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(days);
        params.self_signed(&kp).unwrap().pem()
    }

    pub(crate) fn node() -> NodeIdentity {
        NodeIdentity {
            node_id: "cdn-fr-7k2m".into(),
            vm_id: "cdn-fr-7k2m".into(),
            region: "FR".into(),
        }
    }

    fn vectors() -> serde_json::Value {
        let raw = include_str!("../../../test_vectors/cdn/vectors.json");
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn derivation_matches_the_shared_python_vector() {
        let v = &vectors()["node_key"];
        assert_eq!(v["info"], "HIPPIUS_CDN_NODE_KEY_V1");
        let seed: [u8; 32] = hex::decode(v["lifecycle_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(derive_node_seed(&seed).as_ref()),
            v["node_seed_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(NodeKey::derive(&seed).public_bytes()),
            v["node_public_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn node_key_differs_from_the_telemetry_key() {
        // Same seed, different label: HIPPIUS_TENANT_TELEMETRY_KEY_V1 gives
        // 3d86f591... for [7; 32].
        let seed = derive_node_seed(&[7u8; 32]);
        assert_ne!(
            hex::encode(seed.as_ref()),
            "3d86f59136c2a2b5180b13b78dc3a83a805ae81ea47a0f480e74946311cbd4be"
        );
    }

    #[test]
    fn secret_files_accept_raw_and_hex_and_refuse_loose_modes() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("raw.key");
        fs::write(&raw, [9u8; 32]).unwrap();
        fs::set_permissions(&raw, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_secret_32(&raw).unwrap().as_ref(), &[9u8; 32]);

        let hexf = dir.path().join("hex.key");
        fs::write(&hexf, format!("{}\n", hex::encode([3u8; 32]))).unwrap();
        fs::set_permissions(&hexf, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret_32(&hexf).unwrap().as_ref(), &[3u8; 32]);

        fs::set_permissions(&hexf, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_secret_32(&hexf).unwrap_err().class(),
            "secret-file-permissions"
        );

        // A credential systemd passed with an ACL: root:root, mask in the
        // group bits.
        assert!(secret_mode_ok(0o100440, 0, 0, true));
        assert!(!secret_mode_ok(0o100440, 0, 0, false));
        assert!(secret_mode_ok(0o100400, 61101, 61100, false));
        assert!(!secret_mode_ok(0o100440, 61101, 61100, true));
        assert!(!secret_mode_ok(0o100440, 0, 61100, true));
        assert!(!secret_mode_ok(0o100460, 0, 0, true));
        assert!(!secret_mode_ok(0o100444, 0, 0, true));
        assert!(!secret_mode_ok(0o100404, 61101, 61100, false));

        let short = dir.path().join("short.key");
        fs::write(&short, [1u8; 31]).unwrap();
        fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secret_32(&short).is_err());
        assert!(read_secret_32(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn accepts_a_matching_node_cert_and_reads_the_generation() {
        let key = NodeKey::derive(&[7u8; 32]);
        let pem = node_cert_pem(&key, "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g3", 7);
        let now = crate::clock::unix_now();
        let cert =
            verify_node_cert(&pem, &key.public_bytes(), &node(), "hippius.network", now).unwrap();
        assert_eq!(cert.generation, 3);
        assert_eq!(cert.fingerprint_hex.len(), 64);
        assert!(cert.not_after > now);
    }

    #[test]
    fn refuses_certs_for_another_key_node_region_or_domain() {
        let key = NodeKey::derive(&[7u8; 32]);
        let other = NodeKey::derive(&[8u8; 32]);
        let now = crate::clock::unix_now();
        let good_uri = "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g3";
        let check = |pem: &str, pk: &[u8; 32]| {
            verify_node_cert(pem, pk, &node(), "hippius.network", now)
                .unwrap_err()
                .class()
        };

        let pem = node_cert_pem(&other, good_uri, 7);
        assert_eq!(check(&pem, &key.public_bytes()), "node-cert-key-mismatch");

        for (uri, want) in [
            (
                "spiffe://hippius.network/cdn/AU/cdn-fr-7k2m/g3",
                "node-cert-wrong-node",
            ),
            (
                "spiffe://hippius.network/cdn/FR/cdn-fr-other/g3",
                "node-cert-wrong-node",
            ),
            (
                "spiffe://evil.example/cdn/FR/cdn-fr-7k2m/g3",
                "node-cert-wrong-node",
            ),
            (
                "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g03",
                "node-cert-generation",
            ),
            (
                "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g3/x",
                "node-cert-generation",
            ),
            (
                "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g",
                "node-cert-generation",
            ),
        ] {
            let pem = node_cert_pem(&key, uri, 7);
            assert_eq!(check(&pem, &key.public_bytes()), want, "{uri}");
        }

        let pem = node_cert_pem(&key, good_uri, -1);
        assert_eq!(check(&pem, &key.public_bytes()), "node-cert-expired");

        let doubled = format!("{pem}{pem}");
        assert_eq!(check(&doubled, &key.public_bytes()), "node-cert-shape");
    }

    #[test]
    fn pkcs8_pem_reloads_to_the_same_key() {
        let key = NodeKey::derive(&[5u8; 32]);
        let pem = key.pkcs8_pem().unwrap();
        let kp = rcgen::KeyPair::from_pem(&pem).unwrap();
        assert_eq!(kp.public_key_raw(), key.public_bytes());
    }
}
