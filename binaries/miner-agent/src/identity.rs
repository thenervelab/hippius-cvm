//! The miner's persistent Ed25519 identity — **self-generated**.
//!
//! A miner is UNTRUSTED infrastructure (`project_hippius_compute_locked_
//! decisions.md`): it never authenticates to the hippius-compute Vault
//! and its identity is never Vault-issued. The miner-agent generates
//! its own Ed25519 keypair locally on first boot; the **public** half
//! is printed for the operator to register out-of-band with vali, and
//! the **secret** half never leaves the host.
//!
//! Secret-handling discipline (mirrors `agent-tenant-telemetry`):
//!
//! - the seed is drawn from `OsRng` into a [`Zeroizing`] buffer;
//! - the live key is a `Box<SigningKey>` — `ed25519-dalek`'s `zeroize`
//!   feature wipes its seed on drop;
//! - the on-disk form (hex of the 32-byte seed) only ever exists
//!   inside `Zeroizing` wrappers;
//! - [`MinerIdentity`] derives **no** `Debug` — the key cannot be
//!   formatted into a log line, even truncated.
//!
//! On-disk format: the key file and its public sidecar each hold 64
//! lowercase-hex characters (the 32-byte seed / public key). The key
//! file is written `0400`, the public file `0444`. Both are installed
//! atomically (temp file → fsync → rename → directory fsync) so a
//! crash never leaves a partial or world-readable key.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::error::{MinerAgentError, Result};

/// Length of an Ed25519 seed and of an Ed25519 public key — both 32.
const KEY_LEN: usize = 32;

/// Secret-key file mode: owner-read only.
const KEY_MODE: u32 = 0o400;

/// Public-key file mode: world-readable (the value is public).
const PUB_MODE: u32 = 0o444;

/// The miner's persistent identity keypair.
///
/// Deliberately not `Debug` / `Clone` — the signing key must not be
/// duplicable or formattable.
pub struct MinerIdentity {
    /// Boxed so the key has a stable heap address; `SigningKey` wipes
    /// its seed on drop (the `ed25519-dalek` `zeroize` feature).
    signing_key: Box<SigningKey>,
    /// The public half — safe to print, copy, and register with vali.
    verifying_key: VerifyingKey,
}

impl MinerIdentity {
    /// Generate a brand-new identity. The seed is drawn from the OS
    /// CSPRNG (`getrandom`) into a zeroizing buffer; the signing key
    /// never leaves this process except via [`Self::persist`].
    pub fn generate() -> Result<Self> {
        let mut seed: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new([0u8; KEY_LEN]);
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut seed[..])
            .map_err(|_| MinerAgentError::IdentityKeygen)?;
        let signing_key = Box::new(SigningKey::from_bytes(&seed));
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Load an existing identity from disk.
    ///
    /// The signing key is the source of truth: the public key is
    /// re-derived from it, and the on-disk public sidecar is then
    /// **cross-checked** — a stale or tampered `.pub` file is
    /// fail-closed corruption (`identity-parse/pub-mismatch`), never
    /// silently tolerated.
    pub fn load(key_path: &Path, pub_path: &Path) -> Result<Self> {
        let key_raw = read_required(key_path)?;
        let seed = parse_seed_hex(&key_raw)?;
        let signing_key = Box::new(SigningKey::from_bytes(&seed));
        let verifying_key = signing_key.verifying_key();

        let pub_raw = std::fs::read(pub_path)?;
        let pub_bytes = parse_pub_hex(&pub_raw)?;
        if &pub_bytes != verifying_key.as_bytes() {
            return Err(MinerAgentError::IdentityParse("pub-mismatch"));
        }

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Persist the identity to disk. The key file is written `0400`,
    /// the public sidecar `0444`.
    ///
    /// Both temp files are staged (written + fsynced) *before* either
    /// is renamed into place, so a failure staging or committing the
    /// second leaves the first un-renamed — never a half-written
    /// identity. The two renames are then back-to-back; the only
    /// inter-file window is a crash strictly between them, which
    /// [`Self::load`]'s pub-vs-key cross-check catches (fail-closed).
    ///
    /// This always writes — idempotency (refuse-to-overwrite) is the
    /// caller's policy; see [`Self::key_present`].
    pub fn persist(&self, key_path: &Path, pub_path: &Path) -> Result<()> {
        // Encode the secret seed straight into a zeroizing stack
        // buffer. `SigningKey::as_bytes` *borrows* the key's internal
        // seed (`&[u8; 32]`) — the raw seed is never copied onto the
        // stack, and no `String` / `Vec` heap intermediate ever holds
        // the hex secret.
        let mut key_hex: Zeroizing<[u8; KEY_LEN * 2]> = Zeroizing::new([0u8; KEY_LEN * 2]);
        hex::encode_to_slice(self.signing_key.as_bytes(), &mut key_hex[..])
            .map_err(|_| MinerAgentError::IdentityParse("key-encode"))?;
        // The public key is not secret.
        let pub_hex = hex::encode(self.verifying_key.as_bytes());

        // Stage both, then commit both — the public sidecar first, the
        // secret key last (the key file is the `key_present` commit
        // point). A staging failure drops both temp handles → nothing
        // renamed.
        let key_tmp = stage(key_path, &key_hex[..], KEY_MODE)?;
        let pub_tmp = stage(pub_path, pub_hex.as_bytes(), PUB_MODE)?;
        commit(pub_tmp, pub_path)?;
        commit(key_tmp, key_path)?;
        Ok(())
    }

    /// Whether an identity key file already exists at `key_path`. Used
    /// by `init-identity` for its refuse-to-overwrite idempotency.
    pub fn key_present(key_path: &Path) -> bool {
        key_path.is_file()
    }

    /// The public key as 64 lowercase-hex characters — no `0x` prefix,
    /// no whitespace. This is the exact string the operator registers
    /// with vali.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// The public half of the identity.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign `msg` with the miner identity key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// The §23 `register_child` node-authorisation message this
    /// identity signs, byte-identical to
    /// `pallet-compute-scoring::registration_message`:
    /// `SCALE((b"HIPPIUS_COMPUTE_NODE_REG_V1", family, child, node_id,
    /// nonce))`. Every component is fixed-size, so the SCALE encoding
    /// of the tuple is a plain concatenation — byte-array elements
    /// encode with NO length prefix, `AccountId32` as its 32 raw
    /// bytes, `u64` little-endian. (If the pallet's message ever gains
    /// a variable-length field this MUST switch to real SCALE.)
    pub fn registration_message(&self, family: &[u8; 32], child: &[u8; 32], nonce: u64) -> Vec<u8> {
        const DOMAIN: &[u8] = b"HIPPIUS_COMPUTE_NODE_REG_V1";
        let mut msg = Vec::with_capacity(DOMAIN.len() + 32 * 3 + 8);
        msg.extend_from_slice(DOMAIN);
        msg.extend_from_slice(family);
        msg.extend_from_slice(child);
        // node_id IS this identity's Ed25519 public key — the pallet's
        // `verify_node_sig` checks the sig against node_id as the key.
        msg.extend_from_slice(self.verifying_key.as_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg
    }

    /// Sign a §23 `register_child` authorisation — returns the 64-byte
    /// `node_sig` the family account submits alongside
    /// `register_child(family, child, node_id, node_sig)`. The node_id
    /// is this identity's public key ([`Self::pubkey_hex`]).
    pub fn sign_registration(&self, family: &[u8; 32], child: &[u8; 32], nonce: u64) -> Signature {
        self.sign(&self.registration_message(family, child, nonce))
    }

    /// The node identity as a URI SAN value — `hippius-node:<64-hex>`.
    /// The Edge reads this off the presented cert and gates the
    /// connection on the on-chain registry
    /// (docs/design/permissionless-miner-auth.md).
    pub fn node_uri(&self) -> String {
        format!("hippius-node:{}", self.pubkey_hex())
    }

    /// Mint a **self-signed** TLS client identity (cert + key,
    /// concatenated as one PEM for `reqwest::Identity::from_pem`) whose
    /// private key **is** the Ed25519 node identity, carrying
    /// `URI:hippius-node:<node_id>` as a SAN and the clientAuth EKU.
    ///
    /// Presenting this to the Edge proves possession of the node
    /// identity with NO operator CA — the permissionless replacement
    /// for the operator-issued client cert. The returned buffer holds
    /// the private key, so it is zeroizing.
    pub fn self_signed_client_pem(&self) -> Result<Zeroizing<String>> {
        use rcgen::{
            CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType,
            PKCS_ED25519,
        };
        use rustls_pki_types::PrivatePkcs8KeyDer;

        // PKCS#8 v1 DER for the Ed25519 seed (RFC 8410): a fixed 16-byte
        // header + the 32-byte private seed. Built in a zeroizing buffer.
        const PKCS8_ED25519_PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut der: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(48));
        der.extend_from_slice(&PKCS8_ED25519_PREFIX);
        der.extend_from_slice(self.signing_key.as_bytes());

        let pkcs8 = PrivatePkcs8KeyDer::from(der.as_slice());
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .map_err(|_| MinerAgentError::IdentityCert("keypair"))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|_| MinerAgentError::IdentityCert("params"))?;
        let uri = Ia5String::try_from(self.node_uri())
            .map_err(|_| MinerAgentError::IdentityCert("san"))?;
        params.subject_alt_names.push(SanType::URI(uri));
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params.distinguished_name.push(
            DnType::CommonName,
            format!("hippius-node-{}", &self.pubkey_hex()[..16]),
        );

        let cert = params
            .self_signed(&key_pair)
            .map_err(|_| MinerAgentError::IdentityCert("sign"))?;

        Ok(Zeroizing::new(format!(
            "{}{}",
            cert.pem(),
            key_pair.serialize_pem()
        )))
    }
}

/// Read a required file straight into a `Zeroizing` buffer — the file
/// holds the hex secret, so it must never sit in an un-wiped `Vec`.
/// A missing file maps to the dedicated `identity-missing` classifier
/// so the runbook can tell "operator has not run `init-identity`"
/// apart from a generic I/O failure.
fn read_required(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => MinerAgentError::IdentityMissing,
            _ => MinerAgentError::Io(e),
        })
}

/// Parse a hex seed file directly into a zeroizing 32-byte array — the
/// raw seed never exists outside `Zeroizing`. `decode_to_slice` also
/// validates the hex alphabet; the explicit length check above it
/// yields the precise `key-len` classifier.
fn parse_seed_hex(raw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| MinerAgentError::IdentityParse("key-utf8"))?
        .trim();
    if text.len() != KEY_LEN * 2 {
        return Err(MinerAgentError::IdentityParse("key-len"));
    }
    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    hex::decode_to_slice(text, &mut seed[..])
        .map_err(|_| MinerAgentError::IdentityParse("key-hex"))?;
    Ok(seed)
}

/// Parse a hex public-key file into a 32-byte array. The public key is
/// not secret, so no zeroizing is needed.
fn parse_pub_hex(raw: &[u8]) -> Result<[u8; KEY_LEN]> {
    let text = std::str::from_utf8(raw).map_err(|_| MinerAgentError::IdentityParse("pub-utf8"))?;
    let decoded =
        hex::decode(text.trim()).map_err(|_| MinerAgentError::IdentityParse("pub-hex"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| MinerAgentError::IdentityParse("pub-len"))
}

/// The directory a file lives in — `.` for a bare filename.
fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Stage `bytes` into a temp file in `path`'s directory: write, set
/// `mode`, fsync. The temp is NOT yet renamed into place — the caller
/// finishes with [`commit`]. Dropping the returned handle (any error
/// before `commit`) removes the temp, so a failure leaves nothing.
fn stage(path: &Path, bytes: &[u8], mode: u32) -> Result<NamedTempFile> {
    let dir = parent_dir(path);
    std::fs::create_dir_all(dir)?;
    // `NamedTempFile` is `O_EXCL`-created with mode 0600 — never
    // world-readable, even before the explicit `set_permissions`.
    let mut tmp = tempfile::Builder::new()
        .prefix(".hippius-miner-identity-")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

/// Commit a [`stage`]d temp file to `path` — an atomic rename, then an
/// fsync of the directory so the rename entry itself is durable.
fn commit(tmp: NamedTempFile, path: &Path) -> Result<()> {
    tmp.persist(path)
        .map_err(|e| MinerAgentError::Io(e.error))?;
    std::fs::File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_a_usable_keypair() {
        let id = MinerIdentity::generate().unwrap();
        // The public key derives consistently from the signing key.
        assert_eq!(id.verifying_key(), &id.signing_key.verifying_key());
    }

    #[test]
    fn pubkey_hex_is_64_lowercase_hex_no_prefix() {
        let id = MinerIdentity::generate().unwrap();
        let hex = id.pubkey_hex();
        assert_eq!(hex.len(), 64);
        assert!(!hex.starts_with("0x"));
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(hex.trim(), hex, "no surrounding whitespace");
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let id = MinerIdentity::generate().unwrap();
        let msg = b"miner-agent identity self-test";
        let sig = id.sign(msg);
        assert!(id.verifying_key().verify_strict(msg, &sig).is_ok());
    }

    #[test]
    fn two_generated_identities_differ() {
        let a = MinerIdentity::generate().unwrap();
        let b = MinerIdentity::generate().unwrap();
        assert_ne!(a.pubkey_hex(), b.pubkey_hex());
    }

    #[test]
    fn node_uri_is_hippius_node_prefixed_pubkey() {
        let id = MinerIdentity::generate().unwrap();
        assert_eq!(id.node_uri(), format!("hippius-node:{}", id.pubkey_hex()));
    }

    #[test]
    fn self_signed_client_pem_is_a_matched_cert_key_pair() {
        let id = MinerIdentity::generate().unwrap();
        let pem = id.self_signed_client_pem().unwrap();
        // Both PEM blocks present: the leaf cert and its private key.
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
        assert!(pem.contains("PRIVATE KEY"));
        // reqwest/rustls parse the concatenated PEM only when the
        // private key actually matches the certificate's public key —
        // i.e. the cert's key truly IS this node identity.
        reqwest::Identity::from_pem(pem.as_bytes())
            .expect("self-signed identity must be a usable reqwest client identity");
    }

    #[test]
    fn registration_message_layout_matches_the_pallet() {
        let id = MinerIdentity::generate().unwrap();
        let family = [0x11u8; 32];
        let child = [0x22u8; 32];
        let nonce: u64 = 7;
        let msg = id.registration_message(&family, &child, nonce);
        // domain(27) + family(32) + child(32) + node_id(32) + nonce(8).
        assert_eq!(msg.len(), 27 + 32 + 32 + 32 + 8);
        assert_eq!(&msg[..27], b"HIPPIUS_COMPUTE_NODE_REG_V1");
        assert_eq!(&msg[27..59], &family);
        assert_eq!(&msg[59..91], &child);
        assert_eq!(&msg[91..123], id.verifying_key().as_bytes());
        assert_eq!(&msg[123..131], &nonce.to_le_bytes());
    }

    #[test]
    fn registration_message_byte_matches_parity_scale_codec() {
        // Conformance oracle: the hand-rolled concatenation MUST equal
        // the real SCALE encoding of the tuple the pallet builds —
        // `(b"HIPPIUS_COMPUTE_NODE_REG_V1", family, child, node_id,
        // nonce).encode()`. `[u8; N]` arrays + `u64` encode with no
        // length prefix / LE, so the two agree; this pins it.
        use codec::Encode;
        let id = MinerIdentity::generate().unwrap();
        let family = [0x11u8; 32];
        let child = [0x22u8; 32];
        let nonce: u64 = 7;
        let node_id: [u8; 32] = *id.verifying_key().as_bytes();
        let scale = (
            b"HIPPIUS_COMPUTE_NODE_REG_V1",
            family,
            child,
            node_id,
            nonce,
        )
            .encode();
        assert_eq!(id.registration_message(&family, &child, nonce), scale);
    }

    #[test]
    fn sign_registration_verifies_against_node_id() {
        // The pallet's `verify_node_sig` checks the sig against node_id
        // (= the identity public key) over the registration message.
        let id = MinerIdentity::generate().unwrap();
        let family = [0xAAu8; 32];
        let child = [0xBBu8; 32];
        let nonce: u64 = 3;
        let sig = id.sign_registration(&family, &child, nonce);
        let msg = id.registration_message(&family, &child, nonce);
        assert!(id.verifying_key().verify_strict(&msg, &sig).is_ok());
        // A different nonce must NOT verify (replay/binding sanity).
        let other = id.registration_message(&family, &child, nonce + 1);
        assert!(id.verifying_key().verify_strict(&other, &sig).is_err());
    }

    #[test]
    fn self_signed_certs_are_unique_per_identity() {
        // Distinct identities mint distinct certs; the cert is bound to
        // the node identity, never shared (the bug the permissionless
        // model fixes — one cert can no longer stand in for another).
        let a = MinerIdentity::generate().unwrap();
        let b = MinerIdentity::generate().unwrap();
        assert_ne!(
            a.self_signed_client_pem().unwrap().as_str(),
            b.self_signed_client_pem().unwrap().as_str()
        );
    }

    #[test]
    fn parse_seed_hex_rejects_wrong_length() {
        assert!(matches!(
            parse_seed_hex(b"abcd"),
            Err(MinerAgentError::IdentityParse("key-len"))
        ));
    }

    #[test]
    fn parse_seed_hex_rejects_non_hex() {
        let not_hex = vec![b'z'; 64];
        assert!(matches!(
            parse_seed_hex(&not_hex),
            Err(MinerAgentError::IdentityParse("key-hex"))
        ));
    }

    #[test]
    fn parse_seed_hex_accepts_trailing_whitespace() {
        let id = MinerIdentity::generate().unwrap();
        let mut hex = hex::encode(id.signing_key.to_bytes());
        hex.push('\n');
        assert!(parse_seed_hex(hex.as_bytes()).is_ok());
    }

    #[test]
    fn parse_pub_hex_rejects_wrong_length() {
        assert!(matches!(
            parse_pub_hex(b"00"),
            Err(MinerAgentError::IdentityParse("pub-len"))
        ));
    }
}
