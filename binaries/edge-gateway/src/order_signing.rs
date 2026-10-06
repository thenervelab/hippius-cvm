//! Edge order-signing key (§H phase-2 follow-up).
//!
//! The §K end-to-end test on a live miner surfaced a deferred
//! defect: the miner-agent rejects every lifecycle order because the
//! Ansible-rendered `edge.order_signing_pubkey` in
//! `/etc/hippius-miner/config.toml` is the all-zeros placeholder — no
//! signed order could ever verify against it. The fix is the
//! signing chain `vali → Edge sign → miner verify_strict`. THIS
//! module ships the **Edge sign half**: the priv-key loader + the
//! `sign(body)` primitive. The matching pubkey is rendered into every
//! miner's config by Ansible (see
//! `deploy/ansible/group_vars/miner_nodes.yml`).
//!
//! ## Contrast with `signer.rs` (telemetry-signer)
//!
//! The §15 telemetry key is **boot-generated** — fresh per Edge boot,
//! rotation = redeploy (an old key's signatures simply stop being
//! accepted; Sentinel + the Validator re-fetch the new pubkey from
//! `/v1/edge/pubkey`). The order-signing key is **Vault-loaded**: the
//! miner's pubkey config is Ansible-rendered and must stay stable
//! across Edge redeploys, so the priv key lives in Vault Tier-0 (path
//! `secret/hippius-compute/edge-gateway/order-signing`, property
//! `priv`) and an ExternalSecret materialises it to a file inside the
//! pod. The Edge → miner direction is INNER → MINER (vali asks Edge
//! to sign + relay), which is the inverse of every existing miner →
//! inner relay route — the body is opaque to Edge (canonical-CBOR
//! `OrderBody` the miner-agent re-decodes), exactly as the miner →
//! inner heartbeat body is opaque to the Edge.
//!
//! ## Wire contract (mirrored from
//! `binaries/miner-agent/src/orders/auth.rs`)
//!
//! The miner-agent verifies a `SignedOrder { body, sig }` envelope:
//! `verify_strict(body, sig)` against the configured pubkey, no other
//! gates. `body` is the canonical-CBOR encoding of an `OrderBody`. So
//! the Edge contract is just **"sign these bytes with this key"**.
//! `OrderBody` typing lives entirely with vali (the producer) and the
//! miner-agent (the consumer); the Edge does not introspect.
//!
//! ## Lifecycle
//!
//! 1. Operator generates an Ed25519 keypair offline (see the
//!    `binaries/edge-gateway/README.md` "Order signing" runbook).
//! 2. Operator vault-writes the 32-byte raw seed as 64 lowercase-hex
//!    chars to `secret/hippius-compute/edge-gateway/order-signing`
//!    (property `priv`); the matching pubkey is committed to
//!    `deploy/ansible/group_vars/miner_nodes.yml`.
//! 3. Operator flips `orderSigning.enabled: true` in the Edge Helm
//!    values; the chart materialises the seed at
//!    `/etc/hippius-edge/order-signing/priv.hex` and sets
//!    `EDGE_ORDER_SIGNING_KEY_PATH` to that path.
//! 4. At boot [`OrderSigner::load`] reads the file, decodes the hex,
//!    builds an [`ed25519_dalek::SigningKey`]. An optional
//!    `EDGE_ORDER_SIGNING_EXPECTED_PUBKEY` pins the expected pubkey
//!    in deployment config and fails closed on mismatch — catches
//!    the "Vault holds the wrong priv" misconfig before the first
//!    order goes out.
//! 5. The loaded pubkey is logged once at boot (it is public — the
//!    same value sits in every miner's config) so operators can
//!    visually confirm the Ansible match without reading the secret.
//!
//! ## Feature-flagged (opt-in)
//!
//! Unset `EDGE_ORDER_SIGNING_KEY_PATH` keeps the subsystem disabled;
//! the Edge boots as before — existing clusters are unaffected by
//! this PR. The operator opts in by flipping the Helm-chart toggle
//! once Vault is provisioned.
//!
//! ## Secret discipline
//!
//! - The priv-hex file is read once at boot; the loader never logs
//!   its bytes (the only log line is the derived pubkey hex — public).
//! - The `SigningKey` is heap-boxed and zeroize-on-drop (the
//!   `ed25519-dalek` `zeroize` feature — same posture as `signer.rs`).
//! - The loader's transient buffers (the read `String`, the
//!   `hex::decode`d `Vec<u8>`, the stack `[u8; 32]` seed) are also
//!   zeroized — the `String`/`Vec` via `zeroize::Zeroizing` wrappers
//!   that fire on scope drop, the array via an explicit `.zeroize()`
//!   call immediately after `SigningKey::from_bytes` consumes it.
//! - No `Debug`, no `Clone` on [`OrderSigner`]. The only operations
//!   are `sign` and the public-key accessors; there is no getter for
//!   the secret bytes. Same `&'static str`-only error class
//!   discipline as `CertStoreError` (no `{0}` runtime strings).
//!
//! ## What this module does NOT do (yet)
//!
//! This PR delivers the load + sign primitive only. The matching
//! `POST /v1/edge/order` axum route + the Edge → miner HTTP forwarder
//! are a follow-up; until they land the signing chain is exercised
//! via the operator-side smoke runbook (vault-read priv → off-cluster
//! `openssl pkeyutl -sign` over a CBOR `OrderBody` → `curl` the
//! miner's `:9700/v1/miner/order/{kind}` route — the miner verifies
//! against the same pubkey the Edge would have used). See the
//! README "Order signing" runbook.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::path::Path;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Env var naming the path to the 64-hex-char Ed25519 seed file.
/// Unset ⇒ the order-signing subsystem is disabled at boot.
pub const ENV_KEY_PATH: &str = "EDGE_ORDER_SIGNING_KEY_PATH";

/// Env var naming the expected pubkey hex (64 lowercase chars). When
/// set, [`OrderSigner::load`] derives the pubkey from the loaded seed
/// and fails closed on mismatch — catches the "Vault holds the wrong
/// priv" misconfig before any signed order goes out. Unset ⇒ the
/// match check is skipped (the operator can still read the pubkey
/// from the boot log).
pub const ENV_EXPECTED_PUBKEY: &str = "EDGE_ORDER_SIGNING_EXPECTED_PUBKEY";

/// Ed25519 seed length in bytes.
const SEED_LEN: usize = 32;

/// Length of the seed when encoded as lowercase hex (64 chars).
const SEED_HEX_LEN: usize = SEED_LEN * 2;

/// Stable static-classifier errors. Same `&'static str`-only `Display`
/// discipline as [`crate::mtls::CertStoreError`] — never `{0}` a
/// runtime string, so the audit log can key on `class()`.
#[derive(Debug, thiserror::Error)]
pub enum OrderSigningError {
    /// `EDGE_ORDER_SIGNING_KEY_PATH` was set but empty. The operator
    /// did set the env var; treating that as "subsystem disabled"
    /// would silently mask a deployment typo, so fail closed.
    #[error("order-signing-env-empty")]
    EnvEmpty,
    /// `std::fs::read_to_string` failed for the seed file. Usually
    /// the ExternalSecret has not materialised yet, the path is
    /// wrong, or the file's mode hides it from the pod user.
    #[error("order-signing-read")]
    Read,
    /// File content was not 64 lowercase-hex chars (after trimming).
    /// Either case-mismatch (uppercase) or a non-hex byte.
    #[error("order-signing-hex")]
    Hex,
    /// Decoded bytes were not exactly 32 — wrong file content.
    #[error("order-signing-len")]
    Length,
    /// The derived pubkey did not match `ENV_EXPECTED_PUBKEY`. The
    /// Vault-stored priv key is for a DIFFERENT keypair than the
    /// pubkey deployment config pinned — drift between operator
    /// steps. Fail closed before any order is signed.
    #[error("order-signing-pubkey-mismatch")]
    PubkeyMismatch,
    /// `ENV_EXPECTED_PUBKEY` was set but is not 64 lowercase-hex
    /// chars — same shape rules as the priv-hex file.
    #[error("order-signing-expected-pubkey-hex")]
    ExpectedPubkeyHex,
}

impl OrderSigningError {
    /// Static classifier for the audit / boot-fail log. Mirrors the
    /// `class()` pattern from `CertStoreError`.
    pub fn class(&self) -> &'static str {
        match self {
            OrderSigningError::EnvEmpty => "order-signing-env-empty",
            OrderSigningError::Read => "order-signing-read",
            OrderSigningError::Hex => "order-signing-hex",
            OrderSigningError::Length => "order-signing-len",
            OrderSigningError::PubkeyMismatch => "order-signing-pubkey-mismatch",
            OrderSigningError::ExpectedPubkeyHex => "order-signing-expected-pubkey-hex",
        }
    }
}

/// The Edge's order-signing key. Constructed exactly once per process
/// via [`OrderSigner::load`]. Wrap the result in `Arc` so the future
/// `POST /v1/edge/order` handler + any operator-tooling endpoint can
/// share it.
///
/// No `Debug`, no `Clone` — the secret is single-instance and there
/// is no public-byte getter; the only operations are [`Self::sign`]
/// and the public-key accessors.
pub struct OrderSigner {
    /// Boxed for address stability (so moving the `OrderSigner`
    /// doesn't leave a stale copy of the secret on the old stack /
    /// struct slot). `ed25519-dalek`'s `zeroize` feature makes the
    /// secret bytes wipe on drop — same posture as `EdgeSigner`.
    /// Private: no path from outside this module to the bytes.
    key: Box<SigningKey>,
}

impl OrderSigner {
    /// Load the seed from `path`, hex-decode, build the signing key.
    ///
    /// `expected_pubkey_hex = Some(_)` opts into the boot-time pubkey
    /// match check; the operator pins the expected pubkey via
    /// `EDGE_ORDER_SIGNING_EXPECTED_PUBKEY` in deployment config.
    /// `None` skips the check (the boot log still emits the derived
    /// pubkey for operator visual confirmation).
    pub fn load(
        path: &Path,
        expected_pubkey_hex: Option<&str>,
    ) -> Result<Arc<Self>, OrderSigningError> {
        // Every transient buffer that holds the seed bytes is wrapped
        // in `Zeroizing` so it wipes on drop — review r1: the
        // priv seed must not linger in heap/stack after boot. The
        // long-lived `SigningKey` itself zeroizes via the
        // `ed25519-dalek` `zeroize` feature.
        let raw: Zeroizing<String> =
            Zeroizing::new(std::fs::read_to_string(path).map_err(|_| OrderSigningError::Read)?);
        // `trim_end` only — a leading whitespace byte (very unusual
        // for an ed25519 seed file) is NOT silently stripped; it
        // makes the length check fail instead, surfacing the corrupt
        // file rather than masking it.
        let trimmed = raw.trim_end();
        if trimmed.len() != SEED_HEX_LEN {
            return Err(OrderSigningError::Length);
        }
        // Reject uppercase / non-hex up front. `hex::decode` itself
        // accepts both cases; the explicit guard matches the miner-
        // agent's `require_hex64` discipline so the two sides agree.
        if !is_lowercase_hex(trimmed) {
            return Err(OrderSigningError::Hex);
        }
        let bytes: Zeroizing<Vec<u8>> =
            Zeroizing::new(hex::decode(trimmed).map_err(|_| OrderSigningError::Hex)?);
        let mut seed: [u8; SEED_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| OrderSigningError::Length)?;
        let key = Box::new(SigningKey::from_bytes(&seed));
        // Wipe the stack-allocated seed copy now that the key owns
        // its internal bytes. (`raw` + `bytes` zeroize when their
        // `Zeroizing` wrappers drop at end of scope.)
        seed.zeroize();

        if let Some(expected) = expected_pubkey_hex {
            if expected.len() != SEED_HEX_LEN || !is_lowercase_hex(expected) {
                return Err(OrderSigningError::ExpectedPubkeyHex);
            }
            let derived = hex::encode(key.verifying_key().to_bytes());
            if derived != expected {
                return Err(OrderSigningError::PubkeyMismatch);
            }
        }
        Ok(Arc::new(Self { key }))
    }

    /// The 32-byte Ed25519 public key. Public: every miner's
    /// `edge.order_signing_pubkey` carries the hex of these bytes, so
    /// operators MUST be able to read it. Logged once at boot for
    /// visual confirmation against the Ansible-rendered value.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The public key as an `ed25519-dalek` [`VerifyingKey`] — the
    /// in-process verify path the integration tests use.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign `body` with a detached Ed25519 signature, returning the
    /// 64-byte sig.
    ///
    /// `body` is the canonical-CBOR encoding of an `OrderBody` (the
    /// miner-agent's `binaries/miner-agent/src/orders/types.rs`). The
    /// Edge treats it as opaque — vali constructs it, the miner-agent
    /// re-decodes it for typed dispatch. The contract this function
    /// satisfies is exactly what the miner's
    /// `OrderVerifier::verify` checks:
    /// `verify_strict(body, sig)` against the matching public key.
    pub fn sign(&self, body: &[u8]) -> [u8; 64] {
        self.key.sign(body).to_bytes()
    }
}

/// Whether `s` is exactly the lowercase-hex character set
/// (`0-9` `a-f`). The miner-agent's `require_hex64` applies the same
/// rule; mirroring it here keeps the two sides agreed on the encoding.
fn is_lowercase_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signature;
    use std::io::Write;

    fn write_seed_hex(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    fn write_seed(seed: &[u8; SEED_LEN]) -> tempfile::NamedTempFile {
        write_seed_hex(&hex::encode(seed))
    }

    #[test]
    fn load_decodes_a_valid_seed_and_derives_the_expected_pubkey() {
        let seed = [42u8; SEED_LEN];
        let f = write_seed(&seed);
        let signer = OrderSigner::load(f.path(), None).expect("load");
        // The pubkey the Edge would publish must equal what
        // `ed25519-dalek` produces directly from the same seed — that
        // is the value the operator commits to Ansible.
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(signer.public_key_bytes(), expected);
    }

    #[test]
    fn sign_round_trip_matches_the_miner_agents_verify_strict() {
        // This is the cross-side contract: the miner-agent's
        // `OrderVerifier::verify` calls `verify_strict(&body, &sig)`
        // against the configured pubkey. If this round-trip passes,
        // every miner whose `edge.order_signing_pubkey` matches our
        // derived pubkey will accept every signature we produce.
        let seed = [7u8; SEED_LEN];
        let f = write_seed(&seed);
        let signer = OrderSigner::load(f.path(), None).expect("load");

        // Arbitrary opaque body bytes — the Edge does not introspect.
        let body = b"opaque canonical-CBOR OrderBody bytes";
        let sig = Signature::from_bytes(&signer.sign(body));
        signer
            .verifying_key()
            .verify_strict(body, &sig)
            .expect("verify_strict must accept a signature from the same key");

        // A tampered body must NOT verify under the same signature —
        // confirms the sig genuinely binds the body.
        let mut tampered = body.to_vec();
        tampered[0] ^= 1;
        assert!(signer
            .verifying_key()
            .verify_strict(&tampered, &sig)
            .is_err());
    }

    #[test]
    fn load_rejects_a_seed_file_that_is_not_64_hex_chars() {
        // Short content: 8 chars, not 64.
        let f = write_seed_hex("deadbeef");
        assert!(matches!(
            OrderSigner::load(f.path(), None),
            Err(OrderSigningError::Length)
        ));
    }

    #[test]
    fn load_rejects_uppercase_hex() {
        // 64 chars, valid hex by `hex::decode`, but uppercase — the
        // miner-agent's `require_hex64` rejects this too; the two
        // sides MUST agree on the encoding.
        let f = write_seed_hex(&"AB".repeat(SEED_LEN));
        assert!(matches!(
            OrderSigner::load(f.path(), None),
            Err(OrderSigningError::Hex)
        ));
    }

    #[test]
    fn load_rejects_non_hex_content() {
        // 64 chars, but `z` is not a hex digit.
        let f = write_seed_hex(&"z".repeat(SEED_HEX_LEN));
        assert!(matches!(
            OrderSigner::load(f.path(), None),
            Err(OrderSigningError::Hex)
        ));
    }

    #[test]
    fn load_rejects_a_missing_file() {
        assert!(matches!(
            OrderSigner::load(Path::new("/no/such/file/anywhere"), None),
            Err(OrderSigningError::Read)
        ));
    }

    #[test]
    fn load_strips_trailing_whitespace() {
        // `echo` / most editors add a trailing newline; the loader
        // accepts that so a hand-written seed file does not break boot.
        let seed = [11u8; SEED_LEN];
        let mut content = hex::encode(seed);
        content.push('\n');
        let f = write_seed_hex(&content);
        let signer = OrderSigner::load(f.path(), None).expect("load");
        assert_eq!(
            signer.public_key_bytes(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
    }

    #[test]
    fn load_rejects_leading_whitespace() {
        // r1 follow-up (review Low): `trim_end` — NOT `trim` — means
        // a leading whitespace byte is surfaced as a length mismatch
        // rather than silently stripped. A file with leading
        // whitespace is far more likely corrupt than the operator
        // intentionally indenting the seed.
        let seed = [55u8; SEED_LEN];
        let f = write_seed_hex(&format!(" {}", hex::encode(seed)));
        assert!(matches!(
            OrderSigner::load(f.path(), None),
            Err(OrderSigningError::Length)
        ));
    }

    #[test]
    fn load_accepts_a_matching_expected_pubkey() {
        let seed = [13u8; SEED_LEN];
        let f = write_seed(&seed);
        let expected = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        OrderSigner::load(f.path(), Some(&expected))
            .expect("a matching expected pubkey must accept");
    }

    #[test]
    fn load_rejects_a_mismatching_expected_pubkey() {
        let seed = [13u8; SEED_LEN];
        let f = write_seed(&seed);
        // The pubkey of a DIFFERENT seed — exactly the misconfig the
        // pin catches (Vault holds the wrong priv).
        let wrong = hex::encode(
            SigningKey::from_bytes(&[99u8; SEED_LEN])
                .verifying_key()
                .to_bytes(),
        );
        assert!(matches!(
            OrderSigner::load(f.path(), Some(&wrong)),
            Err(OrderSigningError::PubkeyMismatch)
        ));
    }

    #[test]
    fn load_rejects_a_malformed_expected_pubkey() {
        let seed = [13u8; SEED_LEN];
        let f = write_seed(&seed);
        for bad in ["not-hex-and-wrong-length", "ABCD", &"AB".repeat(32)] {
            assert!(matches!(
                OrderSigner::load(f.path(), Some(bad)),
                Err(OrderSigningError::ExpectedPubkeyHex)
            ));
        }
    }

    #[test]
    fn error_classes_are_static_and_distinct() {
        // The `class()` strings are the audit-log keys; a typo /
        // duplication would silently merge two failure modes.
        let classes = [
            OrderSigningError::EnvEmpty.class(),
            OrderSigningError::Read.class(),
            OrderSigningError::Hex.class(),
            OrderSigningError::Length.class(),
            OrderSigningError::PubkeyMismatch.class(),
            OrderSigningError::ExpectedPubkeyHex.class(),
        ];
        for c in classes {
            assert!(c.starts_with("order-signing-"));
        }
        let unique: std::collections::HashSet<&str> = classes.iter().copied().collect();
        assert_eq!(unique.len(), classes.len());
    }
}
