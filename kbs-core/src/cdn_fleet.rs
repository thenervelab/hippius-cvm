//! The CDN fleet keyring, KBS side (`docs/design/cdn.md` §5.3).
//!
//! Every CDN node shares one X25519 keypair per version: the backend
//! seals zone secrets to the public half, nodes unseal in RAM.
//!
//! ## Custody
//!
//! The private key never exists in plaintext outside this KBS and the
//! attested cdn-node CVMs it releases to:
//! - **Generation.** `transit/datakey/wrapped/cdn-fleet bits=256` — Vault
//!   Transit generates the key and returns ONLY its ciphertext. The writer
//!   (vali, or the operator's `scripts/cdn-fleet-mint.sh`) stores that
//!   ciphertext once; nobody is granted `transit/datakey/plaintext/*`.
//! - **No chosen keys.** No policy grants `transit/encrypt/cdn-fleet`, so
//!   nobody can wrap a key they already know and have the KBS adopt it.
//! - **Read + unwrap** happen here, with a broker-minted capability whose
//!   cdn-fleet leg the KBS requests only inside a release that passed the
//!   `cdn_node` class and perm checks (`crate::snp::check_release_class`),
//!   or for the admin public-key route below. The policy is
//!   `deploy/terraform/policies/kbs-cap-cdn-fleet.hcl`.
//!
//! ## Layout
//!
//! - Transit key [`CDN_FLEET_TRANSIT_KEY`]: aes256-gcm96,
//!   `exportable=false`, `deletion_allowed=false`.
//! - KV-v2 `<mount>/data/`[`CDN_FLEET_KV_PREFIX`]`/v<N>`: one immutable
//!   entry per version, written with `cas=0` so it is always KV version
//!   [`CDN_FLEET_KV_VERSION`], read at exactly that version (§19). The
//!   value is the KBS single-field schema `{"value": base64(ct)}` with
//!   `ct` the `vault:v1:…` ciphertext.
//!
//! ## Which versions a node gets
//!
//! The OrderTicket names them: one [`CDN_FLEET_VERSION_PERM_PREFIX`]`<N>`
//! perm per version, next to [`crate::lifecycle::CDN_NODE_PERM`], all
//! signed by L1. vali decides active / pending / retiring and mints the
//! perms accordingly; the KBS keeps no keyring state, so a KBS restart
//! loses nothing. Rotation = mint `N+1`, re-launch the nodes with both
//! perms, then drop `N` from new tickets.
//!
//! ## Public metadata
//!
//! `public = X25519(clamp(secret))`, and the KBS signs
//! [`public_key_message`] = `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ u64be(version) ‖
//! public` with its response-signing key, so the backend can check that
//! the KBS — not just vali — vouches for the key it seals to. Test
//! vector: `test_vectors/cdn_fleet/public_key_signature.json`.

use crate::error::{KbsError, Result};
use crate::snp::VerifiedReport;
use crate::vault::{AttestedVaultAuth, KbsAuthEvidence, VaultCapability, VaultKv, VaultScope};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub use hippius_types::vault_broker::MAX_CDN_FLEET_VERSIONS;

/// Vault Transit key that wraps every cdn-fleet version.
pub const CDN_FLEET_TRANSIT_KEY: &str = "cdn-fleet";
/// KV-v2 path prefix (under the KBS's mount) of the per-version entries.
pub const CDN_FLEET_KV_PREFIX: &str = "hippius-compute/kbs/cdn-fleet";
/// Each per-version entry is written once, so it is KV version 1.
pub const CDN_FLEET_KV_VERSION: u64 = 1;
/// `WrappedSecret::secret_type` of a released fleet key.
pub const CDN_FLEET_SECRET_TYPE: &str = "cdn-fleet";
/// OrderTicket `lifecycle_perms` prefix naming one fleet key version.
pub const CDN_FLEET_VERSION_PERM_PREFIX: &str = "cdn-fleet-v";
/// Domain of the KBS signature over a fleet public key.
pub const CDN_FLEET_PUB_DOMAIN: &[u8] = b"HIPPIUS_CDN_FLEET_PUB_V1";
/// Length of [`public_key_message`].
pub const PUBLIC_KEY_MESSAGE_LEN: usize = 24 + 8 + 32;

/// KV path of fleet key `version` (relative to the KV mount).
pub fn secret_path(version: u64) -> String {
    format!("{CDN_FLEET_KV_PREFIX}/v{version}")
}

/// The fleet key versions a ticket names, ascending. Empty when the
/// ticket names none (every non-CDN ticket).
///
/// Strict, because these are the only signed input selecting key
/// material: `cdn-fleet-v<N>` with `N` canonical decimal (no sign, no
/// leading zero) in `1..=u32::MAX` (the node agent's version type);
/// duplicates and more than
/// [`MAX_CDN_FLEET_VERSIONS`] refuse rather than being collapsed.
pub fn versions_from_perms(perms: &[String]) -> Result<Vec<u64>> {
    let mut versions = Vec::new();
    for perm in perms {
        let Some(digits) = perm.strip_prefix(CDN_FLEET_VERSION_PERM_PREFIX) else {
            continue;
        };
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0');
        let version = canonical
            .then(|| digits.parse::<u32>().ok())
            .flatten()
            .map(u64::from)
            .ok_or_else(|| KbsError::Policy(format!("cdn-fleet-perm-malformed: {perm:?}")))?;
        if versions.contains(&version) {
            return Err(KbsError::Policy(format!(
                "cdn-fleet-perm-duplicate: version {version}"
            )));
        }
        versions.push(version);
    }
    if versions.len() > MAX_CDN_FLEET_VERSIONS {
        return Err(KbsError::Policy(format!(
            "cdn-fleet-too-many-versions: {} > {MAX_CDN_FLEET_VERSIONS}",
            versions.len()
        )));
    }
    versions.sort_unstable();
    Ok(versions)
}

/// RFC 7748 X25519 clamping, in place. Idempotent, so every
/// implementation derives the same public key from the delivered bytes
/// whether or not it clamps.
pub fn clamp_in_place(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// [`clamp_in_place`] on a copy (public inputs and tests).
pub fn clamp(raw: &[u8; 32]) -> [u8; 32] {
    let mut k = *raw;
    clamp_in_place(&mut k);
    k
}

/// The X25519 public key of a (clamped) fleet secret. The `StaticSecret`
/// wipes itself on drop (x25519-dalek `zeroize`).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let sk = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&sk).to_bytes()
}

/// Read fleet key `version` at its exact path@version, refuse anything
/// that is not Transit ciphertext, unwrap it under
/// [`CDN_FLEET_TRANSIT_KEY`], and return the clamped X25519 secret.
///
/// The plaintext check is unconditional (no `require_wrapped_*` flag):
/// the class is new, so no legacy plaintext entry can exist, and a
/// plaintext one would mean someone chose the key.
pub fn unwrap_secret(
    vault_kv: &dyn VaultKv,
    cap: &VaultCapability,
    version: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    let path = secret_path(version);
    let at_rest = vault_kv.read_exact(cap, &path, CDN_FLEET_KV_VERSION)?;
    if !at_rest.starts_with(b"vault:") {
        return Err(KbsError::Policy(format!(
            "cdn-fleet-not-wrapped: version {version} is not Transit ciphertext at rest"
        )));
    }
    let raw = vault_kv.transit_decrypt(cap, CDN_FLEET_TRANSIT_KEY, &at_rest)?;
    let raw: &[u8; 32] = raw.as_slice().try_into().map_err(|_| {
        KbsError::Policy(format!(
            "cdn-fleet-bad-length: version {version} does not unwrap to 32 bytes"
        ))
    })?;
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(raw);
    clamp_in_place(&mut secret);
    Ok(secret)
}

/// `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ u64be(version) ‖ x25519_public` — the
/// exact bytes the KBS signs. Fixed length, so there is no ambiguity.
pub fn public_key_message(version: u64, x25519_public: &[u8; 32]) -> [u8; PUBLIC_KEY_MESSAGE_LEN] {
    let mut m = [0u8; PUBLIC_KEY_MESSAGE_LEN];
    m[..24].copy_from_slice(CDN_FLEET_PUB_DOMAIN);
    m[24..32].copy_from_slice(&version.to_be_bytes());
    m[32..].copy_from_slice(x25519_public);
    m
}

/// Sign a fleet public key with the KBS response key.
pub fn sign_public_key(sk: &SigningKey, version: u64, x25519_public: &[u8; 32]) -> [u8; 64] {
    sk.sign(&public_key_message(version, x25519_public))
        .to_bytes()
}

/// Verify a KBS signature over a fleet public key (what vali and the
/// backend do before trusting a key, with the pinned KBS response key).
pub fn verify_public_key(
    vk: &VerifyingKey,
    version: u64,
    x25519_public: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    vk.verify(
        &public_key_message(version, x25519_public),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| KbsError::Crypto("cdn-fleet public key signature does not verify".into()))
}

/// A KBS-vouched fleet public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetPublicKey {
    pub version: u64,
    pub x25519_public: [u8; 32],
    pub kbs_kid: Vec<u8>,
    pub signature: [u8; 64],
}

/// What [`derive_public_key`] needs: the same Vault seams and KBS keys
/// the release path uses.
pub struct FleetPublicDeps<'a> {
    pub vault_auth: &'a dyn AttestedVaultAuth,
    pub vault_kv: &'a dyn VaultKv,
    pub kbs_attestation: &'a VerifiedReport,
    pub kbs_auth_pubkey: &'a [u8],
    pub kbs_signing_key: &'a SigningKey,
    pub kbs_kid: &'a [u8],
}

/// Unwrap fleet key `version` with a fleet-only capability, derive its
/// public half and sign it. The secret is wiped before this returns;
/// only public data leaves.
pub fn derive_public_key(
    deps: &FleetPublicDeps,
    version: u64,
    now_unix: u64,
) -> Result<FleetPublicKey> {
    if version == 0 || version > u64::from(u32::MAX) {
        return Err(KbsError::Policy(
            "cdn-fleet version must be in 1..=u32::MAX".into(),
        ));
    }
    let scope = VaultScope::fleet_only(vec![version]);
    let challenge = deps.vault_auth.issue_challenge(&scope, now_unix)?;
    let cap = deps.vault_auth.redeem(
        &KbsAuthEvidence {
            verified: deps.kbs_attestation,
            challenge: &challenge,
            scope: &scope,
            auth_pubkey: deps.kbs_auth_pubkey,
        },
        now_unix,
    )?;
    let secret = unwrap_secret(deps.vault_kv, &cap, version)?;
    let x25519_public = public_key(&secret);
    Ok(FleetPublicKey {
        version,
        x25519_public,
        kbs_kid: deps.kbs_kid.to_vec(),
        signature: sign_public_key(deps.kbs_signing_key, version, &x25519_public),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp::LaunchPolicy;
    use crate::vault::ChallengeVaultAuth;
    use std::collections::HashMap;

    fn perms(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn versions_parse_strictly_and_sort() {
        assert_eq!(versions_from_perms(&perms(&[])).unwrap(), Vec::<u64>::new());
        assert_eq!(
            versions_from_perms(&perms(&["cdn-node", "supersede"])).unwrap(),
            Vec::<u64>::new()
        );
        assert_eq!(
            versions_from_perms(&perms(&["cdn-fleet-v3", "cdn-node", "cdn-fleet-v1"])).unwrap(),
            vec![1, 3]
        );
        for bad in [
            "cdn-fleet-v",
            "cdn-fleet-v0",
            "cdn-fleet-v01",
            "cdn-fleet-v+1",
            "cdn-fleet-v-1",
            "cdn-fleet-v1 ",
            "cdn-fleet-v1a",
            "cdn-fleet-v4294967296",
            "cdn-fleet-v99999999999999999999999",
        ] {
            assert!(versions_from_perms(&perms(&[bad])).is_err(), "{bad:?}");
        }
        assert!(versions_from_perms(&perms(&["cdn-fleet-v2", "cdn-fleet-v2"])).is_err());
        assert!(versions_from_perms(&perms(&[
            "cdn-fleet-v1",
            "cdn-fleet-v2",
            "cdn-fleet-v3",
            "cdn-fleet-v4",
            "cdn-fleet-v5",
        ]))
        .is_err());
    }

    #[test]
    fn clamping_is_rfc7748_and_idempotent() {
        let c = clamp(&[0xffu8; 32]);
        assert_eq!(c[0], 0xf8);
        assert_eq!(c[31], 0x7f);
        let c0 = clamp(&[0u8; 32]);
        assert_eq!(c0[31], 0x40);
        assert_eq!(clamp(&c), c);
        // The public key is the same with or without our clamping: x25519
        // clamps on use, so a node that re-clamps derives the same key.
        let raw = [0x5au8; 32];
        assert_eq!(public_key(&clamp(&raw)), public_key(&raw));
    }

    /// Mock Vault: KV entries plus a reversible "Transit" keyed on the
    /// transit key name, so a test proves the WRONG key is refused.
    struct Kv(HashMap<String, Vec<u8>>);
    fn wrap(transit_key: &str, plaintext: &[u8]) -> Vec<u8> {
        format!("vault:v1:{transit_key}:{}", hex::encode(plaintext)).into_bytes()
    }
    impl VaultKv for Kv {
        fn read_exact(
            &self,
            _cap: &VaultCapability,
            path: &str,
            version: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            if version != CDN_FLEET_KV_VERSION {
                return Err(KbsError::VaultNotFound("no such version".into()));
            }
            self.0
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| KbsError::VaultNotFound("path not found".into()))
        }
        fn transit_decrypt(
            &self,
            _cap: &VaultCapability,
            transit_key: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            let s = core::str::from_utf8(ciphertext).map_err(|_| KbsError::Vault("utf8".into()))?;
            let rest = s
                .strip_prefix("vault:v1:")
                .ok_or_else(|| KbsError::Vault("not ciphertext".into()))?;
            let (key, hexed) = rest
                .split_once(':')
                .ok_or_else(|| KbsError::Vault("malformed".into()))?;
            if key != transit_key {
                return Err(KbsError::Vault("wrong transit key".into()));
            }
            Ok(Zeroizing::new(
                hex::decode(hexed).map_err(|_| KbsError::Vault("hex".into()))?,
            ))
        }
    }

    fn cap() -> VaultCapability {
        VaultCapability::new(
            VaultScope::fleet_only(vec![1]),
            u64::MAX,
            Zeroizing::new(b"t".to_vec()),
        )
    }

    #[test]
    fn unwrap_reads_the_exact_entry_and_clamps() {
        let raw = [0x11u8; 32];
        let kv = Kv(HashMap::from([(
            secret_path(1),
            wrap(CDN_FLEET_TRANSIT_KEY, &raw),
        )]));
        assert_eq!(secret_path(1), "hippius-compute/kbs/cdn-fleet/v1");
        let s = unwrap_secret(&kv, &cap(), 1).unwrap();
        assert_eq!(*s, clamp(&raw));
        // A version that was never minted is a hard error, not an empty key.
        assert!(matches!(
            unwrap_secret(&kv, &cap(), 2),
            Err(KbsError::VaultNotFound(_))
        ));
    }

    #[test]
    fn unwrap_refuses_plaintext_wrong_key_and_wrong_length() {
        let kv = Kv(HashMap::from([
            (secret_path(1), [0x22u8; 32].to_vec()),
            (secret_path(2), wrap("kek-some-vm", &[0x33u8; 32])),
            (secret_path(3), wrap(CDN_FLEET_TRANSIT_KEY, &[0x44u8; 16])),
        ]));
        let e = unwrap_secret(&kv, &cap(), 1).unwrap_err().to_string();
        assert!(e.contains("cdn-fleet-not-wrapped"), "{e}");
        // Ciphertext under another Transit key (e.g. a tenant KEK) is
        // refused by Transit itself: the KBS asks for `cdn-fleet` only.
        assert!(unwrap_secret(&kv, &cap(), 2).is_err());
        let e = unwrap_secret(&kv, &cap(), 3).unwrap_err().to_string();
        assert!(e.contains("cdn-fleet-bad-length"), "{e}");
    }

    #[test]
    fn signature_binds_version_and_key() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let public = public_key(&clamp(&[0x55u8; 32]));
        let sig = sign_public_key(&sk, 7, &public);
        verify_public_key(&vk, 7, &public, &sig).unwrap();
        // Another version, another key, another signer: all refused.
        assert!(verify_public_key(&vk, 8, &public, &sig).is_err());
        let other = public_key(&clamp(&[0x56u8; 32]));
        assert!(verify_public_key(&vk, 7, &other, &sig).is_err());
        let vk2 = SigningKey::from_bytes(&[10u8; 32]).verifying_key();
        assert!(verify_public_key(&vk2, 7, &public, &sig).is_err());
        let m = public_key_message(7, &public);
        assert_eq!(&m[..24], CDN_FLEET_PUB_DOMAIN);
        assert_eq!(&m[24..32], &7u64.to_be_bytes());
        assert_eq!(&m[32..], &public);
    }

    /// The shared vector vali and the backend check their verifier against.
    #[test]
    fn public_key_signature_test_vector() {
        let raw = include_str!("../../test_vectors/cdn_fleet/public_key_signature.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let field = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        let seed: [u8; 32] = field("kbs_signing_seed_hex").try_into().unwrap();
        let datakey: [u8; 32] = field("datakey_plaintext_hex").try_into().unwrap();
        let version = v["version"].as_u64().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let secret = clamp(&datakey);
        assert_eq!(secret.to_vec(), field("x25519_secret_hex"));
        let public = public_key(&secret);
        assert_eq!(public.to_vec(), field("x25519_public_hex"));
        assert_eq!(
            sk.verifying_key().to_bytes().to_vec(),
            field("kbs_public_key_hex")
        );
        assert_eq!(
            public_key_message(version, &public).to_vec(),
            field("message_hex")
        );
        let sig = sign_public_key(&sk, version, &public);
        assert_eq!(sig.to_vec(), field("signature_hex"));
        verify_public_key(&sk.verifying_key(), version, &public, &sig).unwrap();
    }

    #[test]
    fn derive_public_key_is_deterministic_and_verifies() {
        let raw = [0x77u8; 32];
        let kv = Kv(HashMap::from([(
            secret_path(2),
            wrap(CDN_FLEET_TRANSIT_KEY, &raw),
        )]));
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let auth = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 0,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 30,
            cap_ttl: 30,
            challenge_nonce: [1u8; 32],
        };
        let report = VerifiedReport {
            measurement: [0u8; 48],
            report_data: [0u8; 64],
            tcb: 1,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let deps = FleetPublicDeps {
            vault_auth: &auth,
            vault_kv: &kv,
            kbs_attestation: &report,
            kbs_auth_pubkey: b"pk",
            kbs_signing_key: &sk,
            kbs_kid: b"kid",
        };
        let a = derive_public_key(&deps, 2, 100).unwrap();
        let b = derive_public_key(&deps, 2, 101).unwrap();
        assert_eq!(a, b, "same wrapped key, same public key and signature");
        assert_eq!(a.x25519_public, public_key(&clamp(&raw)));
        assert_eq!(a.kbs_kid, b"kid");
        verify_public_key(&sk.verifying_key(), 2, &a.x25519_public, &a.signature).unwrap();
        assert!(derive_public_key(&deps, 0, 100).is_err());
        assert!(derive_public_key(&deps, 1 << 32, 100).is_err());
        assert!(derive_public_key(&deps, 3, 100).is_err());
    }
}
