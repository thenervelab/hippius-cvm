//! `sign-coldkey-registration` — offline signer for an Arion storage
//! node's on-chain onboarding, run on the operator's **storage** host.
//!
//! The provider dashboard registers an Arion family + storage child in
//! two extrinsics, each of which needs a signature from the Arion
//! node's own Ed25519 key (`keypair.bin`, 32 raw seed bytes):
//!
//! 1. `pallet-registration::register_node_with_coldkey` — the node key
//!    signs the raw 200-byte SCALE `RegisterChallenge` the dashboard
//!    built (`HIPPIUS::REGISTER::v1`).
//! 2. `pallet-arion::register_child` — the node key signs
//!    `(b"ARION_NODE_REG_V1", family, child, node_id, nonce).encode()`.
//!
//! This module only reads the key file: no network, no chain, no write.
//! Before signing the challenge it checks the domain, that
//! `node_id_hash` is this node's own peer id (so the command is not a
//! signing oracle for someone else's node), and — unless the operator
//! opts out — that the genesis is mainnet's.

use std::io::Read;
use std::path::Path;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{MinerAgentError, Result};

/// Length of Arion's `keypair.bin`: the raw Ed25519 seed (iroh
/// `SecretKey::to_bytes`), no encoding.
pub const ARION_KEYPAIR_LEN: usize = 32;

/// Length of a SCALE `RegisterChallenge<AccountId32, u64>`.
pub const CHALLENGE_LEN: usize = 200;

/// `RegisterChallenge::domain` the pallet accepts.
pub const REGISTER_DOMAIN: [u8; 24] = *b"HIPPIUS::REGISTER::v1\0\0\0";

/// Hippius mainnet genesis hash.
pub const MAINNET_GENESIS: [u8; 32] = [
    0x28, 0xa6, 0xb5, 0x48, 0x23, 0xf7, 0x86, 0xc5, 0xdd, 0x85, 0x20, 0xef, 0x7b, 0xdb, 0x0e, 0xe2,
    0x63, 0x91, 0x73, 0x81, 0x5b, 0xfb, 0xb7, 0x71, 0x9b, 0xcf, 0x58, 0xef, 0x9e, 0xb5, 0xe1, 0xf9,
];

/// libp2p identity multihash prefix for an Ed25519 key: identity
/// multihash (0x00), length 36 (0x24), protobuf `KeyType = Ed25519`
/// (0x08 0x01), `Data` field of 32 bytes (0x12 0x20).
pub const LIBP2P_ED25519_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// Domain of the Arion `register_child` node signature.
pub const ARION_REG_DOMAIN: &[u8; 17] = b"ARION_NODE_REG_V1";

/// Length of the Arion `register_child` message.
pub const ARION_MESSAGE_LEN: usize = 17 + 32 + 32 + 32 + 8;

/// Arguments for the optional Arion `register_child` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArionArgs {
    pub family: [u8; 32],
    pub child: [u8; 32],
    pub nonce: u64,
}

/// Command output — one JSON object on stdout. Only public values.
#[derive(Debug, Serialize)]
pub struct ColdkeyRegistration {
    pub public_key: String,
    pub node_id_hex: String,
    pub node_id: String,
    pub signature: String,
    pub account: String,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arion: Option<ArionRegistration>,
}

/// The `register_child` inputs + node signature.
#[derive(Debug, Serialize)]
pub struct ArionRegistration {
    pub family: String,
    pub child: String,
    pub node_id: String,
    pub nonce: u64,
    pub node_sig: String,
}

/// Read Arion's `keypair.bin`. Exactly 32 raw bytes, or refuse. The
/// read is bounded so a wrong file is never slurped whole.
pub fn load_arion_keypair(path: &Path) -> Result<SigningKey> {
    let file = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => MinerAgentError::IdentityMissing,
        _ => MinerAgentError::Io(e),
    })?;
    let mut raw = Zeroizing::new(Vec::with_capacity(ARION_KEYPAIR_LEN + 1));
    file.take(ARION_KEYPAIR_LEN as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() != ARION_KEYPAIR_LEN {
        return Err(MinerAgentError::IdentityParse("keypair-len"));
    }
    let mut seed = Zeroizing::new([0u8; ARION_KEYPAIR_LEN]);
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

/// The 38-byte libp2p peer id (identity multihash) of an Ed25519 key —
/// the `node_id_hex` bytes `register_node_with_coldkey` checks.
pub fn libp2p_peer_id(pubkey: &[u8; 32]) -> [u8; 38] {
    let mut out = [0u8; 38];
    out[..6].copy_from_slice(&LIBP2P_ED25519_PREFIX);
    out[6..].copy_from_slice(pubkey);
    out
}

/// `sp_core::hashing::blake2_256`.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(data).into()
}

/// Base58btc (Bitcoin alphabet) — the textual libp2p peer id.
pub fn base58btc(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Base-58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// Parse `0x`-prefixed (or bare) hex.
fn parse_hex(s: &str, which: &'static str) -> Result<Vec<u8>> {
    let trimmed = s.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(trimmed).map_err(|_| MinerAgentError::RegistrationArg(which))
}

/// Parse a 32-byte AccountId from `0x`-hex.
pub fn parse_account32(s: &str, which: &'static str) -> Result<[u8; 32]> {
    parse_hex(s, which)?
        .try_into()
        .map_err(|_| MinerAgentError::RegistrationArg(which))
}

/// Build [`ArionArgs`] from the CLI's optional flags: all three or none.
pub fn arion_args(
    family: Option<&str>,
    child: Option<&str>,
    nonce: Option<u64>,
) -> Result<Option<ArionArgs>> {
    match (family, child, nonce) {
        (None, None, None) => Ok(None),
        (Some(family), Some(child), Some(nonce)) => Ok(Some(ArionArgs {
            family: parse_account32(family, "family")?,
            child: parse_account32(child, "child")?,
            nonce,
        })),
        _ => Err(MinerAgentError::RegistrationArg("arion-args-all-or-none")),
    }
}

/// The fields of a checked challenge the output echoes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedChallenge {
    pub account: [u8; 32],
    pub expires_at: u64,
}

/// Validate a SCALE `RegisterChallenge<AccountId32, u64>` before this
/// node signs it (layout: pallets/registration/src/types.rs
/// `RegisterChallenge`).
pub fn check_challenge(
    challenge: &[u8],
    pubkey: &[u8; 32],
    allow_any_genesis: bool,
) -> Result<CheckedChallenge> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(MinerAgentError::RegistrationArg("challenge-len"));
    }
    if challenge[0..24] != REGISTER_DOMAIN {
        return Err(MinerAgentError::RegistrationArg("challenge-domain"));
    }
    if !allow_any_genesis && challenge[24..56] != MAINNET_GENESIS {
        return Err(MinerAgentError::RegistrationArg("challenge-genesis"));
    }
    if challenge[88..120] != blake2_256(&libp2p_peer_id(pubkey)) {
        return Err(MinerAgentError::RegistrationArg("challenge-foreign-node"));
    }
    let mut account = [0u8; 32];
    account.copy_from_slice(&challenge[56..88]);
    let mut expires_at = [0u8; 8];
    expires_at.copy_from_slice(&challenge[192..200]);
    Ok(CheckedChallenge {
        account,
        expires_at: u64::from_le_bytes(expires_at),
    })
}

/// `pallet-arion::registration_message`:
/// `(b"ARION_NODE_REG_V1", family, child, node_id, nonce).encode()` —
/// a `&[u8; 17]` and `[u8; 32]`s SCALE-encode raw (no length prefix),
/// the `u64` little-endian.
pub fn arion_registration_message(
    family: &[u8; 32],
    child: &[u8; 32],
    node_id: &[u8; 32],
    nonce: u64,
) -> [u8; ARION_MESSAGE_LEN] {
    let mut msg = [0u8; ARION_MESSAGE_LEN];
    msg[..17].copy_from_slice(ARION_REG_DOMAIN);
    msg[17..49].copy_from_slice(family);
    msg[49..81].copy_from_slice(child);
    msg[81..113].copy_from_slice(node_id);
    msg[113..].copy_from_slice(&nonce.to_le_bytes());
    msg
}

/// Check the `0x`-hex challenge and produce both signatures.
pub fn sign_coldkey_registration(
    key: &SigningKey,
    challenge_hex: &str,
    arion: Option<ArionArgs>,
    allow_any_genesis: bool,
) -> Result<ColdkeyRegistration> {
    let pubkey = key.verifying_key().to_bytes();
    let challenge = parse_hex(challenge_hex, "challenge-hex")?;
    let checked = check_challenge(&challenge, &pubkey, allow_any_genesis)?;
    let peer_id = libp2p_peer_id(&pubkey);
    let signature = key.sign(&challenge);
    let arion = arion.map(|a| {
        let msg = arion_registration_message(&a.family, &a.child, &pubkey, a.nonce);
        ArionRegistration {
            family: format!("0x{}", hex::encode(a.family)),
            child: format!("0x{}", hex::encode(a.child)),
            node_id: format!("0x{}", hex::encode(pubkey)),
            nonce: a.nonce,
            node_sig: format!("0x{}", hex::encode(key.sign(&msg).to_bytes())),
        }
    });
    Ok(ColdkeyRegistration {
        public_key: format!("0x{}", hex::encode(pubkey)),
        node_id_hex: format!("0x{}", hex::encode(peer_id)),
        node_id: base58btc(&peer_id),
        signature: format!("0x{}", hex::encode(signature.to_bytes())),
        account: format!("0x{}", hex::encode(checked.account)),
        expires_at: checked.expires_at,
        arion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::io::Write;

    const SEED: [u8; 32] = [0x11; 32];
    const ACCOUNT: [u8; 32] = [0x44; 32];

    /// A challenge for `key`, laid out field by field as
    /// `RegisterChallenge` SCALE-encodes.
    fn challenge_for(key: &SigningKey) -> Vec<u8> {
        let mut c = Vec::with_capacity(CHALLENGE_LEN);
        c.extend_from_slice(&REGISTER_DOMAIN);
        c.extend_from_slice(&MAINNET_GENESIS);
        c.extend_from_slice(&ACCOUNT);
        c.extend_from_slice(&blake2_256(&libp2p_peer_id(
            &key.verifying_key().to_bytes(),
        )));
        c.extend_from_slice(&[0x55; 32]); // ipfs_peer_id_hash
        c.extend_from_slice(&1_000u64.to_le_bytes()); // block_number
        c.extend_from_slice(&[0x66; 32]); // nonce
        c.extend_from_slice(&1_100u64.to_le_bytes()); // expires_at
        c
    }

    fn hex0x(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }

    fn sig_from_hex(s: &str) -> Signature {
        let b: [u8; 64] = hex::decode(&s[2..]).unwrap().try_into().unwrap();
        Signature::from_bytes(&b)
    }

    #[test]
    fn challenge_layout_matches_parity_scale_codec() {
        // Conformance oracle: the test builder must equal the real SCALE
        // encoding of the pallet struct's field tuple with u64 blocks
        // (hippius mainnet `BlockNumber = u64`).
        use codec::Encode;
        let key = SigningKey::from_bytes(&SEED);
        let scale = (
            REGISTER_DOMAIN,
            MAINNET_GENESIS,
            ACCOUNT,
            blake2_256(&libp2p_peer_id(&key.verifying_key().to_bytes())),
            [0x55u8; 32],
            1_000u64,
            [0x66u8; 32],
            1_100u64,
        )
            .encode();
        assert_eq!(scale.len(), CHALLENGE_LEN);
        assert_eq!(challenge_for(&key), scale);
    }

    #[test]
    fn peer_id_known_vector() {
        let peer = libp2p_peer_id(&[0x11; 32]);
        assert_eq!(
            hex::encode(peer),
            "0024080112201111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            base58btc(&peer),
            "12D3KooWAxzCBFVtEyKLnRm43gHxigCoe2d4UmkRTXhBNSv5bcCx"
        );
    }

    #[test]
    fn base58_edge_cases() {
        assert_eq!(base58btc(&[]), "");
        assert_eq!(base58btc(&[0, 0]), "11");
        assert_eq!(base58btc(&[0, 0, 0x01]), "112");
        assert_eq!(base58btc(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn blake2_256_known_vector() {
        // blake2b-256("") — RFC 7693 parameters, 32-byte output.
        assert_eq!(
            hex::encode(blake2_256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn signs_a_valid_challenge_and_the_signature_verifies() {
        let key = SigningKey::from_bytes(&SEED);
        let challenge = challenge_for(&key);
        let out = sign_coldkey_registration(&key, &hex0x(&challenge), None, false).unwrap();
        let vk: VerifyingKey = key.verifying_key();
        assert_eq!(out.public_key, hex0x(vk.as_bytes()));
        assert_eq!(out.node_id_hex, hex0x(&libp2p_peer_id(vk.as_bytes())));
        assert!(out.node_id.starts_with("12D3KooW"));
        assert_eq!(out.account, hex0x(&ACCOUNT));
        assert_eq!(out.expires_at, 1_100);
        assert!(out.arion.is_none());
        vk.verify_strict(&challenge, &sig_from_hex(&out.signature))
            .unwrap();
        let json = serde_json::to_value(&out).unwrap();
        assert!(json.get("arion").is_none());
    }

    #[test]
    fn arion_signature_verifies_over_the_pallet_message() {
        let key = SigningKey::from_bytes(&SEED);
        let challenge = challenge_for(&key);
        let args = ArionArgs {
            family: [0xAA; 32],
            child: [0xBB; 32],
            nonce: 3,
        };
        let out = sign_coldkey_registration(&key, &hex0x(&challenge), Some(args), false).unwrap();
        let arion = out.arion.as_ref().unwrap();
        let vk = key.verifying_key();
        assert_eq!(arion.node_id, hex0x(vk.as_bytes()));
        assert_eq!(arion.family, hex0x(&[0xAA; 32]));
        assert_eq!(arion.child, hex0x(&[0xBB; 32]));
        assert_eq!(arion.nonce, 3);
        let msg = arion_registration_message(&[0xAA; 32], &[0xBB; 32], vk.as_bytes(), 3);
        vk.verify_strict(&msg, &sig_from_hex(&arion.node_sig))
            .unwrap();
        // Bound to the nonce.
        let other = arion_registration_message(&[0xAA; 32], &[0xBB; 32], vk.as_bytes(), 4);
        assert!(vk
            .verify_strict(&other, &sig_from_hex(&arion.node_sig))
            .is_err());
    }

    #[test]
    fn arion_message_known_answer() {
        // Byte-for-byte KAT of pallet-arion `registration_message`
        // (thebrain pallets/arion-pallet/src/lib.rs) and hippius-arion
        // tools/src/bin/generate_registration_data.rs: domain(17) ‖
        // family ‖ child ‖ node_id ‖ nonce LE.
        let key = SigningKey::from_bytes(&SEED);
        let node_id = key.verifying_key().to_bytes();
        let msg = arion_registration_message(&[0xAA; 32], &[0xBB; 32], &node_id, 0x0102);
        let expected = format!(
            "{}{}{}{}{}",
            hex::encode(b"ARION_NODE_REG_V1"),
            "aa".repeat(32),
            "bb".repeat(32),
            hex::encode(node_id),
            "0201000000000000",
        );
        assert_eq!(msg.len(), 121);
        assert_eq!(hex::encode(msg), expected);
        // Same tuple through parity-scale-codec, as the pallet builds it.
        use codec::Encode;
        let scale = (
            b"ARION_NODE_REG_V1",
            [0xAAu8; 32],
            [0xBBu8; 32],
            &node_id,
            0x0102u64,
        )
            .encode();
        assert_eq!(msg.as_slice(), scale.as_slice());
    }

    #[test]
    fn arion_message_differs_from_the_compute_registration_message() {
        let key = SigningKey::from_bytes(&SEED);
        let node_id = key.verifying_key().to_bytes();
        let msg = arion_registration_message(&[1; 32], &[2; 32], &node_id, 0);
        assert!(!msg.starts_with(b"HIPPIUS_COMPUTE_NODE_REG_V1"));
    }

    #[test]
    fn full_output_known_answer() {
        // Ed25519 is deterministic: pin the whole output for seed 0x11×32
        // so a key-derivation or message-layout change cannot slip
        // through. Cross-checked out of band with Python `cryptography`
        // (Ed25519) + `hashlib.blake2b(digest_size=32)`.
        let key = SigningKey::from_bytes(&SEED);
        let args = ArionArgs {
            family: [0xAA; 32],
            child: [0xBB; 32],
            nonce: 3,
        };
        let out = sign_coldkey_registration(&key, &hex0x(&challenge_for(&key)), Some(args), false)
            .unwrap();
        assert_eq!(
            out.public_key,
            "0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        );
        assert_eq!(
            out.node_id_hex,
            "0x002408011220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        );
        assert_eq!(
            out.node_id,
            "12D3KooWPqT2nMDSiXUSx5D7fasaxhxKigVhcqfkKqrLghCq9jxz"
        );
        assert_eq!(
            out.signature,
            "0x26f99ca03821a3e2c72e18a90ef5887bc3c7e2568be4071c0c7bdf6a226a749d\
             314a8249db263e22d8b028ca97b94bc4846d8f827fb42264bbe31412996b840a"
        );
        assert_eq!(
            out.arion.unwrap().node_sig,
            "0xe95c80beee0bf74b5122b57ed89e629b1f7dc7fa4608914f54864f9a43d3f3b2\
             4735e2dd9c737dcb8bd9bf4e2d71ce533659e0e5564e86f12062b0e4b02e3002"
        );
    }

    #[test]
    fn refuses_wrong_length() {
        let key = SigningKey::from_bytes(&SEED);
        let mut c = challenge_for(&key);
        c.push(0);
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-len");
        c.truncate(199);
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-len");
    }

    #[test]
    fn refuses_bad_hex() {
        let key = SigningKey::from_bytes(&SEED);
        let err = sign_coldkey_registration(&key, "0xzz", None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-hex");
    }

    #[test]
    fn refuses_wrong_domain() {
        let key = SigningKey::from_bytes(&SEED);
        let mut c = challenge_for(&key);
        c[20] = b'2';
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-domain");
    }

    #[test]
    fn refuses_a_foreign_node_id_hash() {
        // A challenge built for another node: this key must not sign it.
        let key = SigningKey::from_bytes(&SEED);
        let other = SigningKey::from_bytes(&[0x22; 32]);
        let c = challenge_for(&other);
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-foreign-node");
        // Even with --allow-any-genesis.
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, true).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-foreign-node");
    }

    #[test]
    fn refuses_a_non_mainnet_genesis_unless_allowed() {
        let key = SigningKey::from_bytes(&SEED);
        let mut c = challenge_for(&key);
        c[24..56].copy_from_slice(&[0x77; 32]);
        let err = sign_coldkey_registration(&key, &hex0x(&c), None, false).unwrap_err();
        assert_eq!(err.to_string(), "registration-arg/challenge-genesis");
        let out = sign_coldkey_registration(&key, &hex0x(&c), None, true).unwrap();
        key.verifying_key()
            .verify_strict(&c, &sig_from_hex(&out.signature))
            .unwrap();
    }

    #[test]
    fn arion_args_all_or_none() {
        let f = hex0x(&[1; 32]);
        let c = hex0x(&[2; 32]);
        assert_eq!(arion_args(None, None, None).unwrap(), None);
        assert_eq!(
            arion_args(Some(&f), Some(&c), Some(0)).unwrap(),
            Some(ArionArgs {
                family: [1; 32],
                child: [2; 32],
                nonce: 0
            })
        );
        for partial in [
            arion_args(Some(&f), None, None),
            arion_args(None, Some(&c), None),
            arion_args(None, None, Some(1)),
            arion_args(Some(&f), Some(&c), None),
            arion_args(Some(&f), None, Some(1)),
            arion_args(None, Some(&c), Some(1)),
        ] {
            assert_eq!(
                partial.unwrap_err().to_string(),
                "registration-arg/arion-args-all-or-none"
            );
        }
        assert_eq!(
            arion_args(Some("0x11"), Some(&c), Some(0))
                .unwrap_err()
                .to_string(),
            "registration-arg/family"
        );
    }

    #[test]
    fn keypair_file_must_be_exactly_32_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keypair.bin");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&SEED)
            .unwrap();
        let key = load_arion_keypair(&path).unwrap();
        assert_eq!(
            key.verifying_key(),
            SigningKey::from_bytes(&SEED).verifying_key()
        );
        // The file is left exactly as it was.
        assert_eq!(std::fs::read(&path).unwrap(), SEED);

        for len in [0usize, 31, 33, 64] {
            std::fs::write(&path, vec![0x11; len]).unwrap();
            assert_eq!(
                load_arion_keypair(&path).unwrap_err().to_string(),
                "identity-parse/keypair-len"
            );
        }
        // Our own hex `identity.key` format is not an Arion keypair.
        std::fs::write(&path, hex::encode(SEED)).unwrap();
        assert_eq!(
            load_arion_keypair(&path).unwrap_err().to_string(),
            "identity-parse/keypair-len"
        );
        assert_eq!(
            load_arion_keypair(&dir.path().join("absent"))
                .unwrap_err()
                .to_string(),
            "identity-missing"
        );
    }
}
