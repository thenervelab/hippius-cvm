//! `verify-live-attestation` subcommand — KBS-L0-signed tenant-CVM
//! live-attestation decode + signature verification, for vali's
//! uptime-coverage ingest (§23 / issue #322 Phase B).
//!
//! ## Why this exists
//!
//! A `ServedDeliveryReceipt` is signed by the guest telemetry key,
//! which is HKDF-derived from the §7 lifecycle key and therefore
//! READABLE BY ROOT INSIDE THE CVM. A miner who launches its own
//! tenant VM, extracts that key, then KILLS the VM can keep signing
//! well-formed receipts forever — nothing in the receipt requires the
//! VM to still exist. The
//! [`hippius_types::live_attestation::LiveAttestation`] is the
//! artifact that *cannot* be produced that way: the KBS mints it only
//! after verifying a fresh `SNP_GET_REPORT` (VCEK → ASK → ARK against
//! AMD silicon root, §22 measurement allowlist, launch policy) whose
//! `REPORT_DATA` binds a single-use KBS nonce to the `vm_id`. That
//! report can only come from `/dev/sev-guest` inside a RUNNING CVM.
//!
//! vali consumes these as the coverage meter for uptime billing: only
//! a receipt window overlapped by a verified live attestation is
//! creditable. This subcommand is the decode+verify seam — vali must
//! never parse hostile CBOR in Python.
//!
//! ## `--vk-hex` is REQUIRED here (unlike `verify-host-attestor-cert`)
//!
//! The host-attestor cert path tolerates an unwired KBS L0 key by
//! emitting `verified:false` and persisting a `pending` row. There is
//! no such seam here: an unverified live attestation is worth exactly
//! nothing (a miner could mint one itself), so this subcommand
//! REFUSES to run without a verifying key rather than emit an
//! attacker-influenceable "decode-only" result vali might one day
//! treat as coverage. Fail closed at the seam, not at the consumer.
//!
//! The body's own `signer_pubkey` field is additionally required to
//! byte-equal `--vk-hex`: the body self-certifies which KBS produced
//! it, so a body claiming a different signer than the key that
//! verified it is internally inconsistent and refused.
//!
//! ## Wire contract (the stable JSON the Django consumer parses)
//!
//! - stdin: the canonical-CBOR [`SignedLiveAttestation`] envelope.
//! - `--vk-hex` (REQUIRED): 32-byte hex Ed25519 KBS L0 verifying key.
//! - stdout, one JSON object:
//!   - accept → `{"ok":true,"body":{…}}`.
//!   - reject → `{"ok":false,"error_class":"<class>"}` (no body echoed).
//! - exit: `0` on any validation outcome; `2` on a missing/malformed
//!   `--vk-hex` (stderr line, no JSON); `1` on a stdin/stdout IO
//!   failure.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::cbor::assert_canonical;
use hippius_types::live_attestation::{LiveAttestation, SignedLiveAttestation};
use serde::Serialize;
use sha2::{Digest, Sha256};

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Hard cap on the envelope read from stdin. A live attestation is
/// small (fixed byte fields + a `vm_id` + a 64-byte signature; well
/// under 1 KiB on the wire). Matches `_MAX_LIVE_ATTESTATION_BYTES` in
/// the Django consumer.
const MAX_REQUEST_BYTES: u64 = 4096;

/// Closed `error_class` vocabulary — `&'static str` only. Keep in sync
/// with the Django consumer (`LIVE_ATTESTATION_ERROR_CLASSES`).
mod error_class {
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const NOT_CANONICAL_CBOR: &str = "not_canonical_cbor";
    pub const ENVELOPE_DECODE_FAILED: &str = "envelope_decode_failed";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const BODY_DECODE_FAILED: &str = "body_decode_failed";
    /// The body's self-certified `signer_pubkey` is not the key the
    /// signature verified under.
    pub const SIGNER_MISMATCH: &str = "signer_mismatch";
}

#[derive(clap::Args)]
pub struct VerifyLiveAttestationArgs {
    /// 32-byte hex Ed25519 KBS L0 verifying key. REQUIRED — there is
    /// no decode-only mode (see the module doc).
    #[arg(long)]
    vk_hex: String,
}

/// The decoded body echoed on a successful validation. All byte fields
/// are hex so the JSON is ASCII-safe.
#[derive(Serialize, Debug)]
struct LiveAttestationBody {
    schema_version: u32,
    vm_id: String,
    node_id_hex: String,
    attestation_seq: u64,
    epoch: u64,
    observed_at_unix: u64,
    verified_at_unix: u64,
    expiry_unix: u64,
    measurement_hex: String,
    snp_report_digest_hex: String,
    vcek_chain_digest_hex: String,
    prev_attestation_hash_hex: String,
    signer_pubkey_hex: String,
    chain_genesis_hex: String,
    pallet_instance_hex: String,
    /// SHA-256 of the signed canonical body — the same value the KBS
    /// puts in the NEXT attestation's `prev_attestation_hash`. vali
    /// stores it as a second (byte-exact) replay-dedupe axis.
    body_digest_hex: String,
}

/// `verify-live-attestation` entry point.
pub fn run(args: VerifyLiveAttestationArgs) -> ExitCode {
    let vk = match parse_vk(&args.vk_hex) {
        Ok(vk) => vk,
        Err(message) => {
            eprintln!("hippius-ticket-validator: verify-live-attestation: {message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut buf)
    {
        eprintln!("hippius-ticket-validator: verify-live-attestation: stdin read failed: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }

    emit(verify(&buf, &vk))
}

fn emit(outcome: Result<LiveAttestationBody, &'static str>) -> ExitCode {
    let json = match outcome {
        Ok(body) => serde_json::json!({ "ok": true, "body": body }),
        Err(class) => serde_json::json!({ "ok": false, "error_class": class }),
    };
    let mut stdout = io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &json)
        .map_err(io::Error::from)
        .and_then(|()| stdout.flush());
    match written {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            eprintln!(
                "hippius-ticket-validator: verify-live-attestation: stdout write failed: {e}"
            );
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

/// Core validation — returns the decoded body, or a closed-vocabulary
/// `error_class` on the first failing gate. Gate order is deliberate:
/// size → canonical → envelope decode → strict re-encode → SIGNATURE →
/// body decode → signer self-consistency. Nothing past the signature
/// gate is reachable without the KBS L0 key.
fn verify(buf: &[u8], vk: &VerifyingKey) -> Result<LiveAttestationBody, &'static str> {
    if buf.len() as u64 > MAX_REQUEST_BYTES {
        return Err(error_class::BODY_TOO_LARGE);
    }
    if assert_canonical(buf).is_err() {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let envelope =
        SignedLiveAttestation::decode(buf).map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    // Strict-shape gate — re-encode + demand byte-equality, so a
    // semantically-equal-but-differently-encoded envelope cannot slip
    // a second digest past the consumer's dedupe.
    let recanonical = envelope
        .encode()
        .map_err(|_| error_class::ENVELOPE_DECODE_FAILED)?;
    if recanonical.as_slice() != buf {
        return Err(error_class::NOT_CANONICAL_CBOR);
    }
    let signature: [u8; 64] = envelope
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| error_class::SIGNATURE_INVALID)?;
    vk.verify_strict(&envelope.body, &Signature::from_bytes(&signature))
        .map_err(|_| error_class::SIGNATURE_INVALID)?;

    // The typed decoder asserts canonical body, live-attestation
    // domain, known schema_version, and `validate()` (non-empty vm_id,
    // non-zero seq, non-inverted window, strict expiry).
    let att =
        LiveAttestation::decode(&envelope.body).map_err(|_| error_class::BODY_DECODE_FAILED)?;
    if att.signer_pubkey != vk.to_bytes() {
        return Err(error_class::SIGNER_MISMATCH);
    }
    let body_digest: [u8; 32] = Sha256::digest(&envelope.body).into();
    Ok(LiveAttestationBody {
        body_digest_hex: hex::encode(body_digest),
        schema_version: att.schema_version,
        vm_id: att.vm_id,
        node_id_hex: hex::encode(att.node_id),
        attestation_seq: att.attestation_seq,
        epoch: att.epoch,
        observed_at_unix: att.observed_at_unix,
        verified_at_unix: att.verified_at_unix,
        expiry_unix: att.expiry_unix,
        measurement_hex: hex::encode(att.measurement),
        snp_report_digest_hex: hex::encode(att.snp_report_digest),
        vcek_chain_digest_hex: hex::encode(att.vcek_chain_digest),
        prev_attestation_hash_hex: hex::encode(att.prev_attestation_hash),
        signer_pubkey_hex: hex::encode(att.signer_pubkey),
        chain_genesis_hex: hex::encode(att.chain_genesis),
        pallet_instance_hex: hex::encode(att.pallet_instance),
    })
}

fn parse_vk(vk_hex: &str) -> Result<VerifyingKey, String> {
    let trimmed = vk_hex.trim();
    if trimmed.is_empty() {
        return Err("--vk-hex is required (no decode-only mode)".to_string());
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("--vk-hex is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "--vk-hex must be 32 bytes / 64 hex chars (got {})",
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("--vk-hex is not a valid Ed25519 key: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::live_attestation::{
        DIGEST_LEN, LIVE_ATTESTATION_SCHEMA_VERSION, MEASUREMENT_LEN, PUBKEY_LEN,
    };

    fn kat(signer: &SigningKey) -> LiveAttestation {
        LiveAttestation {
            schema_version: LIVE_ATTESTATION_SCHEMA_VERSION,
            chain_genesis: [0xAA; DIGEST_LEN],
            pallet_instance: [0xDD; DIGEST_LEN],
            vm_id: "tn-live-1".into(),
            node_id: [0xBB; PUBKEY_LEN],
            attestation_seq: 7,
            epoch: 4242,
            observed_at_unix: 1_800_000_000,
            verified_at_unix: 1_800_000_005,
            snp_report_digest: [0x11; DIGEST_LEN],
            vcek_chain_digest: [0x22; DIGEST_LEN],
            measurement: [0x33; MEASUREMENT_LEN],
            prev_attestation_hash: [0x44; DIGEST_LEN],
            expiry_unix: 1_800_000_900,
            signer_pubkey: signer.verifying_key().to_bytes(),
        }
    }

    fn signed(body: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        SignedLiveAttestation {
            body: body.clone(),
            sig: sk.sign(&body).to_bytes().to_vec(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn verified_path_surfaces_every_field() {
        let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let env = signed(kat(&sk).canonical().unwrap(), &sk);
        let body = verify(&env, &sk.verifying_key()).unwrap();
        assert_eq!(body.vm_id, "tn-live-1");
        assert_eq!(body.node_id_hex, "bb".repeat(PUBKEY_LEN));
        assert_eq!(body.attestation_seq, 7);
        assert_eq!(body.epoch, 4242);
        assert_eq!(body.observed_at_unix, 1_800_000_000);
        assert_eq!(body.verified_at_unix, 1_800_000_005);
        assert_eq!(body.expiry_unix, 1_800_000_900);
        assert_eq!(body.measurement_hex, "33".repeat(MEASUREMENT_LEN));
        assert_eq!(body.snp_report_digest_hex, "11".repeat(DIGEST_LEN));
        assert_eq!(body.prev_attestation_hash_hex, "44".repeat(DIGEST_LEN));
        assert_eq!(
            body.signer_pubkey_hex,
            hex::encode(sk.verifying_key().to_bytes())
        );
        // `body_digest_hex` must be SHA-256 over the SIGNED BODY — the
        // same value KBS chains into the next attestation's
        // `prev_attestation_hash`. vali dedupes on it.
        let expected: [u8; 32] = Sha256::digest(kat(&sk).canonical().unwrap()).into();
        assert_eq!(body.body_digest_hex, hex::encode(expected));
    }

    #[test]
    fn body_digest_differs_per_attestation() {
        // Two attestations for the same VM at different seqs must not
        // collide on the dedupe axis.
        let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let a = verify(
            &signed(kat(&sk).canonical().unwrap(), &sk),
            &sk.verifying_key(),
        )
        .unwrap();
        let mut second = kat(&sk);
        second.attestation_seq += 1;
        let b = verify(
            &signed(second.canonical().unwrap(), &sk),
            &sk.verifying_key(),
        )
        .unwrap();
        assert_ne!(a.body_digest_hex, b.body_digest_hex);
    }

    #[test]
    fn wrong_key_is_signature_invalid() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let pretender = SigningKey::from_bytes(&[2u8; 32]);
        let env = signed(kat(&signer).canonical().unwrap(), &signer);
        assert_eq!(
            verify(&env, &pretender.verifying_key()).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn body_signed_by_a_miner_key_is_refused() {
        // The whole point: a miner that mints its OWN live attestation
        // (its own Ed25519 key, its own body) cannot pass — vali only
        // ever verifies under the pinned KBS L0 key.
        let miner = SigningKey::from_bytes(&[0x99u8; 32]);
        let kbs = SigningKey::from_bytes(&[0x11u8; 32]);
        let env = signed(kat(&miner).canonical().unwrap(), &miner);
        assert_eq!(
            verify(&env, &kbs.verifying_key()).unwrap_err(),
            error_class::SIGNATURE_INVALID,
        );
    }

    #[test]
    fn signer_pubkey_mismatch_is_refused() {
        // A body claiming a signer other than the key that actually
        // signed it (and that we verified under) is inconsistent.
        let sk = SigningKey::from_bytes(&[0x7Au8; 32]);
        let mut att = kat(&sk);
        att.signer_pubkey = [0xEE; PUBKEY_LEN];
        let env = signed(att.canonical().unwrap(), &sk);
        assert_eq!(
            verify(&env, &sk.verifying_key()).unwrap_err(),
            error_class::SIGNER_MISMATCH,
        );
    }

    #[test]
    fn tampered_body_is_refused() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut body = kat(&sk).canonical().unwrap();
        let sig = sk.sign(&body);
        let last = body.len() - 1;
        body[last] ^= 0xff;
        let env = SignedLiveAttestation {
            body,
            sig: sig.to_bytes().to_vec(),
        }
        .encode()
        .unwrap();
        let class = verify(&env, &sk.verifying_key()).unwrap_err();
        assert!(
            class == error_class::SIGNATURE_INVALID || class == error_class::NOT_CANONICAL_CBOR,
            "got {class}",
        );
    }

    #[test]
    fn garbage_is_refused() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let class = verify(b"not-cbor", &sk.verifying_key()).unwrap_err();
        assert!(
            class == error_class::NOT_CANONICAL_CBOR
                || class == error_class::ENVELOPE_DECODE_FAILED,
            "got {class}",
        );
    }

    #[test]
    fn oversize_body_is_refused() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let big = vec![0u8; (MAX_REQUEST_BYTES + 1) as usize];
        assert_eq!(
            verify(&big, &sk.verifying_key()).unwrap_err(),
            error_class::BODY_TOO_LARGE,
        );
    }

    #[test]
    fn parse_vk_requires_a_key() {
        assert!(parse_vk("").is_err());
        assert!(parse_vk("   ").is_err());
        assert!(parse_vk("not-hex").is_err());
        assert!(parse_vk("abcd").is_err());
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        assert!(parse_vk(&hex::encode(sk.verifying_key().to_bytes())).is_ok());
    }
}
