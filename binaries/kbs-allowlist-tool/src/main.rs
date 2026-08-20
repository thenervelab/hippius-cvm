//! `hippius-kbs-allowlist-tool` — offline §22 allowlist minter.
//!
//! Reads a TOML manifest (epoch + a list of `(measurement, l1 kids, KBS
//! kids)` tuples), signs the equivalent canonical-CBOR body with an
//! offline Ed25519 root key, and emits the COSE_Sign1 EdDSA artifact the
//! KBS binary consumes via its `[allowlist].signed_path`.
//!
//! ## What this tool DOES guarantee
//!
//! - Bit-identical canonical-CBOR encoding to what `kbs_core::allowlist::
//!   parse_and_verify` re-derives at runtime (shared `hippius_types::
//!   cbor::to_canonical_vec`).
//! - Round-trip pre-flight: every minted artifact is re-parsed +
//!   re-verified by `kbs_core::allowlist::parse_and_verify` against the
//!   matching public key before bytes are written, so an artifact the
//!   runtime would reject is never persisted.
//! - All seed material is held in `zeroize::Zeroizing` and wiped on drop.
//!
//! ## What this tool does NOT do
//!
//! - It is not the §22 ceremony — for production rollouts the seed lives
//!   on an offline ceremony host, never in this repo. The committed dev
//!   key under `packer/kbs-uki/keys/dev/` is the SAME key the §F UKI
//!   provenance signer uses; both are dev-only and clearly marked.
//! - It does NOT publish; `aws s3 cp` (or whatever transport) is a
//!   deliberately separate operator step.

// Tests use unwrap/expect/panic; the workspace denies them in non-test code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciborium::value::Value;
use clap::Parser;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hippius_types::cbor::to_canonical_vec;
use kbs_core::allowlist::{parse_and_verify, ALLOWLIST_V};
use kbs_core::snp::MEASUREMENT_LEN;
use serde::Deserialize;
use zeroize::Zeroizing;

const KBS_RESPONSE_KID_LEN_MIN: usize = 1;
const L1_KID_LEN_MIN: usize = 1;

/// CLI entry point.
#[derive(Parser, Debug)]
#[command(
    name = "hippius-kbs-allowlist-tool",
    version,
    about = "Mint + sign a §22 KBS measurement allowlist artifact (COSE_Sign1 EdDSA)."
)]
struct Args {
    /// Path to the manifest TOML (epoch + entries — see module docs).
    #[arg(long)]
    manifest: PathBuf,
    /// Path to the 32-byte Ed25519 seed (the §22 root signing key).
    /// Fail-closed on any read error or wrong length.
    #[arg(long)]
    seed: PathBuf,
    /// Output path for the signed COSE_Sign1 artifact.
    #[arg(long)]
    out: PathBuf,
}

/// On-disk manifest layout. `#[serde(deny_unknown_fields)]` everywhere so
/// a typo doesn't silently widen what the KBS will accept.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    /// Monotonic anti-rollback counter (§22 HWM). Strictly greater than
    /// the currently-installed epoch in every target KBS.
    epoch: u64,
    /// Per-measurement entries. The tool sorts them by measurement bytes
    /// before encoding (the canonical-CBOR contract).
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    /// 48-byte SNP launch digest, hex. Wrong length / non-hex aborts.
    measurement_hex: String,
    /// L1 OrderTicket-signing kids accepted for THIS measurement, hex.
    /// At least one; the KBS rejects an empty list.
    accepted_l1_kids_hex: Vec<String>,
    /// KBS response-signing kids accepted for THIS measurement, hex. At
    /// least one; the KBS rejects an empty list.
    accepted_kbs_response_kids_hex: Vec<String>,
    /// §22 trust class of THIS measurement — the stable snake_case wire
    /// string the KBS'`AllowlistEntry.class` decodes (`tenant` /
    /// `host_attestor`). Absent ⇒ the `tenant` default (byte-identical to
    /// every already-signed legacy manifest). A `host_attestor` measurement
    /// (the blackbox host-attestor chantier) MUST carry this so the KBS
    /// `class_of` gate namespaces it apart from tenant guest images —
    /// otherwise a host-attestor enrolment fails closed. Any other value
    /// aborts fail-closed.
    #[serde(default)]
    class: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("config: {0}")]
    Config(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("io: {0}")]
    Io(String),
}

/// Load the 32-byte Ed25519 seed from a hex-encoded file.
///
/// Matches the format the §F UKI provenance signer (`binaries/image-
/// provenance`) writes — 64 lowercase hex chars, optionally surrounded
/// by whitespace. Decoding goes straight from the zeroized file buffer
/// so the seed is never copied into an un-zeroized intermediate, not
/// even on the malformed-file error paths.
fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    let raw = Zeroizing::new(
        fs::read(path).map_err(|e| Error::Config(format!("read seed {}: {e}", path.display())))?,
    );
    let seed_vec = Zeroizing::new(
        hex::decode(raw.trim_ascii())
            .map_err(|_| Error::Config(format!("seed {}: file is not hex", path.display())))?,
    );
    if seed_vec.len() != 32 {
        return Err(Error::Config(format!(
            "seed {}: decoded length must be 32 bytes (got {})",
            path.display(),
            seed_vec.len()
        )));
    }
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seed_vec);
    Ok(seed)
}

fn parse_measurement(hex_str: &str) -> Result<[u8; MEASUREMENT_LEN], Error> {
    let v = hex::decode(hex_str.trim())
        .map_err(|e| Error::Manifest(format!("measurement {hex_str:?}: invalid hex: {e}")))?;
    if v.len() != MEASUREMENT_LEN {
        return Err(Error::Manifest(format!(
            "measurement {hex_str:?}: must be {MEASUREMENT_LEN} bytes (got {})",
            v.len()
        )));
    }
    let mut out = [0u8; MEASUREMENT_LEN];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Resolve a manifest entry's `class` field to the CBOR wire string to
/// EMIT, or `None` to OMIT the key entirely.
///
/// The KBS'`AllowlistEntry.class` serde-defaults to `Tenant` when the key
/// is absent, so a `tenant` (or unset) class emits NOTHING — that keeps the
/// canonical CBOR byte-identical to every already-signed legacy manifest
/// (no golden/KAT drift). A `host_attestor` class emits the explicit
/// `class` text key so the KBS `class_of` gate namespaces it. Any other
/// value is a fail-closed abort (a typo must never silently widen trust).
fn resolve_class_wire(class: &Option<String>) -> Result<Option<&'static str>, Error> {
    match class.as_deref().map(str::trim) {
        None | Some("") | Some("tenant") => Ok(None),
        Some("host_attestor") => Ok(Some("host_attestor")),
        Some(other) => Err(Error::Manifest(format!(
            "class {other:?}: must be \"tenant\" or \"host_attestor\""
        ))),
    }
}

fn parse_kid(field: &str, hex_str: &str, min_len: usize) -> Result<Vec<u8>, Error> {
    let v = hex::decode(hex_str.trim())
        .map_err(|e| Error::Manifest(format!("{field} {hex_str:?}: invalid hex: {e}")))?;
    if v.len() < min_len {
        return Err(Error::Manifest(format!(
            "{field} {hex_str:?}: must be at least {min_len} byte(s)"
        )));
    }
    Ok(v)
}

/// Build the canonical-CBOR `AllowlistBody` value (matches
/// `kbs_core::allowlist::AllowlistBody`'s schema bit-for-bit: `v`,
/// `epoch`, and `entries: Vec<(48-byte measurement, AllowlistEntry)>`
/// sorted ascending by measurement).
fn body_value(manifest: &Manifest) -> Result<Value, Error> {
    if manifest.entries.is_empty() {
        return Err(Error::Manifest(
            "manifest entries must not be empty (a zero-measurement allowlist denies everything \
             — equivalent to having no allowlist installed; the KBS already fails closed in that \
             case, so emitting one is a footgun)"
                .into(),
        ));
    }

    // Decode every measurement + kid up front so the sort + validation
    // pass operates on bytes, not strings.
    struct DecodedEntry {
        measurement: [u8; MEASUREMENT_LEN],
        l1_kids: Vec<Vec<u8>>,
        kbs_kids: Vec<Vec<u8>>,
        /// The `class` wire string to emit, or `None` to omit (⇒ Tenant).
        class_wire: Option<&'static str>,
    }
    let mut decoded: Vec<DecodedEntry> = Vec::with_capacity(manifest.entries.len());
    for (i, e) in manifest.entries.iter().enumerate() {
        let m = parse_measurement(&e.measurement_hex)
            .map_err(|err| Error::Manifest(format!("entries[{i}]: {err}")))?;
        if e.accepted_l1_kids_hex.is_empty() {
            return Err(Error::Manifest(format!(
                "entries[{i}]: accepted_l1_kids_hex must list at least one kid"
            )));
        }
        if e.accepted_kbs_response_kids_hex.is_empty() {
            return Err(Error::Manifest(format!(
                "entries[{i}]: accepted_kbs_response_kids_hex must list at least one kid"
            )));
        }
        let mut l1_kids: Vec<Vec<u8>> = Vec::with_capacity(e.accepted_l1_kids_hex.len());
        for (j, kh) in e.accepted_l1_kids_hex.iter().enumerate() {
            l1_kids.push(parse_kid(
                &format!("entries[{i}].accepted_l1_kids_hex[{j}]"),
                kh,
                L1_KID_LEN_MIN,
            )?);
        }
        let mut kbs_kids: Vec<Vec<u8>> = Vec::with_capacity(e.accepted_kbs_response_kids_hex.len());
        for (j, kh) in e.accepted_kbs_response_kids_hex.iter().enumerate() {
            kbs_kids.push(parse_kid(
                &format!("entries[{i}].accepted_kbs_response_kids_hex[{j}]"),
                kh,
                KBS_RESPONSE_KID_LEN_MIN,
            )?);
        }
        let class_wire = resolve_class_wire(&e.class)
            .map_err(|err| Error::Manifest(format!("entries[{i}]: {err}")))?;
        decoded.push(DecodedEntry {
            measurement: m,
            l1_kids,
            kbs_kids,
            class_wire,
        });
    }

    // Sort by 48-byte measurement bytes — the canonical-CBOR contract
    // (`AllowlistBody::into_indexed` refuses non-monotonic entries).
    decoded.sort_by(|a, b| a.measurement.cmp(&b.measurement));

    // Uniqueness check (`into_indexed` already enforces strict-less-than,
    // mirror it here so the tool fails before signing).
    for w in decoded.windows(2) {
        if w[0].measurement == w[1].measurement {
            return Err(Error::Manifest(format!(
                "duplicate measurement {} appears twice in the manifest",
                hex::encode(w[0].measurement)
            )));
        }
    }

    let entries: Vec<Value> = decoded
        .into_iter()
        .map(|d| {
            let DecodedEntry {
                measurement: m,
                l1_kids: l1,
                kbs_kids: kbs,
                class_wire,
            } = d;
            // The `AllowlistEntry` field order in the resulting map is
            // produced by `to_canonical_vec` (it re-sorts by encoded-key
            // bytes), so we can list them in any order here.
            let mut entry_map = vec![
                (
                    Value::Text("accepted_l1_kids".into()),
                    Value::Array(l1.into_iter().map(Value::Bytes).collect()),
                ),
                (
                    Value::Text("accepted_kbs_response_kids".into()),
                    Value::Array(kbs.into_iter().map(Value::Bytes).collect()),
                ),
            ];
            // Emit the `class` key ONLY for a non-default (host_attestor)
            // class — a tenant/absent class omits it, keeping the canonical
            // CBOR byte-identical to legacy manifests (the KBS back-fills
            // the `Tenant` default).
            if let Some(c) = class_wire {
                entry_map.push((Value::Text("class".into()), Value::Text(c.into())));
            }
            Value::Array(vec![Value::Bytes(m.to_vec()), Value::Map(entry_map)])
        })
        .collect();

    Ok(Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(ALLOWLIST_V.into())),
        (
            Value::Text("epoch".into()),
            Value::Integer(manifest.epoch.into()),
        ),
        (Value::Text("entries".into()), Value::Array(entries)),
    ]))
}

fn sign(seed: &Zeroizing<[u8; 32]>, body: &Value) -> Result<Vec<u8>, Error> {
    let payload = to_canonical_vec(body).map_err(|e| Error::Encode(format!("body: {e}")))?;
    let sk = SigningKey::from_bytes(seed);
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
        .build()
        .to_vec()
        .map_err(|e| Error::Encode(format!("COSE_Sign1: {e:?}")))
}

/// Round-trip: re-parse the COSE bytes the tool is about to write,
/// against the SAME root public key the runtime would use, and refuse to
/// emit anything `kbs_core::allowlist::parse_and_verify` would later
/// reject. The runtime accepts no other path.
fn verify_round_trip(cose: &[u8], vk: &VerifyingKey) -> Result<(), Error> {
    parse_and_verify(cose, vk).map_err(|e| Error::Verify(format!("round-trip: {e}")))?;
    Ok(())
}

fn run(args: Args) -> Result<(), Error> {
    let manifest_raw = fs::read_to_string(&args.manifest)
        .map_err(|e| Error::Config(format!("read manifest {}: {e}", args.manifest.display())))?;
    let manifest: Manifest = toml::from_str(&manifest_raw)
        .map_err(|e| Error::Manifest(format!("parse {}: {e}", args.manifest.display())))?;

    let seed = read_seed(&args.seed)?;
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let body = body_value(&manifest)?;
    let cose = sign(&seed, &body)?;
    verify_round_trip(&cose, &vk)?;

    // Write atomically — any half-written artifact would be discovered
    // by a downstream `parse_and_verify` (canonical-encoding check) but
    // we'd rather not emit one at all. Write to `<out>.tmp` + rename.
    let tmp = args.out.with_extension("cose.tmp");
    fs::write(&tmp, &cose).map_err(|e| Error::Io(format!("write {}: {e}", tmp.display())))?;
    fs::rename(&tmp, &args.out).map_err(|e| {
        Error::Io(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            args.out.display()
        ))
    })?;

    eprintln!(
        "hippius-kbs-allowlist-tool: wrote {} bytes to {} (epoch={}, entries={}, root_pubkey={})",
        cose.len(),
        args.out.display(),
        manifest.epoch,
        manifest.entries.len(),
        hex::encode(vk.to_bytes()),
    );
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hippius-kbs-allowlist-tool: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn manifest_with(epoch: u64, entries: Vec<ManifestEntry>) -> Manifest {
        Manifest { epoch, entries }
    }

    fn dev_entry(m: &[u8; 48]) -> ManifestEntry {
        ManifestEntry {
            measurement_hex: hex::encode(m),
            accepted_l1_kids_hex: vec![hex::encode(b"l1-kid-1")],
            accepted_kbs_response_kids_hex: vec![hex::encode(b"kbs-cc-1-response-v1")],
            class: None,
        }
    }

    fn classed_entry(m: &[u8; 48], class: Option<&str>) -> ManifestEntry {
        ManifestEntry {
            measurement_hex: hex::encode(m),
            accepted_l1_kids_hex: vec![hex::encode(b"l1-kid-1")],
            accepted_kbs_response_kids_hex: vec![hex::encode(b"kbs-cc-1-response-v1")],
            class: class.map(str::to_string),
        }
    }

    #[test]
    fn round_trip_signs_and_verifies() {
        // Mint an artifact and confirm `parse_and_verify` accepts it
        // against the matching root pubkey — the same call the KBS makes.
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new([42u8; 32]);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let m = [7u8; 48];
        let manifest = manifest_with(1, vec![dev_entry(&m)]);
        let body = body_value(&manifest).expect("body");
        let cose = sign(&seed, &body).expect("sign");
        let parsed = parse_and_verify(&cose, &vk).expect("verify");
        assert_eq!(parsed.epoch, 1);
        assert_eq!(parsed.v, ALLOWLIST_V);
        assert_eq!(parsed.entries.len(), 1);
        let (entry_m, entry) = &parsed.entries[0];
        assert_eq!(entry_m.as_ref(), &m[..]);
        assert_eq!(entry.accepted_l1_kids.len(), 1);
        assert_eq!(entry.accepted_kbs_response_kids.len(), 1);
        assert_eq!(
            entry.accepted_kbs_response_kids[0].as_ref(),
            b"kbs-cc-1-response-v1"
        );
    }

    #[test]
    fn wrong_pubkey_rejected() {
        // The runtime would reject this artifact — the tool MUST too
        // (we verify against the SAME pubkey the runtime will use).
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new([1u8; 32]);
        let wrong = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        let manifest = manifest_with(1, vec![dev_entry(&[7u8; 48])]);
        let body = body_value(&manifest).expect("body");
        let cose = sign(&seed, &body).expect("sign");
        assert!(parse_and_verify(&cose, &wrong).is_err());
    }

    #[test]
    fn empty_entries_rejected() {
        let manifest = manifest_with(1, vec![]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("entries must not be empty")),
            other => panic!("expected Manifest error, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_measurement_rejected_before_signing() {
        let m = [7u8; 48];
        let manifest = manifest_with(1, vec![dev_entry(&m), dev_entry(&m)]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("duplicate measurement")),
            other => panic!("expected Manifest(duplicate), got {other:?}"),
        }
    }

    #[test]
    fn bad_measurement_hex_rejected() {
        let m = ManifestEntry {
            measurement_hex: "not-hex".into(),
            accepted_l1_kids_hex: vec![hex::encode(b"l")],
            accepted_kbs_response_kids_hex: vec![hex::encode(b"k")],
            class: None,
        };
        let manifest = manifest_with(1, vec![m]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("invalid hex")),
            other => panic!("expected Manifest(invalid hex), got {other:?}"),
        }
    }

    #[test]
    fn wrong_length_measurement_rejected() {
        let m = ManifestEntry {
            measurement_hex: hex::encode([7u8; 32]),
            accepted_l1_kids_hex: vec![hex::encode(b"l")],
            accepted_kbs_response_kids_hex: vec![hex::encode(b"k")],
            class: None,
        };
        let manifest = manifest_with(1, vec![m]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("must be 48 bytes")),
            other => panic!("expected Manifest(48 bytes), got {other:?}"),
        }
    }

    #[test]
    fn empty_l1_kids_rejected() {
        let m = ManifestEntry {
            measurement_hex: hex::encode([7u8; 48]),
            accepted_l1_kids_hex: vec![],
            accepted_kbs_response_kids_hex: vec![hex::encode(b"k")],
            class: None,
        };
        let manifest = manifest_with(1, vec![m]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("accepted_l1_kids_hex")),
            other => panic!("expected Manifest(l1_kids empty), got {other:?}"),
        }
    }

    #[test]
    fn read_seed_accepts_hex_with_trailing_newline() {
        // The committed dev seed is 64 hex chars + a trailing newline —
        // verify the hex parser trims correctly.
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let seed_bytes = [9u8; 32];
        writeln!(f, "{}", hex::encode(seed_bytes)).unwrap();
        let got = read_seed(f.path()).expect("hex seed should load");
        assert_eq!(&got[..], &seed_bytes[..]);
    }

    #[test]
    fn read_seed_rejects_wrong_length() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{}", hex::encode([1u8; 16])).unwrap();
        match read_seed(f.path()) {
            Err(Error::Config(msg)) => assert!(msg.contains("32 bytes")),
            other => panic!("expected Config(length), got {other:?}"),
        }
    }

    #[test]
    fn read_seed_rejects_non_hex() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "not hex at all").unwrap();
        match read_seed(f.path()) {
            Err(Error::Config(msg)) => assert!(msg.contains("not hex")),
            other => panic!("expected Config(not hex), got {other:?}"),
        }
    }

    #[test]
    fn entries_sorted_ascending_in_output() {
        // Two measurements deliberately in reverse manifest order; the
        // tool MUST sort them before signing (the runtime's
        // `into_indexed` rejects non-monotonic input).
        let m_low = [1u8; 48];
        let m_high = [9u8; 48];
        let manifest = manifest_with(1, vec![dev_entry(&m_high), dev_entry(&m_low)]);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new([3u8; 32]);
        let sk = SigningKey::from_bytes(&seed);
        let body = body_value(&manifest).expect("body");
        let cose = sign(&seed, &body).expect("sign");
        let parsed = parse_and_verify(&cose, &sk.verifying_key()).expect("verify");
        assert_eq!(parsed.entries[0].0.as_ref(), &m_low[..]);
        assert_eq!(parsed.entries[1].0.as_ref(), &m_high[..]);
    }

    #[test]
    fn host_attestor_class_round_trips() {
        // A `host_attestor`-class entry must emit the `class` key so the
        // KBS `class_of` resolves it as HostAttestor (the blackbox
        // host-attestor namespace gate). Round-trip through the real
        // decoder to prove the wire form is what the KBS reads.
        use kbs_core::allowlist::{InMemoryHwm, InstalledAllowlist};
        use kbs_core::snp::{AllowlistClass, MeasurementAllowlist};

        let seed: Zeroizing<[u8; 32]> = Zeroizing::new([5u8; 32]);
        let sk = SigningKey::from_bytes(&seed);
        let host = [7u8; 48];
        let tenant = [9u8; 48];
        let manifest = manifest_with(
            1,
            vec![
                classed_entry(&host, Some("host_attestor")),
                classed_entry(&tenant, None),
            ],
        );
        let body = body_value(&manifest).expect("body");
        let cose = sign(&seed, &body).expect("sign");
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&cose).expect("install");
        assert_eq!(al.class_of(&host), Some(AllowlistClass::HostAttestor));
        // An absent class back-fills to Tenant (byte-identical to legacy).
        assert_eq!(al.class_of(&tenant), Some(AllowlistClass::Tenant));
    }

    #[test]
    fn tenant_and_absent_class_are_byte_identical() {
        // Emitting `class = "tenant"` must produce the SAME canonical CBOR
        // as omitting the key (the KBS default) — so a tenant re-pin never
        // drifts the golden `dev.cose` / measurement KATs.
        let m = [3u8; 48];
        let absent = body_value(&manifest_with(1, vec![classed_entry(&m, None)])).expect("absent");
        let explicit =
            body_value(&manifest_with(1, vec![classed_entry(&m, Some("tenant"))])).expect("tenant");
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new([6u8; 32]);
        assert_eq!(
            sign(&seed, &absent).expect("sign a"),
            sign(&seed, &explicit).expect("sign b"),
            "explicit tenant class must be byte-identical to omitting it"
        );
    }

    #[test]
    fn unknown_class_rejected() {
        let m = [4u8; 48];
        let manifest = manifest_with(1, vec![classed_entry(&m, Some("root"))]);
        match body_value(&manifest) {
            Err(Error::Manifest(msg)) => assert!(msg.contains("must be")),
            other => panic!("expected Manifest(class), got {other:?}"),
        }
    }
}
