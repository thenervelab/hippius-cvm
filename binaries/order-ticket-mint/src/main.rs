//! `hippius-order-ticket-mint` — operator tool to mint L1-signed
//! `OrderTicket` COSE_Sign1 envelopes (ARCHITECTURE.md §6).
//!
//! This is a **producer-side** counterpart to
//! `kbs_core::ticket::verify_order_ticket`. The two MUST agree byte-
//! exactly on the wire format — this binary takes the verifier's
//! constraints as its source of truth and emits envelopes the KBS
//! will accept.
//!
//! ## Wire shape (cross-checked against the verifier)
//!
//! - **Body**: canonical-CBOR map per RFC 8949 §4.2.1, built via
//!   `hippius_types::cbor::to_canonical_vec` (sorted-by-encoded-key,
//!   no duplicate keys). Schema = `hippius_types::ticket::OrderTicket`
//!   (`SCHEMA_V = 1`, `deny_unknown_fields`).
//! - **Envelope**: COSE_Sign1 with `alg = EdDSA` + `kid = <operator-
//!   supplied>` in the protected header. The protected header is
//!   itself emitted as deterministic CBOR — the verifier rejects a
//!   non-canonical header bstr as a §20 ambiguity surface.
//! - **Signature**: Ed25519 over the COSE Sig_structure (handled by
//!   `coset`'s `create_signature`).
//!
//! ## Constraint mirror (refuse-at-mint vs verifier-side)
//!
//! The verifier already rejects an out-of-shape ticket, but every
//! such rejection downstream is an operator round-trip. We re-check
//! the same invariants at mint time so a typo'd `--vm-id` fails
//! locally, with a clear message, before the operator pipes bytes
//! into vali.
//!
//! - `v == 1`
//! - `nonce.len() == 32`
//! - `allowed_userdata_digest.len() == 32`
//! - every `allowed_measurement.len() == 48`
//! - `allowed_measurements` non-empty
//! - `luks_vault_ref.path != userdata_vault_ref.path`
//! - `luks_vault_ref.version > 0` AND `userdata_vault_ref.version > 0`
//! - `expiry > issue_time`
//!
//! Anything else (free-form `vm_id`, `tenant_id`, etc.) is the
//! operator's responsibility — they must match the §22 allowlist
//! entry the KBS will gate against.
//!
//! ## Out of scope (per PR-B brief)
//!
//! - Vault staging (LUKS KEK / sealed user-data plaintexts) — PR-V.
//! - Submission to vali — separate session.
//! - Production key handling / rotation — future PR.
//!
//! ## Security envelope
//!
//! - The signing key is read from a file path (CLI flag, not env).
//!   Operators are responsible for the file's filesystem ACL.
//! - The decoded signing key is zero-on-drop via `SigningKey`'s
//!   standard `Drop` impl.
//! - `Debug` is NEVER derived on any struct that carries the seed.
//! - Output is the raw COSE_Sign1 bytes — written to `--out` (file)
//!   or stdout. Stderr carries operator-facing diagnostics only,
//!   NEVER the seed and NEVER the ticket body (§20).

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value;
use clap::Parser;
use coset::CborSerializable;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::cbor::to_canonical_vec;
use hippius_types::guardian::KeyMode;
use hippius_types::ticket::SCHEMA_V;
use rand_core::{OsRng, RngCore};

/// Mint a COSE_Sign1 OrderTicket signed by an L1 Ed25519 key.
#[derive(Parser, Debug)]
#[command(
    name = "hippius-order-ticket-mint",
    about = "Mint an L1-signed OrderTicket COSE_Sign1 envelope (ARCHITECTURE.md §6).",
    long_about = "Mint an L1-signed OrderTicket COSE_Sign1 envelope.\n\nThe output is the byte-exact envelope `kbs_core::ticket::verify_order_ticket` accepts: canonical-CBOR body + COSE_Sign1 EdDSA wrapper + the operator-supplied kid in the protected header. Use `--out` to write to a file; without it the bytes go to stdout."
)]
struct Args {
    // ─── Signing identity ────────────────────────────────────────────
    /// Path to the Ed25519 signing key (32-byte seed, hex-encoded on
    /// a single line — the format
    /// `packer/keys/dev/l1-order-ticket.dev.ed25519` uses).
    #[arg(long, value_name = "FILE")]
    signing_key: PathBuf,

    /// Key identifier embedded in the COSE_Sign1 protected header
    /// (`kid`). The KBS resolves this against its `[[l1_keys]]`
    /// keyring (§22). ASCII string — encoded as bytes verbatim.
    #[arg(long, value_name = "STR")]
    kid: String,

    // ─── OrderTicket field set (§6) ──────────────────────────────────
    /// Public, opaque ticket identifier. Defaults to a fresh UUIDv4.
    #[arg(long, value_name = "STR")]
    ticket_id: Option<String>,

    /// Unix seconds the ticket was issued. Defaults to wall-clock
    /// `now()`.
    #[arg(long, value_name = "EPOCH")]
    issue_time: Option<u64>,

    /// Validity window (seconds) added to `issue_time` to compute
    /// `expiry`. Default: 3600 (1 hour).
    #[arg(long, value_name = "SECS", default_value_t = 3600)]
    expiry_seconds: u64,

    /// Hex-encoded 32-byte L1 per-ticket nonce. Defaults to 32 fresh
    /// random bytes. Must be EXACTLY 32 bytes — the KBS verifier
    /// rejects any other length.
    #[arg(long, value_name = "HEX")]
    nonce_hex: Option<String>,

    #[arg(long, value_name = "STR")]
    tenant_id: String,

    #[arg(long, value_name = "STR")]
    user_id: String,

    #[arg(long, value_name = "STR")]
    vm_id: String,

    #[arg(long, value_name = "STR")]
    lease_id: String,

    #[arg(long, value_name = "U64", default_value_t = 1)]
    vm_generation: u64,

    /// §23 compute miner identifier the placement is bound to.
    #[arg(long, value_name = "STR")]
    node_id: String,

    /// AMD SEV-SNP platform identifier (CHIP_ID / VCEK identity) the
    /// placement is bound to.
    #[arg(long, value_name = "STR")]
    platform_id: String,

    /// Hex-encoded 48-byte SNP launch measurement the KBS will gate
    /// against. May be repeated (`--allowed-measurement-hex <m1>
    /// --allowed-measurement-hex <m2>`). At least one is required.
    // `num_args = 1..` is belt-and-suspenders on top of `required =
    // true`: the latter only forces the flag to appear, the former
    // forces each appearance to carry a value. Together they
    // guarantee the `Vec` is never empty at parse time.
    #[arg(
        long = "allowed-measurement-hex",
        value_name = "HEX",
        required = true,
        num_args = 1..
    )]
    allowed_measurements_hex: Vec<String>,

    /// Vault KV v2 path where the §20 sealed user-data plaintext
    /// lives (e.g. `secret/hippius-compute/tenants/<vm_id>/userdata`).
    #[arg(long, value_name = "PATH")]
    userdata_vault_path: String,
    /// Vault KV v2 version of the user-data secret (must be `>= 1`).
    #[arg(long, value_name = "U64")]
    userdata_vault_version: u64,

    /// Vault KV v2 path where the LUKS KEK lives.
    #[arg(long, value_name = "PATH")]
    luks_vault_path: String,
    /// Vault KV v2 version of the LUKS KEK secret (must be `>= 1`).
    #[arg(long, value_name = "U64")]
    luks_vault_version: u64,

    /// Hex-encoded 32-byte SHA-256 of the user-data + binding fields
    /// the guest will re-derive on attest (§20).
    #[arg(long, value_name = "HEX")]
    allowed_userdata_digest_hex: String,

    /// Tenant VM size catalogue identifier (#312).
    /// One of `small` / `medium` / `large` — see
    /// `hippius_types::flavor::Flavor`. Replaces v1's free-form
    /// `--resource-class`.
    #[arg(long, value_name = "NAME", value_parser = parse_flavor_arg)]
    flavor: hippius_types::flavor::Flavor,

    /// Lifecycle permission grant (`launch` / `stop` / `migrate` /
    /// `destroy`). May be repeated; at least one is required.
    #[arg(
        long = "lifecycle-perm",
        value_name = "STR",
        required = true,
        num_args = 1..
    )]
    lifecycle_perms: Vec<String>,

    /// Customer-held disk keys: who holds this VM's disk key
    /// (`hippius_types::guardian::KeyMode`). Only `split` (M1) or
    /// `customer` (M2) may be given. Omitted ⇒ M0, and the ticket body
    /// carries NO `key_mode` entry — byte-identical to a mint made before
    /// this flag existed. `hippius` is refused: M0 has exactly one wire
    /// encoding (the absent key), and the verifier rejects the explicit one.
    #[arg(long, value_name = "MODE", value_parser = parse_key_mode_arg)]
    key_mode: Option<KeyMode>,

    // ─── Output ──────────────────────────────────────────────────────
    /// Write the COSE_Sign1 bytes to this file. Without `--out` the
    /// bytes are written to stdout — handy for piping into a sink.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// clap value_parser adapter for `Flavor` — bridges the type's
/// `FromStr` impl (#312) into clap's `Result<T, String>` shape.
fn parse_flavor_arg(s: &str) -> core::result::Result<hippius_types::flavor::Flavor, String> {
    s.parse::<hippius_types::flavor::Flavor>()
        .map_err(|e| e.to_string())
}

/// clap value_parser for `--key-mode`: `split` / `customer` only.
fn parse_key_mode_arg(s: &str) -> core::result::Result<KeyMode, String> {
    match KeyMode::from_wire(s) {
        Some(KeyMode::Hippius) => Err(
            "key_mode=hippius must be omitted (absent means hippius — M0 has one encoding)".into(),
        ),
        Some(mode) => Ok(mode),
        None => Err(format!(
            "unknown key mode {s:?} (expected split or customer)"
        )),
    }
}

/// Operator-facing error class. Carries a human-readable diagnostic;
/// the seed / ticket body are NEVER included.
#[derive(Debug)]
enum MintError {
    BadInput(String),
    Io(String),
    Crypto(String),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::BadInput(s) => write!(f, "bad input: {s}"),
            MintError::Io(s) => write!(f, "I/O: {s}"),
            MintError::Crypto(s) => write!(f, "crypto: {s}"),
        }
    }
}

impl std::error::Error for MintError {}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(MintError::BadInput(msg)) => {
            let _ = writeln!(io::stderr(), "error: {msg}");
            // exit 2 mirrors `ticket-validator`'s "structured input
            // rejection" convention — usable from scripts.
            ExitCode::from(2)
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<(), MintError> {
    let signing_key = load_signing_key(&args.signing_key)?;

    let kid_bytes = args.kid.clone().into_bytes();
    if kid_bytes.is_empty() {
        return Err(MintError::BadInput("--kid must not be empty".into()));
    }

    let issue_time = match args.issue_time {
        Some(t) => t,
        None => now_unix()?,
    };
    if args.expiry_seconds == 0 {
        return Err(MintError::BadInput(
            "--expiry-seconds must be > 0 (verifier rejects expired tickets)".into(),
        ));
    }
    let expiry = issue_time
        .checked_add(args.expiry_seconds)
        .ok_or_else(|| MintError::BadInput("issue_time + expiry_seconds overflows u64".into()))?;

    let ticket_id = args
        .ticket_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let nonce = resolve_nonce(args.nonce_hex.as_deref())?;
    let allowed_userdata_digest = decode_hex_exact(
        &args.allowed_userdata_digest_hex,
        32,
        "--allowed-userdata-digest-hex",
    )?;

    if args.allowed_measurements_hex.is_empty() {
        // `clap` `required = true` already enforces ≥1, but keep an
        // explicit guard so the binary still rejects an empty input
        // if invoked via a builder API in a test.
        return Err(MintError::BadInput(
            "at least one --allowed-measurement-hex required".into(),
        ));
    }
    let mut allowed_measurements = Vec::with_capacity(args.allowed_measurements_hex.len());
    for (i, hex_str) in args.allowed_measurements_hex.iter().enumerate() {
        let bytes = decode_hex_exact(hex_str, 48, &format!("--allowed-measurement-hex[{i}]"))?;
        allowed_measurements.push(bytes);
    }

    if args.luks_vault_path == args.userdata_vault_path {
        return Err(MintError::BadInput(
            "--luks-vault-path and --userdata-vault-path must differ (verifier rejects collisions)"
                .into(),
        ));
    }
    if args.userdata_vault_version == 0 || args.luks_vault_version == 0 {
        return Err(MintError::BadInput(
            "Vault ref versions must be >= 1 (KV v2 0 is never a concrete revision)".into(),
        ));
    }

    if args.lifecycle_perms.is_empty() {
        return Err(MintError::BadInput(
            "at least one --lifecycle-perm required".into(),
        ));
    }

    // Build the ticket body as a `Value::Map` and let `to_canonical_vec`
    // sort the keys + reject duplicates. Mirrors the test fixture in
    // `kbs-core::ticket::tests::ticket_payload` so the encoded shape
    // matches what the verifier already exercises.
    let mut body_entries = vec![
        (
            Value::Text("allowed_measurements".into()),
            Value::Array(
                allowed_measurements
                    .iter()
                    .map(|m| Value::Bytes(m.clone()))
                    .collect(),
            ),
        ),
        (
            Value::Text("allowed_userdata_digest".into()),
            Value::Bytes(allowed_userdata_digest),
        ),
        (Value::Text("expiry".into()), Value::Integer(expiry.into())),
        (
            Value::Text("issue_time".into()),
            Value::Integer(issue_time.into()),
        ),
        (
            Value::Text("lease_id".into()),
            Value::Text(args.lease_id.clone()),
        ),
        (
            Value::Text("lifecycle_perms".into()),
            Value::Array(
                args.lifecycle_perms
                    .iter()
                    .map(|p| Value::Text(p.clone()))
                    .collect(),
            ),
        ),
        (
            Value::Text("luks_vault_ref".into()),
            vault_ref_value(&args.luks_vault_path, args.luks_vault_version),
        ),
        (
            Value::Text("node_id".into()),
            Value::Text(args.node_id.clone()),
        ),
        (Value::Text("nonce".into()), Value::Bytes(nonce)),
        (
            Value::Text("platform_id".into()),
            Value::Text(args.platform_id.clone()),
        ),
        (
            Value::Text("flavor".into()),
            Value::Text(args.flavor.as_str().into()),
        ),
        (
            Value::Text("tenant_id".into()),
            Value::Text(args.tenant_id.clone()),
        ),
        (
            Value::Text("ticket_id".into()),
            Value::Text(ticket_id.clone()),
        ),
        (
            Value::Text("user_id".into()),
            Value::Text(args.user_id.clone()),
        ),
        (
            Value::Text("userdata_vault_ref".into()),
            vault_ref_value(&args.userdata_vault_path, args.userdata_vault_version),
        ),
        (Value::Text("v".into()), Value::Integer(SCHEMA_V.into())),
        (
            Value::Text("vm_generation".into()),
            Value::Integer(args.vm_generation.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(args.vm_id.clone())),
    ];
    // Customer-held keys: present only for M1/M2, so an M0 body is
    // unchanged (the canonical encoder sorts the entry into place).
    if let Some(mode) = args.key_mode {
        body_entries.push((
            Value::Text("key_mode".into()),
            Value::Text(mode.as_wire().into()),
        ));
    }
    let body_value = Value::Map(body_entries);
    let payload = to_canonical_vec(&body_value)
        .map_err(|e| MintError::BadInput(format!("encode ticket body: {e}")))?;

    let protected = coset::HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .key_id(kid_bytes)
        .build();
    let cose = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |tbs| signing_key.sign(tbs).to_bytes().to_vec())
        .build();
    let cose_bytes = cose
        .to_vec()
        .map_err(|e| MintError::Crypto(format!("COSE_Sign1 encode: {e:?}")))?;

    write_output(args.out.as_deref(), &cose_bytes)?;
    Ok(())
}

fn vault_ref_value(path: &str, version: u64) -> Value {
    Value::Map(vec![
        (Value::Text("path".into()), Value::Text(path.to_string())),
        (
            Value::Text("version".into()),
            Value::Integer(version.into()),
        ),
    ])
}

fn now_unix() -> Result<u64, MintError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| MintError::Io(format!("system clock before UNIX epoch: {e}")))
}

/// Load a 32-byte Ed25519 seed from a file whose contents are a single
/// line of 64 hex chars (matches the format
/// `packer/keys/dev/l1-order-ticket.dev.ed25519` uses).
fn load_signing_key(path: &PathBuf) -> Result<SigningKey, MintError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| MintError::Io(format!("read signing key {}: {e}", path.display())))?;
    let trimmed = raw.trim();
    // §20: a generic message — never the underlying `hex::FromHexError`
    // — keeps the offending character / position out of the operator
    // diagnostic. Even one byte of partial-key information is a
    // confidentiality leak we have no reason to accept.
    let seed = hex::decode(trimmed)
        .map_err(|_| MintError::BadInput("signing key is not valid hex".into()))?;
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
        MintError::BadInput(format!(
            "signing key must decode to exactly 32 bytes (got {})",
            seed.len()
        ))
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn resolve_nonce(supplied_hex: Option<&str>) -> Result<Vec<u8>, MintError> {
    match supplied_hex {
        Some(s) => decode_hex_exact(s, 32, "--nonce-hex"),
        None => {
            let mut buf = vec![0u8; 32];
            OsRng.fill_bytes(&mut buf);
            Ok(buf)
        }
    }
}

fn decode_hex_exact(input: &str, want_len: usize, flag: &str) -> Result<Vec<u8>, MintError> {
    let bytes = hex::decode(input.trim())
        .map_err(|e| MintError::BadInput(format!("{flag} is not hex: {e}")))?;
    if bytes.len() != want_len {
        return Err(MintError::BadInput(format!(
            "{flag} must decode to {want_len} bytes (got {})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn write_output(out: Option<&std::path::Path>, bytes: &[u8]) -> Result<(), MintError> {
    match out {
        Some(path) => fs::write(path, bytes)
            .map_err(|e| MintError::Io(format!("write {}: {e}", path.display()))),
        None => {
            let stdout = io::stdout();
            let mut h = stdout.lock();
            h.write_all(bytes)
                .map_err(|e| MintError::Io(format!("stdout write: {e}")))?;
            h.flush()
                .map_err(|e| MintError::Io(format!("stdout flush: {e}")))
        }
    }
}
