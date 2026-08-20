//! `hippius-ticket-validator` — vali's Rust shell-out helper.
//!
//! Two subcommands:
//!
//! - `verify-ticket` — parse a COSE_Sign1 OrderTicket from stdin (§6).
//!   Does **NOT** verify the L1 Ed25519 signature: vali transports the
//!   ticket opaquely (§3 / §4); signature verification lives in the
//!   KBS (`kbs_core::ticket::verify_order_ticket`). vali only stores
//!   the byte-exact COSE blob and uses the parsed metadata for
//!   indexing.
//! - `verify-stopped-ack` — verify a `SignedStoppedAck` from stdin
//!   (§24/§25). Re-derives the canonical-CBOR body from the operator-
//!   supplied expected fields and Ed25519-verifies via
//!   `hippius_guest::verify_stopped_ack`. The orchestrator (vali)
//!   requires a valid ack before transitioning a VM to `Destroyed{gen}`
//!   or activating a migration destination — that's where this
//!   subcommand fires.
//! - `read-miner-status` — read §23 `pallet-compute-scoring` state
//!   (`MinerStatuses`, `CurrentEpoch`, `EpochWeights`) from a
//!   `thenervelab/thebrain` Substrate node over JSON-RPC, for the
//!   PR-G4 vali scheduler. Reads no stdin. See `mod miner_status`.
//! - `idempotency-record` / `idempotency-recall` — §14 retry-dedup
//!   over `kbs_core::persist::FileIdempotencyStore`, for the PR-G5
//!   vali §24/§25 orchestrator. Read no stdin. See `mod idempotency`.
//! - `verify-edge-telemetry` / `verify-served-receipt` — §9
//!   telemetry-broker signature + schema validation, for the PR-G6
//!   vali telemetry broker. Body on stdin. See `mod telemetry`.
//! - `verify-heartbeat` — §K miner-heartbeat signature + schema
//!   validation, for vali's heartbeat ingest gate (#127). A
//!   `SignedMinerHeartbeat` envelope on stdin; `--vk-hex`. Unlike every
//!   other `verify-*` subcommand it is **data-bearing** — see the wire
//!   contract note below and `mod heartbeat`.
//!
//! ## Wire contract (`verify-*` subcommands)
//!
//! - stdin: raw bytes (deterministic CBOR for `verify-ticket`,
//!   `SignedStoppedAck` CBOR for `verify-stopped-ack`).
//! - stdout: a single JSON object — `{"tag": "ok", ...}` on success
//!   or `{"tag": "err", "error": "...", "category": "..."}` on a
//!   structured rejection.
//! - stderr: human-readable diagnostic (NEVER ticket / ack bytes — §20
//!   logging discipline).
//! - exit codes:
//!     - `0` — `tag: ok` on stdout.
//!     - `2` — `tag: err`, structured validation failure (HTTP 400).
//!     - `1` — internal/IO error (HTTP 503).
//!
//! `category` is drawn from a stable vocabulary (see `mod category`)
//! so the Django side maps each value to an error code.
//!
//! ### Exception — `verify-heartbeat` is data-bearing
//!
//! `verify-heartbeat` does **not** follow the `tag`/`category` contract
//! above. vali's heartbeat gate (#127) needs the decoded body to run
//! the `±300 s` anti-skew + monotonic-`sequence` replay checks WITHOUT
//! decoding CBOR in Python, so the subcommand emits
//! `{"ok":true,"body":{…}}` on accept / `{"ok":false,"error_class":…}`
//! on reject, and exits `0` for BOTH outcomes (`2` only on a malformed
//! `--vk-hex`, `1` only on a stdin/stdout IO failure). The full
//! contract lives in `mod heartbeat`.

use std::io::{self, Read};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use coset::CborSerializable;
use ed25519_dalek::VerifyingKey;
use hippius_guest::verify_stopped_ack;
use hippius_types::cbor::assert_canonical;
use hippius_types::stopped::{SignedStoppedAck, StoppedAck};
use hippius_types::ticket::{OrderTicket, SCHEMA_V};
use serde::Serialize;

mod derive_lifecycle_vk;
mod derive_telemetry_key;
mod encode_order;
mod gen_lifecycle_key;
mod graceful_exit;
mod heartbeat;
mod host_attestor_cert;
mod host_beacon;
mod host_challenge_request;
mod idempotency;
mod live_attestation;
mod miner_status;
mod pending_prices;
mod telemetry;
mod vm_progress;

/// Stdout JSON envelope. `tag = "ok"`/`tag = "err"` rather than a
/// boolean so future categorical results (e.g. `warn`) can extend the
/// schema without breaking the Django consumer.
///
/// The `Ok` variant boxes the (~400-byte) parsed ticket so the enum
/// stays small on the stack — short-lived in `main`, but it's the
/// shape lint catches and there's no reason to push the larger
/// payload by value.
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum Output {
    Ok {
        ticket: Box<TicketJson>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

/// Hex-encoded byte fields so the JSON is ASCII-safe. The Django side
/// rehydrates via `bytes.fromhex(...)` when needed.
#[derive(Serialize, Debug)]
struct TicketJson {
    v: u32,
    ticket_id: String,
    issue_time: u64,
    expiry: u64,
    nonce_hex: String,
    tenant_id: String,
    user_id: String,
    vm_id: String,
    lease_id: String,
    vm_generation: u64,
    node_id: String,
    platform_id: String,
    allowed_measurements_hex: Vec<String>,
    userdata_vault_ref: VaultRefJson,
    luks_vault_ref: VaultRefJson,
    allowed_userdata_digest_hex: String,
    /// #312 — v2 carries the typed `Flavor` (`small`/`medium`/`large`)
    /// in place of v1's free-form `resource_class: String`. The
    /// JSON-out side surfaces the canonical kebab-case string so the
    /// Python orchestrator can treat it as opaque while still
    /// matching `hippius_types::flavor::Flavor::as_str()`.
    flavor: String,
    lifecycle_perms: Vec<String>,
    /// Outer envelope `kid` (Ed25519 key id) the L1 minter signed
    /// with. Vali stores this for KBS-side routing without ever
    /// trusting it as authority — the KBS independently re-checks the
    /// kid against its §22 offline allowlist.
    kid_hex: String,
    /// Byte length of the COSE_Sign1 envelope as seen on stdin.
    /// Surfaces drift between Django's `Content-Length` and the
    /// validator's view of the bytes (defense against truncation
    /// bugs in middleware).
    cose_len: usize,
}

#[derive(Serialize, Debug)]
struct VaultRefJson {
    path: String,
    version: u64,
}

/// Stable strings for the `category` field — keep in sync with the
/// Django consumers (`apps.orders.validator`, `apps.lifecycle.validator`).
mod category {
    pub const COSE_PARSE: &str = "cose-parse";
    pub const NON_CANONICAL_CBOR: &str = "non-canonical-cbor";
    pub const MISSING_HEADER: &str = "missing-header";
    pub const PAYLOAD_DECODE: &str = "payload-decode";
    pub const SCHEMA: &str = "schema";
    pub const BYTE_LENGTH: &str = "byte-length";
    /// String / blob field exceeded the DB-side `max_length`. Pre-
    /// rejected here so vali never raises a Postgres `DataError`
    /// (would surface as an unhandled 500).
    pub const STRING_TOO_LONG: &str = "string-too-long";
    /// `u64` field exceeded `i64::MAX` (Postgres `BIGINT` is signed
    /// 64-bit). Pre-rejected here for the same reason as
    /// `STRING_TOO_LONG`.
    pub const INT_OVERFLOW: &str = "int-overflow";
    /// COSE protected header `alg` is missing or not Ed25519/EdDSA.
    /// Mirrors `kbs_core::ticket::verify_order_ticket` (§6/§20: the
    /// KBS rejects anything that's not Ed25519 EdDSA).
    pub const ALG: &str = "alg";

    // ─── verify-stopped-ack (§24/§25) ─────────────────────────────
    /// CBOR / hex / byte-length decode failure on an input (vk, nonce,
    /// SignedStoppedAck envelope, body).
    pub const STOPPED_DECODE: &str = "stopped-decode";
    /// Re-derived canonical body did not byte-equal the signed body —
    /// the operator-supplied expected fields disagree with what the
    /// guest signed. Hard reject (§24/§25 anti-replay-across-fields).
    pub const STOPPED_BODY_MISMATCH: &str = "stopped-body-mismatch";
    /// Ed25519 verify failed against the guest's pinned lifecycle key.
    pub const STOPPED_SIGNATURE: &str = "stopped-signature";
    /// The guest-signed `now_unix` is outside the operator-supplied
    /// `[now_unix_min, now_unix_max]` skew window. Anti-replay across
    /// time: vali expects the ack to be freshly signed.
    pub const STOPPED_WINDOW: &str = "stopped-window";
}

// ─── Schema limits (mirror DB CharField max_length in vali) ──────────
//
// Vali's `OrderTicketIntake` uses CharField(max_length=128) for short
// identifiers, CharField(max_length=256) for paths/ids that may be a
// little longer, and CharField(max_length=512) for the hex-encoded
// kid. We pre-reject anything larger so the Postgres write cannot
// fail with `DataError` after the validator has already said `ok`.
//
// Update both sides together — there's a compile-gate test below
// that asserts the constants line up with the validator's emitted
// categories.

const MAX_ID_LEN: usize = 256;
// #312 — `MAX_RESOURCE_CLASS_LEN` retired in OrderTicket v2 (closed
// `Flavor` enum replaces the free-form string; bounded by the type).
const MAX_KID_BYTES: usize = 256;
// hex(MAX_KID_BYTES) ≤ 512, matches CharField(max_length=512).
const MAX_LIFECYCLE_PERMS: usize = 32;
const MAX_LIFECYCLE_PERM_LEN: usize = 64;
const MAX_ALLOWED_MEASUREMENTS: usize = 8;

const SCHEMA_FAIL: u8 = 2;
const INTERNAL_FAIL: u8 = 1;

#[derive(Parser)]
#[command(name = "hippius-ticket-validator")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse a COSE_Sign1 OrderTicket from stdin (§6). Does NOT verify
    /// the L1 signature — that's the KBS's job.
    VerifyTicket,
    /// Verify a `SignedStoppedAck` from stdin (§24/§25) against the
    /// guest's pinned Ed25519 lifecycle key. The operator supplies the
    /// expected fields; we re-derive the canonical body and compare.
    VerifyStoppedAck(VerifyStoppedAckArgs),
    /// Read §23 `pallet-compute-scoring` miner status from a thebrain
    /// Substrate node over JSON-RPC (PR-G4 scheduler). Reads no stdin;
    /// the RPC endpoint comes from the `THEBRAIN_RPC_URL` env var.
    ReadMinerStatus(miner_status::ReadMinerStatusArgs),
    /// Read §23 `pallet-compute-scoring` pending miner price changes
    /// (the marketplace price-watch input) from a thebrain Substrate
    /// node over JSON-RPC. Reads no stdin; the RPC endpoint comes from
    /// the `THEBRAIN_RPC_URL` env var.
    ReadPendingPrices(pending_prices::ReadPendingPricesArgs),
    /// Record a §14 idempotency key (PR-G5 orchestration retry-dedup).
    /// Store dir from the `IDEMPOTENCY_DIR` env var.
    IdempotencyRecord(idempotency::IdempotencyRecordArgs),
    /// Recall a §14 idempotency key. Store dir from `IDEMPOTENCY_DIR`.
    IdempotencyRecall(idempotency::IdempotencyRecallArgs),
    /// Verify a §H Edge telemetry envelope (PR-G6 broker). Canonical
    /// body on stdin; `--sig-hex`, `--vk-hex`.
    VerifyEdgeTelemetry(telemetry::VerifyTelemetryArgs),
    /// Verify a §23 tenant served-delivery receipt (PR-G6 broker).
    /// Canonical body on stdin; `--sig-hex`, `--vk-hex`.
    VerifyServedReceipt(telemetry::VerifyTelemetryArgs),
    /// Verify a §K `SignedMinerHeartbeat` from stdin against the
    /// miner's `--vk-hex` and echo the decoded body for vali's
    /// heartbeat ingest gate (#127). Data-bearing — see `mod heartbeat`.
    VerifyHeartbeat(heartbeat::VerifyHeartbeatArgs),
    /// Verify a `SignedGracefulExit` from stdin against the miner's
    /// `--vk-hex` and echo the decoded body for vali's graceful-exit
    /// endpoint (replay + skew gate). Data-bearing — see
    /// `mod graceful_exit`.
    VerifyGracefulExit(graceful_exit::VerifyGracefulExitArgs),
    /// Verify a `SignedVmProgress` guest-boot milestone from stdin
    /// against the miner's `--vk-hex` and echo the decoded body
    /// (`vm_id`, `milestone`, `timestamp_unix`) for vali's boot-progress
    /// ingest (skew gate + monotonic `boot_phase` advance). Data-bearing
    /// — see `mod vm_progress`.
    VerifyVmProgress(vm_progress::VerifyVmProgressArgs),
    /// Verify a blackbox host-attestor `SignedHostAttestorCert` from stdin
    /// and echo the decoded body (`chip_id`, `measurement`, `node_id`,
    /// `attestor_pubkey`, …) for vali's host-attestor cert-ingest gate
    /// (PR-8). `--vk-hex` (the KBS L0 key) is OPTIONAL: present → the
    /// signature is checked (`verified:true`); absent → decode-only
    /// (`verified:false`, the KBS-L0-pubkey-not-wired seam). Data-bearing
    /// — see `mod host_attestor_cert`.
    VerifyHostAttestorCert(host_attestor_cert::VerifyHostAttestorCertArgs),
    /// Verify a KBS-L0-signed tenant-CVM `SignedLiveAttestation` from
    /// stdin and echo the decoded body (`vm_id`, `node_id`,
    /// `attestation_seq`, `verified_at_unix`, `measurement`, …) for
    /// vali's uptime-coverage ingest (§23). `--vk-hex` (the KBS L0
    /// key) is REQUIRED — there is no decode-only mode, because an
    /// unverified live attestation is worth nothing. Data-bearing —
    /// see `mod live_attestation`.
    VerifyLiveAttestation(live_attestation::VerifyLiveAttestationArgs),
    /// Verify a blackbox host-attestor `SignedHostBeacon` from stdin
    /// against the KBS-certified attestor `--vk-hex` and echo the decoded
    /// body for vali's host-beacon ingest gate (monotonic `seq` + expiry).
    /// Data-bearing — see `mod host_beacon`.
    VerifyHostBeacon(host_beacon::VerifyHostBeaconArgs),
    /// Decode a blackbox host-attestor `HostChallengeRequest` from stdin
    /// and echo the surfaced `signer_pubkey` for vali's nonce authority
    /// (PR-10). Decode-only (no signature) — vali binds the minted
    /// single-use nonce to `{peer-stamped node_id, this pk}`. Data-bearing
    /// — see `mod host_challenge_request`.
    VerifyHostChallengeRequest,
    /// Build a canonical-CBOR §H phase-2 `OrderBody` from a JSON
    /// payload on stdin + `--order-id` + `--kind`. Build-only (no
    /// signature) — vali pipes the bytes into the Edge `POST
    /// /v1/edge/order` body; the Edge signs + forwards to the miner.
    /// See `mod encode_order`.
    EncodeOrder(encode_order::EncodeOrderArgs),
    /// §7 — generate a per-VM guest lifecycle Ed25519 keypair. Reads no
    /// stdin; emits `{"seed_hex","vk_hex"}` on stdout. vali stages the
    /// seed (PRIVATE key) into Vault for the KBS to release to the
    /// attested guest, and records the vk (PUBLIC key) as
    /// `Vm.lifecycle_vk`. See `mod gen_lifecycle_key`.
    GenLifecycleKey,
    /// Derive the per-VM tenant telemetry PUBLIC key from the lifecycle
    /// seed (read as hex on stdin); emits `{"vk_hex"}`. vali provisions
    /// the `TelemetrySource` it verifies served-receipts against. The
    /// guest reproduces the same key from its released lifecycle seed.
    /// See `mod derive_telemetry_key`.
    DeriveTelemetryKey,
    /// §7 — re-derive the lifecycle PUBLIC key from an already-staged
    /// lifecycle seed (read as hex on stdin); emits `{"vk_hex"}`. The KBS
    /// reads the seed at pinned Vault version 1 forever, so a re-launch
    /// reuses the version-1 seed — vali re-derives the matching vk instead
    /// of rotating the keypair. See `mod derive_lifecycle_vk`.
    DeriveLifecycleVk,
}

#[derive(Args)]
struct VerifyStoppedAckArgs {
    /// 32-byte hex Ed25519 verifying key (the guest's lifecycle
    /// pubkey, provisioned via §7 attested release).
    #[arg(long)]
    vk_hex: String,
    /// Expected `vm_id` the ack should bind to.
    #[arg(long)]
    vm_id: String,
    /// Expected `lease_id` the ack should bind to.
    #[arg(long)]
    lease_id: String,
    /// Expected `vm_generation` the ack should bind to.
    #[arg(long)]
    vm_generation: u64,
    /// 32-byte hex of the single-use nonce vali issued for this EOL
    /// event. The signed `nonce` field MUST equal this value.
    #[arg(long)]
    nonce_hex: String,
    /// Inclusive lower bound on the guest-supplied `now_unix`. The
    /// caller (vali) computes `current_time - max_skew`.
    #[arg(long)]
    now_unix_min: u64,
    /// Inclusive upper bound — `current_time + max_skew`.
    #[arg(long)]
    now_unix_max: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyTicket => cmd_verify_ticket(),
        Command::VerifyStoppedAck(args) => cmd_verify_stopped_ack(args),
        Command::ReadMinerStatus(args) => miner_status::run(args),
        Command::ReadPendingPrices(args) => pending_prices::run(args),
        Command::IdempotencyRecord(args) => idempotency::run_record(args),
        Command::IdempotencyRecall(args) => idempotency::run_recall(args),
        Command::VerifyEdgeTelemetry(args) => telemetry::run_edge_telemetry(args),
        Command::VerifyServedReceipt(args) => telemetry::run_served_receipt(args),
        Command::VerifyHeartbeat(args) => heartbeat::run(args),
        Command::VerifyGracefulExit(args) => graceful_exit::run(args),
        Command::VerifyVmProgress(args) => vm_progress::run(args),
        Command::VerifyHostAttestorCert(args) => host_attestor_cert::run(args),
        Command::VerifyLiveAttestation(args) => live_attestation::run(args),
        Command::VerifyHostBeacon(args) => host_beacon::run(args),
        Command::VerifyHostChallengeRequest => host_challenge_request::run(),
        Command::EncodeOrder(args) => encode_order::run(args),
        Command::GenLifecycleKey => gen_lifecycle_key::run(),
        Command::DeriveTelemetryKey => derive_telemetry_key::run(),
        Command::DeriveLifecycleVk => derive_lifecycle_vk::run(),
    }
}

fn cmd_verify_ticket() -> ExitCode {
    let mut cose = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut cose) {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(INTERNAL_FAIL);
    }
    match validate(&cose) {
        Ok(ticket_json) => {
            // serde_json on a `#[derive(Serialize)]` struct can only
            // fail on bad numeric types — none here — so a write
            // failure is the only realistic error and is plumbed to
            // exit code 1.
            match serde_json::to_writer(
                io::stdout().lock(),
                &Output::Ok {
                    ticket: Box::new(ticket_json),
                },
            ) {
                Ok(()) => ExitCode::from(0),
                Err(e) => {
                    eprintln!("hippius-ticket-validator: stdout write failed: {e}");
                    ExitCode::from(INTERNAL_FAIL)
                }
            }
        }
        Err((category, msg)) => {
            let payload = Output::Err {
                error: msg,
                category,
            };
            // Failure to serialize a static-string error is itself an
            // internal failure — caller treats exit-code 1 as 503.
            match serde_json::to_writer(io::stdout().lock(), &payload) {
                Ok(()) => ExitCode::from(SCHEMA_FAIL),
                Err(e) => {
                    eprintln!("hippius-ticket-validator: stdout write failed: {e}");
                    ExitCode::from(INTERNAL_FAIL)
                }
            }
        }
    }
}

// ─── verify-stopped-ack subcommand ───────────────────────────────────

/// Success envelope for `verify-stopped-ack`. Echoes the guest-signed
/// `now_unix` so the operator can audit the value vali accepted.
#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum StoppedOutput {
    Ok {
        now_unix: u64,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

fn cmd_verify_stopped_ack(args: VerifyStoppedAckArgs) -> ExitCode {
    let mut signed_bytes = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut signed_bytes) {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(INTERNAL_FAIL);
    }
    let payload = match verify_stopped(&args, &signed_bytes) {
        Ok(now_unix) => StoppedOutput::Ok { now_unix },
        Err((category, msg)) => StoppedOutput::Err {
            error: msg,
            category,
        },
    };
    let exit = match &payload {
        StoppedOutput::Ok { .. } => 0,
        StoppedOutput::Err { .. } => SCHEMA_FAIL,
    };
    match serde_json::to_writer(io::stdout().lock(), &payload) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(INTERNAL_FAIL)
        }
    }
}

/// Core verification. Returns the guest-signed `now_unix` on success
/// so the caller can log / record it.
fn verify_stopped(
    args: &VerifyStoppedAckArgs,
    signed_bytes: &[u8],
) -> Result<u64, (&'static str, String)> {
    // Decode + length-check the pinned Ed25519 verifying key.
    let vk_bytes = hex::decode(args.vk_hex.as_bytes())
        .map_err(|e| (category::STOPPED_DECODE, format!("vk_hex decode: {e}")))?;
    let vk_arr: [u8; 32] = vk_bytes.as_slice().try_into().map_err(|_| {
        (
            category::STOPPED_DECODE,
            format!("vk must be 32 bytes (got {})", vk_bytes.len()),
        )
    })?;
    let vk = VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| (category::STOPPED_DECODE, format!("vk parse: {e}")))?;

    // Decode the single-use EOL nonce vali issued.
    let nonce_bytes = hex::decode(args.nonce_hex.as_bytes())
        .map_err(|e| (category::STOPPED_DECODE, format!("nonce_hex decode: {e}")))?;
    let nonce_arr: [u8; 32] = nonce_bytes.as_slice().try_into().map_err(|_| {
        (
            category::STOPPED_DECODE,
            format!("nonce must be 32 bytes (got {})", nonce_bytes.len()),
        )
    })?;

    // Decode the SignedStoppedAck envelope (CBOR `{body: bytes, sig:
    // bytes}` — see `hippius_types::stopped::SignedStoppedAck`).
    let signed: SignedStoppedAck = ciborium::de::from_reader(signed_bytes).map_err(|e| {
        (
            category::STOPPED_DECODE,
            format!("SignedStoppedAck decode: {e}"),
        )
    })?;

    // Pull `now_unix` out of the signed body so we can window-check
    // BEFORE re-deriving the expected canonical bytes. We do NOT trust
    // the body yet — the canonical-equality + Ed25519 check below
    // closes the loop.
    let body_now_unix = extract_now_unix(&signed.body)?;
    if body_now_unix < args.now_unix_min || body_now_unix > args.now_unix_max {
        return Err((
            category::STOPPED_WINDOW,
            format!(
                "now_unix={} outside [{}, {}]",
                body_now_unix, args.now_unix_min, args.now_unix_max,
            ),
        ));
    }

    // Re-derive the canonical body the operator EXPECTS the guest to
    // have signed. `verify_stopped_ack` byte-compares against
    // `signed.body` then `verify_strict`s the sig.
    let expected = StoppedAck {
        vm_id: &args.vm_id,
        lease_id: &args.lease_id,
        vm_generation: args.vm_generation,
        nonce: &nonce_arr,
        now_unix: body_now_unix,
    };
    verify_stopped_ack(&vk, &signed, &expected).map_err(classify_guest_error)?;

    Ok(body_now_unix)
}

/// Map `hippius_guest::GuestError` strings onto stable category
/// classifiers. The error's `Display` names the failure mode (body
/// mismatch, ed25519 verify, encode), never bytes — verified by
/// reading `hippius-guest/src/lifecycle.rs`.
fn classify_guest_error(e: hippius_guest::GuestError) -> (&'static str, String) {
    let msg = e.to_string();
    if msg.contains("body mismatch") {
        (category::STOPPED_BODY_MISMATCH, msg)
    } else if msg.contains("ed25519 verify") {
        (category::STOPPED_SIGNATURE, msg)
    } else {
        (category::STOPPED_DECODE, msg)
    }
}

/// Peel `now_unix` out of the signed-body CBOR map.
///
/// The body is `hippius_types::stopped::StoppedAck.canonical()` — a
/// canonical-CBOR map of 6 entries. We decode it as
/// `ciborium::value::Value`, scan for the `now_unix` text key, and
/// coerce to `u64`. If the field is missing / non-integer / negative
/// we return a `stopped-decode` error.
fn extract_now_unix(body: &[u8]) -> Result<u64, (&'static str, String)> {
    let val: ciborium::value::Value = ciborium::de::from_reader(body)
        .map_err(|e| (category::STOPPED_DECODE, format!("body cbor: {e}")))?;
    let entries = match val {
        ciborium::value::Value::Map(m) => m,
        _ => return Err((category::STOPPED_DECODE, "body is not a CBOR map".into())),
    };
    for (k, v) in entries {
        if let ciborium::value::Value::Text(s) = k {
            if s == "now_unix" {
                let i = match v {
                    ciborium::value::Value::Integer(i) => i,
                    _ => {
                        return Err((
                            category::STOPPED_DECODE,
                            "now_unix is not a CBOR integer".into(),
                        ));
                    }
                };
                let as_i128: i128 = i.into();
                return u64::try_from(as_i128).map_err(|_| {
                    (
                        category::STOPPED_DECODE,
                        format!("now_unix outside u64 range ({as_i128})"),
                    )
                });
            }
        }
    }
    Err((category::STOPPED_DECODE, "now_unix field missing".into()))
}

/// Core validation. Returns `(category, message)` on structured
/// failure; the caller turns that into `Output::Err` + exit code 2.
///
/// Visible at module scope so unit + integration tests can drive it
/// without spawning a child process.
/// Reject a string field longer than [`MAX_ID_LEN`].
fn check_id(field: &str, s: &str) -> Result<(), (&'static str, String)> {
    if s.len() > MAX_ID_LEN {
        return Err((
            category::STRING_TOO_LONG,
            format!("{field} > {MAX_ID_LEN} bytes ({} got)", s.len()),
        ));
    }
    Ok(())
}

/// Reject a `u64` field that wouldn't fit in a signed Postgres BIGINT
/// (Django's `BigIntegerField`).
fn check_u64_fits_i64(field: &str, n: u64) -> Result<(), (&'static str, String)> {
    if n > i64::MAX as u64 {
        return Err((
            category::INT_OVERFLOW,
            format!("{field} > i64::MAX (got {n})"),
        ));
    }
    Ok(())
}

fn validate(cose_bytes: &[u8]) -> Result<TicketJson, (&'static str, String)> {
    // §20: the outer envelope MUST itself be deterministically encoded
    // — a non-canonical wrapper would survive an inner-only check.
    assert_canonical(cose_bytes)
        .map_err(|e| (category::NON_CANONICAL_CBOR, format!("envelope: {e}")))?;

    let sign1 = coset::CoseSign1::from_slice(cose_bytes)
        .map_err(|e| (category::COSE_PARSE, format!("COSE_Sign1 parse: {e:?}")))?;

    // The protected header carries `alg` + `kid`. Mirroring
    // `kbs_core::ticket::verify_order_ticket`, we require it to be
    // present AND deterministically encoded — vali pre-rejects a bad
    // envelope so a malformed ticket can't poison the DB.
    let protected_bytes = sign1
        .protected
        .original_data
        .as_ref()
        .filter(|b| !b.is_empty())
        .ok_or((
            category::MISSING_HEADER,
            "missing/empty COSE protected header".into(),
        ))?;
    assert_canonical(protected_bytes)
        .map_err(|e| (category::NON_CANONICAL_CBOR, format!("protected: {e}")))?;

    // §6/§20 + parity with `kbs_core::ticket::verify_order_ticket`:
    // the OrderTicket alg MUST be Ed25519 (EdDSA). Anything else is
    // rejected here so vali doesn't persist a shape the KBS will
    // reject downstream.
    match sign1.protected.header.alg.clone() {
        Some(coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)) => {}
        Some(other) => {
            return Err((category::ALG, format!("alg must be EdDSA, got {other:?}")));
        }
        None => return Err((category::ALG, "alg header missing".into())),
    }

    let kid = sign1.protected.header.key_id.clone();
    if kid.is_empty() {
        return Err((category::MISSING_HEADER, "missing kid".into()));
    }
    if kid.len() > MAX_KID_BYTES {
        return Err((
            category::STRING_TOO_LONG,
            format!("kid > {MAX_KID_BYTES} bytes"),
        ));
    }

    let payload = sign1.payload.as_ref().ok_or((
        category::MISSING_HEADER,
        "detached payload not allowed".into(),
    ))?;
    assert_canonical(payload)
        .map_err(|e| (category::NON_CANONICAL_CBOR, format!("payload: {e}")))?;

    let ticket: OrderTicket = ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| (category::PAYLOAD_DECODE, format!("ticket decode: {e}")))?;

    // §6 schema invariants (the parts vali can check without the §22
    // allowlist — i.e. without measurement / kid acceptance). These
    // mirror `kbs_core::ticket::verify_order_ticket` so a ticket that
    // makes it past vali will not be rejected by the KBS for a shape
    // reason.
    if ticket.v != SCHEMA_V {
        return Err((
            category::SCHEMA,
            format!("unsupported schema v={} (want {SCHEMA_V})", ticket.v),
        ));
    }
    if ticket.nonce().len() != 32 {
        return Err((category::BYTE_LENGTH, "nonce must be 32 bytes".into()));
    }
    let digest: &[u8] = ticket.allowed_userdata_digest.as_ref();
    if digest.len() != 32 {
        return Err((
            category::BYTE_LENGTH,
            "allowed_userdata_digest must be 32 bytes".into(),
        ));
    }
    if ticket.allowed_measurements.is_empty() {
        return Err((category::SCHEMA, "allowed_measurements is empty".into()));
    }
    let mut measurements_hex = Vec::with_capacity(ticket.allowed_measurements.len());
    for m in &ticket.allowed_measurements {
        let bytes: &[u8] = m.as_ref();
        if bytes.len() != 48 {
            return Err((
                category::BYTE_LENGTH,
                "allowed_measurement must be 48 bytes".into(),
            ));
        }
        measurements_hex.push(hex::encode(bytes));
    }
    if ticket.luks_vault_ref.path == ticket.userdata_vault_ref.path {
        return Err((
            category::SCHEMA,
            "luks and user-data Vault refs must be distinct paths".into(),
        ));
    }
    if ticket.luks_vault_ref.version == 0 || ticket.userdata_vault_ref.version == 0 {
        return Err((
            category::SCHEMA,
            "Vault ref version must be a concrete (>0) KV v2 version".into(),
        ));
    }
    if ticket.expiry <= ticket.issue_time {
        return Err((
            category::SCHEMA,
            "expiry must be strictly greater than issue_time".into(),
        ));
    }

    // DB-bound caps — Postgres BIGINT is signed (i64), and Django
    // CharField is bounded. Pre-reject so a structurally-valid CBOR
    // ticket that the KBS would also accept doesn't blow up Django
    // at INSERT time. Limits MUST stay in sync with
    // `vali/apps/orders/models.py`.
    check_id("ticket_id", &ticket.ticket_id)?;
    check_id("vm_id", &ticket.vm_id)?;
    check_id("tenant_id", &ticket.tenant_id)?;
    check_id("user_id", &ticket.user_id)?;
    check_id("lease_id", &ticket.lease_id)?;
    check_id("node_id", &ticket.node_id)?;
    check_id("platform_id", &ticket.platform_id)?;
    check_id("userdata_vault_ref.path", &ticket.userdata_vault_ref.path)?;
    check_id("luks_vault_ref.path", &ticket.luks_vault_ref.path)?;
    // #312 — `flavor: Flavor` is a closed enum (Small/Medium/Large);
    // the wire-format constraint that retired `resource_class`'s
    // length cap is the enum's per-variant validation in
    // `hippius_types::flavor::Flavor`. Decode-time refusal of an
    // unknown variant is the new bound — nothing to length-check here.
    if ticket.lifecycle_perms.len() > MAX_LIFECYCLE_PERMS {
        return Err((
            category::SCHEMA,
            format!(
                "lifecycle_perms > {MAX_LIFECYCLE_PERMS} entries ({} got)",
                ticket.lifecycle_perms.len()
            ),
        ));
    }
    for perm in &ticket.lifecycle_perms {
        if perm.len() > MAX_LIFECYCLE_PERM_LEN {
            return Err((
                category::STRING_TOO_LONG,
                format!("lifecycle_perm > {MAX_LIFECYCLE_PERM_LEN} bytes"),
            ));
        }
    }
    if ticket.allowed_measurements.len() > MAX_ALLOWED_MEASUREMENTS {
        return Err((
            category::SCHEMA,
            format!(
                "allowed_measurements > {MAX_ALLOWED_MEASUREMENTS} entries ({} got)",
                ticket.allowed_measurements.len()
            ),
        ));
    }
    // Postgres BIGINT is signed; reject u64 > i64::MAX so Django's
    // BigIntegerField.save() doesn't raise DataError.
    check_u64_fits_i64("vm_generation", ticket.vm_generation)?;
    check_u64_fits_i64("issue_time", ticket.issue_time)?;
    check_u64_fits_i64("expiry", ticket.expiry)?;
    check_u64_fits_i64(
        "userdata_vault_ref.version",
        ticket.userdata_vault_ref.version,
    )?;
    check_u64_fits_i64("luks_vault_ref.version", ticket.luks_vault_ref.version)?;

    // Hex-encode the byte-typed fields BEFORE moving the `ticket`
    // struct apart (`ticket.nonce()` borrows; the other fields move).
    let nonce_hex = hex::encode(ticket.nonce());
    let userdata_digest_hex = hex::encode(digest);
    Ok(TicketJson {
        v: ticket.v,
        ticket_id: ticket.ticket_id,
        issue_time: ticket.issue_time,
        expiry: ticket.expiry,
        nonce_hex,
        tenant_id: ticket.tenant_id,
        user_id: ticket.user_id,
        vm_id: ticket.vm_id,
        lease_id: ticket.lease_id,
        vm_generation: ticket.vm_generation,
        node_id: ticket.node_id,
        platform_id: ticket.platform_id,
        allowed_measurements_hex: measurements_hex,
        userdata_vault_ref: VaultRefJson {
            path: ticket.userdata_vault_ref.path,
            version: ticket.userdata_vault_ref.version,
        },
        luks_vault_ref: VaultRefJson {
            path: ticket.luks_vault_ref.path,
            version: ticket.luks_vault_ref.version,
        },
        allowed_userdata_digest_hex: userdata_digest_hex,
        flavor: ticket.flavor.as_str().into(),
        lifecycle_perms: ticket.lifecycle_perms,
        kid_hex: hex::encode(&kid),
        cose_len: cose_bytes.len(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use coset::iana::Algorithm;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use hippius_types::cbor::to_canonical_vec;

    fn ticket_payload() -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(vec![7u8; 48])]),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(vec![9u8; 32]),
            ),
            (Value::Text("expiry".into()), Value::Integer(2000.into())),
            (
                Value::Text("issue_time".into()),
                Value::Integer(1000.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text("lease-1".into()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(vec![Value::Text("boot".into())]),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/luks".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text("node-1".into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (
                Value::Text("platform_id".into()),
                Value::Text("chip-1".into()),
            ),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t1".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u1".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (Value::Text("v".into()), Value::Integer(2.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(5.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("abc".into())),
        ]);
        to_canonical_vec(&v).unwrap()
    }

    /// Build a deterministic-CBOR COSE_Sign1 wrapper. The signature
    /// bytes are arbitrary — this binary doesn't verify them.
    fn cose_envelope(payload: Vec<u8>, kid: &[u8]) -> Vec<u8> {
        let protected = HeaderBuilder::new()
            .algorithm(Algorithm::EdDSA)
            .key_id(kid.to_vec())
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |_tbs| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    #[test]
    fn valid_envelope_parses() {
        let cose = cose_envelope(ticket_payload(), b"l1-kid-v1");
        let out = validate(&cose).unwrap();
        assert_eq!(out.v, SCHEMA_V);
        assert_eq!(out.flavor, "small");
        assert_eq!(out.ticket_id, "tk-1");
        assert_eq!(out.vm_id, "abc");
        assert_eq!(out.vm_generation, 5);
        assert_eq!(out.luks_vault_ref.version, 3);
        assert_eq!(out.userdata_vault_ref.version, 2);
        assert_eq!(out.allowed_measurements_hex.len(), 1);
        assert_eq!(out.allowed_measurements_hex[0].len(), 48 * 2);
        assert_eq!(out.allowed_userdata_digest_hex.len(), 32 * 2);
        assert_eq!(out.nonce_hex.len(), 32 * 2);
        assert_eq!(out.kid_hex, hex::encode(b"l1-kid-v1"));
        assert_eq!(out.cose_len, cose.len());
    }

    #[test]
    fn empty_input_is_rejected() {
        // Empty input is structurally not a CBOR item — the
        // canonical-CBOR pre-check trips first. The exact category
        // doesn't matter for the wire contract (HTTP 400 either way),
        // only that it fails closed.
        let (cat, _) = validate(b"").unwrap_err();
        assert!(
            cat == category::NON_CANONICAL_CBOR || cat == category::COSE_PARSE,
            "got {cat}"
        );
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        // Build a payload with v=99 — still canonical, but the schema
        // gate trips (current SCHEMA_V is 2; #312 v2 → v3 bump would
        // need this constant nudged again).
        let v = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(99.into())),
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(vec![7u8; 48])]),
            ),
            // ... rest of fields. Only v matters for this test; the
            // payload-decode step will hit unknown_fields and reject
            // earlier than the v check IF we miss fields. Provide a
            // complete one with v=2.
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(vec![9u8; 32]),
            ),
            (Value::Text("expiry".into()), Value::Integer(2000.into())),
            (
                Value::Text("issue_time".into()),
                Value::Integer(1000.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text("lease-1".into()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(vec![Value::Text("boot".into())]),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/luks".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text("node-1".into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (
                Value::Text("platform_id".into()),
                Value::Text("chip-1".into()),
            ),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t1".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u1".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(5.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("abc".into())),
        ]);
        let bad = to_canonical_vec(&v).unwrap();
        let cose = cose_envelope(bad, b"k");
        let (cat, msg) = validate(&cose).unwrap_err();
        assert_eq!(cat, category::SCHEMA);
        assert!(msg.contains("unsupported schema"), "got: {msg}");
    }

    #[test]
    fn non_canonical_envelope_is_rejected() {
        // Build an unsorted map for the envelope itself by hand — we
        // can't go through `CborSerializable::to_vec` because it
        // sorts. Use a Value-tree directly that ciborium serializes
        // in insertion order.
        let v = Value::Map(vec![
            (Value::Text("zzz".into()), Value::Integer(0.into())),
            (Value::Text("aaa".into()), Value::Integer(0.into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        let (cat, _) = validate(&bytes).unwrap_err();
        assert_eq!(cat, category::NON_CANONICAL_CBOR);
    }

    #[test]
    fn missing_kid_is_rejected() {
        // Build a COSE_Sign1 without setting `kid`. coset still emits
        // a protected header (it carries `alg`), so the rejection
        // path is the empty-kid check, not the missing-header one.
        let protected = HeaderBuilder::new().algorithm(Algorithm::EdDSA).build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(ticket_payload())
            .create_signature(b"", |_| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap();
        let (cat, msg) = validate(&cose).unwrap_err();
        assert_eq!(cat, category::MISSING_HEADER);
        assert!(msg.contains("kid"), "got: {msg}");
    }

    #[test]
    fn wrong_alg_is_rejected() {
        // Build a COSE_Sign1 with ES256 instead of EdDSA. Vali pre-
        // rejects so the KBS never sees a ticket it would reject.
        let protected = HeaderBuilder::new()
            .algorithm(Algorithm::ES256)
            .key_id(b"k".to_vec())
            .build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(ticket_payload())
            .create_signature(b"", |_| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap();
        let (cat, msg) = validate(&cose).unwrap_err();
        assert_eq!(cat, category::ALG);
        assert!(msg.contains("EdDSA"), "got: {msg}");
    }

    fn payload_with_overrides(overrides: &[(&str, Value)]) -> Vec<u8> {
        let mut fields: Vec<(Value, Value)> = vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(vec![7u8; 48])]),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(vec![9u8; 32]),
            ),
            (Value::Text("expiry".into()), Value::Integer(2000.into())),
            (
                Value::Text("issue_time".into()),
                Value::Integer(1000.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text("lease-1".into()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(vec![Value::Text("boot".into())]),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/luks".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text("node-1".into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (
                Value::Text("platform_id".into()),
                Value::Text("chip-1".into()),
            ),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t1".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u1".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (Value::Text("v".into()), Value::Integer(2.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(5.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("abc".into())),
        ];
        for (k, v) in overrides {
            for (key, val) in fields.iter_mut() {
                if let Value::Text(s) = key {
                    if s == k {
                        *val = v.clone();
                        break;
                    }
                }
            }
        }
        to_canonical_vec(&Value::Map(fields)).unwrap()
    }

    #[test]
    fn ticket_id_too_long_is_rejected() {
        let long = "x".repeat(MAX_ID_LEN + 1);
        let payload = payload_with_overrides(&[("ticket_id", Value::Text(long))]);
        let cose = cose_envelope(payload, b"k");
        let (cat, _) = validate(&cose).unwrap_err();
        assert_eq!(cat, category::STRING_TOO_LONG);
    }

    #[test]
    fn vm_generation_overflow_is_rejected() {
        // u64::MAX > i64::MAX — should be caught before insert.
        let payload =
            payload_with_overrides(&[("vm_generation", Value::Integer((u64::MAX).into()))]);
        let cose = cose_envelope(payload, b"k");
        let (cat, _) = validate(&cose).unwrap_err();
        assert_eq!(cat, category::INT_OVERFLOW);
    }

    // ─── verify-stopped-ack ─────────────────────────────────────────
    //
    // The sign-side helper lives in `hippius-guest::sign_stopped_ack`;
    // we cross-build a signed envelope here, then feed it back through
    // the verifier the binary uses.

    use ed25519_dalek::{Signer, SigningKey};

    fn sign_envelope(sk: &SigningKey, ack: &StoppedAck<'_>) -> Vec<u8> {
        let body = ack.canonical().unwrap();
        let sig = sk.sign(&body).to_bytes().to_vec();
        let signed = SignedStoppedAck { body, sig };
        // Encode as canonical CBOR — `to_canonical_vec` over a Value
        // tree so the test envelope is shaped exactly like the wire.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&signed, &mut buf).unwrap();
        buf
    }

    fn default_args(sk: &SigningKey, nonce: &[u8; 32]) -> VerifyStoppedAckArgs {
        VerifyStoppedAckArgs {
            vk_hex: hex::encode(sk.verifying_key().to_bytes()),
            vm_id: "abc".into(),
            lease_id: "lease-1".into(),
            vm_generation: 7,
            nonce_hex: hex::encode(nonce),
            now_unix_min: 999_990,
            now_unix_max: 1_000_010,
        }
    }

    #[test]
    fn stopped_ack_happy_path() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 1_000_000,
        };
        let signed = sign_envelope(&sk, &ack);
        let args = default_args(&sk, &nonce);
        let now = verify_stopped(&args, &signed).unwrap();
        assert_eq!(now, 1_000_000);
    }

    #[test]
    fn stopped_ack_window_out_of_bounds() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 500_000,
        };
        let signed = sign_envelope(&sk, &ack);
        let args = default_args(&sk, &nonce);
        let (cat, _) = verify_stopped(&args, &signed).unwrap_err();
        assert_eq!(cat, category::STOPPED_WINDOW);
    }

    #[test]
    fn stopped_ack_wrong_vm_id_is_body_mismatch() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 1_000_000,
        };
        let signed = sign_envelope(&sk, &ack);
        let mut args = default_args(&sk, &nonce);
        args.vm_id = "different-vm".into();
        let (cat, _) = verify_stopped(&args, &signed).unwrap_err();
        assert_eq!(cat, category::STOPPED_BODY_MISMATCH);
    }

    #[test]
    fn stopped_ack_wrong_nonce_is_body_mismatch() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 1_000_000,
        };
        let signed = sign_envelope(&sk, &ack);
        let mut args = default_args(&sk, &nonce);
        let other = [9u8; 32];
        args.nonce_hex = hex::encode(other);
        let (cat, _) = verify_stopped(&args, &signed).unwrap_err();
        assert_eq!(cat, category::STOPPED_BODY_MISMATCH);
    }

    #[test]
    fn stopped_ack_wrong_signing_key_is_signature_failure() {
        let signer = SigningKey::from_bytes(&[42u8; 32]);
        let pretender = SigningKey::from_bytes(&[99u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 1_000_000,
        };
        // Sign with `signer`, expect verification against `pretender`'s
        // vk to fail.
        let signed = sign_envelope(&signer, &ack);
        let mut args = default_args(&signer, &nonce);
        args.vk_hex = hex::encode(pretender.verifying_key().to_bytes());
        let (cat, _) = verify_stopped(&args, &signed).unwrap_err();
        assert_eq!(cat, category::STOPPED_SIGNATURE);
    }

    #[test]
    fn stopped_ack_bad_vk_hex_is_decode_failure() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &nonce,
            now_unix: 1_000_000,
        };
        let signed = sign_envelope(&sk, &ack);
        let mut args = default_args(&sk, &nonce);
        args.vk_hex = "not-hex".into();
        let (cat, _) = verify_stopped(&args, &signed).unwrap_err();
        assert_eq!(cat, category::STOPPED_DECODE);
    }

    #[test]
    fn stopped_ack_malformed_envelope_is_decode_failure() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let nonce = [3u8; 32];
        let args = default_args(&sk, &nonce);
        let (cat, _) = verify_stopped(&args, b"garbage").unwrap_err();
        assert_eq!(cat, category::STOPPED_DECODE);
    }
}
