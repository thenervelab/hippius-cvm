//! `encode-order` subcommand — vali's helper to build a canonical-CBOR
//! `OrderBody` for the §H phase-2 order-dispatch path.
//!
//! ## Why a subcommand
//!
//! Vali's other shell-outs (`verify-ticket`, `verify-stopped-ack`, …)
//! are read-only / verification helpers. This one is **build-only**:
//! given vali's launch parameters (a JSON object on stdin) it emits
//! the canonical-CBOR `OrderBody` bytes the Edge will sign + the
//! miner-agent will re-decode (`binaries/miner-agent/src/orders/types.rs`).
//!
//! Doing it here keeps:
//!
//! - **Canonical-CBOR discipline** in one process — Python's `cbor2`
//!   has historically produced non-canonical maps; the Rust path
//!   guarantees byte-equality with the miner's `assert_canonical`
//!   check.
//! - **No duplicated struct definitions** across the codebase — we
//!   build the body via [`ciborium::value::Value`] directly, so vali
//!   does not need to ship a copy of `OrderBody`/`OrderKind`/
//!   `LaunchOrder` and risk drifting from the miner-agent's.
//!
//! ## Wire contract
//!
//! - stdin: JSON object with the kind-specific payload fields (see
//!   below).
//! - CLI args: `--order-id <id>` (idempotency key), `--kind <kebab>`
//!   (launch / stop / destroy / migrate).
//! - stdout: raw bytes of the canonical-CBOR `OrderBody` (binary —
//!   vali pipes this directly into the Edge POST body).
//! - exit: `0` on success; `2` on a malformed input (missing field,
//!   bad type, kind / payload mismatch); `1` on a stdin / stdout IO
//!   error.
//!
//! ## Payload schemas (mirror `binaries/miner-agent/src/orders/types.rs`)
//!
//! ### `launch`
//!
//! ```json
//! {
//!   "vm_id": "tenant-1",
//!   "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
//!   "kernel_path": "/var/lib/hippius-miner/vmlinuz",
//!   "initrd_path": "/var/lib/hippius-miner/initrd",
//!   "cmdline": "console=hvc0 quiet",
//!   "luks_disk_path": "/var/lib/hippius-miner/d.img",
//!   "luks_disk_size_gb": 10,
//!   "cpu_count": 2,
//!   "memory_mb": 2048
//! }
//! ```
//!
//! ### `stop`
//!
//! `{"vm_id": "tenant-1", "graceful": true}`
//!
//! ### `destroy` / `migrate`
//!
//! `{"vm_id": "tenant-1"}`

use ciborium::value::Value;
use clap::Args;
use hippius_types::cbor::to_canonical_vec;
use serde_json::Value as Json;
use std::io::{self, Read, Write};
use std::process::ExitCode;

/// Domain-separation tag bound into every signed `OrderBody`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::ORDER_DOMAIN` — pinned
/// here as a `&'static str` so a drift in the miner-agent constant
/// would surface immediately as a `bad-domain` rejection on the
/// miner side.
const ORDER_DOMAIN: &str = "HIPPIUS_MINER_ORDER_V1";

/// Exit code on a malformed input — missing field, bad JSON type,
/// kind / payload mismatch. Matches the rest of the binary
/// (`SCHEMA_FAIL`).
const SCHEMA_FAIL: u8 = 2;

/// Exit code on stdin / stdout IO failure (`INTERNAL_FAIL`).
const INTERNAL_FAIL: u8 = 1;

#[derive(Args)]
pub struct EncodeOrderArgs {
    /// Caller-assigned idempotency key (string). Same `order_id` twice
    /// → same outcome on the miner side, the second a no-op success.
    #[arg(long)]
    pub order_id: String,

    /// One of `launch` / `stop` / `destroy` / `migrate`. Closed
    /// vocabulary — anything else is rejected with `SCHEMA_FAIL`.
    #[arg(long)]
    pub kind: String,

    /// The target miner's `miner_id`. The miner-agent verifies
    /// `OrderBody.target_miner_id == self.config.miner.miner_id`
    /// AFTER the Edge signature checks (gemini r1 High —
    /// cross-miner replay). vali passes the same miner_id it
    /// addresses the dispatch HTTP call to.
    #[arg(long)]
    pub target_miner_id: String,

    /// Unix-seconds-since-epoch the caller is issuing this order. The
    /// miner-agent enforces a ±`MAX_ORDER_AGE_SECS` window around its
    /// own clock (gemini r1 High — long-term replay). vali passes
    /// `int(time.time())` at call time; tests can pin a value for
    /// determinism.
    #[arg(long)]
    pub issued_at_unix: u64,
}

pub fn run(args: EncodeOrderArgs) -> ExitCode {
    let mut payload_bytes = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut payload_bytes) {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(INTERNAL_FAIL);
    }

    match build(&args, &payload_bytes) {
        Ok(bytes) => {
            if let Err(e) = io::stdout().lock().write_all(&bytes) {
                eprintln!("hippius-ticket-validator: stdout write failed: {e}");
                return ExitCode::from(INTERNAL_FAIL);
            }
            ExitCode::from(0)
        }
        Err(class) => {
            // The diagnostic goes to stderr (the wire contract is "bytes
            // on stdout on ok"; an error means stdout is empty + the
            // class lands on stderr). Static classifier ONLY — never the
            // payload bytes (§20).
            eprintln!("hippius-ticket-validator: encode-order: {class}");
            ExitCode::from(SCHEMA_FAIL)
        }
    }
}

/// Build the canonical-CBOR `OrderBody` from the args + JSON payload.
/// Pure function for unit testability — the I/O lives in `run`.
fn build(args: &EncodeOrderArgs, payload_json: &[u8]) -> Result<Vec<u8>, &'static str> {
    let payload: Json = serde_json::from_slice(payload_json).map_err(|_| "payload-json-parse")?;
    let payload_obj = payload.as_object().ok_or("payload-not-object")?;
    let payload_value = match args.kind.as_str() {
        "launch" => build_launch(payload_obj)?,
        "stop" => build_stop(payload_obj)?,
        "destroy" | "migrate" => build_vm_id_only(payload_obj)?,
        "migrate-activate" => build_migrate_activate(payload_obj)?,
        "tenant-preflight" => build_tenant_preflight(payload_obj)?,
        _ => return Err("bad-kind"),
    };

    if args.target_miner_id.is_empty() {
        return Err("missing-target-miner-id");
    }
    // OrderBody fields — pinned to the miner-agent's serde shape:
    //   { "domain": text, "issued_at_unix": uint, "kind": text,
    //     "order_id": text, "payload": map, "target_miner_id": text }
    // Map keys are sorted lexicographically by `to_canonical_vec` (the
    // existing canonical-CBOR helper), so we hand it an unsorted Vec
    // and let the helper enforce the canonical order.
    let body = Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(ORDER_DOMAIN.into()),
        ),
        (
            Value::Text("issued_at_unix".into()),
            Value::Integer(args.issued_at_unix.into()),
        ),
        (Value::Text("kind".into()), Value::Text(args.kind.clone())),
        (
            Value::Text("order_id".into()),
            Value::Text(args.order_id.clone()),
        ),
        (Value::Text("payload".into()), payload_value),
        (
            Value::Text("target_miner_id".into()),
            Value::Text(args.target_miner_id.clone()),
        ),
    ]);
    to_canonical_vec(&body).map_err(|_| "canonical-encode")
}

/// Build the `payload` map for `kind=launch`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::LaunchOrder`.
///
/// `cose_ticket` is the L1 OrderTicket COSE_Sign1 envelope; on the
/// JSON wire it travels as a base64 string (mirroring every
/// `ByteBuf` field's JSON convention), and we re-emit it as a CBOR
/// byte-string so the miner-agent's
/// `LaunchOrder.cose_ticket: ByteBuf` decodes byte-identical to what
/// the L1 mint produced. Empty / oversize bytes are caught here
/// (`cose-ticket-empty` / `cose-ticket-oversize`) so an empty COSE
/// blob cannot make it to the wire and stall every guest at the
/// §21 first stage.
fn build_launch(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let vm_id = string_field(obj, "vm_id")?;
    let ovmf_path = string_field(obj, "ovmf_path")?;
    let kernel_path = string_field(obj, "kernel_path")?;
    let initrd_path = string_field(obj, "initrd_path")?;
    let cmdline = string_field(obj, "cmdline")?;
    let luks_disk_path = string_field(obj, "luks_disk_path")?;
    let luks_disk_size_gb = u32_field(obj, "luks_disk_size_gb")?;
    // #365 — tenant data disk (/dev/vde) size. OPTIONAL in the JSON
    // (older vali payloads omit it ⇒ 0 = no data disk), mirroring the
    // miner-agent's `#[serde(default)]`. Encoded into the CBOR ONLY
    // when > 0, so no-data-disk launches stay byte-identical to the
    // pre-#365 wire shape (an older miner-agent's deny_unknown_fields
    // never sees the key), while a data-disk launch against a miner
    // too old to know the field fails LOUDLY at decode instead of
    // silently launching with no /dev/vde. This bridge dropping the
    // field silently is exactly the bug that shipped the first xlarge
    // without its data disk (observed live 2026-06-11).
    let data_disk_size_gb = optional_u32_field(obj, "data_disk_size_gb")?;
    let cpu_count = u8_field(obj, "cpu_count")?;
    let memory_mb = u32_field(obj, "memory_mb")?;
    let cose_ticket_b64 = string_field(obj, "cose_ticket")?;
    let cose_ticket = STANDARD
        .decode(cose_ticket_b64.as_bytes())
        .map_err(|_| "cose-ticket-base64")?;
    if cose_ticket.is_empty() {
        return Err("cose-ticket-empty");
    }
    // Mirror the host-side push cap (`hippius_types::ticket_vsock::
    // MAX_TICKET_BYTES`) — checking here is defence-in-depth so the
    // signed body the Edge emits is never bigger than what the guest
    // receiver will accept.
    if cose_ticket.len() > hippius_types::ticket_vsock::MAX_TICKET_BYTES {
        return Err("cose-ticket-oversize");
    }
    let mut entries = vec![
        (Value::Text("cmdline".into()), Value::Text(cmdline)),
        (Value::Text("cose_ticket".into()), Value::Bytes(cose_ticket)),
        (
            Value::Text("cpu_count".into()),
            Value::Integer((cpu_count as u64).into()),
        ),
    ];
    // Canonical key order: "cpu_count" < "data_disk_size_gb" <
    // "initrd_path". Omitted entirely when 0 (see the doc above).
    if data_disk_size_gb > 0 {
        entries.push((
            Value::Text("data_disk_size_gb".into()),
            Value::Integer((data_disk_size_gb as u64).into()),
        ));
    }
    entries.extend([
        (Value::Text("initrd_path".into()), Value::Text(initrd_path)),
        (Value::Text("kernel_path".into()), Value::Text(kernel_path)),
        (
            Value::Text("luks_disk_path".into()),
            Value::Text(luks_disk_path),
        ),
        (
            Value::Text("luks_disk_size_gb".into()),
            Value::Integer((luks_disk_size_gb as u64).into()),
        ),
        (
            Value::Text("memory_mb".into()),
            Value::Integer((memory_mb as u64).into()),
        ),
        (Value::Text("ovmf_path".into()), Value::Text(ovmf_path)),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ]);
    // GOLDEN (golden-bake PR4): the miner-staged golden dm-verity base
    // paths the guest boots from (vdb/vdc). OPTIONAL on the JSON wire —
    // a LEGACY launch omits them and the miner-agent's `#[serde(default)]`
    // supplies the canonical `/var/lib/hippius-miner/rootfs.{img,verity}`
    // (the shared BYO-OS rootfs, which IS correct for legacy). A GOLDEN
    // launch MUST carry them (the per-bake `staging/<vm>/rootfs.{img,
    // verity}` path preflight fetched): if this bridge drops them, the
    // miner falls back to the legacy rootfs while the cmdline carries the
    // golden `dm-verity.root=` → root-hash mismatch → the guest fails
    // closed in initramfs (never boots). This is the launch-kind twin of
    // the `data_disk_size_gb` bridge bug (#365): a re-serialising bridge
    // that silently drops a new field. `build_migrate_activate` already
    // carries these; `build_launch` did not. Emitted only when present;
    // `to_canonical_vec` sorts them into canonical key order.
    if let Some(p) = optional_string_field(obj, "rootfs_data_path")? {
        entries.push((Value::Text("rootfs_data_path".into()), Value::Text(p)));
    }
    if let Some(p) = optional_string_field(obj, "rootfs_hash_path")? {
        entries.push((Value::Text("rootfs_hash_path".into()), Value::Text(p)));
    }
    Ok(Value::Map(entries))
}

/// Build the `payload` map for `kind=migrate-activate` (§25 M4). Mirrors
/// `binaries/miner-agent/src/orders/types.rs::MigrateActivateOrder`.
///
/// The dual of `build_launch`: it carries the SAME measured launch tuple
/// (ovmf / kernel / initrd / cmdline / luks / cpu / mem / cose_ticket) plus
/// the §25-specific `get_url` (presigned snapshot GET), `new_gen` (the
/// forward-only destination generation), and the optional `boot_artifacts`
/// staging bundle (M3 dest staging — presigned GET URLs + pinned SHAs the
/// dest fetch-verify-stages before the domain build).
///
/// `cose_ticket` rides as a base64 string on the JSON wire (same convention
/// as `build_launch`) and is re-emitted as a CBOR byte-string so the
/// miner-agent's `ByteBuf` decodes it byte-identical. `rootfs_data_path` /
/// `rootfs_hash_path` are emitted only when present (the miner-agent's
/// `#[serde(default)]` supplies the canonical path otherwise — byte-stable
/// with the launch payload). `boot_artifacts` is emitted only when present
/// (M2 caller / out-of-band staging omits it — the dest then relies on its
/// `dest-artifacts-missing` existence check, never a half boot).
///
/// We hand `to_canonical_vec` an unsorted map and let it enforce the
/// canonical key order — the same discipline `build_launch` uses.
fn build_migrate_activate(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let vm_id = string_field(obj, "vm_id")?;
    let get_url = string_field(obj, "get_url")?;
    let new_gen = obj
        .get("new_gen")
        .and_then(Json::as_u64)
        .ok_or("missing-new-gen")?;
    let ovmf_path = string_field(obj, "ovmf_path")?;
    let kernel_path = string_field(obj, "kernel_path")?;
    let initrd_path = string_field(obj, "initrd_path")?;
    let cmdline = string_field(obj, "cmdline")?;
    let luks_disk_path = string_field(obj, "luks_disk_path")?;
    let luks_disk_size_gb = u32_field(obj, "luks_disk_size_gb")?;
    let cpu_count = u8_field(obj, "cpu_count")?;
    let memory_mb = u32_field(obj, "memory_mb")?;
    let cose_ticket_b64 = string_field(obj, "cose_ticket")?;
    let cose_ticket = STANDARD
        .decode(cose_ticket_b64.as_bytes())
        .map_err(|_| "cose-ticket-base64")?;
    if cose_ticket.is_empty() {
        return Err("cose-ticket-empty");
    }
    if cose_ticket.len() > hippius_types::ticket_vsock::MAX_TICKET_BYTES {
        return Err("cose-ticket-oversize");
    }

    let mut entries = vec![
        (Value::Text("cmdline".into()), Value::Text(cmdline)),
        (Value::Text("cose_ticket".into()), Value::Bytes(cose_ticket)),
        (
            Value::Text("cpu_count".into()),
            Value::Integer((cpu_count as u64).into()),
        ),
        (Value::Text("get_url".into()), Value::Text(get_url)),
        (Value::Text("initrd_path".into()), Value::Text(initrd_path)),
        (Value::Text("kernel_path".into()), Value::Text(kernel_path)),
        (
            Value::Text("luks_disk_path".into()),
            Value::Text(luks_disk_path),
        ),
        (
            Value::Text("luks_disk_size_gb".into()),
            Value::Integer((luks_disk_size_gb as u64).into()),
        ),
        (
            Value::Text("memory_mb".into()),
            Value::Integer((memory_mb as u64).into()),
        ),
        (
            Value::Text("new_gen".into()),
            Value::Integer(new_gen.into()),
        ),
        (Value::Text("ovmf_path".into()), Value::Text(ovmf_path)),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ];
    // §25 anti-rollback state disk — the presigned GET for the source's
    // boot counter. Emitted only when present so an order from a vali that
    // carries no state disk stays BYTE-IDENTICAL to the pre-#876 wire, and
    // a miner-agent that predates the field (`deny_unknown_fields`) still
    // accepts it. Absent ⇒ the miner's `#[serde(default)]` yields "" and it
    // skips the restore.
    //
    // This bridge is an explicit ALLOWLIST re-serialiser: a field that is
    // not listed here is silently dropped, so vali can emit it, the dest
    // never sees it, and the failure surfaces far away as a KBS 403. That
    // is the #365 `data_disk_size_gb` bug and the golden `rootfs_*_path`
    // bug — this is the third. See the decode test below, which mirrors
    // the payload into a `deny_unknown_fields` struct so the next new
    // field cannot vanish the same way.
    // Read directly rather than via `optional_string_field`, which
    // REJECTS an empty string ("optional-string-not-string") instead of
    // treating it as absent. "" and absent must mean the same thing here
    // — "this migration carries no state disk" — or a caller that emits
    // the key with an empty value fails the whole dispatch.
    let state_get_url = obj
        .get("state_get_url")
        .and_then(Json::as_str)
        .filter(|u| !u.is_empty());
    if let Some(u) = state_get_url {
        entries.push((
            Value::Text("state_get_url".into()),
            Value::Text(u.to_string()),
        ));
    }
    // Optional path fields — emitted only when present so an absent one
    // falls to the miner-agent's `#[serde(default)]` canonical path.
    if let Some(p) = optional_string_field(obj, "rootfs_data_path")? {
        entries.push((Value::Text("rootfs_data_path".into()), Value::Text(p)));
    }
    if let Some(p) = optional_string_field(obj, "rootfs_hash_path")? {
        entries.push((Value::Text("rootfs_hash_path".into()), Value::Text(p)));
    }
    // Optional M3 staging bundle — emitted only when present (an absent
    // one is the M2 / out-of-band-staging shape the miner-agent accepts
    // via `#[serde(default)] boot_artifacts: Option<…>`).
    if let Some(staging) = obj.get("boot_artifacts") {
        if !staging.is_null() {
            let staging_obj = staging.as_object().ok_or("boot-artifacts-not-object")?;
            entries.push((
                Value::Text("boot_artifacts".into()),
                build_dest_staging(staging_obj)?,
            ));
        }
    }
    Ok(Value::Map(entries))
}

/// Build the `boot_artifacts` map — mirrors
/// `binaries/miner-agent/src/orders/migration.rs::DestStagingArtifacts`.
/// `kernel` + `initrd` are required; `ovmf` / `rootfs_data` / `rootfs_hash`
/// are optional (`#[serde(default)]`) and emitted only when present.
fn build_dest_staging(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let mut entries = vec![
        (
            Value::Text("kernel".into()),
            build_staged_artifact(obj, "kernel")?,
        ),
        (
            Value::Text("initrd".into()),
            build_staged_artifact(obj, "initrd")?,
        ),
    ];
    for name in ["ovmf", "rootfs_data", "rootfs_hash"] {
        if let Some(v) = obj.get(name) {
            if !v.is_null() {
                entries.push((Value::Text(name.into()), build_staged_artifact(obj, name)?));
            }
        }
    }
    Ok(Value::Map(entries))
}

/// `{ url, sha256_hex }` — mirrors
/// `binaries/miner-agent/src/orders/migration.rs::StagedArtifact`.
fn build_staged_artifact(
    parent: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<Value, &'static str> {
    let obj = parent
        .get(name)
        .and_then(Json::as_object)
        .ok_or("boot-artifact-not-object")?;
    let url = obj
        .get("url")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("boot-artifact-missing-url")?;
    let sha = obj
        .get("sha256_hex")
        .and_then(Json::as_str)
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("boot-artifact-bad-sha256-hex")?;
    Ok(Value::Map(vec![
        (
            Value::Text("sha256_hex".into()),
            Value::Text(sha.to_string()),
        ),
        (Value::Text("url".into()), Value::Text(url.to_string())),
    ]))
}

/// An optional non-empty string field: absent / null ⇒ `None`; present but
/// not a non-empty string ⇒ a loud error (never silently dropped).
fn optional_string_field(
    obj: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<Option<String>, &'static str> {
    match obj.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| Some(s.to_string()))
            .ok_or("optional-string-not-string"),
    }
}

/// Build the `payload` map for `kind=stop`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::StopOrder`.
fn build_stop(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    let graceful = obj
        .get("graceful")
        .and_then(Json::as_bool)
        .ok_or("missing-graceful")?;
    Ok(Value::Map(vec![
        (Value::Text("graceful".into()), Value::Bool(graceful)),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ]))
}

/// Build the `payload` map for `kind ∈ {destroy, migrate}` —
/// `DestroyOrder` and `MigrateOrder` are both `{ vm_id }`.
fn build_vm_id_only(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    Ok(Value::Map(vec![(
        Value::Text("vm_id".into()),
        Value::Text(vm_id),
    )]))
}

/// Build the `payload` map for `kind=tenant-preflight`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::TenantPreflightOrder`.
fn build_tenant_preflight(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    let ovmf_path = string_field(obj, "ovmf_path")?;
    let cmdline = string_field(obj, "cmdline")?;
    let cpu_count = u8_field(obj, "cpu_count")?;
    let luks_disk = build_preflight_artifact(obj, "luks_disk")?;
    let kernel = build_preflight_artifact(obj, "kernel")?;
    let initrd = build_preflight_artifact(obj, "initrd")?;
    let mut entries = vec![
        (Value::Text("cmdline".into()), Value::Text(cmdline)),
        (
            Value::Text("cpu_count".into()),
            Value::Integer((cpu_count as u64).into()),
        ),
        (Value::Text("initrd".into()), initrd),
        (Value::Text("kernel".into()), kernel),
        (Value::Text("luks_disk".into()), luks_disk),
        (Value::Text("ovmf_path".into()), Value::Text(ovmf_path)),
    ];
    // golden-bake PR4: `rootfs_hash` (the golden dm-verity hash tree) is
    // OPTIONAL — emitted only when the caller supplies it (a GOLDEN-mode
    // launch). Absent on the LEGACY path, so the legacy preflight CBOR is
    // byte-identical. Inserted in alphabetical key order (after
    // `ovmf_path`, before `vm_id`) to match the map's existing ordering.
    if obj.get("rootfs_hash").and_then(Json::as_object).is_some() {
        entries.push((
            Value::Text("rootfs_hash".into()),
            build_preflight_artifact(obj, "rootfs_hash")?,
        ));
    }
    entries.push((Value::Text("vm_id".into()), Value::Text(vm_id)));
    Ok(Value::Map(entries))
}

/// `{ url, sha256_hex }` — the [`PreflightArtifact`] shape from the
/// miner-agent side. Both fields required; the URL is treated as
/// opaque text (we don't validate its scheme here — the miner-agent
/// hands it to `reqwest::get` and would reject a non-http(s) one).
fn build_preflight_artifact(
    parent: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<Value, &'static str> {
    let obj = parent
        .get(name)
        .and_then(Json::as_object)
        .ok_or(match name {
            "luks_disk" => "missing-luks-disk",
            "kernel" => "missing-kernel",
            "initrd" => "missing-initrd",
            _ => "missing-artifact",
        })?;
    let url = obj
        .get("url")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(match name {
            "luks_disk" => "missing-luks-disk-url",
            "kernel" => "missing-kernel-url",
            "initrd" => "missing-initrd-url",
            _ => "missing-artifact-url",
        })?;
    let sha = obj
        .get("sha256_hex")
        .and_then(Json::as_str)
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(match name {
            "luks_disk" => "bad-luks-disk-sha256-hex",
            "kernel" => "bad-kernel-sha256-hex",
            "initrd" => "bad-initrd-sha256-hex",
            _ => "bad-artifact-sha256-hex",
        })?;
    Ok(Value::Map(vec![
        (
            Value::Text("sha256_hex".into()),
            Value::Text(sha.to_string()),
        ),
        (Value::Text("url".into()), Value::Text(url.to_string())),
    ]))
}

fn string_field(
    obj: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<String, &'static str> {
    obj.get(name)
        .and_then(Json::as_str)
        .map(str::to_string)
        // The miner-agent rejects empty `vm_id` (`VmId::new`) so we
        // fail fast here too — same shape rules on the two sides.
        .filter(|s| !s.is_empty())
        .ok_or(match name {
            "vm_id" => "missing-vm-id",
            "ovmf_path" => "missing-ovmf-path",
            "kernel_path" => "missing-kernel-path",
            "initrd_path" => "missing-initrd-path",
            "cmdline" => "missing-cmdline",
            "luks_disk_path" => "missing-luks-disk-path",
            "cose_ticket" => "missing-cose-ticket",
            _ => "missing-string-field",
        })
}

fn u32_field(obj: &serde_json::Map<String, Json>, name: &'static str) -> Result<u32, &'static str> {
    let n = obj.get(name).and_then(Json::as_u64).ok_or(match name {
        "luks_disk_size_gb" => "missing-luks-disk-size-gb",
        "memory_mb" => "missing-memory-mb",
        _ => "missing-u32-field",
    })?;
    u32::try_from(n).map_err(|_| match name {
        "luks_disk_size_gb" => "luks-disk-size-gb-overflow",
        "memory_mb" => "memory-mb-overflow",
        _ => "u32-overflow",
    })
}

/// Optional u32: absent ⇒ 0 (the serde-default contract the
/// miner-agent's `LaunchOrder.data_disk_size_gb` mirrors); present but
/// non-numeric / overflowing ⇒ loud error, never a silent 0.
fn optional_u32_field(
    obj: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<u32, &'static str> {
    match obj.get(name) {
        None => Ok(0),
        Some(v) => {
            let n = v.as_u64().ok_or(match name {
                "data_disk_size_gb" => "data-disk-size-gb-not-u32",
                _ => "optional-u32-not-u32",
            })?;
            u32::try_from(n).map_err(|_| match name {
                "data_disk_size_gb" => "data-disk-size-gb-overflow",
                _ => "optional-u32-overflow",
            })
        }
    }
}

fn u8_field(obj: &serde_json::Map<String, Json>, name: &'static str) -> Result<u8, &'static str> {
    let n = obj
        .get(name)
        .and_then(Json::as_u64)
        .ok_or("missing-cpu-count")?;
    u8::try_from(n).map_err(|_| "cpu-count-overflow")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_types::cbor::assert_canonical;

    fn args(order_id: &str, kind: &str) -> EncodeOrderArgs {
        EncodeOrderArgs {
            order_id: order_id.to_string(),
            kind: kind.to_string(),
            target_miner_id: "cc-test-miner".to_string(),
            issued_at_unix: 1_770_000_000,
        }
    }

    fn launch_payload() -> &'static [u8] {
        // `cose_ticket` is base64("fake-cose-ticket-bytes") — the
        // shape vali emits on the JSON wire. Real launches carry a
        // ~few-hundred-byte COSE_Sign1 blob.
        br#"{
            "vm_id": "tenant-1",
            "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
            "kernel_path": "/var/lib/hippius-miner/vmlinuz",
            "initrd_path": "/var/lib/hippius-miner/initrd",
            "cmdline": "console=hvc0",
            "luks_disk_path": "/var/lib/hippius-miner/d.img",
            "luks_disk_size_gb": 10,
            "cpu_count": 2,
            "memory_mb": 2048,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw=="
        }"#
    }

    #[test]
    fn launch_round_trips_to_canonical_cbor() {
        // Build the body, then assert canonical (the §10 invariant the
        // miner-agent's wire gate enforces). A drift in `to_canonical_vec`
        // would be caught by this.
        let bytes = build(&args("ord-1", "launch"), launch_payload()).unwrap();
        assert_canonical(&bytes).expect("encoded body must be canonical");
    }

    #[test]
    fn launch_body_matches_the_miner_agent_struct() {
        // The strongest contract: feed the encoded bytes through the
        // miner-agent's own `OrderBody<LaunchOrder>` decoder (via
        // ciborium::de::from_reader against a mirror of the shape) and
        // verify every field matches. We mirror just the fields we
        // care about — testing `domain`, `kind`, `order_id`, and the
        // launch payload's vm_id/cpu_count/memory_mb.
        use serde::Deserialize;
        use serde_bytes::ByteBuf;
        #[derive(Deserialize)]
        struct WireLaunch {
            vm_id: String,
            cpu_count: u8,
            memory_mb: u32,
            luks_disk_size_gb: u32,
            cose_ticket: ByteBuf,
            cmdline: String,
        }
        #[derive(Deserialize)]
        struct WireBody {
            domain: String,
            order_id: String,
            kind: String,
            target_miner_id: String,
            issued_at_unix: u64,
            payload: WireLaunch,
        }
        let bytes = build(&args("ord-7", "launch"), launch_payload()).unwrap();
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.domain, ORDER_DOMAIN);
        assert_eq!(back.order_id, "ord-7");
        assert_eq!(back.kind, "launch");
        assert_eq!(back.target_miner_id, "cc-test-miner");
        assert_eq!(back.issued_at_unix, 1_770_000_000);
        assert_eq!(back.payload.vm_id, "tenant-1");
        assert_eq!(back.payload.cpu_count, 2);
        assert_eq!(back.payload.memory_mb, 2048);
        assert_eq!(back.payload.luks_disk_size_gb, 10);
        assert_eq!(back.payload.cmdline, "console=hvc0");
        // The ticket bytes survive the base64 → JSON → encoder →
        // canonical-CBOR → miner-agent-decode chain byte-identical
        // (the §6 ticket bytes the L1 mint produced reach the guest
        // unchanged).
        assert_eq!(back.payload.cose_ticket.as_ref(), b"fake-cose-ticket-bytes",);
    }

    #[test]
    fn launch_carries_data_disk_size_gb_when_set() {
        // #365 — the JSON→CBOR bridge MUST forward `data_disk_size_gb`
        // (this bridge silently dropping it shipped the first xlarge
        // with no /dev/vde, 2026-06-11). Decode with the serde(default)
        // mirror of the miner-agent's LaunchOrder field and a canonical
        // check (key order "cpu_count" < "data_disk_size_gb" <
        // "initrd_path").
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct WireLaunch {
            vm_id: String,
            #[serde(default)]
            data_disk_size_gb: u32,
        }
        #[derive(Deserialize)]
        struct WireBody {
            payload: WireLaunch,
        }
        let payload = br#"{
            "vm_id": "tenant-1",
            "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
            "kernel_path": "/var/lib/hippius-miner/vmlinuz",
            "initrd_path": "/var/lib/hippius-miner/initrd",
            "cmdline": "console=hvc0",
            "luks_disk_path": "/var/lib/hippius-miner/d.img",
            "luks_disk_size_gb": 10,
            "data_disk_size_gb": 64,
            "cpu_count": 8,
            "memory_mb": 16384,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw=="
        }"#;
        let bytes = build(&args("ord-dd", "launch"), payload).unwrap();
        assert_canonical(&bytes).expect("data-disk body must stay canonical");
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.payload.vm_id, "tenant-1");
        assert_eq!(back.payload.data_disk_size_gb, 64);
    }

    #[test]
    fn launch_omits_data_disk_key_when_absent_or_zero() {
        // Back-compat: no data disk ⇒ the key is NOT in the CBOR at
        // all, so an older miner-agent's deny_unknown_fields decode
        // still accepts the body (byte-identical to the pre-#365 wire).
        let explicit_zero = String::from_utf8(launch_payload().to_vec())
            .unwrap()
            .replace(
                "\"luks_disk_size_gb\": 10,",
                "\"luks_disk_size_gb\": 10, \"data_disk_size_gb\": 0,",
            )
            .into_bytes();
        for payload in [launch_payload().to_vec(), explicit_zero] {
            let bytes = build(&args("ord-nodd", "launch"), &payload).unwrap();
            assert_canonical(&bytes).expect("canonical");
            // Raw key must be absent from the encoded bytes.
            let needle = b"data_disk_size_gb";
            let found = bytes.windows(needle.len()).any(|w| w == needle.as_slice());
            assert!(
                !found,
                "data_disk_size_gb key must be omitted when 0/absent"
            );
        }
    }

    #[test]
    fn launch_rejects_non_numeric_data_disk_size() {
        // Present-but-garbage must error loudly, never silently 0.
        let payload = String::from_utf8(launch_payload().to_vec())
            .unwrap()
            .replace(
                "\"luks_disk_size_gb\": 10,",
                "\"luks_disk_size_gb\": 10, \"data_disk_size_gb\": \"big\",",
            )
            .into_bytes();
        let err = build(&args("ord-baddd", "launch"), &payload).unwrap_err();
        assert_eq!(err, "data-disk-size-gb-not-u32");
    }

    #[test]
    fn launch_rejects_empty_cose_ticket() {
        // base64("") = "" — an empty ticket would stall every guest at
        // the §21 first stage, so the encoder rejects at the boundary.
        let payload = br#"{
            "vm_id": "tenant-1",
            "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
            "kernel_path": "/var/lib/hippius-miner/vmlinuz",
            "initrd_path": "/var/lib/hippius-miner/initrd",
            "cmdline": "console=hvc0",
            "luks_disk_path": "/var/lib/hippius-miner/d.img",
            "luks_disk_size_gb": 10,
            "cpu_count": 2,
            "memory_mb": 2048,
            "cose_ticket": ""
        }"#;
        let err = build(&args("ord-empty", "launch"), payload).unwrap_err();
        // `string_field` rejects the empty string first with
        // `missing-cose-ticket`; an absent field also lands here. The
        // explicit "empty cose blob" guard further down catches a
        // non-empty base64 that decoded to zero bytes (unreachable
        // with STANDARD alphabet, but defence-in-depth).
        assert!(
            err == "missing-cose-ticket" || err == "cose-ticket-empty",
            "unexpected error class: {err}"
        );
    }

    #[test]
    fn launch_rejects_malformed_base64_cose_ticket() {
        let payload = br#"{
            "vm_id": "tenant-1",
            "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
            "kernel_path": "/var/lib/hippius-miner/vmlinuz",
            "initrd_path": "/var/lib/hippius-miner/initrd",
            "cmdline": "console=hvc0",
            "luks_disk_path": "/var/lib/hippius-miner/d.img",
            "luks_disk_size_gb": 10,
            "cpu_count": 2,
            "memory_mb": 2048,
            "cose_ticket": "not_base64!@#"
        }"#;
        let err = build(&args("ord-bad", "launch"), payload).unwrap_err();
        assert_eq!(err, "cose-ticket-base64");
    }

    #[test]
    fn stop_payload_round_trips() {
        let bytes = build(
            &args("ord-2", "stop"),
            br#"{"vm_id": "tenant-1", "graceful": true}"#,
        )
        .unwrap();
        assert_canonical(&bytes).unwrap();
    }

    #[test]
    fn destroy_payload_round_trips() {
        let bytes = build(&args("ord-3", "destroy"), br#"{"vm_id": "tenant-1"}"#).unwrap();
        assert_canonical(&bytes).unwrap();
    }

    #[test]
    fn migrate_payload_round_trips() {
        let bytes = build(&args("ord-4", "migrate"), br#"{"vm_id": "tenant-1"}"#).unwrap();
        assert_canonical(&bytes).unwrap();
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let err = build(&args("ord-5", "explode"), br#"{"vm_id":"x"}"#).unwrap_err();
        assert_eq!(err, "bad-kind");
    }

    fn migrate_activate_payload() -> &'static [u8] {
        br#"{
            "vm_id": "tenant-1",
            "get_url": "https://s3.example/snap?sig=x",
            "state_get_url": "https://s3.example/state?sig=y",
            "new_gen": 6,
            "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
            "kernel_path": "/var/lib/hippius-miner/vmlinuz",
            "initrd_path": "/var/lib/hippius-miner/initrd",
            "cmdline": "ro hippius.vm_generation=6",
            "luks_disk_path": "/var/lib/hippius-miner/d.img",
            "luks_disk_size_gb": 10,
            "cpu_count": 2,
            "memory_mb": 2048,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw==",
            "rootfs_data_path": "/var/lib/hippius-miner/rootfs.img",
            "rootfs_hash_path": "/var/lib/hippius-miner/rootfs.verity",
            "boot_artifacts": {
                "kernel": {"url": "https://s3/k", "sha256_hex": "aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899"},
                "initrd": {"url": "https://s3/i", "sha256_hex": "bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899aabb"}
            }
        }"#
    }

    #[test]
    fn migrate_activate_omits_the_state_url_when_absent() {
        // Deploy-order safety: a vali that carries no state disk (an
        // in-flight job, or a vali predating #876) must produce a body
        // BYTE-IDENTICAL to the pre-#876 wire, so a miner-agent whose
        // `MigrateActivateOrder` is `deny_unknown_fields` and lacks the
        // field still decodes it. Emitting `state_get_url: ""` instead of
        // omitting the key would break every not-yet-upgraded miner.
        let with_empty = String::from_utf8(migrate_activate_payload().to_vec())
            .unwrap()
            .replace("\"https://s3.example/state?sig=y\"", "\"\"");
        let omitted = String::from_utf8(migrate_activate_payload().to_vec())
            .unwrap()
            .replace("\"state_get_url\": \"https://s3.example/state?sig=y\",", "");

        let a = build(
            &args("ord-act-1", "migrate-activate"),
            with_empty.as_bytes(),
        )
        .unwrap();
        let b = build(&args("ord-act-1", "migrate-activate"), omitted.as_bytes()).unwrap();
        assert_eq!(a, b, "an empty state_get_url must encode as an ABSENT key");

        // And the key really is gone from the bytes (not merely equal to
        // some other encoding of the same absence).
        let hay = String::from_utf8_lossy(&a);
        assert!(
            !hay.contains("state_get_url"),
            "the key must not appear when the caller carries no state disk"
        );
    }

    #[test]
    fn migrate_activate_round_trips_to_canonical_cbor() {
        // §25 M4 — the dest-activation body must be canonical (the wire
        // gate the miner-agent enforces) AND decode through a mirror of the
        // miner-agent's `OrderBody<MigrateActivateOrder>` shape.
        use serde::Deserialize;
        use serde_bytes::ByteBuf;

        let bytes = build(
            &args("ord-act-1", "migrate-activate"),
            migrate_activate_payload(),
        )
        .unwrap();
        assert_canonical(&bytes).expect("encoded body must be canonical");

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireStaged {
            url: String,
            sha256_hex: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireStaging {
            #[serde(default)]
            ovmf: Option<WireStaged>,
            kernel: WireStaged,
            initrd: WireStaged,
            #[serde(default)]
            rootfs_data: Option<WireStaged>,
            #[serde(default)]
            rootfs_hash: Option<WireStaged>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireActivate {
            vm_id: String,
            get_url: String,
            // Deliberately NOT `Option`: if the builder ever stops
            // emitting it, this decode FAILS instead of silently
            // yielding None — which is how the #365 bridge bug and this
            // one both reached production.
            state_get_url: String,
            new_gen: u64,
            ovmf_path: String,
            kernel_path: String,
            initrd_path: String,
            cmdline: String,
            luks_disk_path: String,
            luks_disk_size_gb: u32,
            #[serde(default)]
            rootfs_data_path: Option<String>,
            #[serde(default)]
            rootfs_hash_path: Option<String>,
            cpu_count: u8,
            memory_mb: u32,
            cose_ticket: ByteBuf,
            #[serde(default)]
            boot_artifacts: Option<WireStaging>,
        }
        #[derive(Deserialize)]
        struct WireBody {
            kind: String,
            target_miner_id: String,
            payload: WireActivate,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.kind, "migrate-activate");
        assert_eq!(back.target_miner_id, "cc-test-miner");
        let p = back.payload;
        assert_eq!(p.vm_id, "tenant-1");
        assert_eq!(p.get_url, "https://s3.example/snap?sig=x");
        assert_eq!(p.state_get_url, "https://s3.example/state?sig=y");
        assert_eq!(p.new_gen, 6);
        assert_eq!(p.cmdline, "ro hippius.vm_generation=6");
        assert_eq!(p.luks_disk_size_gb, 10);
        assert_eq!(p.cpu_count, 2);
        assert_eq!(p.memory_mb, 2048);
        assert_eq!(p.cose_ticket.as_ref(), b"fake-cose-ticket-bytes");
        assert_eq!(
            p.rootfs_data_path.as_deref(),
            Some("/var/lib/hippius-miner/rootfs.img")
        );
        assert_eq!(
            p.rootfs_hash_path.as_deref(),
            Some("/var/lib/hippius-miner/rootfs.verity")
        );
        // The measured boot tuple paths survive byte-identical.
        assert_eq!(p.ovmf_path, "/var/lib/hippius-miner/ovmf.fd");
        assert_eq!(p.kernel_path, "/var/lib/hippius-miner/vmlinuz");
        assert_eq!(p.initrd_path, "/var/lib/hippius-miner/initrd");
        assert_eq!(p.luks_disk_path, "/var/lib/hippius-miner/d.img");
        let staging = p.boot_artifacts.expect("boot_artifacts present");
        assert!(staging.ovmf.is_none());
        assert!(staging.rootfs_data.is_none());
        assert!(staging.rootfs_hash.is_none());
        assert_eq!(staging.kernel.url, "https://s3/k");
        assert_eq!(
            staging.kernel.sha256_hex,
            "aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(staging.initrd.url, "https://s3/i");
        assert_eq!(
            staging.initrd.sha256_hex,
            "bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899aabb"
        );
    }

    #[test]
    fn migrate_activate_omits_boot_artifacts_when_absent() {
        // M2 caller (no staging bundle) — the key must be ABSENT so the
        // miner-agent's `#[serde(default)]` decode accepts it.
        let payload = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        // Strip the boot_artifacts object (from its key to the end of the json
        // object), leaving a valid object.
        let no_staging = br#"{
            "vm_id": "tenant-1",
            "get_url": "https://s3.example/snap?sig=x",
            "new_gen": 6,
            "ovmf_path": "/o", "kernel_path": "/k", "initrd_path": "/i",
            "cmdline": "ro", "luks_disk_path": "/l", "luks_disk_size_gb": 10,
            "cpu_count": 2, "memory_mb": 2048,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw=="
        }"#;
        let _ = payload; // keep the helper referenced
        let bytes = build(&args("ord-act-2", "migrate-activate"), no_staging).unwrap();
        assert_canonical(&bytes).expect("canonical");
        let needle = b"boot_artifacts";
        let found = bytes.windows(needle.len()).any(|w| w == needle.as_slice());
        assert!(!found, "boot_artifacts must be omitted when absent");
        // rootfs paths also omitted ⇒ miner-agent serde-defaults them.
        let needle = b"rootfs_data_path";
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn migrate_activate_rejects_empty_cose_ticket() {
        let payload = br#"{
            "vm_id": "tenant-1", "get_url": "u", "new_gen": 1,
            "ovmf_path": "/o", "kernel_path": "/k", "initrd_path": "/i",
            "cmdline": "ro", "luks_disk_path": "/l", "luks_disk_size_gb": 1,
            "cpu_count": 1, "memory_mb": 1, "cose_ticket": ""
        }"#;
        let err = build(&args("ord-act-3", "migrate-activate"), payload).unwrap_err();
        assert!(err == "missing-cose-ticket" || err == "cose-ticket-empty");
    }

    #[test]
    fn migrate_activate_rejects_missing_new_gen() {
        let payload = br#"{
            "vm_id": "tenant-1", "get_url": "u",
            "ovmf_path": "/o", "kernel_path": "/k", "initrd_path": "/i",
            "cmdline": "ro", "luks_disk_path": "/l", "luks_disk_size_gb": 1,
            "cpu_count": 1, "memory_mb": 1,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw=="
        }"#;
        let err = build(&args("ord-act-4", "migrate-activate"), payload).unwrap_err();
        assert_eq!(err, "missing-new-gen");
    }

    #[test]
    fn migrate_activate_rejects_bad_boot_artifact_sha() {
        let payload = br#"{
            "vm_id": "tenant-1", "get_url": "u", "new_gen": 1,
            "ovmf_path": "/o", "kernel_path": "/k", "initrd_path": "/i",
            "cmdline": "ro", "luks_disk_path": "/l", "luks_disk_size_gb": 1,
            "cpu_count": 1, "memory_mb": 1,
            "cose_ticket": "ZmFrZS1jb3NlLXRpY2tldC1ieXRlcw==",
            "boot_artifacts": {
                "kernel": {"url": "https://s3/k", "sha256_hex": "tooshort"},
                "initrd": {"url": "https://s3/i", "sha256_hex": "bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899aabb"}
            }
        }"#;
        let err = build(&args("ord-act-5", "migrate-activate"), payload).unwrap_err();
        assert_eq!(err, "boot-artifact-bad-sha256-hex");
    }

    #[test]
    fn empty_target_miner_id_is_rejected() {
        // gemini r1 High — target binding is non-optional; an empty
        // value would let the miner's `target_miner_id == self.miner_id`
        // check default to vacuously equal on a misconfigured miner.
        let mut a = args("ord-x", "launch");
        a.target_miner_id = "".to_string();
        let err = build(&a, launch_payload()).unwrap_err();
        assert_eq!(err, "missing-target-miner-id");
    }

    #[test]
    fn launch_missing_vm_id_is_rejected() {
        let err = build(
            &args("ord-6", "launch"),
            br#"{
                "ovmf_path": "/o", "kernel_path": "/k",
                "initrd_path": "/i", "cmdline": "x",
                "luks_disk_path": "/l", "luks_disk_size_gb": 1,
                "cpu_count": 1, "memory_mb": 1
            }"#,
        )
        .unwrap_err();
        assert_eq!(err, "missing-vm-id");
    }

    #[test]
    fn launch_empty_vm_id_is_rejected_like_the_miner_agent() {
        // The miner-agent's `VmId::new` rejects empty strings — mirror
        // that here so vali catches the bad input before signing.
        let err = build(
            &args("ord-7", "launch"),
            br#"{
                "vm_id": "",
                "ovmf_path": "/o", "kernel_path": "/k",
                "initrd_path": "/i", "cmdline": "x",
                "luks_disk_path": "/l", "luks_disk_size_gb": 1,
                "cpu_count": 1, "memory_mb": 1
            }"#,
        )
        .unwrap_err();
        assert_eq!(err, "missing-vm-id");
    }

    #[test]
    fn cpu_count_overflow_is_rejected() {
        // The miner-agent's LaunchOrder cpu_count is u8 — 256+ must fail.
        let err = build(
            &args("ord-8", "launch"),
            br#"{
                "vm_id": "tenant-1",
                "ovmf_path": "/o", "kernel_path": "/k",
                "initrd_path": "/i", "cmdline": "x",
                "luks_disk_path": "/l", "luks_disk_size_gb": 1,
                "cpu_count": 999, "memory_mb": 1
            }"#,
        )
        .unwrap_err();
        assert_eq!(err, "cpu-count-overflow");
    }

    #[test]
    fn payload_not_an_object_is_rejected() {
        let err = build(&args("ord-9", "launch"), b"42").unwrap_err();
        assert_eq!(err, "payload-not-object");
    }

    #[test]
    fn bad_json_is_rejected() {
        let err = build(&args("ord-10", "launch"), b"not json").unwrap_err();
        assert_eq!(err, "payload-json-parse");
    }

    #[test]
    fn stop_requires_graceful_field() {
        // `graceful` is a non-optional bool — same as the miner-agent's
        // serde `deny_unknown_fields` shape.
        let err = build(&args("ord-11", "stop"), br#"{"vm_id": "tenant-1"}"#).unwrap_err();
        assert_eq!(err, "missing-graceful");
    }

    // ── golden-bake PR4: optional rootfs_hash preflight artifact ─────
    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Decode the canonical body, drill into `payload`, and report whether
    /// the payload map carries a `rootfs_hash` key.
    fn payload_has_rootfs_hash(bytes: &[u8]) -> bool {
        let v: Value = ciborium::de::from_reader(bytes).unwrap();
        let Value::Map(top) = v else {
            panic!("body not a map")
        };
        let payload = top
            .iter()
            .find_map(|(k, val)| match k {
                Value::Text(t) if t == "payload" => Some(val),
                _ => None,
            })
            .expect("payload present");
        let Value::Map(p) = payload else {
            panic!("payload not a map")
        };
        p.iter()
            .any(|(k, _)| matches!(k, Value::Text(t) if t == "rootfs_hash"))
    }

    fn golden_preflight_json(with_hash: bool) -> String {
        let hash_field = if with_hash {
            format!(
                r#","rootfs_hash": {{"url": "https://s3/rootfs.verity", "sha256_hex": "{HEX64}"}}"#
            )
        } else {
            String::new()
        };
        format!(
            r#"{{
                "vm_id": "tenant-g",
                "ovmf_path": "/var/lib/hippius-miner/ovmf.fd",
                "cmdline": "ro dm-verity.root={HEX64} hippius.disk_gb=10 boot=hippius-golden",
                "cpu_count": 2,
                "luks_disk": {{"url": "https://s3/rootfs.img", "sha256_hex": "{HEX64}"}},
                "kernel": {{"url": "https://s3/vmlinuz", "sha256_hex": "{HEX64}"}},
                "initrd": {{"url": "https://s3/initrd", "sha256_hex": "{HEX64}"}}{hash_field}
            }}"#
        )
    }

    #[test]
    fn golden_preflight_emits_rootfs_hash_and_stays_canonical() {
        let bytes = build(
            &args("ord-g1", "tenant-preflight"),
            golden_preflight_json(true).as_bytes(),
        )
        .expect("golden preflight encodes");
        assert_canonical(&bytes).expect("golden preflight body must be canonical");
        assert!(
            payload_has_rootfs_hash(&bytes),
            "golden preflight must carry rootfs_hash"
        );
    }

    #[test]
    fn legacy_preflight_omits_rootfs_hash() {
        // No rootfs_hash supplied ⇒ the legacy preflight CBOR must NOT
        // carry the key (byte-shape unchanged for the legacy path).
        let bytes = build(
            &args("ord-l1", "tenant-preflight"),
            golden_preflight_json(false).as_bytes(),
        )
        .expect("legacy preflight encodes");
        assert_canonical(&bytes).expect("legacy preflight body must be canonical");
        assert!(
            !payload_has_rootfs_hash(&bytes),
            "legacy preflight must omit rootfs_hash"
        );
    }

    #[test]
    fn golden_preflight_rejects_a_malformed_rootfs_hash() {
        // A present-but-bad rootfs_hash sha fails closed (never silently
        // dropped) — the same discipline as the required artifacts.
        let json = golden_preflight_json(true).replace(HEX64, "zz");
        // `zz` also breaks the other artifacts' shas; that's fine — the
        // point is a malformed artifact is rejected, not silently encoded.
        let err = build(&args("ord-g2", "tenant-preflight"), json.as_bytes()).unwrap_err();
        assert!(
            err.contains("sha256-hex") || err.contains("bad"),
            "got {err}"
        );
    }

    // ── golden-bake: the LAUNCH order must carry the miner-staged golden
    //    rootfs base paths (vdb/vdc). Regression for the bug where
    //    `build_launch` dropped them (unlike `build_migrate_activate`),
    //    so a golden VM booted the LEGACY `/var/lib/hippius-miner/rootfs.img`
    //    while the cmdline carried the golden `dm-verity.root=` → root-hash
    //    mismatch → the guest failed closed in initramfs (never booted).
    fn launch_payload_has_key(bytes: &[u8], key: &str) -> bool {
        let v: Value = ciborium::de::from_reader(bytes).unwrap();
        let Value::Map(top) = v else {
            panic!("body not a map")
        };
        let payload = top
            .iter()
            .find_map(|(k, val)| match k {
                Value::Text(t) if t == "payload" => Some(val),
                _ => None,
            })
            .expect("payload present");
        let Value::Map(p) = payload else {
            panic!("payload not a map")
        };
        p.iter()
            .any(|(k, _)| matches!(k, Value::Text(t) if t == key))
    }

    fn launch_json(with_rootfs: bool) -> String {
        use base64::Engine as _;
        let ct = base64::engine::general_purpose::STANDARD.encode(b"cose");
        let rootfs = if with_rootfs {
            r#","rootfs_data_path": "/var/lib/hippius-miner/staging/tg/rootfs.img",
               "rootfs_hash_path": "/var/lib/hippius-miner/staging/tg/rootfs.verity""#
        } else {
            ""
        };
        format!(
            r#"{{
                "vm_id": "tenant-g", "ovmf_path": "/o", "kernel_path": "/k",
                "initrd_path": "/i",
                "cmdline": "ro dm-verity.root={HEX64} boot=hippius-golden",
                "luks_disk_path": "/l", "luks_disk_size_gb": 1,
                "cpu_count": 2, "memory_mb": 2048, "cose_ticket": "{ct}"{rootfs}
            }}"#
        )
    }

    #[test]
    fn launch_carries_golden_rootfs_paths_and_stays_canonical() {
        let bytes = build(&args("ord-l1", "launch"), launch_json(true).as_bytes())
            .expect("golden launch encodes");
        assert_canonical(&bytes).expect("launch body must be canonical");
        assert!(
            launch_payload_has_key(&bytes, "rootfs_data_path"),
            "golden launch must carry rootfs_data_path (else the guest boots the legacy rootfs)"
        );
        assert!(
            launch_payload_has_key(&bytes, "rootfs_hash_path"),
            "golden launch must carry rootfs_hash_path"
        );
    }

    #[test]
    fn launch_omits_rootfs_paths_when_absent() {
        // A legacy launch (no rootfs paths on the JSON) stays wire-shape
        // identical: the miner-agent's `#[serde(default)]` supplies the
        // canonical `/var/lib/hippius-miner/rootfs.{img,verity}`.
        let bytes = build(&args("ord-l2", "launch"), launch_json(false).as_bytes())
            .expect("legacy launch encodes");
        assert_canonical(&bytes).expect("launch body must be canonical");
        assert!(!launch_payload_has_key(&bytes, "rootfs_data_path"));
        assert!(!launch_payload_has_key(&bytes, "rootfs_hash_path"));
    }
}
