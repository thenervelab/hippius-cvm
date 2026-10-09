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
//! ### `launch` / `migrate-activate` — optional `guardian_ep`
//!
//! Customer-held keys: the canonical `host:port` of the VM's key
//! guardian. Must equal the measured `hippius.guardian_ep=` cmdline token
//! once DECODED — the cmdline carries the lowercase hex of this string,
//! the order the plain string (and is required when the cmdline carries
//! one). Emitted only when set.
//!
//! ### `launch` / `migrate-activate` — optional `net`
//!
//! The guest NIC's settings, `{"cap_mbps": 250, "isolate": true}`
//! (both keys optional; mirrors `NetSpec`). Absent or null ⇒ not emitted,
//! so the body is byte-identical to one without it. `cap_mbps` absent or
//! null and `isolate: false` are not emitted inside it either, as the
//! miner-agent's serde would not emit them.
//!
//! ### `stop`
//!
//! `{"vm_id": "tenant-1", "graceful": true}`
//!
//! ### `destroy` / `migrate`
//!
//! `{"vm_id": "tenant-1"}`
//!
//! ### `backup`
//!
//! ```json
//! {
//!   "vm_id": "tenant-1", "run_id": "r2", "parent_run_id": "r1",
//!   "kind": "full" | "incremental", "part_size": 268435456,
//!   "disk_part_urls": ["https://…partNumber=1…", …], "state_put_url": "https://…"
//! }
//! ```
//!
//! ### `migrate-activate` — optional `backup_chain`
//!
//! `{"restore_id": "…", "full": {"url", "sha256_hex", "size",
//! "part_size"?, "part_sha256_hex"?}, "incrementals": [{…}, …],
//! "state": {…}}` — see `build_backup_chain`.
//!
//! ### `migrate-activate` — optional `staged_restore_id`
//!
//! 32 lower-case hex. With it, `get_url` / `state_get_url` /
//! `backup_chain` must be absent or empty; `get_url` is emitted as `""`.
//!
//! ### `restore`
//!
//! ```json
//! {
//!   "vm_id": "tenant-1", "restore_id": "<32 lower hex>",
//!   "op": "stage" | "abort" | "reclaim",
//!   "chain": {…backup_chain, same restore_id…},   // stage only
//!   "disk_bytes": 42949672960,                     // stage only
//!   "streams": 8                                   // optional
//! }
//! ```
//!
//! ### `net-policy`
//!
//! Host-wide, no `vm_id`. Every key is required except `uplink_hint`
//! (emitted only when a non-null string); an unknown key is refused
//! (`net-policy-unknown-field`) rather than dropped:
//!
//! ```json
//! {
//!   "revision": 7, "not_after_unix": 1770086400, "region": "AU",
//!   "mode": "local" | "edge", "enforce": false,
//!   "local_action": "count" | "drop", "uplink_hint": "eth0",
//!   "infra": [{"ip": "1.1.1.1", "proto": "udp", "port": 51820}],
//!   "region_miners": ["8.8.4.4"],
//!   "nb_control": [{"ip": "9.9.9.9", "proto": "tcp", "port": 443}],
//!   "dns_limit_pps": 20, "smtp_allowed_vms": ["tenant-1"],
//!   "vm_caps": {"tenant-1": 100}
//! }
//! ```
//!
//! The miner-agent checks the values (canonical IPv4, charsets, ranges)
//! and acks `applied:<revision>:<content sha256>`; `net-policy-digest`
//! computes that sha from the same JSON.
//!
//! ### `power-policy`
//!
//! A VM's guest-poweroff policy, both keys required, nothing else:
//!
//! ```json
//! { "vm_id": "tenant-1", "on_guest_poweroff": "restart" | "stop" }
//! ```
//!
//! `launch` takes the same optional `on_guest_poweroff`, emitted only
//! when present (an agent too old to know it refuses the body at decode).

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
    /// AFTER the Edge signature checks (review r1 High —
    /// cross-miner replay). vali passes the same miner_id it
    /// addresses the dispatch HTTP call to.
    #[arg(long)]
    pub target_miner_id: String,

    /// Unix-seconds-since-epoch the caller is issuing this order. The
    /// miner-agent enforces a ±`MAX_ORDER_AGE_SECS` window around its
    /// own clock (review r1 High — long-term replay). vali passes
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
        "backup" => build_backup(payload_obj)?,
        "restore" => build_restore(payload_obj)?,
        "migrate-snapshot" => build_migrate_snapshot(payload_obj)?,
        "net-policy" => build_net_policy(payload_obj)?,
        "power-policy" => build_power_policy(payload_obj)?,
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
    let guardian_ep = guardian_ep_field(obj, &cmdline)?;
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
    // A RELAUNCH (vali reboot-recovery / power start): the miner must find
    // the VM's disks already there and refuse rather than create blank ones.
    // Emitted ONLY when true — a first launch stays byte-identical, and a
    // miner-agent too old to know the key refuses the relaunch at decode
    // (`deny_unknown_fields`) instead of silently blank-creating: the
    // `data_disk_size_gb` lesson, applied up front. Present-but-not-bool
    // is a loud error, never a silent `false`.
    if optional_bool_field(obj, "require_existing_disks")? {
        entries.push((
            Value::Text("require_existing_disks".into()),
            Value::Bool(true),
        ));
    }
    push_guardian_ep(&mut entries, guardian_ep);
    push_net(&mut entries, net_field(obj)?);
    // The guest-poweroff policy: emitted only when present, so a launch
    // without it is byte-identical to before, and a value this bridge does
    // not know is refused — dropping it would silently turn a `stop` VM
    // into a `restart` one (the #365 lesson again).
    if let Some(policy) = on_guest_poweroff_field(obj, false)? {
        entries.push((
            Value::Text("on_guest_poweroff".into()),
            Value::Text(policy.into()),
        ));
    }
    Ok(Value::Map(entries))
}

/// `on_guest_poweroff` — mirrors the miner-agent's `OnGuestPoweroff`
/// (`restart` | `stop`). Absent / null ⇒ `None`, unless `required`.
fn on_guest_poweroff_field(
    obj: &serde_json::Map<String, Json>,
    required: bool,
) -> Result<Option<&'static str>, &'static str> {
    match obj.get("on_guest_poweroff") {
        None | Some(Json::Null) if required => Err("missing-on-guest-poweroff"),
        None | Some(Json::Null) => Ok(None),
        Some(v) => match v.as_str() {
            Some("restart") => Ok(Some("restart")),
            Some("stop") => Ok(Some("stop")),
            _ => Err("bad-on-guest-poweroff"),
        },
    }
}

/// Build the `payload` map for `kind=power-policy`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::PowerPolicyOrder`; an
/// unknown key is refused rather than dropped.
fn build_power_policy(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    if obj.keys().any(|k| k != "vm_id" && k != "on_guest_poweroff") {
        return Err("power-policy-unknown-field");
    }
    let vm_id = string_field(obj, "vm_id")?;
    let policy = on_guest_poweroff_field(obj, true)?.ok_or("missing-on-guest-poweroff")?;
    Ok(Value::Map(vec![
        (
            Value::Text("on_guest_poweroff".into()),
            Value::Text(policy.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ]))
}

/// Highest cap the miner-agent accepts (`netpolicy::MAX_VM_CAP_MBPS`).
const MAX_NET_CAP_MBPS: u64 = 100_000;

/// The optional `net` spec — mirrors `LaunchOrder::net` /
/// `MigrateActivateOrder::net`. Absent / null ⇒ `None`, and then not
/// emitted. Present, it must be an object with no key but `cap_mbps`
/// (an integer in `1..=100000`, or null) and `isolate` (a bool): this
/// bridge copies only the keys it lists, so an unknown key is refused
/// (`bad-net`) rather than silently dropped. An agent too old to know
/// `net` refuses a body that carries it (`deny_unknown_fields`):
/// miner-agents deploy before vali.
fn net_field(obj: &serde_json::Map<String, Json>) -> Result<Option<Value>, &'static str> {
    let net = match obj.get("net") {
        None | Some(Json::Null) => return Ok(None),
        Some(v) => v.as_object().ok_or("bad-net")?,
    };
    if net.keys().any(|k| k != "cap_mbps" && k != "isolate") {
        return Err("bad-net");
    }
    let mut entries = Vec::new();
    match net.get("cap_mbps") {
        None | Some(Json::Null) => {}
        Some(v) => {
            let cap = v
                .as_u64()
                .filter(|c| (1..=MAX_NET_CAP_MBPS).contains(c))
                .ok_or("bad-net-cap")?;
            entries.push((Value::Text("cap_mbps".into()), Value::Integer(cap.into())));
        }
    }
    match net.get("isolate") {
        None => {}
        Some(v) => {
            if v.as_bool().ok_or("bad-net")? {
                entries.push((Value::Text("isolate".into()), Value::Bool(true)));
            }
        }
    }
    Ok(Some(Value::Map(entries)))
}

fn push_net(entries: &mut Vec<(Value, Value)>, net: Option<Value>) {
    if let Some(net) = net {
        entries.push((Value::Text("net".into()), net));
    }
}

/// Customer-held keys: the optional `guardian_ep` — the ONE destination
/// the miner's guardian relay dials for this VM. Mirrors
/// `LaunchOrder::guardian_ep` / `MigrateActivateOrder::guardian_ep`.
///
/// Absent / null ⇒ `None` (M0), and then NOT emitted: an M0 body stays
/// byte-identical and an agent predating the key still decodes it. When
/// present it must be the canonical `host:port` and equal the MEASURED
/// `hippius.guardian_ep=` token of `cmdline` as `GuardianBinding` DECODES
/// it (the token is hex; the comparison is endpoint to endpoint, never
/// this string to the raw token); a customer-keys cmdline
/// WITHOUT it is refused too. That last rule is the #365 lesson applied
/// up front: this bridge re-serialises field by field, and a
/// customer-keys launch whose endpoint vanished here would boot a guest
/// that waits forever on a relay that refuses it. An agent too old to
/// know the key refuses a body that carries it (`deny_unknown_fields`):
/// miner-agents deploy before vali.
fn guardian_ep_field(
    obj: &serde_json::Map<String, Json>,
    cmdline: &str,
) -> Result<Option<String>, &'static str> {
    use hippius_types::guardian::{GuardianBinding, GuardianEndpoint};
    let ep = match obj.get("guardian_ep") {
        None | Some(Json::Null) => None,
        Some(v) => {
            let s = v.as_str().ok_or("bad-guardian-ep")?;
            let parsed = GuardianEndpoint::parse(s).map_err(|_| "bad-guardian-ep")?;
            if parsed.to_wire() != s {
                return Err("bad-guardian-ep");
            }
            Some(parsed)
        }
    };
    let binding = GuardianBinding::from_cmdline(cmdline).map_err(|_| "bad-guardian-cmdline")?;
    match (binding, ep) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err("guardian-ep-orphan"),
        (Some(_), None) => Err("guardian-ep-missing"),
        (Some(b), Some(ep)) if b.endpoint == ep => Ok(Some(ep.to_wire())),
        (Some(_), Some(_)) => Err("guardian-ep-mismatch"),
    }
}

fn push_guardian_ep(entries: &mut Vec<(Value, Value)>, guardian_ep: Option<String>) {
    if let Some(ep) = guardian_ep {
        entries.push((Value::Text("guardian_ep".into()), Value::Text(ep)));
    }
}

/// Optional bool: absent ⇒ `false`; present but not a JSON bool ⇒ error.
fn optional_bool_field(
    obj: &serde_json::Map<String, Json>,
    name: &'static str,
) -> Result<bool, &'static str> {
    match obj.get(name) {
        None => Ok(false),
        Some(v) => v.as_bool().ok_or(match name {
            "require_existing_disks" => "require-existing-disks-not-bool",
            _ => "optional-bool-not-bool",
        }),
    }
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
    // A staged restore boots the disks the miner already staged: no
    // snapshot, no state disk, no chain. `get_url` is then sent empty (the
    // miner's field has no default, so the key stays).
    let staged_restore_id = match obj.get("staged_restore_id") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            v.as_str()
                .filter(|s| is_restore_id(s))
                .ok_or("bad-staged-restore-id")?,
        ),
    };
    let get_url = match staged_restore_id {
        None => string_field(obj, "get_url")?,
        Some(_) => {
            let carries = |k: &str| match obj.get(k) {
                None | Some(Json::Null) => false,
                Some(Json::String(s)) => !s.is_empty(),
                Some(_) => true,
            };
            if carries("get_url") || carries("state_get_url") || carries("backup_chain") {
                return Err("staged-restore-conflict");
            }
            String::new()
        }
    };
    let new_gen = obj
        .get("new_gen")
        .and_then(Json::as_u64)
        .ok_or("missing-new-gen")?;
    let ovmf_path = string_field(obj, "ovmf_path")?;
    let kernel_path = string_field(obj, "kernel_path")?;
    let initrd_path = string_field(obj, "initrd_path")?;
    let cmdline = string_field(obj, "cmdline")?;
    // The dest boots the same measured cmdline, so its relay must dial the
    // same guardian — see `guardian_ep_field`.
    let guardian_ep = guardian_ep_field(obj, &cmdline)?;
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
    // The snapshot's length + sha256 as the source uploaded it — the dest
    // verifies its download against them before attaching it. Emitted only
    // when known (a multipart snapshot), like `state_get_url`.
    match obj.get("snapshot_size") {
        None | Some(Json::Null) => {}
        Some(v) => {
            let size = v.as_u64().filter(|n| *n > 0).ok_or("bad-snapshot-size")?;
            entries.push((
                Value::Text("snapshot_size".into()),
                Value::Integer(size.into()),
            ));
        }
    }
    match obj.get("snapshot_sha256_hex") {
        None | Some(Json::Null) => {}
        Some(v) => {
            let sha = v
                .as_str()
                .filter(|s| is_sha256_hex(s))
                .ok_or("bad-snapshot-sha256-hex")?;
            entries.push((
                Value::Text("snapshot_sha256_hex".into()),
                Value::Text(sha.to_string()),
            ));
        }
    }
    // vali's `DestActivating` deadline (unix seconds): the dest settles by
    // then on every attempt. Emitted only when nonzero — absent, null and
    // 0 all mean "not carried" and encode byte-identical to the pre-field
    // wire, which a miner-agent predating the field still decodes. One
    // that carries it is refused at decode by such an agent
    // (`deny_unknown_fields`): agents deploy before vali. Present but not
    // a non-negative integer is a loud error, never a silent absence.
    match obj.get("settle_by_unix") {
        None | Some(Json::Null) => {}
        Some(v) => {
            let settle_by = v.as_u64().ok_or("bad-settle-by-unix")?;
            if settle_by != 0 {
                entries.push((
                    Value::Text("settle_by_unix".into()),
                    Value::Integer(settle_by.into()),
                ));
            }
        }
    }
    // Optional path fields — emitted only when present so an absent one
    // falls to the miner-agent's `#[serde(default)]` canonical path.
    if let Some(p) = optional_string_field(obj, "rootfs_data_path")? {
        entries.push((Value::Text("rootfs_data_path".into()), Value::Text(p)));
    }
    if let Some(p) = optional_string_field(obj, "rootfs_hash_path")? {
        entries.push((Value::Text("rootfs_hash_path".into()), Value::Text(p)));
    }
    push_guardian_ep(&mut entries, guardian_ep);
    push_net(&mut entries, net_field(obj)?);
    // Staged restore — emitted only when set, so every other activation
    // stays byte-identical and an older agent is never sent the key.
    if let Some(rid) = staged_restore_id {
        entries.push((
            Value::Text("staged_restore_id".into()),
            Value::Text(rid.to_string()),
        ));
    }
    // Optional backup-chain restore — emitted only when present, so every
    // §25 activation stays byte-identical to today's wire and a miner-agent
    // predating the field (`deny_unknown_fields`) still decodes it. When
    // set, the dest ignores `get_url` / `state_get_url`.
    if let Some(chain) = obj.get("backup_chain") {
        if !chain.is_null() {
            let chain_obj = chain.as_object().ok_or("backup-chain-not-object")?;
            entries.push((
                Value::Text("backup_chain".into()),
                build_backup_chain(chain_obj)?,
            ));
        }
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

/// Most incrementals one restore order carries. The miner accepts more
/// (`backup::restore::MAX_CHAIN_INCREMENTALS`), but the whole activation
/// must fit the Edge's 64 KiB order body; vali rebases chains well below
/// this (`VALI_BACKUP_MAX_CHAIN`, capped at 63).
const MAX_CHAIN_INCREMENTALS: usize = 63;

/// Most part URLs one multipart order (`backup`, `migrate-snapshot`)
/// carries: the largest flavor's overlay (1280 GiB) at the store's 512 MiB
/// part ceiling needs ~2,600; 3,000 ~530-byte URLs stay within the 2 MiB
/// multipart body the Edge and the miner give those kinds.
pub const MAX_MULTIPART_PARTS: usize = 3000;

/// Multipart part-size bounds (the miner-agent's `check_part_size`): S3's
/// floor, and the store's ceiling — hippius-s3 answers `EntityTooLarge`
/// for a part over 512 MiB.
const MIN_MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;
pub const MAX_MULTIPART_PART_SIZE: u64 = 512 << 20;

/// Build the `backup_chain` map — mirrors
/// `binaries/miner-agent/src/backup/restore.rs::RestoreChain`
/// `{restore_id, full, incrementals, state}`, each piece a `ChainPiece`
/// `{url, sha256_hex, size}`. A malformed chain fails the encode loudly —
/// the dest must never receive half a chain.
fn build_backup_chain(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let restore_id = obj
        .get("restore_id")
        .and_then(Json::as_str)
        .filter(|s| is_run_id(s))
        .ok_or("backup-chain-bad-restore-id")?;
    let full = build_chain_piece(obj.get("full"))?;
    let state = build_chain_piece(obj.get("state"))?;
    let incs = match obj.get("incrementals") {
        None | Some(Json::Null) => Vec::new(),
        Some(v) => v.as_array().ok_or("backup-chain-bad-incrementals")?.clone(),
    };
    if incs.len() > MAX_CHAIN_INCREMENTALS {
        return Err("backup-chain-too-long");
    }
    let incrementals = incs
        .iter()
        .map(|p| build_chain_piece(Some(p)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::Map(vec![
        (Value::Text("full".into()), full),
        (
            Value::Text("incrementals".into()),
            Value::Array(incrementals),
        ),
        (
            Value::Text("restore_id".into()),
            Value::Text(restore_id.into()),
        ),
        (Value::Text("state".into()), state),
    ]))
}

/// `{url, sha256_hex, size, part_size?, part_sha256_hex?}` — mirrors the
/// miner-agent's `ChainPiece`. The part layout (the multipart part size
/// the object was uploaded in, and each part's sha256) lets the miner
/// fetch the object as parallel verified ranges; each field is emitted
/// only when set, so a chain without it stays byte-identical. A layout
/// that does not tile the object is refused here, as the miner would.
fn build_chain_piece(v: Option<&Json>) -> Result<Value, &'static str> {
    let p = v
        .and_then(Json::as_object)
        .ok_or("backup-chain-piece-not-object")?;
    let url = p
        .get("url")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("backup-chain-piece-missing-url")?;
    let sha = p
        .get("sha256_hex")
        .and_then(Json::as_str)
        .filter(|s| is_sha256_hex(s))
        .ok_or("backup-chain-piece-bad-sha256-hex")?;
    let size = p
        .get("size")
        .and_then(Json::as_u64)
        .filter(|n| *n > 0)
        .ok_or("backup-chain-piece-bad-size")?;
    let part_size = match p.get("part_size") {
        None | Some(Json::Null) => 0,
        Some(v) => v.as_u64().ok_or("backup-chain-piece-bad-part-size")?,
    };
    let part_shas: Vec<String> = match p.get("part_sha256_hex") {
        None | Some(Json::Null) => Vec::new(),
        Some(v) => v
            .as_array()
            .ok_or("backup-chain-piece-bad-part-sha")?
            .iter()
            .map(|h| {
                h.as_str()
                    .filter(|s| is_sha256_hex(s))
                    .map(str::to_string)
                    .ok_or("backup-chain-piece-bad-part-sha")
            })
            .collect::<Result<_, _>>()?,
    };
    if part_size != 0 {
        if !(MIN_MULTIPART_PART_SIZE..=MAX_MULTIPART_PART_SIZE).contains(&part_size) {
            return Err("backup-chain-piece-bad-part-size");
        }
        let parts = size.div_ceil(part_size);
        if parts > MAX_PIECE_PARTS {
            return Err("backup-chain-piece-bad-part-size");
        }
        if !part_shas.is_empty() && part_shas.len() as u64 != parts {
            return Err("backup-chain-piece-part-sha-count");
        }
    } else if !part_shas.is_empty() {
        return Err("backup-chain-piece-part-sha-count");
    }
    let mut entries = vec![
        (
            Value::Text("sha256_hex".into()),
            Value::Text(sha.to_string()),
        ),
        (Value::Text("size".into()), Value::Integer(size.into())),
        (Value::Text("url".into()), Value::Text(url.to_string())),
    ];
    if part_size != 0 {
        entries.push((
            Value::Text("part_size".into()),
            Value::Integer(part_size.into()),
        ));
    }
    if !part_shas.is_empty() {
        entries.push((
            Value::Text("part_sha256_hex".into()),
            Value::Array(part_shas.into_iter().map(Value::Text).collect()),
        ));
    }
    Ok(Value::Map(entries))
}

/// Most parts one piece may be split into (the miner-agent's
/// `transfer::MAX_PARTS`, S3's ceiling).
const MAX_PIECE_PARTS: u64 = 10_000;

/// Build the `payload` map for `kind=restore`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::RestoreOrder`
/// `{vm_id, restore_id, op, chain?, disk_bytes?, streams?}`:
///
/// - `op: "stage"` needs `chain` (whose `restore_id` must be the order's)
///   and `disk_bytes > 0`;
/// - `op: "abort" | "reclaim"` must carry neither (absent / null / 0);
/// - `streams` (1..=255; the miner clamps to 1..=16) is emitted only when
///   given — the miner defaults it to 8.
///
/// `restore_id` is 32 lower-case hex, as the miner requires.
fn build_restore(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    let restore_id = obj
        .get("restore_id")
        .and_then(Json::as_str)
        .filter(|s| is_restore_id(s))
        .ok_or("restore-bad-id")?;
    let op = match obj.get("op").and_then(Json::as_str) {
        Some("stage") => "stage",
        Some("abort") => "abort",
        Some("reclaim") => "reclaim",
        _ => return Err("restore-bad-op"),
    };
    let chain = match obj.get("chain") {
        None | Some(Json::Null) => None,
        Some(v) => Some(v.as_object().ok_or("restore-chain-not-object")?),
    };
    let disk_bytes = match obj.get("disk_bytes") {
        None | Some(Json::Null) => 0,
        Some(v) => v.as_u64().ok_or("restore-bad-disk-bytes")?,
    };
    let mut entries = vec![
        (Value::Text("op".into()), Value::Text(op.into())),
        (
            Value::Text("restore_id".into()),
            Value::Text(restore_id.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ];
    if op == "stage" {
        let chain = chain.ok_or("restore-chain-missing")?;
        if chain.get("restore_id").and_then(Json::as_str) != Some(restore_id) {
            return Err("restore-id-mismatch");
        }
        if disk_bytes == 0 {
            return Err("restore-bad-disk-bytes");
        }
        entries.push((Value::Text("chain".into()), build_backup_chain(chain)?));
        entries.push((
            Value::Text("disk_bytes".into()),
            Value::Integer(disk_bytes.into()),
        ));
    } else if chain.is_some() || disk_bytes != 0 {
        return Err("restore-stray-fields");
    }
    match obj.get("streams") {
        None | Some(Json::Null) => {}
        Some(v) => {
            let n = v
                .as_u64()
                .filter(|n| (1..=u64::from(u8::MAX)).contains(n))
                .ok_or("restore-bad-streams")?;
            entries.push((Value::Text("streams".into()), Value::Integer(n.into())));
        }
    }
    Ok(Value::Map(entries))
}

/// 32 lower-case hex — the miner-agent's `check_restore_id`.
fn is_restore_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the `payload` map for `kind=backup`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::BackupOrder`
/// `{vm_id, run_id, parent_run_id?, kind, part_size, disk_part_urls,
/// state_put_url}`. The part list is bounded by `MAX_MULTIPART_PARTS` and the
/// part size by the store's multipart limits, so a vali bug surfaces here rather
/// than as an Edge 413 / a half-uploaded object. `parent_run_id` is emitted
/// only when present (the miner's `#[serde(default)]`); an incremental
/// without one is refused here.
fn build_backup(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    let run_id = obj
        .get("run_id")
        .and_then(Json::as_str)
        .filter(|s| is_run_id(s))
        .ok_or("backup-bad-run-id")?;
    let parent = match obj.get("parent_run_id") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            v.as_str()
                .filter(|s| is_run_id(s))
                .ok_or("backup-bad-parent-run-id")?,
        ),
    };
    let kind = backup_kind_field(obj)?;
    if kind == "incremental" && parent.is_none() {
        return Err("backup-incremental-without-parent");
    }
    let part_size = obj
        .get("part_size")
        .and_then(Json::as_u64)
        .ok_or("backup-missing-part-size")?;
    if !(MIN_MULTIPART_PART_SIZE..=MAX_MULTIPART_PART_SIZE).contains(&part_size) {
        return Err("backup-bad-part-size");
    }
    let urls = obj
        .get("disk_part_urls")
        .and_then(Json::as_array)
        .ok_or("backup-missing-part-urls")?;
    if urls.is_empty() {
        return Err("backup-no-parts");
    }
    if urls.len() > MAX_MULTIPART_PARTS {
        return Err("backup-too-many-parts");
    }
    let mut part_urls = Vec::with_capacity(urls.len());
    for u in urls {
        let u = u
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("backup-bad-part-url")?;
        part_urls.push(Value::Text(u.to_string()));
    }
    let state_put_url = obj
        .get("state_put_url")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("backup-missing-state-put-url")?;
    let mut entries = vec![
        (
            Value::Text("disk_part_urls".into()),
            Value::Array(part_urls),
        ),
        (Value::Text("kind".into()), Value::Text(kind.into())),
        (
            Value::Text("part_size".into()),
            Value::Integer(part_size.into()),
        ),
        (Value::Text("run_id".into()), Value::Text(run_id.into())),
        (
            Value::Text("state_put_url".into()),
            Value::Text(state_put_url.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ];
    if let Some(parent) = parent {
        entries.push((
            Value::Text("parent_run_id".into()),
            Value::Text(parent.into()),
        ));
    }
    Ok(Value::Map(entries))
}

/// Build the `payload` map for `kind=migrate-snapshot` — the §25 snapshot
/// as a MULTIPART upload. Mirrors the miner-agent's `MigrateSnapshotOrder`
/// `{vm_id, node_id, part_size, disk_part_urls, state_put_url}` (`put_url`,
/// the single-PUT URL, is left out: the miner defaults it). At most
/// `MAX_MULTIPART_PARTS` parts — the Edge and the miner give this kind a
/// 2 MiB body. The state disk URL is required: a destination without the
/// boot counter can never unlock.
fn build_migrate_snapshot(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    let vm_id = string_field(obj, "vm_id")?;
    let node_id = string_field(obj, "node_id")?;
    let part_size = obj
        .get("part_size")
        .and_then(Json::as_u64)
        .ok_or("snapshot-missing-part-size")?;
    if !(MIN_MULTIPART_PART_SIZE..=MAX_MULTIPART_PART_SIZE).contains(&part_size) {
        return Err("snapshot-bad-part-size");
    }
    let urls = obj
        .get("disk_part_urls")
        .and_then(Json::as_array)
        .ok_or("snapshot-missing-part-urls")?;
    if urls.is_empty() {
        return Err("snapshot-no-parts");
    }
    if urls.len() > MAX_MULTIPART_PARTS {
        return Err("snapshot-too-many-parts");
    }
    let mut part_urls = Vec::with_capacity(urls.len());
    for u in urls {
        let u = u
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("snapshot-bad-part-url")?;
        part_urls.push(Value::Text(u.to_string()));
    }
    let state_put_url = obj
        .get("state_put_url")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("snapshot-missing-state-put-url")?;
    Ok(Value::Map(vec![
        (
            Value::Text("disk_part_urls".into()),
            Value::Array(part_urls),
        ),
        (Value::Text("node_id".into()), Value::Text(node_id)),
        (
            Value::Text("part_size".into()),
            Value::Integer(part_size.into()),
        ),
        (
            Value::Text("state_put_url".into()),
            Value::Text(state_put_url.into()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id)),
    ]))
}

/// The `kind` of a backup — closed vocabulary `full` / `incremental`
/// (the miner-agent's kebab-case `BackupKind`).
fn backup_kind_field(obj: &serde_json::Map<String, Json>) -> Result<&'static str, &'static str> {
    match obj.get("kind").and_then(Json::as_str) {
        Some("full") => Ok("full"),
        Some("incremental") => Ok("incremental"),
        _ => Err("backup-bad-kind"),
    }
}

/// `[a-z0-9-]{1,64}` — the miner-agent's run-id rule.
fn is_run_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
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
/// Keys of a `net-policy` payload. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::NetPolicyOrder`.
const NET_POLICY_KEYS: [&str; 13] = [
    "dns_limit_pps",
    "enforce",
    "infra",
    "local_action",
    "mode",
    "nb_control",
    "not_after_unix",
    "region",
    "region_miners",
    "revision",
    "smtp_allowed_vms",
    "uplink_hint",
    "vm_caps",
];

/// Build the `payload` map for `kind=net-policy`. Types and enum values
/// are checked here; the values themselves on the miner, which owns them.
fn build_net_policy(obj: &serde_json::Map<String, Json>) -> Result<Value, &'static str> {
    if obj.keys().any(|k| !NET_POLICY_KEYS.contains(&k.as_str())) {
        return Err("net-policy-unknown-field");
    }
    let uint = |name: &'static str| {
        obj.get(name)
            .and_then(Json::as_u64)
            .ok_or("net-policy-bad-uint")
    };
    let text = |name: &'static str| {
        obj.get(name)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or("net-policy-bad-string")
    };
    let one_of = |name: &'static str, allowed: &[&str]| {
        text(name).and_then(|v| {
            if allowed.contains(&v.as_str()) {
                Ok(v)
            } else {
                Err("net-policy-bad-enum")
            }
        })
    };
    let dns_limit_pps = u32::try_from(uint("dns_limit_pps")?).map_err(|_| "net-policy-bad-uint")?;
    let enforce = obj
        .get("enforce")
        .and_then(Json::as_bool)
        .ok_or("net-policy-bad-bool")?;
    let mut entries = vec![
        (
            Value::Text("dns_limit_pps".into()),
            Value::Integer(dns_limit_pps.into()),
        ),
        (Value::Text("enforce".into()), Value::Bool(enforce)),
        (
            Value::Text("infra".into()),
            net_endpoints(obj.get("infra"))?,
        ),
        (
            Value::Text("local_action".into()),
            Value::Text(one_of("local_action", &["count", "drop"])?),
        ),
        (
            Value::Text("mode".into()),
            Value::Text(one_of("mode", &["local", "edge"])?),
        ),
        (
            Value::Text("nb_control".into()),
            net_endpoints(obj.get("nb_control"))?,
        ),
        (
            Value::Text("not_after_unix".into()),
            Value::Integer(uint("not_after_unix")?.into()),
        ),
        (Value::Text("region".into()), Value::Text(text("region")?)),
        (
            Value::Text("region_miners".into()),
            string_list(obj.get("region_miners"))?,
        ),
        (
            Value::Text("revision".into()),
            Value::Integer(uint("revision")?.into()),
        ),
        (
            Value::Text("smtp_allowed_vms".into()),
            string_list(obj.get("smtp_allowed_vms"))?,
        ),
    ];
    match obj.get("uplink_hint") {
        None | Some(Json::Null) => {}
        Some(v) => entries.push((
            Value::Text("uplink_hint".into()),
            Value::Text(v.as_str().ok_or("net-policy-bad-string")?.to_string()),
        )),
    }
    let caps = obj
        .get("vm_caps")
        .and_then(Json::as_object)
        .ok_or("net-policy-bad-vm-caps")?;
    let mut cap_entries = Vec::with_capacity(caps.len());
    for (vm_id, mbps) in caps {
        let mbps = mbps
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("net-policy-bad-vm-caps")?;
        cap_entries.push((Value::Text(vm_id.clone()), Value::Integer(mbps.into())));
    }
    entries.push((Value::Text("vm_caps".into()), Value::Map(cap_entries)));
    Ok(Value::Map(entries))
}

fn string_list(v: Option<&Json>) -> Result<Value, &'static str> {
    let items = v.and_then(Json::as_array).ok_or("net-policy-bad-list")?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(|s| Value::Text(s.to_string()))
                .ok_or("net-policy-bad-list")
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

/// `[{ip, proto, port}]` — the miner-agent's `NetEndpoint`.
fn net_endpoints(v: Option<&Json>) -> Result<Value, &'static str> {
    let items = v.and_then(Json::as_array).ok_or("net-policy-bad-list")?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let ep = item.as_object().ok_or("net-policy-bad-endpoint")?;
        if ep.len() != 3 {
            return Err("net-policy-bad-endpoint");
        }
        let ip = ep
            .get("ip")
            .and_then(Json::as_str)
            .ok_or("net-policy-bad-endpoint")?;
        let proto = ep
            .get("proto")
            .and_then(Json::as_str)
            .filter(|p| matches!(*p, "tcp" | "udp"))
            .ok_or("net-policy-bad-endpoint")?;
        let port = ep
            .get("port")
            .and_then(Json::as_u64)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or("net-policy-bad-endpoint")?;
        out.push(Value::Map(vec![
            (Value::Text("ip".into()), Value::Text(ip.to_string())),
            (Value::Text("port".into()), Value::Integer(port.into())),
            (Value::Text("proto".into()), Value::Text(proto.to_string())),
        ]));
    }
    Ok(Value::Array(out))
}

/// The `net-policy` content hash the miner acks: SHA-256 of the
/// canonical payload map without `not_after_unix` (see the miner-agent
/// `netpolicy` module docs), lower-case hex.
pub fn net_policy_digest(payload_json: &[u8]) -> Result<String, &'static str> {
    use sha2::{Digest, Sha256};
    let payload: Json = serde_json::from_slice(payload_json).map_err(|_| "payload-json-parse")?;
    let obj = payload.as_object().ok_or("payload-not-object")?;
    let Value::Map(entries) = build_net_policy(obj)? else {
        return Err("canonical-encode");
    };
    let content = Value::Map(
        entries
            .into_iter()
            .filter(|(k, _)| k.as_text() != Some("not_after_unix"))
            .collect(),
    );
    let bytes = to_canonical_vec(&content).map_err(|_| "canonical-encode")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// `net-policy-digest` subcommand: JSON payload on stdin, the content
/// hash hex on stdout. Same exit codes as `encode-order`.
pub fn run_net_policy_digest() -> ExitCode {
    let mut payload_bytes = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut payload_bytes) {
        eprintln!("hippius-ticket-validator: stdin read failed: {e}");
        return ExitCode::from(INTERNAL_FAIL);
    }
    match net_policy_digest(&payload_bytes) {
        Ok(hex) => {
            if let Err(e) = writeln!(io::stdout().lock(), "{hex}") {
                eprintln!("hippius-ticket-validator: stdout write failed: {e}");
                return ExitCode::from(INTERNAL_FAIL);
            }
            ExitCode::from(0)
        }
        Err(class) => {
            eprintln!("hippius-ticket-validator: net-policy-digest: {class}");
            ExitCode::from(SCHEMA_FAIL)
        }
    }
}

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
    fn launch_carries_require_existing_disks_only_when_true() {
        // The relaunch guard rides this bridge; dropping it silently would
        // let a relaunch blank-create the VM's disks again.
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct WireLaunch {
            #[serde(default)]
            require_existing_disks: bool,
        }
        #[derive(Deserialize)]
        struct WireBody {
            payload: WireLaunch,
        }
        let with = |v: &str| {
            String::from_utf8(launch_payload().to_vec())
                .unwrap()
                .replace(
                    "\"luks_disk_size_gb\": 10,",
                    &format!("\"luks_disk_size_gb\": 10, \"require_existing_disks\": {v},"),
                )
                .into_bytes()
        };
        let bytes = build(&args("ord-rl", "launch"), &with("true")).unwrap();
        assert_canonical(&bytes).expect("relaunch body must stay canonical");
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert!(back.payload.require_existing_disks);

        // A first launch (absent or false) stays byte-identical to the
        // pre-flag wire, so an older miner-agent still decodes it.
        let absent = build(&args("ord-rl", "launch"), launch_payload()).unwrap();
        let explicit_false = build(&args("ord-rl", "launch"), &with("false")).unwrap();
        assert_eq!(absent, explicit_false);
        assert!(!launch_payload_has_key(&absent, "require_existing_disks"));

        assert_eq!(
            build(&args("ord-rl", "launch"), &with("\"yes\"")).unwrap_err(),
            "require-existing-disks-not-bool"
        );
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
    fn migrate_activate_carries_the_snapshot_digest_only_when_known() {
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        let sha = "ab".repeat(32);
        let with = base.replacen(
            "\"new_gen\"",
            &format!(
                "\"snapshot_size\": 42949672960, \"snapshot_sha256_hex\": \"{sha}\", \"new_gen\""
            ),
            1,
        );
        let bytes = build(&args("ord-act-d", "migrate-activate"), with.as_bytes()).unwrap();
        assert_canonical(&bytes).expect("canonical");
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let payload = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("payload"))
            .unwrap()
            .1
            .as_map()
            .unwrap()
            .clone();
        let get = |key: &str| {
            payload
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|e| e.1.clone())
        };
        assert_eq!(
            get("snapshot_size"),
            Some(Value::Integer(42_949_672_960u64.into()))
        );
        assert_eq!(get("snapshot_sha256_hex"), Some(Value::Text(sha)));

        let without = build(
            &args("ord-act-d", "migrate-activate"),
            migrate_activate_payload(),
        )
        .unwrap();
        let hay = String::from_utf8_lossy(&without);
        assert!(!hay.contains("snapshot_size") && !hay.contains("snapshot_sha256_hex"));

        for (field, class) in [
            ("\"snapshot_size\": 0, ", "bad-snapshot-size"),
            (
                "\"snapshot_sha256_hex\": \"XYZ\", ",
                "bad-snapshot-sha256-hex",
            ),
        ] {
            let bad = base.replacen("\"new_gen\"", &format!("{field}\"new_gen\""), 1);
            let err = build(&args("ord-act-d", "migrate-activate"), bad.as_bytes()).unwrap_err();
            assert_eq!(err, class);
        }
    }

    #[test]
    fn migrate_activate_carries_settle_by_only_when_nonzero() {
        // The bridge is an allowlist re-serialiser: a settle-by it dropped
        // would leave every retry on the per-attempt clock again, silently.
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        let with = |v: &str| {
            base.replacen(
                "\"new_gen\"",
                &format!("\"settle_by_unix\": {v}, \"new_gen\""),
                1,
            )
        };
        let args = args("ord-act-s", "migrate-activate");
        let bytes = build(&args, with("1790000000").as_bytes()).unwrap();
        assert_canonical(&bytes).expect("canonical");
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let payload = v
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("payload"))
            .unwrap()
            .1
            .as_map()
            .unwrap()
            .clone();
        assert_eq!(
            payload
                .iter()
                .find(|(k, _)| k.as_text() == Some("settle_by_unix"))
                .map(|e| e.1.clone()),
            Some(Value::Integer(1_790_000_000u64.into()))
        );

        // Absent, null and 0 all encode byte-identical to today's wire.
        let absent = build(&args, migrate_activate_payload()).unwrap();
        assert!(!String::from_utf8_lossy(&absent).contains("settle_by_unix"));
        for v in ["0", "null"] {
            assert_eq!(
                build(&args, with(v).as_bytes()).unwrap(),
                absent,
                "settle_by_unix={v}"
            );
        }

        for v in ["-1", "\"1790000000\"", "1.5"] {
            assert_eq!(
                build(&args, with(v).as_bytes()).unwrap_err(),
                "bad-settle-by-unix",
                "settle_by_unix={v}"
            );
        }
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
            #[serde(default)]
            settle_by_unix: u64,
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
        assert_eq!(p.settle_by_unix, 0, "not carried ⇒ not emitted");
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
        // review r1 High — target binding is non-optional; an empty
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

    fn backup_payload(n_parts: usize) -> String {
        let urls: Vec<String> = (1..=n_parts)
            .map(|i| format!("\"https://s3/p?partNumber={i}\""))
            .collect();
        format!(
            r#"{{"vm_id":"tenant-1","run_id":"r2","parent_run_id":"r1","kind":"incremental",
               "part_size":268435456,"disk_part_urls":[{}],
               "state_put_url":"https://s3/state"}}"#,
            urls.join(",")
        )
    }

    #[test]
    fn backup_round_trips_through_a_mirror_of_the_miner_shape() {
        use serde::Deserialize;

        let bytes = build(&args("backup-r2", "backup"), backup_payload(3).as_bytes()).unwrap();
        assert_canonical(&bytes).expect("canonical");

        // Mirrors `orders::types::BackupOrder` on the miner side.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireBackup {
            vm_id: String,
            run_id: String,
            #[serde(default)]
            parent_run_id: Option<String>,
            kind: String,
            part_size: u64,
            disk_part_urls: Vec<String>,
            state_put_url: String,
        }
        #[derive(Deserialize)]
        struct WireBody {
            kind: String,
            payload: WireBackup,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.kind, "backup");
        let p = back.payload;
        assert_eq!(p.vm_id, "tenant-1");
        assert_eq!(p.run_id, "r2");
        assert_eq!(p.parent_run_id.as_deref(), Some("r1"));
        assert_eq!(p.kind, "incremental");
        assert_eq!(p.part_size, 268_435_456);
        assert_eq!(p.disk_part_urls.len(), 3);
        assert_eq!(p.disk_part_urls[2], "https://s3/p?partNumber=3");
        assert_eq!(p.state_put_url, "https://s3/state");
    }

    fn snapshot_payload(n_parts: usize) -> String {
        let urls: Vec<String> = (1..=n_parts)
            .map(|i| format!("\"https://s3/p?partNumber={i}\""))
            .collect();
        format!(
            r#"{{"vm_id":"tenant-1","node_id":"miner-a","part_size":536870912,
               "disk_part_urls":[{}],"state_put_url":"https://s3/state"}}"#,
            urls.join(",")
        )
    }

    #[test]
    fn migrate_snapshot_round_trips_through_a_mirror_of_the_miner_shape() {
        use serde::Deserialize;

        let bytes = build(
            &args("mig-snap-1", "migrate-snapshot"),
            snapshot_payload(40).as_bytes(),
        )
        .unwrap();
        assert_canonical(&bytes).expect("canonical");

        // Mirrors `orders::types::MigrateSnapshotOrder` on the miner side.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSnapshot {
            vm_id: String,
            node_id: String,
            #[serde(default)]
            put_url: String,
            #[serde(default)]
            state_put_url: String,
            #[serde(default)]
            disk_part_urls: Vec<String>,
            #[serde(default)]
            part_size: u64,
        }
        #[derive(Deserialize)]
        struct WireBody {
            kind: String,
            payload: WireSnapshot,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.kind, "migrate-snapshot");
        let p = back.payload;
        assert_eq!(
            (p.vm_id.as_str(), p.node_id.as_str()),
            ("tenant-1", "miner-a")
        );
        assert_eq!(
            p.put_url, "",
            "a multipart snapshot carries no single-PUT URL"
        );
        assert_eq!(p.part_size, 512 << 20);
        assert_eq!(p.disk_part_urls.len(), 40);
        assert_eq!(p.disk_part_urls[39], "https://s3/p?partNumber=40");
        assert_eq!(p.state_put_url, "https://s3/state");
    }

    #[test]
    fn migrate_snapshot_refuses_what_the_miner_or_the_edge_would() {
        let ok = snapshot_payload(2);
        for (payload, class) in [
            (snapshot_payload(0), "snapshot-no-parts"),
            (
                snapshot_payload(MAX_MULTIPART_PARTS + 1),
                "snapshot-too-many-parts",
            ),
            (ok.replace("536870912", "1024"), "snapshot-bad-part-size"),
            (
                ok.replace("536870912", "536870913"),
                "snapshot-bad-part-size",
            ),
            (
                ok.replace(
                    r#""state_put_url":"https://s3/state""#,
                    r#""state_put_url":"""#,
                ),
                "snapshot-missing-state-put-url",
            ),
            (
                ok.replace(r#""node_id":"miner-a","#, ""),
                "missing-string-field",
            ),
        ] {
            let got = build(&args("m", "migrate-snapshot"), payload.as_bytes()).unwrap_err();
            assert_eq!(got, class);
        }
    }

    #[test]
    fn a_full_without_a_parent_omits_the_key() {
        let payload = backup_payload(1)
            .replace("\"parent_run_id\":\"r1\",", "")
            .replace("\"incremental\"", "\"full\"");
        let bytes = build(&args("b", "backup"), payload.as_bytes()).unwrap();
        let needle = b"parent_run_id";
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn backup_with_the_maximum_part_list_fits_the_multipart_body_cap() {
        // 3,000 realistic ~530-byte presigned URLs must fit the Edge's
        // multipart order cap (`MAX_MULTIPART_ORDER_BODY` = 2 MiB - 256).
        let url = format!("\"https://s3.hippius.com/{}\"", "x".repeat(505));
        let urls = vec![url; MAX_MULTIPART_PARTS].join(",");
        let payload = format!(
            r#"{{"vm_id":"tenant-1","run_id":"r1","kind":"full",
               "part_size":536870912,"disk_part_urls":[{urls}],
               "state_put_url":"https://s3/state"}}"#
        );
        let bytes = build(&args("backup-r1", "backup"), payload.as_bytes()).unwrap();
        // The largest flavor (1280 GiB, +1/64 incremental headroom) at
        // 512 MiB parts needs 2,601.
        build(
            &args("backup-r1", "backup"),
            backup_payload(2_601).as_bytes(),
        )
        .unwrap();
        assert!(
            bytes.len() < 2 * 1024 * 1024 - 256,
            "body {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn a_part_over_the_stores_512_mib_ceiling_is_refused() {
        // hippius-s3 answers `EntityTooLarge` above 512 MiB: such an order
        // could only half-upload.
        let ok = backup_payload(1).replace("268435456", "536870912");
        build(&args("b", "backup"), ok.as_bytes()).unwrap();
        let over = backup_payload(1).replace("268435456", "536870913");
        assert_eq!(
            build(&args("b", "backup"), over.as_bytes()).unwrap_err(),
            "backup-bad-part-size"
        );
    }

    #[test]
    fn migrate_snapshot_with_the_maximum_part_list_fits_the_multipart_body_cap() {
        // 3,000 realistic ~530-byte presigned URLs (the largest flavor's
        // overlay needs ~2,600) must fit the Edge's `migrate-snapshot` cap
        // (`MAX_MULTIPART_ORDER_BODY` = 2 MiB - 256).
        let url = format!("\"https://s3.hippius.com/{}\"", "x".repeat(505));
        let urls = vec![url; MAX_MULTIPART_PARTS].join(",");
        let payload = format!(
            r#"{{"vm_id":"tenant-1","node_id":"miner-a","part_size":536870912,
               "disk_part_urls":[{urls}],"state_put_url":"https://s3/state"}}"#
        );
        let bytes = build(&args("mig-snap", "migrate-snapshot"), payload.as_bytes()).unwrap();
        assert!(
            bytes.len() < 2 * 1024 * 1024 - 256,
            "body {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn backup_rejects_malformed_payloads() {
        let cases = [
            (
                backup_payload(MAX_MULTIPART_PARTS + 1),
                "backup-too-many-parts",
            ),
            (backup_payload(0), "backup-no-parts"),
            (
                backup_payload(1).replace("268435456", "1024"),
                "backup-bad-part-size",
            ),
            (
                backup_payload(1).replace("\"incremental\"", "\"diff\""),
                "backup-bad-kind",
            ),
            (
                backup_payload(1).replace("\"https://s3/state\"", "\"\""),
                "backup-missing-state-put-url",
            ),
            (
                backup_payload(1).replace("\"parent_run_id\":\"r1\",", ""),
                "backup-incremental-without-parent",
            ),
            (
                backup_payload(1).replace("\"r2\"", "\"R_2\""),
                "backup-bad-run-id",
            ),
        ];
        for (payload, want) in cases {
            assert_eq!(
                build(&args("b", "backup"), payload.as_bytes()).unwrap_err(),
                want
            );
        }
    }

    fn piece(url: &str, c: char, size: u64) -> String {
        format!(
            r#"{{"url":"{url}","sha256_hex":"{}","size":{size}}}"#,
            c.to_string().repeat(64)
        )
    }

    fn with_backup_chain(chain_json: &str) -> String {
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        base.replacen(
            "\"vm_id\": \"tenant-1\",",
            &format!("\"vm_id\": \"tenant-1\", \"backup_chain\": {chain_json},"),
            1,
        )
    }

    #[test]
    fn migrate_activate_carries_a_backup_chain() {
        use serde::Deserialize;

        let chain = format!(
            r#"{{"restore_id":"job-1","full":{},"incrementals":[{}],"state":{}}}"#,
            piece("https://s3/full", 'a', 100),
            piece("https://s3/inc1", 'b', 7),
            piece("https://s3/state", 'c', 1_048_576),
        );
        let bytes = build(
            &args("ord-act-c", "migrate-activate"),
            with_backup_chain(&chain).as_bytes(),
        )
        .unwrap();
        assert_canonical(&bytes).expect("canonical");

        // Mirrors `backup::restore::{RestoreChain, ChainPiece}`.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePiece {
            url: String,
            sha256_hex: String,
            size: u64,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireChain {
            restore_id: String,
            full: WirePiece,
            #[serde(default)]
            incrementals: Vec<WirePiece>,
            state: WirePiece,
        }
        #[derive(Deserialize)]
        struct WireActivate {
            backup_chain: WireChain,
        }
        #[derive(Deserialize)]
        struct WireBody {
            payload: WireActivate,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let chain = back.payload.backup_chain;
        assert_eq!(chain.restore_id, "job-1");
        assert_eq!(chain.full.url, "https://s3/full");
        assert_eq!(chain.full.size, 100);
        assert_eq!(chain.full.sha256_hex, "a".repeat(64));
        assert_eq!(chain.incrementals.len(), 1);
        assert_eq!(chain.incrementals[0].sha256_hex, "b".repeat(64));
        assert_eq!(chain.state.size, 1_048_576);
    }

    #[test]
    fn migrate_activate_without_a_chain_omits_the_key() {
        let bytes = build(
            &args("ord-act-1", "migrate-activate"),
            migrate_activate_payload(),
        )
        .unwrap();
        let needle = b"backup_chain";
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn migrate_activate_rejects_a_malformed_chain() {
        let ok = |c| piece("u", c, 1);
        let cases = [
            (
                format!(
                    r#"{{"restore_id":"j","full":{},"state":{}}}"#,
                    piece("u", 'z', 1),
                    ok('a')
                ),
                "backup-chain-piece-bad-sha256-hex",
            ),
            (
                format!(
                    r#"{{"restore_id":"j","full":{},"state":{}}}"#,
                    piece("u", 'a', 0),
                    ok('a')
                ),
                "backup-chain-piece-bad-size",
            ),
            (
                format!(r#"{{"restore_id":"j","full":{}}}"#, ok('a')),
                "backup-chain-piece-not-object",
            ),
            (
                format!(
                    r#"{{"restore_id":"","full":{},"state":{}}}"#,
                    ok('a'),
                    ok('a')
                ),
                "backup-chain-bad-restore-id",
            ),
            (
                format!(
                    r#"{{"restore_id":"j","full":{},"incrementals":[{}],"state":{}}}"#,
                    ok('a'),
                    vec![ok('b'); MAX_CHAIN_INCREMENTALS + 1].join(","),
                    ok('a')
                ),
                "backup-chain-too-long",
            ),
        ];
        for (chain, want) in cases {
            assert_eq!(
                build(
                    &args("x", "migrate-activate"),
                    with_backup_chain(&chain).as_bytes()
                )
                .unwrap_err(),
                want
            );
        }
    }

    #[test]
    fn a_maximal_backup_chain_fits_the_order_body_cap() {
        // MAX_CHAIN_INCREMENTALS realistic ~500-byte presigned GETs, plus
        // the boot-artifact URLs + a 4 KiB ticket, must fit the signed-order
        // cap (edge `MAX_MINER_ORDER_BODY` = 64 KiB - 256).
        use base64::Engine as _;
        let url = |i: usize| format!("https://s3.hippius.com/{i:04}{}", "x".repeat(470));
        let sha = "a".repeat(64);
        let p = |i: usize| {
            format!(
                r#"{{"url":"{}","sha256_hex":"{sha}","size":107374182400}}"#,
                url(i)
            )
        };
        let incs: Vec<String> = (1..=MAX_CHAIN_INCREMENTALS).map(p).collect();
        let ticket = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 4096]);
        let staged = |n: &str| format!(r#""{n}":{{"url":"{}","sha256_hex":"{sha}"}}"#, url(900));
        let payload = format!(
            r#"{{"vm_id":"tenant-1","get_url":"{}","state_get_url":"{}","new_gen":6,
               "ovmf_path":"/var/lib/hippius-miner/ovmf.fd",
               "kernel_path":"/var/lib/hippius-miner/staging/tenant-1/tenant.vmlinuz",
               "initrd_path":"/var/lib/hippius-miner/staging/tenant-1/tenant.initrd.img",
               "cmdline":"{}","luks_disk_path":"/var/lib/hippius-miner/overlay/tenant-1.img",
               "luks_disk_size_gb":10,"cpu_count":32,"memory_mb":131072,
               "cose_ticket":"{ticket}",
               "boot_artifacts":{{{},{},{},{}}},
               "backup_chain":{{"restore_id":"job-0123456789abcdef","full":{},
                                "incrementals":[{}],"state":{}}}}}"#,
            url(998),
            url(999),
            "c".repeat(1024),
            staged("kernel"),
            staged("initrd"),
            staged("rootfs_data"),
            staged("rootfs_hash"),
            p(0),
            incs.join(","),
            p(997)
        );
        let bytes = build(&args("act", "migrate-activate"), payload.as_bytes()).unwrap();
        assert!(bytes.len() < 64 * 1024 - 256, "body {} bytes", bytes.len());
    }

    // ── staged restore ──────────────────────────────────────────────

    const RID: &str = "0123456789abcdef0123456789abcdef";

    /// A `restore` stage payload whose full carries a part layout.
    fn restore_stage_payload() -> String {
        let a = "a".repeat(64);
        let full = format!(
            r#"{{"url":"https://s3/full","sha256_hex":"{a}","size":{},
                "part_size":536870912,"part_sha256_hex":["{a}","{b}"]}}"#,
            (512u64 << 20) + 1,
            b = "b".repeat(64)
        );
        format!(
            r#"{{"vm_id":"tenant-1","restore_id":"{RID}","op":"stage","disk_bytes":{},
               "streams":8,"chain":{{"restore_id":"{RID}","full":{full},
               "incrementals":[{}],"state":{}}}}}"#,
            (512u64 << 20) + 1,
            piece("https://s3/inc", 'c', 7),
            piece("https://s3/state", 'd', 1_048_576),
        )
    }

    /// Mirrors `backup::restore::ChainPiece` (with the part layout).
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WirePiece {
        url: String,
        sha256_hex: String,
        size: u64,
        #[serde(default)]
        part_size: u64,
        #[serde(default)]
        part_sha256_hex: Vec<String>,
    }

    /// Mirrors `backup::restore::RestoreChain`.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireChain {
        restore_id: String,
        full: WirePiece,
        #[serde(default)]
        incrementals: Vec<WirePiece>,
        state: WirePiece,
    }

    /// Mirrors `orders::types::RestoreOrder`.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireRestore {
        vm_id: String,
        restore_id: String,
        op: String,
        #[serde(default)]
        chain: Option<WireChain>,
        #[serde(default)]
        disk_bytes: u64,
        #[serde(default)]
        streams: Option<u8>,
    }

    #[derive(serde::Deserialize)]
    struct WireRestoreBody {
        kind: String,
        payload: WireRestore,
    }

    #[test]
    fn restore_stage_round_trips_through_a_mirror_of_the_miner_shape() {
        let bytes = build(&args("r-1", "restore"), restore_stage_payload().as_bytes()).unwrap();
        assert_canonical(&bytes).expect("canonical");
        let back: WireRestoreBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.kind, "restore");
        let p = back.payload;
        assert_eq!(
            (p.vm_id.as_str(), p.restore_id.as_str(), p.op.as_str()),
            ("tenant-1", RID, "stage")
        );
        assert_eq!(p.disk_bytes, (512 << 20) + 1);
        assert_eq!(p.streams, Some(8));
        let chain = p.chain.unwrap();
        assert_eq!(chain.restore_id, RID);
        assert_eq!(chain.full.url, "https://s3/full");
        assert_eq!(chain.full.sha256_hex, "a".repeat(64));
        assert_eq!(chain.full.size, (512 << 20) + 1);
        assert_eq!(chain.full.part_size, 512 << 20);
        assert_eq!(chain.full.part_sha256_hex, ["a".repeat(64), "b".repeat(64)]);
        assert_eq!(chain.incrementals.len(), 1);
        assert_eq!(chain.incrementals[0].part_size, 0, "no layout ⇒ no key");
        assert_eq!(chain.state.size, 1_048_576);
        // A piece without a layout emits neither key.
        for needle in [&b"part_size"[..], b"part_sha256_hex"] {
            let n = bytes.windows(needle.len()).filter(|w| *w == needle).count();
            assert_eq!(n, 1, "only the full carries a layout");
        }
    }

    #[test]
    fn restore_abort_and_reclaim_carry_only_the_id() {
        for op in ["abort", "reclaim"] {
            let json = format!(
                r#"{{"vm_id":"tenant-1","restore_id":"{RID}","op":"{op}","disk_bytes":0,"chain":null}}"#
            );
            let bytes = build(&args("r-2", "restore"), json.as_bytes()).unwrap();
            assert_canonical(&bytes).expect("canonical");
            let back: WireRestoreBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(back.payload.op, op);
            assert!(back.payload.chain.is_none());
            assert_eq!(back.payload.disk_bytes, 0);
            assert!(back.payload.streams.is_none());
        }
    }

    #[test]
    fn restore_rejects_a_malformed_order() {
        let stage = restore_stage_payload();
        let other = "fedcba9876543210fedcba9876543210";
        let cases = [
            (stage.replacen(RID, other, 1), "restore-id-mismatch"),
            (stage.replace(RID, &RID.to_uppercase()), "restore-bad-id"),
            (
                stage.replace(r#""op":"stage""#, r#""op":"swap""#),
                "restore-bad-op",
            ),
            (
                stage.replace(r#""op":"stage""#, r#""op":"abort""#),
                "restore-stray-fields",
            ),
            (
                stage.replace(r#""streams":8"#, r#""streams":0"#),
                "restore-bad-streams",
            ),
            (
                stage.replace(r#""disk_bytes":536870913,"#, ""),
                "restore-bad-disk-bytes",
            ),
            (
                stage.replace(r#","part_sha256_hex":["#, r#","part_sha256_hex":["00","#),
                "backup-chain-piece-bad-part-sha",
            ),
            (
                stage.replace(&format!(r#","{}"]"#, "b".repeat(64)), "]"),
                "backup-chain-piece-part-sha-count",
            ),
            (
                stage.replace(r#""part_size":536870912"#, r#""part_size":1024"#),
                "backup-chain-piece-bad-part-size",
            ),
            (
                format!(
                    r#"{{"vm_id":"tenant-1","restore_id":"{RID}","op":"stage","disk_bytes":1}}"#
                ),
                "restore-chain-missing",
            ),
        ];
        for (payload, want) in cases {
            assert_ne!(payload, stage, "{want}: the case must change the payload");
            assert_eq!(
                build(&args("r", "restore"), payload.as_bytes()).unwrap_err(),
                want
            );
        }
    }

    fn staged_activate(extra_edit: impl Fn(String) -> String) -> String {
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        let base = base
            .replace(r#""get_url": "https://s3.example/snap?sig=x","#, "")
            .replace(r#""state_get_url": "https://s3.example/state?sig=y","#, "")
            .replacen(
                "\"vm_id\": \"tenant-1\",",
                &format!("\"vm_id\": \"tenant-1\", \"staged_restore_id\": \"{RID}\","),
                1,
            );
        extra_edit(base)
    }

    #[test]
    fn migrate_activate_carries_a_staged_restore_id_and_no_urls() {
        #[derive(serde::Deserialize)]
        struct WireActivate {
            get_url: String,
            staged_restore_id: String,
            #[serde(default)]
            state_get_url: Option<String>,
            #[serde(default)]
            backup_chain: Option<serde::de::IgnoredAny>,
        }
        #[derive(serde::Deserialize)]
        struct WireBody {
            payload: WireActivate,
        }
        let payload = staged_activate(|s| s);
        let bytes = build(&args("act-s", "migrate-activate"), payload.as_bytes()).unwrap();
        assert_canonical(&bytes).expect("canonical");
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.payload.get_url, "", "the key stays, empty");
        assert_eq!(back.payload.staged_restore_id, RID);
        assert!(back.payload.state_get_url.is_none());
        assert!(back.payload.backup_chain.is_none());
        // Empty strings mean absent.
        let payload = staged_activate(|s| {
            s.replacen(
                "\"new_gen\"",
                "\"get_url\": \"\", \"state_get_url\": \"\", \"new_gen\"",
                1,
            )
        });
        build(&args("act-s", "migrate-activate"), payload.as_bytes()).unwrap();
        // Without it, the key is not on the wire.
        let plain = build(&args("act", "migrate-activate"), migrate_activate_payload()).unwrap();
        let needle = b"staged_restore_id";
        assert!(!plain.windows(needle.len()).any(|w| w == needle.as_slice()));
    }

    #[test]
    fn a_staged_restore_refuses_anything_to_download() {
        for (edit, want) in [
            (
                r#""get_url": "https://s3/x", "new_gen""#,
                "staged-restore-conflict",
            ),
            (
                r#""state_get_url": "https://s3/y", "new_gen""#,
                "staged-restore-conflict",
            ),
            (
                r#""backup_chain": {}, "new_gen""#,
                "staged-restore-conflict",
            ),
        ] {
            let payload = staged_activate(|s| s.replacen("\"new_gen\"", edit, 1));
            assert_eq!(
                build(&args("x", "migrate-activate"), payload.as_bytes()).unwrap_err(),
                want
            );
        }
        let payload = staged_activate(|s| s.replace(RID, "job-1"));
        assert_eq!(
            build(&args("x", "migrate-activate"), payload.as_bytes()).unwrap_err(),
            "bad-staged-restore-id"
        );
    }

    // ── customer-held keys: guardian_ep ────────────────────────────────

    const GUARDIAN_PK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// A split cmdline measuring `ep` — hex-encoded, as vali mints it.
    fn guardian_cmdline(ep: &str) -> String {
        format!(
            "console=hvc0 hippius.key_mode=split hippius.guardian_pk={GUARDIAN_PK} \
             hippius.guardian_ep={}",
            hex::encode(ep)
        )
    }

    /// `launch_payload()` with its cmdline replaced and `extra` JSON
    /// members appended.
    fn launch_json_with(cmdline: &str, extra: &str) -> String {
        let base = String::from_utf8(launch_payload().to_vec()).unwrap();
        let base = base.replace(
            "\"cmdline\": \"console=hvc0\"",
            &format!("\"cmdline\": \"{cmdline}\""),
        );
        base.replacen('{', &format!("{{ {extra}"), 1)
    }

    /// The FULL miner-agent `LaunchOrder` wire shape, `deny_unknown_fields`
    /// — the guardian key must decode into its own field, and no other key
    /// may appear.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireLaunchFull {
        #[allow(dead_code)]
        vm_id: String,
        #[allow(dead_code)]
        ovmf_path: String,
        #[allow(dead_code)]
        kernel_path: String,
        #[allow(dead_code)]
        initrd_path: String,
        cmdline: String,
        #[allow(dead_code)]
        luks_disk_path: String,
        #[allow(dead_code)]
        luks_disk_size_gb: u32,
        #[serde(default)]
        #[allow(dead_code)]
        data_disk_size_gb: u32,
        #[serde(default)]
        #[allow(dead_code)]
        rootfs_data_path: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        rootfs_hash_path: Option<String>,
        #[allow(dead_code)]
        cpu_count: u8,
        #[allow(dead_code)]
        memory_mb: u32,
        #[allow(dead_code)]
        cose_ticket: serde_bytes::ByteBuf,
        #[serde(default)]
        #[allow(dead_code)]
        require_existing_disks: bool,
        #[serde(default)]
        guardian_ep: Option<String>,
        #[serde(default)]
        net: Option<WireNet>,
    }

    /// The miner-agent's `NetSpec`, `deny_unknown_fields`.
    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct WireNet {
        #[serde(default)]
        cap_mbps: Option<u32>,
        #[serde(default)]
        isolate: bool,
    }

    #[derive(serde::Deserialize)]
    struct WireLaunchBody {
        payload: WireLaunchFull,
    }

    #[test]
    fn launch_carries_guardian_ep_into_the_miner_shape() {
        let ep = "100.64.1.2:7443";
        let json = launch_json_with(
            &guardian_cmdline(ep),
            &format!("\"guardian_ep\": \"{ep}\","),
        );
        let bytes = build(&args("g", "launch"), json.as_bytes()).unwrap();
        assert_canonical(&bytes).unwrap();
        let back: WireLaunchBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.payload.guardian_ep.as_deref(), Some(ep));
        assert_eq!(back.payload.cmdline, guardian_cmdline(ep));
    }

    /// H1b: the order's plain endpoint is checked against the DECODED
    /// token — including endpoints that spell cloud-init's `cc:` in the
    /// clear — and never against the raw hex.
    #[test]
    fn the_order_endpoint_is_compared_with_the_decoded_token() {
        for ep in ["guardian.example.cc:443", "[2001:db8::cc:1]:443"] {
            let json = launch_json_with(
                &guardian_cmdline(ep),
                &format!("\"guardian_ep\": \"{ep}\","),
            );
            let bytes = build(&args("g", "launch"), json.as_bytes()).unwrap();
            let back: WireLaunchBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(back.payload.guardian_ep.as_deref(), Some(ep));
            assert!(!back.payload.cmdline.contains("cc:"));
        }
        let ep = "100.64.1.2:7443";
        let tok = hex::encode(ep);
        let plain_cmdline = format!(
            "console=hvc0 hippius.key_mode=split hippius.guardian_pk={GUARDIAN_PK} \
             hippius.guardian_ep={ep}"
        );
        for (cmdline, order_ep, want) in [
            // The order carrying the raw token is no endpoint.
            (guardian_cmdline(ep), tok.clone(), "bad-guardian-ep"),
            // A cmdline measuring the plain (pre-H1b) spelling.
            (plain_cmdline, ep.to_string(), "bad-guardian-cmdline"),
            // Uppercase hex: a second spelling of the token.
            (
                guardian_cmdline(ep).replace(&tok, &tok.to_ascii_uppercase()),
                ep.to_string(),
                "bad-guardian-cmdline",
            ),
        ] {
            let json = launch_json_with(&cmdline, &format!("\"guardian_ep\": \"{order_ep}\","));
            assert_eq!(
                build(&args("g", "launch"), json.as_bytes()).unwrap_err(),
                want,
                "{order_ep}"
            );
        }
    }

    #[test]
    fn an_m0_launch_is_byte_identical_with_or_without_a_null_guardian_ep() {
        let plain = build(&args("g", "launch"), launch_payload()).unwrap();
        assert!(!launch_payload_has_key(&plain, "guardian_ep"));
        let null = launch_json_with("console=hvc0", "\"guardian_ep\": null,");
        assert_eq!(build(&args("g", "launch"), null.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn a_launch_guardian_ep_must_match_the_measured_token() {
        let ep = "guardian.example.com:7443";
        let cases: [(String, String, &str); 7] = [
            // Non-canonical spellings.
            (
                guardian_cmdline(ep),
                "\"guardian_ep\": \"GUARDIAN.example.com:7443\",".into(),
                "bad-guardian-ep",
            ),
            (
                guardian_cmdline(ep),
                "\"guardian_ep\": \"guardian.example.com:07443\",".into(),
                "bad-guardian-ep",
            ),
            (
                guardian_cmdline(ep),
                "\"guardian_ep\": 7443,".into(),
                "bad-guardian-ep",
            ),
            // Another guardian than the measured one.
            (
                guardian_cmdline(ep),
                "\"guardian_ep\": \"guardian.example.org:7443\",".into(),
                "guardian-ep-mismatch",
            ),
            // A customer-keys cmdline whose endpoint the bridge would drop.
            (guardian_cmdline(ep), String::new(), "guardian-ep-missing"),
            // An endpoint for an M0 VM.
            (
                "console=hvc0".into(),
                format!("\"guardian_ep\": \"{ep}\","),
                "guardian-ep-orphan",
            ),
            // A cmdline the guardian grammar refuses.
            (
                format!("{} hippius.key_mode=split", guardian_cmdline(ep)),
                format!("\"guardian_ep\": \"{ep}\","),
                "bad-guardian-cmdline",
            ),
        ];
        for (cmdline, extra, want) in cases {
            let json = launch_json_with(&cmdline, &extra);
            assert_eq!(
                build(&args("g", "launch"), json.as_bytes()).unwrap_err(),
                want,
                "{extra}"
            );
        }
    }

    #[test]
    fn migrate_activate_carries_guardian_ep_and_checks_it() {
        let ep = "[2001:db8::1]:7443";
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        let cmd = format!("ro hippius.vm_generation=6 {}", guardian_cmdline(ep));
        let with = base
            .replace(
                "\"cmdline\": \"ro hippius.vm_generation=6\"",
                &format!("\"cmdline\": \"{cmd}\""),
            )
            .replacen('{', &format!("{{ \"guardian_ep\": \"{ep}\","), 1);
        let bytes = build(&args("a", "migrate-activate"), with.as_bytes()).unwrap();
        assert_canonical(&bytes).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(top) = v else { panic!() };
        let Some((_, Value::Map(payload))) =
            top.iter().find(|(k, _)| k.as_text() == Some("payload"))
        else {
            panic!()
        };
        let got = payload
            .iter()
            .find(|(k, _)| k.as_text() == Some("guardian_ep"))
            .and_then(|(_, v)| v.as_text());
        assert_eq!(got, Some(ep));
        // Absent on an M0 activation (byte-stable), refused when dropped.
        let plain = build(&args("a", "migrate-activate"), migrate_activate_payload()).unwrap();
        assert!(!String::from_utf8_lossy(&plain).contains("guardian_ep"));
        let dropped = base.replace(
            "\"cmdline\": \"ro hippius.vm_generation=6\"",
            &format!("\"cmdline\": \"{cmd}\""),
        );
        assert_eq!(
            build(&args("a", "migrate-activate"), dropped.as_bytes()).unwrap_err(),
            "guardian-ep-missing"
        );
    }

    #[test]
    fn launch_carries_net_into_the_miner_shape() {
        let decode = |extra: &str| {
            let json = launch_json_with("console=hvc0", extra);
            let bytes = build(&args("n", "launch"), json.as_bytes()).unwrap();
            assert_canonical(&bytes).unwrap();
            let back: WireLaunchBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            (bytes, back.payload.net)
        };
        let (_, net) = decode("\"net\": {\"cap_mbps\": 250, \"isolate\": true},");
        assert_eq!(
            net,
            Some(WireNet {
                cap_mbps: Some(250),
                isolate: true
            })
        );
        // Defaults are not encoded, as the miner's serde would not.
        let (bytes, net) = decode("\"net\": {\"cap_mbps\": null, \"isolate\": false},");
        assert_eq!(
            net,
            Some(WireNet {
                cap_mbps: None,
                isolate: false
            })
        );
        for key in [&b"isolate"[..], b"cap_mbps"] {
            assert!(!bytes.windows(key.len()).any(|w| w == key));
        }
    }

    #[test]
    fn a_launch_without_net_is_byte_identical() {
        let plain = build(&args("g", "launch"), launch_payload()).unwrap();
        assert!(!launch_payload_has_key(&plain, "net"));
        let null = launch_json_with("console=hvc0", "\"net\": null,");
        assert_eq!(build(&args("g", "launch"), null.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn a_bad_net_is_refused() {
        for (extra, want) in [
            ("\"net\": 1,", "bad-net"),
            ("\"net\": {\"cap_mbps\": 1, \"vlan\": 2},", "bad-net"),
            ("\"net\": {\"isolate\": \"yes\"},", "bad-net"),
            ("\"net\": {\"cap_mbps\": 0},", "bad-net-cap"),
            ("\"net\": {\"cap_mbps\": 100001},", "bad-net-cap"),
            ("\"net\": {\"cap_mbps\": 2.5},", "bad-net-cap"),
            ("\"net\": {\"cap_mbps\": -1},", "bad-net-cap"),
        ] {
            let json = launch_json_with("console=hvc0", extra);
            assert_eq!(
                build(&args("n", "launch"), json.as_bytes()).unwrap_err(),
                want,
                "{extra}"
            );
        }
    }

    #[test]
    fn migrate_activate_carries_net() {
        let base = String::from_utf8(migrate_activate_payload().to_vec()).unwrap();
        let with = base.replacen('{', "{ \"net\": {\"cap_mbps\": 100, \"isolate\": true},", 1);
        let bytes = build(&args("a", "migrate-activate"), with.as_bytes()).unwrap();
        assert_canonical(&bytes).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(top) = v else { panic!() };
        let Some((_, Value::Map(payload))) =
            top.iter().find(|(k, _)| k.as_text() == Some("payload"))
        else {
            panic!()
        };
        let net = payload
            .iter()
            .find(|(k, _)| k.as_text() == Some("net"))
            .map(|(_, v)| v.clone());
        assert_eq!(
            net,
            // Canonical order: the shorter key first.
            Some(Value::Map(vec![
                (Value::Text("isolate".into()), Value::Bool(true)),
                (Value::Text("cap_mbps".into()), Value::Integer(100.into())),
            ]))
        );
        let plain = build(&args("a", "migrate-activate"), migrate_activate_payload()).unwrap();
        assert!(!launch_payload_has_key(&plain, "net"));
    }

    fn net_policy_vector() -> Json {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/net_policy_v1.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn net_policy_args(v: &Json) -> EncodeOrderArgs {
        EncodeOrderArgs {
            order_id: v["order_id"].as_str().unwrap().to_string(),
            kind: "net-policy".to_string(),
            target_miner_id: v["target_miner_id"].as_str().unwrap().to_string(),
            issued_at_unix: v["issued_at_unix"].as_u64().unwrap(),
        }
    }

    fn net_policy_payload(mutate: impl FnOnce(&mut serde_json::Map<String, Json>)) -> Vec<u8> {
        let mut payload = net_policy_vector()["cases"][0]["payload"]
            .as_object()
            .unwrap()
            .clone();
        mutate(&mut payload);
        serde_json::to_vec(&payload).unwrap()
    }

    /// The shared vectors the edge-gateway and miner-agent tests consume:
    /// a change here is a wire change on all three.
    #[test]
    fn net_policy_matches_the_shared_vectors() {
        let v = net_policy_vector();
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let payload = serde_json::to_vec(&case["payload"]).unwrap();
            let body = build(&net_policy_args(&v), &payload).unwrap();
            assert_canonical(&body).unwrap();
            assert_eq!(
                hex::encode(&body),
                case["body_hex"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                net_policy_digest(&payload).unwrap(),
                case["content_sha256"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn net_policy_digest_ignores_only_the_expiry() {
        let base = net_policy_digest(&net_policy_payload(|_| {})).unwrap();
        let renewed = net_policy_payload(|p| {
            p.insert("not_after_unix".into(), Json::from(1_770_100_000u64));
        });
        assert_eq!(net_policy_digest(&renewed).unwrap(), base);
        let other = net_policy_payload(|p| {
            p.insert("enforce".into(), Json::Bool(true));
        });
        assert_ne!(net_policy_digest(&other).unwrap(), base);
    }

    #[test]
    fn net_policy_omits_an_absent_or_null_uplink_hint() {
        let v = net_policy_vector();
        let absent = build(
            &net_policy_args(&v),
            &net_policy_payload(|p| {
                p.remove("uplink_hint");
            }),
        )
        .unwrap();
        let null = build(
            &net_policy_args(&v),
            &net_policy_payload(|p| {
                p.insert("uplink_hint".into(), Json::Null);
            }),
        )
        .unwrap();
        assert_eq!(absent, null);
        assert!(!absent.windows(11).any(|w| w == b"uplink_hint"));
    }

    #[test]
    fn net_policy_refuses_rather_than_drops() {
        let v = net_policy_vector();
        let refused = |mutate: &dyn Fn(&mut serde_json::Map<String, Json>)| {
            build(&net_policy_args(&v), &net_policy_payload(mutate)).unwrap_err()
        };
        assert_eq!(
            refused(&|p| {
                p.insert("vm_id".into(), Json::from("tenant-1"));
            }),
            "net-policy-unknown-field"
        );
        assert_eq!(
            refused(&|p| {
                p.remove("revision");
            }),
            "net-policy-bad-uint"
        );
        assert_eq!(
            refused(&|p| {
                p.remove("vm_caps");
            }),
            "net-policy-bad-vm-caps"
        );
        assert_eq!(
            refused(&|p| {
                p.insert("mode".into(), Json::from("open"));
            }),
            "net-policy-bad-enum"
        );
        assert_eq!(
            refused(&|p| {
                p.insert(
                    "infra".into(),
                    serde_json::json!([{"ip": "198.51.100.7", "proto": "udp", "port": 51820, "x": 1}]),
                );
            }),
            "net-policy-bad-endpoint"
        );
        assert_eq!(
            refused(&|p| {
                p.insert(
                    "nb_control".into(),
                    serde_json::json!([{"ip": "192.0.2.10", "proto": "icmp", "port": 1}]),
                );
            }),
            "net-policy-bad-endpoint"
        );
        assert_eq!(
            refused(&|p| {
                p.insert("dns_limit_pps".into(), Json::from(u64::from(u32::MAX) + 1));
            }),
            "net-policy-bad-uint"
        );
    }

    fn power_policy_vector() -> Json {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/power_policy_v1.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn power_policy_bodies_match_the_shared_vector() {
        let v = power_policy_vector();
        for case in v["cases"].as_array().unwrap() {
            let args = EncodeOrderArgs {
                order_id: v["order_id"].as_str().unwrap().to_string(),
                kind: case["kind"].as_str().unwrap().to_string(),
                target_miner_id: v["target_miner_id"].as_str().unwrap().to_string(),
                issued_at_unix: v["issued_at_unix"].as_u64().unwrap(),
            };
            let payload = serde_json::to_vec(&case["payload"]).unwrap();
            let bytes = build(&args, &payload).unwrap();
            assert_canonical(&bytes).unwrap();
            assert_eq!(
                hex::encode(&bytes),
                case["body_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn a_launch_carries_on_guest_poweroff_only_when_set() {
        let plain = build(&args("g", "launch"), launch_payload()).unwrap();
        assert!(!launch_payload_has_key(&plain, "on_guest_poweroff"));
        let null = launch_json_with("console=hvc0", "\"on_guest_poweroff\": null,");
        assert_eq!(build(&args("g", "launch"), null.as_bytes()).unwrap(), plain);
        for policy in ["stop", "restart"] {
            let json = launch_json_with(
                "console=hvc0",
                &format!("\"on_guest_poweroff\": \"{policy}\","),
            );
            let bytes = build(&args("g", "launch"), json.as_bytes()).unwrap();
            assert_canonical(&bytes).unwrap();
            let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            let Value::Map(top) = v else { panic!() };
            let Some((_, Value::Map(payload))) =
                top.iter().find(|(k, _)| k.as_text() == Some("payload"))
            else {
                panic!("no payload");
            };
            let got = payload
                .iter()
                .find(|(k, _)| k.as_text() == Some("on_guest_poweroff"))
                .and_then(|(_, v)| v.as_text());
            assert_eq!(got, Some(policy));
        }
    }

    #[test]
    fn a_bad_on_guest_poweroff_is_refused_never_dropped() {
        for extra in [
            "\"on_guest_poweroff\": \"Stop\",",
            "\"on_guest_poweroff\": \"halt\",",
            "\"on_guest_poweroff\": true,",
        ] {
            let json = launch_json_with("console=hvc0", extra);
            assert_eq!(
                build(&args("g", "launch"), json.as_bytes()).unwrap_err(),
                "bad-on-guest-poweroff",
                "{extra}"
            );
        }
        for (payload, want) in [
            (&br#"{"vm_id":"t"}"#[..], "missing-on-guest-poweroff"),
            (
                br#"{"vm_id":"t","on_guest_poweroff":null}"#,
                "missing-on-guest-poweroff",
            ),
            (
                br#"{"vm_id":"t","on_guest_poweroff":"off"}"#,
                "bad-on-guest-poweroff",
            ),
            (br#"{"on_guest_poweroff":"stop"}"#, "missing-vm-id"),
            (
                br#"{"vm_id":"t","on_guest_poweroff":"stop","graceful":true}"#,
                "power-policy-unknown-field",
            ),
        ] {
            assert_eq!(
                build(&args("p", "power-policy"), payload).unwrap_err(),
                want,
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }
}
