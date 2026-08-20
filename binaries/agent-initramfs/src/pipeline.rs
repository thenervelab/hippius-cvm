//! Stage orchestration for the §21 boot pipeline.
//!
//! Each [`Stage`] is a pure function in [`crate::stages`] that returns
//! `Result<_, AgentError>`. [`run`] composes them in §21 order; the
//! first `Err` aborts the boot (fail-closed — never `switch_root` with
//! a partially-released VM).
//!
//! ## Ownership / secret discipline (§20)
//!
//! The pipeline ends in `switch_root` → `execve(2)`, which does **not**
//! run Rust destructors. Therefore [`Zeroizing`] only fires if drops
//! happen **before** the pivot. [`run`] enforces this by moving each
//! secret-bearing value into the stage that consumes it, by value:
//!
//! - `keys: Ephemeral` is moved into [`crate::stages::verify`] — the
//!   X25519 scalar drops + wipes immediately after the §6/§7/§19/§20
//!   binding gate.
//! - `secrets` is destructured into `luks` / `userdata`; each
//!   [`Zeroizing<Vec<u8>>`] is moved into its consumer
//!   ([`crate::stages::unlock`] / [`crate::stages::seed`]) which then
//!   drops them at the end of its own scope.
//!
//! By the time control reaches [`crate::stages::switch_root::pivot`]
//! no secret-bearing value is live. Future PRs MUST preserve this:
//! adding a by-reference stage signature (or holding `secrets` past
//! the seed stage) silently undoes the wipe.
//!
//! ## Pipeline status
//!
//! As of PR-E1.5 every §21 stage is real — `LoadTicket`, `Keygen`,
//! `NonceFetch`, `SnpReport`, `KbsRelease`, `VerifyRelease`,
//! `LuksUnlock`, `NoCloudSeed` and `SwitchRoot`. The pipeline runs
//! end-to-end: on the happy path [`run`] does not return — the
//! `SwitchRoot` stage `execve`s the guest init. `AgentError::Todo` is
//! retained only as an unused sentinel (no stage emits it). The
//! compile-gate test
//! ([`tests/compile_gate.rs`](../../tests/compile_gate.rs)) pins the
//! full §21 order via [`SECTION_21_ORDER`].
//!
//! ## Error-variant policy (no plaintext in `Display`)
//!
//! [`AgentError`] variants MUST stay structurally secret-free: a
//! variant carrying `Vec<u8>` of unwrapped user-data, or a stringified
//! signed-response body, would leak through `Display` /
//! [`crate::log_fatal`]. Every variant carries only a [`Stage`] enum
//! tag, a closed-vocabulary `&'static str` classifier (whose `Display`
//! renders the fixed tag, never the inner string), or a wrapped
//! [`hippius_guest::GuestError`] (whose own Display is audited not to
//! include plaintext).

use crate::stages::kbs_client::HttpClient;
use crate::stages::seed::SeedWriter;
use crate::stages::snp_report::SnpReportProvider;
use crate::stages::switch_root::{PivotConfig, PivotMode, RootfsPivot};
use crate::stages::unlock::LuksUnlocker;
use crate::stages::verity::RootfsVerity;
use crate::stages::{
    kbs_client, keygen, network, seed, snp_report, switch_root, ticket, unlock, verify, verity,
};
use hippius_guest::UnwrappedSecrets;
use thiserror::Error;

/// Identifier for each §21 pipeline step. Used by [`AgentError::Todo`]
/// so the compile-gate test (and any future log) can pin **which**
/// stage stubbed out, without ever surfacing secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Load the COSE_Sign1 `OrderTicket` (§6) the L1 minted (delivered
    /// to the guest via the miner-supplied UKI input channel — exact
    /// source pinned in PR-E1.2).
    LoadTicket,
    /// X25519 ephemeral keygen inside mlocked RAM (§20).
    Keygen,
    /// Fetch a fresh single-use KBS nonce (POST `/v1/kbs/nonce`).
    NonceFetch,
    /// `SNP_GET_REPORT` ioctl on `/dev/sev-guest` with
    /// `REPORT_DATA = nonce ‖ pubkey` (§20 exact layout).
    SnpReport,
    /// POST `/v1/kbs/release` (`{cose_ticket, snp_report, nonce}`) and
    /// receive a `SignedResponse`.
    KbsRelease,
    /// [`hippius_guest::verify_and_unwrap_release`] — §6/§7/§19/§20
    /// binding gate. The real library performs `verify_strict` on the
    /// KBS Ed25519 signature + every field-binding check before HPKE
    /// unwrap (see `hippius-guest/src/release.rs`). Skeleton stub here
    /// is reached only after every preceding stage succeeds; PR-E1.3
    /// wires the real call.
    VerifyRelease,
    /// `cryptsetup luksOpen` on the per-VM confidential volume.
    LuksUnlock,
    /// `veritysetup open` on the read-only dm-verity rootfs — creates
    /// `/dev/mapper/hippius-rootfs` from the data + hash backing
    /// devices, integrity-anchored by the measured `dm-verity.root=`
    /// cmdline token. Must run BEFORE [`Self::SwitchRoot`] mounts it.
    OpenRootfsVerity,
    /// Materialize user-data as a NoCloud seed on tmpfs (§20:
    /// datasource list pinned to `[NoCloud, None]`).
    NoCloudSeed,
    /// `pivot_root(2)` / `switch_root` into the dm-verity rootfs
    /// (§11) — never returns on the happy path.
    SwitchRoot,
}

/// Canonical §21 order. Pinned as a `const` so a regression in
/// [`run`] that drops or reorders a stage is caught by
/// `compile_gate.rs` at test time. Length = 10 stages; if a real stage
/// is genuinely added or removed, update this array AND
/// `compile_gate.rs::pipeline_pins_section_21_order` in the same PR.
pub const SECTION_21_ORDER: [Stage; 10] = [
    Stage::LoadTicket,
    Stage::Keygen,
    Stage::NonceFetch,
    Stage::SnpReport,
    Stage::KbsRelease,
    Stage::VerifyRelease,
    Stage::LuksUnlock,
    Stage::OpenRootfsVerity,
    Stage::NoCloudSeed,
    Stage::SwitchRoot,
];

#[derive(Debug, Error)]
pub enum AgentError {
    /// PR-E1.1 sentinel: the named stage is not yet implemented. Each
    /// follow-up PR (E1.2 … E1.5) replaces one or more `Todo` returns
    /// with a real implementation.
    ///
    /// **Display is a static string** — the `{0:?}` is on the
    /// [`Stage`] enum, which has a finite set of variants that all
    /// render to short identifiers (`Keygen`, `LoadTicket`, …). No
    /// secret-bearing payload can splice through.
    #[error("stage not implemented (skeleton): {0:?}")]
    Todo(Stage),

    /// `hippius-guest` rejected the KBS response (signature, binding,
    /// HPKE unwrap, or user-data digest). Fail-closed (§6/§7/§19/§20).
    ///
    /// `Display` is the fixed tag `"release-rejected"` — it does NOT
    /// interpolate the inner `GuestError`, whose own `Display`
    /// (`GuestError::Binding`) carries `expected` / `got` strings such
    /// as vm_id / tenant_id / vault paths. The wrapped error stays
    /// reachable via the `Error::source` chain for a debugger, but can
    /// never splice into a log line through `{err}`.
    #[error("release-rejected")]
    Guest(#[from] hippius_guest::GuestError),

    /// `/dev/sev-guest` ioctl path failed (PR-E1.2). The payload is a
    /// `&'static str` from the closed
    /// [`crate::stages::snp_ioctl::cat`] vocabulary — open-failed /
    /// ioctl-failed / short-report. The `Display` impl emits a fixed
    /// "snp-device-failed" tag (no `{0}` interpolation) so the §20
    /// "no plaintext to logs" discipline is preserved even on an
    /// accidental `eprintln!("{err}")`; [`Self::class`] returns the
    /// same fixed tag for the audit sink.
    #[error("snp-device-failed")]
    SnpDevice(&'static str),

    /// PR-E1.3: the COSE_Sign1 `OrderTicket` could not be loaded or
    /// decoded. The `&'static str` is a closed-vocabulary classifier
    /// (`read` / `cose-parse` / `order-decode` / …); `Display` emits
    /// only the fixed "ticket-failed" tag — no `{0}` interpolation, so
    /// no tenant identifier from the ticket can leak.
    #[error("ticket-failed")]
    Ticket(&'static str),

    /// PR-E1.3: the KBS HTTP exchange failed — transport, a strict
    /// timeout, an unexpected status, or a malformed response. The
    /// `&'static str` is a closed-vocabulary classifier; `Display`
    /// emits only "kbs-failed" so no URL / header / body context can
    /// leak through a log line (§20 review focus).
    #[error("kbs-failed")]
    Kbs(&'static str),

    /// PR-E1.3: the KBS returned a **signed denial** (HTTP 403). This
    /// is terminal — the agent aborts and the VM powers off; the
    /// ticket is nonce-bound to this single exchange, so there is
    /// nothing to retry. Distinct class from [`Self::Kbs`] so the
    /// runbook can tell a deliberate denial from a transport failure.
    #[error("kbs-denial")]
    KbsDenial,

    /// PR-E1.3: the verify stage could not even assemble the binding
    /// check — an un-decodable UKI-pinned KBS key, or a ticket digest
    /// of the wrong length. Distinct from [`Self::Guest`], which is the
    /// binding check running and rejecting.
    #[error("verify-failed")]
    Verify(&'static str),

    /// PR-E1.4: the LUKS unlock stage failed — the backing device
    /// could not be resolved (`hippius.luks_device=` absent), or
    /// `libcryptsetup` rejected the device / header / released key.
    /// The `&'static str` is a closed-vocabulary classifier
    /// (`device-missing` / `crypt-init` / `header-load` / `activate` /
    /// …); `Display` emits only the fixed "luks-failed" tag — no `{0}`
    /// interpolation, so neither the device path nor any key context
    /// can leak through a log line (§20). Fail-closed and terminal:
    /// there is no retry and no alternative-key fallback (§14).
    #[error("luks-failed")]
    Luks(&'static str),

    /// PR-E1.5: the NoCloud-seed stage failed — the target directory is
    /// not memory-backed (`not-tmpfs`), or a `mkdir` / file write
    /// failed. `Display` emits only the fixed `"seed-failed"` tag, so
    /// neither the seed path nor a byte of the cloud-init plaintext can
    /// leak through a log line (§20). Fail-closed.
    #[error("seed-failed")]
    Seed(&'static str),

    /// PR-E1.5: the `switch_root` pivot failed — the verity rootfs
    /// could not be mounted, a virtual-fs move failed, or the
    /// `chroot` / `execv` failed. `Display` emits only the fixed
    /// `"switch-root-failed"` tag. Fail-closed and terminal (§14).
    #[error("switch-root-failed")]
    SwitchRoot(&'static str),

    /// PR-E1.5: a §20 production-hardening assertion failed — the
    /// measured kernel command line carries a debug shell, a
    /// `crashkernel=` reservation, no `panic=`, or no `ds=nocloud`
    /// pin; or the serial-console suppression / poweroff syscall
    /// failed. `Display` emits only the fixed `"hardening-failed"`
    /// tag. Fail-closed.
    #[error("hardening-failed")]
    Hardening(&'static str),

    /// PR-E1.5: the §24/§25 end-of-life path hit an error
    /// (`encode` of the stopped-ack, `luks-close`, …). `Display`
    /// emits only the fixed `"eol-failed"` tag. Note the EOL sequence
    /// itself is fail-closed-best-effort — most EOL step failures are
    /// swallowed and never become this error (see
    /// [`crate::stages::eol`]).
    #[error("eol-failed")]
    Eol(&'static str),

    /// Phase A close: the dm-verity rootfs open stage failed —
    /// `dm-verity.root=` could not be parsed, the data / hash backing
    /// devices are missing, or `libcryptsetup`'s
    /// `crypt_activate_by_volume_key(CRYPT_VERITY, …)` was rejected
    /// by the kernel. `&'static str` is a closed-vocabulary classifier
    /// (`cmdline-read` / `root-missing` / `root-hex` / `init` /
    /// `header-load` / `activate`). `Display` emits only the fixed
    /// `"verity-failed"` tag — neither the device path nor the root
    /// hash bytes leak through a log line (§20). Fail-closed.
    #[error("verity-failed")]
    Verity(&'static str),

    /// PR-#194: in-initramfs network bring-up failed — no eth0
    /// appeared after `init_module`, the link could not be set up,
    /// the DHCP exchange timed out / malformed, the lease could not
    /// be applied to the interface, or `/etc/resolv.conf` could not
    /// be written. The `&'static str` is a closed-vocabulary
    /// classifier (`no-interface` / `link-up` / `dhcp-discover` /
    /// `dhcp-no-offer` / `apply-lease` / `resolv-write` / …);
    /// `Display` emits only the fixed `"network-failed"` tag.
    ///
    /// Distinct from [`Self::Kbs`] (which classifies a KBS HTTP
    /// failure) so the runbook can tell "the interface never came
    /// up" from "the interface is up but the KBS hostname did not
    /// resolve / the connect was refused". Fail-closed and terminal.
    #[error("network-failed")]
    Network(&'static str),
}

impl AgentError {
    /// Static, plaintext-free classification used by
    /// [`crate::log_fatal`]. NEVER touches an error's `Display` —
    /// keeps the §20 "no plaintext to logs" contract structural.
    pub fn class(&self) -> &'static str {
        match self {
            AgentError::Todo(_) => "stage-not-implemented",
            AgentError::Guest(_) => "release-rejected",
            AgentError::SnpDevice(_) => "snp-device-failed",
            AgentError::Ticket(_) => "ticket-failed",
            AgentError::Kbs(_) => "kbs-failed",
            AgentError::KbsDenial => "kbs-denial",
            AgentError::Verify(_) => "verify-failed",
            AgentError::Luks(_) => "luks-failed",
            AgentError::Seed(_) => "seed-failed",
            AgentError::SwitchRoot(_) => "switch-root-failed",
            AgentError::Hardening(_) => "hardening-failed",
            AgentError::Eol(_) => "eol-failed",
            AgentError::Network(_) => "network-failed",
            AgentError::Verity(_) => "verity-failed",
        }
    }

    /// The closed-vocabulary inner sub-classifier for variants that
    /// carry one. `None` for variants without inner detail (just
    /// `KbsDenial` today). The fail-closed path uses this to surface
    /// `"family:sub-class"` on serial — `"network-failed:netlink-deserialize"`
    /// rather than the family-only collapse that hid every race-window
    /// sub-class during #200 / #202 debugging.
    ///
    /// §20 plaintext-free invariant preserved: every returned `&str`
    /// is a compile-time literal embedded in this binary, never an
    /// error's `Display` output.
    pub fn sub_class(&self) -> Option<&'static str> {
        match self {
            AgentError::SnpDevice(s)
            | AgentError::Ticket(s)
            | AgentError::Kbs(s)
            | AgentError::Verify(s)
            | AgentError::Luks(s)
            | AgentError::Seed(s)
            | AgentError::SwitchRoot(s)
            | AgentError::Hardening(s)
            | AgentError::Eol(s)
            | AgentError::Network(s)
            | AgentError::Verity(s) => Some(*s),
            // `Todo(Stage)` and `Guest(GuestError)` carry non-`&str`
            // payloads (a `Stage` enum and a domain-error type
            // respectively). Their family name from `class()` already
            // narrows triage; surfacing the inner payload here would
            // need either a `Display` interpolation (§20 violation —
            // GuestError carries vm_id / vault path strings) or a
            // hand-rolled per-variant mapping (not worth the LOC for
            // two variants that almost never fire in production).
            // `KbsDenial` is a unit variant — no sub-class at all.
            AgentError::Todo(_) | AgentError::Guest(_) | AgentError::KbsDenial => None,
        }
    }
}

/// Runtime configuration assembled from `/proc/cmdline` + UKI-embedded
/// constants. PR-E1.3 resolves `kbs_base_url` from the kernel command
/// line (see [`kbs_client::resolve_kbs_url`], applied by [`crate::main`]);
/// the remaining fields are still skeleton defaults pending a later
/// PR's full parser.
///
/// Note the absence of any `/dev/sev-guest` path: PR-E1.2 routes the
/// SNP report through [`SnpReportProvider`] (see
/// [`crate::stages::snp_report`]) and the real
/// [`crate::stages::snp_ioctl::SevGuestProvider`] opens the device by
/// the kernel-fixed name — no `Config::sev_guest_dev` field.
/// Which boot-handoff path the §21 pipeline takes — the choice is
/// surfaced on `/proc/cmdline` as `hippius.handoff=<value>`, which is
/// folded into the launch digest so a tampered miner cannot flip the
/// path.
///
///   - `ManagedRootfs` (legacy): activate the §F dm-verity rootfs and
///     pivot into Hippius's measured Debian runtime. The path every
///     PR through #256 ships.
///   - `TenantLuks` (#257 BYO base-OS, default going forward): skip
///     verity entirely; the per-VM LUKS volume IS the tenant's
///     vanilla cloud-image rootfs. Pivot mounts it RW, bind-mounts
///     Hippius's kernel-modules tree into it, then `execv`s the
///     tenant's `/sbin/init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandoffMode {
    /// Legacy §F managed-rootfs path. The current crate default — left
    /// as the default so existing tests and the `Config::default()`
    /// surface keep their established shape; production main.rs
    /// overrides this from the measured `hippius.handoff=` cmdline
    /// token (default `tenant-luks`).
    #[default]
    ManagedRootfs,
    /// #257 BYO base-OS — tenant LUKS volume is the rootfs.
    TenantLuks,
}

#[derive(Debug, Default, Clone)]
pub struct Config {
    /// Path the initramfs reads the COSE_Sign1 ticket from (see
    /// [`crate::stages::ticket`]).
    pub ticket_path: String,
    /// HTTPS base URL for the KBS, reached through Guardian → Edge GW.
    pub kbs_base_url: String,
    /// Device node for the per-VM LUKS volume.
    pub luks_device: String,
    /// Mount point where the NoCloud tmpfs seed is materialized.
    pub nocloud_tmpfs_dir: String,
    /// Which boot-handoff path to take — `ManagedRootfs` or
    /// `TenantLuks`. See [`HandoffMode`].
    pub handoff: HandoffMode,
    /// Hippius kernel release (= `uname(2).release`) the agent is
    /// running on. Used by the `TenantLuks` pivot to bind-mount
    /// `/lib/modules/<release>` into the tenant rootfs so the tenant
    /// can `modprobe` modules of the running kernel. Empty in
    /// `ManagedRootfs` mode (the §F image bundles its own matching
    /// modules tree).
    pub kernel_release: String,
    /// Device node for the rootfs (target of `switch_root`).
    /// In `ManagedRootfs` mode this is `/dev/mapper/hippius-rootfs`
    /// (the dm-verity mapper). In `TenantLuks` mode this is the
    /// unlocked LUKS data device (typically
    /// `/dev/mapper/hippius-data`). The verity stage activates the
    /// managed name from [`Self::rootfs_data_device`] +
    /// [`Self::rootfs_hash_device`] right before `switch_root`.
    pub rootfs_device: String,
    /// Backing data device for the dm-verity rootfs (the squashfs).
    /// Defaults to `/dev/vdb` — the second virtio-blk disk the
    /// miner-agent attaches to the guest. Overridable via the
    /// `hippius.rootfs_data=` cmdline token (measured) or
    /// `HIPPIUS_ROOTFS_DATA` env var (dev).
    pub rootfs_data_device: String,
    /// Backing hash-tree device for the dm-verity rootfs. Defaults to
    /// `/dev/vdc` — the third virtio-blk disk the miner-agent
    /// attaches. Overridable via `hippius.rootfs_hash=` cmdline
    /// (measured) or `HIPPIUS_ROOTFS_HASH` env (dev).
    pub rootfs_hash_device: String,
    /// dm-verity root hash, parsed from the `dm-verity.root=<64-hex>`
    /// token in the measured cmdline. The launch digest covers that
    /// cmdline byte-for-byte, so the root hash is integrity-anchored
    /// in the §F measurement.
    pub rootfs_root_hash: [u8; 32],
    /// Ed25519 KBS response-signing public key, baked into the
    /// measured UKI (§20). 32 zero bytes in the skeleton.
    pub pinned_kbs_vk: [u8; 32],
    /// KID for [`Self::pinned_kbs_vk`], also UKI-embedded.
    pub pinned_kbs_kid: Vec<u8>,
}

impl Config {
    /// Skeleton defaults — every field empty / zero. [`crate::main`]
    /// overrides `kbs_base_url` with the resolved KBS URL; a later PR
    /// adds the full `/proc/cmdline` + UKI-constants parser for the
    /// remaining fields.
    pub fn from_skeleton_defaults() -> Self {
        Self::default()
    }
}

/// Env-var override for [`resolve_handoff_mode`] (dev only).
pub const ENV_HANDOFF: &str = "HIPPIUS_HANDOFF";
/// `/proc/cmdline` token for [`resolve_handoff_mode`] (production —
/// folded into the launch digest).
pub const CMDLINE_HANDOFF_KEY: &str = "hippius.handoff";

/// Resolve [`HandoffMode`] from `HIPPIUS_HANDOFF` env (dev override) →
/// `hippius.handoff=` on `/proc/cmdline` (production, measured) →
/// **default `tenant-luks`** (#257 BYO base-OS).
///
/// Why `tenant-luks` is the default: PR-#257 closes Phase A by making
/// BYO base-OS the production path. A future cmdline that explicitly
/// requests `managed-rootfs` still works (legacy / dev), but absence
/// must NOT silently fall back to the legacy verity path — every
/// production tenant UKI carries the explicit token, so an
/// undecorated boot is a dev / debug session and `tenant-luks` is the
/// expected target.
pub fn resolve_handoff_mode() -> HandoffMode {
    let env = std::env::var(ENV_HANDOFF).ok();
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok();
    resolve_handoff_mode_from(env.as_deref(), cmdline.as_deref())
}

/// The pure env-vs-cmdline precedence decision behind
/// [`resolve_handoff_mode`].
///
/// Recognised values: `"tenant-luks"` ⇒ [`HandoffMode::TenantLuks`];
/// `"managed-rootfs"` ⇒ [`HandoffMode::ManagedRootfs`]; anything else
/// (or absent) ⇒ default [`HandoffMode::TenantLuks`]. An unrecognised
/// value is treated as absent rather than fail-closed — operators
/// can't soft-brick a boot by typoing the token (the worst case is
/// they get the default).
pub fn resolve_handoff_mode_from(env: Option<&str>, cmdline: Option<&str>) -> HandoffMode {
    if let Some(value) = env.filter(|v| !v.is_empty()) {
        if let Some(mode) = parse_handoff_value(value) {
            return mode;
        }
    }
    if let Some(cmdline) = cmdline {
        let prefix = format!("{CMDLINE_HANDOFF_KEY}=");
        if let Some(value) = cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(&prefix))
            .filter(|v| !v.is_empty())
        {
            if let Some(mode) = parse_handoff_value(value) {
                return mode;
            }
        }
    }
    HandoffMode::TenantLuks
}

fn parse_handoff_value(value: &str) -> Option<HandoffMode> {
    match value {
        "tenant-luks" => Some(HandoffMode::TenantLuks),
        "managed-rootfs" => Some(HandoffMode::ManagedRootfs),
        _ => None,
    }
}

/// Run the full §21 pipeline. Returns `Ok(())` only on the impossible
/// path where `switch_root` does NOT pivot (i.e., a future stage
/// regression); every other terminating condition is an `Err`.
///
/// `snp_provider` is the source of the SEV-SNP attestation report. In
/// production [`crate::main`] passes
/// [`crate::stages::snp_ioctl::SevGuestProvider`] (real
/// `/dev/sev-guest`); tests + non-SNP dev hosts pass
/// [`crate::stages::snp_report::MockSnpReportProvider`]. The §20
/// `REPORT_DATA = nonce ‖ pubkey` layout is enforced INSIDE
/// [`snp_report::request`] regardless of which provider runs — the
/// provider only sees the already-built 64-byte buffer.
///
/// `http` is the KBS transport. Production passes a
/// [`kbs_client::ReqwestHttpClient`]; integration tests pass a mock
/// that returns canned, validly-signed responses.
///
/// `unlocker` is the LUKS unlock backend. In production [`crate::main`]
/// passes [`crate::stages::luks_cryptsetup::RealLuksUnlocker`] (real
/// `libcryptsetup`, Linux only); tests + non-Linux dev hosts pass
/// [`crate::stages::unlock::MockLuksUnlocker`].
///
/// `seed_writer` materialises the NoCloud tmpfs seed; production passes
/// [`crate::stages::seed::RealSeedWriter`], tests
/// [`crate::stages::seed::MockSeedWriter`]. `pivot` performs the final
/// `switch_root`; production passes
/// [`crate::stages::switch_root::RealRootfsPivot`] (Linux), tests
/// [`crate::stages::switch_root::MockRootfsPivot`]. Both are trait
/// objects for the same reason as `unlocker` — the real side `execve`s
/// / mounts and is untestable from `cargo test`.
pub fn run(
    cfg: &Config,
    snp_provider: &dyn SnpReportProvider,
    http: &dyn HttpClient,
    unlocker: &dyn LuksUnlocker,
    verity_opener: &dyn RootfsVerity,
    seed_writer: &dyn SeedWriter,
    pivot: &dyn RootfsPivot,
) -> Result<(), AgentError> {
    // §21 step 0: ticket already minted by L1, delivered to the guest.
    let ticket = ticket::load(&cfg.ticket_path)?;

    // §21 steps 5–6: ephemeral keygen → KBS nonce → SNP report.
    let keys = keygen::generate_ephemeral()?;
    let nonce = kbs_client::fetch_nonce(http, &cfg.kbs_base_url)?;
    let report = snp_report::request(snp_provider, &nonce.0, keys.public_bytes())?;
    // The guest's OWN launch measurement, read from the report it just
    // generated — the independent source for the §20 binding check.
    let measurement = snp_report::measurement(&report)?;

    // §21 step 7: ship ticket + report + nonce to the KBS, get a
    // signed+wrapped release response back. A KBS denial is terminal.
    // The legacy `pipeline::run` path predates Phase 2A boot-counter
    // CAS (Codex audit #2) and does not yet read/write the counter
    // file; pass `None` so KBS short-circuits the check exactly as
    // pre-Phase-2A wire requests did.
    let signed = kbs_client::release(
        http,
        &cfg.kbs_base_url,
        ticket.cose_bytes(),
        &nonce,
        &report,
        None,
    )?;

    // §21 step 12: verify (Ed25519, fields, HPKE) + unwrap (§6/§7/
    // §19/§20). `keys` is consumed by value — the X25519 secret scalar
    // drops + wipes immediately after this stage returns.
    // Legacy `pipeline::run` discards `boot_counter` — Phase 2A
    // wiring is opt-in via the `hippius-guest-release` binary which
    // exposes `--last-counter-file` / `--new-counter-file`. The
    // legacy custom-Rust-initramfs has no persistent storage path
    // for the counter, so it stays at the pre-Phase-2A no-op.
    let UnwrappedSecrets {
        luks,
        userdata,
        // §7: the legacy custom-Rust-initramfs `pipeline::run` does not
        // write the lifecycle key — that path is the KBS-UKI managed-
        // rootfs boot, not the BYO-OS/systemd §25 fence. The
        // `hippius-guest-release` binary (cryptsetup keyscript) is the
        // one that materialises the key to tmpfs via `--lifecycle-key
        // -out`. Drop it here (Zeroizing wipes on drop).
        lifecycle_key: _,
        boot_counter: _,
        // `kbs-core::volume_stamp` — same story as `boot_counter`: the
        // legacy custom-Rust-initramfs `pipeline::run` has no on-disk
        // wiring for the anti-rollback confirm sequence. Opt-in wiring
        // lives in the `hippius-guest-release` binary
        // (`--volume-stamp-ctx-out` / `--confirm-volume-stamp`).
        expected_volume_stamp: _,
        volume_stamp_token: _,
    } = verify::verify_and_unwrap(
        &signed,
        keys,
        &nonce,
        &ticket,
        &measurement,
        &cfg.pinned_kbs_vk,
        &cfg.pinned_kbs_kid,
    )?;

    // §21 step 12b: unlock the LUKS volume — `luks` is moved in and
    // wiped by `Zeroizing` Drop inside the stage scope (the unlocker's
    // `unlock`, real or mock, consumes it by value).
    unlock::open_luks(unlocker, &cfg.luks_device, luks)?;

    // §21 step 12b': open the dm-verity rootfs — creates
    // `/dev/mapper/hippius-rootfs` from the data + hash backing
    // devices the miner-agent attached, integrity-anchored by the
    // measured `dm-verity.root=` cmdline token (parsed into
    // `cfg.rootfs_root_hash`). The §F build pipeline ran
    // `veritysetup format <data> <hash>` and folded the root hash
    // into the launch digest via `assemble-uki.sh`. Carries no
    // secret material — the verity protocol is integrity, not
    // confidentiality.
    //
    // BYO base-OS (#257, `HandoffMode::TenantLuks`) skips this stage:
    // there is no §F managed rootfs to verity-open — the tenant LUKS
    // volume IS the rootfs and is unlocked above. Integrity then
    // comes from LUKS2 AES-XTS-integrity (set at `luksFormat` time)
    // rather than dm-verity.
    if cfg.handoff == HandoffMode::ManagedRootfs {
        verity::open_rootfs(
            verity_opener,
            &cfg.rootfs_data_device,
            &cfg.rootfs_hash_device,
            &cfg.rootfs_root_hash,
        )?;
    }

    // §21 step 12c: write the NoCloud seed onto tmpfs — `userdata` is
    // moved in and wiped by `Zeroizing` Drop inside the stage scope.
    seed::write_nocloud(seed_writer, &cfg.nocloud_tmpfs_dir, userdata)?;

    // §21 step 12d: flush the initramfs DHCP lease + default route so
    // the kernel netdev state does not survive `switch_root` and clash
    // with the userspace network configurator's re-DHCP. Without this
    // the guest ends up with TWO IPs on `enp1s0` (initramfs lease as
    // primary + userspace lease as secondary) — observed live in the
    // 2026-05-30 tenant smoke. The teardown is a no-op when bring-up
    // never stashed a lease (KBS UKI variant), so the call is safe to
    // run unconditionally. See `stages::network::teardown_for_switchroot`.
    network::teardown_for_switchroot()?;

    // §21 step 13: switch_root into the chosen rootfs. No secret-bearing
    // local is live at this point — every `Zeroizing` buffer (X25519
    // scalar, LUKS key, user-data) was consumed + wiped by an earlier
    // stage — so the `execve(2)` bypass of Drop is safe.
    let pivot_cfg = match cfg.handoff {
        HandoffMode::ManagedRootfs => PivotConfig {
            rootfs_device: cfg.rootfs_device.clone(),
            mode: PivotMode::ManagedRootfs,
        },
        HandoffMode::TenantLuks => PivotConfig {
            rootfs_device: cfg.rootfs_device.clone(),
            mode: PivotMode::TenantLuks {
                kernel_release: cfg.kernel_release.clone(),
            },
        },
    };
    switch_root::pivot(pivot, &pivot_cfg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §21 order must equal the order [`run`] executes. The compile-
    /// gate test in `tests/compile_gate.rs` walks the array and the
    /// pipeline together; this test just pins the array length.
    #[test]
    fn section_21_order_has_ten_stages() {
        assert_eq!(SECTION_21_ORDER.len(), 10);
        // The first stage MUST be ticket-load: every subsequent stage
        // takes the ticket bytes (directly or via the release call).
        assert_eq!(SECTION_21_ORDER[0], Stage::LoadTicket);
        // The last stage MUST be the pivot — otherwise the boot
        // would return control to the initramfs with secrets already
        // released.
        assert_eq!(
            SECTION_21_ORDER[SECTION_21_ORDER.len() - 1],
            Stage::SwitchRoot
        );
    }

    #[test]
    fn agent_error_class_is_static() {
        // The §20 logging discipline relies on `class()` returning a
        // `&'static str` — never a formatted, plaintext-bearing value.
        // Pin every variant: a future addition that carries a `Vec<u8>`
        // or a `String` would fail the `: &'static str` cast here.
        let cases: &[(AgentError, &'static str)] = &[
            (AgentError::Todo(Stage::Keygen), "stage-not-implemented"),
            (AgentError::SnpDevice("open-failed"), "snp-device-failed"),
            (AgentError::Luks("activate"), "luks-failed"),
        ];
        for (err, want) in cases {
            let c: &'static str = err.class();
            assert_eq!(c, *want);
        }
    }

    #[test]
    fn resolve_handoff_defaults_to_tenant_luks() {
        // Absent both env and cmdline ⇒ TenantLuks (the #257 BYO-OS
        // default). An empty cmdline string with no token also counts
        // as absent. A boot without an explicit token is a dev /
        // debug session — fail safe to the new default rather than
        // the legacy path.
        assert_eq!(
            resolve_handoff_mode_from(None, None),
            HandoffMode::TenantLuks
        );
        assert_eq!(
            resolve_handoff_mode_from(None, Some("ro quiet console=ttyS0")),
            HandoffMode::TenantLuks
        );
        assert_eq!(
            resolve_handoff_mode_from(Some(""), Some("")),
            HandoffMode::TenantLuks
        );
    }

    #[test]
    fn resolve_handoff_parses_cmdline_token() {
        // The production path: the measured UKI's cmdline carries
        // `hippius.handoff=<value>`, which is folded into the launch
        // digest so a tampered miner cannot flip the path.
        assert_eq!(
            resolve_handoff_mode_from(None, Some("ro hippius.handoff=managed-rootfs quiet")),
            HandoffMode::ManagedRootfs
        );
        assert_eq!(
            resolve_handoff_mode_from(None, Some("ro hippius.handoff=tenant-luks quiet")),
            HandoffMode::TenantLuks
        );
    }

    #[test]
    fn resolve_handoff_env_overrides_cmdline() {
        // The dev override: the env var wins outright over the
        // cmdline so an operator can flip the path on a dev VM
        // without rebuilding the UKI.
        assert_eq!(
            resolve_handoff_mode_from(
                Some("managed-rootfs"),
                Some("ro hippius.handoff=tenant-luks quiet")
            ),
            HandoffMode::ManagedRootfs
        );
    }

    #[test]
    fn resolve_handoff_unknown_value_falls_back_to_default() {
        // A typo / unrecognised value MUST NOT fail-closed — the
        // worst case is the operator gets the safe default. The boot
        // must not soft-brick on a stray `hippius.handoff=foobar`.
        assert_eq!(
            resolve_handoff_mode_from(None, Some("ro hippius.handoff=foobar quiet")),
            HandoffMode::TenantLuks
        );
        assert_eq!(
            resolve_handoff_mode_from(Some("garbage"), None),
            HandoffMode::TenantLuks
        );
    }

    #[test]
    fn snp_device_display_is_static_string() {
        // PR-E1.2: the `&'static str` payload on `SnpDevice` is for
        // internal pattern-matching (the closed `cat::` vocabulary in
        // `stages/snp_ioctl.rs`). The `Display` impl MUST emit a
        // fixed tag — `eprintln!("{err}")` cannot leak the inner
        // classifier. (For `Todo` the inner is the `Stage` enum tag,
        // a finite identifier — also safe.)
        let err = AgentError::SnpDevice("ioctl-failed");
        assert_eq!(err.to_string(), "snp-device-failed");
        assert_eq!(err.class(), err.to_string());
    }
}
