//! `hippius-agent-initramfs` — `/init` for the measured SEV-SNP guest.
//!
//! Two entry points, dispatched on `argv[1]`.
//!
//! **boot** (no subcommand) drives [`run`] — the §21 boot pipeline:
//! load the OrderTicket → X25519 keygen → KBS nonce → SNP attestation
//! report → KBS release → verify + unwrap → LUKS unlock → NoCloud
//! tmpfs seed → `switch_root` into the dm-verity rootfs.
//!
//! **`eol`** drives [`run_eol`] — the §24/§25 end-of-life path: sign a
//! `StoppedAck` → push it to vali → tear down dm-crypt → power off. The
//! measured image's shutdown integration (a systemd shutdown unit /
//! dracut shutdown hook — §F) invokes `hippius-agent-initramfs eol`.
//!
//! **Status — PR-E1.5 closes the initramfs E1 sub-track.** Every §21
//! stage is real (PR-E1.1 skeleton → E1.2 `/dev/sev-guest` → E1.3 KBS
//! HTTP → E1.4 LUKS → **E1.5 NoCloud seed + `switch_root` + §20
//! production hardening + the §24/§25 EOL path**). The boot path no
//! longer returns: on success `switch_root` `execve`s the guest init;
//! on any failure the agent powers the VM **off** (§20 "no
//! emergency/debug shell" — never a shell, never a lingering state).

// Same workspace-clippy carve-out as the sibling `lib.rs` (`unwrap_used`
// / `expect_used` / `panic` denied production-wide, allowed in tests so
// `.expect("…")` reads naturally inside the test module added at the
// bottom of this file).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use ed25519_dalek::SigningKey;
use hippius_agent_initramfs::{
    bring_up_dhcp, eol_teardown, is_vsock_url, poweroff, resolve_handoff_mode, resolve_kbs_url,
    resolve_luks_device, resolve_rootfs_devices, resolve_verity_root_hash, run, run_eol,
    run_eol_sign_only, suppress_kernel_console, Config, EolSink, HandoffMode, HttpClient,
    LuksUnlocker, RealSeedWriter, ReqwestHttpClient, RootfsPivot, RootfsVerity, SnpReportProvider,
    StoppedAckParams, VsockHttpClient, MAPPER_NAME as LUKS_MAPPER_NAME, NOCLOUD_SEED_DIR,
    PINNED_KBS_RESPONSE_KID, PINNED_KBS_RESPONSE_VK, ROOTFS_MAPPER,
};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// Exit code for the impossible path where the boot pipeline returns
/// `Ok(())` instead of pivoting via `switch_root(2)`.
const EXIT_DID_NOT_PIVOT: u8 = 1;

/// Exit code for the §21 fail-closed path. The agent powers the VM off
/// first ([`fail_closed`]); this non-zero code is only the last-resort
/// fallback if the poweroff syscall itself failed — initramfs PID 1
/// exiting non-zero panics the kernel, which `panic=1` turns into a
/// reboot. No shell, no retry loop, no leaked plaintext (§20).
const EXIT_FAIL_CLOSED: u8 = 2;

fn main() -> ExitCode {
    // Mount the kernel virtual filesystems FIRST — the §21 boot
    // pipeline reads `/proc/cmdline` (hardening assert + KBS-URL /
    // LUKS-device resolution) and the §24/§25 EOL path the same way,
    // and a measured initramfs cpio ships none of `/proc`, `/sys`,
    // `/dev` pre-mounted. Gated to PID 1: a future init wrapper, or a
    // dev/test invocation, will not be the kernel's `init` process and
    // already runs in a tree where these are mounted; mounting on top
    // would be a hostile shadow. See `mount_initramfs_filesystems`.
    if let Err(class) = mount_initramfs_filesystems() {
        return fail_closed(class);
    }
    // Pull the kernel modules the §21 boot pipeline depends on into
    // the running kernel. Debian Trixie's 6.12 ships both AF_VSOCK
    // (`CONFIG_VSOCKETS=m`) and virtio-net (`virtio_net=m`) as
    // modules, so the tenant-UKI's `stages::ticket_vsock::recv_ticket`
    // (vsock) and `stages::network::bring_up_dhcp` (eth0) both fail
    // closed before there is anything to do unless these get loaded
    // first — observed both modes live (vsock 2026-05-25 #190;
    // network 2026-05-25 #194). See [`load_kernel_modules`] for the
    // per-family load contract.
    if let Err(class) = load_kernel_modules() {
        return fail_closed(class);
    }
    // Wait for the LUKS backing block-device node to materialise. The
    // §21 boot pipeline opens `/dev/vda` (per the tenant UKI's cmdline
    // `hippius.luks_device=/dev/vda`) via `libcryptsetup`'s
    // `crypt_init`; under Debian Trixie 6.12 the kernel only exposes
    // that node once `virtio_blk` (CONFIG_VIRTIO_BLK=m) has loaded
    // AND finished its asynchronous PCI / device-mapper bring-up.
    // `init_module(2)` returns the moment the kernel accepts the
    // module bytes — the per-device probe runs on a workqueue, so
    // there is a sub-second window where the module is "loaded" but
    // the device node is not yet present. Hitting that window made
    // `crypt_init` fail closed with ENOTBLK and collapsed the boot
    // at `luks-failed:crypt-init` on the post-virtio_blk-bundle live
    // boot (#238). The pattern mirrors `wait_for_interface`
    // (#200 / #202) which closed the equivalent virtio_net registration
    // race. PID-1 gate matches `load_kernel_modules` — non-init
    // invocations skip cleanly so the same binary stays safe under
    // `cargo run` / `cargo test`.
    if let Err(class) = wait_for_luks_block_device() {
        return fail_closed(class);
    }
    // Dispatch on the subcommand. `eol` runs the §24/§25 teardown; any
    // other argv (or none) runs the §21 boot pipeline.
    //
    // `eol --sign-only` is the systemd-shutdown-hook variant (§F): it
    // signs + pushes the StoppedAck and RETURNS, leaving the luksClose +
    // poweroff to systemd's own shutdown sequence. The measured tenant
    // image's `hippius-eol-sign.service` (`Before=shutdown.target`)
    // invokes this on every clean ACPI poweroff — which is exactly what a
    // §25 quiesce (`virsh shutdown`) and a §24 decommission trigger. The
    // plain `eol` form keeps the legacy initramfs-as-init contract
    // (sign → push → luksClose → poweroff).
    match (
        std::env::args().nth(1).as_deref(),
        std::env::args().nth(2).as_deref(),
    ) {
        (Some("eol"), Some("--sign-only")) => run_eol_sign_only_subcommand(),
        (Some("eol"), _) => run_eol_subcommand(),
        _ => run_boot(),
    }
}

/// Poll for the LUKS backing block-device path until it exists as a
/// real block device, within a fixed budget. Returns `Ok(())` on
/// success, `Err("luks-device-wait")` on budget exhaustion, or
/// `Err("luks-device-resolve")` if neither `/proc/cmdline` nor the
/// dev env var named one.
///
/// Skipped (no-op `Ok(())`) when not PID 1, so dev / test invocations
/// outside an initramfs are unaffected.
#[cfg(target_os = "linux")]
fn wait_for_luks_block_device() -> Result<(), &'static str> {
    use std::os::unix::fs::FileTypeExt;
    use std::time::{Duration, Instant};

    if std::process::id() != 1 {
        return Ok(());
    }

    // Resolve the LUKS device path the same way the §21 pipeline does
    // — `HIPPIUS_LUKS_DEVICE` env override first, then
    // `hippius.luks_device=` on `/proc/cmdline` (the measured cmdline
    // baked into the UKI). Reuses the pipeline's free function so any
    // future cmdline-token rename touches one place.
    let device =
        hippius_agent_initramfs::resolve_luks_device().map_err(|_| "luks-device-resolve")?;
    let path = std::path::PathBuf::from(device.as_str());

    // ~3 s budget × 50 ms poll matches `wait_for_interface`
    // (PR #200 / #202) — observed virtio_blk probe latency on the
    // measured Trixie 6.12 kernel is in the low-tens-of-ms range; 3 s
    // is generous enough that pathological vendor-driver load delays
    // (e.g. a vhost-blk queue init under host CPU pressure) still
    // fit. Budget exhaustion is fail-closed — never an emergency
    // shell, never a retry-forever loop (§20).
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.file_type().is_block_device() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("luks-device-wait");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_for_luks_block_device() -> Result<(), &'static str> {
    Ok(())
}

/// `uname(2).release` — the running kernel's release string (e.g.
/// `"6.12.63+deb13-amd64"`). Used by the BYO-OS pivot to bind-mount
/// `/lib/modules/<release>` into the tenant rootfs (the tenant's
/// userspace runs Hippius's measured kernel, so the modules tree on
/// disk MUST match the running kernel — same handoff pattern dracut /
/// mkinitcpio use).
#[cfg(target_os = "linux")]
fn resolve_kernel_release() -> Result<String, &'static str> {
    let utsname = nix::sys::utsname::uname().map_err(|_| "handoff-uname")?;
    utsname
        .release()
        .to_str()
        .map(str::to_string)
        .ok_or("handoff-uname-utf8")
}

#[cfg(not(target_os = "linux"))]
fn resolve_kernel_release() -> Result<String, &'static str> {
    // Non-Linux dev host: the pivot stage never runs in earnest here
    // (the canned SNP report fails KBS verification far earlier), but
    // keep the resolver stub harmless so the test path compiles.
    Ok(String::new())
}

/// Mount `/proc`, `/sys`, `/dev`, and `/run` once, in PID 1 only.
///
/// **Why this exists.** The measured tenant UKI's initramfs cpio
/// carries `/init` → `hippius-agent-initramfs`, the agent binary, and
/// the dynamic-linker baggage — no other content. The Linux kernel
/// does **not** auto-mount procfs / sysfs / devtmpfs for the
/// initramfs; that is `/init`'s job. PR-E1.5 read `/proc/cmdline`
/// before mounting `/proc`, so production booted into
/// `fail-closed: cmdline-read` and powered off ~1 s after the kernel
/// handed off to `/init` — the §21 release path was never exercised
/// (live, 2026-05-25 E2E session).
///
/// **PID-1 gate.** A non-init invocation (`cargo run`, an integration
/// test, a hypothetical wrapper that wraps this binary) already lives
/// in a tree where the host's `/proc` is mounted; mounting on top
/// would shadow it and break unrelated readers. The gate makes this
/// function a safe no-op everywhere except where it is needed.
///
/// **Filesystem set.**
/// - `/proc` procfs `MS_NOSUID|MS_NODEV|MS_NOEXEC` — canonical
///   hardening triple; matches what systemd / dracut mount.
/// - `/sys` sysfs `MS_NOSUID|MS_NODEV|MS_NOEXEC` — ditto.
/// - `/dev` devtmpfs `MS_NOSUID`, `mode=0755` — `MS_NODEV` would
///   defeat the entire point of devtmpfs (it IS the device nodes);
///   `MS_NOEXEC` would block running e.g. `/dev/initctl`-shaped
///   helpers a downstream stage might invoke. The mode pin matches
///   the kernel default and is independent of the umask the
///   initramfs inherits.
/// - `/run` tmpfs `MS_NOSUID|MS_NODEV`, `mode=0755` — `MS_NOEXEC` is
///   intentionally OFF (cloud-init / netbird helpers may stage
///   executables here once the seed lands). Required for two
///   downstream contracts: (1) `stages::seed`'s §20
///   `ensure_memory_backed` guard `statfs`s the seed's nearest
///   existing ancestor and refuses anything other than `TMPFS_MAGIC`;
///   (2) `stages::switch_root` `MS_MOVE`s `/run` into `/sysroot/run`
///   so the cloud-init NoCloud seed survives the pivot
///   (review r1 convergent High).
///
/// **Error classes** are compile-time `&'static str` for the §20
/// logging discipline (`no_seed_logging.rs` enforces this). The mkdir
/// failure class names the offender (`proc-mkdir` / `sys-mkdir` /
/// `dev-mkdir` / `run-mkdir`) so an operator never has to guess which
/// path the kernel refused (review r1 Low). The mount failure class
/// mirrors the same per-target naming (`proc-mount`, `sys-mount`,
/// `dev-mount`, `run-mount`).
#[cfg(target_os = "linux")]
fn mount_initramfs_filesystems() -> Result<(), &'static str> {
    // Not the kernel's init — host already mounted these. Skip cleanly
    // so the same binary is safe to `cargo run` from a dev shell, and
    // so the unit test below can call this function unconditionally.
    if std::process::id() != 1 {
        return Ok(());
    }

    use nix::mount::{mount, MsFlags};

    // The hardening triple — present on every well-behaved
    // `/proc` / `/sys` mount in the systemd / dracut universe.
    let hardening = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;

    // `/run` keeps `MS_NOSUID|MS_NODEV` (the standard distro pin) but
    // omits `MS_NOEXEC` — see the per-mount rationale above.
    let run_flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

    // The fstype name is reused as the `source` argument — the kernel
    // ignores `source` for procfs/sysfs/devtmpfs/tmpfs but `mount(2)`
    // refuses a NULL source for them, so a stable placeholder is
    // required; the fstype is the conventional choice.
    let mounts: &[Mount] = &[
        Mount {
            target: "/proc",
            fstype: "proc",
            flags: hardening,
            data: None,
            mkdir_class: "proc-mkdir",
            mount_class: "proc-mount",
        },
        Mount {
            target: "/sys",
            fstype: "sysfs",
            flags: hardening,
            data: None,
            mkdir_class: "sys-mkdir",
            mount_class: "sys-mount",
        },
        Mount {
            target: "/dev",
            fstype: "devtmpfs",
            flags: MsFlags::MS_NOSUID,
            data: Some("mode=0755"),
            mkdir_class: "dev-mkdir",
            mount_class: "dev-mount",
        },
        Mount {
            target: "/run",
            fstype: "tmpfs",
            flags: run_flags,
            data: Some("mode=0755"),
            mkdir_class: "run-mkdir",
            mount_class: "run-mount",
        },
    ];

    for m in mounts {
        // `create_dir_all` is idempotent — a future cpio that DOES ship
        // these as empty dirs is not penalised.
        std::fs::create_dir_all(m.target).map_err(|_| m.mkdir_class)?;
        mount(Some(m.fstype), m.target, Some(m.fstype), m.flags, m.data)
            .map_err(|_| m.mount_class)?;
    }
    Ok(())
}

/// One row in [`mount_initramfs_filesystems`]'s spec table — extracted
/// out of an in-place tuple to keep `clippy::type_complexity` happy
/// AND to give every column a named identity at the call site.
#[cfg(target_os = "linux")]
struct Mount {
    target: &'static str,
    fstype: &'static str,
    flags: nix::mount::MsFlags,
    data: Option<&'static str>,
    /// Static class emitted to the serial console (and the exit
    /// classifier) when `mkdir(target)` fails.
    mkdir_class: &'static str,
    /// Static class emitted when `mount(2)` itself returns an error.
    mount_class: &'static str,
}

/// Non-Linux dev / CI host: `/proc` already lives wherever the host put
/// it and the syscalls do not exist anyway. The PID-1 gate plus the
/// `cfg` means the production binary alone ever performs a real mount.
#[cfg(not(target_os = "linux"))]
fn mount_initramfs_filesystems() -> Result<(), &'static str> {
    Ok(())
}

/// Load the kernel modules the §21 boot pipeline depends on into the
/// running kernel, in dependency order, family-by-family.
///
/// Five families are loaded:
///
/// 1. **AF_VSOCK** — `vsock`, `vmw_vsock_virtio_transport_common`,
///    `vmw_vsock_virtio_transport`. Without these the `/dev/vsock`
///    device node never appears, and
///    `stages::ticket_vsock::recv_ticket`'s `VsockListener::bind` fails
///    closed at `vsock-bind` ~1 s after `/init` started (observed
///    2026-05-25 — closed in PR #190).
///
/// 2. **virtio-net** — `failover`, `net_failover`, `virtio_net`.
///    Without these `/sys/class/net` carries only `lo`, no `eth0`
///    is exposed by the kernel, and `stages::network::bring_up_dhcp`
///    has nothing to issue a DHCP DISCOVER on — `ReqwestHttpClient::
///    post_cbor` fails closed at `kbs-connect` ~0.9 s after `/init`
///    started (observed 2026-05-25 — closed in PR #194).
///
/// 3. **virtio-blk** — `virtio_blk`. Without this `/dev/vda` never
///    materialises and `libcryptsetup::crypt_init` fails closed with
///    `IOError(ENOTBLK "Block device required")` →
///    `AgentError::Luks("crypt-init")` ~4 s after `/init` (observed
///    2026-05-27, this commit's predecessor).
///
/// 4. **dm-crypt + AES-XTS** — `dm-mod`, `dm-crypt`, `xts`, `cryptd`,
///    `crypto_simd`, `aesni-intel`. Without these the kernel device-
///    mapper rejects the dm-crypt activation libcryptsetup tries to
///    set up (LUKS volume cipher is `aes-xts-plain64`), and
///    `crypt_activate_by_passphrase` returns an opaque error →
///    `AgentError::Luks("activate")`. Confirmed live 2026-05-28: the
///    agent received the correct 32-byte KEK (sha256 byte-for-byte
///    matches Vault) but activate fail-closed; a standalone host-side
///    libcryptsetup-rs test with the same bytes succeeded because the
///    host had dm-crypt + aes-xts loaded ambiently. This family
///    bridges that gap.
///
/// 5. **SEV-SNP attestation** — `crypto_null`, `gf128mul`,
///    `ghash-generic`, `gcm`, `configfs`, `tsm`, `sev-guest`.
///    Without these `/dev/sev-guest` never appears and the SNP
///    attestation report read fails — observed 2026-05-26
///    (closed in PR #206/#207).
///
/// **Per-family skip semantics.** The first module file's existence
/// is the "did the UKI bundle this family?" probe. Absent → that
/// family was deliberately not staged for this UKI flavour (kbs-uki
/// has no use for vsock, e.g.); skip cleanly so the same agent binary
/// serves both UKI roles without code branches.
///
/// **Load order.** Pinned per-family by the modules' declared
/// `depends:`. Reordering would surface as the kernel returning
/// `ENOENT` on a dependent name.
///   - vsock:       `vsock` ← `…transport_common` ← `…virtio_transport`
///   - virtio-net:  `failover` ← `net_failover` ← `virtio_net`
///   - virtio-blk:  `virtio_blk` (no `depends:`)
///   - dm-crypt:    `dm-mod` ← `dm-crypt`; `xts`; `cryptd` ←
///     `crypto_simd`; `gf128mul` ← `aesni-intel`
///   - SEV-SNP:     `configfs` + `crypto_null` ← `gf128mul`
///     ← `ghash-generic` ← `gcm` ← `tsm` ← `sev-guest`
///
/// `virtio_pci` / `virtio_ring` are built-in in Trixie
/// (`modules.builtin`) so the PCI bus is already enumerated by the
/// time we get here.
///
/// **`<kver>` resolution.** `uname(2)` releases (e.g.
/// `"6.12.63+deb13-amd64"`) — never hardcoded, so a kernel version
/// bump in `inputs.lock` flows through without an agent code change.
///
/// **`EEXIST` is tolerated.** A future kernel that flips a family
/// from `=m` to `=y` returns `EEXIST` for an already-builtin module
/// — that's success, not failure.
///
/// **PID-1 gate.** Mirrors `mount_initramfs_filesystems`'s posture:
/// outside PID 1 (a `cargo test` invocation, a dev wrapper) the
/// kernel modules either already live or never will, and a real
/// `init_module(2)` would either be a no-op or hit `EPERM` —
/// short-circuit to `Ok` so the same binary stays test-friendly.
///
/// **§20 logging discipline.** Every error path returns a compile-
/// time `&'static str` sub-class (`<family>-modules-<step>-<name>`)
/// — enforced crate-wide by `tests/no_seed_logging.rs`. The
/// per-module class lets the operator see exactly which step failed,
/// not a generic "modules".
#[cfg(target_os = "linux")]
fn load_kernel_modules() -> Result<(), &'static str> {
    if std::process::id() != 1 {
        return Ok(());
    }

    use nix::sys::utsname::uname;

    let utsname = uname().map_err(|_| "kmod-modules-uname")?;
    // `release()` returns `&OsStr`; cast through `to_str()` for the
    // path-format below. A non-UTF-8 kernel release is impossible in
    // practice (Linux always emits ASCII), but we still fail closed
    // rather than `to_string_lossy` so the failure surfaces.
    let release: &str = utsname
        .release()
        .to_str()
        .ok_or("kmod-modules-uname-utf8")?;

    // (relative module-name, read-error-class, load-error-class).
    // Order is load order. `name_rel` is the path under
    // `/lib/modules/<kver>/kernel/` and the module filename stem.
    let vsock: &[(&str, &'static str, &'static str)] = &[
        (
            "net/vmw_vsock/vsock",
            "vsock-modules-read-vsock",
            "vsock-modules-load-vsock",
        ),
        (
            "net/vmw_vsock/vmw_vsock_virtio_transport_common",
            "vsock-modules-read-common",
            "vsock-modules-load-common",
        ),
        (
            "net/vmw_vsock/vmw_vsock_virtio_transport",
            "vsock-modules-read-transport",
            "vsock-modules-load-transport",
        ),
    ];
    let virtio_net: &[(&str, &'static str, &'static str)] = &[
        (
            "net/core/failover",
            "network-modules-read-failover",
            "network-modules-load-failover",
        ),
        (
            "drivers/net/net_failover",
            "network-modules-read-net-failover",
            "network-modules-load-net-failover",
        ),
        (
            "drivers/net/virtio_net",
            "network-modules-read-virtio-net",
            "network-modules-load-virtio-net",
        ),
    ];
    // SEV-SNP attestation: /dev/sev-guest is exposed by the
    // `sev_guest` driver (CONFIG_SEV_GUEST=m on Debian Trixie's
    // 6.12 kernel). Depends on `tsm` (CoCo TSM framework). The
    // agent's SNP report read at stages::snp_ioctl needs the
    // device node, so load both BEFORE the attestation stage.
    let sev_guest: &[(&str, &'static str, &'static str)] = &[
        (
            "fs/configfs/configfs",
            "snp-modules-read-configfs",
            "snp-modules-load-configfs",
        ),
        // Crypto modules required by sev-guest probe (gcm(aes) AEAD
        // for the SNP guest message encryption). Load chain:
        //   crypto_null (gcm dep) → gf128mul (ghash_generic dep) →
        //   ghash_generic → gcm → sev-guest
        // CONFIG_CRYPTO_AES=y so AES is built-in (no .ko needed).
        (
            "crypto/crypto_null",
            "snp-modules-read-crypto-null",
            "snp-modules-load-crypto-null",
        ),
        (
            "lib/crypto/gf128mul",
            "snp-modules-read-gf128mul",
            "snp-modules-load-gf128mul",
        ),
        (
            "crypto/ghash-generic",
            "snp-modules-read-ghash",
            "snp-modules-load-ghash",
        ),
        ("crypto/gcm", "snp-modules-read-gcm", "snp-modules-load-gcm"),
        (
            "drivers/virt/coco/tsm",
            "snp-modules-read-tsm",
            "snp-modules-load-tsm",
        ),
        (
            "drivers/virt/coco/sev-guest/sev-guest",
            "snp-modules-read-sev-guest",
            "snp-modules-load-sev-guest",
        ),
    ];

    // virtio-blk: /dev/vda for the LUKS-encrypted tenant data volume.
    // Debian Trixie ships `virtio_blk=m`. The agent's
    // `stages::unlock::resolve_luks_device` returns `/dev/vda` (per
    // the tenant UKI's cmdline `hippius.luks_device=/dev/vda`), and
    // `libcryptsetup`'s `crypt_init` fails-closed with
    // `IOError(ENOTBLK "Block device required")` until this module
    // loads and the kernel exposes the device node. Observed live
    // 2026-05-27 ~16:14 UTC via a debug-eprintln initramfs.
    //
    // No deps in the .ko `depends:` field — virtio_blk talks directly
    // to the virtio-pci bus (which is built-in in Trixie); the only
    // staged sibling needed is the file itself.
    let virtio_blk: &[(&str, &'static str, &'static str)] = &[(
        "drivers/block/virtio_blk",
        "block-modules-read-virtio-blk",
        "block-modules-load-virtio-blk",
    )];

    // dm-crypt + AES-XTS chain — `libcryptsetup`'s `activate_by_passphrase`
    // succeeds at deriving the master key via argon2id (userspace), then
    // hands it to the kernel device-mapper to create the dm-crypt target
    // for `aes-xts-plain64`. Without these modules the kernel refuses
    // the dm-crypt activation and `crypt_activate_by_passphrase` returns
    // an opaque error → `AgentError::Luks("activate")`. Observed live
    // 2026-05-27: agent received the correct 32-byte KEK from KBS
    // (sha256 matched Vault byte-for-byte), the bytes opened the LUKS
    // slot via host-side `cryptsetup open --key-file -` AND via a
    // standalone host-side libcryptsetup-rs binary (same `activate_by_
    // passphrase` call), but the in-guest call fail-closed because
    // dm-crypt + aes-xts were missing. The chain matches the kernel's
    // `modinfo depends:` graph (Debian Trixie 6.12):
    //   dm-mod              → no deps
    //   dm-crypt            → depends: dm-mod
    //   xts                 → no deps
    //   cryptd              → no deps
    //   crypto_simd         → depends: cryptd
    //   gf128mul            → no deps (also loaded by sev-guest family;
    //                         init_module on an already-loaded module
    //                         returns EEXIST which load_module_family
    //                         treats as success — safe to load here
    //                         first, sev-guest's later load is a no-op)
    //   aesni-intel         → depends: crypto_simd, gf128mul
    // Initial dm_crypt_aes (PR #242) staged the family WITHOUT gf128mul
    // and relied on sev-guest loading it later — but sev-guest runs
    // AFTER dm_crypt_aes, so aesni-intel's init_module fail-closed with
    // ENODEP at `dm-modules-load-aesni-intel` (observed live 2026-05-28
    // post-#243 boot). Stage gf128mul HERE, before aesni-intel, so the
    // dependency is satisfied at the moment init_module(aesni-intel)
    // is called.
    let dm_crypt_aes: &[(&str, &'static str, &'static str)] = &[
        (
            "drivers/md/dm-mod",
            "dm-modules-read-dm-mod",
            "dm-modules-load-dm-mod",
        ),
        (
            "drivers/md/dm-crypt",
            "dm-modules-read-dm-crypt",
            "dm-modules-load-dm-crypt",
        ),
        ("crypto/xts", "dm-modules-read-xts", "dm-modules-load-xts"),
        (
            "crypto/cryptd",
            "dm-modules-read-cryptd",
            "dm-modules-load-cryptd",
        ),
        (
            "crypto/crypto_simd",
            "dm-modules-read-crypto-simd",
            "dm-modules-load-crypto-simd",
        ),
        (
            "lib/crypto/gf128mul",
            "dm-modules-read-gf128mul",
            "dm-modules-load-gf128mul",
        ),
        (
            "arch/x86/crypto/aesni-intel",
            "dm-modules-read-aesni-intel",
            "dm-modules-load-aesni-intel",
        ),
    ];

    // dm-verity chain — the §21 verity stage opens
    // `/dev/mapper/hippius-rootfs` from the data + hash backing
    // devices the miner-agent attaches at `/dev/vdb` + `/dev/vdc`.
    // Without these, `libcryptsetup::activate_by_volume_key
    // (CRYPT_VERITY, …)` is rejected by the kernel and the boot
    // fail-closes at `verity-failed:activate`. Dependency chain per
    // `modinfo depends:` (Debian Trixie 6.12):
    //   dm-bufio            (no deps)
    //   reed_solomon        (no deps)
    //   dm-verity           ← dm-mod, dm-bufio, reed_solomon
    // `dm-mod` is already loaded by the dm-crypt family above, so
    // dm-verity's third dep is satisfied at the moment of
    // init_module. Ordering: load AFTER dm_crypt_aes (which pins
    // dm-mod) and BEFORE sev_guest is irrelevant for verity — sev-
    // guest loads its own crypto helpers independently.
    let dm_verity: &[(&str, &'static str, &'static str)] = &[
        (
            "drivers/md/dm-bufio",
            "verity-modules-read-dm-bufio",
            "verity-modules-load-dm-bufio",
        ),
        (
            "lib/reed_solomon/reed_solomon",
            "verity-modules-read-reed-solomon",
            "verity-modules-load-reed-solomon",
        ),
        (
            "drivers/md/dm-verity",
            "verity-modules-read-dm-verity",
            "verity-modules-load-dm-verity",
        ),
    ];

    // Rootfs filesystem driver — the §F build-rootfs.sh produces a
    // squashfs (`mksquashfs` deterministic mode); the §21 switch_root
    // mounts `/dev/mapper/hippius-rootfs` with `mount(2)` against the
    // candidate fstypes `["erofs", "squashfs"]`. Both ship `=m` in
    // Debian Trixie's 6.12 kernel, so `mount(2)` returns ENODEV until
    // the driver is in the running kernel. Observed live 2026-05-28:
    // post-verity activation, boot fail-closed at
    // `switch-root-failed:mount-rootfs` because the kernel had no
    // squashfs handler. squashfs has no `depends:` field — single-
    // module family. (erofs lives next to it; we don't stage it
    // because the build only produces squashfs. The switch_root
    // candidate loop's erofs attempt returns ENODEV harmlessly and
    // the loop moves on to squashfs.)
    let rootfs_fs: &[(&str, &'static str, &'static str)] = &[(
        "fs/squashfs/squashfs",
        "rootfs-fs-read-squashfs",
        "rootfs-fs-load-squashfs",
    )];

    // #257 BYO base-OS (`hippius.handoff=tenant-luks`): the tenant
    // LUKS volume IS the rootfs and ships an ext4 (or xfs / btrfs)
    // filesystem from the vanilla cloud image baked in at
    // `tenant-image-bake.sh --base-image-url` time. In Trixie's
    // 6.12 kernel `CONFIG_EXT4_FS=m`, so without staging+loading
    // ext4 (plus its deps) the BYO-OS pivot's `mount(2)` returns
    // ENODEV on every candidate and fail-closes at
    // `switch-root-failed:mount-rootfs` (observed live 2026-05-28,
    // first attempt at booting Ubuntu 24.04 cloud-image into the
    // post-#258 TenantLuks pivot). `ext4.ko` declares
    // `depends: jbd2,crc16,mbcache` — load chain matches.
    //
    // ManagedRootfs UKIs (the legacy verity path) leave this family
    // staged but unused: the per-family skip semantics in
    // `load_module_family` mean a UKI that did NOT bundle ext4.ko
    // simply skips this family at runtime, with no error. So the
    // same agent binary serves both UKI flavours without code
    // branches — same precedent as the managed-rootfs squashfs
    // family above.
    let tenant_luks_fs: &[(&str, &'static str, &'static str)] = &[
        ("fs/jbd2/jbd2", "rootfs-fs-read-jbd2", "rootfs-fs-load-jbd2"),
        ("lib/crc16", "rootfs-fs-read-crc16", "rootfs-fs-load-crc16"),
        (
            "fs/mbcache",
            "rootfs-fs-read-mbcache",
            "rootfs-fs-load-mbcache",
        ),
        ("fs/ext4/ext4", "rootfs-fs-read-ext4", "rootfs-fs-load-ext4"),
    ];

    load_module_family(release, vsock)?;
    load_module_family(release, virtio_net)?;
    load_module_family(release, virtio_blk)?;
    load_module_family(release, dm_crypt_aes)?;
    load_module_family(release, dm_verity)?;
    load_module_family(release, rootfs_fs)?;
    load_module_family(release, tenant_luks_fs)?;
    load_module_family(release, sev_guest)?;
    Ok(())
}

/// Insert one `(rel, read_class, load_class)` family of modules in
/// the order given. The first module's existence is the "did the
/// UKI bundle this family?" probe — absent → clean skip; present →
/// every entry must load (modulo `EEXIST` for already-builtin).
#[cfg(target_os = "linux")]
fn load_module_family(
    release: &str,
    family: &[(&str, &'static str, &'static str)],
) -> Result<(), &'static str> {
    use nix::errno::Errno;
    use nix::kmod::init_module;
    use std::ffi::CString;

    let Some((first_rel, _, _)) = family.first() else {
        return Ok(());
    };
    let first_path = format!("/lib/modules/{release}/kernel/{first_rel}.ko");
    if !std::path::Path::new(&first_path).exists() {
        return Ok(());
    }
    // Empty params — none of the modules we load take parameters.
    // `CString::new("")` is infallible; the `map_err` is for
    // type-system completeness only.
    let no_params = CString::new("").map_err(|_| "kmod-modules-params")?;
    for (rel, read_class, load_class) in family {
        let path = format!("/lib/modules/{release}/kernel/{rel}.ko");
        let bytes = std::fs::read(&path).map_err(|_| *read_class)?;
        match init_module(&bytes, &no_params) {
            Ok(()) => {}
            // CONFIG_VSOCKETS=y or virtio-net builtin (future kernel)
            // returns EEXIST — that's success.
            Err(Errno::EEXIST) => {}
            Err(_) => return Err(*load_class),
        }
    }
    Ok(())
}

/// Non-Linux dev / CI host: `init_module(2)` is a Linux syscall and
/// the tenant UKI cpio doesn't ship on a macOS dev tree anyway.
/// Mirrors `mount_initramfs_filesystems`'s non-Linux stub.
#[cfg(not(target_os = "linux"))]
fn load_kernel_modules() -> Result<(), &'static str> {
    Ok(())
}

/// The §21 boot pipeline entry point. Never returns on the happy path
/// (`switch_root` `execve`s the guest init); every other outcome powers
/// the VM off via [`fail_closed`].
fn run_boot() -> ExitCode {
    // §20 production hardening — refuse to boot unless the measured
    // kernel command line carries the hardened profile (no debug shell,
    // no kdump, `panic>=1`, `ds=nocloud`). The cmdline is folded into
    // the SNP launch measurement, so asserting it is asserting the
    // measurement is the hardened image. Linux-only — `/proc/cmdline`
    // is a Linux interface; a non-Linux dev host never performs a real
    // boot. See `stages::hardening`.
    #[cfg(target_os = "linux")]
    {
        use hippius_agent_initramfs::assert_hardened_cmdline;
        let cmdline = match std::fs::read_to_string("/proc/cmdline") {
            Ok(c) => c,
            Err(_) => return fail_closed("cmdline-read"),
        };
        if let Err(err) = assert_hardened_cmdline(&cmdline) {
            return fail_closed_err(err);
        }
    }
    // §20 serial-console suppression — stop kernel messages echoing to
    // the serial console for the rest of the boot (covers the entire
    // secret-handling window: KBS release → verify → seed). A no-op on
    // a non-Linux dev host.
    if let Err(err) = suppress_kernel_console() {
        return fail_closed_err(err);
    }

    // Bring up `eth0` + lease an IPv4 from the libvirt-NAT DHCP
    // server + write `/etc/resolv.conf` BEFORE the first KBS HTTPS
    // call. virtio_net is `=m` in Debian Trixie 6.12, so without
    // this `ReqwestHttpClient::post_cbor` fails closed at the very
    // first connect (`kbs-connect` ~0.9 s after `/init` started —
    // observed live 2026-05-25 post-#190). The vsock ticket-recv
    // stage is independent of TCP/IP, so running network bring-up
    // before it (rather than splitting `run` into two halves) keeps
    // the orchestration linear and the per-stage error classes
    // distinct (`network-failed` vs `ticket-failed` vs `kbs-failed`).
    if let Err(err) = bring_up_dhcp() {
        return fail_closed_err(err);
    }

    let provider = snp_provider();
    let unlocker = luks_unlocker();
    let verity = verity_opener();
    let pivot = rootfs_pivot();
    let seed_writer = RealSeedWriter::new();

    // KBS HTTP transport — a `reqwest`/`rustls` blocking client with
    // the §20 strict connect (5 s) + request (30 s) timeouts baked in.
    let http = match ReqwestHttpClient::new() {
        Ok(h) => h,
        Err(err) => return fail_closed(err.class()),
    };

    // KBS base URL + LUKS backing device: the `HIPPIUS_*` env var (dev
    // / override), else the `hippius.*=` token on the measured UKI's
    // kernel command line. Absent both ⇒ fail closed.
    let kbs_url = match resolve_kbs_url() {
        Ok(url) => url,
        Err(err) => return fail_closed(err.class()),
    };
    let luks_device = match resolve_luks_device() {
        Ok(device) => device,
        Err(err) => return fail_closed(err.class()),
    };
    // Resolve the boot-handoff mode (`hippius.handoff=` cmdline token,
    // measured; dev override via `HIPPIUS_HANDOFF`). Default
    // `tenant-luks` — see [`resolve_handoff_mode`] docs and #257.
    let handoff = resolve_handoff_mode();

    // dm-verity inputs are only consumed in `ManagedRootfs` mode; the
    // BYO base-OS path skips the verity stage entirely (the LUKS
    // volume IS the rootfs). Resolving them in `TenantLuks` mode
    // would also fail-close on a tenant UKI cmdline that no longer
    // carries `dm-verity.root=` / `hippius.rootfs_*=`.
    let (rootfs_data_device, rootfs_hash_device, rootfs_root_hash) = match handoff {
        HandoffMode::ManagedRootfs => {
            // Defaults are `/dev/vdb` + `/dev/vdc` — the second + third
            // virtio-blk disks the miner-agent attaches. Cmdline tokens
            // `hippius.rootfs_data=` / `hippius.rootfs_hash=` override
            // (measured); env vars override above that (dev only). The
            // root hash is the launch-digest-covered
            // `dm-verity.root=<64-hex>` token — an unparseable or
            // absent value is fail-closed by `resolve_verity_root_hash`.
            let (data, hash) = match resolve_rootfs_devices() {
                Ok(pair) => pair,
                Err(err) => return fail_closed_err(err),
            };
            let root_hash = match resolve_verity_root_hash() {
                Ok(h) => h,
                Err(err) => return fail_closed_err(err),
            };
            (data, hash, root_hash)
        }
        HandoffMode::TenantLuks => (String::new(), String::new(), [0u8; 32]),
    };

    let mut cfg = Config::from_skeleton_defaults();
    cfg.kbs_base_url = kbs_url;
    cfg.luks_device = luks_device;
    // The NoCloud seed dir is a pinned constant — referenced by the
    // measured image, not configurable (see `stages::seed`).
    cfg.nocloud_tmpfs_dir = NOCLOUD_SEED_DIR.to_string();
    cfg.handoff = handoff;
    // Pivot target depends on mode:
    //   - ManagedRootfs: the dm-verity mapper the verity stage opens.
    //   - TenantLuks (#257): the unlocked LUKS data mapper from the
    //     `unlock` stage IS the rootfs.
    cfg.rootfs_device = match handoff {
        HandoffMode::ManagedRootfs => ROOTFS_MAPPER.to_string(),
        HandoffMode::TenantLuks => format!("/dev/mapper/{LUKS_MAPPER_NAME}"),
    };
    // Kernel release — only needed for the BYO-OS bind-mount of
    // `/lib/modules/<release>` into the tenant rootfs. Resolve via
    // `uname(2)` so a kernel version bump flows through without code
    // change (same pattern as `load_kernel_modules`). On non-Linux
    // dev hosts `uname` is unavailable; the pipeline never reaches
    // `switch_root` on those (the canned SNP report fails KBS
    // verification far earlier).
    if handoff == HandoffMode::TenantLuks {
        match resolve_kernel_release() {
            Ok(r) => cfg.kernel_release = r,
            Err(class) => return fail_closed(class),
        }
    }
    cfg.rootfs_data_device = rootfs_data_device;
    cfg.rootfs_hash_device = rootfs_hash_device;
    cfg.rootfs_root_hash = rootfs_root_hash;
    // §E1 wire-up 3/3 — pin the KBS response-signing trust anchors
    // from the UKI-embedded compile-time constants. A cmdline-
    // overridable trust anchor would defeat the §20 model (the host
    // miner could substitute its own KBS); see
    // `trust_anchors.rs` for the lockstep ledger that keeps this
    // const in sync with `deploy/gitops/apps/kbs/values.yaml` +
    // `test_vectors/allowlist/dev-manifest.toml`.
    cfg.pinned_kbs_vk = PINNED_KBS_RESPONSE_VK;
    cfg.pinned_kbs_kid = PINNED_KBS_RESPONSE_KID.to_vec();
    // Ticket source: a `vsock://` URI dispatches `stages::ticket::load`
    // to the host→guest AF_VSOCK receiver
    // (`stages::ticket_vsock::recv_ticket`). The expected source CID is
    // pinned at `2` (the host) inside the receiver — the segment shown
    // in the URI is informational only. The miner-agent pushes the
    // L1-minted COSE OrderTicket on `hippius_types::ticket_vsock::PORT`
    // after the libvirt domain reaches `Running`; this URI tells the
    // pipeline to listen for it.
    cfg.ticket_path = format!("vsock://2:{}", hippius_types::ticket_vsock::PORT);

    match run(
        &cfg,
        provider.as_ref(),
        &http,
        unlocker.as_ref(),
        verity.as_ref(),
        &seed_writer,
        pivot.as_ref(),
    ) {
        // Reached only if `switch_root` did not pivot (a stub, or the
        // non-Linux `MockRootfsPivot`). On a real boot this is a bug —
        // power off rather than fall through to a shell prompt.
        Ok(()) => {
            log_fatal("pipeline-returned-without-pivot");
            let _ = poweroff();
            ExitCode::from(EXIT_DID_NOT_PIVOT)
        }
        // §20 "no plaintext to logs": [`fail_closed_err`] surfaces
        // `class():sub_class()` — every sub-class string is a
        // compile-time `&'static str` per [`AgentError::sub_class`]
        // (the §20 plaintext-free invariant is structural). Without
        // the sub-class an operator triaging a `luks-failed` cannot
        // distinguish `crypt-init` (block-device race / missing
        // virtio_blk) from `header-load` (wrong device / corrupt
        // header) from `activate` (wrong released key) — observed
        // 2026-05-27 on the post-virtio_blk-bundle live boot, where
        // the family-only `luks-failed` collapsed all three.
        Err(err) => fail_closed_err(err),
    }
}

/// The §24/§25 end-of-life subcommand. Resolves the `StoppedAck` inputs,
/// runs [`run_eol`], and — whatever happens — ends in a poweroff. Never
/// returns on the expected path (`run_eol` → `poweroff`).
fn run_eol_subcommand() -> ExitCode {
    let sink = eol_sink();

    // Assemble the signed-ack inputs. If the identity / vali URL / HTTP
    // transport cannot be resolved we still tear down + power off
    // (fail-closed) via the shared `eol_teardown` — just without an
    // audit ack. Every path ends in a poweroff.
    match eol_push_inputs() {
        Some((key, params, vali_url)) => match eol_http_for(&vali_url) {
            Ok(http) => {
                let _ = run_eol(key, &params, &vali_url, http.as_ref(), sink.as_ref());
            }
            // No HTTP transport — skip the signed-ack push, but run the
            // same teardown + poweroff `run_eol` would have.
            Err(_) => {
                log_fatal("eol-http-unavailable");
                let _ = eol_teardown(sink.as_ref());
            }
        },
        // No resolvable VM identity — no ack is possible; still tear
        // down the dm-crypt mapping and power off.
        None => {
            log_fatal("eol-inputs-unresolved");
            let _ = eol_teardown(sink.as_ref());
        }
    }
    // `run_eol` / `eol_teardown` return only if the poweroff syscall
    // itself failed.
    log_fatal("eol-poweroff-failed");
    ExitCode::from(EXIT_FAIL_CLOSED)
}

/// The §25 systemd-shutdown-hook EOL subcommand (`eol --sign-only`).
///
/// Signs + best-effort-pushes the `StoppedAck`, then RETURNS — it does
/// NOT tear down dm-crypt or power off (systemd owns those on this
/// path). Always exits `0`: a sign/push miss is swallowed (fail-closed
/// audit, never a failed shutdown), and there is no poweroff syscall to
/// fail. The fence is enforced vali-side on the VERIFIED ack — an absent
/// ack just times the migration / decommission out (never advances).
fn run_eol_sign_only_subcommand() -> ExitCode {
    match eol_push_inputs() {
        Some((key, params, vali_url)) => match eol_http_for(&vali_url) {
            Ok(http) => run_eol_sign_only(key, &params, &vali_url, http.as_ref()),
            // No HTTP transport — no push is possible; log + still exit 0
            // so systemd's shutdown proceeds (fail-closed audit).
            Err(_) => log_fatal("eol-http-unavailable"),
        },
        // No resolvable VM identity — no ack is possible; log + exit 0.
        None => log_fatal("eol-inputs-unresolved"),
    }
    ExitCode::SUCCESS
}

/// Pick the EOL stopped-ack transport from the `hippius.vali_url` scheme,
/// mirroring how the §21 boot pipeline selects its KBS transport from
/// `hippius.kbs_url`.
///
/// - `vsock://CID:PORT` ⇒ [`VsockHttpClient`] — the DEFAULT. The
///   confidential guest has NO IP route to the in-cluster vali, so the
///   ack rides the host vsock proxy (the same channel the KBS release
///   exchange uses); the miner-agent forwards the opaque bytes to vali's
///   `/v1/lifecycle/stopped` ingress.
/// - anything else (`https://…`) ⇒ [`ReqwestHttpClient`] — the legacy IP
///   path, used only where a direct route to vali exists.
///
/// Returns `Err(())` only if the reqwest client cannot be built; the
/// vsock client is infallible to construct (stateless), so the default
/// path never fails here.
fn eol_http_for(vali_url: &str) -> Result<Box<dyn HttpClient>, ()> {
    if is_vsock_url(vali_url) {
        Ok(Box::new(VsockHttpClient::new()))
    } else {
        ReqwestHttpClient::new()
            .map(|c| Box::new(c) as Box<dyn HttpClient>)
            .map_err(|_| ())
    }
}

/// Resolve the §24 EOL inputs from env vars / the kernel command line.
///
/// Returns `Some((lifecycle_key, params, vali_url))` once the VM
/// identity, the nonce and the vali URL have all resolved. The
/// lifecycle key is `None` when its file could not be read — the EOL
/// path then skips the signed-ack push but still tears down + powers
/// off, per the fail-closed contract. Returns `None` outright if the
/// identity itself is unresolvable.
fn eol_push_inputs() -> Option<(Option<SigningKey>, StoppedAckParams, String)> {
    let cmdline = read_cmdline();
    let get = |env: &str, key: &str| resolve_value(&cmdline, env, key);

    let vm_id = get("HIPPIUS_EOL_VM_ID", "hippius.vm_id")?;
    let lease_id = get("HIPPIUS_EOL_LEASE_ID", "hippius.lease_id")?;
    let vm_generation = get("HIPPIUS_EOL_VM_GENERATION", "hippius.vm_generation")?
        .parse::<u64>()
        .ok()?;
    let nonce = decode_hex_32(&get("HIPPIUS_EOL_NONCE", "hippius.eol_nonce")?)?;
    let vali_url = get("HIPPIUS_VALI_URL", "hippius.vali_url")?;

    // The lifecycle key is optional — a missing / unreadable key file
    // means an unsigned EOL (still teardown + poweroff), never an abort.
    let lifecycle_key = get("HIPPIUS_LIFECYCLE_KEY_PATH", "hippius.lifecycle_key_path")
        .and_then(|path| load_lifecycle_key(&path));

    let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        // A guest clock before the Unix epoch — log the skew (static
        // class, no secret) and sign with `0`; the orchestrator
        // sanity-checks the stop time vali-side regardless.
        Err(_) => {
            log_fatal("eol-clock-skew");
            0
        }
    };

    let params = StoppedAckParams {
        vm_id,
        lease_id,
        vm_generation,
        nonce,
        now_unix,
    };
    Some((lifecycle_key, params, vali_url))
}

/// Read the 32-byte Ed25519 lifecycle-key seed from `path` into a
/// `SigningKey` for the §24/§25 EOL ack.
///
/// §20 secret discipline: the seed is read straight into a
/// `Zeroizing<Vec<u8>>` and copied — with **no** bare `[u8; 32]`
/// transient — into a `Zeroizing<[u8; 32]>` via `copy_from_slice`, so
/// every copy of the raw seed wipes on drop (`SigningKey` is itself
/// `ZeroizeOnDrop` — the crate enables ed25519-dalek's `zeroize`
/// feature). The read is **bounded** to 33 bytes so a wrong / hostile
/// key path cannot OOM the EOL process before `eol_teardown` runs.
///
/// `None` on any error (missing file, wrong length, …) — the EOL path
/// then runs unsigned; it never aborts.
fn load_lifecycle_key(path: &str) -> Option<SigningKey> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    // 33-byte cap: exactly 32 is required; the extra byte detects an
    // over-long file without slurping an unbounded stream.
    file.take(33).read_to_end(&mut buf).ok()?;
    if buf.len() != 32 {
        return None;
    }
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(buf.as_slice());
    Some(SigningKey::from_bytes(&seed))
}

/// Read `/proc/cmdline`, or `""` if it cannot be read (a non-Linux dev
/// host, or an environment without `/proc`). Callers fall back to env
/// vars, so an empty cmdline is not fatal here.
fn read_cmdline() -> String {
    std::fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

/// Resolve a value: the `env` var first (dev / explicit override), then
/// the `cmdline_key=` token in `/proc/cmdline`. An empty value counts
/// as absent. Mirrors the precedence in `resolve_kbs_url` /
/// `resolve_luks_device`.
fn resolve_value(cmdline: &str, env: &str, cmdline_key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(env) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let prefix = format!("{cmdline_key}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Decode exactly 32 bytes from a 64-character hex string. Returns
/// `None` on any wrong length or non-hex character.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Fail-closed terminal handler: log the static error class, then power
/// the VM off (§20 — never a shell, never a lingering inspectable
/// state). `poweroff()` returns only if the syscall failed (or on a
/// non-Linux dev host), in which case the non-zero `ExitCode` is the
/// last-resort fallback.
fn fail_closed(class: &'static str) -> ExitCode {
    log_fatal(class);
    let _ = poweroff();
    ExitCode::from(EXIT_FAIL_CLOSED)
}

/// Variant of [`fail_closed`] that takes an [`AgentError`] and surfaces
/// its `sub_class()` via [`log_fatal_err`]. Same poweroff + non-zero
/// `ExitCode` posture.
fn fail_closed_err(err: hippius_agent_initramfs::AgentError) -> ExitCode {
    log_fatal_err(&err);
    let _ = poweroff();
    ExitCode::from(EXIT_FAIL_CLOSED)
}

/// Construct the `SnpReportProvider` for this build target.
///
/// - Linux/x86_64: real `SevGuestProvider` — opens `/dev/sev-guest`.
/// - Anything else (e.g. macOS dev host): `MockSnpReportProvider` —
///   the pipeline shape is exercisable but every downstream stage fails
///   closed (the canned blob carries no AMD signature).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn snp_provider() -> Box<dyn SnpReportProvider> {
    Box::new(hippius_agent_initramfs::SevGuestProvider::new())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn snp_provider() -> Box<dyn SnpReportProvider> {
    use hippius_agent_initramfs::{MockSnpReportProvider, SNP_REPORT_LEN};
    Box::new(MockSnpReportProvider::new(vec![0u8; SNP_REPORT_LEN]))
}

/// Construct the `LuksUnlocker` for this build target. Linux:
/// `RealLuksUnlocker` (real `libcryptsetup`). Non-Linux: `MockLuksUnlocker`.
#[cfg(target_os = "linux")]
fn luks_unlocker() -> Box<dyn LuksUnlocker> {
    Box::new(hippius_agent_initramfs::RealLuksUnlocker::new())
}

#[cfg(not(target_os = "linux"))]
fn luks_unlocker() -> Box<dyn LuksUnlocker> {
    use hippius_agent_initramfs::MockLuksUnlocker;
    Box::new(MockLuksUnlocker::new())
}

/// Construct the `RootfsVerity` opener for this build target. Linux:
/// `RealRootfsVerity` (real `libcryptsetup` dm-verity). Non-Linux:
/// `MockRootfsVerity::ok()` — the canned SNP report fails KBS
/// verification long before the verity stage runs on a non-Linux
/// dev host, but the trait shape stays exercisable.
#[cfg(target_os = "linux")]
fn verity_opener() -> Box<dyn RootfsVerity> {
    Box::new(hippius_agent_initramfs::RealRootfsVerity::new())
}

#[cfg(not(target_os = "linux"))]
fn verity_opener() -> Box<dyn RootfsVerity> {
    use hippius_agent_initramfs::MockRootfsVerity;
    Box::new(MockRootfsVerity::ok())
}

/// Construct the `RootfsPivot` for this build target. Linux:
/// `RealRootfsPivot` (real `mount`/`chroot`/`execv`). Non-Linux:
/// `MockRootfsPivot` (the pipeline never reaches it on a non-Linux
/// build — the canned SNP report fails KBS verification far earlier).
#[cfg(target_os = "linux")]
fn rootfs_pivot() -> Box<dyn RootfsPivot> {
    Box::new(hippius_agent_initramfs::RealRootfsPivot::new())
}

#[cfg(not(target_os = "linux"))]
fn rootfs_pivot() -> Box<dyn RootfsPivot> {
    use hippius_agent_initramfs::MockRootfsPivot;
    Box::new(MockRootfsPivot::new())
}

/// Construct the `EolSink` for this build target. Linux: `RealEolSink`
/// (real `libcryptsetup` deactivate + `reboot(2)`). Non-Linux:
/// `MockEolSink`.
#[cfg(target_os = "linux")]
fn eol_sink() -> Box<dyn EolSink> {
    Box::new(hippius_agent_initramfs::RealEolSink::new())
}

#[cfg(not(target_os = "linux"))]
fn eol_sink() -> Box<dyn EolSink> {
    use hippius_agent_initramfs::MockEolSink;
    Box::new(MockEolSink::new())
}

/// Emit a single static diagnostic to stderr. §20: no seed bytes / no
/// plaintext to the serial console. The argument MUST be `&'static str`
/// (or already-statically-classified — see `AgentError::class`);
/// production must NOT introduce a `&str` overload that takes arbitrary
/// formatted text. Enforced crate-wide by `tests/no_seed_logging.rs`.
fn log_fatal(class: &'static str) {
    eprintln!("hippius-agent-initramfs: fail-closed: {class}");
}

/// Variant of [`log_fatal`] that surfaces the [`AgentError`] sub-class
/// when present, emitting `"family:sub-class"` instead of the
/// family-only collapse. Solves the #200 / #202 diagnosis-time
/// invisibility — the family `"network-failed"` told us a network
/// stage tripped, but hid which sub-class (`mac-read` vs `mac-parse`
/// vs `netlink-deserialize`), forcing an iterative debug-initrd
/// rebuild to find each one. With the sub-class surfaced, the next
/// race-window sub-class self-reports on serial.
///
/// §20 plaintext-free invariant preserved: every emitted string is a
/// compile-time `&'static str` literal embedded in this binary — the
/// `class()` family name from `AgentError::class` and the
/// `sub_class()` tag from `AgentError::sub_class`.
fn log_fatal_err(err: &hippius_agent_initramfs::AgentError) {
    match err.sub_class() {
        Some(sub) => eprintln!(
            "hippius-agent-initramfs: fail-closed: {}:{}",
            err.class(),
            sub,
        ),
        None => eprintln!("hippius-agent-initramfs: fail-closed: {}", err.class()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock the PID-1 gate against a refactor that "simplifies" it
    /// away — without the gate, calling `mount_initramfs_filesystems`
    /// from a test would attempt a real `mount(2)` on the CI host's
    /// `/proc` / `/sys` / `/dev` / `/run`.
    ///
    /// Containerized CI sometimes runs the test binary as the
    /// container entrypoint (so the runner IS PID 1) — `cargo test`
    /// under `docker run --init=false`, certain nextest setups
    /// (review r2 P2). In that case the test skips with a stderr note
    /// rather than driving a real mount; the dev-VM CI path
    /// (`~/bin/run-ci-locally.sh`) runs the binary natively, so the
    /// gate is exercised there.
    #[test]
    fn mount_initramfs_filesystems_skips_when_not_pid_one() {
        if std::process::id() == 1 {
            eprintln!(
                "skipping: test runner is PID 1 (containerized env) — \
                 the gate would NOT short-circuit; refusing to mount(2) the host."
            );
            return;
        }
        mount_initramfs_filesystems().expect("non-PID-1 invocation must be a successful no-op");
    }

    /// Same lock as the mount test, for the vsock module loader. On a
    /// non-PID-1 invocation the function MUST short-circuit before
    /// touching `init_module(2)` (which would either be a no-op or
    /// hit `EPERM`/`EEXIST` depending on the host kernel — neither is
    /// what we want to assert here). On a containerized PID-1 test
    /// runner we skip, mirroring `mount_initramfs_filesystems_skips_…`.
    #[test]
    fn load_kernel_modules_skips_when_not_pid_one() {
        if std::process::id() == 1 {
            eprintln!(
                "skipping: test runner is PID 1 (containerized env) — \
                 the gate would NOT short-circuit; refusing to call init_module(2)."
            );
            return;
        }
        load_kernel_modules().expect("non-PID-1 invocation must be a successful no-op");
    }
}
