//! Stage 9 — `switch_root` into the dm-verity rootfs (PR-E1.5, §21
//! step 13 / §11).
//!
//! The dm-verity rootfs device is activated by the initramfs bootstrap
//! (§F PR-F3 — its root hash is embedded in the measured UKI); this
//! stage assumes the verity-mapped device is ready at
//! `/dev/mapper/hippius-rootfs` and performs the final pivot:
//!
//! 1. mount the verity rootfs **read-only** on `/sysroot`,
//! 2. move-mount the kernel virtual filesystems `/dev`, `/proc`, `/sys`
//!    and `/run` into `/sysroot` — `/run` carries the NoCloud tmpfs
//!    seed (§21 step 12) across the pivot so cloud-init in the new root
//!    can still read it,
//! 3. `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`,
//!    `chdir("/")` — the initramfs-rootfs `switch_root` dance (an
//!    initramfs cannot `pivot_root(2)` out of itself; `MS_MOVE` + a
//!    `chroot` is the kernel-sanctioned equivalent),
//! 4. `execv("/sbin/init")` — the guest OS init. **Does not return.**
//!
//! Any failure — verity device absent, an unexpected block-device
//! layout, a mount error — is fail-closed: the boot aborts (the KBS
//! release is already spent, so a retry needs a fresh ticket, §14).
//!
//! ## Why a trait (mirrors `LuksUnlocker`, PR-E1.4)
//!
//! The pivot ends in `execv(2)` — utterly untestable from `cargo test`
//! and destructive if it ran. So the cross-platform [`RootfsPivot`]
//! trait + [`MockRootfsPivot`] live here, and the real
//! [`RealRootfsPivot`] is gated to `target_os = "linux"` (it drives
//! `mount(2)` / `chroot(2)` / `execv(2)` via `nix`). The §21 pipeline
//! holds `&dyn RootfsPivot`; tests inject the mock, so `cargo test`
//! never mounts or `execv`s.
//!
//! ## Secret discipline (§20)
//!
//! By the time the pipeline reaches this stage, every secret-bearing
//! value — the X25519 scalar, the LUKS key, the user-data plaintext —
//! has already been consumed + `Zeroizing`-dropped by the earlier
//! stages ([`crate::stages::verify`] / `unlock` / `seed`). This stage
//! takes **no** secret input, so the `execv(2)` bypass of `Drop` is
//! safe: there is nothing live left to wipe. The compile-gate test
//! pins the by-value signatures upstream that guarantee it.

use crate::pipeline::AgentError;
use core::cell::RefCell;

/// Pinned device-mapper path of the dm-verity rootfs. The initramfs
/// bootstrap (§F PR-F3) activates verity under this fixed name before
/// `/init` runs; this stage assumes it is ready. Fixed (not
/// configurable): the measured initramfs references this exact path, so
/// a per-boot name would break the §11 boot chain.
pub const ROOTFS_MAPPER: &str = "/dev/mapper/hippius-rootfs";

/// Stable classifier strings for [`AgentError::SwitchRoot`]. Several
/// are raised only by the Linux-only `RealRootfsPivot` — hence the
/// non-Linux `dead_code` allowance (on Linux every entry is reachable).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod cat {
    /// Mounting the rootfs device on `/sysroot` failed for every
    /// candidate filesystem type — the device is absent, or its layout
    /// is not what the measured UKI attested (§11). In BYO-OS mode
    /// (`hippius.handoff=tenant-luks`), this fires if the tenant's
    /// LUKS volume carries no filesystem the agent recognises.
    pub(crate) const MOUNT_ROOTFS: &str = "mount-rootfs";
    /// Move-mounting a kernel virtual filesystem (`/dev`, `/proc`,
    /// `/sys`, `/run`) into `/sysroot` failed.
    pub(crate) const MOVE_MOUNT: &str = "move-mount";
    /// `chdir` into the new root failed.
    pub(crate) const CHDIR: &str = "chdir";
    /// `mount(".", "/", MS_MOVE)` — relocating the new root onto `/` —
    /// failed.
    pub(crate) const MOVE_ROOT: &str = "move-root";
    /// `chroot` into the new root failed.
    pub(crate) const CHROOT: &str = "chroot";
    /// `execv("/sbin/init")` failed — the new root carries no init, or
    /// it is not executable. (A *successful* `execv` never returns.)
    pub(crate) const EXECV: &str = "execv";
    /// Bind-mounting the initramfs's kernel-modules tree into
    /// `/sysroot/lib/modules/<kver>` failed. BYO-OS mode only — the
    /// tenant's userspace runs Hippius's measured kernel, so
    /// `modprobe`'d modules MUST resolve to the matching `/lib/modules/
    /// <kver>` tree (or every `modprobe` returns ENOENT and half the
    /// tenant's cloud-init silently fails). Mirrors the standard
    /// initrd-to-root module handoff pattern (dracut / mkinitcpio).
    pub(crate) const MODULES_BIND: &str = "modules-bind";
}

/// What kind of rootfs the §21 pivot is targeting.
///
/// Same final `switch_root` mechanics either way — the difference is
/// what gets mounted at `/sysroot`, with which fstype candidate list,
/// and whether the agent first bind-mounts Hippius's measured kernel-
/// modules tree into the tenant's rootfs so the tenant's userspace
/// can `modprobe` everything the running kernel ships.
#[derive(Debug, Clone)]
pub enum PivotMode {
    /// **Managed-rootfs**: mount the §F dm-verity rootfs (squashfs /
    /// erofs, read-only) and pivot into Hippius's measured Debian
    /// runtime. The legacy default — every PR through #256 ships this.
    /// Kept as a fallback / dev option behind `hippius.handoff=
    /// managed-rootfs` once BYO-OS becomes default.
    ManagedRootfs,
    /// **Tenant-LUKS (BYO base-OS, #257)**: mount the unlocked
    /// per-VM LUKS data volume (which IS the tenant's chosen
    /// Ubuntu / Debian / CentOS cloud-image rootfs) read-write at
    /// `/sysroot`, bind-mount the running kernel's modules tree into
    /// it, then pivot. Hippius's measured kernel runs the tenant's
    /// userspace. The trust model holds because the kernel +
    /// initramfs are still measured (the bouncer); the disk is
    /// encrypted with the per-VM KEK the miner does not have; and
    /// everything Hippius does in this VM ends at the pivot —
    /// after `execv`, the tenant's `/sbin/init` (e.g. systemd) is
    /// PID 1 and Hippius has no foothold. The agent's measured
    /// kernel-modules tree path passes through `kernel_release`
    /// (`uname(2).release`) so a kernel bump flows without code
    /// change — same precedent as `main::load_kernel_modules`.
    TenantLuks {
        /// Hippius kernel release (= `uname(2).release`), so the agent
        /// knows which `/lib/modules/<release>` to bind-mount.
        kernel_release: String,
    },
}

/// Configuration for the §21 pivot stage. Mirrors the trait-config
/// pattern the other stages use (LuksUnlocker / RootfsVerity) — the
/// pipeline assembles this once and hands a borrow to the pivot impl.
#[derive(Debug, Clone)]
pub struct PivotConfig {
    /// Block device to mount at `/sysroot`. `ManagedRootfs` mode points
    /// it at [`ROOTFS_MAPPER`] (the dm-verity mapper); `TenantLuks`
    /// mode points it at the unlocked LUKS data device (typically
    /// `/dev/mapper/hippius-data`, see
    /// [`crate::stages::unlock::MAPPER_NAME`]).
    pub rootfs_device: String,
    /// Which pivot mode we're driving.
    pub mode: PivotMode,
}

/// Filesystem types tried (in order) for the managed dm-verity rootfs.
/// `erofs` and `squashfs` are the two formats the §F image factory
/// produces. The raw `mount(2)` syscall needs an explicit fstype
/// (unlike `mount(8)` it does not probe), so the pivot tries each.
#[cfg(target_os = "linux")]
const MANAGED_ROOTFS_FSTYPES: &[&str] = &["erofs", "squashfs"];

/// Filesystem types tried (in order) for the BYO-OS LUKS volume —
/// the formats vanilla cloud images use. `ext4` is overwhelmingly the
/// most common (Ubuntu cloud, Debian generic, CentOS Stream all
/// default to it); `xfs` covers Rocky / AlmaLinux; `btrfs` covers
/// Fedora cloud + openSUSE. Probed in popularity order. Same raw
/// `mount(2)` no-probe constraint as the managed list.
#[cfg(target_os = "linux")]
const TENANT_LUKS_FSTYPES: &[&str] = &["ext4", "xfs", "btrfs"];

/// Performs the final §21 `switch_root` pivot into the chosen rootfs.
///
/// Production: [`RealRootfsPivot`] (Linux). Tests + non-Linux dev hosts:
/// [`MockRootfsPivot`]. The §21 pipeline holds this as
/// `&dyn RootfsPivot`.
pub trait RootfsPivot {
    /// Mount the rootfs described by `cfg`, move the kernel virtual
    /// filesystems across, and `execv` the guest init.
    ///
    /// On success this **does not return** (`execv(2)` replaces the
    /// process image). Every return is therefore an `Err` — fail-closed.
    fn pivot_into_rootfs(&self, cfg: &PivotConfig) -> Result<(), AgentError>;
}

/// Stage entry function — perform the pivot via `pivot`.
///
/// A thin forwarder kept for parity with the other §21 stage modules.
pub fn pivot(pivot: &dyn RootfsPivot, cfg: &PivotConfig) -> Result<(), AgentError> {
    pivot.pivot_into_rootfs(cfg)
}

// ── Production implementation (Linux only) ──────────────────────────

/// Production [`RootfsPivot`] — drives the real `mount(2)` / `chroot(2)`
/// / `execv(2)` syscalls via `nix`.
///
/// Zero-sized + stateless. Linux-only: the syscalls + the `nix`
/// dependency only exist there. A non-Linux dev build uses
/// [`MockRootfsPivot`] (see [`crate::main`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct RealRootfsPivot;

#[cfg(target_os = "linux")]
impl RealRootfsPivot {
    /// Construct a pivot. No-op (stateless); kept as an explicit entry
    /// point for parity with the other stage providers.
    pub fn new() -> Self {
        Self
    }
}

/// Mount point the verity rootfs is staged at before the pivot.
#[cfg(target_os = "linux")]
const SYSROOT: &str = "/sysroot";

/// Kernel virtual filesystems moved into the new root, in order. `/run`
/// is included so the NoCloud tmpfs seed (§21 step 12) survives the
/// pivot for cloud-init to consume.
#[cfg(target_os = "linux")]
const VIRTUAL_FS: &[&str] = &["/dev", "/proc", "/sys", "/run"];

#[cfg(target_os = "linux")]
impl RootfsPivot for RealRootfsPivot {
    fn pivot_into_rootfs(&self, cfg: &PivotConfig) -> Result<(), AgentError> {
        use nix::mount::{mount, MsFlags};
        use nix::unistd::{chdir, chroot, execv};
        use std::ffi::CString;
        use std::path::Path;

        // 1. Mount the chosen rootfs on /sysroot. Ensure the mountpoint
        //    exists first — a measured initramfs cpio should ship
        //    `/sysroot`, but creating it is idempotent.
        //
        //    The fstype candidate list + mount flags differ by mode:
        //      - ManagedRootfs: read-only (verity is by construction
        //        immutable); erofs / squashfs.
        //      - TenantLuks (#257 BYO base-OS): read-write (the tenant
        //        OS expects to journal, write /etc/resolv.conf, etc.);
        //        ext4 / xfs / btrfs — the formats vanilla cloud images
        //        ship.
        //    `MS_NOSUID` is NOT set in either mode — it would disable
        //    every set-uid binary (`sudo`, `ping`, …) the tenant
        //    legitimately uses; integrity is anchored by verity
        //    (managed) or by AES-XTS-integrity LUKS (tenant, #257).
        std::fs::create_dir_all(SYSROOT).map_err(|_| AgentError::SwitchRoot(cat::MOUNT_ROOTFS))?;
        let (fstypes, mount_flags): (&[&str], MsFlags) = match cfg.mode {
            PivotMode::ManagedRootfs => (MANAGED_ROOTFS_FSTYPES, MsFlags::MS_RDONLY),
            PivotMode::TenantLuks { .. } => (TENANT_LUKS_FSTYPES, MsFlags::empty()),
        };
        let mut mounted = false;
        for fstype in fstypes {
            let ok = mount(
                Some(cfg.rootfs_device.as_str()),
                SYSROOT,
                Some(*fstype),
                mount_flags,
                None::<&str>,
            )
            .is_ok();
            if ok {
                mounted = true;
                break;
            }
        }
        if !mounted {
            return Err(AgentError::SwitchRoot(cat::MOUNT_ROOTFS));
        }

        // 2a. BYO-OS only: bind-mount the initramfs's `/lib/modules/<kver>`
        //     tree into the tenant rootfs so the tenant's userspace can
        //     `modprobe` any module the running (Hippius-measured)
        //     kernel ships. The tenant's own `/lib/modules/<kver>` is
        //     for a different kernel (its base-image kernel), which we
        //     don't run — so without this bind every `modprobe`
        //     resolves to ENOENT and half of cloud-init / netbird /
        //     systemd unit dependencies silently fail. Standard
        //     dracut / mkinitcpio initrd-to-root handoff pattern.
        //
        //     The bind happens BEFORE the MS_MOVE / chroot dance so the
        //     mountpoint resolves under the initramfs's own
        //     `/lib/modules/<kver>` source, which the chroot will then
        //     shadow — the bind makes the kernel module bytes visible
        //     inside the new root regardless.
        if let PivotMode::TenantLuks { kernel_release } = &cfg.mode {
            let src = format!("/lib/modules/{kernel_release}");
            let dst = format!("{SYSROOT}/lib/modules/{kernel_release}");
            std::fs::create_dir_all(&dst).map_err(|_| AgentError::SwitchRoot(cat::MODULES_BIND))?;
            mount(
                Some(src.as_str()),
                dst.as_str(),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|_| AgentError::SwitchRoot(cat::MODULES_BIND))?;
        }

        // 2b. Move the kernel virtual filesystems into the new root so
        //     they (and, crucially, the /run tmpfs NoCloud seed) survive
        //     the pivot.
        for vfs in VIRTUAL_FS {
            let target = format!("{SYSROOT}{vfs}");
            mount(
                Some(*vfs),
                target.as_str(),
                None::<&str>,
                MsFlags::MS_MOVE,
                None::<&str>,
            )
            .map_err(|_| AgentError::SwitchRoot(cat::MOVE_MOUNT))?;
        }

        // 3. The initramfs-rootfs `switch_root` dance. An initramfs
        //    cannot `pivot_root(2)` out of itself; `chdir` into the new
        //    root, `MS_MOVE` it onto `/`, then `chroot` into it.
        chdir(Path::new(SYSROOT)).map_err(|_| AgentError::SwitchRoot(cat::CHDIR))?;
        mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|_| AgentError::SwitchRoot(cat::MOVE_ROOT))?;
        chroot(".").map_err(|_| AgentError::SwitchRoot(cat::CHROOT))?;
        chdir("/").map_err(|_| AgentError::SwitchRoot(cat::CHDIR))?;

        // 4. Hand off to the guest OS init. `execv` replaces the process
        //    image — on success it NEVER returns, so reaching the line
        //    after it means the `execv` failed.
        let init = CString::new("/sbin/init").map_err(|_| AgentError::SwitchRoot(cat::EXECV))?;
        execv(&init, &[init.as_c_str()]).map_err(|_| AgentError::SwitchRoot(cat::EXECV))?;
        Err(AgentError::SwitchRoot(cat::EXECV))
    }
}

// ── Mock implementation (all platforms) ─────────────────────────────

/// Test / non-Linux dev-host stand-in for [`RealRootfsPivot`].
///
/// Records the [`PivotConfig`] of its last call and returns a
/// configurable outcome **without** mounting or `execv`-ing anything —
/// so `cargo test` (which runs on Linux in CI) can drive the §21
/// pipeline through this stage without destroying the test runner.
pub struct MockRootfsPivot {
    /// `Ok(())` ⇒ `pivot_into_rootfs` "succeeds" (returns `Ok` — the
    /// mock cannot diverge like a real `execv`); `Err(class)` ⇒ it
    /// fails with `AgentError::SwitchRoot(class)`.
    outcome: Result<(), &'static str>,
    /// The [`PivotConfig`] of the last call, or `None` if never called.
    last_call: RefCell<Option<PivotConfig>>,
}

impl MockRootfsPivot {
    /// A mock whose `pivot_into_rootfs` returns `Ok`.
    pub fn new() -> Self {
        Self {
            outcome: Ok(()),
            last_call: RefCell::new(None),
        }
    }

    /// A mock whose `pivot_into_rootfs` fails closed with
    /// `AgentError::SwitchRoot(class)` — used to pin fail-closed
    /// propagation through `pipeline::run`.
    pub fn failing(class: &'static str) -> Self {
        Self {
            outcome: Err(class),
            last_call: RefCell::new(None),
        }
    }

    /// The `rootfs_device` of the most recent call, or `None`.
    pub fn last_device(&self) -> Option<String> {
        self.last_call
            .borrow()
            .as_ref()
            .map(|c| c.rootfs_device.clone())
    }

    /// The full [`PivotConfig`] of the most recent call, or `None`.
    pub fn last_call(&self) -> Option<PivotConfig> {
        self.last_call.borrow().clone()
    }
}

impl Default for MockRootfsPivot {
    fn default() -> Self {
        Self::new()
    }
}

impl RootfsPivot for MockRootfsPivot {
    fn pivot_into_rootfs(&self, cfg: &PivotConfig) -> Result<(), AgentError> {
        *self.last_call.borrow_mut() = Some(cfg.clone());
        self.outcome.map_err(AgentError::SwitchRoot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_cfg(device: &str) -> PivotConfig {
        PivotConfig {
            rootfs_device: device.to_string(),
            mode: PivotMode::ManagedRootfs,
        }
    }

    #[test]
    fn pivot_forwards_the_config_to_the_pivot_impl() {
        let p = MockRootfsPivot::new();
        pivot(&p, &managed_cfg("/dev/mapper/hippius-rootfs")).expect("mock pivot succeeds");
        assert_eq!(
            p.last_device().as_deref(),
            Some("/dev/mapper/hippius-rootfs")
        );
        let last = p.last_call().expect("call recorded");
        assert!(matches!(last.mode, PivotMode::ManagedRootfs));
    }

    #[test]
    fn pivot_forwards_tenant_luks_mode_with_kernel_release() {
        // #257 BYO base-OS: the mode + kernel_release MUST round-trip
        // through the trait so the real impl can drive the right
        // fstype list + bind-mount the matching modules tree.
        let p = MockRootfsPivot::new();
        let cfg = PivotConfig {
            rootfs_device: "/dev/mapper/hippius-data".to_string(),
            mode: PivotMode::TenantLuks {
                kernel_release: "6.12.63+deb13-amd64".to_string(),
            },
        };
        pivot(&p, &cfg).expect("mock pivot succeeds");
        let last = p.last_call().expect("call recorded");
        match last.mode {
            PivotMode::TenantLuks { kernel_release } => {
                assert_eq!(kernel_release, "6.12.63+deb13-amd64");
            }
            PivotMode::ManagedRootfs => panic!("expected TenantLuks mode"),
        }
        assert_eq!(last.rootfs_device, "/dev/mapper/hippius-data");
    }

    #[test]
    fn pivot_is_fail_closed_on_a_pivot_error() {
        let p = MockRootfsPivot::failing(cat::MOUNT_ROOTFS);
        let err = pivot(&p, &managed_cfg("/dev/mapper/hippius-rootfs"))
            .expect_err("a failing pivot must Err");
        assert!(matches!(err, AgentError::SwitchRoot(_)));
        // §20: the error class is the fixed static tag — no device path.
        assert_eq!(err.class(), "switch-root-failed");
        assert_eq!(err.to_string(), "switch-root-failed");
    }

    #[test]
    fn rootfs_pivot_trait_is_object_safe() {
        // §21 `run` takes `&dyn RootfsPivot` — pin object-safety here.
        let p: Box<dyn RootfsPivot> = Box::new(MockRootfsPivot::new());
        assert!(p
            .pivot_into_rootfs(&managed_cfg("/dev/mapper/hippius-rootfs"))
            .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_rootfs_pivot_impl_is_present_on_linux() {
        // The Linux-only `RealRootfsPivot` MUST implement `RootfsPivot`
        // — a refactor dropping the `impl` breaks this `&dyn` coercion.
        // Constructed + coerced only; never *called* (a real call mounts
        // and `execv`s). Parallels `real_luks_unlocker_impl_is_present`.
        let p = RealRootfsPivot::new();
        let _: &dyn RootfsPivot = &p;
    }
}
