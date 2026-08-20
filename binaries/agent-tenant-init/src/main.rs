//! `/sbin/init` for the Hippius tenant dm-verity rootfs.
//!
//! ## Why this exists
//!
//! The §F build-rootfs.sh used to write a `#!/bin/sh` placeholder
//! `/sbin/init`. The deterministic tenant rootfs ships no shell
//! binary (only the two compiled bundled binaries + glibc + the
//! dynamic linker), so the placeholder's shebang resolution failed
//! ENOENT and `crate::stages::switch_root` fail-closed at
//! `switch-root-failed:execv` on every boot — observed live
//! 2026-05-28 once the rest of the boot chain (LUKS → dm-verity →
//! squashfs mount → chroot) was unblocked by PRs #238–#253.
//!
//! This binary is the deterministic, statically-built foothold the
//! agent-initramfs `execv("/sbin/init")` hands off to. It is
//! deliberately minimal: announce on the serial console, defensively
//! re-mount `/proc` + `/sys` + `/dev` (the initramfs already
//! `MS_MOVE`'d them, but tolerating a missing mount keeps the
//! foothold robust under future pipeline re-orderings), then block
//! forever on `pause(2)` so the kernel never panics on a PID-1 exit.
//!
//! ## What it does NOT do (deferred to follow-up PRs)
//!
//! - **Mount the NoCloud seed** (`/run/cloud-init/seed/nocloud-net/`
//!   on tmpfs survived the pivot via the §21 `MS_MOVE /run`). The
//!   cloud-init datasource lookup runs from here; that wire-up is a
//!   dedicated follow-up.
//! - **Start NetBird** (`/sbin/netbird up --setup-key <…>` — needs
//!   the KBS-released setup key, which today lives in the cloud-init
//!   user-data the §21 pipeline already wrote to the NoCloud seed).
//! - **Start the tenant-telemetry signer** (the §23 per-VM signer
//!   that lives at `/sbin/hippius-agent-tenant-telemetry` — needs a
//!   supervisor for restart semantics).
//! - **Reap zombies, handle SIGTERM, etc.** A real PID-1 supervises;
//!   this MVP only needs to not exit.
//!
//! Each of those is its own §F follow-up — and each is a §22
//! allowlist-affecting change because it shifts the rootfs.img bytes
//! and therefore the dm-verity root hash. Doing them incrementally
//! keeps each KAT re-pin scoped.
//!
//! ## Why Rust + nix (not C, not a shell script)
//!
//! The rootfs already ships glibc + ld for the
//! `hippius-agent-tenant-telemetry` binary; this init reuses that
//! ABI rather than adding a static binary (which would cost ~5-10
//! MB to the rootfs.img / dm-verity coverage surface). `nix` is the
//! same FFI wrapper the initramfs agent uses, so the `unsafe_code =
//! \"forbid\"` workspace lint inherits cleanly. The bin links
//! against libc + ld already present in the rootfs.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nix::mount::{mount, MsFlags};
use std::path::Path;

/// Best-effort mount: if the target is already mounted (the
/// initramfs `MS_MOVE`'d it across the pivot, the happy path), the
/// kernel returns `EBUSY` and we treat it as success. Anything else
/// is also silently tolerated — this is a tenant-rootfs init MVP,
/// not a strict orchestrator.
fn mount_maybe(fstype: &str, target: &str) {
    if !Path::new(target).exists() {
        // The mount-point must exist for `mount(2)`; the
        // measured rootfs ships /proc, /sys, /dev as empty dirs.
        // Skip silently if absent — the dir is the failure mode,
        // not something to crash on.
        return;
    }
    let _ = mount(
        Some(fstype),
        target,
        Some(fstype),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );
}

fn main() -> std::convert::Infallible {
    // 1. Announce on serial — the §20 fail-closed log discipline does
    //    NOT apply post-pivot: by here every secret has been wiped,
    //    and confirmation that the boot chain reached PID 1 in the
    //    measured rootfs is exactly what an operator needs from the
    //    serial console. A single line, no plaintext from any
    //    pre-pivot state.
    eprintln!("hippius-agent-tenant-init: tenant runtime up (PID 1)");

    // 2. Defensively re-mount the kernel virtual filesystems. The
    //    initramfs `MS_MOVE`'d these across the pivot, so they ARE
    //    here in production — EBUSY is the expected outcome and is
    //    treated as success. Tolerating absence keeps the foothold
    //    robust against a future initramfs change that no longer
    //    moves /proc (e.g. a `pivot_root(2)` migration); /dev is
    //    intentionally NOT re-mounted because re-creating devtmpfs
    //    on top of the moved tree would mask the real device nodes.
    mount_maybe("proc", "/proc");
    mount_maybe("sysfs", "/sys");

    // 3. Block forever — the kernel panics on a PID-1 exit, so this
    //    MUST never return. `nix::unistd::pause` blocks on a signal
    //    that never arrives (no signal handlers are installed). The
    //    return type is `Infallible` so `main` cannot accidentally
    //    fall through.
    loop {
        nix::unistd::pause();
    }
}
