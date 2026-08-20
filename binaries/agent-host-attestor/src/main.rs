//! `hippius-agent-host-attestor` — the host attestor service entrypoint.
//!
//! On the bare-metal SEV-SNP host, once per boot: fetch the stable
//! measurement-bound SNP derived key, HKDF-derive the per-boot Ed25519
//! signer, enrol the public key with the KBS (via a `host-enroll` vsock
//! frame), and run the periodic liveness-beacon loop — synchronous (no
//! async runtime) to keep the measured TCB minimal.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! The derived-key fetch (establish) and the boot report request (enrol)
//! run strictly in order on the single main thread — establish fully
//! returns (its transient `Firmware` handle closed) before enrol opens the
//! device again — so the serialized, sequence-numbered channel is never
//! raced. AFTER those two, `run` spawns the periodic **re-enroll** loop on
//! its own thread; that loop is the SOLE remaining opener of
//! `/dev/sev-guest` (it re-runs `get_report` on each tick, one at a time),
//! and it NEVER re-fetches the derived key (that stays a one-time
//! establish, R1). The beacon loop + pusher sign with Ed25519 / do socket
//! I/O only — neither touches the device — so nothing ever races the
//! re-enroll's `get_report`.
//!
//! ## Ships inert
//!
//! Functional, but nothing launches this binary yet (PR-7) and vali does
//! not consume its frames yet (PR-8) — so the feature is inert
//! end-to-end. Off-target (non-Linux/x86_64) the binary is a deliberate
//! placeholder that refuses to run: the real path needs `/dev/sev-guest`.
//!
//! On any establishment / enrollment failure the agent exits non-zero
//! (fail-closed). On a clean shutdown it returns **normally** so the
//! signer key's `Zeroize`-on-drop fires before the process exits.

use std::process::ExitCode;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> ExitCode {
    match run::run() {
        Ok(()) => ExitCode::SUCCESS,
        // §20: log only the static error class — never dynamic text,
        // never any key material.
        Err(e) => {
            eprintln!("hippius-agent-host-attestor: fail-closed: {}", e.class());
            ExitCode::FAILURE
        }
    }
}

/// Off-target (non-Linux/x86_64): the real path needs `/dev/sev-guest`,
/// which only exists on a Linux/x86_64 SEV-SNP guest. Refuse to run
/// rather than silently no-op, so an accidental deployment on the wrong
/// target is caught loudly.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() -> ExitCode {
    eprintln!(
        "hippius-agent-host-attestor: inert on this target — the enroll/beacon path needs \
         /dev/sev-guest (Linux/x86_64 SEV-SNP); refusing to run"
    );
    ExitCode::FAILURE
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod run {
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use hippius_agent_host_attestor::beacon_loop::{run_beacon_loop, unix_now, BeaconLoopConfig};
    use hippius_agent_host_attestor::config::Config;
    use hippius_agent_host_attestor::derived_key::SevGuestDerivedKeyProvider;
    use hippius_agent_host_attestor::enroll::enroll;
    use hippius_agent_host_attestor::error::{HostAttestorError, Result};
    use hippius_agent_host_attestor::establish::establish;
    use hippius_agent_host_attestor::frame::encode_enroll_frame;
    use hippius_agent_host_attestor::nonce::{ChallengeNonceSource, NonceSource, OsRngNonceSource};
    use hippius_agent_host_attestor::reenroll::{
        spawn_reenroll_loop, EnrollFrameSlot, ReenrollParams,
    };
    use hippius_agent_host_attestor::shutdown::{self, Shutdown};
    use hippius_agent_host_attestor::snp::SevGuestProvider;
    use hippius_agent_host_attestor::{BeaconBuilder, BeaconQueue, VsockPusher, VSOCK_HOST_CID};

    /// Upper bound on waiting for the vsock pusher to drain + exit on
    /// shutdown. The pusher's vsock dial is a blocking syscall the
    /// `vsock` crate offers no timed variant for (and `forbid(unsafe_code)`
    /// rules out a hand-rolled non-blocking connect) — a wedged host could
    /// park the pusher thread. This bound caps the graceful-shutdown wait:
    /// past it, `run` proceeds and process exit reaps the abandoned
    /// thread. Comfortably above the pusher's `WRITE_TIMEOUT` (10 s).
    const PUSHER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

    /// The service body. Returns `Ok(())` only after a clean shutdown —
    /// and MUST return rather than `process::exit`, so the signer's
    /// destructor (zeroize) runs.
    pub fn run() -> Result<()> {
        // Mount the kernel pseudo-filesystems FIRST — this binary is the
        // diskless attestor UKI's `/init` (PID 1), and the initrd cpio
        // ships none of `/proc`, `/sys`, `/dev` pre-mounted (the kernel
        // does not auto-mount them for `/init`). Without them
        // `Config::resolve` cannot read `/proc/cmdline` nor the kernel
        // `boot_id` (`/proc/sys/kernel/random/boot_id`) — the live boot
        // died at `fail-closed: boot-id-missing` → kernel panic — and
        // `establish` cannot open `/dev/sev-guest` (devtmpfs on `/dev` is
        // what surfaces the SNP device). Mirrors the tenant
        // `agent-initramfs` PID-1 mount (#171).
        mount_pseudo_filesystems()?;

        // Load the bundled kernel modules NEXT — before any config read or
        // device open. The measured diskless initrd carries the `.ko` bytes
        // for `sev-guest` (+ its crypto/TSM deps) and the `vsock` transport
        // stack, but the Debian stock guest kernel ships them as loadable
        // modules (`CONFIG_SEV_GUEST=m`, `CONFIG_VSOCKETS=m`,
        // `CONFIG_VIRTIO_VSOCKETS=m`) — nothing is loaded for a bare `/init`.
        // Until they load, `/dev/sev-guest` never appears (`establish` +
        // `enroll` fail `open-failed`, the live blocker) and the
        // challenge/enroll/beacon vsock cannot bind. Mirrors the tenant
        // `agent-initramfs` `load_kernel_modules` (init_module at PID 1),
        // scoped to just the two families the diskless attestor needs.
        load_kernel_modules()?;

        // Install the shutdown handler — before any key is derived.
        let shutdown = shutdown::install()?;

        let cfg = Config::resolve()?;
        // Beacons use locally-random nonces (freshness = seq + expiry);
        // the ENROLLMENT nonce is vali-minted (single-use, fail-closed).
        let nonce_source = OsRngNonceSource::new();

        // ── 1. establish: fetch the SNP derived key ONCE, build signer.
        //    (First /dev/sev-guest interaction — completes and closes the
        //    device before enrol opens it.)
        let established = establish(&SevGuestDerivedKeyProvider::new())?;
        let signer_pubkey = established.pubkey();
        eprintln!("hippius-agent-host-attestor: signer established");

        // ── 2. enrol: pull a FRESH vali-minted single-use nonce bound to
        //    the signer pubkey (fail-closed — no local fallback, so a
        //    pre-generated enrollment report cannot be replayed). The same
        //    challenge response ALSO carries the vali-stamped `node_id`
        //    (PR-10b-S2a): the guest can't read its node_id from the
        //    measured cmdline (that would make the measurement per-node),
        //    so it uses THIS node_id for both the enrollment identity and
        //    the REPORT_DATA binding. Then request the platform SNP report
        //    bound to {nonce, signer pubkey, node_id} and assemble the
        //    HostEnrollment. (Second — and last — /dev/sev-guest interaction.)
        let challenge =
            ChallengeNonceSource::new(VSOCK_HOST_CID, cfg.challenge_vsock_port, signer_pubkey);
        let host_challenge = challenge.fetch()?;
        let node_id = host_challenge.node_id;
        eprintln!("hippius-agent-host-attestor: fresh vali nonce + node_id obtained");
        let issued_at = unix_now()?;
        let enrolled = enroll(
            &SevGuestProvider::new(),
            &signer_pubkey,
            &node_id,
            &cfg.boot_id,
            &host_challenge.nonce,
            issued_at,
        )?;
        eprintln!("hippius-agent-host-attestor: enrolled");

        // The shared, swappable enrollment frame: the pusher (re)sends it,
        // and the periodic re-enroll loop installs a fresh one before the
        // KBS cert's 2 h TTL lapses (keeping the vali row `attested`).
        let enroll_slot =
            EnrollFrameSlot::new(Arc::new(encode_enroll_frame(&enrolled.enrollment)?));

        // ── 3. re-enroll: spawn the periodic re-enroll loop. It re-runs the
        //    challenge + enroll (a FRESH single-use nonce + a FRESH SNP
        //    report) each interval — reusing the CACHED signer (the derived
        //    key is NEVER re-fetched, R1) — and installs the fresh frame for
        //    the pusher. After establish + the boot enroll (both done above
        //    on this main thread), this loop is the SOLE opener of
        //    /dev/sev-guest (the beacon loop + pusher never touch it), so the
        //    serialized channel is never raced. Fail-SOFT: a transient
        //    re-enroll failure logs + retries, since the current cert is
        //    valid until its TTL.
        let reenroll = spawn_reenroll_loop(
            ReenrollParams {
                cid: VSOCK_HOST_CID,
                challenge_port: cfg.challenge_vsock_port,
                signer_pubkey,
                boot_id: cfg.boot_id.clone(),
                interval: Duration::from_secs(cfg.enroll_interval_secs),
            },
            enroll_slot.clone(),
            shutdown.clone(),
        )?;

        // ── 4. beat: build + push periodic beacons until shutdown. The
        //    beacons carry the SAME challenge-delivered node_id as the
        //    enrollment/cert. Returns once shutdown latches (having latched
        //    it for the pusher + joined the pusher thread).
        let loop_result = run_beacons(
            &cfg,
            &node_id,
            &established.signer,
            &enrolled,
            &enroll_slot,
            &nonce_source,
            &shutdown,
        );

        // Shutdown is latched by `run_beacons`; the re-enroll loop polls it
        // and returns — join it (time-bounded, same discipline as the
        // pusher) so its `Firmware` handle is closed before process exit.
        join_thread_bounded(reenroll, "re-enroll");

        // Drop the established signer explicitly: it holds a
        // `ZeroizeOnDrop` `SigningKey`, so the key wipes here — before
        // the process exits. `run` MUST return normally for this to fire.
        drop(established);
        eprintln!("hippius-agent-host-attestor: shutdown — signer key zeroized");
        loop_result
    }

    /// Build the beacon components, encode the enrollment preamble, start
    /// the vsock pusher, and run the loop until `shutdown` latches.
    fn run_beacons(
        cfg: &Config,
        node_id: &str,
        signer: &hippius_agent_host_attestor::HostAttestorSigner,
        enrolled: &hippius_agent_host_attestor::Enrolled,
        enroll_slot: &EnrollFrameSlot,
        nonce_source: &dyn NonceSource,
        shutdown: &Shutdown,
    ) -> Result<()> {
        let mut builder = BeaconBuilder::new(
            node_id.to_string(),
            cfg.boot_id.clone(),
            cfg.chain_genesis,
            cfg.pallet_instance,
            signer.pubkey(),
            &enrolled.platform,
        );

        // The pusher writes the current enrollment frame on every fresh
        // connection AND re-sends it whenever the re-enroll loop installs a
        // fresher one (idempotent; vali upserts by chip_id).
        // The queue is shared: this thread's beacon loop fills it; the
        // pusher (its own thread) drains it to the host. Spawn the pusher
        // BEFORE the loop so a beacon is never built with nowhere to go.
        let queue = Arc::new(Mutex::new(BeaconQueue::new()));
        let pusher = VsockPusher::new(
            VSOCK_HOST_CID,
            cfg.vsock_port,
            enroll_slot.clone(),
            Arc::clone(&queue),
            shutdown.clone(),
        )
        .spawn()?;

        let loop_config = BeaconLoopConfig {
            interval: Duration::from_secs(cfg.interval_secs),
            window_secs: cfg.window_secs,
        };
        let loop_result = run_beacon_loop(
            &mut builder,
            &queue,
            signer,
            nonce_source,
            shutdown,
            &loop_config,
        );

        // The loop has ended — latch shutdown unconditionally so the
        // pusher observes it; its final drain flushes the buffer. The
        // join is time-bounded so a wedged vsock dial cannot stall the
        // process (and its key-zeroizing exit).
        shutdown.trigger();
        join_thread_bounded(pusher, "vsock pusher");
        loop_result
    }

    /// Join a background worker thread, but never block shutdown longer
    /// than [`PUSHER_JOIN_TIMEOUT`]. Shared by the vsock pusher and the
    /// re-enroll loop; `name` labels the log line. A timed-out join is
    /// abandoned (process exit reaps the thread) rather than wedging the
    /// key-zeroizing shutdown.
    fn join_thread_bounded(handle: std::thread::JoinHandle<Result<()>>, name: &'static str) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(handle.join());
        });
        match rx.recv_timeout(PUSHER_JOIN_TIMEOUT) {
            Ok(Ok(Ok(()))) => eprintln!("hippius-agent-host-attestor: {name} drained"),
            Ok(Ok(Err(e))) => {
                eprintln!("hippius-agent-host-attestor: {name} exited: {}", e.class())
            }
            Ok(Err(_)) => eprintln!("hippius-agent-host-attestor: {name} thread panicked"),
            Err(_) => {
                eprintln!("hippius-agent-host-attestor: {name} join timed out — abandoning")
            }
        }
    }

    /// Mount `/proc`, `/sys`, `/dev` once, at PID 1 only.
    ///
    /// **Why.** The measured diskless attestor UKI's initramfs cpio carries
    /// `/init` → this binary and its dynamic-linker baggage — nothing else.
    /// The Linux kernel does **not** auto-mount procfs / sysfs / devtmpfs
    /// for the initramfs; that is `/init`'s job. Without them
    /// [`Config::resolve`] reads an empty `/proc/cmdline` and cannot read
    /// the kernel `boot_id` (`/proc/sys/kernel/random/boot_id`) → it fails
    /// closed with `boot-id-missing`; and `establish` cannot open the SNP
    /// `/dev/sev-guest` node (devtmpfs on `/dev` is what surfaces it).
    /// Both were fatal on live silicon (kernel panic, "Attempted to kill
    /// init") until this ran. Directly mirrors the tenant `agent-initramfs`
    /// mount (#171) — same hardening flags, same PID-1 gate.
    ///
    /// **PID-1 gate.** A non-init invocation (`cargo test`, a dev shell,
    /// a wrapper) already lives in a tree where the host's `/proc` is
    /// mounted; mounting on top would shadow it. The gate makes this a
    /// safe no-op everywhere except the real diskless boot.
    ///
    /// **Filesystem set** (matches systemd / dracut and the tenant agent):
    /// - `/proc` procfs `MS_NOSUID|MS_NODEV|MS_NOEXEC` — hardening triple.
    /// - `/sys`  sysfs `MS_NOSUID|MS_NODEV|MS_NOEXEC` — ditto.
    /// - `/dev`  devtmpfs `MS_NOSUID`, `mode=0755` — `MS_NODEV` would
    ///   defeat the point of devtmpfs (it IS the device nodes).
    ///
    /// **Idempotent.** An already-mounted target (`EBUSY`) is treated as
    /// success, so a future cpio that pre-mounts — or a rerun — is not
    /// penalised. Any other `mount(2)` error fails closed with a static
    /// `*-mount` class (and an explicit serial line), so the panic shows
    /// the real reason instead of the misleading `boot-id-missing`.
    fn mount_pseudo_filesystems() -> Result<()> {
        // Not the kernel's init — the host already mounted these. Skip so
        // the same binary is safe under `cargo test` / a dev shell.
        if std::process::id() != 1 {
            return Ok(());
        }

        use nix::mount::{mount, MsFlags};

        // The hardening triple every well-behaved `/proc` / `/sys` mount
        // in the systemd / dracut universe carries.
        let hardening = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;

        // The fstype name doubles as the `source` argument — the kernel
        // ignores `source` for procfs/sysfs/devtmpfs, but `mount(2)`
        // refuses a NULL source, so the fstype is the conventional
        // placeholder.
        let mounts: &[PseudoMount] = &[
            PseudoMount {
                target: "/proc",
                fstype: "proc",
                flags: hardening,
                data: None,
                mkdir_class: "proc-mkdir",
                mount_class: "proc-mount",
            },
            PseudoMount {
                target: "/sys",
                fstype: "sysfs",
                flags: hardening,
                data: None,
                mkdir_class: "sys-mkdir",
                mount_class: "sys-mount",
            },
            PseudoMount {
                target: "/dev",
                fstype: "devtmpfs",
                flags: MsFlags::MS_NOSUID,
                data: Some("mode=0755"),
                mkdir_class: "dev-mkdir",
                mount_class: "dev-mount",
            },
        ];

        for m in mounts {
            // `create_dir_all` is idempotent — a future cpio that DOES
            // ship these as empty dirs is not penalised.
            std::fs::create_dir_all(m.target)
                .map_err(|_| HostAttestorError::Mount(m.mkdir_class))?;
            let res = mount(Some(m.fstype), m.target, Some(m.fstype), m.flags, m.data);
            if let Err(e) = &res {
                if *e != nix::errno::Errno::EBUSY {
                    // Surface the real reason on the serial console —
                    // unlike the silent `boot-id-missing` this replaces.
                    eprintln!(
                        "hippius-agent-host-attestor: mount {} ({}) failed",
                        m.target, m.fstype
                    );
                }
            }
            classify_mount(res, m.mount_class)?;
        }
        eprintln!("hippius-agent-host-attestor: pseudo-filesystems mounted");
        Ok(())
    }

    /// Load the bundled kernel modules the diskless attestor needs, at
    /// PID 1 only.
    ///
    /// **Why.** The Debian stock guest kernel the UKI ships
    /// (`6.12.63+deb13-amd64`) builds the SNP guest driver and the vsock
    /// transport as **loadable modules** — `CONFIG_SEV_GUEST=m`,
    /// `CONFIG_VSOCKETS=m`, `CONFIG_VIRTIO_VSOCKETS=m`. For a bare `/init`
    /// nothing loads them, so `/dev/sev-guest` never appears (`establish`
    /// fails `open-failed` — the live blocker this fixes) and the
    /// challenge/enroll/beacon vsock cannot bind. The measured initrd cpio
    /// carries the raw `.ko` bytes (see the diskless UKI
    /// `build-initramfs.sh`); this loads them in dependency order.
    ///
    /// **Which families.** Only the two the diskless attestor uses — NOT
    /// the tenant's disk / verity / network set:
    /// - **`sev_guest`**: `configfs` → `crypto_null` → `gf128mul` →
    ///   `ghash-generic` → `gcm` → `tsm` → `sev-guest`. The driver depends
    ///   on the CoCo TSM framework (`tsm` → `configfs`) and allocates a
    ///   `gcm(aes)` AEAD for guest-message protection (the crypto chain);
    ///   `aes` is built-in (`CONFIG_CRYPTO_AES=y`).
    /// - **`vsock`**: `vsock` → `vmw_vsock_virtio_transport_common` →
    ///   `vmw_vsock_virtio_transport`. The virtio-vsock DOWN nonce +
    ///   UP enroll/beacon relay ride this stack. `virtio` / `virtio_pci`
    ///   are built-in, so the device is already on the bus.
    ///
    /// Load order matches the tenant `agent-initramfs::load_kernel_modules`
    /// families verbatim (dependency-first); kept in lockstep with the
    /// diskless `build-initramfs.sh` staging list.
    ///
    /// **PID-1 gate.** Outside PID 1 (`cargo test`, a dev shell) the
    /// modules either already live or `init_module(2)` would hit `EPERM` —
    /// short-circuit to `Ok` so the same binary stays test-friendly, the
    /// same posture as [`mount_pseudo_filesystems`].
    ///
    /// **Fail-closed.** A missing `.ko` or a real `init_module(2)` error
    /// aborts the boot with a static `<family>-modules-<step>-<name>`
    /// class (and an explicit serial line) — so the next iteration's serial
    /// shows the real reason rather than a later, misleading failure.
    /// An already-loaded module (`EEXIST`) is treated as success.
    fn load_kernel_modules() -> Result<()> {
        if std::process::id() != 1 {
            return Ok(());
        }

        use nix::sys::utsname::uname;

        let utsname = uname().map_err(|_| HostAttestorError::Module("kmod-modules-uname"))?;
        // `release()` is `&OsStr`; a non-UTF-8 kernel release is impossible
        // on Linux (always ASCII) but we fail closed rather than lossily
        // coerce, so any surprise surfaces.
        let release: &str = utsname
            .release()
            .to_str()
            .ok_or(HostAttestorError::Module("kmod-modules-uname-utf8"))?;

        // (relative `.ko` path under `/lib/modules/<kver>/kernel/`,
        // read-error class, load-error class). Order IS load order.
        //
        // vsock transport stack — the guest-initiated challenge PULL and
        // the enroll/beacon UP relay bind `AF_VSOCK`; `VsockListener` /
        // `VsockStream` fail closed until the module set is live.
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

        // SEV-SNP attestation — `/dev/sev-guest` is exposed by the
        // `sev-guest` driver (`CONFIG_SEV_GUEST=m`). It depends on the CoCo
        // TSM framework (`tsm` → `configfs`) and the sev-guest probe
        // allocates a `gcm(aes)` AEAD (crypto_null → gf128mul →
        // ghash-generic → gcm) for guest-message protection. Load ALL
        // before `establish` opens the device.
        let sev_guest: &[(&str, &'static str, &'static str)] = &[
            (
                "fs/configfs/configfs",
                "sev-guest-modules-read-configfs",
                "sev-guest-modules-load-configfs",
            ),
            (
                "crypto/crypto_null",
                "sev-guest-modules-read-crypto-null",
                "sev-guest-modules-load-crypto-null",
            ),
            (
                "lib/crypto/gf128mul",
                "sev-guest-modules-read-gf128mul",
                "sev-guest-modules-load-gf128mul",
            ),
            (
                "crypto/ghash-generic",
                "sev-guest-modules-read-ghash",
                "sev-guest-modules-load-ghash",
            ),
            (
                "crypto/gcm",
                "sev-guest-modules-read-gcm",
                "sev-guest-modules-load-gcm",
            ),
            (
                "drivers/virt/coco/tsm",
                "sev-guest-modules-read-tsm",
                "sev-guest-modules-load-tsm",
            ),
            (
                "drivers/virt/coco/sev-guest/sev-guest",
                "sev-guest-modules-read-sev-guest",
                "sev-guest-modules-load-sev-guest",
            ),
        ];

        load_module_family(release, vsock)?;
        load_module_family(release, sev_guest)?;
        eprintln!("hippius-agent-host-attestor: kernel modules loaded");
        Ok(())
    }

    /// Insert one `(rel, read_class, load_class)` family of modules in the
    /// given order. The first module's existence is the "did the initrd
    /// bundle this family?" probe — absent → clean skip; present → every
    /// entry must load (modulo `EEXIST` when built into a future kernel).
    /// Mirrors the tenant `agent-initramfs::load_module_family` exactly.
    fn load_module_family(
        release: &str,
        family: &[(&str, &'static str, &'static str)],
    ) -> Result<()> {
        use nix::errno::Errno;
        use nix::kmod::init_module;
        use std::ffi::CString;

        let Some((first_rel, _, _)) = family.first() else {
            return Ok(());
        };
        let first_path = format!("/lib/modules/{release}/kernel/{first_rel}.ko");
        if !std::path::Path::new(&first_path).exists() {
            // The initrd did not bundle this family — nothing to do. A
            // real deployment always bundles both, so this only trips in a
            // dev/CI tree, where the PID-1 gate above already returned.
            return Ok(());
        }
        // None of the modules we load take parameters. `CString::new("")`
        // is infallible; the `map_err` is for type completeness only.
        let no_params =
            CString::new("").map_err(|_| HostAttestorError::Module("kmod-modules-params"))?;
        for (rel, read_class, load_class) in family {
            let path = format!("/lib/modules/{release}/kernel/{rel}.ko");
            let bytes = std::fs::read(&path).map_err(|_| HostAttestorError::Module(read_class))?;
            match init_module(&bytes, &no_params) {
                Ok(()) => {}
                // Built-in in a future kernel returns EEXIST — success.
                Err(Errno::EEXIST) => {}
                Err(_) => {
                    // Surface the real reason on the serial console — so a
                    // module-load failure shows here, not later as an
                    // `open-failed` on `/dev/sev-guest`.
                    eprintln!(
                        "hippius-agent-host-attestor: init_module failed ({})",
                        load_class
                    );
                    return Err(HostAttestorError::Module(load_class));
                }
            }
        }
        Ok(())
    }

    /// Classify a `mount(2)` result: success and "already mounted"
    /// (`EBUSY`) are both OK; any other errno fails closed with the
    /// static `mount_class`. Pure — unit-testable without root / PID 1.
    fn classify_mount(
        res: std::result::Result<(), nix::errno::Errno>,
        mount_class: &'static str,
    ) -> Result<()> {
        match res {
            Ok(()) | Err(nix::errno::Errno::EBUSY) => Ok(()),
            Err(_) => Err(HostAttestorError::Mount(mount_class)),
        }
    }

    /// One row in [`mount_pseudo_filesystems`]'s spec table — a named
    /// struct (not an in-place tuple) to keep `clippy::type_complexity`
    /// quiet and give every column an identity at the call site.
    struct PseudoMount {
        target: &'static str,
        fstype: &'static str,
        flags: nix::mount::MsFlags,
        data: Option<&'static str>,
        /// Static class emitted when `mkdir(target)` fails.
        mkdir_class: &'static str,
        /// Static class emitted when `mount(2)` itself returns an error.
        mount_class: &'static str,
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    mod tests {
        use super::*;

        #[test]
        fn classify_mount_treats_success_and_ebusy_as_ok() {
            classify_mount(Ok(()), "dev-mount").expect("Ok maps to Ok");
            classify_mount(Err(nix::errno::Errno::EBUSY), "dev-mount")
                .expect("already-mounted (EBUSY) is not a failure");
        }

        #[test]
        fn classify_mount_fails_closed_on_a_real_errno() {
            let err = classify_mount(Err(nix::errno::Errno::EPERM), "proc-mount")
                .expect_err("a genuine mount error must fail closed");
            assert_eq!(err.class(), "proc-mount");
        }

        #[test]
        fn mount_pseudo_filesystems_is_a_noop_when_not_pid1() {
            // The test process is not PID 1, so the PID-1 gate returns
            // early without touching the host's mounts.
            if std::process::id() != 1 {
                mount_pseudo_filesystems().expect("non-PID-1 is a clean no-op");
            }
        }

        #[test]
        fn load_kernel_modules_is_a_noop_when_not_pid1() {
            // The test process is not PID 1, so the PID-1 gate returns
            // early without touching kernel module state.
            if std::process::id() != 1 {
                load_kernel_modules().expect("non-PID-1 is a clean no-op");
            }
        }

        #[test]
        fn load_module_family_skips_an_empty_family() {
            // No first module → nothing to probe → clean skip.
            load_module_family("6.12.63+deb13-amd64", &[])
                .expect("an empty family is a clean no-op");
        }

        #[test]
        fn load_module_family_skips_an_unbundled_family() {
            // The probe module does not exist under this fabricated kernel
            // release, so the whole family is skipped without a load
            // attempt — the "did the initrd bundle this family?" contract.
            let family: &[(&str, &'static str, &'static str)] = &[(
                "drivers/virt/coco/sev-guest/sev-guest",
                "sev-guest-modules-read-sev-guest",
                "sev-guest-modules-load-sev-guest",
            )];
            load_module_family("0.0.0-does-not-exist-hippius-test", family)
                .expect("an unbundled family (probe .ko absent) is a clean skip");
        }
    }
}
