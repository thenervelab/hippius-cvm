//! Running a request into a `DiskProbeResult` and leaving it where the
//! telemetry agent reads it (`/run/hippius/disk-probe/result.cbor`).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use hippius_types::disk_stats::{DiskProbeResult, DiskProbeTarget, HIST_BUCKETS};

use crate::crypt::{close_opener_mapping, Mapping};
use crate::error::{ProbeError, Result};
use crate::profiles::{self, Timing};
use crate::request::{Profile, Request};

/// Where things are on the guest.
#[derive(Debug, Clone)]
pub struct Host {
    /// The v1 test file's directory, on the data (OS disk) filesystem.
    pub probe_dir: PathBuf,
    /// udev's `/dev/disk/by-id` (slot serials, without device I/O).
    pub by_id: PathBuf,
    pub dev_root: PathBuf,
    /// `/dev/mapper` (where the initramfs opener's slot mappings are).
    pub mapper_root: PathBuf,
    pub cryptsetup: PathBuf,
    /// The guest components record (`version=` is the release).
    pub components_record: PathBuf,
    /// `uname -r`.
    pub osrelease: PathBuf,
    /// Map dedicated disks through dm-crypt (off only in tests).
    pub crypt: bool,
}

impl Host {
    pub fn production() -> Self {
        Self {
            probe_dir: PathBuf::from("/var/lib/hippius-probe"),
            by_id: PathBuf::from("/dev/disk/by-id"),
            dev_root: PathBuf::from("/dev"),
            mapper_root: PathBuf::from("/dev/mapper"),
            cryptsetup: PathBuf::from("/usr/sbin/cryptsetup"),
            components_record: PathBuf::from("/run/hippius/guest-components"),
            osrelease: PathBuf::from("/proc/sys/kernel/osrelease"),
            crypt: true,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn release_version(record: &Path) -> u32 {
    std::fs::read_to_string(record)
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("version=").map(str::to_string))
        })
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn kernel(osrelease: &Path) -> String {
    let k = std::fs::read_to_string(osrelease).unwrap_or_default();
    k.trim()
        .chars()
        .filter(|c| (' '..='~').contains(c))
        .take(hippius_types::disk_stats::MAX_KERNEL_LEN)
        .collect()
}

fn failed(slot: &str, profile: Profile, code: &'static str) -> DiskProbeTarget {
    DiskProbeTarget {
        slot: slot.to_string(),
        profile: profile.as_str().to_string(),
        metrics: Vec::new(),
        hist_qd1: vec![0; HIST_BUCKETS],
        error: code.to_string(),
    }
}

/// `f` on its own thread, `None` if it is not done within `budget` (a
/// read a dying disk never answers, or a target slower than its budget):
/// the probe cancels it ([`crate::engine::set_cancel`]) so it stops
/// issuing I/O before the next target is measured, gives it a moment to
/// clean up (its test file, its mapping), and moves on. A thread stuck in
/// the kernel is left behind.
pub fn within<T: Send + 'static>(
    budget: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&cancel);
    std::thread::spawn(move || {
        crate::engine::set_cancel(flag);
        let _ = tx.send(f());
    });
    match rx.recv_timeout(budget) {
        Ok(v) => Some(v),
        Err(_) => {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = rx.recv_timeout(CLEANUP_GRACE);
            None
        }
    }
}

/// How long an aborted target gets to return and clean up.
const CLEANUP_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

fn probe_one(
    slot: &str,
    profile: Profile,
    nonce: [u8; 32],
    host: &Host,
    timing: &Timing,
) -> DiskProbeTarget {
    match profile {
        Profile::V1 => profiles::run_v1(&host.probe_dir, &nonce, timing),
        Profile::D1 => {
            let device = match profiles::find_slot_device(&host.by_id, &host.dev_root, slot) {
                Ok(device) => device,
                Err(code) => return failed(slot, profile, code),
            };
            if !host.crypt {
                return profiles::run_d1(slot, &device, &nonce, timing);
            }
            // The opener's LUKS mapping of a slot (guest release 6+) holds
            // the device the probe's plain mapping needs (crypt.rs).
            if let Err(e) = close_opener_mapping(&host.cryptsetup, &host.mapper_root, slot) {
                return failed(slot, profile, error_code(&e));
            }
            match Mapping::open(&host.cryptsetup, &device, slot) {
                Ok(mapping) => profiles::run_d1(slot, &mapping.device, &nonce, timing),
                Err(e) => failed(slot, profile, error_code(&e)),
            }
        }
    }
}

/// Probe every target of `req`, one at a time, each within its budget.
pub fn run(req: &Request, host: &Host, timing: &Timing) -> DiskProbeResult {
    let started_at = now_unix();
    let targets = req
        .targets
        .iter()
        .map(|t| {
            let (slot, profile, nonce) = (t.slot.clone(), t.profile, req.nonce);
            let (host, timing) = (host.clone(), *timing);
            within(timing.target_budget, move || {
                probe_one(&slot, profile, nonce, &host, &timing)
            })
            .unwrap_or_else(|| failed(&t.slot, t.profile, "probe-timeout"))
        })
        .collect();
    DiskProbeResult {
        run_id: req.run_id,
        nonce: req.nonce,
        vm_id: req.vm_id.clone(),
        vcpus: std::thread::available_parallelism()
            .map_or(0, |n| u32::try_from(n.get()).unwrap_or(u32::MAX)),
        kernel: kernel(&host.osrelease),
        release_version: release_version(&host.components_record),
        started_at,
        finished_at: now_unix().max(started_at),
        targets,
    }
}

fn error_code(e: &ProbeError) -> &'static str {
    match e {
        ProbeError::Target(code) => code,
        _ => "probe-failed",
    }
}

/// Write `result` as canonical CBOR at `path`, atomically, mode 0600.
pub fn write(result: &DiskProbeResult, path: &Path) -> Result<()> {
    let value = result
        .to_value()
        .map_err(|_| ProbeError::Result("encode"))?;
    let bytes =
        hippius_types::cbor::to_canonical_vec(&value).map_err(|_| ProbeError::Result("encode"))?;
    let dir = path.parent().ok_or(ProbeError::Result("path"))?;
    std::fs::create_dir_all(dir).map_err(|_| ProbeError::Result("dir"))?;
    let tmp = dir.join(".result.cbor.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| ProbeError::Result("write"))?;
    f.write_all(&bytes)
        .map_err(|_| ProbeError::Result("write"))?;
    f.sync_all().map_err(|_| ProbeError::Result("write"))?;
    std::fs::rename(&tmp, path).map_err(|_| ProbeError::Result("write"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::profiles::Timing;
    use std::time::Duration;

    const MIB: u64 = 1024 * 1024;

    fn timing() -> Timing {
        Timing {
            v1_file: 4 * MIB,
            v1_precondition_max: Duration::from_secs(10),
            v1_seq_read: Duration::from_millis(20),
            v1_random: Duration::from_millis(20),
            v1_qd1: Duration::from_millis(20),
            ramp: Duration::ZERO,
            d1_zone_len: 2 * MIB,
            d1_zone: Duration::from_millis(10),
            d1_random_read: Duration::from_millis(10),
            d1_qd1: Duration::from_millis(10),
            d1_write_window: 2 * MIB,
            d1_seq_write: Duration::from_millis(10),
            d1_sustained_write: Duration::from_millis(10),
            d1_surface_samples: 8,
            d1_min_bytes: 8 * MIB,
            target_budget: Duration::from_secs(60),
            direct: false,
        }
    }

    /// Two disks, the OS one and `x0` (a device-sized file standing in
    /// for `/dev/vdb`), plus an `x1` the request names but the VM lacks.
    #[test]
    fn a_two_disk_request_probes_each_and_writes_a_result_the_receipt_takes() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::create_dir_all(r.join("by-id")).unwrap();
        for (dev, serial) in [("vda", "hippius-os"), ("vdb", "hippius-x0")] {
            std::os::unix::fs::symlink(
                format!("../../{dev}"),
                r.join("by-id").join(format!("virtio-{serial}")),
            )
            .unwrap();
        }
        std::fs::create_dir_all(r.join("dev")).unwrap();
        std::fs::File::create(r.join("dev/vdb"))
            .unwrap()
            .set_len(16 * MIB)
            .unwrap();
        std::fs::write(
            r.join("components"),
            "version=5\nsecurity_epoch=1\nmounted=yes\n",
        )
        .unwrap();
        std::fs::write(r.join("osrelease"), "6.8.0-generic\n").unwrap();
        let host = Host {
            probe_dir: r.join("probe"),
            by_id: r.join("by-id"),
            dev_root: r.join("dev"),
            mapper_root: r.join("mapper"),
            cryptsetup: r.join("no-cryptsetup"),
            components_record: r.join("components"),
            osrelease: r.join("osrelease"),
            crypt: false,
        };
        let req = Request::parse(
            format!(
                r#"{{"vm_id":"probe-1","run_id":"{}","nonce":"{}","start_delay_s":0,
                "targets":[{{"slot":"os","profile":"v1"}},{{"slot":"x0","profile":"d1"}},
                {{"slot":"x1","profile":"d1"}}]}}"#,
                "01".repeat(16),
                "02".repeat(32)
            )
            .as_bytes(),
        )
        .unwrap();
        let result = run(&req, &host, &timing());
        assert_eq!(result.release_version, 5);
        assert_eq!(result.kernel, "6.8.0-generic");
        let slots: Vec<_> = result
            .targets
            .iter()
            .map(|t| (t.slot.as_str(), t.error.as_str()))
            .collect();
        assert_eq!(slots, [("os", ""), ("x0", ""), ("x1", "disk-not-found")]);
        let out = r.join("run/result.cbor");
        write(&result, &out).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // What the telemetry agent decodes.
        let v: ciborium::value::Value =
            ciborium::de::from_reader(std::fs::read(&out).unwrap().as_slice()).unwrap();
        assert_eq!(DiskProbeResult::from_value(&v).unwrap(), result);
    }

    #[test]
    fn a_target_past_its_budget_is_given_up() {
        assert_eq!(within(Duration::from_secs(5), || 7), Some(7));
        assert_eq!(
            within(Duration::from_millis(20), || std::thread::sleep(
                Duration::from_secs(2)
            )),
            None
        );
    }

    #[test]
    fn a_failed_crypt_mapping_is_the_targets_error() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::create_dir_all(r.join("by-id")).unwrap();
        std::os::unix::fs::symlink("../../vdb", r.join("by-id/virtio-hippius-x0")).unwrap();
        let host = Host {
            probe_dir: r.join("probe"),
            by_id: r.join("by-id"),
            dev_root: r.join("dev"),
            mapper_root: r.join("mapper"),
            cryptsetup: r.join("no-cryptsetup"),
            components_record: r.join("none"),
            osrelease: r.join("none"),
            crypt: true,
        };
        let req = Request::parse(
            format!(
                r#"{{"vm_id":"probe-1","run_id":"{}","nonce":"{}","start_delay_s":0,
                "targets":[{{"slot":"x0","profile":"d1"}}]}}"#,
                "01".repeat(16),
                "02".repeat(32)
            )
            .as_bytes(),
        )
        .unwrap();
        let result = run(&req, &host, &timing());
        assert_eq!(result.targets[0].error, "crypt-open-failed");
        assert_eq!(result.release_version, 0);
        assert!(result.to_value().is_ok());
    }

    /// A slot the initramfs opener formatted and opened (guest release 6+):
    /// its mapping is closed first, then the probe maps the device; a
    /// mapping that will not close is the target's error and the device is
    /// never mapped.
    #[test]
    fn the_openers_mapping_is_closed_before_the_probe_opens_its_own() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::create_dir_all(r.join("by-id")).unwrap();
        std::os::unix::fs::symlink("../../vdf", r.join("by-id/virtio-hippius-x0")).unwrap();
        std::fs::create_dir_all(r.join("mapper")).unwrap();
        // `close` removes the mapping and exits `$CLOSE`; `open` always
        // fails here (no device-mapper in a unit test).
        let script = |name: &str, close_code: i32| {
            let path = r.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\necho \"$1 $2\" >> '{log}'\nif [ \"$1\" = close ]; then\n  \
                     [ {close_code} -eq 0 ] && rm -f '{mapper}/'\"$2\"\n  exit {close_code}\nfi\nexit 1\n",
                    log = r.join("calls").display(),
                    mapper = r.join("mapper").display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            crate::crypt::test_support::exec_ready(&path, &r.join("calls"));
            path
        };
        let host = |cryptsetup: PathBuf| Host {
            probe_dir: r.join("probe"),
            by_id: r.join("by-id"),
            dev_root: r.join("dev"),
            mapper_root: r.join("mapper"),
            cryptsetup,
            components_record: r.join("none"),
            osrelease: r.join("none"),
            crypt: true,
        };
        let req = Request::parse(
            format!(
                r#"{{"vm_id":"probe-1","run_id":"{}","nonce":"{}","start_delay_s":0,
                "targets":[{{"slot":"x0","profile":"d1"}}]}}"#,
                "01".repeat(16),
                "02".repeat(32)
            )
            .as_bytes(),
        )
        .unwrap();

        std::fs::write(r.join("mapper/hippius-x0"), b"").unwrap();
        let refused = run(&req, &host(script("cs-refuse", 3)), &timing());
        assert_eq!(refused.targets[0].error, "opener-close-failed");
        assert_eq!(
            std::fs::read_to_string(r.join("calls")).unwrap(),
            "close hippius-x0\n"
        );

        std::fs::remove_file(r.join("calls")).unwrap();
        let closed = run(&req, &host(script("cs-close", 0)), &timing());
        assert!(!r.join("mapper/hippius-x0").exists());
        assert_eq!(
            std::fs::read_to_string(r.join("calls")).unwrap(),
            "close hippius-x0\nopen --type\n"
        );
        assert_eq!(closed.targets[0].error, "crypt-open-failed");
    }
}
