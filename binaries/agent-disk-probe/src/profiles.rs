//! The two profiles (design §3.2, §3.3), each turning one target into a
//! `DiskProbeTarget`: metrics sorted by name, the QD1 histogram, and an
//! error code when the target could not be finished.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hippius_types::disk_stats::{DiskProbeTarget, HIST_BUCKETS};

use crate::engine::{self, AlignedBuf, Outcome, Pattern, Phase};
use crate::error::{ProbeError, Result};
use crate::request::Profile;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Sizes and durations of the profiles. [`Timing::PRODUCTION`] is the
/// design's; tests shrink it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// v1: the test file (and the sequential precondition).
    pub v1_file: u64,
    pub v1_precondition_max: Duration,
    pub v1_seq_read: Duration,
    pub v1_random: Duration,
    pub v1_qd1: Duration,
    pub ramp: Duration,
    /// d1: the zone read at 0 / 50 / 95 % of the disk.
    pub d1_zone_len: u64,
    pub d1_zone: Duration,
    pub d1_random_read: Duration,
    pub d1_qd1: Duration,
    /// d1: the write window, its sequential and sustained random writes.
    pub d1_write_window: u64,
    pub d1_seq_write: Duration,
    pub d1_sustained_write: Duration,
    /// d1: the sampled surface read.
    pub d1_surface_samples: u64,
    /// Smallest dedicated disk probed.
    pub d1_min_bytes: u64,
    /// The longest one target may take before it is given up
    /// (`probe-timeout`).
    pub target_budget: Duration,
    /// Open with `O_DIRECT` (off only for tests on a filesystem without it).
    pub direct: bool,
}

impl Timing {
    pub const PRODUCTION: Timing = Timing {
        v1_file: 16 * GIB,
        v1_precondition_max: Duration::from_secs(180),
        v1_seq_read: Duration::from_secs(30),
        v1_random: Duration::from_secs(45),
        v1_qd1: Duration::from_secs(30),
        ramp: Duration::from_secs(5),
        d1_zone_len: 8 * GIB,
        d1_zone: Duration::from_secs(15),
        d1_random_read: Duration::from_secs(30),
        d1_qd1: Duration::from_secs(20),
        d1_write_window: 8 * GIB,
        d1_seq_write: Duration::from_secs(20),
        d1_sustained_write: Duration::from_secs(60),
        d1_surface_samples: 2048,
        d1_min_bytes: 64 * GIB,
        target_budget: Duration::from_secs(30 * 60),
        direct: true,
    };
}

fn open(path: &Path, create: bool, direct: bool) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true);
    if create {
        o.create(true).truncate(true);
    }
    if direct {
        o.custom_flags(libc::O_DIRECT);
    }
    o.open(path)
}

fn target(slot: &str, profile: Profile, mut metrics: Vec<(String, u64)>) -> DiskProbeTarget {
    metrics.sort();
    DiskProbeTarget {
        slot: slot.to_string(),
        profile: profile.as_str().to_string(),
        metrics,
        hist_qd1: vec![0; HIST_BUCKETS],
        error: String::new(),
    }
}

fn metric(name: &str, value: u64) -> (String, u64) {
    (name.to_string(), value)
}

/// Collects phases; the first I/O error ends the profile with `io-error`.
struct Run<'a> {
    file: &'a File,
    nonce: &'a [u8; 32],
}

impl Run<'_> {
    fn phase(&self, phase: &Phase) -> Result<Outcome> {
        let out = engine::run(self.file, phase, self.nonce);
        if out.errors > 0 {
            return Err(ProbeError::Target("io-error"));
        }
        Ok(out)
    }
}

/// `v1`: the OS disk, through a file in the data filesystem (`dir`).
pub fn run_v1(dir: &Path, nonce: &[u8; 32], t: &Timing) -> DiskProbeTarget {
    let path = dir.join("probe.dat");
    let mut out = target("os", Profile::V1, Vec::new());
    let result = v1_phases(&path, nonce, t, &mut out);
    let _ = std::fs::remove_file(&path);
    if let Err(e) = result {
        out.error = e.to_string();
    }
    out.metrics.sort();
    out
}

fn v1_phases(path: &Path, nonce: &[u8; 32], t: &Timing, out: &mut DiskProbeTarget) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|_| ProbeError::Target("no-probe-dir"))?;
    }
    let file = open(path, true, t.direct).map_err(|_| ProbeError::Target("open-failed"))?;
    // Allocated up front: O_DIRECT writes that extend a file or fill a
    // hole take the inode lock exclusively (ext4, xfs), which would run
    // the QD8 precondition at QD1; writes into allocated (unwritten)
    // extents run in parallel. Reads stay inside the written prefix
    // below, so the unwritten rest is never read.
    nix::fcntl::fallocate(
        &file,
        nix::fcntl::FallocateFlags::empty(),
        0,
        i64::try_from(t.v1_file).unwrap_or(i64::MAX),
    )
    .map_err(|_| ProbeError::Target("no-space"))?;
    let run = Run { file: &file, nonce };
    let base = Phase {
        name: "",
        pattern: Pattern::Sequential,
        write: false,
        block: MIB as usize,
        queue_depth: 8,
        start: 0,
        len: t.v1_file,
        ramp: t.ramp,
        duration: None,
        until_bytes: None,
    };
    // 1. Precondition: the whole file written sequentially (so every later
    //    read is of real, allocated blocks).
    let seq_write = run.phase(&Phase {
        name: "v1-seq-write",
        write: true,
        ramp: Duration::ZERO,
        duration: Some(t.v1_precondition_max),
        until_bytes: Some(t.v1_file),
        ..base
    })?;
    file.sync_all()
        .map_err(|_| ProbeError::Target("io-error"))?;
    out.metrics.push(metric("seq_write_mbps", seq_write.mbps()));
    // A disk too slow to write it all within the cap leaves the rest
    // unwritten: every later phase stays inside what was written (a read
    // of a hole is answered by the filesystem, never the disk).
    let written = seq_write.bytes / MIB * MIB;
    if written < t.v1_file / 16 {
        return Err(ProbeError::Target("precondition-incomplete"));
    }
    let base = Phase {
        len: written,
        ..base
    };
    // 2. Sequential read.
    let seq_read = run.phase(&Phase {
        name: "v1-seq-read",
        duration: Some(t.v1_seq_read),
        ..base
    })?;
    out.metrics.push(metric("seq_read_mbps", seq_read.mbps()));
    // 3. Random read, 4 KiB QD32.
    let small = Phase {
        pattern: Pattern::Random,
        block: 4096,
        queue_depth: 32,
        duration: Some(t.v1_random),
        ..base
    };
    let rr = run.phase(&Phase {
        name: "v1-rr",
        ..small
    })?;
    out.metrics.push(metric("rr_iops", rr.iops()));
    out.metrics
        .push(metric("rr_p99_us", rr.latency.percentile(990)));
    // 4. Random write, 4 KiB QD32.
    let rw = run.phase(&Phase {
        name: "v1-rw",
        write: true,
        ..small
    })?;
    out.metrics.push(metric("rw_iops", rw.iops()));
    out.metrics
        .push(metric("rw_p99_us", rw.latency.percentile(990)));
    // 5. Random read, 4 KiB QD1.
    let qd1 = run.phase(&Phase {
        name: "v1-qd1",
        queue_depth: 1,
        ramp: Duration::ZERO,
        duration: Some(t.v1_qd1),
        ..small
    })?;
    out.metrics
        .push(metric("qd1_p50_us", qd1.latency.percentile(500)));
    out.metrics
        .push(metric("qd1_p99_us", qd1.latency.percentile(990)));
    out.hist_qd1 = qd1.latency.log2();
    Ok(())
}

/// The block device of slot `slot`: the disk udev links as
/// `<by_id>/virtio-hippius-<slot>`, as `<dev_root>/<name>`. No device I/O
/// (a `serial` read is one, and a hung disk never answers it).
pub fn find_slot_device(
    by_id: &Path,
    dev_root: &Path,
    slot: &str,
) -> std::result::Result<PathBuf, &'static str> {
    let link = by_id.join(format!(
        "virtio-{}{slot}",
        hippius_types::disk_stats::SLOT_SERIAL_PREFIX
    ));
    let target = std::fs::read_link(&link).map_err(|_| "disk-not-found")?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.starts_with("vd") && n.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or("disk-not-found")?;
    Ok(dev_root.join(name))
}

/// `d1`: a dedicated disk at `device` (already behind the ephemeral
/// dm-crypt mapping when probed for real).
pub fn run_d1(slot: &str, device: &Path, nonce: &[u8; 32], t: &Timing) -> DiskProbeTarget {
    let mut out = target(slot, Profile::D1, Vec::new());
    if let Err(e) = d1_phases(device, nonce, t, &mut out) {
        out.error = e.to_string();
    }
    out.metrics.sort();
    out
}

fn d1_phases(device: &Path, nonce: &[u8; 32], t: &Timing, out: &mut DiskProbeTarget) -> Result<()> {
    let mut file = open(device, false, t.direct).map_err(|_| ProbeError::Target("open-failed"))?;
    let size = file
        .seek(SeekFrom::End(0))
        .map_err(|_| ProbeError::Target("size-unknown"))?;
    let size = size - size % MIB;
    if size < t.d1_min_bytes {
        return Err(ProbeError::Target("disk-too-small"));
    }
    // The size the guest sees (ungraded): vali sells the disk at this
    // size, never at the miner's own figure.
    out.metrics.push(metric("size_mib", size / MIB));
    let run = Run { file: &file, nonce };
    let zone_len = t.d1_zone_len.min(size / 4) / MIB * MIB;
    let zone = |name: &'static str, at_percent: u64| Phase {
        name,
        pattern: Pattern::Sequential,
        write: false,
        block: MIB as usize,
        queue_depth: 8,
        start: ((size - zone_len) * at_percent / 100) / MIB * MIB,
        len: zone_len,
        ramp: Duration::ZERO,
        duration: Some(t.d1_zone),
        until_bytes: None,
    };
    // 1. Zoned sequential reads: outer (0 %), middle, inner (95 %).
    for (name, at, key) in [
        ("d1-zone-0", 0, "seq_read_outer_mbps"),
        ("d1-zone-50", 50, "seq_read_mid_mbps"),
        ("d1-zone-95", 95, "seq_read_inner_mbps"),
    ] {
        let o = run.phase(&zone(name, at))?;
        out.metrics.push(metric(key, o.mbps()));
    }
    // 2. Random read across the whole disk, 4 KiB QD32.
    let small = Phase {
        name: "d1-rr",
        pattern: Pattern::Random,
        write: false,
        block: 4096,
        queue_depth: 32,
        start: 0,
        len: size,
        ramp: Duration::ZERO,
        duration: Some(t.d1_random_read),
        until_bytes: None,
    };
    let rr = run.phase(&small)?;
    out.metrics.push(metric("rr_iops", rr.iops()));
    // 3. QD1 latency.
    let qd1 = run.phase(&Phase {
        name: "d1-qd1",
        queue_depth: 1,
        duration: Some(t.d1_qd1),
        ..small
    })?;
    out.metrics
        .push(metric("qd1_p50_us", qd1.latency.percentile(500)));
    out.metrics
        .push(metric("qd1_p99_us", qd1.latency.percentile(990)));
    out.hist_qd1 = qd1.latency.log2();
    // 4. In a random window: sequential write, then sustained random
    //    write (exposes SMR collapse and the cache-full cliff).
    let window = t.d1_write_window.min(size / 4) / MIB * MIB;
    let mut rng = engine::offset_rng(nonce, "d1-window", 0);
    let start = (rng.next_u64() % ((size - window) / MIB + 1)) * MIB;
    let sw = run.phase(&Phase {
        name: "d1-seq-write",
        pattern: Pattern::Sequential,
        write: true,
        block: MIB as usize,
        queue_depth: 8,
        start,
        len: window,
        duration: Some(t.d1_seq_write),
        ..small
    })?;
    out.metrics.push(metric("seq_write_mbps", sw.mbps()));
    let rw = run.phase(&Phase {
        name: "d1-rw",
        write: true,
        start,
        len: window,
        duration: Some(t.d1_sustained_write),
        ..small
    })?;
    out.metrics.push(metric("rw_sustained_iops", rw.iops()));
    // 5. Sampled surface read: every sample attempted, errors counted.
    let mut buf = AlignedBuf::new(MIB as usize, 0);
    let samples = t.d1_surface_samples.max(1);
    let stride = (size / MIB) / samples;
    let mut errors = 0u64;
    for i in 0..samples {
        let offset = (i * stride.max(1)).min(size / MIB - 1) * MIB;
        if file.read_exact_at(buf.as_mut_slice(), offset).is_err() {
            errors += 1;
        }
    }
    out.metrics.push(metric("surface_errors", errors));
    if errors > 0 {
        return Err(ProbeError::Target("io-error"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    pub(crate) const FAST: Timing = Timing {
        v1_file: 4 * MIB,
        v1_precondition_max: Duration::from_secs(10),
        v1_seq_read: Duration::from_millis(30),
        v1_random: Duration::from_millis(30),
        v1_qd1: Duration::from_millis(30),
        ramp: Duration::from_millis(5),
        d1_zone_len: 2 * MIB,
        d1_zone: Duration::from_millis(20),
        d1_random_read: Duration::from_millis(20),
        d1_qd1: Duration::from_millis(20),
        d1_write_window: 2 * MIB,
        d1_seq_write: Duration::from_millis(20),
        d1_sustained_write: Duration::from_millis(20),
        d1_surface_samples: 16,
        d1_min_bytes: 8 * MIB,
        target_budget: Duration::from_secs(60),
        direct: false,
    };

    fn names(t: &DiskProbeTarget) -> Vec<&str> {
        t.metrics.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn v1_reports_every_metric_sorted_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let t = run_v1(dir.path(), &[3; 32], &FAST);
        assert_eq!(t.error, "");
        assert_eq!(
            names(&t),
            [
                "qd1_p50_us",
                "qd1_p99_us",
                "rr_iops",
                "rr_p99_us",
                "rw_iops",
                "rw_p99_us",
                "seq_read_mbps",
                "seq_write_mbps"
            ]
        );
        assert!(t.metrics.iter().find(|(k, _)| k == "rr_iops").unwrap().1 > 0);
        assert!(t.hist_qd1.iter().any(|n| *n > 0));
        assert!(!dir.path().join("probe.dat").exists());
        assert_eq!(t.slot, "os");
        assert_eq!(t.profile, "v1");
    }

    #[test]
    fn d1_reports_every_metric_on_a_device_sized_file() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("disk");
        std::fs::File::create(&dev)
            .unwrap()
            .set_len(16 * MIB)
            .unwrap();
        let t = run_d1("x0", &dev, &[4; 32], &FAST);
        assert_eq!(t.error, "");
        assert_eq!(
            names(&t),
            [
                "qd1_p50_us",
                "qd1_p99_us",
                "rr_iops",
                "rw_sustained_iops",
                "seq_read_inner_mbps",
                "seq_read_mid_mbps",
                "seq_read_outer_mbps",
                "seq_write_mbps",
                "size_mib",
                "surface_errors"
            ]
        );
        assert_eq!(
            t.metrics.iter().find(|(k, _)| k == "size_mib").unwrap().1,
            16
        );
        assert_eq!(
            t.metrics
                .iter()
                .find(|(k, _)| k == "surface_errors")
                .unwrap()
                .1,
            0
        );
    }

    #[test]
    fn a_disk_below_the_minimum_or_missing_is_an_error_code() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("disk");
        std::fs::File::create(&dev).unwrap().set_len(MIB).unwrap();
        assert_eq!(run_d1("x0", &dev, &[4; 32], &FAST).error, "disk-too-small");
        assert_eq!(
            run_d1("x0", &dir.path().join("none"), &[4; 32], &FAST).error,
            "open-failed"
        );
    }

    #[test]
    fn a_slot_device_is_found_by_its_udev_link() {
        let dir = tempfile::tempdir().unwrap();
        for (link, dev) in [
            ("virtio-hippius-os", "../../vda"),
            ("virtio-hippius-x0", "../../vdb"),
            ("virtio-hippius-x1-part1", "../../vdc1"),
            ("ata-hippius-x2", "../../sda"),
        ] {
            std::os::unix::fs::symlink(dev, dir.path().join(link)).unwrap();
        }
        let dev = Path::new("/dev");
        assert_eq!(
            find_slot_device(dir.path(), dev, "x0"),
            Ok(PathBuf::from("/dev/vdb"))
        );
        assert_eq!(
            find_slot_device(dir.path(), dev, "x1"),
            Err("disk-not-found")
        );
        assert_eq!(
            find_slot_device(dir.path(), dev, "x2"),
            Err("disk-not-found")
        );
        assert_eq!(
            find_slot_device(dir.path(), dev, "x5"),
            Err("disk-not-found")
        );
    }
}
