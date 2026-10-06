//! `--integrity-wipe` — initialise every sector of a freshly
//! `luksFormat --integrity-no-wipe`'d LUKS2 + dm-integrity volume.
//!
//! dm-integrity keeps an authentication tag per sector. A sector that was
//! never written through the mapping carries a garbage tag and reads back
//! as `EILSEQ`, so before the filesystem sees the device every sector has
//! to be written once. `cryptsetup luksFormat` does that itself with ONE
//! synchronous 1 MiB write at a time (queue depth ≤ 1), which makes the
//! first boot of a golden VM take `disk_gb / serial_rate` — 9 min for a
//! medium on a write-through SATA RAID, 72 min for a 2xlarge.
//!
//! This writes the same zeros through the same mapping, with [`WORKERS`]
//! writers in flight. The end state is identical to cryptsetup's own
//! wipe: every sector written once through dm-crypt's AEAD under the
//! in-guest master key, so every sector carries a valid tag and any later
//! host modification reads `EILSEQ`. Nothing about the security changes,
//! only the queue depth.
//!
//! Striping is interleaved: chunk `i` goes to worker `i % WORKERS`, so the
//! writes in flight stay within `WORKERS × BLOCK` bytes of each other.
//! That keeps the stream sequential enough for spinning disks and RAID
//! controllers, where disjoint per-worker ranges would seek.
//!
//! The caller (`hippius-golden-overlay.sh`) activates the mapping with
//! `--integrity-no-journal` for the wipe, as cryptsetup does for its own:
//! journaling zeros only doubles the writes. Any failure is fatal — the
//! caller never puts a filesystem on a partially wiped device.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{FileExt, FileTypeExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// Writers in flight. 8 × 4 MiB was the knee in the lab (4 → 8 gained,
/// 16 lost). Constants, not flags: a cmdline knob would move the launch
/// measurement for no benefit.
pub const WORKERS: usize = 8;

/// Bytes per write. Also bounds the in-flight total to 32 MiB, well
/// under an SEV guest's swiotlb bounce pool (64 MiB minimum).
pub const BLOCK: usize = 4 << 20;

/// `O_DIRECT` needs the buffer address, the file offset and the length
/// aligned to the logical block size. 4096 covers every case we meet
/// (the LUKS2 sector size we format with is 4096).
pub const ALIGN: usize = 4096;

/// The only directory a wipe target may live in.
const MAPPER_DIR: &str = "/dev/mapper";

#[derive(Debug, PartialEq, Eq)]
pub enum WipeError {
    /// The target is not something we are willing to overwrite.
    Target(String),
    /// Opening or sizing the device failed.
    Open(String),
    /// A write failed. `offset` is where the failing write started.
    Write { offset: u64, error: String },
    /// Flushing the device cache failed.
    Sync(String),
}

impl std::fmt::Display for WipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Target(m) => write!(f, "target: {m}"),
            Self::Open(m) => write!(f, "open: {m}"),
            Self::Write { offset, error } => write!(f, "write at offset {offset}: {error}"),
            Self::Sync(m) => write!(f, "sync: {m}"),
        }
    }
}

/// Refuse anything that is not a block device directly under
/// `/dev/mapper/`. The wipe zeroes a whole device; the one thing it must
/// never be pointed at is the raw miner disk, the golden lower or a
/// mounted volume (the last is also refused by `O_EXCL` at open).
pub fn check_target(path: &Path) -> Result<(), WipeError> {
    check_target_under(path, Path::new(MAPPER_DIR))
}

fn check_target_under(path: &Path, dir: &Path) -> Result<(), WipeError> {
    let lexically_ok = path.parent() == Some(dir)
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !lexically_ok {
        return Err(WipeError::Target(format!(
            "refusing {}: only a device directly under {}/ may be wiped",
            path.display(),
            dir.display()
        )));
    }
    let meta = std::fs::metadata(path)
        .map_err(|e| WipeError::Target(format!("{}: {e}", path.display())))?;
    if !meta.file_type().is_block_device() {
        return Err(WipeError::Target(format!(
            "refusing {}: not a block device",
            path.display()
        )));
    }
    Ok(())
}

/// Open the device for the wipe: `O_DIRECT` (no page cache, real queue
/// depth) and `O_EXCL` (fails with `EBUSY` if anything — a mount, another
/// mapping — holds the device). One descriptor shared by every worker:
/// a second `O_EXCL` open of the same block device would itself fail.
pub fn open_device(path: &Path) -> Result<(File, u64), WipeError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_DIRECT | libc::O_EXCL)
        .open(path)
        .map_err(|e| WipeError::Open(format!("{}: {e}", path.display())))?;
    // `lseek(SEEK_END)` reports a block device's size without the
    // `BLKGETSIZE64` ioctl (this crate forbids `unsafe`).
    let size = file
        .seek(SeekFrom::End(0))
        .map_err(|e| WipeError::Open(format!("{}: size: {e}", path.display())))?;
    Ok((file, size))
}

/// Positional write, the one operation the wipe needs. A trait so the
/// short-write / `EINTR` / failure paths are testable without a device.
pub trait WriteAt: Sync {
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize>;
}

impl WriteAt for File {
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        FileExt::write_at(self, buf, offset)
    }
}

/// Byte range `(offset, len)` of chunk `index` on a device of `size`
/// bytes. The last chunk is short when `size` is not a multiple of
/// `block`.
pub fn chunk_range(index: u64, block: u64, size: u64) -> (u64, u64) {
    let offset = index * block;
    (offset, block.min(size - offset))
}

/// Chunks on a device of `size` bytes.
pub fn chunk_count(size: u64, block: u64) -> u64 {
    size.div_ceil(block)
}

/// The chunks worker `worker` of `workers` writes: `worker`,
/// `worker + workers`, `worker + 2·workers`, … (interleaved striping).
pub fn worker_chunks(worker: usize, workers: usize, chunks: u64) -> impl Iterator<Item = u64> {
    (worker as u64..chunks).step_by(workers)
}

/// A zeroed buffer of `len` bytes whose start is `ALIGN`-aligned, without
/// `unsafe`: over-allocate by `ALIGN` and slice from the first aligned
/// address.
pub struct AlignedZeros {
    storage: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedZeros {
    pub fn new(len: usize) -> Self {
        let storage = vec![0u8; len + ALIGN];
        let start = storage.as_ptr().align_offset(ALIGN);
        Self {
            storage,
            start,
            len,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.len]
    }
}

/// Write `buf` fully at `offset`: loop over short writes, retry `EINTR`,
/// and treat a zero-length write as an error rather than spinning.
fn write_all_at<W: WriteAt + ?Sized>(dev: &W, buf: &[u8], offset: u64) -> Result<(), WipeError> {
    let mut done = 0usize;
    while done < buf.len() {
        match dev.write_at(&buf[done..], offset + done as u64) {
            Ok(0) => {
                return Err(WipeError::Write {
                    offset: offset + done as u64,
                    error: "wrote zero bytes".to_string(),
                })
            }
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(WipeError::Write {
                    offset: offset + done as u64,
                    error: e.to_string(),
                })
            }
        }
    }
    Ok(())
}

/// Zero `size` bytes of `dev` with `workers` writers of `block` bytes.
///
/// `size` must be a multiple of [`ALIGN`] and `block` a non-zero multiple
/// of [`ALIGN`] — checked BEFORE the first write, because an unaligned
/// `O_DIRECT` write fails with `EINVAL` halfway through the device. The
/// first error stops every worker at its next chunk and is returned with
/// the offset of the failing write. `progress(done, size)` is called
/// after every chunk.
pub fn wipe<W: WriteAt + ?Sized>(
    dev: &W,
    size: u64,
    workers: usize,
    block: usize,
    progress: &(dyn Fn(u64, u64) + Sync),
) -> Result<(), WipeError> {
    let align = ALIGN as u64;
    if workers == 0 {
        return Err(WipeError::Target("zero workers".to_string()));
    }
    if block == 0 || !block.is_multiple_of(ALIGN) {
        return Err(WipeError::Target(format!(
            "block size {block} is not a non-zero multiple of {ALIGN}"
        )));
    }
    if size == 0 || !size.is_multiple_of(align) {
        return Err(WipeError::Target(format!(
            "device size {size} is not a non-zero multiple of {ALIGN} — O_DIRECT would fail mid-device"
        )));
    }

    let chunks = chunk_count(size, block as u64);
    let written = AtomicU64::new(0);
    let failed = AtomicBool::new(false);
    let first_error: Mutex<Option<WipeError>> = Mutex::new(None);

    std::thread::scope(|scope| {
        for worker in 0..workers {
            let (written, failed, first_error) = (&written, &failed, &first_error);
            scope.spawn(move || {
                let zeros = AlignedZeros::new(block);
                for index in worker_chunks(worker, workers, chunks) {
                    if failed.load(Ordering::Relaxed) {
                        return;
                    }
                    let (offset, len) = chunk_range(index, block as u64, size);
                    if let Err(e) = write_all_at(dev, &zeros.as_slice()[..len as usize], offset) {
                        failed.store(true, Ordering::Relaxed);
                        first_error
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get_or_insert(e);
                        return;
                    }
                    let done = written.fetch_add(len, Ordering::Relaxed) + len;
                    progress(done, size);
                }
            });
        }
    });

    match first_error
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Progress line every 10 %, from whichever worker crosses the boundary.
/// Goes to stderr; the initramfs routes it to `/dev/kmsg`, so the serial
/// console shows how far a long first boot is.
pub fn progress_every_tenth(path: &Path) -> impl Fn(u64, u64) + Sync + '_ {
    let last_decile = AtomicU64::new(0);
    move |done, size| {
        let decile = done * 10 / size;
        if last_decile.fetch_max(decile, Ordering::Relaxed) < decile {
            eprintln!(
                "hippius-guest-release: integrity-wipe {}: {}% ({} of {} MiB)",
                path.display(),
                decile * 10,
                done >> 20,
                size >> 20
            );
        }
    }
}

/// The whole `--integrity-wipe` mode: check, open, wipe, `fdatasync`.
pub fn run(path: &Path) -> Result<u64, WipeError> {
    check_target(path)?;
    let (file, size) = open_device(path)?;
    eprintln!(
        "hippius-guest-release: integrity-wipe {}: start, {} MiB, {WORKERS} writers x {} MiB",
        path.display(),
        size >> 20,
        BLOCK >> 20
    );
    wipe(&file, size, WORKERS, BLOCK, &progress_every_tenth(path))?;
    file.sync_data()
        .map_err(|e| WipeError::Sync(e.to_string()))?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Read;
    use std::sync::atomic::AtomicUsize;

    const MIB: u64 = 1 << 20;

    #[test]
    fn every_chunk_is_owned_by_exactly_one_worker() {
        for (chunks, workers) in [
            (0u64, 8usize),
            (1, 8),
            (7, 8),
            (8, 8),
            (9, 8),
            (1000, 8),
            (13, 3),
        ] {
            let mut seen = HashSet::new();
            for w in 0..workers {
                for c in worker_chunks(w, workers, chunks) {
                    assert!(c < chunks, "chunk {c} out of range {chunks}");
                    assert!(seen.insert(c), "chunk {c} assigned twice");
                    assert_eq!(c as usize % workers, w, "not interleaved");
                }
            }
            assert_eq!(
                seen.len() as u64,
                chunks,
                "chunks={chunks} workers={workers}"
            );
        }
    }

    #[test]
    fn ranges_tile_the_device_with_a_short_tail() {
        let block = 4 * MIB;
        for size in [4096, 4 * MIB, 4 * MIB + 4096, 10 * MIB, 1024 * MIB + 8192] {
            let chunks = chunk_count(size, block);
            let mut next = 0u64;
            for i in 0..chunks {
                let (off, len) = chunk_range(i, block, size);
                assert_eq!(off, next, "gap or overlap at chunk {i}");
                assert!(len > 0 && len <= block);
                assert_eq!(off % ALIGN as u64, 0);
                assert_eq!(len % ALIGN as u64, 0, "tail not O_DIRECT-aligned");
                next = off + len;
            }
            assert_eq!(next, size, "does not end at the device end");
        }
    }

    #[test]
    fn the_buffer_is_zero_and_aligned_for_o_direct() {
        for len in [4096, BLOCK] {
            let z = AlignedZeros::new(len);
            assert_eq!(z.as_slice().len(), len);
            assert_eq!(z.as_slice().as_ptr() as usize % ALIGN, 0);
            assert!(z.as_slice().iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn unaligned_geometry_is_refused_before_any_write() {
        let dev = Recorder::default();
        let noop = |_: u64, _: u64| {};
        for (size, block) in [
            (4096 * 3 + 512, BLOCK),
            (0, BLOCK),
            (8192, 4096 + 512),
            (8192, 0),
        ] {
            assert!(matches!(
                wipe(&dev, size, 4, block, &noop),
                Err(WipeError::Target(_))
            ));
        }
        assert!(matches!(
            wipe(&dev, 8192, 0, 4096, &noop),
            Err(WipeError::Target(_))
        ));
        assert_eq!(dev.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn every_byte_is_written_once_through_short_writes_and_eintr() {
        let size = 37 * 4096 + 5 * MIB;
        let dev = Recorder {
            short_every: Some(3),
            eintr_every: Some(5),
            ..Default::default()
        };
        wipe(&dev, size, 4, 64 * 1024, &|_, _| {}).unwrap();
        let mut spans = dev.spans.lock().unwrap().clone();
        spans.sort_unstable();
        let mut next = 0;
        for (off, len) in spans {
            assert_eq!(off, next, "gap or overlap at {off}");
            next = off + len;
        }
        assert_eq!(next, size);
    }

    #[test]
    fn the_first_error_is_returned_with_its_offset_and_nothing_follows_it() {
        let size = 64 * MIB;
        let dev = Recorder {
            fail_at: Some(12 * MIB),
            ..Default::default()
        };
        let err = wipe(&dev, size, 1, MIB as usize, &|_, _| {}).unwrap_err();
        assert_eq!(
            err,
            WipeError::Write {
                offset: 12 * MIB,
                error: std::io::Error::from_raw_os_error(libc::EIO).to_string()
            }
        );
        let written: u64 = dev.spans.lock().unwrap().iter().map(|s| s.1).sum();
        assert_eq!(written, 12 * MIB, "the worker kept going after the failure");
        // Several workers: the same error surfaces, whoever hits it.
        let dev = Recorder {
            fail_at: Some(12 * MIB),
            ..Default::default()
        };
        let err = wipe(&dev, size, WORKERS, MIB as usize, &|_, _| {}).unwrap_err();
        assert!(
            matches!(err, WipeError::Write { offset, .. } if offset == 12 * MIB),
            "{err:?}"
        );
    }

    #[test]
    fn a_zero_length_write_is_an_error_not_a_hang() {
        let dev = Recorder {
            zero_at: Some(8192),
            ..Default::default()
        };
        let err = wipe(&dev, 4 * 4096, 1, 4096, &|_, _| {}).unwrap_err();
        assert!(
            matches!(err, WipeError::Write { offset: 8192, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn progress_reaches_the_full_size() {
        let size = 16 * MIB;
        let max = AtomicU64::new(0);
        wipe(
            &Recorder::default(),
            size,
            8,
            MIB as usize,
            &|done, total| {
                assert_eq!(total, size);
                max.fetch_max(done, Ordering::Relaxed);
            },
        )
        .unwrap();
        assert_eq!(max.load(Ordering::Relaxed), size);
    }

    #[test]
    fn a_real_file_is_zeroed_end_to_end_with_o_direct_when_supported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.img");
        let size = 9 * MIB + 4 * 4096;
        std::fs::write(&path, vec![0xa5u8; size as usize]).unwrap();
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(&path)
        {
            Ok(f) => f,
            // tmpfs refuses O_DIRECT; fall back to a buffered descriptor
            // so the end-to-end byte check still runs.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                std::fs::OpenOptions::new().write(true).open(&path).unwrap()
            }
            Err(e) => panic!("open: {e}"),
        };
        wipe(&file, size, WORKERS, MIB as usize, &|_, _| {}).unwrap();
        file.sync_data().unwrap();
        let mut back = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut back).unwrap();
        assert_eq!(back.len() as u64, size);
        assert!(back.iter().all(|&b| b == 0), "a byte survived the wipe");
    }

    #[test]
    fn only_block_devices_directly_under_the_mapper_dir_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mapper = dir.path().join("mapper");
        std::fs::create_dir(&mapper).unwrap();
        let regular = mapper.join("upper");
        std::fs::write(&regular, b"x").unwrap();

        for bad in [
            Path::new("/dev/vda").to_path_buf(),
            Path::new("/dev/mapper").to_path_buf(),
            mapper.join("../mapper/upper"),
            mapper.join("sub/upper"),
            Path::new("mapper/upper").to_path_buf(),
        ] {
            assert!(
                matches!(check_target_under(&bad, &mapper), Err(WipeError::Target(_))),
                "{} accepted",
                bad.display()
            );
        }
        // Lexically fine, but a regular file.
        let err = check_target_under(&regular, &mapper).unwrap_err();
        assert!(
            matches!(&err, WipeError::Target(m) if m.contains("not a block device")),
            "{err:?}"
        );
        // A real block device in the right place passes (`/dev/loop0`
        // exists on any Linux CI runner; skipped where it does not).
        if Path::new("/dev/loop0").exists() {
            assert_eq!(
                check_target_under(Path::new("/dev/loop0"), Path::new("/dev")),
                Ok(())
            );
        }
    }

    /// In-memory device that records what was written and can inject
    /// short writes, `EINTR`, zero-length writes and a hard failure.
    #[derive(Default)]
    struct Recorder {
        spans: Mutex<Vec<(u64, u64)>>,
        calls: AtomicUsize,
        short_every: Option<usize>,
        eintr_every: Option<usize>,
        fail_at: Option<u64>,
        zero_at: Option<u64>,
    }

    impl WriteAt for Recorder {
        fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_at == Some(offset) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            if self.zero_at == Some(offset) {
                return Ok(0);
            }
            if self.eintr_every.is_some_and(|k| n.is_multiple_of(k)) {
                return Err(std::io::Error::from_raw_os_error(libc::EINTR));
            }
            assert!(buf.iter().all(|&b| b == 0), "non-zero data written");
            let len = if self.short_every.is_some_and(|k| n.is_multiple_of(k)) && buf.len() > 4096 {
                4096
            } else {
                buf.len()
            };
            self.spans.lock().unwrap().push((offset, len as u64));
            Ok(len)
        }
    }
}
