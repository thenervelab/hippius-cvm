//! The I/O engine: N threads issuing blocking `pread`/`pwrite` (queue
//! depth = N) on one file or block device, `O_DIRECT`, for a duration or a
//! byte count, timing every I/O.
//!
//! Random offsets come from a keyed SHA-256 stream per worker, seeded from
//! vali's nonce, the phase and the worker index: the miner cannot predict
//! which blocks a probe touches, so it cannot cache them ahead.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::hist::Histogram;

thread_local! {
    /// The calling thread's cancel flag ([`set_cancel`]).
    static CANCEL: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

/// Phases run from this thread stop at their next I/O boundary once
/// `flag` is set (a target past its budget).
pub fn set_cancel(flag: Arc<AtomicBool>) {
    CANCEL.with(|c| *c.borrow_mut() = Some(flag));
}

fn current_cancel() -> Arc<AtomicBool> {
    CANCEL.with(|c| c.borrow().clone()).unwrap_or_default()
}

/// `O_DIRECT` wants block-aligned buffers, offsets and lengths.
pub const ALIGN: usize = 4096;

/// What one phase does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Each I/O at the next block of a shared cursor (wraps in the span).
    Sequential,
    /// Each I/O at a random block of the span.
    Random,
}

/// One phase of a profile.
#[derive(Debug, Clone, Copy)]
pub struct Phase {
    /// Seeds the offsets (with the nonce): distinct per phase.
    pub name: &'static str,
    pub pattern: Pattern,
    pub write: bool,
    pub block: usize,
    pub queue_depth: usize,
    /// The span used: `[start, start + len)`, bytes, block-aligned.
    pub start: u64,
    pub len: u64,
    /// Not measured: the first part of the run.
    pub ramp: Duration,
    /// Measured time after the ramp; `None` with `until_bytes`.
    pub duration: Option<Duration>,
    /// Stop once this many bytes are done (sequential precondition),
    /// within `duration` when both are set.
    pub until_bytes: Option<u64>,
}

/// What a phase measured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub ios: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub latency: Histogram,
    /// I/O errors (EIO and friends) — a phase stops at the first.
    pub errors: u64,
}

impl Outcome {
    /// MB/s (10^6 bytes per second), rounded down.
    pub fn mbps(&self) -> u64 {
        let micros = self.elapsed.as_micros().max(1);
        u64::try_from(u128::from(self.bytes) / micros).unwrap_or(u64::MAX)
    }

    /// I/Os per second, rounded down.
    pub fn iops(&self) -> u64 {
        let micros = self.elapsed.as_micros().max(1);
        u64::try_from(u128::from(self.ios) * 1_000_000 / micros).unwrap_or(u64::MAX)
    }
}

/// A block-aligned buffer (an over-allocation, used from its aligned
/// offset: no `unsafe`).
pub struct AlignedBuf {
    backing: Vec<u8>,
    offset: usize,
    len: usize,
}

impl AlignedBuf {
    pub fn new(len: usize, fill: u8) -> Self {
        let backing = vec![fill; len + ALIGN];
        let offset = backing.as_ptr().align_offset(ALIGN).min(ALIGN);
        Self {
            backing,
            offset,
            len,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.backing[self.offset..self.offset + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.backing[self.offset..self.offset + self.len]
    }
}

/// A pseudo-random stream: SHA-256 in counter mode over a key. With the
/// key secret (vali's nonce) its output cannot be predicted. Built on the
/// SHA-256 already in the measured guests' dependency set: a new crate
/// (a ChaCha one pulled `ppv-lite86` features) changes every measured
/// binary through workspace feature unification.
pub struct OffsetRng {
    key: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl OffsetRng {
    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(self.counter.to_le_bytes());
        self.block = h.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.used + 8 > self.block.len() {
            self.refill();
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.block[self.used..self.used + 8]);
        self.used += 8;
        u64::from_le_bytes(b)
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// The offset stream of worker `worker` in `phase`.
pub fn offset_rng(nonce: &[u8; 32], phase: &str, worker: usize) -> OffsetRng {
    let mut h = Sha256::new();
    h.update(b"hippius-disk-probe-offsets-v1");
    h.update(nonce);
    h.update(phase.as_bytes());
    h.update((worker as u64).to_le_bytes());
    let mut rng = OffsetRng {
        key: h.finalize().into(),
        counter: 0,
        block: [0; 32],
        used: 32,
    };
    rng.refill();
    rng
}

/// Run `phase` on `file`. Data written is random (incompressible, never
/// zero: a thin layer cannot elide it).
pub fn run(file: &File, phase: &Phase, nonce: &[u8; 32]) -> Outcome {
    let blocks = phase.len / phase.block as u64;
    if blocks == 0 || phase.queue_depth == 0 {
        return Outcome::default();
    }
    let cursor = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let cancel = current_cancel();
    let started = Instant::now();
    let measure_from = started + phase.ramp;
    let deadline = phase.duration.map(|d| measure_from + d);

    let workers: Vec<Outcome> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..phase.queue_depth)
            .map(|worker| {
                let cursor = Arc::clone(&cursor);
                let stop = Arc::clone(&stop);
                let cancel = Arc::clone(&cancel);
                scope.spawn(move || {
                    let mut rng = offset_rng(nonce, phase.name, worker);
                    let mut buf = AlignedBuf::new(phase.block, 0);
                    if phase.write {
                        rng.fill_bytes(buf.as_mut_slice());
                    }
                    let (mut ios, mut bytes, mut errors) = (0u64, 0u64, 0u64);
                    let mut latency = Histogram::default();
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        // Aborted (its target is past its budget): an
                        // error, so the target ends here.
                        if cancel.load(Ordering::Relaxed) {
                            errors += 1;
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        let now = Instant::now();
                        if deadline.is_some_and(|d| now >= d) {
                            break;
                        }
                        let block = match phase.pattern {
                            Pattern::Sequential => {
                                let n = cursor.fetch_add(1, Ordering::Relaxed);
                                if phase.until_bytes.is_some_and(|limit| {
                                    n.saturating_mul(phase.block as u64) >= limit
                                }) {
                                    break;
                                }
                                n % blocks
                            }
                            Pattern::Random => rng.next_u64() % blocks,
                        };
                        let offset = phase.start + block * phase.block as u64;
                        let t0 = Instant::now();
                        let r = if phase.write {
                            file.write_all_at(buf.as_slice(), offset)
                        } else {
                            file.read_exact_at(buf.as_mut_slice(), offset)
                        };
                        let took = t0.elapsed();
                        if r.is_err() {
                            errors += 1;
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        if t0 >= measure_from {
                            ios += 1;
                            bytes += phase.block as u64;
                            latency.record(u64::try_from(took.as_micros()).unwrap_or(u64::MAX));
                        }
                    }
                    Outcome {
                        ios,
                        bytes,
                        elapsed: Duration::ZERO,
                        latency,
                        errors,
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or(Outcome {
                    errors: 1,
                    ..Outcome::default()
                })
            })
            .collect()
    });
    let end = Instant::now();
    let mut out = Outcome {
        elapsed: end.saturating_duration_since(measure_from),
        ..Outcome::default()
    };
    for w in workers {
        out.ios += w.ios;
        out.bytes += w.bytes;
        out.errors += w.errors;
        out.latency.merge(&w.latency);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn file(len: u64) -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("p"))
            .unwrap();
        f.set_len(len).unwrap();
        (dir, f)
    }

    fn phase(pattern: Pattern, write: bool) -> Phase {
        Phase {
            name: "t",
            pattern,
            write,
            block: 4096,
            queue_depth: 4,
            start: 0,
            len: 1 << 20,
            ramp: Duration::ZERO,
            duration: Some(Duration::from_millis(50)),
            until_bytes: None,
        }
    }

    #[test]
    fn the_offset_streams_are_the_nonces_and_distinct_per_worker_and_phase() {
        let n = [7u8; 32];
        let a = offset_rng(&n, "rr", 0).next_u64();
        assert_eq!(a, offset_rng(&n, "rr", 0).next_u64());
        assert_ne!(a, offset_rng(&n, "rr", 1).next_u64());
        assert_ne!(a, offset_rng(&n, "rw", 0).next_u64());
        assert_ne!(a, offset_rng(&[8u8; 32], "rr", 0).next_u64());
    }

    #[test]
    fn a_sequential_precondition_writes_exactly_its_bytes() {
        let (_d, f) = file(1 << 20);
        let p = Phase {
            duration: None,
            until_bytes: Some(1 << 20),
            ..phase(Pattern::Sequential, true)
        };
        let out = run(&f, &p, &[1; 32]);
        assert_eq!(out.bytes, 1 << 20);
        assert_eq!(out.ios, 256);
        assert_eq!(out.errors, 0);
        // Random, incompressible data: never a zero block.
        let mut b = vec![0u8; 4096];
        f.read_exact_at(&mut b, 4096 * 7).unwrap();
        assert!(b.iter().any(|x| *x != 0));
    }

    #[test]
    fn a_timed_random_read_counts_its_ios_and_latencies() {
        let (_d, f) = file(1 << 20);
        let out = run(&f, &phase(Pattern::Random, false), &[1; 32]);
        assert!(out.ios > 0);
        assert_eq!(out.latency.count(), out.ios);
        assert!(out.elapsed >= Duration::from_millis(50));
        assert!(out.iops() > 0);
    }

    #[test]
    fn an_abort_stops_a_running_phase() {
        let (_d, f) = file(1 << 20);
        let p = Phase {
            duration: Some(Duration::from_secs(30)),
            ..phase(Pattern::Random, false)
        };
        let started = Instant::now();
        let flag = Arc::new(AtomicBool::new(false));
        let out = std::thread::scope(|s| {
            let h = s.spawn(|| {
                set_cancel(Arc::clone(&flag));
                run(&f, &p, &[1; 32])
            });
            std::thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::Relaxed);
            h.join().unwrap()
        });
        assert!(out.errors > 0);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn an_io_error_stops_the_phase_and_is_counted() {
        // Reads past the end of a short file fail (`read_exact_at`).
        let (_d, f) = file(4096);
        let p = Phase {
            len: 1 << 20,
            ..phase(Pattern::Random, false)
        };
        let out = run(&f, &p, &[1; 32]);
        assert!(out.errors > 0);
    }
}
