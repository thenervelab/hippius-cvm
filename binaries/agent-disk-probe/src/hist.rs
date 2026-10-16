//! Latency histograms, in microseconds.
//!
//! [`Histogram`] is log-linear: exact below 64 µs, then 64 sub-buckets per
//! power of two (≤ 1.6 % error), so percentiles are close without keeping
//! every sample. [`Histogram::log2`] folds it into the 32 log2-µs buckets
//! the receipt carries (`hist_qd1`).

use hippius_types::disk_stats::HIST_BUCKETS;

const SUB: u64 = 64;
const SUB_BITS: u32 = 6;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Histogram {
    buckets: Vec<u64>,
    count: u64,
}

fn index(us: u64) -> usize {
    if us < SUB {
        return us as usize;
    }
    let exp = 63 - us.leading_zeros();
    let sub = (us >> (exp - SUB_BITS)) & (SUB - 1);
    (SUB + u64::from(exp - SUB_BITS) * SUB + sub) as usize
}

/// The largest value bucket `i` holds.
fn upper(i: usize) -> u64 {
    let i = i as u64;
    if i < SUB {
        return i;
    }
    let exp = (i - SUB) / SUB + u64::from(SUB_BITS);
    let sub = (i - SUB) % SUB;
    let base = (SUB + sub) << (exp - u64::from(SUB_BITS));
    base + (1 << (exp - u64::from(SUB_BITS))) - 1
}

impl Histogram {
    pub fn record(&mut self, us: u64) {
        let i = index(us);
        if self.buckets.len() <= i {
            self.buckets.resize(i + 1, 0);
        }
        self.buckets[i] += 1;
        self.count += 1;
    }

    pub fn merge(&mut self, other: &Histogram) {
        if self.buckets.len() < other.buckets.len() {
            self.buckets.resize(other.buckets.len(), 0);
        }
        for (a, b) in self.buckets.iter_mut().zip(&other.buckets) {
            *a += b;
        }
        self.count += other.count;
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// The `per_mille`-th per-mille latency (500 = p50, 990 = p99), the
    /// upper bound of its bucket; 0 when empty.
    pub fn percentile(&self, per_mille: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = (self.count * per_mille).div_ceil(1000).max(1);
        let mut seen = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return upper(i);
            }
        }
        upper(self.buckets.len().saturating_sub(1))
    }

    /// Counts per log2-µs bucket: bucket `b` holds `[2^b, 2^(b+1))` µs
    /// (bucket 0 also 0 µs), the last one everything above.
    pub fn log2(&self) -> Vec<u32> {
        let mut out = vec![0u32; HIST_BUCKETS];
        for (i, n) in self.buckets.iter().enumerate() {
            if *n == 0 {
                continue;
            }
            // Every value of a bucket shares its log2 (sub-buckets never
            // straddle a power of two).
            let low = if i == 0 { 1 } else { upper(i) };
            let b = (63 - low.max(1).leading_zeros()) as usize;
            let slot = &mut out[b.min(HIST_BUCKETS - 1)];
            *slot = slot.saturating_add(u32::try_from(*n).unwrap_or(u32::MAX));
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_value_lands_in_a_bucket_whose_bound_is_close_above_it() {
        for us in [
            0u64, 1, 63, 64, 65, 100, 1000, 4095, 4096, 123_456, 9_999_999,
        ] {
            let up = upper(index(us));
            assert!(up >= us, "{us}");
            assert!(up - us <= us / 60 + 1, "{us} -> {up}");
        }
    }

    #[test]
    fn percentiles_follow_the_samples() {
        let mut h = Histogram::default();
        for us in 1..=1000 {
            h.record(us);
        }
        let p50 = h.percentile(500);
        let p99 = h.percentile(990);
        assert!((490..=510).contains(&p50), "{p50}");
        assert!((980..=1010).contains(&p99), "{p99}");
        assert_eq!(Histogram::default().percentile(990), 0);
    }

    #[test]
    fn the_log2_fold_keeps_every_sample_in_its_power_of_two() {
        let mut h = Histogram::default();
        for us in [0, 1, 2, 3, 100, 1000, 1023, 1024, u64::MAX / 2] {
            h.record(us);
        }
        let b = h.log2();
        assert_eq!(b.len(), HIST_BUCKETS);
        assert_eq!(b[0], 2); // 0 and 1
        assert_eq!(b[1], 2); // 2, 3
        assert_eq!(b[6], 1); // 100
        assert_eq!(b[9], 2); // 1000, 1023
        assert_eq!(b[10], 1); // 1024
        assert_eq!(b[31], 1); // everything above
        assert_eq!(b.iter().map(|n| u64::from(*n)).sum::<u64>(), h.count());
    }
}
