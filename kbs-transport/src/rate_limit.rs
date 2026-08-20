//! Per-process token-bucket rate limiter for nonce issuance.
//!
//! The KBS-nonce store is durable on disk; an unauthenticated peer that
//! can reach the transport could otherwise drip-fill it indefinitely
//! (§13/§17 DoS surface). This module installs a single global bucket
//! shared by all `POST /v1/kbs/nonce` calls.
//!
//! This is ONE LAYER OF DEFENSE — the Edge gateway is the natural place
//! for per-source rate limiting; an in-process bucket cannot
//! discriminate between callers. The bucket here exists so a single KBS
//! instance cannot be DoS'd to the point of disk exhaustion before the
//! Edge layer mitigates.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Token-bucket parameters.
#[derive(Debug, Clone, Copy)]
pub struct RateConfig {
    /// Refill rate, tokens per second.
    pub refill_per_sec: f64,
    /// Maximum bucket capacity (burst). Cannot exceed this.
    pub burst: u32,
}

impl Default for RateConfig {
    /// 100 nonces/sec sustained, 200-burst. Generous for normal KBS
    /// traffic (one nonce per release, releases bounded by Vault round
    /// trips) but enough headroom to refuse a runaway loop quickly.
    fn default() -> Self {
        Self {
            refill_per_sec: 100.0,
            burst: 200,
        }
    }
}

/// Simple token-bucket. Thread-safe via a short critical section under a
/// `Mutex`; on lock poison we fail closed (deny).
pub struct NonceRateLimiter {
    cfg: RateConfig,
    state: Mutex<Bucket>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl NonceRateLimiter {
    pub fn new(cfg: RateConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(Bucket {
                tokens: f64::from(cfg.burst),
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to consume one token. Returns `true` on success, `false` if
    /// the bucket is empty (caller should respond 429).
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_at(Instant::now())
    }

    fn try_acquire_at(&self, now: Instant) -> bool {
        let Ok(mut b) = self.state.lock() else {
            return false; // poisoned ⇒ deny
        };
        let elapsed = now.saturating_duration_since(b.last_refill);
        if elapsed > Duration::ZERO {
            let refill = elapsed.as_secs_f64() * self.cfg.refill_per_sec;
            b.tokens = (b.tokens + refill).min(f64::from(self.cfg.burst));
            b.last_refill = now;
        }
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_starts_full() {
        let rl = NonceRateLimiter::new(RateConfig {
            refill_per_sec: 1.0,
            burst: 3,
        });
        for _ in 0..3 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire()); // empty
    }

    #[test]
    fn bucket_refills_at_rate() {
        let rl = NonceRateLimiter::new(RateConfig {
            refill_per_sec: 10.0,
            burst: 1,
        });
        let t0 = Instant::now();
        assert!(rl.try_acquire_at(t0));
        // Same instant: empty.
        assert!(!rl.try_acquire_at(t0));
        // 100 ms later: refill_per_sec * 0.1 = 1 token.
        assert!(rl.try_acquire_at(t0 + Duration::from_millis(100)));
    }

    #[test]
    fn bucket_capped_at_burst() {
        let rl = NonceRateLimiter::new(RateConfig {
            refill_per_sec: 1000.0,
            burst: 5,
        });
        // Long elapsed time would otherwise overflow the bucket; cap at burst.
        let t0 = Instant::now();
        // Drain.
        for _ in 0..5 {
            assert!(rl.try_acquire_at(t0));
        }
        assert!(!rl.try_acquire_at(t0));
        // Wait 10 seconds — refill should be 10000 tokens but cap at 5.
        let t1 = t0 + Duration::from_secs(10);
        for _ in 0..5 {
            assert!(rl.try_acquire_at(t1));
        }
        assert!(!rl.try_acquire_at(t1));
    }
}
