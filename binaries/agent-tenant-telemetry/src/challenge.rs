//! The validator challenge a `ServedDeliveryReceipt` commits to.
//!
//! Per ARCHITECTURE.md §23 a tenant receipt is not a free-standing
//! self-report: it binds a specific validator (`validator_id`), that
//! validator's fresh challenge nonce, and the scoring `epoch`. Those
//! three values originate OUTSIDE the guest — a validator issues them.
//!
//! PR-E2.2 ships the receipt loop against the [`ChallengeSource`]
//! capability; the production source — validator challenges pulled in
//! over the Edge channel — lands with PR-E2.3. Until then
//! [`StaticChallengeSource`] lets `main` carry a challenge injected via
//! config, or run the loop idle when none is configured.

use crate::error::Result;

/// The per-window validator challenge a receipt is bound to.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The validator this receipt commits to (opaque id bytes).
    pub validator_id: Vec<u8>,
    /// The validator's fresh 32-byte challenge nonce.
    pub validator_nonce: [u8; 32],
    /// The scoring epoch the challenge belongs to.
    pub epoch: u64,
}

/// A source of the current validator challenge.
///
/// A trait — like E2.1's `SnpReportProvider` — so the receipt loop and
/// its tests depend on the capability, not on a concrete channel.
pub trait ChallengeSource {
    /// The active validator challenge, or `None` when none is available
    /// — the receipt loop then idles for that interval rather than
    /// signing a receipt with no validator to commit to.
    fn current_challenge(&self) -> Result<Option<Challenge>>;
}

/// A [`ChallengeSource`] backed by a fixed, optional challenge.
///
/// `main` builds it from config — `Some` when a challenge is
/// provisioned, `None` otherwise; tests build it with a known
/// challenge. It is the E2.2 placeholder for PR-E2.3's live
/// Edge-pulled challenge source.
pub struct StaticChallengeSource {
    challenge: Option<Challenge>,
}

impl StaticChallengeSource {
    /// A source that always yields `challenge`.
    pub fn new(challenge: Challenge) -> Self {
        Self {
            challenge: Some(challenge),
        }
    }

    /// A source that never yields a challenge — the loop runs idle.
    pub fn idle() -> Self {
        Self { challenge: None }
    }
}

impl ChallengeSource for StaticChallengeSource {
    fn current_challenge(&self) -> Result<Option<Challenge>> {
        Ok(self.challenge.clone())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn challenge() -> Challenge {
        Challenge {
            validator_id: b"validator-1".to_vec(),
            validator_nonce: [7u8; 32],
            epoch: 9,
        }
    }

    #[test]
    fn static_source_yields_the_configured_challenge() {
        let src = StaticChallengeSource::new(challenge());
        let got = src
            .current_challenge()
            .unwrap()
            .expect("a configured source yields Some");
        assert_eq!(got.validator_id, b"validator-1");
        assert_eq!(got.validator_nonce, [7u8; 32]);
        assert_eq!(got.epoch, 9);
    }

    #[test]
    fn idle_source_yields_none() {
        let src = StaticChallengeSource::idle();
        assert!(src.current_challenge().unwrap().is_none());
    }
}
