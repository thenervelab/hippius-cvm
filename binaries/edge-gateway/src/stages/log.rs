//! Stage 4 — structured envelope log.
//!
//! §20 logging discipline applied to the relay path: NEVER write
//! envelope bytes to a log sink, NEVER call `Display` / `{:?}` on
//! the body, NEVER include decoded inner fields. The only thing
//! that ships is:
//!
//! - the [`Direction`](crate::Direction) tag (audit + routing),
//! - the source [`PeerId`] (PR-H4 — mTLS-derived peer identity,
//!   replaced PR-H3's socket IP),
//! - the body length (non-secret cardinality),
//! - a static `outcome` classifier the caller picks from a fixed
//!   vocabulary.
//!
//! Two entry points — one per envelope typestate — so a caller
//! never needs to "go back" to a raw form for logging.

use crate::mtls::PeerId;
use crate::pipeline::Direction;
use crate::stages::envelope::{RawEnvelope, ValidatedEnvelope};

fn emit(direction: Direction, peer: &PeerId, body_len: usize, outcome: &'static str) {
    // Production swap-in (PR-H6) replaces this with the audit
    // sink, but the CALL CONTRACT must remain `&'static str` only
    // — no overload that accepts arbitrary `Display`. The `peer`
    // field is formatted via `PeerId`'s `Display` impl, which only
    // writes the cert-derived identity string (no body bytes, no
    // user-controlled formatter path).
    eprintln!(
        "edge-gateway: direction={} source={} body_len={} outcome={}",
        direction.as_class_str(),
        peer,
        body_len,
        outcome,
    );
}

/// Log a pre-validate envelope. The outcome MUST be a `&'static str`
/// — passing a runtime-built `String` is rejected at compile time.
pub fn log_raw(env: &RawEnvelope, outcome: &'static str) {
    emit(env.direction(), env.peer(), env.body_len(), outcome);
}

/// Log a post-validate envelope. Same `&'static str` discipline.
pub fn log_validated(env: &ValidatedEnvelope, outcome: &'static str) {
    emit(env.direction(), env.peer(), env.body_len(), outcome);
}

/// Log a shed event keyed on `peer` alone — used by the rate-limit
/// stage when there is no envelope yet (we shed before validate)
/// and by the queue-full path when the envelope has already been
/// dropped by `try_send`'s by-value return. Same static-str rule.
pub fn log_shed(direction: Direction, peer: &PeerId, outcome: &'static str) {
    emit(direction, peer, 0, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{Direction, MessageKind};

    fn test_peer() -> PeerId {
        PeerId::new("test-peer")
    }

    #[test]
    fn log_raw_signature_is_static_str_only() {
        // Type-level proof: any `String`-accepting overload would
        // fail this cast.
        let _: fn(&RawEnvelope, &'static str) = log_raw;
    }

    #[test]
    fn log_validated_signature_is_static_str_only() {
        let _: fn(&ValidatedEnvelope, &'static str) = log_validated;
    }

    #[test]
    fn log_shed_signature_is_static_str_only() {
        let _: fn(Direction, &PeerId, &'static str) = log_shed;
    }

    #[test]
    fn log_raw_smoke() {
        let env = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::KbsRequest,
            test_peer(),
            vec![1u8, 2, 3],
        );
        log_raw(&env, "accepted");
    }
}
