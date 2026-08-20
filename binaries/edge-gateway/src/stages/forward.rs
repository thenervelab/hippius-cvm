//! Stage 3 — forward the envelope across the diode.
//!
//! ## Typestate guarantee
//!
//! `forward` accepts a [`ValidatedEnvelope`] BY VALUE — not a
//! [`crate::stages::envelope::RawEnvelope`]. There is no way to
//! construct a `ValidatedEnvelope` outside of
//! [`crate::stages::validate::validate`] (its constructor is
//! `pub(crate)` and only that function calls it). Therefore the
//! type signature itself proves the §10 wire-gate ran before
//! forward — no test asserting "validate happens first" is needed.
//!
//! PR-H1: returns [`EdgeError::Todo`]`(Stage::Forward)`. PR-H2 wires
//! the real destination:
//!
//! - `Direction::MinerToInner` → push onto the §9 pull-broker queue
//!   (bounded; the inner side pulls). Edge does NOT hold an inner
//!   reply address — the broker IS the address (gag-order /
//!   no-callback rule, §13/§23). PR-H3 introduces a `PullBrokerSink`
//!   typestate so even this can't drift.
//! - `Direction::InnerToMiner` → write the (already-Guardian-
//!   signed) envelope to the open mTLS connection to the
//!   addressed miner peer. Edge does NOT author the signature.

use crate::pipeline::{EdgeError, Stage};
use crate::stages::envelope::ValidatedEnvelope;

/// Forward `envelope` across the diode.
///
/// Skeleton: drops the envelope (the `Vec<u8>` body deallocates at
/// end of scope) and returns
/// [`EdgeError::Todo`]`(Stage::Forward)`.
pub async fn forward(envelope: ValidatedEnvelope) -> Result<(), EdgeError> {
    // Consume the envelope explicitly so the bytes are released
    // BEFORE the function returns. PR-H2 will push these bytes onto
    // the broker queue / socket here; until then, dropping is the
    // correct behaviour (the wire gate already accepted them, so
    // there's nothing to do).
    let _ = envelope.into_body();
    Err(EdgeError::Todo(Stage::Forward))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtls::PeerId;
    use crate::pipeline::{Direction, MessageKind};
    use crate::stages::envelope::RawEnvelope;
    use crate::stages::validate::validate;
    use ciborium::value::Value;
    use hippius_types::cbor::to_canonical_vec;

    fn peer() -> PeerId {
        PeerId::new("test-peer")
    }

    fn validated_envelope() -> ValidatedEnvelope {
        // `{body, sig}` canonical-CBOR — matches every SignedX kind.
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(vec![0u8; 8])),
            (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let raw = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            peer(),
            body,
        );
        // The only path to a `ValidatedEnvelope` — proves the
        // typestate barrier holds inside the crate too.
        validate(raw).unwrap()
    }

    #[tokio::test]
    async fn forward_is_stubbed() {
        let err = forward(validated_envelope()).await.unwrap_err();
        assert!(matches!(err, EdgeError::Todo(Stage::Forward)));
    }
}
