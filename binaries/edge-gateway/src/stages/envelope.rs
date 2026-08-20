//! Opaque relay envelopes — typestate-locked.
//!
//! Edge is structurally NOT a typed-payload consumer (§5.6: KBS↔guest
//! responses are HPKE-wrapped to the guest ephemeral key — Edge sees
//! ciphertext only). To make the §10 wire-gate invariant
//! "schema-validate BEFORE forward" *structural* — not just
//! documentation — this module ships TWO types:
//!
//! - [`RawEnvelope`]: pre-validate. Constructible from wire bytes by
//!   the [`crate::stages::accept`] stage (or integration tests).
//! - [`ValidatedEnvelope`]: post-validate. The ONLY way to obtain
//!   one is via [`crate::stages::validate::validate_canonical`]:
//!   its constructor is `pub(crate)` and only called from
//!   `validate.rs`.
//!
//! [`crate::stages::forward::forward`] takes `ValidatedEnvelope` by
//! value. A future PR that tried to forward bytes without going
//! through the wire gate would have to either reach into the
//! `pub(crate)` constructor (visible review surface) or skip
//! `forward` entirely (which means there's no relay at all). The
//! diff that broke §10 would be impossible to write without first
//! deleting `pub(crate)` from this file.
//!
//! Note the **absence** of:
//!
//! - Any field that would imply a parsed inner type. Adding one
//!   would couple Edge to inner schema and re-introduce the
//!   plaintext-access path §5.6 forbids.
//! - Public `body_bytes` / `into_body`. Both are `pub(crate)` —
//!   external code (PR-H2 callers, tests in `tests/`) can construct
//!   a `RawEnvelope` and inspect non-secret metadata, but cannot
//!   reach into the bytes.
//! - `Clone` / `Default`. The compile-fail doc-tests below pin both.
//! - `Debug` over body bytes. The `Debug` impl surfaces `body_len`
//!   only.

use crate::mtls::PeerId;
use crate::pipeline::{Direction, MessageKind};

/// Pre-validate envelope. The accept stage emits one of these; only
/// [`crate::stages::validate::validate_canonical`] can turn it into
/// a [`ValidatedEnvelope`] (the type `forward` requires).
///
/// **Compile-fail doc-test** — `RawEnvelope` MUST NOT be `Clone`. A
/// `#[derive(Clone)]` on this type would defeat the bounded-queue
/// cap (PR-H3) by letting an accept-side handler keep a copy after
/// hand-off:
///
/// ```compile_fail
/// use hippius_edge_gateway::stages::envelope::RawEnvelope;
/// fn assert_clone<T: Clone>() {}
/// fn _check() { assert_clone::<RawEnvelope>(); }
/// ```
///
/// **Compile-fail doc-test** — `RawEnvelope` MUST NOT be `Default`,
/// so a zero-direction "empty" envelope can't be fabricated:
///
/// ```compile_fail
/// use hippius_edge_gateway::stages::envelope::RawEnvelope;
/// let _ = RawEnvelope::default();
/// ```
pub struct RawEnvelope {
    direction: Direction,
    /// PR-H2: caller-asserted wire shape. The validate stage checks
    /// (a) the kind's expected direction matches `direction`, and
    /// (b) the body decodes against the corresponding hippius-types
    /// (or local) schema with `deny_unknown_fields`. PR-H3+ will
    /// derive `kind` from the HTTP route / mTLS peer instead of
    /// trusting the caller.
    kind: MessageKind,
    /// PR-H4: mTLS-derived peer identity. Replaces the PR-H3 socket
    /// IP (which collapsed all CGNAT'd NetBird peers into one
    /// rate-limit bucket — see [`crate::mtls::peer_id`]). Derived
    /// from the leaf cert's SAN URI / SAN DNS / Subject CN, in that
    /// order. Stable across the §B Q11 90-day cert rotation
    /// (the SAN identity is the rotation invariant; key material
    /// is not). The rate-limit stage keys per-source token buckets
    /// on this value and the audit log emits it as the `source=`
    /// label.
    peer: PeerId,
    body: Vec<u8>,
}

impl RawEnvelope {
    /// Construct from raw wire bytes. The bytes are NOT validated
    /// here — that's the wire-gate stage's job. `kind` is the
    /// caller's assertion about what shape the body should have;
    /// `validate` rejects it if the body disagrees. PR-H4: `peer`
    /// is the [`PeerId`] the mTLS acceptor extracted from the
    /// handshake's leaf cert — never a value read from the wire
    /// body (§5.6 opacity).
    pub fn from_wire(direction: Direction, kind: MessageKind, peer: PeerId, body: Vec<u8>) -> Self {
        Self {
            direction,
            kind,
            peer,
            body,
        }
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Peer identity as derived by the mTLS acceptor at handshake
    /// time. Stable for the envelope's whole lifetime (no
    /// re-derivation path inside Edge).
    pub fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// Body length in bytes. Safe to log (non-secret cardinality);
    /// never surfaces the bytes themselves.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Borrow the body for the wire-gate check. `pub(crate)` so the
    /// only caller is `validate::validate`. External code cannot
    /// inspect the bytes structurally — this is the type-level
    /// enforcement of §5.6 opacity.
    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.body
    }
}

impl core::fmt::Debug for RawEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawEnvelope")
            .field("direction", &self.direction.as_class_str())
            .field("kind", &self.kind.as_class_str())
            .field("peer", &self.peer)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Post-validate envelope. The only constructor
/// ([`Self::from_validated`]) is `pub(crate)` and only invoked from
/// [`crate::stages::validate::validate_canonical`]. Therefore the
/// only path to producing one is **through** the wire gate — which
/// is the §10 invariant, encoded in the type system.
///
/// **Compile-fail doc-test** — same negative-trait pins as
/// `RawEnvelope`:
///
/// ```compile_fail
/// use hippius_edge_gateway::stages::envelope::ValidatedEnvelope;
/// fn assert_clone<T: Clone>() {}
/// fn _check() { assert_clone::<ValidatedEnvelope>(); }
/// ```
///
/// ```compile_fail
/// use hippius_edge_gateway::stages::envelope::ValidatedEnvelope;
/// let _ = ValidatedEnvelope::default();
/// ```
pub struct ValidatedEnvelope {
    raw: RawEnvelope,
}

impl ValidatedEnvelope {
    /// `pub(crate)` constructor. The ONLY caller is
    /// `validate::validate` — see that function's body.
    pub(crate) fn from_validated(raw: RawEnvelope) -> Self {
        Self { raw }
    }

    pub fn direction(&self) -> Direction {
        self.raw.direction()
    }

    pub fn kind(&self) -> MessageKind {
        self.raw.kind()
    }

    pub fn body_len(&self) -> usize {
        self.raw.body_len()
    }

    /// Peer identity preserved from the pre-validate envelope. The
    /// bounded queue stage uses this to attribute a `QueueFull` shed
    /// back to the originating peer.
    pub fn peer(&self) -> &PeerId {
        self.raw.peer()
    }

    /// Consume and surface the body bytes. `pub(crate)` so the only
    /// caller is `forward::forward`. External code cannot pull the
    /// validated bytes out of the relay path.
    pub(crate) fn into_body(self) -> Vec<u8> {
        self.raw.body
    }

    /// Borrow the validated body bytes for the **opaque byte relay**
    /// (PR-H8 [`crate::forward`]). `pub(crate)` — same containment as
    /// [`Self::into_body`]: only the in-crate forward path may read
    /// the bytes, and only to ship them onward verbatim. The forward
    /// client takes `&ValidatedEnvelope` (it does not own the
    /// envelope — the router still needs it for the post-forward
    /// telemetry record), so a borrowing accessor is required.
    pub(crate) fn body_bytes(&self) -> &[u8] {
        self.raw.body_bytes()
    }
}

impl core::fmt::Debug for ValidatedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedEnvelope")
            .field("direction", &self.raw.direction.as_class_str())
            .field("kind", &self.raw.kind.as_class_str())
            .field("peer", &self.raw.peer)
            .field("body_len", &self.raw.body.len())
            .finish()
    }
}
