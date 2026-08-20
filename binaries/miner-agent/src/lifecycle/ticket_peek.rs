//! #312 — early-fail gate for `flavor` vs `LaunchOrder.cpu_count`.
//!
//! ## Scope
//!
//! This module **PEEKS** at the COSE_Sign1 OrderTicket payload — it
//! does NOT verify the L1 Ed25519 signature. Signature verification
//! lives in two other places already:
//!
//! - `kbs-core::ticket::verify_order_ticket` (KBS release-time gate).
//! - `agent-initramfs::stages::ticket::verify` (guest-side at boot).
//!
//! The miner-agent stays the opaque relay for everything except this
//! ONE field (`flavor`). The rationale: a launch where
//! `ticket.flavor.vcpus() != LaunchOrder.cpu_count` will eventually
//! fail at KBS release because the SNP launch_digest is computed from
//! `cpu_count`, and the §22 allowlist's pinned digest for that flavor
//! used the catalogue's `vcpus()`. So the chain catches it — but the
//! guest has to boot, run the keyscript, hit KBS, and only then get
//! denied. Doing the check at miner-agent launch admission time saves
//! that whole round-trip and surfaces the operator-side bug at order
//! dispatch (HTTP 400) instead of at boot (vmconsole stderr).
//!
//! ## Signature trust model
//!
//! The miner-agent has no L1 verifying-key material mounted. It
//! cannot tell a forged ticket from a real one. That's fine for the
//! same reason: a forged ticket can mint any `flavor`, but at KBS
//! release the §22 allowlist requires the L1 kid to be pinned for the
//! attested measurement — a forged-by-unknown-key ticket gets
//! rejected by KBS. So the `flavor` we read here is at most "what an
//! attacker who got the ticket bytes through chose to claim", and
//! the worst case is they crash their own launch early.

use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1};
use hippius_types::flavor::Flavor;

use crate::error::{MinerAgentError, Result};

/// Decode the COSE_Sign1 envelope, extract its CBOR payload, walk the
/// top-level map for the `"flavor"` text key, parse the canonical
/// kebab-case string into a `Flavor`.
///
/// Returns:
/// - `Ok(Flavor)` when the payload is a CBOR map and `"flavor"`
///   resolves to a recognised variant.
/// - `Err(MinerAgentError::LaunchInput(...))` with a stable static
///   classifier for every failure mode — never echoes ticket bytes
///   or the L1 kid (§20 logging discipline).
///
/// Static classifiers emitted (kept stable so vali's order-dispatch
/// layer can map them to operator-facing error codes):
///
/// - `ticket-peek/cose-decode`     — outer CoseSign1 frame malformed.
/// - `ticket-peek/missing-payload` — `CoseSign1.payload` is `None`.
/// - `ticket-peek/cbor-decode`     — payload not parseable as CBOR.
/// - `ticket-peek/not-a-map`       — payload root is not a CBOR map.
/// - `ticket-peek/missing-flavor`  — no `"flavor"` text key.
/// - `ticket-peek/flavor-not-text` — `"flavor"` value is not a CBOR
///   text string.
/// - `ticket-peek/unknown-flavor`  — text string is not a known
///   catalogue variant.
pub fn read_flavor(cose_bytes: &[u8]) -> Result<Flavor> {
    let sign1 = CoseSign1::from_slice(cose_bytes)
        .map_err(|_| MinerAgentError::LaunchInput("ticket-peek/cose-decode"))?;
    let payload = sign1
        .payload
        .ok_or(MinerAgentError::LaunchInput("ticket-peek/missing-payload"))?;
    let value: Value = ciborium::de::from_reader(payload.as_slice())
        .map_err(|_| MinerAgentError::LaunchInput("ticket-peek/cbor-decode"))?;
    let Value::Map(entries) = value else {
        return Err(MinerAgentError::LaunchInput("ticket-peek/not-a-map"));
    };
    for (k, v) in &entries {
        if let Value::Text(t) = k {
            if t == "flavor" {
                let Value::Text(flavor_str) = v else {
                    return Err(MinerAgentError::LaunchInput("ticket-peek/flavor-not-text"));
                };
                return flavor_str
                    .parse::<Flavor>()
                    .map_err(|_| MinerAgentError::LaunchInput("ticket-peek/unknown-flavor"));
            }
        }
    }
    Err(MinerAgentError::LaunchInput("ticket-peek/missing-flavor"))
}

/// Pair gate — read `flavor` and assert it agrees with
/// `cpu_count_in_launch_order`. The two MUST match because:
///
/// - `Flavor::vcpus()` is the catalogue-canonical vCPU count.
/// - `LaunchOrder.cpu_count` drives QEMU's `-smp N` flag.
/// - The §22 allowlist pinned launch_digest was computed against the
///   catalogue value (via vali's `_resolve_launch_size`); a mismatch
///   here means an operator override slipped past the catalogue.
///
/// Returns `Ok(Flavor)` on agreement (so the caller can log it for
/// audit). Returns `Err(MinerAgentError::LaunchInput("flavor-cpu-
/// mismatch"))` on disagreement; the classifier is stable so vali's
/// order-dispatch can surface it to the operator.
pub fn enforce_flavor_matches_cpu_count(
    cose_bytes: &[u8],
    cpu_count_in_launch_order: u8,
) -> Result<Flavor> {
    let flavor = read_flavor(cose_bytes)?;
    if flavor.vcpus() != cpu_count_in_launch_order {
        return Err(MinerAgentError::LaunchInput("flavor-cpu-mismatch"));
    }
    Ok(flavor)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use coset::{CoseSign1Builder, HeaderBuilder};

    fn cose_with_payload(payload_cbor: Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload_cbor, &mut buf).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(buf)
            // Bogus signature — `read_flavor` doesn't verify, so the
            // sig bytes are irrelevant; they just need to be valid
            // CBOR per the CoseSign1 shape.
            .create_signature(b"", |_t| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    fn ticket_map_with_flavor(flavor: &str) -> Value {
        Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("flavor".into()), Value::Text(flavor.into())),
            (
                Value::Text("ticket_id".into()),
                Value::Text("tk-fixture".into()),
            ),
        ])
    }

    #[test]
    fn happy_path_small() {
        let cose = cose_with_payload(ticket_map_with_flavor("small"));
        assert_eq!(read_flavor(&cose).unwrap(), Flavor::Small);
    }

    #[test]
    fn happy_path_medium() {
        let cose = cose_with_payload(ticket_map_with_flavor("medium"));
        assert_eq!(read_flavor(&cose).unwrap(), Flavor::Medium);
    }

    #[test]
    fn happy_path_large() {
        let cose = cose_with_payload(ticket_map_with_flavor("large"));
        assert_eq!(read_flavor(&cose).unwrap(), Flavor::Large);
    }

    #[test]
    fn unknown_flavor_classifies_loud() {
        let cose = cose_with_payload(ticket_map_with_flavor("XL"));
        let err = read_flavor(&cose).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("ticket-peek/unknown-flavor")
        ));
    }

    #[test]
    fn missing_flavor_classifies_loud() {
        let cose = cose_with_payload(Value::Map(vec![(
            Value::Text("v".into()),
            Value::Integer(2.into()),
        )]));
        let err = read_flavor(&cose).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("ticket-peek/missing-flavor")
        ));
    }

    #[test]
    fn payload_root_not_a_map_classifies_loud() {
        let cose = cose_with_payload(Value::Text("not a map".into()));
        let err = read_flavor(&cose).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("ticket-peek/not-a-map")
        ));
    }

    #[test]
    fn flavor_field_not_text_classifies_loud() {
        let cose = cose_with_payload(Value::Map(vec![(
            Value::Text("flavor".into()),
            Value::Integer(42.into()),
        )]));
        let err = read_flavor(&cose).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("ticket-peek/flavor-not-text")
        ));
    }

    #[test]
    fn cose_garbage_classifies_loud() {
        let err = read_flavor(b"\x00garbage").unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("ticket-peek/cose-decode")
        ));
    }

    #[test]
    fn enforce_matches_small_with_1_vcpu() {
        let cose = cose_with_payload(ticket_map_with_flavor("small"));
        let f = enforce_flavor_matches_cpu_count(&cose, 1).unwrap();
        assert_eq!(f, Flavor::Small);
    }

    #[test]
    fn enforce_matches_medium_with_2_vcpu() {
        let cose = cose_with_payload(ticket_map_with_flavor("medium"));
        let f = enforce_flavor_matches_cpu_count(&cose, 2).unwrap();
        assert_eq!(f, Flavor::Medium);
    }

    #[test]
    fn enforce_rejects_mismatch_small_with_4_vcpu() {
        let cose = cose_with_payload(ticket_map_with_flavor("small"));
        let err = enforce_flavor_matches_cpu_count(&cose, 4).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("flavor-cpu-mismatch")
        ));
    }

    #[test]
    fn enforce_rejects_mismatch_large_with_1_vcpu() {
        let cose = cose_with_payload(ticket_map_with_flavor("large"));
        let err = enforce_flavor_matches_cpu_count(&cose, 1).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::LaunchInput("flavor-cpu-mismatch")
        ));
    }
}
