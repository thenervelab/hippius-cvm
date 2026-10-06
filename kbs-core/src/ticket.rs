//! Signed, immutable OrderTicket (ARCHITECTURE.md §6).
//!
//! Wire format: COSE_Sign1 (RFC 9052) over deterministic CBOR (§cbor),
//! EdDSA/Ed25519. The KBS verifies signature + expiry before anything and
//! derives Vault paths/policy from ticket fields, never the request envelope.
//! Single-use is enforced by the anti-replay store (§replay), not here.

use crate::cbor::assert_canonical;
use crate::error::{KbsError, Result};
use coset::CborSerializable;
use ed25519_dalek::{Signature, VerifyingKey};

// Canonical schema + types live in the `hippius-types` crate so L1
// (the minter) and the guest can depend on them without pulling in
// the KBS verification stack. Re-export for backwards compatibility
// with existing kbs-core call sites and tests.
pub use hippius_types::ticket::{OrderTicket, VaultRef, SCHEMA_V};

/// Resolves an L1 ticket-signing `kid` to its trusted Ed25519 public key.
/// The authoritative keyring comes ONLY from the KBS offline allowlist
/// artifact (§6/§22) — never from the request, vali, or the guest image.
pub trait L1Keyring {
    fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey>;
}

/// Verify COSE_Sign1 signature + expiry, enforce deterministic CBOR (outer
/// envelope AND protected header AND payload) and the fixed schema. Returns
/// `(ticket, kid)` so the caller can enforce `accepts_l1_kid(measurement,
/// kid)` once the attested measurement is known (§6/§22).
pub fn verify_order_ticket(
    cose_bytes: &[u8],
    keyring: &dyn L1Keyring,
    now_unix: u64,
) -> Result<(OrderTicket, Vec<u8>)> {
    verify_order_ticket_inner(cose_bytes, keyring, Some(now_unix))
}

/// [`verify_order_ticket`] WITHOUT the `issue_time`/`expiry` window —
/// every other check (canonical CBOR, EdDSA signature under an
/// allowlisted L1 kid, schema) is identical.
///
/// For the custody-lease bind ONLY (`crate::custody`). A bind re-presents
/// the ticket its boot was released under, possibly days later (daemon
/// restart, KBS restart), and tickets expire after 24 h. What the bind
/// takes from the ticket is identity — the measurement set, the placement,
/// the Vault paths — while what AUTHORISES it is the live lifecycle state
/// (`Active{gen, host, lease}` + the committed boot counter), which the
/// bind checks separately. The release path must keep using
/// [`verify_order_ticket`]: there the expiry bounds replay of a ticket
/// against a fresh boot.
pub fn verify_order_ticket_ignoring_expiry(
    cose_bytes: &[u8],
    keyring: &dyn L1Keyring,
) -> Result<(OrderTicket, Vec<u8>)> {
    verify_order_ticket_inner(cose_bytes, keyring, None)
}

fn verify_order_ticket_inner(
    cose_bytes: &[u8],
    keyring: &dyn L1Keyring,
    now_unix: Option<u64>,
) -> Result<(OrderTicket, Vec<u8>)> {
    // §22/§20: the wire bytes themselves must be deterministic — a
    // non-canonical outer wrapper would survive a payload-only check.
    assert_canonical(cose_bytes)?;

    let sign1 = coset::CoseSign1::from_slice(cose_bytes)
        .map_err(|e| KbsError::Ticket(format!("COSE_Sign1 parse: {e:?}")))?;

    // §20: the COSE protected header bstr MUST itself be deterministically
    // encoded (alg/kid are signed-context; a non-canonical header is an
    // ambiguity surface).
    match sign1.protected.original_data.as_ref() {
        Some(hdr) if !hdr.is_empty() => assert_canonical(hdr)?,
        _ => {
            return Err(KbsError::Ticket(
                "missing/empty COSE protected header".into(),
            ))
        }
    }

    match sign1.protected.header.alg.clone() {
        Some(coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)) => {}
        other => {
            return Err(KbsError::Ticket(format!(
                "alg must be EdDSA, got {other:?}"
            )))
        }
    }

    let kid = sign1.protected.header.key_id.clone();
    if kid.is_empty() {
        return Err(KbsError::Ticket("missing kid".into()));
    }
    let vk = keyring
        .verifying_key(&kid)
        .ok_or_else(|| KbsError::Ticket("kid not in allowlisted L1 keyring".into()))?;

    sign1
        .verify_signature(b"", |sig, tbs| {
            let sig = Signature::from_slice(sig)
                .map_err(|e| KbsError::Crypto(format!("sig decode: {e}")))?;
            vk.verify_strict(tbs, &sig)
                .map_err(|e| KbsError::Crypto(format!("ed25519 verify: {e}")))
        })
        .map_err(|e| KbsError::Ticket(format!("signature invalid: {e}")))?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| KbsError::Ticket("detached payload not allowed".into()))?;

    assert_canonical(payload)?;

    let ticket: OrderTicket = ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| KbsError::Ticket(format!("ticket decode: {e}")))?;

    if let Some(now_unix) = now_unix {
        if now_unix >= ticket.expiry {
            return Err(KbsError::Ticket("expired".into()));
        }
        if now_unix < ticket.issue_time {
            return Err(KbsError::Ticket(
                "not yet valid (issue_time in future)".into(),
            ));
        }
    }
    for m in &ticket.allowed_measurements {
        let bytes: &[u8] = m.as_ref();
        if bytes.len() != 48 {
            return Err(KbsError::Ticket(
                "allowed_measurement must be 48 bytes".into(),
            ));
        }
    }
    let dg: &[u8] = ticket.allowed_userdata_digest.as_ref();
    if dg.len() != 32 {
        return Err(KbsError::Ticket(
            "allowed_userdata_digest must be 32 bytes".into(),
        ));
    }
    // Schema invariants (§6).
    if ticket.v != SCHEMA_V {
        return Err(KbsError::Ticket(format!(
            "unsupported schema v={} (want {SCHEMA_V})",
            ticket.v
        )));
    }
    // Customer-held keys: a present `key_mode` other than split/customer
    // (explicit `hippius`, CBOR `null`) already failed the decode above —
    // see `OrderTicket::key_mode`. M0 has exactly one encoding.
    if ticket.nonce().len() != 32 {
        return Err(KbsError::Ticket("nonce must be 32 bytes".into()));
    }
    if ticket.allowed_measurements.is_empty() {
        return Err(KbsError::Ticket("allowed_measurements is empty".into()));
    }
    if ticket.luks_vault_ref.path == ticket.userdata_vault_ref.path {
        return Err(KbsError::Ticket(
            "luks and user-data Vault refs must be distinct paths".into(),
        ));
    }
    if ticket.luks_vault_ref.version == 0 || ticket.userdata_vault_ref.version == 0 {
        return Err(KbsError::Ticket(
            "Vault ref version must be a concrete (>0) KV v2 version".into(),
        ));
    }
    Ok((ticket, kid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::to_canonical_vec;
    use ciborium::value::Value;
    use coset::CborSerializable;
    use ed25519_dalek::{Signer, SigningKey};

    struct OneKey {
        kid: Vec<u8>,
        vk: VerifyingKey,
    }
    impl L1Keyring for OneKey {
        fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
            (kid == self.kid).then_some(self.vk)
        }
    }

    fn ticket_payload() -> Vec<u8> {
        let v = Value::Map(vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(vec![7u8; 48])]),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(vec![9u8; 32]),
            ),
            (Value::Text("expiry".into()), Value::Integer(2000.into())),
            (
                Value::Text("issue_time".into()),
                Value::Integer(1000.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text("lease-1".into()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(vec![Value::Text("boot".into())]),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/luks".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text("node-1".into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (
                Value::Text("platform_id".into()),
                Value::Text("chip-1".into()),
            ),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t1".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u1".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (Value::Text("v".into()), Value::Integer(2.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(5.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("abc".into())),
        ]);
        to_canonical_vec(&v).unwrap()
    }

    fn signed(sk: &SigningKey, kid: &[u8], payload: Vec<u8>) -> Vec<u8> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(kid.to_vec())
            .build();
        coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap()
    }

    #[test]
    fn valid_ticket_verifies() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let ks = OneKey {
            kid: kid.clone(),
            vk: sk.verifying_key(),
        };
        let cose = signed(&sk, &kid, ticket_payload());
        let (t, kid_out) = verify_order_ticket(&cose, &ks, 1500).unwrap();
        assert_eq!(kid_out, b"l1-kid");
        assert_eq!(t.vm_id, "abc");
        assert_eq!(t.vm_generation, 5);
        assert_eq!(t.luks_vault_ref.version, 3);
    }

    /// `ticket_payload()` with a `key_mode` text entry added (canonical).
    fn payload_with_key_mode(mode: &str) -> Vec<u8> {
        payload_with_key_mode_value(Value::Text(mode.into()))
    }

    /// `ticket_payload()` with a `key_mode` entry of any CBOR value.
    fn payload_with_key_mode_value(value: Value) -> Vec<u8> {
        let Value::Map(mut entries) =
            ciborium::de::from_reader::<Value, _>(ticket_payload().as_slice()).unwrap()
        else {
            panic!("ticket payload is a map")
        };
        entries.push((Value::Text("key_mode".into()), value));
        to_canonical_vec(&Value::Map(entries)).unwrap()
    }

    #[test]
    fn key_mode_is_optional_signed_and_closed_vocabulary() {
        use hippius_types::guardian::KeyMode;
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let ks = OneKey {
            kid: kid.clone(),
            vk: sk.verifying_key(),
        };
        // An M0 ticket — every ticket minted today — carries no key_mode
        // and reads as `hippius`.
        let (t, _) = verify_order_ticket(&signed(&sk, &kid, ticket_payload()), &ks, 1500).unwrap();
        assert_eq!(t.key_mode, None);
        assert_eq!(t.key_mode(), KeyMode::Hippius);
        for (wire, mode) in [("split", KeyMode::Split), ("customer", KeyMode::Customer)] {
            let cose = signed(&sk, &kid, payload_with_key_mode(wire));
            let (t, _) = verify_order_ticket(&cose, &ks, 1500).unwrap();
            assert_eq!(t.key_mode, Some(mode));
            assert_eq!(t.key_mode(), mode);
        }
        // M0 has one encoding: an explicit `hippius` is refused, and so is
        // a CBOR `null` (which a plain `Option` would read as absent).
        let explicit = signed(&sk, &kid, payload_with_key_mode("hippius"));
        let err = verify_order_ticket(&explicit, &ks, 1500).unwrap_err();
        assert!(err.to_string().contains("must be omitted"), "{err}");
        let null = signed(&sk, &kid, payload_with_key_mode_value(Value::Null));
        assert!(
            verify_order_ticket(&null, &ks, 1500).is_err(),
            "null key_mode"
        );
        // Anything else is a decode failure, never a default.
        for bad in ["Customer", "", "none", "m2"] {
            let cose = signed(&sk, &kid, payload_with_key_mode(bad));
            assert!(verify_order_ticket(&cose, &ks, 1500).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn expired_is_denied() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let ks = OneKey {
            kid: kid.clone(),
            vk: sk.verifying_key(),
        };
        let cose = signed(&sk, &kid, ticket_payload());
        assert!(verify_order_ticket(&cose, &ks, 2000).is_err());
    }

    #[test]
    fn ignoring_expiry_skips_only_the_time_window() {
        // CLAIM: the custody variant accepts an expired ticket, and still
        // refuses a ticket signed by a key outside the keyring.
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let ks = OneKey {
            kid: kid.clone(),
            vk: sk.verifying_key(),
        };
        let cose = signed(&sk, &kid, ticket_payload());
        assert!(verify_order_ticket(&cose, &ks, 2000).is_err());
        let (t, got_kid) = verify_order_ticket_ignoring_expiry(&cose, &ks).unwrap();
        assert_eq!(got_kid, kid);
        assert_eq!(t.expiry, 2000);

        let rogue = SigningKey::from_bytes(&[43u8; 32]);
        let forged = signed(&rogue, &kid, ticket_payload());
        assert!(verify_order_ticket_ignoring_expiry(&forged, &ks).is_err());
    }

    #[test]
    fn unknown_kid_is_denied() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let cose = signed(&sk, b"other-kid", ticket_payload());
        let ks = OneKey {
            kid: b"l1-kid".to_vec(),
            vk: sk.verifying_key(),
        };
        assert!(verify_order_ticket(&cose, &ks, 1500).is_err());
    }

    #[test]
    fn tampered_signature_is_denied() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let wrong = SigningKey::from_bytes(&[7u8; 32]);
        let ks = OneKey {
            kid: kid.clone(),
            vk: wrong.verifying_key(),
        };
        let cose = signed(&sk, &kid, ticket_payload());
        assert!(verify_order_ticket(&cose, &ks, 1500).is_err());
    }

    #[test]
    fn noncanonical_payload_is_denied() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-kid".to_vec();
        let ks = OneKey {
            kid: kid.clone(),
            vk: sk.verifying_key(),
        };
        // insertion-ordered (unsorted) map → non-canonical
        let v = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("ticket_id".into()), Value::Text("tk".into())),
        ]);
        let mut p = Vec::new();
        ciborium::ser::into_writer(&v, &mut p).unwrap();
        let cose = signed(&sk, &kid, p);
        assert!(verify_order_ticket(&cose, &ks, 1500).is_err());
    }
}
