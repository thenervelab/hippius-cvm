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

    if now_unix >= ticket.expiry {
        return Err(KbsError::Ticket("expired".into()));
    }
    if now_unix < ticket.issue_time {
        return Err(KbsError::Ticket(
            "not yet valid (issue_time in future)".into(),
        ));
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
