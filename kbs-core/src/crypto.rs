//! KBS-side crypto operations (ARCHITECTURE.md §20).
//!
//! Wire types — `ReleaseContext`, `WrappedSecret`, `KbsResponse`,
//! `SignedResponse`, `SignedDenial` and the pinned suite/domain
//! constants — live in `hippius-types` so L1 and the guest depend on
//! the SAME schema. This module owns the verification/signing/wrapping
//! logic only.

use crate::cbor::to_canonical_vec;
use crate::error::{KbsError, Result};
use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemT,
    OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

pub use hippius_types::release::{
    KbsResponse, ReleaseContext, SignedDenial, SignedResponse, WrappedSecret, DENIAL_DOMAIN,
    HPKE_INFO, HPKE_SUITE_ID, RELEASE_DOMAIN,
};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

/// HPKE-wrap `plaintext` to the attested guest X25519 public key, bound
/// to `ctx` (§20). `ctx` is used as both HPKE `info` and `aad`.
pub fn hpke_wrap(
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
    ctx: &ReleaseContext,
) -> Result<WrappedSecret> {
    let info = ctx.canonical()?;
    let pk = <Kem as KemT>::PublicKey::from_bytes(recipient_pub)
        .map_err(|e| KbsError::Crypto(format!("hpke pubkey: {e}")))?;
    #[cfg(test)]
    if let Some(sealed) = test_rng::with_seeded(|rng| {
        hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &pk,
            &info,
            plaintext,
            &info,
            rng,
        )
    }) {
        let (encapped, ct) = sealed.map_err(|e| KbsError::Crypto(format!("hpke seal: {e}")))?;
        return Ok(WrappedSecret {
            secret_type: ctx.secret_type.to_string(),
            secret_path: ctx.secret_path.to_string(),
            secret_version: ctx.secret_version,
            enc: encapped.to_bytes().to_vec(),
            ct,
        });
    }
    let mut csprng = rand::rngs::OsRng;
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        plaintext,
        &info,
        &mut csprng,
    )
    .map_err(|e| KbsError::Crypto(format!("hpke seal: {e}")))?;
    Ok(WrappedSecret {
        secret_type: ctx.secret_type.to_string(),
        secret_path: ctx.secret_path.to_string(),
        secret_version: ctx.secret_version,
        enc: encapped.to_bytes().to_vec(),
        ct,
    })
}

/// Recipient-side unwrap (guest parity / tests). The caller MUST pass
/// the identical re-derived context.
pub fn hpke_unwrap(
    recipient_secret: &[u8; 32],
    w: &WrappedSecret,
    ctx: &ReleaseContext,
) -> Result<Zeroizing<Vec<u8>>> {
    let info = ctx.canonical()?;
    let sk = <Kem as KemT>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|e| KbsError::Crypto(format!("hpke privkey: {e}")))?;
    let enc = <Kem as KemT>::EncappedKey::from_bytes(&w.enc)
        .map_err(|e| KbsError::Crypto(format!("hpke enc: {e}")))?;
    let pt =
        hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, &info, &w.ct, &info)
            .map_err(|e| KbsError::Crypto(format!("hpke open: {e}")))?;
    Ok(Zeroizing::new(pt))
}

/// HPKE seal (the §20 suite) with a caller-chosen `info` and `aad`, for
/// payloads that are not a §20 release secret — the custody rekey KEK
/// (`crate::custody`), whose `info` is its own domain and whose `aad`
/// binds the exact signed verdict it travels with. Returns `(enc, ct)`.
pub fn hpke_seal_raw(
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = <Kem as KemT>::PublicKey::from_bytes(recipient_pub)
        .map_err(|e| KbsError::Crypto(format!("hpke pubkey: {e}")))?;
    let mut csprng = rand::rngs::OsRng;
    let (encapped, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        &mut csprng,
    )
    .map_err(|e| KbsError::Crypto(format!("hpke seal: {e}")))?;
    Ok((encapped.to_bytes().to_vec(), ct))
}

/// Recipient side of [`hpke_seal_raw`] (guest parity / tests).
pub fn hpke_open_raw(
    recipient_secret: &[u8; 32],
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let sk = <Kem as KemT>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|e| KbsError::Crypto(format!("hpke privkey: {e}")))?;
    let enc = <Kem as KemT>::EncappedKey::from_bytes(enc)
        .map_err(|e| KbsError::Crypto(format!("hpke enc: {e}")))?;
    let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, info, ct, aad)
        .map_err(|e| KbsError::Crypto(format!("hpke open: {e}")))?;
    Ok(Zeroizing::new(pt))
}

fn canonical_response(resp: &KbsResponse) -> Result<Vec<u8>> {
    let value =
        Value::serialized(resp).map_err(|e| KbsError::Crypto(format!("response encode: {e}")))?;
    Ok(to_canonical_vec(&value)?)
}

pub fn sign_response(signing_key: &SigningKey, resp: &KbsResponse) -> Result<SignedResponse> {
    let body = canonical_response(resp)?;
    let sig = signing_key.sign(&body);
    Ok(SignedResponse {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

pub fn verify_response(vk: &VerifyingKey, signed: &SignedResponse) -> Result<KbsResponse> {
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| KbsError::Crypto(format!("sig decode: {e}")))?;
    vk.verify_strict(&signed.body, &sig)
        .map_err(|e| KbsError::Crypto(format!("response sig invalid: {e}")))?;
    ciborium::de::from_reader(signed.body.as_slice())
        .map_err(|e| KbsError::Crypto(format!("response decode: {e}")))
}

pub fn sign_denial(
    signing_key: &SigningKey,
    ticket_id: Option<&str>,
    vm_id: Option<&str>,
    reason: &str,
) -> Result<SignedDenial> {
    let v = Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(DENIAL_DOMAIN.into()),
        ),
        (
            Value::Text("ticket_id".into()),
            Value::Text(ticket_id.unwrap_or("").into()),
        ),
        (
            Value::Text("vm_id".into()),
            Value::Text(vm_id.unwrap_or("").into()),
        ),
        (Value::Text("reason".into()), Value::Text(reason.into())),
    ]);
    let body = to_canonical_vec(&v)?;
    let sig = signing_key.sign(&body);
    Ok(SignedDenial {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

/// TEST-ONLY deterministic randomness for [`hpke_wrap`], so a whole
/// release can be pinned byte for byte (a known-answer test on the full
/// signed response). Production always draws from `OsRng`.
#[cfg(test)]
pub(crate) mod test_rng {
    use rand::SeedableRng;
    use std::cell::RefCell;

    thread_local! {
        static HPKE_RNG: RefCell<Option<rand::rngs::StdRng>> = const { RefCell::new(None) };
    }

    /// Every `hpke_wrap` on this thread draws from one `StdRng` seeded
    /// with `seed` until [`clear`].
    pub(crate) fn seed(seed: u64) {
        HPKE_RNG.with(|c| *c.borrow_mut() = Some(rand::rngs::StdRng::seed_from_u64(seed)));
    }

    pub(crate) fn clear() {
        HPKE_RNG.with(|c| *c.borrow_mut() = None);
    }

    pub(crate) fn with_seeded<T>(f: impl FnOnce(&mut rand::rngs::StdRng) -> T) -> Option<T> {
        HPKE_RNG.with(|c| c.borrow_mut().as_mut().map(f))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A FIXED X25519 keypair derived from `ikm` (known-answer tests).
    pub fn fixed_x25519(ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
        let (sk, pk) = Kem::derive_keypair(ikm);
        let pkb: [u8; 32] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("x25519 pubkey is 32 bytes");
        let skb: [u8; 32] = sk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("x25519 secret is 32 bytes");
        (pkb, skb)
    }

    pub fn gen_x25519() -> ([u8; 32], [u8; 32]) {
        let mut rng = rand::rngs::OsRng;
        let (sk, pk) = Kem::gen_keypair(&mut rng);
        let pkb: [u8; 32] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("x25519 pubkey is 32 bytes");
        let skb: [u8; 32] = sk
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("x25519 secret is 32 bytes");
        (pkb, skb)
    }

    pub fn ctx<'a>(
        kbs_nonce: &'a [u8; 32],
        measurement: &'a [u8; 48],
        kid: &'a [u8],
        secret_type: &'a str,
        allowed_userdata_digest: &'a [u8; 32],
    ) -> ReleaseContext<'a> {
        ReleaseContext {
            v: 1,
            ticket_id: "tk-1",
            tenant_id: "t1",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce,
            measurement,
            kbs_kid: kid,
            secret_type,
            secret_path: "kbs/vm/abc/luks",
            secret_version: 3,
            allowed_userdata_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_roundtrip_context_bound() {
        let (pk_b, sk_b) = test_support::gen_x25519();
        let n = [1u8; 32];
        let m = [7u8; 48];
        let d = [9u8; 32];
        let c = test_support::ctx(&n, &m, b"kid", "luks", &d);
        let w = hpke_wrap(&pk_b, b"luks-key-material", &c).unwrap();
        let pt = hpke_unwrap(&sk_b, &w, &c).unwrap();
        assert_eq!(pt.as_slice(), b"luks-key-material");
    }

    #[test]
    fn hpke_wrong_context_fails_closed() {
        let (pk_b, sk_b) = test_support::gen_x25519();
        let n = [1u8; 32];
        let m = [7u8; 48];
        let d = [9u8; 32];
        let c1 = test_support::ctx(&n, &m, b"kid", "luks", &d);
        let c2 = test_support::ctx(&n, &m, b"kid", "userdata", &d); // different secret_type
        let w = hpke_wrap(&pk_b, b"x", &c1).unwrap();
        assert!(hpke_unwrap(&sk_b, &w, &c2).is_err());
    }

    #[test]
    fn hpke_wrong_allowed_userdata_digest_fails_closed() {
        // Regression for the §20 binding: a release wrapped with one
        // `allowed_userdata_digest` MUST NOT unwrap under any other.
        let (pk_b, sk_b) = test_support::gen_x25519();
        let n = [1u8; 32];
        let m = [7u8; 48];
        let d1 = [9u8; 32];
        let d2 = [0xAAu8; 32];
        let c1 = test_support::ctx(&n, &m, b"kid", "luks", &d1);
        let c2 = test_support::ctx(&n, &m, b"kid", "luks", &d2);
        let w = hpke_wrap(&pk_b, b"x", &c1).unwrap();
        assert!(hpke_unwrap(&sk_b, &w, &c2).is_err());
    }

    #[test]
    fn signed_response_roundtrip_and_tamper() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let resp = KbsResponse {
            domain: RELEASE_DOMAIN.into(),
            v: 1,
            ticket_id: "tk".into(),
            tenant_id: "t".into(),
            vm_id: "abc".into(),
            vm_generation: 7,
            kbs_nonce: vec![1u8; 32],
            measurement: vec![7u8; 48],
            kbs_kid: b"kbs-kid".to_vec(),
            hpke_suite_id: HPKE_SUITE_ID,
            allowed_userdata_digest: vec![9u8; 32],
            luks: Some(WrappedSecret {
                secret_type: "luks".into(),
                secret_path: "p".into(),
                secret_version: 1,
                enc: vec![1],
                ct: vec![2],
            }),
            userdata: WrappedSecret {
                secret_type: "userdata".into(),
                secret_path: "q".into(),
                secret_version: 1,
                enc: vec![3],
                ct: vec![4],
            },
            lifecycle_key: None,
            boot_counter: 0,
            expected_volume_stamp: 0,
            volume_stamp_token: None,
            volume_stamp_transition: None,
            cdn_fleet: None,
        };
        let signed = sign_response(&sk, &resp).unwrap();
        assert_eq!(verify_response(&sk.verifying_key(), &signed).unwrap(), resp);
        let mut bad = signed.clone();
        bad.body[0] ^= 0xff;
        assert!(verify_response(&sk.verifying_key(), &bad).is_err());
    }

    #[test]
    fn signed_denial_verifies() {
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let d = sign_denial(&sk, Some("tk"), Some("abc"), "expired").unwrap();
        let sig = Signature::from_slice(&d.sig).unwrap();
        assert!(sk.verifying_key().verify_strict(&d.body, &sig).is_ok());
    }
}
