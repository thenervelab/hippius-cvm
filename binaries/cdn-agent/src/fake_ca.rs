//! A minimal RFC 8555 CA for the ACME tests: directory, nonces, accounts
//! (ES256 JWS verified, EAB HMAC checked when required), one-name orders
//! with a DNS-01 challenge, finalize (the request is signed by a test
//! root with rcgen) and the chain download.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde_json::{json, Value};

use crate::test_support::{MockBackend, Reply, Request};

/// Knobs and observations.
#[derive(Default)]
pub struct CaState {
    base: String,
    next_nonce: u64,
    nonces: BTreeSet<String>,
    /// kid → JWK.
    accounts: BTreeMap<String, Value>,
    /// order id → (names, status, cert pem).
    orders: BTreeMap<u64, (Vec<String>, String, Option<String>)>,
    next_order: u64,
    /// Answer the next N JWS with badNonce.
    pub bad_nonces: u32,
    /// newOrder answers rateLimited.
    pub rate_limited: bool,
    /// Require this EAB (kid, mac key).
    pub eab: Option<(String, Vec<u8>)>,
    /// Challenge responses received (order id).
    pub responded: Vec<u64>,
    /// Answer the next N certificate downloads with 503.
    pub cert_unavailable: u32,
    /// Authorizations deactivated (order id).
    pub deactivated: Vec<u64>,
    /// Lifetime of issued certificates, days.
    pub days: i64,
}

pub struct FakeCa {
    pub mock: MockBackend,
    pub state: Arc<Mutex<CaState>>,
}

impl FakeCa {
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(CaState {
            days: 90,
            ..CaState::default()
        }));
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fake ACME root");
        let root = params.self_signed(&root_key).unwrap();
        let s2 = Arc::clone(&state);
        let ca = Arc::new((root, root_key));
        let mock = MockBackend::start(move |req| handle(&s2, &ca, req));
        state.lock().unwrap().base = format!("http://{}", mock.addr());
        Self { mock, state }
    }

    pub fn directory_url(&self) -> String {
        format!("http://{}/dir", self.mock.addr())
    }
}

fn nonce(s: &mut CaState) -> String {
    s.next_nonce += 1;
    let n = format!("n{}", s.next_nonce);
    s.nonces.insert(n.clone());
    n
}

fn problem(s: &mut CaState, status: u16, kind: &str) -> Reply {
    let n = nonce(s);
    Reply::json(status, &json!({"type": kind}).to_string()).with_header("Replay-Nonce", &n)
}

fn handle(
    state: &Mutex<CaState>,
    ca: &(rcgen::Certificate, rcgen::KeyPair),
    req: &Request,
) -> Reply {
    let mut s = state.lock().unwrap();
    let base = s.base.clone();
    match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/dir") => {
            return Reply::json(
                200,
                &json!({
                    "newNonce": format!("{base}/nonce"),
                    "newAccount": format!("{base}/acct"),
                    "newOrder": format!("{base}/order"),
                })
                .to_string(),
            )
        }
        ("HEAD", "/nonce") => {
            let n = nonce(&mut s);
            return Reply::status(200).with_header("Replay-Nonce", &n);
        }
        ("POST", _) => {}
        _ => return Reply::status(404),
    }
    assert_eq!(req.header("content-type"), Some("application/jose+json"));
    let jws: Value = serde_json::from_slice(&req.body).unwrap();
    let protected: Value =
        serde_json::from_slice(&B64U.decode(jws["protected"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(protected["alg"], "ES256");
    assert_eq!(
        protected["url"],
        format!("{base}{}", req.target),
        "url header"
    );
    let n = protected["nonce"].as_str().unwrap().to_string();
    if s.bad_nonces > 0 {
        s.bad_nonces -= 1;
        s.nonces.remove(&n);
        return problem(&mut s, 400, "urn:ietf:params:acme:error:badNonce");
    }
    assert!(
        s.nonces.remove(&n),
        "nonce {n} was not issued or was reused"
    );
    let jwk = match (protected.get("jwk"), protected.get("kid")) {
        (Some(jwk), None) => jwk.clone(),
        (None, Some(kid)) => s.accounts.get(kid.as_str().unwrap()).cloned().unwrap(),
        _ => panic!("exactly one of jwk and kid"),
    };
    let mut point = vec![0x04];
    point.extend(B64U.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(B64U.decode(jwk["y"].as_str().unwrap()).unwrap());
    let input = format!(
        "{}.{}",
        jws["protected"].as_str().unwrap(),
        jws["payload"].as_str().unwrap()
    );
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(
            input.as_bytes(),
            &B64U.decode(jws["signature"].as_str().unwrap()).unwrap(),
        )
        .expect("JWS signature");
    let payload: Option<Value> = match jws["payload"].as_str().unwrap() {
        "" => None,
        p => Some(serde_json::from_slice(&B64U.decode(p).unwrap()).unwrap()),
    };
    let fresh = nonce(&mut s);
    let target = req.target.clone();
    let reply = |status: u16, body: Value| {
        Reply::json(status, &body.to_string()).with_header("Replay-Nonce", &fresh)
    };
    if target == "/acct" {
        let payload = payload.unwrap();
        assert_eq!(payload["termsOfServiceAgreed"], true);
        if let Some((kid, mac)) = s.eab.clone() {
            let b = &payload["externalAccountBinding"];
            let p: Value =
                serde_json::from_slice(&B64U.decode(b["protected"].as_str().unwrap()).unwrap())
                    .unwrap();
            assert_eq!(p["alg"], "HS256");
            assert_eq!(p["kid"], kid);
            assert_eq!(p["url"], format!("{base}/acct"));
            let inner: Value =
                serde_json::from_slice(&B64U.decode(b["payload"].as_str().unwrap()).unwrap())
                    .unwrap();
            assert_eq!(inner, jwk, "EAB binds the account key");
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &mac);
            ring::hmac::verify(
                &key,
                format!(
                    "{}.{}",
                    b["protected"].as_str().unwrap(),
                    b["payload"].as_str().unwrap()
                )
                .as_bytes(),
                &B64U.decode(b["signature"].as_str().unwrap()).unwrap(),
            )
            .expect("EAB MAC");
        }
        let kid = format!("{base}/acct/{}", s.accounts.len() + 1);
        s.accounts.insert(kid.clone(), jwk);
        return reply(201, json!({"status": "valid"})).with_header("Location", &kid);
    }
    assert!(protected.get("kid").is_some(), "only newAccount uses jwk");
    if target == "/order" {
        if s.rate_limited {
            return problem(&mut s, 429, "urn:ietf:params:acme:error:rateLimited");
        }
        let names: Vec<String> = payload.unwrap()["identifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["value"].as_str().unwrap().to_string())
            .collect();
        s.next_order += 1;
        let id = s.next_order;
        s.orders.insert(id, (names, "pending".into(), None));
        return reply(201, order_json(&base, id, &s.orders[&id]))
            .with_header("Location", &format!("{base}/o/{id}"));
    }
    let id: u64 = target
        .rsplit('/')
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if target.starts_with("/o/") {
        return reply(200, order_json(&base, id, &s.orders[&id]));
    }
    if target.starts_with("/authz/") && payload.is_some() {
        assert_eq!(payload, Some(json!({"status": "deactivated"})));
        s.deactivated.push(id);
        return reply(200, json!({"status": "deactivated"}));
    }
    if target.starts_with("/authz/") {
        let (names, status, _) = s.orders[&id].clone();
        let st = if status == "pending" {
            "pending"
        } else {
            "valid"
        };
        return reply(
            200,
            json!({"status": st, "identifier": {"type": "dns", "value": names[0]},
                   "challenges": [
                       {"type": "http-01", "url": format!("{base}/chall-http/{id}"), "token": "th"},
                       {"type": "dns-01", "url": format!("{base}/chall/{id}"), "token": format!("tok{id}"),
                        "status": st}]}),
        );
    }
    if target.starts_with("/chall/") {
        assert_eq!(payload, Some(json!({})));
        s.responded.push(id);
        s.orders.get_mut(&id).unwrap().1 = "ready".into();
        return reply(200, json!({"type": "dns-01", "status": "processing"}));
    }
    if target.starts_with("/finalize/") {
        let der = B64U
            .decode(payload.unwrap()["csr"].as_str().unwrap())
            .unwrap();
        let mut params = rcgen::CertificateSigningRequestParams::from_der(&der.into()).unwrap();
        let now = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap();
        params.params.not_before = now - time::Duration::minutes(1);
        params.params.not_after = now + time::Duration::days(s.days);
        let leaf = params.signed_by(&ca.0, &ca.1).unwrap();
        let chain = format!("{}{}", leaf.pem(), ca.0.pem());
        let o = s.orders.get_mut(&id).unwrap();
        o.1 = "valid".into();
        o.2 = Some(chain);
        return reply(200, order_json(&base, id, &s.orders[&id]));
    }
    if target.starts_with("/cert/") && s.cert_unavailable > 0 {
        s.cert_unavailable -= 1;
        return problem(&mut s, 503, "urn:ietf:params:acme:error:serverInternal");
    }
    if target.starts_with("/cert/") {
        assert_eq!(
            req.header("accept"),
            Some("application/pem-certificate-chain")
        );
        let pem = s.orders[&id].2.clone().unwrap();
        let mut r = Reply::status(200).with_header("Replay-Nonce", &fresh);
        r = r.with_header("Content-Type", "application/pem-certificate-chain");
        return r.with_body(pem.as_bytes());
    }
    Reply::status(404)
}

fn order_json(base: &str, id: u64, o: &(Vec<String>, String, Option<String>)) -> Value {
    let mut v = json!({
        "status": o.1,
        "identifiers": o.0.iter().map(|n| json!({"type": "dns", "value": n})).collect::<Vec<_>>(),
        "authorizations": [format!("{base}/authz/{id}")],
        "finalize": format!("{base}/finalize/{id}"),
    });
    if o.2.is_some() {
        v["certificate"] = json!(format!("{base}/cert/{id}"));
    }
    v
}
