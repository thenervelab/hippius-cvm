//! An RFC 8555 ACME client, blocking, for the issuing node (CDN plan I4).
//!
//! Only what the fleet needs: an ES256 account key generated in RAM
//! (never written, never sent anywhere but as its public JWK), optional
//! external account binding (Google Trust Services), one order at a time
//! with DNS-01, finalize with a request from [`crate::csr`], and the
//! chain download. Every exchange is a JWS POST; nonces come from
//! `Replay-Nonce` and a `badNonce` refusal is retried once.
//!
//! The CA is reached over the web PKI with the same transport posture as
//! the backend client: https only (outside tests), TLS ≥ 1.2, no
//! redirects, bounded bodies. CA error documents are reduced to their
//! `type` for logs.

use std::io::Read;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine as _;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CdnError, Result};

const MAX_BODY: u64 = 1024 * 1024;
/// Short: the issuer runs on the feed thread, one exchange per tick.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const JOSE: &str = "application/jose+json";
const PEM_CHAIN: &str = "application/pem-certificate-chain";
const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";
pub const RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";
/// The account is gone: register a new one. (`unauthorized` is not
/// enough: CAs also use it for order and authorization refusals, and a
/// fallback account bound with a single-use binding cannot be replaced.)
pub const ACCOUNT_GONE: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// A CA's external account binding (RFC 8555 §7.3.4): the key id and the
/// base64url HMAC key the CA issued. The key is secret: it comes with the
/// KBS-released node identity, never from the image.
#[derive(Clone)]
pub struct Eab {
    pub kid: String,
    pub hmac_b64u: Zeroizing<String>,
}

impl std::fmt::Debug for Eab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Eab {{ kid: {:?}, hmac: <redacted> }}", self.kid)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// An order, as the CA returns it.
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
    pub status: String,
    #[serde(default)]
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(default)]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    pub status: String,
    #[serde(default)]
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// A CA error document's `type`, sanitised.
fn problem_type(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Problem {
        #[serde(rename = "type")]
        kind: String,
    }
    serde_json::from_slice::<Problem>(body).ok().map(|p| {
        p.kind
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
            .take(96)
            .collect()
    })
}

/// A failed exchange: the status and the problem `type`, if any.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub status: u16,
    pub problem: Option<String>,
}

/// One ACME account at one CA.
pub struct AcmeClient {
    http: Client,
    directory_url: String,
    directory: Option<Directory>,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    /// The account URL once registered.
    kid: Option<String>,
    nonce: Option<String>,
    /// The last refusal, for the caller's back-off decision.
    pub last_refusal: Option<Refusal>,
}

impl AcmeClient {
    /// A fresh account key for the CA at `directory_url`.
    pub fn new(directory_url: &str) -> Result<Self> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CdnError::Acme("account-key-generate"))?;
        let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|_| CdnError::Acme("account-key-load"))?;
        let http = Client::builder()
            .use_rustls_tls()
            .https_only(!cfg!(test))
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("hippius-cdn-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| CdnError::Acme("client-build"))?;
        Ok(Self {
            http,
            directory_url: directory_url.to_string(),
            directory: None,
            key,
            rng,
            kid: None,
            nonce: None,
            last_refusal: None,
        })
    }

    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    pub fn account_url(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The account key's JWK (public), in the RFC 7638 member order.
    fn jwk(&self) -> Value {
        let point = self.key.public_key().as_ref();
        // Uncompressed: 0x04 || X(32) || Y(32).
        json!({
            "crv": "P-256",
            "kty": "EC",
            "x": B64U.encode(&point[1..33]),
            "y": B64U.encode(&point[33..65]),
        })
    }

    /// RFC 7638 thumbprint of the account key.
    pub fn thumbprint(&self) -> String {
        let point = self.key.public_key().as_ref();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            B64U.encode(&point[1..33]),
            B64U.encode(&point[33..65])
        );
        B64U.encode(Sha256::digest(canonical.as_bytes()))
    }

    /// The DNS-01 TXT value for `token` (RFC 8555 §8.4).
    pub fn dns01_value(&self, token: &str) -> String {
        let key_authorization = format!("{token}.{}", self.thumbprint());
        B64U.encode(Sha256::digest(key_authorization.as_bytes()))
    }

    fn directory(&mut self) -> Result<Directory> {
        if let Some(d) = &self.directory {
            return Ok(d.clone());
        }
        let resp = self
            .http
            .get(&self.directory_url)
            .send()
            .map_err(|_| CdnError::Acme("directory-transport"))?;
        let (status, _, body) = read(resp)?;
        if !status.is_success() {
            return Err(CdnError::Acme("directory-status"));
        }
        let d: Directory =
            serde_json::from_slice(&body).map_err(|_| CdnError::Acme("directory-decode"))?;
        self.directory = Some(d.clone());
        Ok(d)
    }

    fn fresh_nonce(&mut self) -> Result<String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let dir = self.directory()?;
        if !self.same_origin(&dir.new_nonce) {
            return Err(CdnError::Acme("url-off-origin"));
        }
        let resp = self
            .http
            .head(&dir.new_nonce)
            .send()
            .map_err(|_| CdnError::Acme("nonce-transport"))?;
        nonce_of(resp.headers()).ok_or(CdnError::Acme("nonce-missing"))
    }

    /// Whether `url` is on the CA's own origin (scheme, host, port): the
    /// only place an order, authorization or certificate URL may point.
    fn same_origin(&self, url: &str) -> bool {
        match (
            reqwest::Url::parse(url),
            reqwest::Url::parse(&self.directory_url),
        ) {
            (Ok(a), Ok(b)) => a.origin() == b.origin(),
            _ => false,
        }
    }

    /// Sign and POST `payload` (`None`: POST-as-GET) to `url`. A `badNonce`
    /// refusal is retried once with the nonce it carried.
    fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        accept: Option<&str>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        // A failure without a CA answer (transport) leaves no refusal.
        self.last_refusal = None;
        if !self.same_origin(url) {
            return Err(CdnError::Acme("url-off-origin"));
        }
        let mut retried = false;
        loop {
            let nonce = self.fresh_nonce()?;
            let body = self.jws(url, &nonce, payload)?;
            let mut req = self.http.post(url).header(CONTENT_TYPE, JOSE).body(body);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            let resp = req.send().map_err(|_| CdnError::Acme("transport"))?;
            let (status, headers, body) = read(resp)?;
            if let Some(n) = nonce_of(&headers) {
                self.nonce = Some(n);
            }
            if status.is_success() {
                self.last_refusal = None;
                return Ok((status, headers, body));
            }
            let problem = problem_type(&body);
            if problem.as_deref() == Some(BAD_NONCE) && !retried {
                retried = true;
                continue;
            }
            eprintln!(
                "hippius-cdn-agent: acme: status {} problem {}",
                status.as_u16(),
                problem.as_deref().unwrap_or("-")
            );
            self.last_refusal = Some(Refusal {
                status: status.as_u16(),
                problem,
            });
            return Err(CdnError::Acme("refused"));
        }
    }

    /// The flattened JWS: the account URL in the header once registered,
    /// the account key's JWK before (newAccount).
    fn jws(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<Vec<u8>> {
        let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
        match &self.kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk(),
        }
        let protected_b64 = B64U.encode(protected.to_string().as_bytes());
        let payload_b64 = match payload {
            Some(p) => B64U.encode(p.to_string().as_bytes()),
            None => String::new(),
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = self
            .key
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| CdnError::Acme("jws-sign"))?;
        serde_json::to_vec(&Jws {
            protected: &protected_b64,
            payload: &payload_b64,
            signature: &B64U.encode(sig.as_ref()),
        })
        .map_err(|_| CdnError::Acme("jws-encode"))
    }

    /// Register (or find) the account. `contact` is a `mailto:` URI.
    pub fn ensure_account(&mut self, contact: Option<&str>, eab: Option<&Eab>) -> Result<()> {
        if self.kid.is_some() {
            return Ok(());
        }
        let dir = self.directory()?;
        let mut payload = json!({"termsOfServiceAgreed": true});
        if let Some(c) = contact {
            payload["contact"] = json!([c]);
        }
        if let Some(eab) = eab {
            payload["externalAccountBinding"] = self.eab_binding(eab, &dir.new_account)?;
        }
        let (_, headers, _) = self.post(&dir.new_account, Some(&payload), None)?;
        let kid = location(&headers).ok_or(CdnError::Acme("account-no-location"))?;
        self.kid = Some(kid);
        Ok(())
    }

    /// RFC 8555 §7.3.4: an HS256 JWS over the account JWK, keyed by the
    /// CA-issued MAC key.
    fn eab_binding(&self, eab: &Eab, new_account_url: &str) -> Result<Value> {
        let mac_key = Zeroizing::new(
            B64U.decode(eab.hmac_b64u.trim_end_matches('=').as_bytes())
                .map_err(|_| CdnError::Acme("eab-key-not-base64url"))?,
        );
        let protected = json!({"alg": "HS256", "kid": eab.kid, "url": new_account_url});
        let protected_b64 = B64U.encode(protected.to_string().as_bytes());
        let payload_b64 = B64U.encode(self.jwk().to_string().as_bytes());
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mac_key);
        let tag = hmac::sign(&key, format!("{protected_b64}.{payload_b64}").as_bytes());
        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": B64U.encode(tag.as_ref()),
        }))
    }

    /// A new order for `names`: its URL and body.
    pub fn new_order(&mut self, names: &[&str]) -> Result<(String, Order)> {
        let dir = self.directory()?;
        let identifiers: Vec<Value> = names
            .iter()
            .map(|n| json!({"type": "dns", "value": n}))
            .collect();
        let (_, headers, body) = self.post(
            &dir.new_order,
            Some(&json!({"identifiers": identifiers})),
            None,
        )?;
        let url = location(&headers).ok_or(CdnError::Acme("order-no-location"))?;
        let order = serde_json::from_slice(&body).map_err(|_| CdnError::Acme("order-decode"))?;
        Ok((url, order))
    }

    pub fn order(&mut self, url: &str) -> Result<Order> {
        let (_, _, body) = self.post(url, None, None)?;
        serde_json::from_slice(&body).map_err(|_| CdnError::Acme("order-decode"))
    }

    pub fn authorization(&mut self, url: &str) -> Result<Authorization> {
        let (_, _, body) = self.post(url, None, None)?;
        serde_json::from_slice(&body).map_err(|_| CdnError::Acme("authz-decode"))
    }

    /// Tell the CA the challenge is ready.
    pub fn respond(&mut self, challenge_url: &str) -> Result<()> {
        self.post(challenge_url, Some(&json!({})), None).map(|_| ())
    }

    /// Give up an authorization (RFC 8555 §7.5.2), so an abandoned order
    /// does not hold one of the account's pending authorizations.
    pub fn deactivate(&mut self, authz_url: &str) -> Result<()> {
        self.post(authz_url, Some(&json!({"status": "deactivated"})), None)
            .map(|_| ())
    }

    /// Whether the last refusal says the account itself is unusable.
    pub fn account_unusable(&self) -> bool {
        self.last_refusal
            .as_ref()
            .and_then(|r| r.problem.as_deref())
            .is_some_and(|p| p == ACCOUNT_GONE)
    }

    /// Submit the DER request.
    pub fn finalize(&mut self, finalize_url: &str, csr_der: &[u8]) -> Result<Order> {
        let (_, _, body) = self.post(
            finalize_url,
            Some(&json!({"csr": B64U.encode(csr_der)})),
            None,
        )?;
        serde_json::from_slice(&body).map_err(|_| CdnError::Acme("order-decode"))
    }

    /// Download the PEM chain.
    pub fn certificate(&mut self, url: &str) -> Result<String> {
        let (_, _, body) = self.post(url, None, Some(PEM_CHAIN))?;
        let pem = String::from_utf8(body).map_err(|_| CdnError::Acme("chain-not-utf8"))?;
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(CdnError::Acme("chain-not-pem"));
        }
        Ok(pem)
    }
}

#[derive(Serialize)]
struct Jws<'a> {
    protected: &'a str,
    payload: &'a str,
    signature: &'a str,
}

fn read(resp: reqwest::blocking::Response) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let mut body = Vec::new();
    resp.take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|_| CdnError::Acme("body-read"))?;
    if body.len() as u64 > MAX_BODY {
        return Err(CdnError::Acme("body-too-large"));
    }
    Ok((status, headers, body))
}

fn nonce_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 256
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_string)
}

fn location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 2048)
        .map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::csr::CertKey;
    use crate::fake_ca::FakeCa;

    fn issue(c: &mut AcmeClient, name: &str) -> String {
        let (url, order) = c.new_order(&[name]).unwrap();
        assert_eq!(order.status, "pending");
        let authz = c.authorization(&order.authorizations[0]).unwrap();
        let ch = authz
            .challenges
            .iter()
            .find(|ch| ch.kind == "dns-01")
            .unwrap()
            .clone();
        c.respond(&ch.url).unwrap();
        assert_eq!(c.order(&url).unwrap().status, "ready");
        let key = CertKey::generate().unwrap();
        let done = c
            .finalize(&order.finalize, &key.csr_der(&[name]).unwrap())
            .unwrap();
        assert_eq!(done.status, "valid");
        c.certificate(&done.certificate.unwrap()).unwrap()
    }

    #[test]
    fn a_full_order_against_the_fake_ca() {
        let ca = FakeCa::start();
        let mut c = AcmeClient::new(&ca.directory_url()).unwrap();
        c.ensure_account(Some("mailto:ops@example.test"), None)
            .unwrap();
        assert!(c.account_url().unwrap().contains("/acct/1"));
        // Registering again is a no-op.
        c.ensure_account(None, None).unwrap();
        let chain = issue(&mut c, "*.cdn.example.test");
        assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert_eq!(ca.state.lock().unwrap().responded, vec![1]);
    }

    #[test]
    fn dns01_value_is_the_key_authorization_digest() {
        let c = AcmeClient::new("http://127.0.0.1:1/dir").unwrap();
        let v = c.dns01_value("tok");
        assert_eq!(v.len(), 43);
        let expect = B64U.encode(Sha256::digest(format!("tok.{}", c.thumbprint()).as_bytes()));
        assert_eq!(v, expect);
        // RFC 7638 order: crv, kty, x, y.
        let jwk = c.jwk().to_string();
        let canonical: Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(canonical["kty"], "EC");
        assert_eq!(c.thumbprint().len(), 43);
    }

    #[test]
    fn a_bad_nonce_is_retried_once() {
        let ca = FakeCa::start();
        ca.state.lock().unwrap().bad_nonces = 1;
        let mut c = AcmeClient::new(&ca.directory_url()).unwrap();
        c.ensure_account(None, None).unwrap();
        ca.state.lock().unwrap().bad_nonces = 2;
        assert_eq!(
            c.new_order(&["a.example.test"]).unwrap_err().class(),
            "refused"
        );
        let r = c.last_refusal.clone().unwrap();
        assert_eq!(r.problem.as_deref(), Some(BAD_NONCE));
    }

    #[test]
    fn external_account_binding_is_mac_signed_over_the_jwk() {
        let ca = FakeCa::start();
        let mac = b"0123456789abcdef0123456789abcdef".to_vec();
        ca.state.lock().unwrap().eab = Some(("kid-1".into(), mac.clone()));
        let mut c = AcmeClient::new(&ca.directory_url()).unwrap();
        let eab = Eab {
            kid: "kid-1".into(),
            hmac_b64u: Zeroizing::new(B64U.encode(&mac)),
        };
        c.ensure_account(None, Some(&eab)).unwrap();
        assert!(format!("{eab:?}").contains("redacted"));
    }

    #[test]
    fn urls_off_the_ca_origin_are_refused() {
        let ca = FakeCa::start();
        let mut c = AcmeClient::new(&ca.directory_url()).unwrap();
        c.ensure_account(None, None).unwrap();
        let elsewhere = format!("http://127.0.0.2:{}/o/1", ca.mock.addr().port());
        assert_eq!(c.order(&elsewhere).unwrap_err().class(), "url-off-origin");
        assert_eq!(
            c.certificate("https://evil.example/cert/1")
                .unwrap_err()
                .class(),
            "url-off-origin"
        );
    }

    #[test]
    fn rate_limits_are_reported_to_the_caller() {
        let ca = FakeCa::start();
        ca.state.lock().unwrap().rate_limited = true;
        let mut c = AcmeClient::new(&ca.directory_url()).unwrap();
        c.ensure_account(None, None).unwrap();
        assert!(c.new_order(&["a.example.test"]).is_err());
        let r = c.last_refusal.clone().unwrap();
        assert_eq!(r.status, 429);
        assert_eq!(r.problem.as_deref(), Some(RATE_LIMITED));
    }
}
