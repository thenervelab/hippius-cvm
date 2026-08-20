//! `RemoteBrokerVaultAuth` — the KBS-side client of the
//! SNP-attestation-bound Vault broker (§8 / #102 PR B).
//!
//! Implements [`kbs_core::vault::AttestedVaultAuth`] over the broker's
//! two canonical-CBOR endpoints (`binaries/kbs-vault-broker`):
//!
//! 1. `POST /v1/broker/challenge` — send the per-VM
//!    [`BrokerScope`], get a fresh single-use 32-byte nonce.
//! 2. `POST /v1/broker/redeem` — produce a FRESH SNP self-report via
//!    [`SelfReportProvider`] whose `REPORT_DATA = nonce(32) ‖
//!    auth_pubkey(32)` ([`broker_report_data`]), send it with the
//!    scope + nonce + pubkey, get back a per-VM-scoped short-TTL
//!    Vault token ([`kbs_core::vault::VaultCapability`]).
//!
//! ## Why `ev.verified` is ignored
//!
//! [`kbs_core::vault::KbsAuthEvidence::verified`] is the vestigial
//! placeholder report from the MVP seam
//! (`attest::placeholder_verified_report()` — all zeros). The broker
//! never sees it and would not trust it if it did: the §8 trust root
//! is the FRESH self-report minted here per redeem, which the broker
//! verifies itself against the AMD chain, binding the challenge
//! nonce and the KBS auth pubkey via `REPORT_DATA` and checking the
//! KBS measurement against ITS allowlist. Re-using a cached/placeholder
//! report would break freshness (anti-replay) — so this client
//! deliberately does not look at `ev.verified`.
//!
//! ## §20 secret discipline
//!
//! Errors carry a closed vocabulary only (`broker-challenge: http-401`
//! style). Response bodies are NEVER formatted into an error — the
//! redeem response contains the minted Vault token. The token goes
//! straight into `Zeroizing` via [`VaultCapability::new`].

use crate::kbs_self_report::{broker_report_data, SelfReportProvider};
use hippius_types::vault_broker::{
    BrokerScope, ChallengeRequest, ChallengeResponse, RedeemRequest, RedeemResponse,
    AUTH_PUBKEY_LEN,
};
use kbs_core::error::{KbsError, Result};
use kbs_core::vault::{
    AttestedVaultAuth, KbsAuthEvidence, VaultCapability, VaultChallenge, VaultScope,
};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Hard cap on a broker response body. The largest legitimate response
/// (a `RedeemResponse`) is well under
/// `hippius_types::vault_broker::MAX_BODY_LEN` (16 KiB); 64 KiB keeps
/// a generous margin while bounding a hostile/looping peer.
const MAX_RESPONSE_LEN: usize = 64 * 1024;

/// KBS-side broker client. Cheap to construct (no network I/O until a
/// release runs); blocking HTTP, matching the synchronous
/// `AttestedVaultAuth` seam (same posture as
/// [`crate::vault_mvp::StaticTokenVaultKv`]).
pub struct RemoteBrokerVaultAuth {
    agent: ureq::Agent,
    /// Base URL, trailing `/` trimmed (e.g.
    /// `http://kbs-vault-broker.kbs.svc:8100`).
    broker_url: String,
    self_report: Arc<dyn SelfReportProvider>,
}

impl RemoteBrokerVaultAuth {
    pub fn new(broker_url: &str, self_report: Arc<dyn SelfReportProvider>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .build();
        Self {
            agent,
            broker_url: broker_url.trim_end_matches('/').to_string(),
            self_report,
        }
    }

    /// RA-KBS-M1 — like [`new`], but pins the broker's server cert to
    /// `ca_path` (a PEM CA bundle) when set, so the broker↔KBS hop can be
    /// TLS (`broker_url = https://…`). The minted per-VM Vault token then
    /// never transits the pod network in cleartext. `ca_path = None`
    /// keeps the plain-HTTP client (backward compatible). Fallible only
    /// because reading + parsing the CA PEM can fail.
    pub fn new_tls(
        broker_url: &str,
        self_report: Arc<dyn SelfReportProvider>,
        ca_path: Option<&std::path::Path>,
    ) -> std::result::Result<Self, String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10));
        if let Some(path) = ca_path {
            let pem = std::fs::read(path)
                .map_err(|e| format!("vault.broker_ca_path {}: {e}", path.display()))?;
            let cfg = crate::vault_mvp::ca_pinned_tls_config(&pem)?;
            builder = builder.tls_config(Arc::new(cfg));
        }
        Ok(Self {
            agent: builder.build(),
            broker_url: broker_url.trim_end_matches('/').to_string(),
            self_report,
        })
    }

    /// POST canonical-CBOR `body` to `{broker_url}{path}` and return
    /// the response bytes (capped at [`MAX_RESPONSE_LEN`]). `op` is the
    /// closed-vocabulary error prefix (`broker-challenge` /
    /// `broker-redeem`); HTTP error statuses surface as
    /// `"{op}: http-{code}"` — never the response body (§20).
    fn post_cbor(&self, path: &str, body: &[u8], op: &str) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.broker_url, path);
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/cbor")
            .send_bytes(body)
            .map_err(|e| classify_ureq_error(op, &e))?;
        let mut bytes = Vec::new();
        resp.into_reader()
            .take(MAX_RESPONSE_LEN as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| KbsError::Vault(format!("{op}: response-read-failed")))?;
        if bytes.len() > MAX_RESPONSE_LEN {
            return Err(KbsError::Vault(format!("{op}: response-too-large")));
        }
        Ok(bytes)
    }
}

/// Map a `ureq` error to the closed vocabulary. The status code is
/// safe to surface; the response body and transport detail (which can
/// echo headers or token material) are deliberately dropped.
fn classify_ureq_error(op: &str, e: &ureq::Error) -> KbsError {
    match e {
        ureq::Error::Status(code, _) => KbsError::Vault(format!("{op}: http-{code}")),
        ureq::Error::Transport(_) => KbsError::Vault(format!("{op}: transport")),
    }
}

/// Field-for-field map onto the crypto-free wire type
/// (`hippius_types::vault_broker::BrokerScope` mirrors
/// `kbs_core::vault::VaultScope` by design).
fn broker_scope(s: &VaultScope) -> BrokerScope {
    BrokerScope {
        vm_id: s.vm_id.clone(),
        luks_path: s.luks_path.clone(),
        luks_version: s.luks_version,
        userdata_path: s.userdata_path.clone(),
        userdata_version: s.userdata_version,
        // §7: carry the optional lifecycle path@version through so the
        // broker grants the third read-only ACL path when present.
        lifecycle_path: s.lifecycle_path.clone(),
        lifecycle_version: s.lifecycle_version,
    }
}

impl AttestedVaultAuth for RemoteBrokerVaultAuth {
    fn issue_challenge(&self, scope: &VaultScope, _now_unix: u64) -> Result<VaultChallenge> {
        let body = ChallengeRequest {
            scope: broker_scope(scope),
        }
        .canonical()
        .map_err(KbsError::from)?;
        let resp = self.post_cbor("/v1/broker/challenge", &body, "broker-challenge")?;
        let ch = ChallengeResponse::decode(&resp).map_err(KbsError::from)?;
        Ok(VaultChallenge {
            nonce: ch.nonce,
            expiry_unix: ch.expiry_unix,
        })
    }

    fn redeem(&self, ev: &KbsAuthEvidence, _now_unix: u64) -> Result<VaultCapability> {
        // Fail-closed shape check BEFORE any network or device I/O:
        // the §8 REPORT_DATA layout requires exactly 32 pubkey bytes.
        let auth_pubkey: [u8; AUTH_PUBKEY_LEN] = ev
            .auth_pubkey
            .try_into()
            .map_err(|_| KbsError::Vault("broker-redeem: auth-pubkey-not-32-bytes".into()))?;

        // §8 binding: a FRESH self-report per redeem, REPORT_DATA =
        // challenge_nonce ‖ auth_pubkey. `ev.verified` (the MVP
        // placeholder report) is deliberately ignored — see module
        // docs; the broker verifies THIS report against the AMD chain
        // and its own KBS-measurement allowlist.
        let report_data = broker_report_data(&ev.challenge.nonce, &auth_pubkey);
        let self_report = self.self_report.report_for(&report_data)?;

        let scope = broker_scope(ev.scope);
        let body = RedeemRequest {
            scope: scope.clone(),
            challenge_nonce: ev.challenge.nonce,
            auth_pubkey,
            snp_report: self_report.report,
            // The VEK travels with the report so the broker's chain
            // matches the report's current TCB (§17 / #394). Empty when
            // the host PSP has no cached cert table — the broker then
            // uses its mounted VEK.
            vek_der: self_report.vek_der,
        }
        .canonical()
        .map_err(KbsError::from)?;
        let resp_bytes = self.post_cbor("/v1/broker/redeem", &body, "broker-redeem")?;
        let resp = RedeemResponse::decode(&resp_bytes).map_err(KbsError::from)?;
        if resp.scope != scope {
            // The token MUST authorize exactly the scope we asked for
            // (§19 exact path@version) — refuse a drifted broker.
            return Err(KbsError::Vault("broker-redeem: scope-mismatch".into()));
        }
        Ok(VaultCapability::new(
            ev.scope.clone(),
            resp.cap_expiry_unix,
            Zeroizing::new(resp.vault_token),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kbs_self_report::MockSelfReport;
    use kbs_core::snp::VerifiedReport;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::mpsc;

    const NONCE: [u8; 32] = [7u8; 32];
    const PUBKEY: [u8; 32] = [9u8; 32];

    fn vault_scope() -> VaultScope {
        VaultScope {
            vm_id: "vm-1".into(),
            luks_path: "hippius-compute/kbs/tenants/vm-1/luks-kek".into(),
            luks_version: 2,
            userdata_path: "hippius-compute/kbs/tenants/vm-1/userdata".into(),
            userdata_version: 1,
            lifecycle_path: None,
            lifecycle_version: None,
        }
    }

    fn placeholder_report() -> VerifiedReport {
        VerifiedReport {
            measurement: [0u8; 48],
            report_data: [0u8; 64],
            tcb: 0,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        }
    }

    struct Recorded {
        path: String,
        body: Vec<u8>,
    }

    /// Minimal in-process mock broker: accepts one connection per
    /// canned `(status, body)` response, parses the HTTP request
    /// (headers until `\r\n\r\n`, then `Content-Length` body bytes),
    /// records what it saw, and replies. `Connection: close` forces
    /// ureq to reconnect per request, so each canned response maps to
    /// one accept.
    fn spawn_broker(responses: Vec<(u16, Vec<u8>)>) -> (String, mpsc::Receiver<Recorded>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, resp_body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let content_length: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; content_length];
                stream.read_exact(&mut body).unwrap();
                tx.send(Recorded { path, body }).unwrap();
                let reason = match status {
                    200 => "OK",
                    403 => "Forbidden",
                    _ => "Error",
                };
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\n\
                     Content-Type: application/cbor\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    resp_body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&resp_body).unwrap();
            }
        });
        (format!("http://{addr}"), rx)
    }

    #[test]
    fn challenge_then_redeem_happy_path_binds_nonce_and_pubkey() {
        let challenge_resp = ChallengeResponse {
            nonce: NONCE,
            expiry_unix: 1_000,
        }
        .canonical()
        .unwrap();
        let redeem_resp = RedeemResponse {
            scope: broker_scope(&vault_scope()),
            cap_expiry_unix: 2_000,
            vault_token: b"hvs.tok".to_vec(),
        }
        .canonical()
        .unwrap();
        let (url, rx) = spawn_broker(vec![(200, challenge_resp), (200, redeem_resp)]);

        let mock = Arc::new(MockSelfReport::new());
        // Trailing '/' on purpose — `new` must trim it.
        let auth = RemoteBrokerVaultAuth::new(&format!("{url}/"), Arc::clone(&mock) as _);

        let scope = vault_scope();
        let challenge = auth.issue_challenge(&scope, 900).unwrap();
        assert_eq!(challenge.nonce, NONCE);
        assert_eq!(challenge.expiry_unix, 1_000);

        let verified = placeholder_report();
        let ev = KbsAuthEvidence {
            verified: &verified,
            challenge: &challenge,
            scope: &scope,
            auth_pubkey: &PUBKEY,
        };
        let cap = auth.redeem(&ev, 950).unwrap();
        assert_eq!(cap.token(), b"hvs.tok");
        assert_eq!(cap.expiry_unix, 2_000);
        assert_eq!(cap.scope, scope);

        // What the broker actually saw on the wire.
        let first = rx.recv().unwrap();
        assert_eq!(first.path, "/v1/broker/challenge");
        let creq = ChallengeRequest::decode(&first.body).unwrap();
        assert_eq!(creq.scope, broker_scope(&scope));

        let second = rx.recv().unwrap();
        assert_eq!(second.path, "/v1/broker/redeem");
        let rreq = RedeemRequest::decode(&second.body).unwrap();
        let expected_rd = broker_report_data(&NONCE, &PUBKEY);
        assert_eq!(rreq.challenge_nonce, NONCE);
        assert_eq!(rreq.auth_pubkey, PUBKEY);
        // The fresh self-report was minted for EXACTLY nonce ‖ pubkey
        // (the mock embeds the requested REPORT_DATA in its first 64
        // bytes and records the calls).
        assert_eq!(&rreq.snp_report[..64], &expected_rd);
        assert_eq!(mock.calls.lock().unwrap().as_slice(), &[expected_rd]);
    }

    #[test]
    fn broker_403_is_a_closed_vocab_error_without_token_material() {
        let (url, _rx) = spawn_broker(vec![(403, b"denied hvs.SECRET".to_vec())]);
        let auth = RemoteBrokerVaultAuth::new(&url, Arc::new(MockSelfReport::new()));

        let scope = vault_scope();
        let challenge = VaultChallenge {
            nonce: NONCE,
            expiry_unix: 1_000,
        };
        let verified = placeholder_report();
        let ev = KbsAuthEvidence {
            verified: &verified,
            challenge: &challenge,
            scope: &scope,
            auth_pubkey: &PUBKEY,
        };
        // `VaultCapability` has no `Debug` (the token is secret), so
        // `unwrap_err()` is unavailable — match instead.
        let err = match auth.redeem(&ev, 950) {
            Err(e) => e,
            Ok(_) => panic!("redeem must fail on a 403"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("broker-redeem: http-403"), "got: {msg}");
        // §20: the response body (which could carry secret material)
        // must never reach the error.
        assert!(!msg.contains("denied"), "body leaked: {msg}");
        assert!(!msg.contains("hvs."), "token material leaked: {msg}");
    }

    #[test]
    fn wrong_length_auth_pubkey_fails_before_any_io() {
        // A listener we never accept on: if the client attempted an
        // HTTP call, the connection would sit in the backlog and the
        // non-blocking accept below would return it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mock = Arc::new(MockSelfReport::new());
        let auth = RemoteBrokerVaultAuth::new(&url, Arc::clone(&mock) as _);

        let scope = vault_scope();
        let challenge = VaultChallenge {
            nonce: NONCE,
            expiry_unix: 1_000,
        };
        let verified = placeholder_report();
        let short_pubkey = [9u8; 31];
        let ev = KbsAuthEvidence {
            verified: &verified,
            challenge: &challenge,
            scope: &scope,
            auth_pubkey: &short_pubkey,
        };
        let err = match auth.redeem(&ev, 950) {
            Err(e) => e,
            Ok(_) => panic!("redeem must fail on a 31-byte pubkey"),
        };
        assert!(
            format!("{err}").contains("auth-pubkey-not-32-bytes"),
            "got: {err}"
        );
        // No self-report was minted …
        assert!(mock.calls.lock().unwrap().is_empty());
        // … and no HTTP connection was attempted.
        listener.set_nonblocking(true).unwrap();
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("unexpected connection to broker: {other:?}"),
        }
    }
}
