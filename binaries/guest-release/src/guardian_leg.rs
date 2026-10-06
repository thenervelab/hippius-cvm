//! Customer-held keys — the **guardian leg** of an M1 (`split`) / M2
//! (`customer`) release.
//!
//! Runs BEFORE any KBS contact. Every KBS release of a golden VM counts
//! against its unconfirmed-release bound, so a guest that took the KBS
//! release and then gave up on a dead guardian would, boot after boot,
//! lock itself out. This leg therefore waits for the guardian INSIDE the
//! one boot — retrying with backoff (1 s doubling to a 60 s cap),
//! indefinitely — and only returns once it holds a verified `share_C`.
//! It never reboots and never touches the KBS while waiting.
//!
//! One attempt, over the miner-agent guardian relay
//! (`vsock://2:`[`GUARDIAN_VSOCK_PORT`], framing in
//! [`hippius_agent_initramfs::GuardianVsockClient`]):
//!
//! 1. `GUARDIAN_RECIPE_PATH` (relay-local): the [`LaunchRecipe`] the
//!    miner launched this VM with. Untrusted — the guardian recomputes
//!    the launch digest from it and compares it with the SNP report.
//! 2. `/v1/guardian/nonce`: a single-use guardian nonce.
//! 3. A fresh X25519 key, distinct from the KBS leg's.
//! 4. An SNP report with `REPORT_DATA = report_data::guardian(nonce,
//!    vm_id, guest_pub, share_c_version)`.
//! 5. `/v1/guardian/release`, then [`hippius_guest::open_guardian_reply`]:
//!    Ed25519 against the MEASURED `guardian_pk`, the shared
//!    `check_against` rules, HPKE open.
//!
//! Outcomes: a verified release ends the leg; a verified denial is shown
//! as `awaiting-guardian:refused:<reason>` and waited out — except
//! `erased`, the one terminal reason, which ends the leg with an error
//! the caller turns into a halt; anything unverified (relay errors,
//! unsigned or forged answers, a denial that does not echo this
//! request) is noise and is retried.
//!
//! §20: the status lines carry only fixed classifiers and the guardian's
//! closed-vocabulary reason — never a byte of key material.

use std::time::Duration;

use hippius_agent_initramfs::stages::{keygen, snp_report};
use hippius_agent_initramfs::{AgentError, HttpClient, SnpReportProvider};
use hippius_guest::{open_guardian_reply, GuardianRelease, GuardianReply, GuestError};
use hippius_types::guardian::{
    decode_canonical, encode_canonical, relay_answer, GuardianBinding, GuardianDenyReason,
    GuardianNonceRequest, GuardianNonceResponse, GuardianReleaseRequest, LaunchRecipe,
    GUARDIAN_NONCE_PATH, GUARDIAN_RECIPE_PATH, GUARDIAN_RELEASE_PATH, GUARDIAN_WIRE_V,
};

/// First retry delay.
pub(crate) const BACKOFF_START: Duration = Duration::from_secs(1);
/// Retry delay cap — also the steady-state status cadence.
pub(crate) const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// The leg's only terminal outcome: the guardian signed `erased`.
pub(crate) const ERASED: &str = "erased";

/// What the leg needs from the outside world besides its transports:
/// a way to wait and a place to say why it is waiting. Production
/// sleeps and prints; tests record and stop.
pub(crate) trait LegEnv {
    /// Wait `delay` before the next attempt. `false` stops the leg
    /// (tests only — production always waits and continues).
    fn pause(&mut self, delay: Duration) -> bool;
    /// One human-readable status line (no secrets).
    fn status(&mut self, line: &str);
}

/// Why one attempt did not end the leg. `Retry` is noise; `Denied` is a
/// verified, non-terminal refusal.
enum Miss {
    Retry(&'static str),
    Denied(GuardianDenyReason),
}

/// Run the guardian leg to completion: `Ok` with a verified share, or
/// `Err(AgentError::Guardian(ERASED))` on the signed terminal denial.
/// Never returns on anything else (unless `env.pause` says stop).
pub(crate) fn run(
    relay: &dyn HttpClient,
    relay_url: &str,
    snp: &dyn SnpReportProvider,
    env: &mut dyn LegEnv,
    binding: &GuardianBinding,
    vm_id: &str,
    share_c_version: Option<u32>,
) -> Result<GuardianRelease, AgentError> {
    let mut delay = BACKOFF_START;
    loop {
        match attempt(relay, relay_url, snp, binding, vm_id, share_c_version) {
            Ok(release) => {
                env.status(&format!(
                    "guardian: share released (key_mode={} share_c_version={})",
                    binding.mode.as_wire(),
                    release.share_c_version
                ));
                return Ok(release);
            }
            Err(Miss::Denied(reason)) if reason.is_terminal() => {
                env.status("awaiting-guardian:refused:erased");
                return Err(AgentError::Guardian(ERASED));
            }
            Err(Miss::Denied(reason)) => {
                env.status(&format!("awaiting-guardian:refused:{}", reason.as_wire()));
            }
            Err(Miss::Retry(why)) => env.status(&format!("awaiting-guardian:{why}")),
        }
        if !env.pause(delay) {
            return Err(AgentError::Guardian("stopped"));
        }
        delay = (delay * 2).min(BACKOFF_CAP);
    }
}

fn attempt(
    relay: &dyn HttpClient,
    relay_url: &str,
    snp: &dyn SnpReportProvider,
    binding: &GuardianBinding,
    vm_id: &str,
    share_c_version: Option<u32>,
) -> Result<GuardianRelease, Miss> {
    // 1. The recipe (relay-local; untrusted, checked by the guardian).
    let recipe_body = post(relay, relay_url, GUARDIAN_RECIPE_PATH, &[])?;
    let launch_recipe: LaunchRecipe =
        decode_canonical(&recipe_body).map_err(|_| Miss::Retry("bad-response:recipe"))?;

    // 2. A single-use guardian nonce.
    let nonce_req = encode_canonical(&GuardianNonceRequest {
        v: GUARDIAN_WIRE_V,
        vm_id: vm_id.to_string(),
    })
    .map_err(|_| Miss::Retry("request-encode"))?;
    let nonce_body = post(relay, relay_url, GUARDIAN_NONCE_PATH, &nonce_req)?;
    let nonce: GuardianNonceResponse =
        decode_canonical(&nonce_body).map_err(|_| Miss::Retry("bad-response:nonce"))?;
    nonce
        .validate()
        .map_err(|_| Miss::Retry("bad-response:nonce"))?;
    let nonce_arr: [u8; 32] = nonce
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Miss::Retry("bad-response:nonce"))?;

    // 3 + 4. A fresh key for THIS request, bound into the report.
    let keys = keygen::generate_ephemeral().map_err(|_| Miss::Retry("keygen"))?;
    let guest_pub = *keys.public_bytes();
    let rd = snp_report::guardian_report_data(&nonce_arr, vm_id, &guest_pub, share_c_version)
        .map_err(|_| Miss::Retry("report-data"))?;
    let report = snp.get_report(rd).map_err(|_| Miss::Retry("snp-report"))?;

    // 5. The release request. `validate` also refuses a recipe whose
    //    measured cmdline does not bind this mode — a relay lying about
    //    the recipe is retried here rather than sent.
    let request = GuardianReleaseRequest {
        v: GUARDIAN_WIRE_V,
        vm_id: vm_id.to_string(),
        key_mode: binding.mode,
        nonce: nonce.nonce,
        snp_report: report.0,
        guest_pub: guest_pub.to_vec(),
        vcek_chain: Vec::new(),
        launch_recipe,
        share_c_version,
    };
    request
        .validate()
        .map_err(|_| Miss::Retry("bad-response:recipe"))?;
    let body = encode_canonical(&request).map_err(|_| Miss::Retry("request-encode"))?;
    // Any status: a signed denial may ride a 4xx, and the signature —
    // not the relay-controlled status — says what the body is.
    let reply = relay
        .post_cbor(&url(relay_url, GUARDIAN_RELEASE_PATH), &body)
        .map_err(|_| Miss::Retry("unreachable"))?;
    // The X25519 secret is consumed here and wipes when this returns.
    let guest_sk = keys.into_secret();
    match open_guardian_reply(&reply.body, binding, &request, &guest_sk) {
        Ok(GuardianReply::Released(release)) => Ok(release),
        Ok(GuardianReply::Denied(reason)) => Err(Miss::Denied(reason)),
        Err(e) => Err(Miss::Retry(match relay_class(reply.status, &reply.body) {
            Some(class) => class,
            None if matches!(e, GuestError::Signature(_)) => "bad-signature",
            None => "bad-response:unverified",
        })),
    }
}

/// POST `path` and return the body of a 2xx answer; any other answer
/// is a retry, classified by the relay's own answer class when it sent
/// one.
fn post(relay: &dyn HttpClient, relay_url: &str, path: &str, body: &[u8]) -> Result<Vec<u8>, Miss> {
    let reply = relay
        .post_cbor(&url(relay_url, path), body)
        .map_err(|_| Miss::Retry("unreachable"))?;
    if !(200..300).contains(&reply.status) {
        return Err(Miss::Retry(
            relay_class(reply.status, &reply.body).unwrap_or("bad-response:status"),
        ));
    }
    Ok(reply.body)
}

fn url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// The design's status vocabulary for an answer the RELAY made itself
/// (`None` for anything else). Display hints only — the relay is
/// untrusted, and none of them is terminal.
fn relay_class(status: u16, body: &[u8]) -> Option<&'static str> {
    const CLASSES: [((u16, &str), &str); 8] = [
        (relay_answer::UNREACHABLE, "unreachable"),
        (relay_answer::TIMEOUT, "timeout"),
        (relay_answer::NO_GUARDIAN, "relay:not-configured"),
        (relay_answer::PATH_FORBIDDEN, "relay:path-forbidden"),
        (relay_answer::BAD_RESPONSE, "bad-response"),
        (relay_answer::REQUEST_TOO_LARGE, "relay:request-too-large"),
        (relay_answer::NO_RECIPE, "relay:no-recipe"),
        (relay_answer::RATE_LIMITED, "relay:rate-limited"),
    ];
    CLASSES
        .iter()
        .find(|((s, class), _)| *s == status && body == class.as_bytes())
        .map(|(_, shown)| *shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_classes_map_to_the_design_vocabulary() {
        let (s, b) = relay_answer::UNREACHABLE;
        assert_eq!(relay_class(s, b.as_bytes()), Some("unreachable"));
        let (s, b) = relay_answer::TIMEOUT;
        assert_eq!(relay_class(s, b.as_bytes()), Some("timeout"));
        let (s, b) = relay_answer::RATE_LIMITED;
        assert_eq!(relay_class(s, b.as_bytes()), Some("relay:rate-limited"));
        // A class under the wrong status, or any other body, is not a
        // relay answer.
        assert_eq!(relay_class(200, b"guardian-unreachable"), None);
        assert_eq!(relay_class(502, b"whatever"), None);
    }

    #[test]
    fn url_joins_without_a_double_slash() {
        assert_eq!(
            url("vsock://2:19271/", GUARDIAN_NONCE_PATH),
            "vsock://2:19271/v1/guardian/nonce"
        );
        assert_eq!(
            url("vsock://2:19271", GUARDIAN_NONCE_PATH),
            "vsock://2:19271/v1/guardian/nonce"
        );
    }
}
