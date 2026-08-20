//! Host-side **guest-boot progress sink** — a display-only, fail-open
//! side-channel the miner-agent uses to tell vali when a tenant guest
//! reaches a boot milestone (booting / kek-released / running) AFTER the
//! launch order was accepted.
//!
//! ## Fail-open, non-blocking — NEVER on the boot path
//!
//! A progress report is a display convenience, not a control signal: it
//! does NOT gate the KEK release, the attestation, the order handling, or
//! billing. Every [`VmProgressSink::report`] call therefore:
//!
//! - is spawned fire-and-forget by the caller (it never blocks the guest
//!   exchange it observes), and
//! - swallows every error internally (build / sign / transport) — a
//!   report that cannot be sent is logged and dropped, exactly like an
//!   at-least-once heartbeat, but WITHOUT any retry (a boot milestone is
//!   momentary; a stale re-send would only race a later milestone).
//!
//! ## Transport — the shared Edge mTLS leg
//!
//! The sink reuses the SAME miner→Edge mTLS client the §K heartbeat
//! pusher builds ([`crate::build_edge_mtls_client`]) and POSTs a signed
//! canonical-CBOR [`SignedVmProgress`] to the Edge `/v1/edge/vm-progress`
//! route. The Edge relays it opaquely to vali, which resolves the miner
//! from the mTLS peer-id and verifies the Ed25519 signature — the same
//! trust anchor as the heartbeat. No new transport is introduced.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hippius_types::vm_progress::{SignedVmProgress, VmProgressMilestone, VmProgressReport};

use crate::config::EdgeSection;
use crate::error::Result;
use crate::identity::MinerIdentity;

/// The Edge route a vm-progress report is POSTed to. Appended to the
/// configured Edge endpoint (the SAME endpoint the heartbeat targets).
const VM_PROGRESS_ROUTE: &str = "/v1/edge/vm-progress";

/// `content-type` of the posted report body — canonical CBOR.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// The seam the kbs-proxy reports milestones through. Production is
/// [`EdgeVmProgressSink`]; tests inject a recording stub.
#[async_trait]
pub trait VmProgressSink: Send + Sync {
    /// Best-effort, fail-open report that `vm_id` reached `milestone`.
    /// MUST NOT panic and MUST NOT propagate an error — a delivery
    /// failure is logged and dropped so the caller's boot path is never
    /// affected.
    async fn report(&self, vm_id: &str, milestone: VmProgressMilestone);
}

/// Production [`VmProgressSink`] — signs a [`SignedVmProgress`] with the
/// miner identity and POSTs it over the shared Edge mTLS client.
pub struct EdgeVmProgressSink {
    client: reqwest::Client,
    /// Full `https://…/v1/edge/vm-progress` URL, resolved once at boot.
    url: String,
    miner_id: String,
    identity: Arc<MinerIdentity>,
}

impl EdgeVmProgressSink {
    /// Build the sink from the `[edge]` config + the node identity +
    /// the registered `miner_id`. Reuses [`crate::build_edge_mtls_client`]
    /// — the exact mTLS leg the heartbeat pusher uses. Fails closed at
    /// boot ONLY on a material mTLS-material problem; the caller treats a
    /// build failure as "no sink" (progress reporting simply stays off),
    /// never as a serve-fatal error.
    pub fn new(edge: &EdgeSection, identity: Arc<MinerIdentity>, miner_id: String) -> Result<Self> {
        let client = crate::build_edge_mtls_client(edge, &identity)?;
        let url = format!(
            "{}{}",
            edge.endpoint.trim_end_matches('/'),
            VM_PROGRESS_ROUTE
        );
        Ok(Self {
            client,
            url,
            miner_id,
            identity,
        })
    }

    /// Build + sign the canonical `SignedVmProgress` envelope for
    /// `(vm_id, milestone)` at the current wall clock. Returns the wire
    /// bytes, or a static class on any encode/clock failure (the caller
    /// logs + drops — fail-open).
    fn build_envelope(
        &self,
        vm_id: &str,
        milestone: VmProgressMilestone,
    ) -> core::result::Result<Vec<u8>, &'static str> {
        let now = now_unix().ok_or("clock")?;
        let report =
            VmProgressReport::new(self.miner_id.clone(), vm_id.to_string(), milestone, now);
        let body = report.canonical().map_err(|_| "encode-body")?;
        let sig = self.identity.sign(&body).to_bytes().to_vec();
        SignedVmProgress { body, sig }
            .canonical()
            .map_err(|_| "encode-envelope")
    }
}

#[async_trait]
impl VmProgressSink for EdgeVmProgressSink {
    async fn report(&self, vm_id: &str, milestone: VmProgressMilestone) {
        let bytes = match self.build_envelope(vm_id, milestone) {
            Ok(b) => b,
            Err(class) => {
                eprintln!(
                    "hippius-miner-agent: vm-progress: vm={vm_id} milestone={} build-failed:{class}",
                    milestone.as_wire()
                );
                return;
            }
        };
        // Bounded, single-shot POST — no retry (a boot milestone is
        // momentary). Any outcome other than a 2xx is logged and dropped.
        match self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .timeout(Duration::from_secs(10))
            .body(bytes)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                eprintln!(
                    "hippius-miner-agent: vm-progress: vm={vm_id} milestone={} delivered",
                    milestone.as_wire()
                );
            }
            Ok(resp) => {
                eprintln!(
                    "hippius-miner-agent: vm-progress: vm={vm_id} milestone={} rejected status={}",
                    milestone.as_wire(),
                    resp.status().as_u16()
                );
            }
            Err(_) => {
                eprintln!(
                    "hippius-miner-agent: vm-progress: vm={vm_id} milestone={} transport-failed",
                    milestone.as_wire()
                );
            }
        }
    }
}

/// Wall-clock now as Unix seconds, or `None` on a clock-before-epoch
/// failure (the report is then dropped — fail-open).
fn now_unix() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::vm_progress::{SignedVmProgress, DOMAIN, SIGNATURE_LEN};
    use std::sync::Mutex;

    /// A recording sink — proves the kbs-proxy calls `report` with the
    /// right `(vm_id, milestone)` without any network.
    struct RecordingSink {
        seen: Mutex<Vec<(String, VmProgressMilestone)>>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl VmProgressSink for RecordingSink {
        async fn report(&self, vm_id: &str, milestone: VmProgressMilestone) {
            self.seen
                .lock()
                .expect("lock")
                .push((vm_id.to_string(), milestone));
        }
    }

    /// A test identity + miner_id, without touching the Edge transport —
    /// `build_envelope` is pure (sign + encode) so it is unit-testable in
    /// isolation.
    fn sink_without_transport() -> EdgeVmProgressSink {
        // The reqwest client is never exercised here (we only call
        // `build_envelope`), so a default client is fine.
        EdgeVmProgressSink {
            client: reqwest::Client::new(),
            url: "https://edge.invalid/v1/edge/vm-progress".to_string(),
            miner_id: "miner-a".to_string(),
            identity: Arc::new(MinerIdentity::generate().expect("identity")),
        }
    }

    #[test]
    fn build_envelope_signs_a_verifiable_report() {
        use ed25519_dalek::{Signature, Verifier};

        let sink = sink_without_transport();
        let bytes = sink
            .build_envelope("vm-xyz", VmProgressMilestone::KekReleased)
            .expect("envelope");
        // The wire bytes decode to a well-formed signed envelope whose
        // signature verifies against the sink's identity — exactly what
        // vali's `verify-vm-progress` will check.
        let env: SignedVmProgress = ciborium::de::from_reader(bytes.as_slice()).expect("decode");
        assert_eq!(env.sig.len(), SIGNATURE_LEN);
        let vk = sink.identity.verifying_key();
        let sig_arr: [u8; SIGNATURE_LEN] = env.sig.as_slice().try_into().expect("sig len");
        vk.verify(&env.body, &Signature::from_bytes(&sig_arr))
            .expect("signature verifies against the miner identity");
        // And the body carries the milestone + vm_id we asked for.
        let report: ciborium::value::Value =
            ciborium::de::from_reader(env.body.as_slice()).expect("body decode");
        let map = match report {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("body not a map"),
        };
        let get = |key: &str| -> String {
            map.iter()
                .find_map(|(k, v)| match (k, v) {
                    (ciborium::value::Value::Text(name), ciborium::value::Value::Text(val))
                        if name == key =>
                    {
                        Some(val.clone())
                    }
                    _ => None,
                })
                .unwrap_or_default()
        };
        assert_eq!(get("vm_id"), "vm-xyz");
        assert_eq!(get("milestone"), "kek-released");
        assert_eq!(get("domain"), DOMAIN);
    }

    #[tokio::test]
    async fn recording_sink_captures_reports() {
        let sink = RecordingSink::new();
        sink.report("vm-1", VmProgressMilestone::KekReleased).await;
        let seen = sink.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "vm-1");
        assert_eq!(seen[0].1, VmProgressMilestone::KekReleased);
    }
}
