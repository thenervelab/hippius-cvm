//! One-tick orchestration — separated from `main` so it's testable
//! against a mock `SnpReportProvider` + a mock HTTP client without
//! spinning up a real socket.

use crate::relay::AttestationSink;
use hippius_agent_initramfs::stages::snp_report::{
    live_attestation_report_data, SnpReportProvider,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Closed-vocabulary tick-level error class.
#[derive(Debug, Error)]
pub enum TickError {
    #[error("epoch-read")]
    EpochRead,
    #[error("clock")]
    Clock,
    #[error("snp-report-data")]
    SnpReportData,
    #[error("snp-report")]
    SnpReport,
    #[error("nonce-fetch")]
    NonceFetch,
    #[error("keepalive-post")]
    KeepalivePost,
}

/// Per-tick inputs.
pub struct TickInputs<'a> {
    pub vm_id: &'a str,
    pub node_id: &'a [u8; 32],
    /// Path to a text file containing the current compute-pallet
    /// epoch as decimal. The miner-agent (or some companion
    /// process) keeps this fresh; the keepalive agent re-reads it
    /// each tick. Absent / unreadable ⇒ `TickError::EpochRead` (we
    /// fail-close rather than ship attestations for epoch 0 the
    /// pallet would silently reject).
    pub epoch_file: &'a std::path::Path,
    /// `now_unix + expiry_offset_secs` becomes the
    /// `LiveAttestation::expiry_unix` field. Long enough to absorb
    /// the validator's batch latency, short enough that a stale
    /// signed body cannot be re-submitted weeks later.
    pub expiry_offset_secs: u64,
}

/// Per-tick result: the canonical-CBOR-encoded
/// `SignedLiveAttestation` bytes returned by KBS (callers can
/// archive them, push them to vali, or just trust KBS's own sink).
#[derive(Debug, Clone)]
pub struct TickOutput {
    pub signed_live_attestation: Vec<u8>,
}

/// Pluggable seam for the KBS client so tests don't need a real
/// reqwest client.
pub trait KbsTransport {
    fn fetch_nonce(&self) -> Result<[u8; 32], TickError>;
    fn post_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; 32],
        snp_report: &[u8],
        kbs_nonce: &[u8; 32],
        epoch: u64,
        expiry_unix: u64,
    ) -> Result<Vec<u8>, TickError>;
}

/// Real-client adapter — wraps `crate::client::KbsClient`.
impl KbsTransport for crate::client::KbsClient {
    fn fetch_nonce(&self) -> Result<[u8; 32], TickError> {
        crate::client::KbsClient::fetch_nonce(self).map_err(|_| TickError::NonceFetch)
    }
    fn post_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; 32],
        snp_report: &[u8],
        kbs_nonce: &[u8; 32],
        epoch: u64,
        expiry_unix: u64,
    ) -> Result<Vec<u8>, TickError> {
        crate::client::KbsClient::post_keepalive(
            self,
            vm_id,
            node_id,
            snp_report,
            kbs_nonce,
            epoch,
            expiry_unix,
        )
        .map_err(|_| TickError::KeepalivePost)
    }
}

fn read_epoch(path: &std::path::Path) -> Result<u64, TickError> {
    let s = std::fs::read_to_string(path).map_err(|_| TickError::EpochRead)?;
    s.trim().parse::<u64>().map_err(|_| TickError::EpochRead)
}

fn now_unix() -> Result<u64, TickError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TickError::Clock)
}

/// Run one keepalive cycle AND push the result to vali (§23).
///
/// Same as [`run_once`], plus the last hop: the KBS-signed attestation
/// is pushed through `sink` (vsock → miner-agent → Edge → vali's
/// uptime-coverage ingest). vali cannot credit this VM's served
/// receipts without it once the uptime-liveness gate is armed.
///
/// A push failure NEVER fails the tick: the attestation is already
/// minted and archived KBS-side, and the next tick pushes a fresh one.
/// The failure class is returned alongside the output so the caller can
/// log it — silently swallowing it would hide a fleet-wide relay
/// outage, which once the gate is armed is a fleet-wide revenue outage.
pub fn run_once_and_push(
    inputs: &TickInputs,
    provider: &dyn SnpReportProvider,
    kbs: &dyn KbsTransport,
    sink: &dyn AttestationSink,
) -> Result<(TickOutput, Option<&'static str>), TickError> {
    let out = run_once(inputs, provider, kbs)?;
    let push = sink
        .push(&out.signed_live_attestation)
        .err()
        .map(|e| e.class());
    Ok((out, push))
}

/// Run one keepalive cycle: read epoch, fetch nonce, ask the SNP
/// provider for a report, POST it to KBS, return the signed bytes.
pub fn run_once(
    inputs: &TickInputs,
    provider: &dyn SnpReportProvider,
    kbs: &dyn KbsTransport,
) -> Result<TickOutput, TickError> {
    let epoch = read_epoch(inputs.epoch_file)?;
    let now = now_unix()?;
    let expiry = now.saturating_add(inputs.expiry_offset_secs);

    let nonce = kbs.fetch_nonce()?;
    let rd =
        live_attestation_report_data(&nonce, inputs.vm_id).map_err(|_| TickError::SnpReportData)?;
    let report = provider.get_report(rd).map_err(|_| TickError::SnpReport)?;
    let signed = kbs.post_keepalive(
        inputs.vm_id,
        inputs.node_id,
        report.0.as_slice(),
        &nonce,
        epoch,
        expiry,
    )?;
    Ok(TickOutput {
        signed_live_attestation: signed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_agent_initramfs::stages::snp_report::{MockSnpReportProvider, SNP_REPORT_LEN};
    use std::cell::RefCell;
    use std::sync::Mutex;

    type PostRecord = (String, [u8; 32], Vec<u8>, [u8; 32], u64, u64);
    struct StubKbs {
        nonce: [u8; 32],
        last_post: Mutex<RefCell<Option<PostRecord>>>,
        post_response: Vec<u8>,
        fail_nonce: bool,
        fail_post: bool,
    }
    impl StubKbs {
        fn ok(nonce: [u8; 32]) -> Self {
            Self {
                nonce,
                last_post: Mutex::new(RefCell::new(None)),
                post_response: vec![0xCD; 16],
                fail_nonce: false,
                fail_post: false,
            }
        }
    }
    impl KbsTransport for StubKbs {
        fn fetch_nonce(&self) -> Result<[u8; 32], TickError> {
            if self.fail_nonce {
                return Err(TickError::NonceFetch);
            }
            Ok(self.nonce)
        }
        fn post_keepalive(
            &self,
            vm_id: &str,
            node_id: &[u8; 32],
            snp_report: &[u8],
            kbs_nonce: &[u8; 32],
            epoch: u64,
            expiry_unix: u64,
        ) -> Result<Vec<u8>, TickError> {
            if self.fail_post {
                return Err(TickError::KeepalivePost);
            }
            self.last_post.lock().unwrap().replace(Some((
                vm_id.to_string(),
                *node_id,
                snp_report.to_vec(),
                *kbs_nonce,
                epoch,
                expiry_unix,
            )));
            Ok(self.post_response.clone())
        }
    }

    fn epoch_file_with(value: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(value.as_bytes()).unwrap();
        f
    }

    #[test]
    fn run_once_happy_path() {
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        let out = run_once(&inputs, &provider, &kbs).expect("happy keepalive");
        assert_eq!(out.signed_live_attestation, vec![0xCD; 16]);

        let post = kbs.last_post.lock().unwrap().borrow().clone().unwrap();
        assert_eq!(post.0, "vm-test");
        assert_eq!(post.1, [0xBB; 32]);
        assert_eq!(post.3, [0x42; 32]);
        assert_eq!(post.4, 42);
        // expiry is now + 600s; bounded by the test wall clock, so
        // just verify it's strictly after the file's epoch alone.
        assert!(post.5 > 1_700_000_000);

        // The mock provider captured the REPORT_DATA the keepalive
        // built — assert it matches the canonical helper, NOT the
        // tenant-release layout (regression guard against §20
        // cross-domain replay).
        let captured = provider.captured_report_data().unwrap();
        let expected =
            hippius_types::report_data::live_attestation(&[0x42; 32], "vm-test").unwrap();
        assert_eq!(captured, expected);
    }

    #[test]
    fn run_once_and_push_relays_the_kbs_signed_bytes_verbatim() {
        // The attestation vali must see is EXACTLY what KBS signed — a
        // re-encode would break the L0 signature.
        use crate::relay::WriterSink;
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        let sink = WriterSink(std::cell::RefCell::new(Vec::new()));

        let (out, push_err) = run_once_and_push(&inputs, &provider, &kbs, &sink).unwrap();

        assert!(push_err.is_none());
        let framed = sink.0.into_inner();
        let expected = crate::relay::encode_frame(&out.signed_live_attestation).unwrap();
        assert_eq!(framed, expected);
    }

    #[test]
    fn a_push_failure_does_not_fail_the_tick() {
        // The attestation is already minted + archived KBS-side; a
        // vsock hiccup must not be reported as a failed keepalive.
        use crate::relay::{AttestationSink, RelayError};
        struct Broken;
        impl AttestationSink for Broken {
            fn push(&self, _: &[u8]) -> Result<(), RelayError> {
                Err(RelayError::Io)
            }
        }
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);

        let (out, push_err) = run_once_and_push(&inputs, &provider, &kbs, &Broken).unwrap();

        assert_eq!(out.signed_live_attestation, vec![0xCD; 16]);
        // …but it IS surfaced, so a fleet-wide relay outage is visible.
        assert_eq!(push_err, Some("relay-io"));
    }

    #[test]
    fn a_failed_tick_pushes_nothing() {
        use crate::relay::WriterSink;
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let mut kbs = StubKbs::ok([0x42; 32]);
        kbs.fail_post = true;
        let sink = WriterSink(std::cell::RefCell::new(Vec::new()));

        assert!(run_once_and_push(&inputs, &provider, &kbs, &sink).is_err());
        assert!(
            sink.0.into_inner().is_empty(),
            "nothing may be relayed when KBS did not sign an attestation"
        );
    }

    #[test]
    fn run_once_propagates_nonce_failure() {
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let mut kbs = StubKbs::ok([0x42; 32]);
        kbs.fail_nonce = true;
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::NonceFetch));
    }

    #[test]
    fn run_once_propagates_post_failure() {
        let f = epoch_file_with("42");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let mut kbs = StubKbs::ok([0x42; 32]);
        kbs.fail_post = true;
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::KeepalivePost));
    }

    #[test]
    fn run_once_rejects_unreadable_epoch_file() {
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: std::path::Path::new("/dev/null/no-such-file"),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::EpochRead));
    }

    #[test]
    fn run_once_rejects_non_decimal_epoch() {
        let f = epoch_file_with("not-a-number\n");
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::EpochRead));
    }
}
