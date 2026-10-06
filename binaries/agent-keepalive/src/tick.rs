//! One-tick orchestration — separated from `main` so it's testable
//! against a mock `SnpReportProvider` + a mock HTTP client without
//! spinning up a real socket.

use crate::relay::AttestationSink;
use hippius_agent_initramfs::stages::snp_report::{
    live_attestation_components_report_data, live_attestation_report_data,
    live_attestation_resources_report_data, SnpReportProvider,
};
use hippius_types::live_attestation::{GuestComponents, GuestResources};
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
    #[error("resources:{0}")]
    Resources(crate::resources::ResourcesError),
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
    /// `Some(root)` ⇒ read the guest's vCPU / RAM figures under `root`
    /// (`/` in production) and attest them: they go into `REPORT_DATA`
    /// and the request, and the KBS signs them into a schema-v3 body.
    /// `None` ⇒ the resource-less keepalive, byte-identical to before.
    /// Switched on by the MEASURED `hippius.attest_resources=1` token, so
    /// vali turns it on only once the KBS understands the field — and the
    /// host cannot turn it off.
    pub resources_root: Option<&'a std::path::Path>,
    /// `Some(probe)` ⇒ attest the guest components release and its health
    /// (schema v4): the values go into `REPORT_DATA` and the request.
    /// Never fails the tick — a check that cannot run is a cleared bit.
    /// Switched on by the RELEASE (`HIPPIUS_KEEPALIVE_ATTEST_COMPONENTS=1`
    /// in its measured `keepalive.env`), which is cut only once the KBS
    /// understands the field.
    pub components: Option<&'a crate::components::ComponentsTracker>,
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
    #[allow(clippy::too_many_arguments)]
    fn post_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; 32],
        snp_report: &[u8],
        kbs_nonce: &[u8; 32],
        epoch: u64,
        expiry_unix: u64,
        resources: Option<&GuestResources>,
        components: Option<&GuestComponents>,
    ) -> Result<Vec<u8>, TickError>;
}

/// Real-client adapter — wraps `crate::client::KbsClient`.
impl KbsTransport for crate::client::KbsClient {
    fn fetch_nonce(&self) -> Result<[u8; 32], TickError> {
        crate::client::KbsClient::fetch_nonce(self).map_err(|_| TickError::NonceFetch)
    }
    #[allow(clippy::too_many_arguments)]
    fn post_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; 32],
        snp_report: &[u8],
        kbs_nonce: &[u8; 32],
        epoch: u64,
        expiry_unix: u64,
        resources: Option<&GuestResources>,
        components: Option<&GuestComponents>,
    ) -> Result<Vec<u8>, TickError> {
        crate::client::KbsClient::post_keepalive(
            self,
            vm_id,
            node_id,
            snp_report,
            kbs_nonce,
            epoch,
            expiry_unix,
            resources,
            components,
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

    // Read the resources before the nonce: a guest that cannot say what
    // it runs with does not spend a KBS nonce.
    let resources = match inputs.resources_root {
        Some(root) => Some(crate::resources::read(root).map_err(TickError::Resources)?),
        None => None,
    };
    let nonce = kbs.fetch_nonce()?;
    // After the nonce: the KBS states the nonce's issuance as when these
    // checks were made at the earliest, so they must not be older.
    let components = inputs.components.map(|tracker| tracker.tick());
    let rd = match (&components, &resources) {
        (Some(c), r) => {
            live_attestation_components_report_data(&nonce, inputs.vm_id, c, r.as_ref())
        }
        (None, Some(r)) => live_attestation_resources_report_data(&nonce, inputs.vm_id, r),
        (None, None) => live_attestation_report_data(&nonce, inputs.vm_id),
    }
    .map_err(|_| TickError::SnpReportData)?;
    let report = provider.get_report(rd).map_err(|_| TickError::SnpReport)?;
    let signed = kbs.post_keepalive(
        inputs.vm_id,
        inputs.node_id,
        report.0.as_slice(),
        &nonce,
        epoch,
        expiry,
        resources.as_ref(),
        components.as_ref(),
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

    type PostRecord = (
        String,
        [u8; 32],
        Vec<u8>,
        [u8; 32],
        u64,
        u64,
        Option<GuestResources>,
        Option<GuestComponents>,
    );
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
        #[allow(clippy::too_many_arguments)]
        fn post_keepalive(
            &self,
            vm_id: &str,
            node_id: &[u8; 32],
            snp_report: &[u8],
            kbs_nonce: &[u8; 32],
            epoch: u64,
            expiry_unix: u64,
            resources: Option<&GuestResources>,
            components: Option<&GuestComponents>,
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
                resources.copied(),
                components.copied(),
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
            resources_root: None,
            components: None,
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
        assert_eq!(
            post.6, None,
            "no resources unless the measured cmdline asks"
        );

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
    fn run_once_attests_the_resources_it_read() {
        let f = epoch_file_with("42");
        let root = tempfile::tempdir().unwrap();
        let p = root.path();
        std::fs::create_dir_all(p.join("sys/devices/system/cpu")).unwrap();
        std::fs::write(p.join("sys/devices/system/cpu/online"), "0-1\n").unwrap();
        std::fs::create_dir_all(p.join("proc")).unwrap();
        std::fs::write(p.join("proc/meminfo"), "MemTotal:        7900000 kB\n").unwrap();
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
            resources_root: Some(p),
            components: None,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        run_once(&inputs, &provider, &kbs).expect("keepalive with resources");

        let want = GuestResources {
            vcpus_online: 2,
            mem_firmware_kib: 0,
            mem_total_kib: 7_900_000,
            mem_unaccepted_kib: 0,
        };
        let post = kbs.last_post.lock().unwrap().borrow().clone().unwrap();
        assert_eq!(post.6, Some(want), "the request carries what was read");
        // …and the report binds the SAME values, so the KBS can check them.
        let expected = hippius_types::report_data::live_attestation_with_resources(
            &[0x42; 32],
            "vm-test",
            &want,
        )
        .unwrap();
        assert_eq!(provider.captured_report_data().unwrap(), expected);
    }

    #[test]
    fn run_once_attests_the_components_with_and_without_resources() {
        use crate::components::{ComponentsProbe, ComponentsTracker};
        let f = epoch_file_with("42");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("record"),
            "version=2\nsecurity_epoch=1\ncommit=c\nmounted=yes\n",
        )
        .unwrap();
        let probe = ComponentsProbe {
            record: dir.path().join("record"),
            release_bin: dir.path().join("no-bin"),
            self_exe: dir.path().join("no-exe"),
            systemctl: dir.path().join("no-systemctl"),
            timeout: std::time::Duration::from_secs(1),
        };
        let tracker = ComponentsTracker::new(probe, 9);
        let mut want = GuestComponents {
            release_version: 2,
            security_epoch: 1,
            health: hippius_types::live_attestation::components_health::MOUNTED,
            instance: 9,
            unhealthy_ticks: 0,
        };
        let root = tempfile::tempdir().unwrap();
        let p = root.path();
        std::fs::create_dir_all(p.join("sys/devices/system/cpu")).unwrap();
        std::fs::write(p.join("sys/devices/system/cpu/online"), "0-1\n").unwrap();
        std::fs::create_dir_all(p.join("proc")).unwrap();
        std::fs::write(p.join("proc/meminfo"), "MemTotal:        7900000 kB\n").unwrap();
        let resources = GuestResources {
            vcpus_online: 2,
            mem_firmware_kib: 0,
            mem_total_kib: 7_900_000,
            mem_unaccepted_kib: 0,
        };
        for (root, expect_resources) in [(None, None), (Some(p), Some(resources))] {
            let inputs = TickInputs {
                vm_id: "vm-test",
                node_id: &[0xBB; 32],
                epoch_file: f.path(),
                expiry_offset_secs: 600,
                resources_root: root,
                components: Some(&tracker),
            };
            let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
            let kbs = StubKbs::ok([0x42; 32]);
            run_once(&inputs, &provider, &kbs).expect("keepalive with components");
            // Only MOUNTED passes: every tick latches a failure.
            want.unhealthy_ticks += 1;
            let post = kbs.last_post.lock().unwrap().borrow().clone().unwrap();
            assert_eq!((post.6, post.7), (expect_resources, Some(want)));
            let expected = hippius_types::report_data::live_attestation_with_components(
                &[0x42; 32],
                "vm-test",
                &want,
                expect_resources.as_ref(),
            )
            .unwrap();
            assert_eq!(provider.captured_report_data().unwrap(), expected);
        }
    }

    #[test]
    fn unreadable_resources_fail_the_tick_before_a_nonce_is_spent() {
        let f = epoch_file_with("42");
        let empty = tempfile::tempdir().unwrap();
        let inputs = TickInputs {
            vm_id: "vm-test",
            node_id: &[0xBB; 32],
            epoch_file: f.path(),
            expiry_offset_secs: 600,
            resources_root: Some(empty.path()),
            components: None,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let mut kbs = StubKbs::ok([0x42; 32]);
        kbs.fail_nonce = true; // would surface as NonceFetch if reached
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::Resources(_)), "{err:?}");
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
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
            resources_root: None,
            components: None,
        };
        let provider = MockSnpReportProvider::new(vec![0xAA; SNP_REPORT_LEN]);
        let kbs = StubKbs::ok([0x42; 32]);
        let err = run_once(&inputs, &provider, &kbs).unwrap_err();
        assert!(matches!(err, TickError::EpochRead));
    }
}
