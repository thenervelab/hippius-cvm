use std::path::PathBuf;
use std::sync::Mutex as StdMutex;

use hippius_types::guardian::{
    GuardianNonceRequest, LaunchRecipe, DENY_SIG_DOMAIN, GUARDIAN_NONCE_PATH,
    GUARDIAN_RELEASE_PATH, GUARDIAN_STAMP_CONFIRM_PATH,
};
use serde_bytes::ByteBuf;

use super::*;
use crate::lifecycle::guardian::GuardianRoute;
use crate::lifecycle::{HostResources, MockLaunchDigest, MockLibvirtDriver};
use crate::orders::LaunchOrder;

// ---------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------

const EP_A: &str = "100.64.0.10:7443";
const EP_B: &str = "100.64.0.11:7443";
const PK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// An M1 cmdline measuring `ep` — hex-encoded, as vali mints it.
fn cmdline(ep: &str) -> String {
    let tok = hex::encode(ep.as_bytes());
    format!(
        "console=hvc0 hippius.key_mode=split hippius.guardian_pk={PK} hippius.guardian_ep={tok}"
    )
}

fn recipe(ep: &str) -> LaunchRecipe {
    LaunchRecipe {
        ovmf_sha384: vec![1; 48],
        kernel_sha256: vec![2; 32],
        initrd_sha256: vec![3; 32],
        cmdline: cmdline(ep),
        vcpus: 2,
        vcpu_type: "EpycGenoa".into(),
        guest_features: 1,
    }
}

fn binding(vm: &str, domain: &str, ep: &str) -> RouteBinding {
    RouteBinding {
        vm_id: VmId::new(vm).unwrap(),
        domain: domain.into(),
        route: GuardianRoute {
            endpoint: ep.into(),
            recipe: recipe(ep),
        },
    }
}

/// A route table keyed by CID; mutable so a test can change a CID's owner
/// between admission and the post-read re-resolve.
struct FakeRoutes(StdMutex<HashMap<u32, Result<RouteBinding, &'static str>>>);

impl FakeRoutes {
    fn one(cid: u32, vm: &str, ep: &str) -> Self {
        let mut m = HashMap::new();
        m.insert(cid, Ok(binding(vm, "dom-1", ep)));
        Self(StdMutex::new(m))
    }
    fn of(m: HashMap<u32, Result<RouteBinding, &'static str>>) -> Self {
        Self(StdMutex::new(m))
    }
    fn set(&self, cid: u32, v: Result<RouteBinding, &'static str>) {
        self.0.lock().unwrap().insert(cid, v);
    }
}

impl GuardianRouteSource for FakeRoutes {
    fn route_for_cid(&self, cid: u32) -> Result<RouteBinding, &'static str> {
        self.0
            .lock()
            .unwrap()
            .get(&cid)
            .cloned()
            .unwrap_or(Err("unknown-cid"))
    }
}

impl GuardianRouteSource for Arc<FakeRoutes> {
    fn route_for_cid(&self, cid: u32) -> Result<RouteBinding, &'static str> {
        self.as_ref().route_for_cid(cid)
    }
}

/// A fake guardian: records every call, answers from a script.
struct FakeGuardian {
    answer: Result<(u16, Vec<u8>), DialError>,
    calls: StdMutex<Vec<(String, String, Vec<u8>)>>,
}

impl FakeGuardian {
    fn answering(answer: Result<(u16, Vec<u8>), DialError>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            calls: StdMutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> Vec<(String, String, Vec<u8>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl GuardianDialer for FakeGuardian {
    async fn post(
        &self,
        endpoint: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), DialError> {
        self.calls
            .lock()
            .unwrap()
            .push((endpoint.into(), path.into(), body.to_vec()));
        self.answer.clone()
    }
}

#[derive(Default)]
struct RecordingSink {
    seen: StdMutex<Vec<(String, VmProgressMilestone)>>,
}

#[async_trait]
impl VmProgressSink for RecordingSink {
    async fn report(&self, vm_id: &str, milestone: VmProgressMilestone) {
        self.seen.lock().unwrap().push((vm_id.into(), milestone));
    }
}

impl RecordingSink {
    /// Let the detached report tasks run, then read.
    async fn seen(&self) -> Vec<(String, VmProgressMilestone)> {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        self.seen.lock().unwrap().clone()
    }
}

fn relay(
    routes: impl GuardianRouteSource + 'static,
    dialer: Arc<dyn GuardianDialer>,
    sink: Option<Arc<RecordingSink>>,
) -> GuardianRelay {
    GuardianRelay::new(
        Arc::new(routes),
        dialer,
        sink.map(|s| s as Arc<dyn VmProgressSink>),
    )
}

fn frame(path: &str, body: &[u8]) -> Vec<u8> {
    let req = KbsProxyRequest {
        path: path.into(),
        body: ByteBuf::from(body.to_vec()),
    };
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&req, &mut cbor).unwrap();
    let mut out = (cbor.len() as u32).to_be_bytes().to_vec();
    out.extend(cbor);
    out
}

/// Run one connection from `cid` sending `raw`; return the outcome and
/// the decoded response (if any was written).
async fn exchange_raw(
    relay: &GuardianRelay,
    cid: u32,
    raw: Vec<u8>,
) -> (GuardianRelayOutcome, Option<KbsProxyResponse>) {
    let (mut guest, host) = tokio::io::duplex(256 * 1024);
    guest.write_all(&raw).await.unwrap();
    // The guest has said everything: EOF, as a real one-shot client.
    guest.shutdown().await.unwrap();
    let outcome = serve_guardian_conn(host, relay, cid).await;
    let mut buf = Vec::new();
    guest.read_to_end(&mut buf).await.unwrap();
    if buf.is_empty() {
        return (outcome, None);
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    assert_eq!(len, buf.len() - 4);
    (outcome, Some(ciborium::de::from_reader(&buf[4..]).unwrap()))
}

async fn exchange(
    relay: &GuardianRelay,
    cid: u32,
    path: &str,
    body: &[u8],
) -> (GuardianRelayOutcome, Option<KbsProxyResponse>) {
    exchange_raw(relay, cid, frame(path, body)).await
}

fn signed_denial(reason: GuardianDenyReason) -> Vec<u8> {
    let denial = GuardianDenial {
        v: 1,
        vm_id: "vm-a".into(),
        nonce: vec![7; 32],
        guest_pub_hash: vec![8; 32],
        reason,
    };
    encode_canonical(&SignedGuardianDenial {
        body: encode_canonical(&denial).unwrap(),
        sig: vec![9; 64],
    })
    .unwrap()
}

// ---------------------------------------------------------------------
// handler
// ---------------------------------------------------------------------

#[tokio::test]
async fn every_allowed_path_is_forwarded_verbatim_to_the_cids_guardian() {
    for path in GUARDIAN_ALLOWED_PATHS {
        let g = FakeGuardian::answering(Ok((200, b"guardian-says".to_vec())));
        let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
        let (outcome, resp) = exchange(&r, 5, path, b"opaque-cbor").await;
        assert_eq!(outcome, GuardianRelayOutcome::Forwarded { status: 200 });
        let resp = resp.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_slice(), b"guardian-says");
        assert_eq!(
            g.calls(),
            vec![(EP_A.to_string(), path.to_string(), b"opaque-cbor".to_vec())]
        );
    }
}

#[tokio::test]
async fn a_guardian_status_is_passed_through_unchanged() {
    let g = FakeGuardian::answering(Ok((409, b"x".to_vec())));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, None);
    let (outcome, resp) = exchange(&r, 5, GUARDIAN_NONCE_PATH, b"b").await;
    assert_eq!(outcome, GuardianRelayOutcome::Forwarded { status: 409 });
    assert_eq!(resp.unwrap().status, 409);
}

#[tokio::test]
async fn a_forbidden_path_is_answered_locally_and_never_dialed() {
    for path in [
        "/v1/guardian/nonce?x=1",
        "/v1/guardian/release/",
        "/v1/guardian/admin",
        "/v1/kbs/release",
        "/V1/GUARDIAN/NONCE",
        "",
        "http://10.0.0.1/v1/guardian/nonce",
    ] {
        let g = FakeGuardian::answering(Ok((200, vec![])));
        let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
        let (outcome, resp) = exchange(&r, 5, path, b"b").await;
        assert_eq!(
            outcome,
            GuardianRelayOutcome::Answered {
                class: relay_answer::PATH_FORBIDDEN.1,
                why: "path"
            },
            "{path}"
        );
        let resp = resp.unwrap();
        assert_eq!(resp.status, 403);
        assert_eq!(
            resp.body.as_slice(),
            relay_answer::PATH_FORBIDDEN.1.as_bytes()
        );
        assert!(g.calls().is_empty(), "{path}");
    }
}

#[tokio::test]
async fn the_request_body_cap_is_exact() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
    let at_cap = vec![0u8; GUARDIAN_MAX_REQUEST_BYTES];
    let (outcome, _) = exchange(&r, 5, GUARDIAN_RELEASE_PATH, &at_cap).await;
    assert_eq!(outcome, GuardianRelayOutcome::Forwarded { status: 200 });
    let over = vec![0u8; GUARDIAN_MAX_REQUEST_BYTES + 1];
    let (outcome, resp) = exchange(&r, 5, GUARDIAN_RELEASE_PATH, &over).await;
    assert_eq!(
        outcome,
        GuardianRelayOutcome::Answered {
            class: relay_answer::REQUEST_TOO_LARGE.1,
            why: "body"
        }
    );
    assert_eq!(resp.unwrap().status, 413);
    assert_eq!(g.calls().len(), 1, "only the at-cap body was forwarded");
}

#[tokio::test]
async fn an_oversize_or_empty_frame_is_dropped_before_decode() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
    // The frame cap is the body cap plus 1 KiB of envelope — spelled out
    // here, not via the constant, so a drift in it is caught.
    assert_eq!(MAX_REQUEST_FRAME, 64 * 1024 + 1024);
    let mut huge = ((64 * 1024 + 1024 + 1) as u32).to_be_bytes().to_vec();
    huge.extend(vec![0u8; 16]);
    assert_eq!(
        exchange_raw(&r, 5, huge).await,
        (GuardianRelayOutcome::Dropped("length"), None)
    );
    // Exactly at the cap the length is accepted (then the short body
    // fails the read, not the length check).
    let mut at_cap = ((64 * 1024 + 1024) as u32).to_be_bytes().to_vec();
    at_cap.extend(vec![0u8; 16]);
    assert_eq!(
        exchange_raw(&r, 5, at_cap).await,
        (GuardianRelayOutcome::Dropped("read-body"), None)
    );
    assert_eq!(
        exchange_raw(&r, 5, vec![0, 0, 0, 0]).await,
        (GuardianRelayOutcome::Dropped("length"), None)
    );
    let mut junk = 3u32.to_be_bytes().to_vec();
    junk.extend([0xff, 0xff, 0xff]);
    assert_eq!(
        exchange_raw(&r, 5, junk).await,
        (GuardianRelayOutcome::Dropped("decode"), None)
    );
    assert!(g.calls().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_silent_guest_is_dropped_after_the_read_timeout() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, None);
    let (_guest, host) = tokio::io::duplex(1024);
    let outcome = serve_guardian_conn(host, &r, 5).await;
    assert_eq!(outcome, GuardianRelayOutcome::Dropped("read-timeout"));
}

#[tokio::test]
async fn a_cid_without_a_route_is_refused_and_never_dialed() {
    for why in [
        "unknown-cid",
        "no-guardian",
        "cid-unverified",
        "cid-not-current",
    ] {
        let g = FakeGuardian::answering(Ok((200, vec![])));
        let mut routes = HashMap::new();
        routes.insert(5, Err(why));
        let r = relay(FakeRoutes::of(routes), g.clone(), None);
        for path in [GUARDIAN_NONCE_PATH, GUARDIAN_RECIPE_PATH] {
            // Dropped at admission: nothing read, nothing answered.
            let (outcome, resp) = exchange(&r, 5, path, b"b").await;
            assert_eq!(outcome, GuardianRelayOutcome::Dropped(why));
            assert!(resp.is_none());
        }
        assert!(g.calls().is_empty());
    }
    // Wrong CID: CID 6 is nobody's.
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
    let (outcome, resp) = exchange(&r, 6, GUARDIAN_NONCE_PATH, b"b").await;
    assert_eq!(outcome, GuardianRelayOutcome::Dropped("unknown-cid"));
    assert!(resp.is_none());
    assert!(g.calls().is_empty());
}

/// Slowloris: a route-less CID is refused before a byte is read — the
/// connection is not even held for the read timeout.
#[tokio::test(start_paused = true)]
async fn a_route_less_cid_is_dropped_without_waiting_for_its_bytes() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, None);
    let (_guest, host) = tokio::io::duplex(1024);
    let t0 = tokio::time::Instant::now();
    let outcome = serve_guardian_conn(host, &r, 9).await;
    assert_eq!(outcome, GuardianRelayOutcome::Dropped("unknown-cid"));
    assert_eq!(
        tokio::time::Instant::now(),
        t0,
        "no read timeout was waited"
    );
}

#[test]
fn each_vm_holds_at_most_four_connections() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let mut m = HashMap::new();
    m.insert(5, Ok(binding("vm-a", "dom-1", EP_A)));
    m.insert(6, Ok(binding("vm-b", "dom-2", EP_B)));
    let r = relay(FakeRoutes::of(m), g, None);
    assert_eq!(MAX_INFLIGHT_PER_VM, 4);
    let held: Vec<Admission> = (0..4).map(|_| r.admit(5).unwrap()).collect();
    assert_eq!(r.admit(5).err(), Some("vm-inflight-cap"));
    // Another VM is unaffected.
    let b = r.admit(6).unwrap();
    assert_eq!(b.binding().vm_id.as_str(), "vm-b");
    // Releasing one slot frees exactly one.
    let mut held = held;
    held.pop();
    let again = r.admit(5).unwrap();
    assert_eq!(r.admit(5).err(), Some("vm-inflight-cap"));
    drop(again);
    drop(held);
    // All released: the count is gone, a full burst is admitted again.
    let _all: Vec<Admission> = (0..4).map(|_| r.admit(5).unwrap()).collect();
}

/// The CID's owner changed between accept and the post-read re-resolve:
/// refused, and the new owner's guardian is never dialed.
#[tokio::test]
async fn a_cid_whose_owner_changed_after_admission_is_refused() {
    for changed in [
        binding("vm-b", "dom-1", EP_B), // another VM
        binding("vm-a", "dom-2", EP_A), // same vm_id, new domain incarnation
    ] {
        let g = FakeGuardian::answering(Ok((200, vec![])));
        let routes = Arc::new(FakeRoutes::one(5, "vm-a", EP_A));
        let r = GuardianRelay::new(Arc::new(Arc::clone(&routes)), g.clone(), None);
        let admission = r.admit(5).unwrap();
        routes.set(5, Ok(changed));
        let (mut guest, host) = tokio::io::duplex(256 * 1024);
        guest
            .write_all(&frame(GUARDIAN_NONCE_PATH, b"b"))
            .await
            .unwrap();
        let outcome = handle_guardian_conn(host, &r, 5, admission).await;
        assert_eq!(
            outcome,
            GuardianRelayOutcome::Answered {
                class: relay_answer::NO_GUARDIAN.1,
                why: "cid-owner-changed"
            }
        );
        assert!(g.calls().is_empty());
    }
    // Owner gone entirely after admission: answered with the class.
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let routes = Arc::new(FakeRoutes::one(5, "vm-a", EP_A));
    let r = GuardianRelay::new(Arc::new(Arc::clone(&routes)), g.clone(), None);
    let admission = r.admit(5).unwrap();
    routes.set(5, Err("cid-not-current"));
    let (mut guest, host) = tokio::io::duplex(1024);
    guest
        .write_all(&frame(GUARDIAN_NONCE_PATH, b"b"))
        .await
        .unwrap();
    let outcome = handle_guardian_conn(host, &r, 5, admission).await;
    assert_eq!(
        outcome,
        GuardianRelayOutcome::Answered {
            class: relay_answer::NO_GUARDIAN.1,
            why: "cid-not-current"
        }
    );
    assert!(g.calls().is_empty());
}

#[tokio::test]
async fn the_recipe_path_is_answered_locally_with_the_canonical_recipe() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
    let (outcome, resp) = exchange(&r, 5, GUARDIAN_RECIPE_PATH, b"ignored").await;
    assert_eq!(outcome, GuardianRelayOutcome::Recipe);
    let resp = resp.unwrap();
    assert_eq!(resp.status, 200);
    let back: LaunchRecipe = decode_canonical(&resp.body).unwrap();
    assert_eq!(back, recipe(EP_A));
    assert!(g.calls().is_empty(), "the recipe is never forwarded");
}

#[tokio::test]
async fn dial_failures_answer_locally_and_report_the_matching_reason() {
    for (err, ans, reason) in [
        (
            DialError::Unreachable,
            relay_answer::UNREACHABLE,
            GuardianWaitReason::Unreachable,
        ),
        (
            DialError::Timeout,
            relay_answer::TIMEOUT,
            GuardianWaitReason::Timeout,
        ),
        (
            DialError::BadResponse,
            relay_answer::BAD_RESPONSE,
            GuardianWaitReason::BadResponse,
        ),
    ] {
        let sink = Arc::new(RecordingSink::default());
        let g = FakeGuardian::answering(Err(err));
        let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, Some(sink.clone()));
        let (outcome, resp) = exchange(&r, 5, GUARDIAN_NONCE_PATH, b"b").await;
        assert_eq!(
            outcome,
            GuardianRelayOutcome::Answered {
                class: ans.1,
                why: "dial"
            }
        );
        let resp = resp.unwrap();
        assert_eq!(
            (resp.status, resp.body.as_slice()),
            (ans.0, ans.1.as_bytes())
        );
        assert_eq!(
            sink.seen().await,
            vec![(
                "vm-a".to_string(),
                VmProgressMilestone::AwaitingGuardian(reason)
            )]
        );
    }
}

#[tokio::test]
async fn a_signed_denial_is_relayed_and_reported_as_refused() {
    for reason in GuardianDenyReason::ALL {
        let sink = Arc::new(RecordingSink::default());
        let body = signed_denial(reason);
        let g = FakeGuardian::answering(Ok((403, body.clone())));
        let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, Some(sink.clone()));
        let (outcome, resp) = exchange(&r, 5, GUARDIAN_RELEASE_PATH, b"b").await;
        assert_eq!(outcome, GuardianRelayOutcome::Forwarded { status: 403 });
        assert_eq!(resp.unwrap().body.into_vec(), body, "relayed verbatim");
        assert_eq!(
            sink.seen().await,
            vec![(
                "vm-a".to_string(),
                VmProgressMilestone::AwaitingGuardian(GuardianWaitReason::Refused(reason))
            )]
        );
    }
}

#[tokio::test]
async fn a_success_reports_nothing_and_a_non_denial_error_is_bad_response() {
    let sink = Arc::new(RecordingSink::default());
    let g = FakeGuardian::answering(Ok((200, b"signed-response".to_vec())));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, Some(sink.clone()));
    exchange(&r, 5, GUARDIAN_RELEASE_PATH, b"b").await;
    assert!(sink.seen().await.is_empty());

    let sink = Arc::new(RecordingSink::default());
    let g = FakeGuardian::answering(Ok((500, b"oops".to_vec())));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g, Some(sink.clone()));
    exchange(&r, 5, GUARDIAN_RELEASE_PATH, b"b").await;
    assert_eq!(
        sink.seen().await,
        vec![(
            "vm-a".to_string(),
            VmProgressMilestone::AwaitingGuardian(GuardianWaitReason::BadResponse)
        )]
    );
}

#[tokio::test]
async fn progress_is_reported_at_most_once_per_interval_per_vm() {
    let sink = Arc::new(RecordingSink::default());
    let g = FakeGuardian::answering(Err(DialError::Unreachable));
    let routes = FakeRoutes::one(5, "vm-a", EP_A);
    routes.set(6, Ok(binding("vm-b", "dom-2", EP_B)));
    let r = relay(routes, g, Some(sink.clone()));
    for _ in 0..3 {
        exchange(&r, 5, GUARDIAN_NONCE_PATH, b"b").await;
        exchange(&r, 6, GUARDIAN_NONCE_PATH, b"b").await;
    }
    let seen = sink.seen().await;
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen.iter().any(|(v, _)| v == "vm-a"));
    assert!(seen.iter().any(|(v, _)| v == "vm-b"));
}

#[test]
fn progress_limiter_interval_and_bound() {
    let l = ProgressLimiter::new();
    let t0 = Instant::now();
    assert!(l.try_acquire("a", t0));
    assert!(!l.try_acquire("a", t0 + PROGRESS_MIN_INTERVAL - Duration::from_millis(1)));
    assert!(l.try_acquire("a", t0 + PROGRESS_MIN_INTERVAL));
    // Full table: fresh entries are kept, a newcomer is refused …
    let l = ProgressLimiter::new();
    for i in 0..PROGRESS_MAX_TRACKED_VMS {
        assert!(l.try_acquire(&format!("vm-{i}"), t0));
    }
    assert!(!l.try_acquire("late", t0 + Duration::from_secs(1)));
    // … until the tracked ones age out of their interval.
    assert!(l.try_acquire("late", t0 + PROGRESS_MIN_INTERVAL));
}

#[tokio::test]
async fn forwards_are_rate_limited_per_vm() {
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = relay(FakeRoutes::one(5, "vm-a", EP_A), g.clone(), None);
    for _ in 0..FORWARD_BURST {
        let (o, _) = exchange(&r, 5, GUARDIAN_NONCE_PATH, b"b").await;
        assert_eq!(o, GuardianRelayOutcome::Forwarded { status: 200 });
    }
    let (o, resp) = exchange(&r, 5, GUARDIAN_NONCE_PATH, b"b").await;
    assert_eq!(
        o,
        GuardianRelayOutcome::Answered {
            class: relay_answer::RATE_LIMITED.1,
            why: "rate"
        }
    );
    assert_eq!(resp.unwrap().status, 429);
    assert_eq!(g.calls().len(), FORWARD_BURST as usize);
    // The recipe path is local and never metered.
    let (o, _) = exchange(&r, 5, GUARDIAN_RECIPE_PATH, b"").await;
    assert_eq!(o, GuardianRelayOutcome::Recipe);
}

#[test]
fn denial_reason_only_reads_a_well_formed_denial() {
    assert_eq!(
        denial_reason(&signed_denial(GuardianDenyReason::Erased)),
        Some(GuardianDenyReason::Erased)
    );
    // A signed RESPONSE has the same outer shape; its body is not a denial.
    let resp_like = encode_canonical(&SignedGuardianDenial {
        body: encode_canonical(&GuardianNonceRequest {
            v: 1,
            vm_id: "vm-a".into(),
        })
        .unwrap(),
        sig: vec![9; 64],
    })
    .unwrap();
    assert_eq!(denial_reason(&resp_like), None);
    // Wrong signature length, garbage, empty.
    let short_sig = encode_canonical(&SignedGuardianDenial {
        body: vec![],
        sig: vec![1; 63],
    })
    .unwrap();
    assert_eq!(denial_reason(&short_sig), None);
    assert_eq!(denial_reason(b"not cbor"), None);
    assert_eq!(denial_reason(&[]), None);
    // A denial body that fails validation (short nonce).
    let bad = GuardianDenial {
        v: 1,
        vm_id: "vm-a".into(),
        nonce: vec![7; 31],
        guest_pub_hash: vec![8; 32],
        reason: GuardianDenyReason::Tcb,
    };
    let bad = encode_canonical(&SignedGuardianDenial {
        body: encode_canonical(&bad).unwrap(),
        sig: vec![9; 64],
    })
    .unwrap();
    assert_eq!(denial_reason(&bad), None);
    let _ = DENY_SIG_DOMAIN;
    let _ = GUARDIAN_STAMP_CONFIRM_PATH;
}

// ---------------------------------------------------------------------
// real lifecycle: CID → current VM → route
// ---------------------------------------------------------------------

fn lifecycle() -> Arc<CvmLifecycle> {
    // A private state root, so no adopt sidecar ever lands in the real
    // `/var/lib/hippius-miner` of the machine running the tests.
    let root = Box::leak(Box::new(tempfile::tempdir().unwrap()))
        .path()
        .to_path_buf();
    lifecycle_at(
        Arc::new(MockLibvirtDriver::new()),
        Arc::new(MockLaunchDigest::fixed([4u8; 48])),
        &root,
    )
}

fn lifecycle_at(
    driver: Arc<MockLibvirtDriver>,
    digest: Arc<MockLaunchDigest>,
    root: &std::path::Path,
) -> Arc<CvmLifecycle> {
    crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
        cbitpos: 51,
        reduced_phys_bits: 1,
    });
    Arc::new(
        CvmLifecycle::new_with_poll(
            driver,
            digest,
            HostResources {
                total_cpus: 64,
                total_memory_mb: 1 << 20,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests()
        .with_state_disk_root(root.to_path_buf()),
    )
}

// ---------------------------------------------------------------------
// re-adoption: a missing route is rebuilt from the LIVE domain
// ---------------------------------------------------------------------

/// How the adopt snapshot is damaged before the "restart".
#[derive(Clone, Copy, Debug)]
enum Snapshot {
    /// Written by an agent that did not know routes (no guardian keys).
    WithoutRoute,
    /// Guardian keys present but the recipe is garbage.
    Damaged,
    /// No snapshot at all: orphan adoption from libvirt alone.
    Missing,
}

fn snapshot_file(root: &std::path::Path, vm: &str) -> std::path::PathBuf {
    root.join("adopt").join(format!("{vm}.json"))
}

fn damage(root: &std::path::Path, vm: &str, how: Snapshot) {
    let path = snapshot_file(root, vm);
    if let Snapshot::Missing = how {
        std::fs::remove_file(&path).unwrap();
        return;
    }
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let obj = v.as_object_mut().unwrap();
    assert!(
        obj.contains_key("guardian_ep"),
        "launch persisted the route"
    );
    match how {
        Snapshot::WithoutRoute => {
            obj.remove("guardian_ep");
            obj.remove("guardian_recipe_cbor_hex");
        }
        Snapshot::Damaged => {
            obj.insert("guardian_recipe_cbor_hex".into(), "00ff".into());
        }
        Snapshot::Missing => unreachable!(),
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
}

#[tokio::test]
async fn a_lost_route_is_rebuilt_from_the_live_domain_on_readoption() {
    for how in [Snapshot::WithoutRoute, Snapshot::Damaged, Snapshot::Missing] {
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let digest = Arc::new(MockLaunchDigest::fixed([4u8; 48]));
        let lc1 = lifecycle_at(driver.clone(), digest.clone(), root.path());
        lc1.launch(order("vm-a", Some(EP_A))).await.unwrap();
        let cid = cid_of(&lc1, "vm-a");
        let launched = lc1.route_for_cid(cid).unwrap().route;
        damage(root.path(), "vm-a", how);

        // "Restart": fresh lifecycle, same libvirt, same state root.
        let lc2 = lifecycle_at(driver.clone(), digest.clone(), root.path());
        assert_eq!(lc2.readopt_running().await.unwrap(), 1, "{how:?}");
        let b = lc2.route_for_cid(cid).unwrap();
        assert_eq!(b.vm_id.as_str(), "vm-a", "{how:?}");
        // The endpoint is the measured token of the LIVE cmdline, and the
        // recipe is recomputed over the live domain's own boot inputs —
        // the same exact cmdline and vCPU count the launch measured.
        assert_eq!(b.route.endpoint, EP_A, "{how:?}");
        assert_eq!(b.route, launched, "{how:?}");

        // And the relay dials it.
        let g = FakeGuardian::answering(Ok((200, vec![])));
        let r = GuardianRelay::new(lc2.clone(), g.clone(), None);
        exchange(&r, cid, GUARDIAN_NONCE_PATH, b"b").await;
        assert_eq!(g.calls()[0].0, EP_A, "{how:?}");
    }
}

#[tokio::test]
async fn a_route_that_cannot_be_rebuilt_is_left_absent_never_invented() {
    for how in [Snapshot::WithoutRoute, Snapshot::Missing] {
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let lc1 = lifecycle_at(
            driver.clone(),
            Arc::new(MockLaunchDigest::fixed([4u8; 48])),
            root.path(),
        );
        lc1.launch(order("vm-a", Some(EP_A))).await.unwrap();
        let cid = cid_of(&lc1, "vm-a");
        damage(root.path(), "vm-a", how);
        // The recipe cannot be recomputed on this "host".
        let lc2 = lifecycle_at(
            driver.clone(),
            Arc::new(MockLaunchDigest::failing()),
            root.path(),
        );
        assert_eq!(lc2.readopt_running().await.unwrap(), 1, "still re-adopted");
        assert_eq!(
            lc2.route_for_cid(cid).unwrap_err(),
            "no-guardian",
            "{how:?}"
        );
    }
}

#[tokio::test]
async fn an_m0_domain_gets_no_route_on_readoption() {
    for how in [Snapshot::Missing] {
        let root = tempfile::tempdir().unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let digest = Arc::new(MockLaunchDigest::fixed([4u8; 48]));
        let lc1 = lifecycle_at(driver.clone(), digest.clone(), root.path());
        lc1.launch(order("vm-m0", None)).await.unwrap();
        let cid = cid_of(&lc1, "vm-m0");
        damage(root.path(), "vm-m0", how);
        let lc2 = lifecycle_at(driver.clone(), digest.clone(), root.path());
        assert_eq!(lc2.readopt_running().await.unwrap(), 1);
        assert_eq!(lc2.route_for_cid(cid).unwrap_err(), "no-guardian");
    }
    // Snapshot intact (no route, M0): same.
    let root = tempfile::tempdir().unwrap();
    let driver = Arc::new(MockLibvirtDriver::new());
    let digest = Arc::new(MockLaunchDigest::fixed([4u8; 48]));
    let lc1 = lifecycle_at(driver.clone(), digest.clone(), root.path());
    lc1.launch(order("vm-m0", None)).await.unwrap();
    let cid = cid_of(&lc1, "vm-m0");
    let lc2 = lifecycle_at(driver.clone(), digest, root.path());
    assert_eq!(lc2.readopt_running().await.unwrap(), 1);
    assert_eq!(lc2.route_for_cid(cid).unwrap_err(), "no-guardian");
}

#[tokio::test]
async fn a_live_cmdline_with_a_forbidden_endpoint_gets_no_route() {
    let root = tempfile::tempdir().unwrap();
    let driver = Arc::new(MockLibvirtDriver::new());
    let digest = Arc::new(MockLaunchDigest::fixed([4u8; 48]));
    // A live domain whose cmdline names a host-local guardian (it could
    // never have launched through this agent; libvirt says it runs).
    let lc1 = lifecycle_at(driver.clone(), digest.clone(), root.path());
    lc1.launch(order("vm-a", Some(EP_A))).await.unwrap();
    let cid = cid_of(&lc1, "vm-a");
    let id = crate::lifecycle::DomainId::new("hippius-tenant-vm-a").unwrap();
    let xml = crate::lifecycle::LibvirtDriver::domain_xml(driver.as_ref(), &id)
        .await
        .unwrap()
        // The cmdline carries the endpoint hex-encoded.
        .replace(&hex::encode(EP_A), &hex::encode("127.0.0.1:9700"));
    driver.seed_domain_xml(id, crate::lifecycle::DomainState::Running, &xml);
    damage(root.path(), "vm-a", Snapshot::Missing);
    let lc2 = lifecycle_at(driver.clone(), digest, root.path());
    assert_eq!(lc2.readopt_running().await.unwrap(), 1);
    assert_eq!(lc2.route_for_cid(cid).unwrap_err(), "no-guardian");
}

fn cose_ticket() -> Vec<u8> {
    use ciborium::value::Value;
    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    let payload = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
        (Value::Text("flavor".into()), Value::Text("medium".into())),
    ]);
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .build(),
        )
        .payload(payload_buf)
        .create_signature(b"", |_| vec![0u8; 64])
        .build()
        .to_vec()
        .unwrap()
}

fn order(vm: &str, ep: Option<&str>) -> LaunchOrder {
    LaunchOrder {
        vm_id: VmId::new(vm).unwrap(),
        ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
        kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
        initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
        cmdline: match ep {
            Some(ep) => cmdline(ep),
            None => "console=hvc0 quiet".into(),
        },
        luks_disk_path: PathBuf::from(format!("/var/lib/hippius-miner/{vm}.img")),
        luks_disk_size_gb: 10,
        data_disk_size_gb: 0,
        rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
        rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
        cpu_count: 2,
        memory_mb: 2048,
        cose_ticket: ByteBuf::from(cose_ticket()),
        require_existing_disks: false,
        guardian_ep: ep.map(String::from),
        net: None,
        on_guest_poweroff: None,
    }
}

fn cid_of(lc: &CvmLifecycle, vm: &str) -> u32 {
    lc.cid_allocator()
        .cid_for_vm(&VmId::new(vm).unwrap())
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn the_lifecycle_routes_a_cid_to_its_current_owners_guardian() {
    let lc = lifecycle();
    lc.launch(order("vm-a", Some(EP_A))).await.unwrap();
    let cid = cid_of(&lc, "vm-a");
    let b = lc.route_for_cid(cid).unwrap();
    let (vm, route) = (b.vm_id, b.route);
    assert_eq!(vm.as_str(), "vm-a");
    assert_eq!(route.endpoint, EP_A);
    // The recipe is the launch's: its measured cmdline and vCPU count.
    assert_eq!(route.recipe.cmdline, cmdline(EP_A));
    assert_eq!(route.recipe.vcpus, 2);
    // Any other CID is nobody's.
    assert_eq!(lc.route_for_cid(cid + 1).unwrap_err(), "unknown-cid");
}

#[tokio::test]
async fn an_m0_vm_has_no_route() {
    let lc = lifecycle();
    lc.launch(order("vm-m0", None)).await.unwrap();
    let cid = cid_of(&lc, "vm-m0");
    assert_eq!(lc.route_for_cid(cid).unwrap_err(), "no-guardian");
}

#[tokio::test]
async fn a_reused_cid_routes_to_the_new_owner_never_the_stale_one() {
    let lc = lifecycle();
    lc.launch(order("vm-a", Some(EP_A))).await.unwrap();
    let cid = cid_of(&lc, "vm-a");
    lc.stop(&VmId::new("vm-a").unwrap(), false).await.unwrap();
    assert!(lc.route_for_cid(cid).is_err(), "stopped ⇒ no route");

    // B takes the freed CID, with ANOTHER guardian.
    lc.launch(order("vm-b", Some(EP_B))).await.unwrap();
    assert_eq!(cid_of(&lc, "vm-b"), cid, "the allocator reuses the CID");
    let b = lc.route_for_cid(cid).unwrap();
    let (vm, route) = (b.vm_id, b.route);
    assert_eq!(vm.as_str(), "vm-b");
    assert_eq!(route.endpoint, EP_B);

    // End to end through the handler: the dial goes to B's guardian.
    let g = FakeGuardian::answering(Ok((200, vec![])));
    let r = GuardianRelay::new(lc.clone(), g.clone(), None);
    exchange(&r, cid, GUARDIAN_NONCE_PATH, b"b").await;
    assert_eq!(g.calls()[0].0, EP_B);

    // And an M0 successor on the same CID gets nothing at all.
    lc.stop(&VmId::new("vm-b").unwrap(), false).await.unwrap();
    lc.launch(order("vm-c", None)).await.unwrap();
    assert_eq!(cid_of(&lc, "vm-c"), cid);
    let (outcome, _) = exchange(&r, cid, GUARDIAN_NONCE_PATH, b"b").await;
    assert_eq!(outcome, GuardianRelayOutcome::Dropped("no-guardian"));
    assert_eq!(g.calls().len(), 1);
}

#[tokio::test]
async fn an_unverified_cid_is_refused() {
    let lc = lifecycle();
    let vm = VmId::new("vm-x").unwrap();
    let alloc = lc.cid_allocator();
    let cid = alloc.allocate(&vm).unwrap(); // pending-create ⇒ unverified
    assert_eq!(lc.route_for_cid(cid).unwrap_err(), "cid-unverified");
}

#[tokio::test]
async fn a_launch_whose_guardian_ep_disagrees_with_the_cmdline_is_refused() {
    let lc = lifecycle();
    let mut o = order("vm-bad", Some(EP_A));
    o.guardian_ep = Some(EP_B.into());
    assert!(matches!(
        lc.launch(o).await,
        Err(crate::error::MinerAgentError::LaunchInput(
            "guardian-ep-mismatch"
        ))
    ));
    let mut o = order("vm-bad", Some(EP_A));
    o.guardian_ep = None;
    assert!(matches!(
        lc.launch(o).await,
        Err(crate::error::MinerAgentError::LaunchInput(
            "guardian-ep-missing"
        ))
    ));
    let mut o = order("vm-bad", None);
    o.guardian_ep = Some(EP_A.into());
    assert!(matches!(
        lc.launch(o).await,
        Err(crate::error::MinerAgentError::LaunchInput(
            "guardian-ep-orphan"
        ))
    ));
    // Nothing was reserved.
    assert_eq!(lc.tracked_count().unwrap(), 0);
}

// ---------------------------------------------------------------------
// the real HTTP dialer against a loopback fake guardian
// ---------------------------------------------------------------------

/// Serve ONE HTTP/1.1 connection with `reply` (raw bytes), after
/// recording the request head. Returns the port.
async fn one_shot_server(reply: Vec<u8>) -> (u16, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        // Read until the body (Content-Length) is in.
        loop {
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let cl = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if body.len() >= cl {
                    break;
                }
            }
        }
        if !reply.is_empty() {
            sock.write_all(&reply).await.unwrap();
            let _ = sock.shutdown().await;
        } else {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        String::from_utf8_lossy(&req).to_string()
    });
    (port, task)
}

fn http(status: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

#[tokio::test]
async fn the_http_dialer_posts_cbor_to_exactly_the_endpoint_and_path() {
    let (port, server) = one_shot_server(http("200 OK", b"answer")).await;
    let d = ReqwestGuardianDialer::for_loopback_tests(Duration::from_secs(5));
    let got = d
        .post(
            &format!("127.0.0.1:{port}"),
            GUARDIAN_NONCE_PATH,
            b"req-bytes",
        )
        .await;
    assert_eq!(got, Ok((200, b"answer".to_vec())));
    let req = server.await.unwrap();
    assert!(
        req.starts_with("POST /v1/guardian/nonce HTTP/1.1\r\n"),
        "{req}"
    );
    assert!(req
        .to_ascii_lowercase()
        .contains("content-type: application/cbor"));
    assert!(req.ends_with("req-bytes"));
}

/// Port 25 is never dialed, even with the host-local test escape on: a
/// listener there would have answered.
#[tokio::test]
async fn the_http_dialer_never_dials_smtp() {
    let d = ReqwestGuardianDialer::for_loopback_tests(Duration::from_secs(5));
    for ep in ["127.0.0.1:25", "guardian.example.com:25"] {
        assert_eq!(
            d.post(ep, GUARDIAN_NONCE_PATH, b"x").await,
            Err(DialError::Unreachable),
            "{ep}"
        );
    }
}

#[tokio::test]
async fn the_http_dialer_refuses_redirects_and_oversize_answers() {
    let (port, _s) = one_shot_server(
        b"HTTP/1.1 307 Temporary Redirect\r\nlocation: http://127.0.0.1:1/\r\ncontent-length: 0\r\n\r\n"
            .to_vec(),
    )
    .await;
    let d = ReqwestGuardianDialer::for_loopback_tests(Duration::from_secs(5));
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Err(DialError::BadResponse)
    );
    // Declared over the cap.
    let big = vec![b'a'; GUARDIAN_MAX_RESPONSE_BYTES + 1];
    let (port, _s) = one_shot_server(http("200 OK", &big)).await;
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Err(DialError::BadResponse)
    );
    // Exactly at the cap is fine.
    let at = vec![b'a'; GUARDIAN_MAX_RESPONSE_BYTES];
    let (port, _s) = one_shot_server(http("200 OK", &at)).await;
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Ok((200, at))
    );
    // Undeclared (close-delimited) and over the cap: the running cap.
    let mut chunked = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec();
    chunked.extend(vec![b'b'; GUARDIAN_MAX_RESPONSE_BYTES + 1]);
    let (port, _s) = one_shot_server(chunked).await;
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Err(DialError::BadResponse)
    );
}

#[tokio::test]
async fn the_http_dialer_classifies_unreachable_and_timeout() {
    let d = ReqwestGuardianDialer::for_loopback_tests(Duration::from_millis(300));
    // Nothing listens: bind + drop to get a free port.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Err(DialError::Unreachable)
    );
    // Accepts, reads, never answers.
    let (port, _s) = one_shot_server(Vec::new()).await;
    assert_eq!(
        d.post(&format!("127.0.0.1:{port}"), GUARDIAN_NONCE_PATH, b"x")
            .await,
        Err(DialError::Timeout)
    );
}

#[test]
fn only_non_local_public_or_cgnat_literals_are_dialable() {
    let host = |s: &str| GuardianEndpoint::parse(s).unwrap().host;
    assert!(dialable_host(&host("100.64.0.10:1")));
    assert!(dialable_host(&host("192.0.2.1:1")));
    assert!(dialable_host(&host("guardian.example.com:1")));
    for bad in [
        "127.0.0.1:1",
        "10.0.0.1:1",
        "192.168.0.1:1",
        "[fd00::1]:1",
        "localhost:1",
    ] {
        assert!(!dialable_host(&host(bad)), "{bad}");
    }
}

#[tokio::test]
async fn a_launch_whose_recipe_fails_reserves_nothing() {
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            Arc::new(MockLibvirtDriver::new()),
            Arc::new(MockLaunchDigest::failing()),
            HostResources {
                total_cpus: 64,
                total_memory_mb: 1 << 20,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests(),
    );
    assert!(lc.launch(order("vm-r", Some(EP_A))).await.is_err());
    assert_eq!(lc.tracked_count().unwrap(), 0);
    assert!(lc
        .cid_allocator()
        .cid_for_vm(&VmId::new("vm-r").unwrap())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn the_resolver_drops_host_local_addresses() {
    use reqwest::dns::Resolve;
    use std::str::FromStr;
    let resolve = |n: &str| AllowedAddrResolver.resolve(reqwest::dns::Name::from_str(n).unwrap());
    // Host-local, and private-but-not-local: both dropped.
    for refused in ["localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254"] {
        assert!(resolve(refused).await.is_err(), "{refused}");
    }
    // An allowed, non-local address survives, unchanged.
    for kept in ["192.0.2.1", "100.64.0.10"] {
        let addrs: Vec<SocketAddr> = match resolve(kept).await {
            Ok(a) => a.collect(),
            Err(e) => panic!("{kept}: {e}"),
        };
        assert_eq!(addrs.len(), 1, "{kept}");
        assert_eq!(addrs[0].ip().to_string(), kept);
    }
}

#[tokio::test]
async fn the_production_dialer_never_dials_a_host_local_endpoint() {
    // A listener that would answer — it must never be reached.
    let (port, server) = one_shot_server(http("200 OK", b"leak")).await;
    let d = ReqwestGuardianDialer::new().unwrap();
    for host in ["127.0.0.1", "localhost"] {
        assert_eq!(
            d.post(&format!("{host}:{port}"), GUARDIAN_NONCE_PATH, b"x")
                .await,
            Err(DialError::Unreachable),
            "{host}"
        );
    }
    assert!(!server.is_finished());
    server.abort();
}
