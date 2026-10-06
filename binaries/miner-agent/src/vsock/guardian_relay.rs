//! Host-side **key-guardian vsock relay** (customer-held keys, design
//! §1.2 / §5.4).
//!
//! A customer-keys (M1/M2) guest asks its customer's key guardian for a
//! share BEFORE it asks the KBS. The initramfs has no usable network, so
//! it dials this relay on `vsock://2:`[`GUARDIAN_VSOCK_PORT`] and the
//! miner-agent POSTs the request to the guardian over the host's network
//! (typically a NetBird address). Same framing as the KBS relay: one
//! length-prefixed CBOR [`KbsProxyRequest`] `{path, body}` in, one
//! [`KbsProxyResponse`] `{status, body}` out, per connection.
//!
//! ## Trust
//!
//! The relay is untrusted and adds no authority: the exchange is
//! authenticated and encrypted end to end at the application layer (SNP
//! report bound to a guardian nonce, share HPKE-sealed to a key in SNP
//! RAM, every guardian decision signed by a key pinned in the measured
//! cmdline). All the relay can do is drop traffic. What it must NOT
//! become is an open HTTP proxy, so:
//!
//! - it dials ONLY the `guardian_ep` of the VM that owns the connecting
//!   CID **now** ([`GuardianRouteSource`], backed by
//!   [`crate::lifecycle::CvmLifecycle::guardian_route_for_cid`]) — a CID
//!   the agent cannot attribute to a current, verified, customer-keys VM
//!   is refused, never routed to a stale owner's guardian (the #1126
//!   CID-reuse lesson);
//! - only the exact paths in [`GUARDIAN_ALLOWED_PATHS`] are forwarded;
//! - bodies are capped both ways, the dial has connect + total timeouts,
//!   redirects are not followed, no proxy env is honoured, and the
//!   destination may not be (or resolve to) a loopback / link-local /
//!   unspecified / multicast / RFC 1918 / ULA address or one of the
//!   miner's own addresses;
//! - each VM is rate limited (a tenant cannot turn miners into an HTTP
//!   request generator aimed at whatever `host:port` it names).
//!
//! ## The relay-local recipe path
//!
//! [`GUARDIAN_RECIPE_PATH`] is answered here, never forwarded: the
//! canonical-CBOR [`hippius_types::guardian::LaunchRecipe`] this CID's
//! VM was launched (and measured) with. Untrusted by design — the
//! guardian recomputes the digest and compares it with the SNP report.
//!
//! ## Progress (display only, fail-open)
//!
//! A failed guardian leg is reported as `awaiting-guardian:<reason>`
//! through the shared [`VmProgressSink`], at most once per
//! [`PROGRESS_MIN_INTERVAL`] per VM: `unreachable` / `timeout` from the
//! dial, `refused:<reason>` when the guardian's answer decodes as a
//! signed denial (the signature is NOT checked — display only),
//! `bad-response` for anything else that is not a success.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hippius_types::guardian::{
    decode_canonical, encode_canonical, is_guardian_allowed_path, relay_answer, GuardianDenial,
    GuardianDenyReason, GuardianEndpoint, GuardianHost, SignedGuardianDenial,
    GUARDIAN_ALLOWED_PATHS, GUARDIAN_MAX_REQUEST_BYTES, GUARDIAN_MAX_RESPONSE_BYTES,
    GUARDIAN_RECIPE_PATH, GUARDIAN_VSOCK_PORT,
};
use hippius_types::kbs_vsock::{KbsProxyRequest, KbsProxyResponse};
use hippius_types::vm_progress::{GuardianWaitReason, VmProgressMilestone};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::kbs_proxy::CustodyRelayGate;
use super::vm_progress::VmProgressSink;
use crate::lifecycle::guardian::{
    endpoint_host_allowed, ip_allowed, is_local_address, RouteBinding,
};
use crate::lifecycle::{CvmLifecycle, VmId};

/// Connect timeout for one guardian dial.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total timeout for one guardian exchange (connect + request + body).
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a guest may take to send its request frame once connected.
pub const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Minimum gap between two `awaiting-guardian` reports for one VM.
pub const PROGRESS_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Most VMs the progress limiter tracks at once.
pub const PROGRESS_MAX_TRACKED_VMS: usize = 1024;
/// Per-VM forward burst. An honest guest sends a nonce + a release per
/// attempt with backoff from 1 s up to 60 s: a dozen covers the first
/// attempts of a boot with room for a stamp confirm.
pub const FORWARD_BURST: u32 = 12;
/// One forward token back per this interval (12 per minute) — above the
/// honest steady state (2 per minute at the 60 s backoff cap).
pub const FORWARD_REFILL_EVERY: Duration = Duration::from_secs(5);

/// The request frame cap: the body cap plus room for the `{path, body}`
/// CBOR envelope around it.
const MAX_REQUEST_FRAME: usize = GUARDIAN_MAX_REQUEST_BYTES + 1024;

/// Resolves a connecting CID to the VM that owns it now and its route.
/// Production: [`CvmLifecycle`]. The `Err` is a static class for the log.
pub trait GuardianRouteSource: Send + Sync {
    fn route_for_cid(&self, cid: u32) -> Result<RouteBinding, &'static str>;
}

impl GuardianRouteSource for CvmLifecycle {
    fn route_for_cid(&self, cid: u32) -> Result<RouteBinding, &'static str> {
        self.guardian_route_for_cid(cid)
    }
}

/// Most guardian connections one VM may hold open at once. An honest
/// guest runs one exchange at a time; the rest is headroom for a retry
/// racing a timed-out attempt. Bounds what one tenant can pin (sockets,
/// permits, outbound dials) no matter how it paces its bytes.
pub const MAX_INFLIGHT_PER_VM: usize = 4;

/// A connection admitted at accept: the CID's binding at that moment,
/// holding one of its VM's [`MAX_INFLIGHT_PER_VM`] slots until dropped.
pub struct Admission {
    binding: RouteBinding,
    _slot: InflightSlot,
}

impl Admission {
    pub fn binding(&self) -> &RouteBinding {
        &self.binding
    }
}

type InflightMap = Arc<Mutex<HashMap<String, usize>>>;

struct InflightSlot {
    map: InflightMap,
    vm_id: String,
}

impl Drop for InflightSlot {
    fn drop(&mut self) {
        if let Ok(mut map) = self.map.lock() {
            if let Some(n) = map.get_mut(&self.vm_id) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&self.vm_id);
                }
            }
        }
    }
}

/// Why a dial produced no guardian answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// Could not connect (refused, no route, no allowed address, DNS).
    Unreachable,
    /// No complete answer within [`EXCHANGE_TIMEOUT`].
    Timeout,
    /// An answer that breaks the relay contract (over the response cap, a
    /// redirect, a transport error mid-body).
    BadResponse,
}

/// POSTs one relayed request to a guardian. A trait so tests inject a
/// fake guardian and the handler stays off the network.
#[async_trait]
pub trait GuardianDialer: Send + Sync {
    /// POST `body` (`application/cbor`) to `http://<endpoint><path>` and
    /// return `(status, body)`. `endpoint` is a canonical `host:port`.
    async fn post(
        &self,
        endpoint: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), DialError>;
}

/// Production [`GuardianDialer`]: plain HTTP/1.1 (the channel is secured
/// end to end above HTTP; the guardian listens on a NetBird address), no
/// redirects, no proxy, bounded timeouts, and a resolver that drops
/// host-local addresses.
pub struct ReqwestGuardianDialer {
    client: reqwest::Client,
    /// Test-only escape from the host-local address refusal, so the
    /// real HTTP path can be exercised against a loopback fake guardian.
    allow_host_local: bool,
}

impl ReqwestGuardianDialer {
    pub fn new() -> Result<Self, crate::error::MinerAgentError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(EXCHANGE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(AllowedAddrResolver))
            .build()
            .map_err(|_| crate::error::MinerAgentError::ConfigInvalid("guardian-relay-client"))?;
        Ok(Self {
            client,
            allow_host_local: false,
        })
    }

    /// The production client shape minus the address filter, with a
    /// short total timeout — for tests against a loopback fake guardian.
    #[cfg(test)]
    fn for_loopback_tests(total: Duration) -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(total)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            client,
            allow_host_local: true,
        }
    }
}

#[async_trait]
impl GuardianDialer for ReqwestGuardianDialer {
    async fn post(
        &self,
        endpoint: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), DialError> {
        // The route was validated at launch / re-adoption; re-check the
        // literal here so no code path can dial a host-local address.
        let ep = GuardianEndpoint::parse(endpoint).map_err(|_| DialError::Unreachable)?;
        if !self.allow_host_local && !dialable_host(&ep.host) {
            return Err(DialError::Unreachable);
        }
        let url = format!("http://{}{}", ep.to_wire(), path);
        let mut resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .map_err(classify)?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(DialError::BadResponse);
        }
        if resp
            .content_length()
            .is_some_and(|n| n > GUARDIAN_MAX_RESPONSE_BYTES as u64)
        {
            return Err(DialError::BadResponse);
        }
        // Stream with a running cap: a hostile guardian cannot make the
        // agent buffer more than the cap, declared length or not.
        let mut out = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            if e.is_timeout() {
                DialError::Timeout
            } else {
                DialError::BadResponse
            }
        })? {
            if out.len() + chunk.len() > GUARDIAN_MAX_RESPONSE_BYTES {
                return Err(DialError::BadResponse);
            }
            out.extend_from_slice(&chunk);
        }
        Ok((status.as_u16(), out))
    }
}

fn classify(e: reqwest::Error) -> DialError {
    if e.is_timeout() {
        DialError::Timeout
    } else {
        DialError::Unreachable
    }
}

/// Whether the dialer may connect to `host`: the static class check
/// ([`endpoint_host_allowed`]) plus, for an IP literal, not one of this
/// host's own addresses. A DNS name is checked per resolved address by
/// [`AllowedAddrResolver`].
fn dialable_host(host: &GuardianHost) -> bool {
    let literal = match host {
        GuardianHost::Ipv4(a) => Some(IpAddr::V4(*a)),
        GuardianHost::Ipv6(a) => Some(IpAddr::V6(*a)),
        GuardianHost::Dns(_) => None,
    };
    endpoint_host_allowed(host) && !literal.is_some_and(is_local_address)
}

/// DNS resolution that keeps only [`ip_allowed`] addresses that are not
/// this host's own: a guardian NAME that resolves (or is rebound) to
/// loopback / link-local / a private range / the miner itself is as
/// unreachable as one that does not resolve at all. reqwest connects to
/// exactly the addresses returned here, so there is no check-then-use gap.
struct AllowedAddrResolver;

impl reqwest::dns::Resolve for AllowedAddrResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| ip_allowed(a.ip()) && !is_local_address(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("guardian-name-has-no-allowed-address".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Once-per-interval gate for `awaiting-guardian` reports, keyed by
/// `vm_id` (never by CID, which is recycled).
pub struct ProgressLimiter {
    last: Mutex<HashMap<String, Instant>>,
}

impl Default for ProgressLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressLimiter {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }

    /// `true` ⇒ report now (and start this VM's quiet interval).
    pub fn try_acquire(&self, vm_id: &str, now: Instant) -> bool {
        let Ok(mut last) = self.last.lock() else {
            return false;
        };
        if let Some(t) = last.get(vm_id) {
            if now.saturating_duration_since(*t) < PROGRESS_MIN_INTERVAL {
                return false;
            }
        } else if last.len() >= PROGRESS_MAX_TRACKED_VMS {
            // An entry past its interval says nothing a fresh one would not.
            last.retain(|_, t| now.saturating_duration_since(*t) < PROGRESS_MIN_INTERVAL);
            if last.len() >= PROGRESS_MAX_TRACKED_VMS {
                return false;
            }
        }
        last.insert(vm_id.to_string(), now);
        true
    }
}

/// Everything one relay connection needs.
pub struct GuardianRelay {
    pub routes: Arc<dyn GuardianRouteSource>,
    pub dialer: Arc<dyn GuardianDialer>,
    /// The shared, fail-open boot-progress sink. `None` ⇒ no reporting.
    pub progress: Option<Arc<dyn VmProgressSink>>,
    pub limiter: ProgressLimiter,
    pub forwards: CustodyRelayGate,
    inflight: InflightMap,
}

impl GuardianRelay {
    pub fn new(
        routes: Arc<dyn GuardianRouteSource>,
        dialer: Arc<dyn GuardianDialer>,
        progress: Option<Arc<dyn VmProgressSink>>,
    ) -> Self {
        Self {
            routes,
            dialer,
            progress,
            limiter: ProgressLimiter::new(),
            forwards: CustodyRelayGate::with_rate(FORWARD_BURST, FORWARD_REFILL_EVERY),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Accept-time gate, BEFORE a single byte is read: the CID must
    /// resolve to a current customer-keys VM ([`GuardianRouteSource`]) and
    /// that VM must have a free in-flight slot. Anything else is dropped
    /// unread, so a CID with no route — or a VM already holding
    /// [`MAX_INFLIGHT_PER_VM`] connections — cannot park sockets on the
    /// relay (slowloris).
    pub fn admit(&self, src_cid: u32) -> Result<Admission, &'static str> {
        let binding = self.routes.route_for_cid(src_cid)?;
        let key = binding.vm_id.as_str().to_string();
        let mut map = self.inflight.lock().map_err(|_| "inflight-lock")?;
        let n = map.entry(key.clone()).or_insert(0);
        if *n >= MAX_INFLIGHT_PER_VM {
            return Err("vm-inflight-cap");
        }
        *n += 1;
        Ok(Admission {
            binding,
            _slot: InflightSlot {
                map: Arc::clone(&self.inflight),
                vm_id: key,
            },
        })
    }

    /// Fire-and-forget `awaiting-guardian:<reason>` for `vm_id`, rate
    /// limited. Never blocks or fails the relayed exchange.
    fn report_waiting(&self, vm_id: &VmId, reason: GuardianWaitReason) {
        let Some(sink) = self.progress.as_ref() else {
            return;
        };
        if !self.limiter.try_acquire(vm_id.as_str(), Instant::now()) {
            return;
        }
        let sink = Arc::clone(sink);
        let vm_id = vm_id.as_str().to_string();
        tokio::spawn(async move {
            sink.report(&vm_id, VmProgressMilestone::AwaitingGuardian(reason))
                .await;
        });
    }
}

/// Outcome of one relay connection — static classes only (no request or
/// response bytes, no endpoint) for the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardianRelayOutcome {
    /// Forwarded; the guardian's HTTP status.
    Forwarded { status: u16 },
    /// Answered the relay-local recipe path.
    Recipe,
    /// Answered locally with a [`relay_answer`] class; `why` is the
    /// finer-grained reason for the log.
    Answered {
        class: &'static str,
        why: &'static str,
    },
    /// Dropped without an answer.
    Dropped(&'static str),
}

/// The signed denial's reason, if `body` decodes as one. Display only:
/// the signature is not verified (the relay has no business trusting or
/// distrusting it — the guest does that).
pub fn denial_reason(body: &[u8]) -> Option<GuardianDenyReason> {
    let signed: SignedGuardianDenial = decode_canonical(body).ok()?;
    signed.validate().ok()?;
    let denial: GuardianDenial = decode_canonical(&signed.body).ok()?;
    denial.validate().ok()?;
    Some(denial.reason)
}

/// Drive one guardian-relay connection from `src_cid`. Generic over the
/// stream so tests run it on a `tokio::io::duplex`.
/// [`GuardianRelay::admit`] then [`handle_guardian_conn`]; a refused
/// admission drops the connection unread.
pub async fn serve_guardian_conn<S>(
    stream: S,
    relay: &GuardianRelay,
    src_cid: u32,
) -> GuardianRelayOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match relay.admit(src_cid) {
        Ok(admission) => handle_guardian_conn(stream, relay, src_cid, admission).await,
        Err(why) => GuardianRelayOutcome::Dropped(why),
    }
}

/// Drive one ADMITTED connection. The admission's slot is held until
/// this returns.
pub async fn handle_guardian_conn<S>(
    mut stream: S,
    relay: &GuardianRelay,
    src_cid: u32,
    admission: Admission,
) -> GuardianRelayOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = match tokio::time::timeout(
        REQUEST_READ_TIMEOUT,
        read_framed(&mut stream, MAX_REQUEST_FRAME),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(class)) => return GuardianRelayOutcome::Dropped(class),
        Err(_) => return GuardianRelayOutcome::Dropped("read-timeout"),
    };
    let req: KbsProxyRequest = match ciborium::de::from_reader(&frame[..]) {
        Ok(r) => r,
        Err(_) => return GuardianRelayOutcome::Dropped("decode"),
    };
    let is_recipe = req.path == GUARDIAN_RECIPE_PATH;
    if !is_recipe && !is_guardian_allowed_path(&req.path) {
        return answer(&mut stream, relay_answer::PATH_FORBIDDEN, "path").await;
    }
    if req.body.len() > GUARDIAN_MAX_REQUEST_BYTES {
        return answer(&mut stream, relay_answer::REQUEST_TOO_LARGE, "body").await;
    }
    // Re-resolved AFTER the request is read — as close to the dial as
    // possible — and required to be the SAME VM on the SAME domain
    // incarnation that was admitted: a CID whose owner changed while the
    // guest was sending is refused, never routed to the new owner's
    // guardian with the old guest's bytes.
    let now = match relay.routes.route_for_cid(src_cid) {
        Ok(b) => b,
        Err(why) => return answer(&mut stream, relay_answer::NO_GUARDIAN, why).await,
    };
    let pinned = admission.binding();
    if now.vm_id != pinned.vm_id || now.domain != pinned.domain {
        return answer(&mut stream, relay_answer::NO_GUARDIAN, "cid-owner-changed").await;
    }
    let RouteBinding { vm_id, route, .. } = now;
    if is_recipe {
        return match encode_canonical(&route.recipe) {
            Ok(cbor) => match write_response(&mut stream, 200, cbor).await {
                Ok(()) => GuardianRelayOutcome::Recipe,
                Err(class) => GuardianRelayOutcome::Dropped(class),
            },
            Err(_) => answer(&mut stream, relay_answer::NO_RECIPE, "encode").await,
        };
    }
    if !relay.forwards.try_acquire(vm_id.as_str(), Instant::now()) {
        return answer(&mut stream, relay_answer::RATE_LIMITED, "rate").await;
    }
    let (status, body) = match relay
        .dialer
        .post(&route.endpoint, &req.path, &req.body)
        .await
    {
        Ok(pair) => pair,
        Err(err) => {
            let (reason, ans) = match err {
                DialError::Unreachable => {
                    (GuardianWaitReason::Unreachable, relay_answer::UNREACHABLE)
                }
                DialError::Timeout => (GuardianWaitReason::Timeout, relay_answer::TIMEOUT),
                DialError::BadResponse => {
                    (GuardianWaitReason::BadResponse, relay_answer::BAD_RESPONSE)
                }
            };
            relay.report_waiting(&vm_id, reason);
            return answer(&mut stream, ans, "dial").await;
        }
    };
    if let Some(reason) = denial_reason(&body) {
        relay.report_waiting(&vm_id, GuardianWaitReason::Refused(reason));
    } else if !(200..300).contains(&status) {
        relay.report_waiting(&vm_id, GuardianWaitReason::BadResponse);
    }
    match write_response(&mut stream, status, body).await {
        Ok(()) => GuardianRelayOutcome::Forwarded { status },
        Err(class) => GuardianRelayOutcome::Dropped(class),
    }
}

async fn answer<S>(
    stream: &mut S,
    (status, class): (u16, &'static str),
    why: &'static str,
) -> GuardianRelayOutcome
where
    S: AsyncWrite + Unpin,
{
    match write_response(stream, status, class.as_bytes().to_vec()).await {
        Ok(()) => GuardianRelayOutcome::Answered { class, why },
        Err(c) => GuardianRelayOutcome::Dropped(c),
    }
}

async fn write_response<S>(stream: &mut S, status: u16, body: Vec<u8>) -> Result<(), &'static str>
where
    S: AsyncWrite + Unpin,
{
    let resp = KbsProxyResponse {
        status,
        body: ByteBuf::from(body),
    };
    let mut frame = Vec::new();
    ciborium::ser::into_writer(&resp, &mut frame).map_err(|_| "encode")?;
    let len = u32::try_from(frame.len()).map_err(|_| "oversize")?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|_| "write-length")?;
    stream.write_all(&frame).await.map_err(|_| "write-body")?;
    stream.flush().await.map_err(|_| "flush")?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_framed<R>(reader: &mut R, max: usize) -> Result<Vec<u8>, &'static str>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| "read-length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max {
        return Err("length");
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| "read-body")?;
    Ok(body)
}

fn log_outcome(cid: u32, outcome: &GuardianRelayOutcome) {
    match outcome {
        GuardianRelayOutcome::Forwarded { status } => {
            eprintln!("hippius-miner-agent: guardian-relay: cid={cid} forwarded status={status}");
        }
        GuardianRelayOutcome::Recipe => {
            eprintln!("hippius-miner-agent: guardian-relay: cid={cid} recipe");
        }
        GuardianRelayOutcome::Answered { class, why } => {
            eprintln!("hippius-miner-agent: guardian-relay: cid={cid} answered {class} ({why})");
        }
        GuardianRelayOutcome::Dropped(class) => {
            eprintln!("hippius-miner-agent: guardian-relay: cid={cid} dropped {class}");
        }
    }
}

/// Every path the relay acts on — for the startup log line.
fn paths_line() -> String {
    let mut all: Vec<&str> = GUARDIAN_ALLOWED_PATHS.to_vec();
    all.push(GUARDIAN_RECIPE_PATH);
    all.join(",")
}

/// Bind the guardian-relay vsock port and serve until cancelled. Mirrors
/// [`super::kbs_proxy::run_kbs_proxy_listener`] (concurrency cap,
/// transient-accept backoff, drain on shutdown). Every connection passes
/// [`GuardianRelay::admit`] BEFORE it is read, and
/// [`handle_guardian_conn`] re-resolves the owner after the read.
#[cfg(target_os = "linux")]
pub async fn run_guardian_relay_listener(
    relay: Arc<GuardianRelay>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use tokio::task::JoinSet;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(VMADDR_CID_ANY, GUARDIAN_VSOCK_PORT);
    let listener = match VsockListener::bind(addr) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("hippius-miner-agent: guardian-relay: bind-error");
            return;
        }
    };
    eprintln!(
        "hippius-miner-agent: guardian-relay: up paths={}",
        paths_line()
    );

    let permits = Arc::new(tokio::sync::Semaphore::new(super::MAX_INFLIGHT_GUEST_CONNS));
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                eprintln!("hippius-miner-agent: guardian-relay: shutdown");
                break;
            }
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let src_cid = addr.cid();
                let admission = match relay.admit(src_cid) {
                    Ok(a) => a,
                    Err(why) => {
                        log_outcome(src_cid, &GuardianRelayOutcome::Dropped(why));
                        drop(stream);
                        continue;
                    }
                };
                let relay = Arc::clone(&relay);
                conns.spawn(async move {
                    let _permit = permit;
                    let outcome =
                        handle_guardian_conn(stream, relay.as_ref(), src_cid, admission).await;
                    log_outcome(src_cid, &outcome);
                });
            }
        }
        while conns.try_join_next().is_some() {}
    }
    conns.shutdown().await;
}

#[cfg(test)]
mod tests;
