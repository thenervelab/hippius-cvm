//! Host-side **KBS-over-vsock proxy** — the miner-agent forwards a
//! tenant guest's §21 release exchange to the real KBS over the host's
//! network, so the guest needs zero network access of its own.
//!
//! The tenant CVM has no route to the in-cluster KBS (a mesh-only
//! cluster address);
//! routing its traffic through the host's NetBird mesh is fragile (it
//! broke when the mesh routing drifted). Instead the guest dials this
//! proxy on `vsock://2:`[`hippius_types::kbs_vsock::PORT`]; the agent
//! POSTs the two allowed KBS paths over its OWN network — which DOES
//! reach the KBS — and relays the responses. The §102 "kata can't
//! reach VIPs → relay" pattern.
//!
//! ## Trust
//!
//! - The connection's **source CID** is checked against the
//!   [`CidAllocator`]: only a CID the agent assigned to a live tenant
//!   CVM is served. A stray CID is dropped (same gate as the relay).
//! - Only [`hippius_types::kbs_vsock::ALLOWED_PATHS`] are forwarded —
//!   the proxy can never be coerced into an arbitrary-URL SSRF.
//! - The agent adds NO authority of its own: the request body is the
//!   guest's signed COSE ticket + SNP report; the KBS attests it. The
//!   agent is an opaque relay (it cannot forge a release).
//!
//! ## Two destinations — KBS and vali (§25 source-ack)
//!
//! The same proxy carries two flows, routed by the request path
//! ([`hippius_types::kbs_vsock::is_lifecycle_path`]):
//!
//! - the §21 KBS release exchange ([`KbsBackend`] → the KBS), and
//! - the §24/§25 guest stopped-ack push ([`KbsBackend`] → vali's
//!   `/v1/lifecycle/stopped` ingress; the body is the OPAQUE
//!   `SignedStoppedAck` and the `?vm_id=&generation=` query rides in the
//!   forwarded path). The miner NEVER decodes or alters the ack — vali's
//!   verifier owns the signature/generation check (§5.6 opacity; the
//!   split-brain fence stays vali-side).
//!
//! Each destination is a separate [`KbsBackend`] so an absent `[lifecycle]`
//! config simply means the stopped-ack path is refused (`no-vali-backend`)
//! — never an SSRF into an unconfigured host.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hippius_types::kbs_vsock::{
    is_allowed_path, is_lifecycle_path, KbsProxyRequest, KbsProxyResponse, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::peer::CidAllocator;
use super::vm_progress::VmProgressSink;

/// An HTTP backend the proxy forwards a guest request to (the KBS, or
/// vali's lifecycle ingress). A trait so tests inject a stub and the
/// listener stays off the network.
#[async_trait]
pub trait KbsBackend: Send + Sync {
    /// POST `body` (`application/cbor`) to `<base><path>` and return
    /// `(status, response_body)`. `path` carries any `?query` verbatim.
    /// `Err(())` is a transport failure (the proxy then drops the
    /// connection; the guest retries).
    async fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ()>;
}

/// The destination backends the proxy routes between by request path:
/// the §21 KBS exchange to `kbs`, the §24/§25 stopped-ack push to `vali`
/// (when configured). Each is an opaque forwarder — neither decodes the
/// guest body (§5.6).
pub struct ProxyBackends {
    /// The KBS backend — the two §21 release paths route here.
    pub kbs: Arc<dyn KbsBackend>,
    /// The vali lifecycle-ingress backend — `/v1/lifecycle/stopped`
    /// routes here. `None` when no `[lifecycle]` config is present: the
    /// stopped-ack path is then REFUSED (`no-vali-backend`), never
    /// silently dropped or mis-routed to the KBS.
    pub vali: Option<Arc<dyn KbsBackend>>,
    /// Optional display-only guest-boot progress sink. When present, a
    /// SUCCESSFUL (`status=200`) KBS-release forward fires a fire-and-
    /// forget `kek-released` milestone for the source CID's vm_id. Fail-
    /// open: absent ⇒ no reporting; a send error never affects the
    /// release exchange (see [`super::vm_progress`]).
    pub progress: Option<Arc<dyn VmProgressSink>>,
}

/// Production [`KbsBackend`] — a `reqwest` client with built-in roots
/// (both the KBS and vali serve a public / mesh-reachable cert). Used
/// for BOTH destinations (each constructed with its own base URL).
/// Distinct from the Edge heartbeat client, which pins a private CA.
pub struct ReqwestKbsBackend {
    base_url: String,
    client: reqwest::Client,
}

impl ReqwestKbsBackend {
    /// Build the backend for `base_url` (e.g. `https://kbs.hippius.network`
    /// or the vali lifecycle ingress base). `field` names the config key
    /// for the error class.
    pub fn new(base_url: String) -> Result<Self, crate::error::MinerAgentError> {
        Self::new_for(base_url, "kbs.endpoint")
    }

    /// Build the backend for `base_url`, attributing a build error to the
    /// config `field` (so a vali-backend misconfig surfaces distinctly
    /// from a KBS one).
    pub fn new_for(
        base_url: String,
        field: &'static str,
    ) -> Result<Self, crate::error::MinerAgentError> {
        Self::build(base_url, field, None)
    }

    /// Build the backend for `base_url`, adding the PEM CA bundle at
    /// `ca_path` to the trust roots (KEEPING the webpki built-in roots).
    ///
    /// Used for the §24/§25 stopped-ack hop when `vali_url` points at the
    /// Edge's stopped-ack relay, which serves the Edge's OWN server cert
    /// (issued by the private hippius-compute CA, not a public Let's
    /// Encrypt cert). The Edge cert carries the Edge LoadBalancer's mesh
    /// address as an `IP:` SAN,
    /// so dialing the LB IP directly validates against it once this CA is
    /// trusted — no public DNS / public cert needed for the internal mesh
    /// hop. `field` attributes a load / build error.
    pub fn new_with_ca(
        base_url: String,
        ca_path: &std::path::Path,
        field: &'static str,
    ) -> Result<Self, crate::error::MinerAgentError> {
        let pem = std::fs::read(ca_path)
            .map_err(|_| crate::error::MinerAgentError::ConfigInvalid(field))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|_| crate::error::MinerAgentError::ConfigInvalid(field))?;
        Self::build(base_url, field, Some(cert))
    }

    /// Shared builder — `extra_ca` (when present) is added to the roots
    /// on top of the webpki built-ins. `redirect: none`, bounded
    /// timeouts, rustls.
    fn build(
        base_url: String,
        field: &'static str,
        extra_ca: Option<reqwest::Certificate>,
    ) -> Result<Self, crate::error::MinerAgentError> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca) = extra_ca {
            builder = builder.add_root_certificate(ca);
        }
        let client = builder
            .build()
            .map_err(|_| crate::error::MinerAgentError::ConfigInvalid(field))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait]
impl KbsBackend for ReqwestKbsBackend {
    async fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ()> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| ())?;
        let status = resp.status().as_u16();
        // Bound the response before reading (a hostile/misbehaving
        // backend cannot OOM the agent).
        let bytes = resp.bytes().await.map_err(|_| ())?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(());
        }
        Ok((status, bytes.to_vec()))
    }
}

/// Drive one proxy connection: read the framed request, gate the path,
/// route it to the KBS or the vali lifecycle backend, write the framed
/// response. Generic over the stream so tests run it on a
/// `tokio::io::duplex` without a real VsockStream. `src_cid` must already
/// be validated by the caller.
pub async fn handle_kbs_proxy_conn<S>(
    mut stream: S,
    backends: &ProxyBackends,
    vm_id: Option<&str>,
) -> KbsProxyOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = match read_framed(&mut stream, MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(class) => return KbsProxyOutcome::Refused(class),
    };
    let req: KbsProxyRequest = match ciborium::de::from_reader(&req[..]) {
        Ok(r) => r,
        Err(_) => return KbsProxyOutcome::Refused("decode"),
    };
    if !is_allowed_path(&req.path) {
        return KbsProxyOutcome::Refused("path-forbidden");
    }
    // Route by path: the stopped-ack ingress goes to vali, everything
    // else (the KBS paths) to the KBS. The miner NEVER decodes the body
    // either way (§5.6) — it forwards opaque bytes + the verbatim query.
    let backend: &dyn KbsBackend = if is_lifecycle_path(&req.path) {
        match backends.vali.as_deref() {
            Some(b) => b,
            // No `[lifecycle]` config ⇒ the stopped-ack path is refused
            // rather than mis-routed. Fail-closed: the migration just
            // times out vali-side (never advances on a dropped ack).
            None => return KbsProxyOutcome::Refused("no-vali-backend"),
        }
    } else {
        backends.kbs.as_ref()
    };
    // Recognise the §21 KEK-release endpoint SPECIFICALLY (not the nonce
    // pre-flight, which also 200s) so only the actual key release fires a
    // milestone.
    let is_kbs_release = {
        let (component, _query) = hippius_types::kbs_vsock::split_query(&req.path);
        component == hippius_types::kbs_vsock::KBS_RELEASE_PATH
    };
    let (status, body) = match backend.post(&req.path, &req.body).await {
        Ok(pair) => pair,
        Err(()) => return KbsProxyOutcome::Refused("kbs-transport"),
    };
    // Display-only, fail-open, NON-blocking boot-progress side-channel:
    // a SUCCESSFUL KBS-release forward (`status=200` on the §21 release
    // path) means the KBS just released the LUKS KEK to this attested
    // guest. Fire a fire-and-forget `kek-released` milestone for the
    // guest's vm_id. Spawned detached so it can NEVER delay (or fail) the
    // release exchange — the guest's response is written below regardless.
    // Absent sink / vm_id ⇒ no-op.
    if is_kbs_release && status == 200 {
        if let (Some(sink), Some(vm_id)) = (backends.progress.as_ref(), vm_id) {
            let sink = Arc::clone(sink);
            let vm_id = vm_id.to_string();
            tokio::spawn(async move {
                sink.report(
                    &vm_id,
                    hippius_types::vm_progress::VmProgressMilestone::KekReleased,
                )
                .await;
            });
        }
    }
    let resp = KbsProxyResponse {
        status,
        body: ByteBuf::from(body),
    };
    let mut frame = Vec::new();
    if ciborium::ser::into_writer(&resp, &mut frame).is_err() {
        return KbsProxyOutcome::Refused("encode");
    }
    if write_framed(&mut stream, &frame).await.is_err() {
        return KbsProxyOutcome::Refused("write");
    }
    let _ = stream.shutdown().await;
    KbsProxyOutcome::Forwarded { status }
}

/// Outcome of one proxied connection — a static classifier for the log
/// line (never echoes request bytes, §K).
#[derive(Debug, PartialEq, Eq)]
pub enum KbsProxyOutcome {
    /// Forwarded to the KBS; carries the KBS HTTP status.
    Forwarded { status: u16 },
    /// Dropped before/at forward; carries a static class.
    Refused(&'static str),
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

async fn write_framed<W>(writer: &mut W, body: &[u8]) -> Result<(), &'static str>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(body.len()).map_err(|_| "oversize")?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|_| "write-length")?;
    writer.write_all(body).await.map_err(|_| "write-body")?;
    writer.flush().await.map_err(|_| "flush")?;
    Ok(())
}

fn log_proxy(cid: u32, outcome: &KbsProxyOutcome) {
    match outcome {
        KbsProxyOutcome::Forwarded { status } => {
            eprintln!("hippius-miner-agent: kbs-proxy: cid={cid} forwarded status={status}");
        }
        KbsProxyOutcome::Refused(class) => {
            eprintln!("hippius-miner-agent: kbs-proxy: cid={cid} refused {class}");
        }
    }
}

/// Bind the KBS-proxy vsock port and serve guest connections until
/// cancelled. Mirrors [`super::run_vsock_listener`] (concurrency cap,
/// CID gate, transient-accept backoff).
#[cfg(target_os = "linux")]
pub async fn run_kbs_proxy_listener(
    allocator: Arc<CidAllocator>,
    backends: Arc<ProxyBackends>,
    cancel: tokio_util::sync::CancellationToken,
) {
    use tokio::task::JoinSet;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(VMADDR_CID_ANY, hippius_types::kbs_vsock::PORT);
    let listener = match VsockListener::bind(addr) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("hippius-miner-agent: kbs-proxy: bind-error");
            return;
        }
    };
    eprintln!("hippius-miner-agent: kbs-proxy: up");

    let permits = Arc::new(tokio::sync::Semaphore::new(super::MAX_INFLIGHT_GUEST_CONNS));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                eprintln!("hippius-miner-agent: kbs-proxy: shutdown");
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
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(stream); continue; }
                };
                let src_cid = addr.cid();
                // Only a CID the agent assigned to a live tenant CVM.
                // Capture the resolved vm_id so a successful KBS release
                // can be attributed to it in the boot-progress side-channel.
                let vm_id = match allocator.vm_id_for_cid(src_cid) {
                    Ok(Some(vm_id)) => vm_id,
                    _ => {
                        log_proxy(src_cid, &KbsProxyOutcome::Refused("unknown-cid"));
                        drop(stream);
                        continue;
                    }
                };
                let backends = Arc::clone(&backends);
                conns.spawn(async move {
                    let _permit = permit;
                    let outcome =
                        handle_kbs_proxy_conn(stream, backends.as_ref(), Some(vm_id.as_str())).await;
                    log_proxy(src_cid, &outcome);
                });
            }
        }
        while conns.try_join_next().is_some() {}
    }
    conns.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A backend that records the `(path, body)` it was POSTed and returns
    /// a fixed `(status, body)`. The recorded path lets a test assert the
    /// `?vm_id=&generation=` query was forwarded verbatim (opacity: the
    /// proxy never parses it).
    struct StubBackend {
        status: u16,
        body: Vec<u8>,
        seen: Mutex<Option<(String, Vec<u8>)>>,
    }

    impl StubBackend {
        fn new(status: u16, body: Vec<u8>) -> Self {
            Self {
                status,
                body,
                seen: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl KbsBackend for StubBackend {
        async fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ()> {
            assert!(is_allowed_path(path));
            *self.seen.lock().unwrap() = Some((path.to_string(), body.to_vec()));
            Ok((self.status, self.body.clone()))
        }
    }

    /// A backend that PANICS if called — proves a routing/gate decision
    /// fired BEFORE any forward (no SSRF, no mis-route).
    struct PanicBackend;
    #[async_trait]
    impl KbsBackend for PanicBackend {
        async fn post(&self, _p: &str, _b: &[u8]) -> Result<(u16, Vec<u8>), ()> {
            panic!("backend must not be called");
        }
    }

    /// `ProxyBackends` with `kbs` set and `vali` absent (no `[lifecycle]`).
    fn kbs_only(kbs: Arc<dyn KbsBackend>) -> ProxyBackends {
        ProxyBackends {
            kbs,
            vali: None,
            progress: None,
        }
    }

    /// `ProxyBackends` with BOTH backends wired.
    fn both(kbs: Arc<dyn KbsBackend>, vali: Arc<dyn KbsBackend>) -> ProxyBackends {
        ProxyBackends {
            kbs,
            vali: Some(vali),
            progress: None,
        }
    }

    /// `ProxyBackends` with a KBS backend + a recording progress sink —
    /// drives the boot-progress emit assertions.
    fn kbs_with_progress(
        kbs: Arc<dyn KbsBackend>,
        progress: Arc<dyn VmProgressSink>,
    ) -> ProxyBackends {
        ProxyBackends {
            kbs,
            vali: None,
            progress: Some(progress),
        }
    }

    fn framed(req: &KbsProxyRequest) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(req, &mut cbor).unwrap();
        let mut wire = (cbor.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&cbor);
        wire
    }

    /// Run one connection: write `req`, return `(outcome, response)`.
    /// No vm_id ⇒ the boot-progress side-channel is a no-op (the existing
    /// routing/gate tests don't exercise it).
    async fn exchange(
        req: &KbsProxyRequest,
        backends: ProxyBackends,
    ) -> (KbsProxyOutcome, Option<KbsProxyResponse>) {
        exchange_with_vm(req, backends, None).await
    }

    /// Like [`exchange`] but attributes the connection to `vm_id` — drives
    /// the boot-progress emit path.
    async fn exchange_with_vm(
        req: &KbsProxyRequest,
        backends: ProxyBackends,
        vm_id: Option<&str>,
    ) -> (KbsProxyOutcome, Option<KbsProxyResponse>) {
        let (mut client, server) = tokio::io::duplex(8192);
        let wire = framed(req);
        let vm_id = vm_id.map(str::to_string);
        let srv = tokio::spawn(async move {
            handle_kbs_proxy_conn(server, &backends, vm_id.as_deref()).await
        });
        client.write_all(&wire).await.unwrap();
        client.shutdown().await.unwrap();
        let mut len_buf = [0u8; 4];
        let resp = match client.read_exact(&mut len_buf).await {
            Ok(_) => {
                let mut body = vec![0u8; u32::from_be_bytes(len_buf) as usize];
                client.read_exact(&mut body).await.unwrap();
                Some(ciborium::de::from_reader::<KbsProxyResponse, _>(&body[..]).unwrap())
            }
            // A refused connection writes no framed response (the server
            // returned before the write) — EOF here is expected.
            Err(_) => None,
        };
        (srv.await.unwrap(), resp)
    }

    #[tokio::test]
    async fn forwards_kbs_path_to_the_kbs_backend() {
        let kbs = Arc::new(StubBackend::new(200, vec![7u8; 48]));
        let req = KbsProxyRequest {
            path: "/v1/kbs/release".to_string(),
            body: ByteBuf::from(vec![1u8, 2, 3]),
        };
        let (outcome, resp) = exchange(&req, both(kbs.clone(), Arc::new(PanicBackend))).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 200 });
        let resp = resp.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.into_vec(), vec![7u8; 48]);
        // The KBS backend saw the release path — NOT the vali (panic) one.
        assert_eq!(
            kbs.seen.lock().unwrap().as_ref().unwrap().0,
            "/v1/kbs/release"
        );
    }

    #[tokio::test]
    async fn refuses_forbidden_path_without_calling_either_backend() {
        let req = KbsProxyRequest {
            path: "/v1/admin/allowlist/reload".to_string(),
            body: ByteBuf::from(vec![]),
        };
        // Both backends panic if touched — the SSRF gate fires first.
        let (outcome, _) =
            exchange(&req, both(Arc::new(PanicBackend), Arc::new(PanicBackend))).await;
        assert_eq!(outcome, KbsProxyOutcome::Refused("path-forbidden"));
    }

    #[tokio::test]
    async fn relays_a_403_denial_verbatim() {
        let kbs = Arc::new(StubBackend::new(403, vec![]));
        let req = KbsProxyRequest {
            path: "/v1/kbs/release".to_string(),
            body: ByteBuf::from(vec![9u8]),
        };
        let (outcome, resp) = exchange(&req, kbs_only(kbs)).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 403 });
        assert_eq!(resp.unwrap().status, 403);
    }

    // ── §25 stopped-ack routing ─────────────────────────────────────

    #[tokio::test]
    async fn routes_the_stopped_ack_to_vali_with_the_query_and_body_verbatim() {
        // The KBS backend PANICS if touched — proves the lifecycle path
        // routes to vali, NOT the KBS. The opaque ack bytes + the
        // `?vm_id=&generation=` query must reach the vali backend exactly
        // (the relay never decodes or rewrites them — §5.6).
        let vali = Arc::new(StubBackend::new(202, vec![]));
        let ack_bytes = vec![0xABu8; 96];
        let req = KbsProxyRequest {
            path: "/v1/lifecycle/stopped?vm_id=mig-e2e-1&generation=3".to_string(),
            body: ByteBuf::from(ack_bytes.clone()),
        };
        let (outcome, resp) = exchange(&req, both(Arc::new(PanicBackend), vali.clone())).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 202 });
        assert_eq!(resp.unwrap().status, 202);
        let seen = vali.seen.lock().unwrap();
        let (path, body) = seen.as_ref().unwrap();
        // The query rode through verbatim — vali keys (vm_id, generation).
        assert_eq!(path, "/v1/lifecycle/stopped?vm_id=mig-e2e-1&generation=3");
        // The OPAQUE ack body is byte-identical (no decode, no mutation).
        assert_eq!(body, &ack_bytes);
    }

    // ── boot-progress side-channel (kek-released) ───────────────────

    use super::super::vm_progress::VmProgressSink;
    use hippius_types::vm_progress::VmProgressMilestone;
    use std::sync::Mutex as StdMutex;

    /// A recording progress sink for the emit assertions.
    struct SpySink {
        seen: StdMutex<Vec<(String, VmProgressMilestone)>>,
    }
    impl SpySink {
        fn new() -> Self {
            Self {
                seen: StdMutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<(String, VmProgressMilestone)> {
            self.seen.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl VmProgressSink for SpySink {
        async fn report(&self, vm_id: &str, milestone: VmProgressMilestone) {
            self.seen
                .lock()
                .unwrap()
                .push((vm_id.to_string(), milestone));
        }
    }

    /// Give the detached fire-and-forget emit task a moment to run.
    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn a_successful_kbs_release_emits_kek_released_for_the_vm() {
        let kbs = Arc::new(StubBackend::new(200, vec![7u8; 48]));
        let sink = Arc::new(SpySink::new());
        let req = KbsProxyRequest {
            path: "/v1/kbs/release".to_string(),
            body: ByteBuf::from(vec![1u8, 2, 3]),
        };
        let (outcome, _resp) = exchange_with_vm(
            &req,
            kbs_with_progress(kbs, sink.clone()),
            Some("vm-boot-1"),
        )
        .await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 200 });
        settle().await;
        let seen = sink.seen();
        assert_eq!(seen.len(), 1, "one kek-released report for the release");
        assert_eq!(seen[0].0, "vm-boot-1");
        assert_eq!(seen[0].1, VmProgressMilestone::KekReleased);
    }

    #[tokio::test]
    async fn a_403_kbs_denial_emits_no_progress() {
        // A denial is NOT a release — the guest never got the KEK, so no
        // `kek-released` milestone fires.
        let kbs = Arc::new(StubBackend::new(403, vec![]));
        let sink = Arc::new(SpySink::new());
        let req = KbsProxyRequest {
            path: "/v1/kbs/release".to_string(),
            body: ByteBuf::from(vec![9u8]),
        };
        let (outcome, _) =
            exchange_with_vm(&req, kbs_with_progress(kbs, sink.clone()), Some("vm-x")).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 403 });
        settle().await;
        assert!(sink.seen().is_empty(), "a denial must not emit progress");
    }

    #[tokio::test]
    async fn a_kbs_nonce_fetch_emits_no_progress() {
        // Only the RELEASE 200 is the kek-released signal; the nonce
        // pre-flight (also a 200 to the KBS) must NOT emit.
        let kbs = Arc::new(StubBackend::new(200, vec![0u8; 32]));
        let sink = Arc::new(SpySink::new());
        let req = KbsProxyRequest {
            path: "/v1/kbs/nonce".to_string(),
            body: ByteBuf::from(vec![1u8]),
        };
        let (outcome, _) =
            exchange_with_vm(&req, kbs_with_progress(kbs, sink.clone()), Some("vm-n")).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 200 });
        settle().await;
        // The nonce path is not the release path — but note both are
        // non-lifecycle KBS paths. We only want the RELEASE to emit.
        assert!(
            sink.seen().is_empty(),
            "the nonce pre-flight must not emit kek-released"
        );
    }

    #[tokio::test]
    async fn a_stopped_ack_forward_emits_no_progress() {
        // The lifecycle stopped-ack path (routed to vali) is not a KEK
        // release — it must never emit a boot-progress milestone even on
        // a 2xx.
        let vali = Arc::new(StubBackend::new(202, vec![]));
        let sink = Arc::new(SpySink::new());
        let req = KbsProxyRequest {
            path: "/v1/lifecycle/stopped?vm_id=x&generation=1".to_string(),
            body: ByteBuf::from(vec![1u8]),
        };
        let backends = ProxyBackends {
            kbs: Arc::new(PanicBackend),
            vali: Some(vali),
            progress: Some(sink.clone()),
        };
        let (outcome, _) = exchange_with_vm(&req, backends, Some("vm-eol")).await;
        assert_eq!(outcome, KbsProxyOutcome::Forwarded { status: 202 });
        settle().await;
        assert!(
            sink.seen().is_empty(),
            "a stopped-ack must not emit boot progress"
        );
    }

    #[tokio::test]
    async fn stopped_ack_is_refused_when_no_vali_backend_is_configured() {
        // No `[lifecycle]` config ⇒ `vali: None`. The path is allow-listed
        // but cannot route — refused (fail-closed), NEVER mis-routed to the
        // KBS (which panics if touched).
        let req = KbsProxyRequest {
            path: "/v1/lifecycle/stopped?vm_id=x&generation=1".to_string(),
            body: ByteBuf::from(vec![1u8]),
        };
        let (outcome, _) = exchange(&req, kbs_only(Arc::new(PanicBackend))).await;
        assert_eq!(outcome, KbsProxyOutcome::Refused("no-vali-backend"));
    }
}
