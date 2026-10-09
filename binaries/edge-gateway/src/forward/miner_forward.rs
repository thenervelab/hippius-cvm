//! Edge → miner-agent forwarder — the outbound half of the
//! `vali → Edge sign → miner verify` lifecycle-order chain.
//!
//! PR #144 shipped the [`OrderSigner`](crate::order_signing::OrderSigner)
//! primitive (load the Vault-materialised Ed25519 seed; sign body bytes).
//! This module is the wire client that relays a freshly-signed envelope
//! to the target miner's `:9700` orders server (see
//! `binaries/miner-agent/src/orders/mod.rs`).
//!
//! ## Why it lives next to [`kbs_forward`](super::kbs_forward) rather than reusing it
//!
//! Both modules are "Edge → inner-plane HTTP POST" — but the contracts
//! diverge in three ways the existing trait deliberately does not cover:
//!
//! 1. **Wire shape** — `kbs_forward` POSTs an already-validated
//!    [`ValidatedEnvelope`] (the §9 wire frame), whereas the miner
//!    orders server speaks a different protocol: a
//!    `SignedOrder { body, sig }` CBOR object the Edge constructs here
//!    (it is the signer, not a relay).
//! 2. **Destination selection** — `kbs_forward` resolves to ONE of two
//!    fixed in-cluster bases (KBS or vali); the miner forwarder is
//!    parametric in `target_addr` (the miner's NetBird `100.64.x.y`
//!    address, supplied per-order by the trusted caller).
//! 3. **Transport** — the miner orders server binds `:9700` plain HTTP
//!    on its NetBird interface (`miner-agent-config.toml.j2` →
//!    `orders.bind_addr`); the trust boundary is NetBird mesh
//!    membership, not TLS. `kbs_forward` negotiates TLS 1.3 against an
//!    in-cluster `https://` endpoint when the operator configures one.
//!
//! Folding either of those into [`ForwardClient`](super::ForwardClient)
//! would weaken its invariants (fixed routes; envelope-body relay).
//! [`MinerForward`] is a sibling trait with its own narrow contract.
//!
//! ## Opaque body, trusted URL
//!
//! The Edge does NOT decode the `OrderBody` CBOR. Vali built it; the
//! miner-agent will re-decode + dispatch it. This module:
//!
//! - **Signs the bytes verbatim** (the byte sequence the caller hands
//!   us is exactly what `verify_strict` will check against on the miner
//!   side).
//! - **Wraps `{body, sig}` as `SignedOrder` CBOR** — the wire envelope
//!   the miner-agent's
//!   [`OrderVerifier::verify`](binaries/miner-agent/src/orders/auth.rs)
//!   decodes. The struct is **mirrored** here (NOT pulled from
//!   miner-agent — the Edge does not depend on the miner-agent crate);
//!   the two definitions are pinned identical by a round-trip test in
//!   `tests/inner_router_test.rs`.
//! - **Picks the URL** from `(target_addr, OrderKind)` ALONE — never
//!   from any header / body field the caller chose. `target_addr` is
//!   validated against the NetBird CGNAT range
//!   (`100.64.0.0/10`) by the router *before* this module sees it; we
//!   format it back through `SocketAddr` (already typed) to belt-and-
//!   suspenders any residual injection surface.
//!
//! ## Transport posture
//!
//! - **Plain HTTP** — the miner's orders server is plaintext on
//!   NetBird (the WireGuard tunnel is the confidentiality layer).
//! - `connect_timeout` 5 s, whole-request `timeout` 30 s — identical to
//!   the §20 slow-loris bounds in [`kbs_forward`](super::kbs_forward).
//! - No redirect following, no proxy. The orders server is a single
//!   exact endpoint; a redirect would be a misconfig, not a feature.
//! - Response body hard-bounded by [`MAX_MINER_RESPONSE_BYTES`] (the
//!   miner orders server replies with an empty body on `2xx` and a tiny
//!   classifier string on `4xx`; the cap stops a hostile / buggy peer
//!   from driving an unbounded allocation).
//!
//! ## Trait seam
//!
//! [`MinerForward`] is the seam the inner router depends on. Production
//! is [`ReqwestMinerForward`]; tests inject [`MockMinerForward`] to
//! exercise the router off the network. Same pattern as
//! [`ForwardClient`](super::ForwardClient) +
//! [`MockForwardClient`](super::MockForwardClient).

use crate::order_signing::OrderSigner;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::net::SocketAddr;
use std::time::Duration;

/// `content-type` of every POSTed body — canonical CBOR. Matches the
/// miner-agent's `axum::extract` decoder (it accepts a raw byte body
/// and decodes via `ciborium`; the header is informational but pinned
/// here for symmetry with [`kbs_forward`](super::kbs_forward)).
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Strict connect timeout — a miner slower than this to complete TCP
/// is treated as unreachable (§20 slow-loris bound on connection
/// setup). Matches [`kbs_forward::CONNECT_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Strict whole-request timeout (send + miner work + response read)
/// for the launch / stop / destroy / migrate kinds. Bounds a miner
/// that dribbles bytes. Matches [`kbs_forward::REQUEST_TIMEOUT`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Whole-request timeout override for `tenant-preflight`. The miner
/// downloads tens-of-MB-to-GB of artifacts via presigned URLs, sha-
/// verifies them, AND computes the SNP launch_digest — wall-clock
/// dominated by the qcow2 download. 30 minutes is generous on a
/// 100 Mbit link; tighter would let a slow miner kill the dispatch
/// before the work completes.
const PREFLIGHT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Hard upper bound on the miner's response body, in bytes. The miner
/// orders server replies with an empty body on `2xx` and a tiny
/// static classifier on `4xx` (e.g. `"bad-signature"`); 64 KiB is
/// generous for that traffic shape and bounds a hostile / buggy peer.
/// Independent of [`MAX_MINER_ORDER_BODY`] (request cap) so the two
/// directions can evolve separately.
pub const MAX_MINER_RESPONSE_BYTES: usize = 64 * 1024;

/// Response cap for a poll that reports a multipart upload's part receipts
/// (`backup` and §25 snapshot status): ~170 bytes per part (ETag + sha256),
/// up to `encode-order`'s 3,000 parts.
pub const MAX_MULTIPART_STATUS_RESPONSE_BYTES: usize = 1024 * 1024;

/// Hard upper bound on the **outbound** envelope (`SignedOrder { body, sig }`
/// CBOR) the Edge POSTs to a miner — matches the miner-agent's
/// `MAX_ORDER_BODY` exactly (`binaries/miner-agent/src/orders/mod.rs`)
/// so a body the Edge accepts inbound is guaranteed to fit the miner's
/// inbound cap once wrapped.
pub const MAX_MINER_REQUEST_BYTES: usize = 64 * 1024;

/// Worst-case CBOR overhead of wrapping a body in
/// `SignedOrder { body: bytes, sig: bytes }`:
/// - 1 byte for the 2-entry map marker (`0xa2`)
/// - 5 bytes for `"body"` text-major-3
/// - 3 bytes for the `body` bytes-major-2 length prefix (up to 64 KiB
///   uses `0x59 <hi> <lo>`)
/// - 4 bytes for `"sig"` text-major-3
/// - 2 bytes for the `sig` bytes-major-2 length prefix (`0x58 0x40`)
/// - 64 bytes for the Ed25519 signature itself
///
/// Total `≤ 79 bytes`. We round up to `256` for a generous safety
/// margin — the alternative is the §H phase-2 review's review r1
/// Medium: an inner body sized exactly at the miner-agent's
/// `MAX_ORDER_BODY` becomes `body + sig + overhead` after signing and
/// is GUARANTEED to be rejected by the miner-side `DefaultBodyLimit`.
const SIGNED_ORDER_OVERHEAD: usize = 256;

/// Hard upper bound on the **inbound** order body the Edge accepts at
/// `POST /v1/edge/order`. Set so the wrapped `SignedOrder` envelope
/// fits inside the miner-agent's `MAX_ORDER_BODY` (see
/// [`SIGNED_ORDER_OVERHEAD`]). The inner router applies this cap on the
/// request body before signing; the forwarder re-asserts it as a
/// tripwire.
pub const MAX_MINER_ORDER_BODY: usize = MAX_MINER_REQUEST_BYTES - SIGNED_ORDER_OVERHEAD;

/// Request cap for an order carrying a presigned multipart part list
/// (`migrate-snapshot`, `backup`): one ~530-byte URL per part, and the
/// store takes parts of at most 512 MiB, so the largest flavor's overlay
/// (1280 GiB) needs ~2,600 of them. Mirrors the miner-agent's
/// `MAX_MULTIPART_ORDER_BODY` on those two routes.
pub const MAX_MULTIPART_REQUEST_BYTES: usize = 2 * 1024 * 1024;

/// [`MAX_MINER_ORDER_BODY`] for a multipart order (see
/// [`MAX_MULTIPART_REQUEST_BYTES`]).
pub const MAX_MULTIPART_ORDER_BODY: usize = MAX_MULTIPART_REQUEST_BYTES - SIGNED_ORDER_OVERHEAD;

/// The lifecycle command the order carries. Mirrors the miner-agent's
/// `OrderKind` (`binaries/miner-agent/src/orders/types.rs`) but lives
/// here so the Edge does not depend on the miner-agent crate (opacity
/// discipline — see module docs). The kebab-case path mapping is the
/// SAME mapping the miner's routes use, kept in lockstep by the
/// integration test in `tests/inner_router_test.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKind {
    /// Provision + launch a tenant CVM.
    Launch,
    /// Stop a running CVM (graceful or forced).
    Stop,
    /// Decommission a CVM — stop + reclaim disk capacity (§24).
    Destroy,
    /// Migrate a CVM to another host (§25) — miner returns 501.
    Migrate,
    /// §25 migration **M1** — quiesce (clean stop) the source CVM so its
    /// writable LUKS volume is static for the snapshot.
    MigrateQuiesce,
    /// §25 migration **M1** — snapshot the source CVM's writable volume
    /// and upload it (still encrypted) to a presigned S3 PUT URL.
    MigrateSnapshot,
    /// §25 migration **M2/M4** — activate the DESTINATION CVM: download the
    /// encrypted LUKS snapshot, stage the measured boot artifacts, and boot
    /// the libvirt domain at `new_gen`. Dispatched by vali ONLY after the
    /// verified source-ack fence + the KBS `Migrating{new_gen, dest}` move
    /// (the split-brain gate is enforced upstream — see the miner-agent's
    /// `handle_migrate_activate`).
    MigrateActivate,
    /// Pre-launch artifact fetch + sha verify + SNP launch_digest
    /// compute on the miner. The miner returns a JSON envelope vali
    /// parses for the digest before minting the matching OrderTicket.
    TenantPreflight,
    /// Live backup of a running golden CVM through presigned multipart
    /// part URLs (ACK-then-async; status via `forward_backup_status`).
    Backup,
    /// Staged restore of a CVM from its backups (`stage` / `abort` /
    /// `reclaim`; `stage` is ACK-then-async, status via
    /// `forward_restore_status`).
    Restore,
    /// Host-wide guest network policy. Names no VM; the miner persists
    /// it under a monotonic revision and answers
    /// `applied:<revision>:<sha256>`.
    NetPolicy,
    /// A VM's guest-poweroff policy (`restart` | `stop`), applied by the
    /// miner in place; it answers `power-policy:<policy>`.
    PowerPolicy,
}

impl OrderKind {
    /// The miner-agent route segment for this kind. The miner's router
    /// (`binaries/miner-agent/src/orders/mod.rs`) declares
    /// `/v1/miner/order/{launch,stop,destroy,migrate,tenant-preflight}`;
    /// we build the matching path here from a closed enum, never from
    /// caller text.
    pub fn route_segment(self) -> &'static str {
        match self {
            OrderKind::Launch => "launch",
            OrderKind::Stop => "stop",
            OrderKind::Destroy => "destroy",
            OrderKind::Migrate => "migrate",
            OrderKind::MigrateQuiesce => "migrate-quiesce",
            OrderKind::MigrateSnapshot => "migrate-snapshot",
            OrderKind::MigrateActivate => "migrate-activate",
            OrderKind::TenantPreflight => "tenant-preflight",
            OrderKind::Backup => "backup",
            OrderKind::Restore => "restore",
            OrderKind::NetPolicy => "net-policy",
            OrderKind::PowerPolicy => "power-policy",
        }
    }

    /// The inbound body cap for this kind: [`MAX_MULTIPART_ORDER_BODY`] for
    /// an order carrying a multipart part list, [`MAX_MINER_ORDER_BODY`]
    /// for every other.
    pub fn max_order_body(self) -> usize {
        match self {
            // A restore `stage` carries a per-part sha256 for every 512 MiB
            // of every piece of its chain.
            OrderKind::MigrateSnapshot | OrderKind::Backup | OrderKind::Restore => {
                MAX_MULTIPART_ORDER_BODY
            }
            _ => MAX_MINER_ORDER_BODY,
        }
    }

    /// Parse the kebab-case header value vali sends as
    /// `x-hippius-order-kind`. Closed vocabulary — any other text is
    /// rejected by the router as a `bad-kind` request, never reaching
    /// the wire.
    pub fn from_header(value: &str) -> Option<Self> {
        match value {
            "launch" => Some(OrderKind::Launch),
            "stop" => Some(OrderKind::Stop),
            "destroy" => Some(OrderKind::Destroy),
            "migrate" => Some(OrderKind::Migrate),
            // §25 M4 — vali dispatches the dest activation through the SAME
            // `/v1/edge/order` inner-router path launch/stop use, naming the
            // kind in the `x-hippius-order-kind` header.
            "migrate-activate" => Some(OrderKind::MigrateActivate),
            "tenant-preflight" => Some(OrderKind::TenantPreflight),
            // vali's backup tick dispatches through the same inner-router
            // path; the status comes back via `GET /v1/relay/{vm}/backup`.
            "backup" => Some(OrderKind::Backup),
            // vali's restore job dispatches through the same path; the
            // status comes back via `GET /v1/relay/{vm}/restore`.
            "restore" => Some(OrderKind::Restore),
            // vali dispatches the §25 snapshot through this path when it
            // carries multipart part URLs (the relay route rebuilds only
            // the single-PUT shape).
            "migrate-snapshot" => Some(OrderKind::MigrateSnapshot),
            // vali's net-policy reconcile pushes each miner's policy here.
            "net-policy" => Some(OrderKind::NetPolicy),
            // vali's `PATCH /v1/vm/<id>/power-policy` and its reconcile.
            "power-policy" => Some(OrderKind::PowerPolicy),
            _ => None,
        }
    }

    /// Stable static classifier for log lines. Same shape as the
    /// miner-agent's `OrderKind::as_class_str` so audit logs on the
    /// two sides line up.
    pub fn as_class_str(self) -> &'static str {
        self.route_segment()
    }
}

/// The wire envelope POSTed to the miner — `{body, sig}`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::SignedOrder` exactly
/// (`#[serde(deny_unknown_fields)]`, same field order, `ByteBuf` for
/// the byte slots so canonical CBOR uses major type 2 — bytes — not
/// 4 — array of u8). A round-trip test in
/// `tests/inner_router_test.rs` decodes a Edge-built envelope through
/// the miner-agent's actual type to pin the two definitions identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedOrderWire {
    /// CBOR-encoded `OrderBody` bytes — opaque to the Edge.
    body: ByteBuf,
    /// Detached Ed25519 signature (64 bytes) over `body`.
    sig: ByteBuf,
}

/// Static-classifier error from a miner-forward attempt. Same
/// `&'static str`-only `Display` discipline as
/// [`super::ForwardError`] — the inner classifier is drawn from a
/// closed vocabulary, never caller-built text, and the `Display`
/// renders only the outer class so a forward failure cannot leak a
/// URL / header / body into a log line.
#[derive(Debug, thiserror::Error)]
pub enum MinerForwardError {
    /// The HTTP client could not be built (broken TLS backend etc.).
    /// Boot-time only — surfaced so `main` can fail-closed.
    #[error("miner-forward-client-build")]
    ClientBuild,
    /// Encoding the `SignedOrder` envelope to CBOR failed. Defensive:
    /// `ciborium` cannot fail on a `ByteBuf` + `ByteBuf` struct in
    /// practice, but the path returns a classifier rather than
    /// `unwrap`-ing.
    #[error("miner-forward-encode")]
    Encode,
    /// The request did not reach the miner, or no response was
    /// received: connect, timeout, peer closed the socket mid-write.
    /// Distinct from a miner that answered with a non-2xx status (that
    /// is a successful [`MinerForwardResponse`] the router maps to
    /// `502`).
    #[error("miner-forward-transport")]
    Transport,
    /// The miner's response body exceeded [`MAX_MINER_RESPONSE_BYTES`].
    /// Rejected outright rather than relayed truncated.
    #[error("miner-forward-response-too-large")]
    ResponseTooLarge,
    /// Reading the miner's response body failed mid-stream.
    #[error("miner-forward-response-read")]
    ResponseRead,
}

impl MinerForwardError {
    /// Static classifier — identical to the `Display` impl. Named
    /// contract for the telemetry / diagnostic sinks (mirrors
    /// [`super::ForwardError::class`]).
    pub fn class(&self) -> &'static str {
        match self {
            MinerForwardError::ClientBuild => "miner-forward-client-build",
            MinerForwardError::Encode => "miner-forward-encode",
            MinerForwardError::Transport => "miner-forward-transport",
            MinerForwardError::ResponseTooLarge => "miner-forward-response-too-large",
            MinerForwardError::ResponseRead => "miner-forward-response-read",
        }
    }
}

/// The miner's response to a signed order. The router maps this back
/// to the caller (vali) verbatim: `status` becomes the vali-facing
/// HTTP status, `body` becomes the vali-facing response body. On a
/// non-2xx the miner-agent returns a short static classifier
/// (`"bad-signature"`, `"order-id-collision"`, etc.) — opaque to the
/// Edge, surfaced unchanged so vali can branch on the exact class.
#[derive(Debug, Clone)]
pub struct MinerForwardResponse {
    /// The miner's HTTP status.
    pub status: u16,
    /// The miner's response body — relayed to vali verbatim.
    pub body: Vec<u8>,
}

/// Sign a CBOR `OrderBody` and POST `SignedOrder { body, sig }` to the
/// target miner's `:9700` orders server.
///
/// `body` is **opaque to the Edge** — vali built it, the miner-agent
/// will re-decode it. The Edge:
///
/// 1. Signs `body` with [`OrderSigner::sign`] (the miner verifies via
///    `verify_strict` against the same key).
/// 2. CBOR-encodes `SignedOrder { body, sig }` (the wire shape).
/// 3. POSTs that to `http://{target_addr}/v1/miner/order/{kind}`.
///
/// `#[async_trait]` so the router can hold a `dyn MinerForward` — the
/// production [`ReqwestMinerForward`] and the test
/// [`MockMinerForward`] are both dispatched through this trait object.
#[async_trait]
pub trait MinerForward: Send + Sync {
    /// Sign, wrap, and POST. See trait-level docs for the invariants
    /// the caller is responsible for (`body` must be canonical CBOR of
    /// an `OrderBody`; `target_addr` must be validated against the
    /// NetBird CGNAT range upstream).
    async fn forward_signed_order(
        &self,
        signer: &OrderSigner,
        target_addr: SocketAddr,
        kind: OrderKind,
        body: &[u8],
    ) -> Result<MinerForwardResponse, MinerForwardError>;

    /// §25 migration **M1** — relay an UNSIGNED `GET` to the source
    /// miner's snapshot-status route
    /// (`/v1/miner/migration/{vm_id}/status`). The status read carries
    /// no side effect and no secret, so it is not a signed order — the
    /// Edge just proxies it and relays the miner's `{"status": …}` JSON
    /// (or `404` when no migration is recorded) back to vali's
    /// `poll_snapshot`. `vm_id` is charset-validated by the relay router
    /// upstream (same gate the miner applies), so it cannot inject a
    /// path component here.
    async fn forward_migration_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError>;

    /// §25 migration **M2** — relay an UNSIGNED `GET` to the SOURCE
    /// miner's source-stopped-ack route
    /// (`/v1/miner/migration/{vm_id}/source-ack`). Like the snapshot
    /// status poll it carries no side effect: the ack it returns is the
    /// guest's own Ed25519-signed `SignedStoppedAck`, opaque to the Edge
    /// AND the miner — only vali can verify it. The Edge proxies the
    /// miner's `{"signed_ack_hex": …}` JSON (or `404` when the guest has
    /// not produced one yet) back to vali's `poll_source_ack`. `vm_id` is
    /// charset-validated by the relay router upstream.
    async fn forward_source_ack(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError>;

    /// Reboot-recovery — relay an UNSIGNED `GET` to the miner's
    /// per-VM domain-state route (`/v1/miner/vm/{vm_id}/domain-state`).
    /// Like the migration status / source-ack polls this carries no
    /// side effect and no secret: it just asks libvirt "is this
    /// domain running right now?" and relays the miner's `{"running":
    /// …}` JSON (or `503` when the miner's libvirt is itself
    /// unreachable) back to the caller. `vm_id` is charset-validated
    /// by the relay router upstream, so it cannot inject a path
    /// component here.
    async fn forward_domain_state(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError>;

    /// Live backup — relay an UNSIGNED `GET` to the miner's backup-status
    /// route (`/v1/miner/backup/{vm_id}/status`). No side effect, no
    /// secret: the miner reports its latest run for the VM (sizes,
    /// sha256s, part ETags) plus the live bitmap/boot-counter probe, and
    /// the Edge relays that JSON (or `404`) back to vali. `vm_id` is
    /// charset-validated by the relay router upstream.
    async fn forward_backup_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError>;

    /// Staged restore — relay an UNSIGNED `GET` to the miner's
    /// restore-status route (`/v1/miner/restore/{vm_id}/status`). No side
    /// effect, no secret (ids, states, byte counts). `vm_id` is
    /// charset-validated by the relay router upstream.
    async fn forward_restore_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError>;
}

/// Production [`MinerForward`] — a `reqwest` client + the constants
/// above. One client serves every miner; routing is parametric in
/// `target_addr`. Cheap to clone via `Arc` (the trait object the
/// router holds is `Arc<dyn MinerForward>` so the inner clone is the
/// `Arc`, not the `reqwest::Client` itself).
pub struct ReqwestMinerForward {
    client: reqwest::Client,
}

impl ReqwestMinerForward {
    /// Build the client. `Err(ClientBuild)` only on a `reqwest` builder
    /// failure — surfaced so `main` can fail-closed at boot rather than
    /// discover it on the first relayed order.
    pub fn new() -> Result<Self, MinerForwardError> {
        let client = reqwest::Client::builder()
            // Plain HTTP, but still pin `rustls` (no native-tls) for
            // consistency with the rest of the codebase — if the
            // operator ever flips to `https://` for an in-cluster
            // miner proxy this client negotiates TLS 1.3 too.
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| MinerForwardError::ClientBuild)?;
        Ok(Self { client })
    }

    /// Build the URL from `(target_addr, kind)` ALONE. `SocketAddr` is
    /// already typed (the router constructed it from
    /// `x-hippius-target-addr` via `SocketAddr::parse`, then range-
    /// checked it against `100.64.0.0/10`); we just `Display` it. The
    /// path segment is a `&'static str` from a closed enum — there is
    /// no caller-controlled component anywhere in the URL.
    fn build_url(target_addr: SocketAddr, kind: OrderKind) -> String {
        format!(
            "http://{}/v1/miner/order/{}",
            target_addr,
            kind.route_segment()
        )
    }

    /// CBOR-encode `SignedOrder { body, sig }`. Split out so it is
    /// unit-testable without a live miner. `body` is borrowed verbatim
    /// (no copy until `ByteBuf::from`) — the signature was computed
    /// over these exact bytes, so any re-encoding here would break
    /// verification on the miner side.
    fn encode_wire(body: &[u8], sig: &[u8; 64]) -> Result<Vec<u8>, MinerForwardError> {
        let wire = SignedOrderWire {
            body: ByteBuf::from(body.to_vec()),
            sig: ByteBuf::from(sig.to_vec()),
        };
        let mut buf = Vec::with_capacity(body.len() + 64 + 32);
        ciborium::ser::into_writer(&wire, &mut buf).map_err(|_| MinerForwardError::Encode)?;
        Ok(buf)
    }
}

#[async_trait]
impl MinerForward for ReqwestMinerForward {
    async fn forward_signed_order(
        &self,
        signer: &OrderSigner,
        target_addr: SocketAddr,
        kind: OrderKind,
        body: &[u8],
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // The inbound body cap is enforced by the router's
        // `DefaultBodyLimit`. Re-assert here as a tripwire — a future
        // caller that bypasses the router would otherwise be able to
        // sign + relay an arbitrarily large body.
        if body.len() > kind.max_order_body() {
            return Err(MinerForwardError::Encode);
        }

        let sig = signer.sign(body);
        let wire = Self::encode_wire(body, &sig)?;
        let url = Self::build_url(target_addr, kind);

        // Per-kind whole-request timeout. The client-level
        // `REQUEST_TIMEOUT` covers launch/stop/destroy/migrate;
        // `tenant-preflight` downloads + sha-verifies + measures so
        // its miner-side work is wall-clock dominated by the qcow2
        // fetch and gets a much longer budget.
        let request_timeout = match kind {
            OrderKind::TenantPreflight => PREFLIGHT_REQUEST_TIMEOUT,
            _ => REQUEST_TIMEOUT,
        };
        let mut response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(wire)
            .timeout(request_timeout)
            .send()
            .await
            .map_err(|_| MinerForwardError::Transport)?;

        let status = response.status().as_u16();
        // `content-length` is advisory — when present we can reject up
        // front; when absent (chunked / streaming peer) we MUST still
        // bound allocation, by reading chunks one at a time and
        // stopping the moment accumulated bytes exceed the cap. A
        // single `.bytes().await` would buffer the full upstream body
        // before the size check fires — a hostile or buggy peer could
        // then drive unbounded allocation despite the cap. (review r1
        // High.)
        if let Some(len) = response.content_length() {
            if len > MAX_MINER_RESPONSE_BYTES as u64 {
                return Err(MinerForwardError::ResponseTooLarge);
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MinerForwardError::ResponseRead)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_MINER_RESPONSE_BYTES {
                return Err(MinerForwardError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        Ok(MinerForwardResponse { status, body })
    }

    async fn forward_migration_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // URL built from the typed `SocketAddr` Display + a `&'static`
        // path shape; `vm_id` is the only caller component and it was
        // charset-validated upstream (the relay router constructs it
        // through the same `[a-z0-9-]` gate the miner enforces), so no
        // path traversal is possible.
        let url = format!("http://{}/v1/miner/migration/{}/status", target_addr, vm_id);
        self.get_and_relay(&url, MAX_MULTIPART_STATUS_RESPONSE_BYTES)
            .await
    }

    async fn forward_source_ack(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // Same typed-Display + `&'static` path shape as the status GET;
        // `vm_id` charset-validated upstream — no path traversal.
        let url = format!(
            "http://{}/v1/miner/migration/{}/source-ack",
            target_addr, vm_id
        );
        self.get_and_relay(&url, MAX_MINER_RESPONSE_BYTES).await
    }

    async fn forward_domain_state(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // Same typed-Display + `&'static` path shape as the other
        // unsigned poll GETs; `vm_id` charset-validated upstream — no
        // path traversal.
        let url = format!("http://{}/v1/miner/vm/{}/domain-state", target_addr, vm_id);
        self.get_and_relay(&url, MAX_MINER_RESPONSE_BYTES).await
    }

    async fn forward_backup_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // Same typed-Display + `&'static` path shape as the other
        // unsigned poll GETs; `vm_id` charset-validated upstream — no
        // path traversal.
        let url = format!("http://{}/v1/miner/backup/{}/status", target_addr, vm_id);
        self.get_and_relay(&url, MAX_MULTIPART_STATUS_RESPONSE_BYTES)
            .await
    }

    async fn forward_restore_status(
        &self,
        target_addr: SocketAddr,
        vm_id: &str,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        // Same shape as the backup poll; `vm_id` charset-validated
        // upstream — no path traversal.
        let url = format!("http://{}/v1/miner/restore/{}/status", target_addr, vm_id);
        self.get_and_relay(&url, MAX_MULTIPART_STATUS_RESPONSE_BYTES)
            .await
    }
}

impl ReqwestMinerForward {
    /// Shared streaming GET → bounded body relay for the unsigned poll
    /// routes. Bounds the response body at `cap` the same way
    /// `forward_signed_order` does so a hostile / buggy miner cannot drive
    /// unbounded allocation.
    async fn get_and_relay(
        &self,
        url: &str,
        cap: usize,
    ) -> Result<MinerForwardResponse, MinerForwardError> {
        let mut response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|_| MinerForwardError::Transport)?;

        let status = response.status().as_u16();
        if let Some(len) = response.content_length() {
            if len > cap as u64 {
                return Err(MinerForwardError::ResponseTooLarge);
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| MinerForwardError::ResponseRead)?
        {
            if body.len().saturating_add(chunk.len()) > cap {
                return Err(MinerForwardError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(MinerForwardResponse { status, body })
    }
}

/// Canned-response [`MinerForward`] for tests. Records every call (the
/// signed wire bytes the production client would have POSTed) and
/// returns a canned response or canned [`MinerForwardError`]. Keeps
/// the router tests off the network while still exercising the
/// signing + URL-construction logic.
///
/// Unconditionally compiled (not `#[cfg(test)]`) so the separate-
/// crate integration tests in `tests/` — which do not see the lib's
/// `cfg(test)` items — can drive the production router against it.
pub use mock::{MockMinerForward, RecordedMinerForward, RecordedStatusForward};

mod mock {
    use super::*;
    use std::sync::Mutex;

    /// One recorded forward call.
    #[derive(Debug, Clone)]
    pub struct RecordedMinerForward {
        /// The target the call was routed to.
        pub target_addr: SocketAddr,
        /// The order kind (the route segment the call would have hit).
        pub kind: OrderKind,
        /// The original body bytes the caller handed the mock.
        pub body: Vec<u8>,
        /// The 64-byte signature the mock observed over `body`.
        pub sig: [u8; 64],
    }

    /// One recorded §25 M1 migration-status GET call.
    #[derive(Debug, Clone)]
    pub struct RecordedStatusForward {
        /// The target the GET was routed to.
        pub target_addr: SocketAddr,
        /// The `vm_id` path segment the GET would have hit.
        pub vm_id: String,
    }

    /// A [`MinerForward`] that returns a canned outcome.
    pub struct MockMinerForward {
        outcome: Mutex<Result<MinerForwardResponse, MinerForwardError>>,
        calls: Mutex<Vec<RecordedMinerForward>>,
        status_calls: Mutex<Vec<RecordedStatusForward>>,
    }

    impl MockMinerForward {
        /// A mock that returns `status` + `body` for every call.
        pub fn with_response(status: u16, body: Vec<u8>) -> Self {
            Self {
                outcome: Mutex::new(Ok(MinerForwardResponse { status, body })),
                calls: Mutex::new(Vec::new()),
                status_calls: Mutex::new(Vec::new()),
            }
        }

        /// A mock whose every call fails with `err` — drives the
        /// "forward transport failure → `502`" router test.
        pub fn with_error(err: MinerForwardError) -> Self {
            Self {
                outcome: Mutex::new(Err(err)),
                calls: Mutex::new(Vec::new()),
                status_calls: Mutex::new(Vec::new()),
            }
        }

        /// Every forward call recorded so far, in order. A poisoned
        /// lock yields the inner `Vec` anyway — same recovery posture
        /// as [`super::super::MockForwardClient::calls`].
        pub fn calls(&self) -> Vec<RecordedMinerForward> {
            match self.calls.lock() {
                Ok(g) => g.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        /// Every §25 M1 migration-status GET recorded so far, in order.
        pub fn status_calls(&self) -> Vec<RecordedStatusForward> {
            match self.status_calls.lock() {
                Ok(g) => g.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    #[async_trait]
    impl MinerForward for MockMinerForward {
        async fn forward_signed_order(
            &self,
            signer: &OrderSigner,
            target_addr: SocketAddr,
            kind: OrderKind,
            body: &[u8],
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            // Sign + record so a test can assert the mock observed the
            // same signature a real miner would have verified.
            let sig = signer.sign(body);
            let record = RecordedMinerForward {
                target_addr,
                kind,
                body: body.to_vec(),
                sig,
            };
            match self.calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }

        async fn forward_migration_status(
            &self,
            target_addr: SocketAddr,
            vm_id: &str,
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            let record = RecordedStatusForward {
                target_addr,
                vm_id: vm_id.to_string(),
            };
            match self.status_calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }

        async fn forward_source_ack(
            &self,
            target_addr: SocketAddr,
            vm_id: &str,
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            // Recorded into the same `status_calls` vec — both are
            // unsigned GET polls keyed by (target, vm_id); a test that
            // needs to distinguish asserts on the relay route, not the
            // mock's recording shape.
            let record = RecordedStatusForward {
                target_addr,
                vm_id: vm_id.to_string(),
            };
            match self.status_calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }

        async fn forward_backup_status(
            &self,
            target_addr: SocketAddr,
            vm_id: &str,
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            // Recorded into the same `status_calls` vec as the other
            // unsigned GET polls.
            let record = RecordedStatusForward {
                target_addr,
                vm_id: vm_id.to_string(),
            };
            match self.status_calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }

        async fn forward_restore_status(
            &self,
            target_addr: SocketAddr,
            vm_id: &str,
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            // Recorded into the same `status_calls` vec as the other
            // unsigned GET polls.
            let record = RecordedStatusForward {
                target_addr,
                vm_id: vm_id.to_string(),
            };
            match self.status_calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }

        async fn forward_domain_state(
            &self,
            target_addr: SocketAddr,
            vm_id: &str,
        ) -> Result<MinerForwardResponse, MinerForwardError> {
            // Recorded into the same `status_calls` vec as the other
            // unsigned GET polls — both are keyed by (target, vm_id); a
            // test that needs to distinguish asserts on the relay route.
            let record = RecordedStatusForward {
                target_addr,
                vm_id: vm_id.to_string(),
            };
            match self.status_calls.lock() {
                Ok(mut g) => g.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            }
            let outcome = match self.outcome.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match &*outcome {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(clone_err(e)),
            }
        }
    }

    /// Clone a [`MinerForwardError`] (it is not `Clone` — a `#[source]`
    /// would be lost) for the mock's canned-error replay across both
    /// trait methods.
    fn clone_err(e: &MinerForwardError) -> MinerForwardError {
        match e {
            MinerForwardError::ClientBuild => MinerForwardError::ClientBuild,
            MinerForwardError::Encode => MinerForwardError::Encode,
            MinerForwardError::Transport => MinerForwardError::Transport,
            MinerForwardError::ResponseTooLarge => MinerForwardError::ResponseTooLarge,
            MinerForwardError::ResponseRead => MinerForwardError::ResponseRead,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn order_kind_route_segments_match_the_miner_agent_routes() {
        // `binaries/miner-agent/src/orders/mod.rs` declares exactly
        // these four routes; any drift between this enum and the
        // miner-agent's would cause a 404 on every order. Pinned by
        // hand here; the integration test cross-checks against the
        // miner-agent's `OrderKind` round-tripped through CBOR.
        assert_eq!(OrderKind::Launch.route_segment(), "launch");
        assert_eq!(OrderKind::Stop.route_segment(), "stop");
        assert_eq!(OrderKind::Destroy.route_segment(), "destroy");
        assert_eq!(OrderKind::Migrate.route_segment(), "migrate");
        // §25 M4 — the dest-activation route segment must match the
        // miner-agent's `/v1/miner/order/migrate-activate` route.
        assert_eq!(
            OrderKind::MigrateActivate.route_segment(),
            "migrate-activate"
        );
        // Must match the miner-agent's `/v1/miner/order/backup` route.
        assert_eq!(OrderKind::Backup.route_segment(), "backup");
        // Must match the miner-agent's `/v1/miner/order/restore` route.
        assert_eq!(OrderKind::Restore.route_segment(), "restore");
        assert_eq!(
            OrderKind::Restore.max_order_body(),
            MAX_MULTIPART_ORDER_BODY
        );
        // Must match the miner-agent's `/v1/miner/order/net-policy` route.
        assert_eq!(OrderKind::NetPolicy.route_segment(), "net-policy");
        assert_eq!(OrderKind::NetPolicy.max_order_body(), MAX_MINER_ORDER_BODY);
        // Must match the miner-agent's `/v1/miner/order/power-policy` route.
        assert_eq!(OrderKind::PowerPolicy.route_segment(), "power-policy");
        assert_eq!(
            OrderKind::PowerPolicy.max_order_body(),
            MAX_MINER_ORDER_BODY
        );
    }

    #[test]
    fn order_kind_from_header_is_closed_vocabulary() {
        for (text, expected) in [
            ("launch", OrderKind::Launch),
            ("stop", OrderKind::Stop),
            ("destroy", OrderKind::Destroy),
            ("migrate", OrderKind::Migrate),
            // §25 M4 — vali sends this header value for the dest activation.
            ("migrate-activate", OrderKind::MigrateActivate),
            ("backup", OrderKind::Backup),
            ("restore", OrderKind::Restore),
            // §25 snapshot with multipart part URLs.
            ("migrate-snapshot", OrderKind::MigrateSnapshot),
            ("net-policy", OrderKind::NetPolicy),
            ("power-policy", OrderKind::PowerPolicy),
        ] {
            assert_eq!(OrderKind::from_header(text), Some(expected));
        }
        // Case-sensitive: the miner-agent's serde rename_all is
        // kebab-case (all lowercase), so "Launch" is NOT accepted.
        assert_eq!(OrderKind::from_header("Launch"), None);
        // Whitespace + empty + arbitrary garbage all rejected.
        assert_eq!(OrderKind::from_header(""), None);
        assert_eq!(OrderKind::from_header("launch "), None);
        assert_eq!(OrderKind::from_header("../../etc/passwd"), None);
    }

    #[test]
    fn build_url_takes_no_caller_text() {
        // The URL is built solely from the typed `SocketAddr` Display +
        // a `&'static str` route segment. There is no path the caller
        // can inject — proven by attempting to feed nonsense via the
        // *typed* inputs (a `SocketAddr` literally cannot carry a
        // path-traversal sequence, that is the whole point).
        let addr: SocketAddr = "100.64.0.1:9700".parse().unwrap();
        assert_eq!(
            ReqwestMinerForward::build_url(addr, OrderKind::Launch),
            "http://100.64.0.1:9700/v1/miner/order/launch"
        );
        assert_eq!(
            ReqwestMinerForward::build_url(addr, OrderKind::Stop),
            "http://100.64.0.1:9700/v1/miner/order/stop"
        );
        assert_eq!(
            ReqwestMinerForward::build_url(addr, OrderKind::Destroy),
            "http://100.64.0.1:9700/v1/miner/order/destroy"
        );
        assert_eq!(
            ReqwestMinerForward::build_url(addr, OrderKind::Migrate),
            "http://100.64.0.1:9700/v1/miner/order/migrate"
        );
    }

    #[test]
    fn encode_wire_round_trips_through_the_wire_struct() {
        // The encoded bytes decode back to a `SignedOrderWire` with the
        // same `body` + `sig` slots. Pinning this guarantees the CBOR
        // shape on the wire matches what the miner-agent's
        // `SignedOrder` decoder expects (cross-checked end-to-end in
        // `tests/inner_router_test.rs`).
        let body = b"opaque-canonical-cbor-body".to_vec();
        let sig = [7u8; 64];
        let bytes = ReqwestMinerForward::encode_wire(&body, &sig).unwrap();
        let back: SignedOrderWire = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(&back.body[..], body.as_slice());
        assert_eq!(&back.sig[..], &sig[..]);
    }

    #[test]
    fn client_builds_with_default_settings() {
        assert!(ReqwestMinerForward::new().is_ok());
    }

    #[test]
    fn error_classes_are_static_and_match_display() {
        for err in [
            MinerForwardError::ClientBuild,
            MinerForwardError::Encode,
            MinerForwardError::Transport,
            MinerForwardError::ResponseTooLarge,
            MinerForwardError::ResponseRead,
        ] {
            assert_eq!(err.class(), err.to_string());
        }
    }

    #[test]
    fn max_miner_order_body_leaves_room_for_the_signed_envelope() {
        // The miner-agent's request cap (`MAX_ORDER_BODY = 64 KiB` in
        // `binaries/miner-agent/src/orders/mod.rs`) is the WRAPPED
        // envelope's bound. Edge accepts a smaller INNER body so the
        // wrapped `SignedOrder { body, sig }` envelope still fits.
        assert_eq!(MAX_MINER_REQUEST_BYTES, 64 * 1024);
        const _: () = assert!(MAX_MINER_ORDER_BODY < MAX_MINER_REQUEST_BYTES);
        assert_eq!(
            MAX_MINER_REQUEST_BYTES - MAX_MINER_ORDER_BODY,
            SIGNED_ORDER_OVERHEAD
        );
        // Sanity: even an OrderBody at the inner cap encodes to
        // <= MAX_MINER_REQUEST_BYTES once wrapped. Build the envelope
        // explicitly and assert.
        let body = vec![0u8; MAX_MINER_ORDER_BODY];
        let sig = [0u8; 64];
        let wire = ReqwestMinerForward::encode_wire(&body, &sig).unwrap();
        assert!(
            wire.len() <= MAX_MINER_REQUEST_BYTES,
            "wrapped envelope ({} B) must fit miner cap ({} B)",
            wire.len(),
            MAX_MINER_REQUEST_BYTES,
        );
        // The 4xx classifier bodies the miner returns are tiny (a few
        // bytes); 64 KiB is overkill — generous-yet-bounded.
        assert_eq!(MAX_MINER_RESPONSE_BYTES, 64 * 1024);
    }

    #[tokio::test]
    async fn mock_records_the_sig_the_signer_would_produce() {
        // The mock signs with the real `OrderSigner` so a test can
        // assert end-to-end: "the bytes the production client would
        // have POSTed are exactly what the miner's `verify_strict`
        // accepts under the matching pubkey". The signature property
        // itself is unit-tested in `order_signing.rs`; here we just
        // verify the mock plumbs the signer through.
        use std::io::Write;
        let seed = [42u8; 32];
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(hex::encode(seed).as_bytes()).unwrap();
        f.flush().unwrap();
        let signer = OrderSigner::load(f.path(), None).unwrap();

        let mock = MockMinerForward::with_response(200, Vec::new());
        let addr: SocketAddr = "100.64.0.1:9700".parse().unwrap();
        let body = b"order-body-bytes";
        let _ = mock
            .forward_signed_order(&signer, addr, OrderKind::Launch, body)
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target_addr, addr);
        assert_eq!(calls[0].kind, OrderKind::Launch);
        assert_eq!(calls[0].body, body);
        // Mock's recorded sig is exactly what the production client
        // would have POSTed — and exactly what a real miner with the
        // same pubkey would `verify_strict`.
        use ed25519_dalek::Signature;
        let sig = Signature::from_bytes(&calls[0].sig);
        signer.verifying_key().verify_strict(body, &sig).unwrap();
    }

    /// A one-shot-per-connection HTTP/1.1 server answering every GET with
    /// a `len`-byte 200 body, with a Content-Length or close-delimited.
    async fn serve_body(len: usize, content_length: bool) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let cl = if content_length {
                        format!("content-length: {len}\r\n")
                    } else {
                        String::new()
                    };
                    let head = format!("HTTP/1.1 200 OK\r\n{cl}connection: close\r\n\r\n");
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&vec![b'x'; len]).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_part_receipt_status_gets_the_multipart_response_cap() {
        // ~3,000 part receipts (~170 B each) is far past the 64 KiB cap
        // every other miner response keeps.
        let client = ReqwestMinerForward::new().unwrap();
        let receipts = serve_body(3000 * 170, true).await;
        let r = client
            .forward_backup_status(receipts, "vm-1")
            .await
            .unwrap();
        assert_eq!(r.body.len(), 3000 * 170);
        let r = client
            .forward_migration_status(receipts, "vm-1")
            .await
            .unwrap();
        assert_eq!(r.body.len(), 3000 * 170);
        let r = client
            .forward_restore_status(receipts, "vm-1")
            .await
            .unwrap();
        assert_eq!(r.body.len(), 3000 * 170);
        // The small polls keep the 64 KiB cap ...
        let err = client
            .forward_domain_state(receipts, "vm-1")
            .await
            .unwrap_err();
        assert!(matches!(err, MinerForwardError::ResponseTooLarge));
        // ... and the receipt polls are still bounded.
        for content_length in [true, false] {
            let huge = serve_body(MAX_MULTIPART_STATUS_RESPONSE_BYTES + 1, content_length).await;
            let err = client
                .forward_backup_status(huge, "vm-1")
                .await
                .unwrap_err();
            assert!(matches!(err, MinerForwardError::ResponseTooLarge));
            let err = client
                .forward_restore_status(huge, "vm-1")
                .await
                .unwrap_err();
            assert!(matches!(err, MinerForwardError::ResponseTooLarge));
        }
    }

    #[tokio::test]
    async fn production_client_rejects_oversize_body_before_dialing() {
        // Tripwire: a future caller bypassing the router's
        // `DefaultBodyLimit` cannot sign + relay an oversize body.
        // Crucially this fires WITHOUT attempting a network connection
        // — proven by the test passing even when no miner is reachable.
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(hex::encode([42u8; 32]).as_bytes()).unwrap();
        f.flush().unwrap();
        let signer = OrderSigner::load(f.path(), None).unwrap();

        let client = ReqwestMinerForward::new().unwrap();
        // The test binds a free port locally so a `connect` would
        // succeed, but the body cap check fires before the request is
        // even built.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let too_big = vec![0u8; MAX_MINER_ORDER_BODY + 1];
        let err = client
            .forward_signed_order(&signer, addr, OrderKind::Launch, &too_big)
            .await
            .unwrap_err();
        assert!(matches!(err, MinerForwardError::Encode));
    }
}
