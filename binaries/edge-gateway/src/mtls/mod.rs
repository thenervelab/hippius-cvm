//! mTLS termination for the Edge accept stage (PR-H4, §10).
//!
//! Three sub-modules, each load-bearing for a different reviewer
//! concern:
//!
//! - [`peer_id`] — extract a stable per-peer identity from the
//!   handshake's leaf cert (replaces the NAT-collapsed `IpAddr`
//!   PR-H3 used as the rate-limit key).
//! - [`revocation`] — CRL distribution + 60 s polling + fail-closed
//!   health gate. Review of PR-H4 v1 specced this surface:
//!   missing / corrupt CRL ⇒ drop every connection until the file
//!   comes back.
//! - [`cert_store`] — load PEMs (CA / chain / key), build the rustls
//!   `ServerConfig` with `WebPkiClientVerifier` + CRL snapshot. No
//!   path here exports the private key — it's moved into
//!   `ServerConfig` and never re-surfaced.
//!
//! The public entry points are [`MtlsRuntime::load`] (boot) and
//! [`MtlsAcceptor::accept`] (per-connection). PR-H5 wires this into
//! a real `tokio::net::TcpListener` accept loop; PR-H4 ships the
//! handshake mechanics + integration tests over loopback.
//!
//! ## Live CRL rotation (Blocker fix, review PR-H4 v1 review)
//!
//! Review flagged: the boot-time `ServerConfig` bakes the initial CRL
//! snapshot into its `WebPkiClientVerifier`; refreshing the CRL
//! store later does NOT propagate new revocations to live
//! connections. Fix: [`MtlsRuntime`] holds the active `ServerConfig`
//! inside an [`arc_swap::ArcSwap`]; on every successful CRL poll
//! the runtime rebuilds a fresh `ServerConfig` (re-reading the CA /
//! cert / key PEMs + the new CRL snapshot) and atomically swaps it
//! in. [`MtlsAcceptor::accept`] snapshots the live config at
//! handshake start, so the next connection uses the rebuilt
//! verifier — within 60 s + handshake of an operator's CRL push.
//!
//! Review also flagged a TOCTOU on the health gate: `accept` checks
//! `is_healthy()` BEFORE the handshake; the poller could flip
//! unhealthy mid-handshake and the connection would still be
//! accepted. Fix: re-check `is_healthy()` AFTER the handshake
//! completes, drop the connection if the gate flipped.

pub mod cert_store;
pub mod onchain_verifier;
pub mod peer_id;
pub mod registry;
pub mod revocation;

pub use cert_store::{CertPaths, CertStoreError};
pub use peer_id::{PeerId, PeerIdError};
pub use registry::RegistryStore;
pub use revocation::{CrlError, CrlStore};

use crate::pipeline::EdgeError;
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Runtime-rotating mTLS material. Owns the live `ServerConfig` +
/// the [`CrlStore`] + the [`CertPaths`] needed to rebuild the
/// config on a CRL refresh.
///
/// The acceptor [`MtlsAcceptor`] holds an `Arc<MtlsRuntime>` and
/// snapshots the live config at handshake time. The CRL poller
/// (spawned by [`revocation::spawn_poller`]) also holds an
/// `Arc<MtlsRuntime>` and calls [`MtlsRuntime::refresh`] on each
/// 60 s tick — that path re-reads the on-disk material AND
/// rebuilds the verifier with the fresh CRL set, so a freshly-
/// revoked cert is rejected on the next handshake.
pub struct MtlsRuntime {
    paths: CertPaths,
    server_config: ArcSwap<ServerConfig>,
    /// `None` ⇒ no CRL configured. The accept gate skips the
    /// healthy-check; `refresh()` is a no-op.
    crl_store: Option<Arc<CrlStore>>,
    /// `Some` ⇒ **permissionless on-chain** miner auth: the
    /// `ServerConfig` accepts self-signed client certs and admission
    /// is gated on this live registered+`Active` set (no CA, no CRL).
    /// Mutually exclusive with `crl_store` in practice — a runtime is
    /// built by either [`Self::load`] (CA) or [`Self::load_onchain`].
    registry: Option<Arc<RegistryStore>>,
}

/// Refresh outcome. Distinguishes "CRL re-read failed" from "rebuild
/// of the `ServerConfig` failed" so the audit log can attribute the
/// fail-closed event to the right operational layer.
#[derive(Debug, thiserror::Error)]
pub enum MtlsRefreshError {
    /// `crl_store.refresh()` failed (file missing, corrupt, …).
    #[error("crl-refresh")]
    Crl(CrlError),
    /// CRL refresh succeeded but rebuilding the `ServerConfig` from
    /// the re-read PEMs failed (cert / key file became unreadable
    /// between the boot read and this tick, e.g.). The CrlStore is
    /// healthy in this case; the runtime falls back on the previous
    /// (stale) `ServerConfig` and the next tick retries.
    #[error("crl-rebuild")]
    Rebuild(CertStoreError),
}

impl MtlsRefreshError {
    /// Static-classifier mapping. Same `&'static str`-only contract
    /// as `EdgeError::class`.
    pub fn class(&self) -> &'static str {
        match self {
            MtlsRefreshError::Crl(e) => revocation::crl_error_class(e),
            MtlsRefreshError::Rebuild(e) => e.class(),
        }
    }
}

impl MtlsRuntime {
    /// Load the runtime from `paths`. Builds the initial
    /// `ServerConfig` synchronously. If a CRL path was configured
    /// AND the initial read failed, the [`CrlStore`] starts
    /// unhealthy and the boot config has an empty CRL set — Edge
    /// will reject every connection at the [`MtlsAcceptor::accept`]
    /// gate until the poller flips healthy.
    pub fn load(paths: CertPaths) -> Result<Arc<Self>, CertStoreError> {
        let crl_store = paths.crl.as_ref().map(|crl_path| {
            // Boot policy: a CRL path was *specified*, so its
            // absence / corruption at boot is a fail-closed event.
            // Edge starts unhealthy; the poller flips healthy when
            // the file appears.
            Arc::new(CrlStore::load(crl_path).unwrap_or_else(|_| CrlStore::unhealthy_at(crl_path)))
        });
        let cfg = build_from_disk(&paths, crl_store.as_deref())?;
        Ok(Arc::new(Self {
            paths,
            server_config: ArcSwap::from_pointee(cfg),
            crl_store,
            registry: None,
        }))
    }

    /// Load the runtime in **permissionless on-chain** miner-auth mode
    /// (`docs/design/permissionless-miner-auth.md`). The `ServerConfig`
    /// is built once with the self-signed-accepting client verifier
    /// (no CA, no CRL, no rebuild); admission is gated on the live
    /// [`RegistryStore`], populated by [`registry::spawn_poller`].
    ///
    /// The caller owns the [`RegistryStore`] (so it can spawn
    /// [`registry::spawn_poller`] on the same Arc). It starts
    /// **unhealthy** (empty allow set) so the Edge fails closed until
    /// the first successful chain poll — the same fail-closed boot
    /// posture as a configured-but-missing CRL.
    pub fn load_onchain(
        paths: CertPaths,
        registry: Arc<RegistryStore>,
    ) -> Result<Arc<Self>, CertStoreError> {
        let chain = cert_store::load_cert_chain(&paths.cert)?;
        let key = cert_store::load_key_pem(&paths.key)?;
        let cfg = cert_store::build_server_config_onchain(chain, key)?;
        Ok(Arc::new(Self {
            paths,
            server_config: ArcSwap::from_pointee(cfg),
            crl_store: None,
            registry: Some(registry),
        }))
    }

    /// The on-chain registry store, if this runtime is in on-chain
    /// mode. [`crate::main`] spawns [`registry::spawn_poller`] on it.
    pub fn registry(&self) -> Option<&Arc<RegistryStore>> {
        self.registry.as_ref()
    }

    /// The fail-closed classifier the acceptor reports when the health
    /// gate is down — mode-aware so logs/metrics attribute it to the
    /// right subsystem (stale registry snapshot vs stale CRL).
    fn health_gate_class(&self) -> &'static str {
        if self.registry.is_some() {
            "registry-unhealthy"
        } else {
            "crl-unhealthy"
        }
    }

    /// `true` iff the latest poll cycle parsed cleanly (or the
    /// operator opted out of CRL revocation by leaving
    /// `EDGE_MTLS_CRL_PATH` unset).
    pub fn is_healthy(&self) -> bool {
        // On-chain mode: health is the registry poll's freshness — a
        // stale snapshot fails closed exactly like a stale CRL.
        if let Some(registry) = &self.registry {
            return registry.is_healthy();
        }
        match &self.crl_store {
            Some(s) => s.is_healthy(),
            None => true,
        }
    }

    /// `true` iff the runtime is wired to a CRL store. Used by
    /// [`crate::main`] to decide whether to spawn the poller (no
    /// store ⇒ nothing to poll).
    pub fn has_crl_store(&self) -> bool {
        self.crl_store.is_some()
    }

    /// Snapshot of the live `ServerConfig`. Cheap (`ArcSwap`'s
    /// `load_full` is one atomic read + Arc refcount bump). The
    /// returned Arc is stable for the caller's lifetime; the
    /// poller may swap a fresh config in concurrently, but
    /// in-flight handshakes finish against their captured snapshot.
    pub fn current_config(&self) -> Arc<ServerConfig> {
        self.server_config.load_full()
    }

    /// Build a fresh TLS 1.3 `ClientConfig` for the HA peer link
    /// (PR-H5). Re-reads the CA / cert / key PEMs from disk on every
    /// call so a 90-day cert rotation (§B Q11) is picked up on the
    /// next dialer reconnect — no process restart, same disk-re-read
    /// discipline as [`Self::refresh`].
    ///
    /// The current CRL snapshot is embedded in the server-cert
    /// verifier, so the dialer rejects a **revoked** peer cert just
    /// as [`MtlsAcceptor::accept`] rejects a revoked client cert —
    /// the peer link enforces revocation on both directions. The
    /// caller is expected to gate on [`Self::is_healthy`] first
    /// (the HA dialer does): an unhealthy CRL store means the
    /// embedded snapshot may be stale, so dialing must fail closed.
    pub fn build_client_config(&self) -> Result<Arc<rustls::ClientConfig>, CertStoreError> {
        let roots = cert_store::load_ca_roots(&self.paths.ca)?;
        let chain = cert_store::load_cert_chain(&self.paths.cert)?;
        let key = cert_store::load_key_pem(&self.paths.key)?;
        let crl_snapshot = match &self.crl_store {
            Some(s) => (*s.snapshot()).clone(),
            None => Vec::new(),
        };
        let cfg = cert_store::build_client_config(roots, chain, key, crl_snapshot)?;
        Ok(Arc::new(cfg))
    }

    /// Re-read the CRL file + rebuild the `ServerConfig` with the
    /// fresh CRL snapshot. Called by [`revocation::spawn_poller`]
    /// on every 60 s tick.
    ///
    /// On failure: CrlStore is marked unhealthy (gate fails closed);
    /// the live `ServerConfig` is left untouched. Returns the
    /// classifier so the poller can log it.
    pub fn refresh(&self) -> Result<(), MtlsRefreshError> {
        let Some(crl_store) = &self.crl_store else {
            return Ok(()); // No CRL configured → nothing to do.
        };
        // Step 1: refresh CRL from disk. On error CrlStore is
        // already flipped unhealthy by `refresh`.
        crl_store.refresh().map_err(MtlsRefreshError::Crl)?;
        // Step 2: rebuild the live `ServerConfig` with the fresh
        // CRL snapshot. Re-reads CA / cert / key from disk (the
        // private key is non-Clone, and we never retain it in
        // memory past the previous rebuild). On rebuild failure
        // the CrlStore stays healthy but we leave the old config
        // in place — the next tick retries.
        let new_cfg =
            build_from_disk(&self.paths, Some(crl_store)).map_err(MtlsRefreshError::Rebuild)?;
        self.server_config.store(Arc::new(new_cfg));
        Ok(())
    }
}

fn build_from_disk(
    paths: &CertPaths,
    crl_store: Option<&CrlStore>,
) -> Result<ServerConfig, CertStoreError> {
    let roots = cert_store::load_ca_roots(&paths.ca)?;
    let chain = cert_store::load_cert_chain(&paths.cert)?;
    let key = cert_store::load_key_pem(&paths.key)?;
    let crl_snapshot = match crl_store {
        Some(s) => (*s.snapshot()).clone(),
        None => Vec::new(),
    };
    cert_store::build_server_config(roots, chain, key, crl_snapshot)
}

/// Server-side mTLS acceptor — the production binding between the
/// rotating rustls `ServerConfig` ([`MtlsRuntime`]) and the
/// connection-level handshake.
pub struct MtlsAcceptor {
    runtime: Arc<MtlsRuntime>,
}

impl MtlsAcceptor {
    /// Build from a shared [`MtlsRuntime`]. Multiple acceptors can
    /// share one runtime (PR-H5 HA fan-in); the live `ServerConfig`
    /// is atomically swappable behind the `ArcSwap`.
    pub fn new(runtime: Arc<MtlsRuntime>) -> Self {
        Self { runtime }
    }

    /// `true` iff the underlying runtime is willing to negotiate.
    /// Mirrors [`MtlsRuntime::is_healthy`].
    pub fn is_healthy(&self) -> bool {
        self.runtime.is_healthy()
    }

    /// Drive one inbound TCP connection through the handshake and
    /// extract the peer identity. On success the caller owns the
    /// TLS stream + the `PeerId` and can read framed envelope bytes
    /// from the stream (PR-H5 wires the real frame reader; PR-H4
    /// integration tests just round-trip a handshake).
    ///
    /// Failure modes — all surfaced as `Err(EdgeError::MtlsFailed)`
    /// with a stable category classifier:
    ///
    /// - CRL store unhealthy (pre- or post-handshake) → drop.
    /// - TLS handshake fails (no client cert, expired, unknown CA,
    ///   revoked via the CRL, weak cipher offered — rustls refuses
    ///   TLS 1.2 entirely so the handshake just fails) → drop.
    /// - Handshake succeeded but the peer cert lacks any identity
    ///   carrier (no SAN, no CN) → drop.
    ///
    /// **Post-handshake re-check** (review PR-H4 v1 Blocker fix):
    /// the gate is consulted both BEFORE the handshake (cheap
    /// fail-closed) AND AFTER (closes the TOCTOU window where the
    /// poller flips unhealthy mid-handshake — a connection that
    /// negotiated under a stale CRL snapshot must NOT be returned).
    pub async fn accept<IO>(&self, stream: IO) -> Result<(PeerId, TlsStream<IO>), EdgeError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.runtime.is_healthy() {
            return Err(EdgeError::MtlsFailed(self.runtime.health_gate_class()));
        }
        let cfg = self.runtime.current_config();
        let inner = TlsAcceptor::from(cfg);
        let tls = inner
            .accept(stream)
            .await
            .map_err(|_| EdgeError::MtlsFailed("handshake"))?;

        // Post-handshake TOCTOU close. If the CRL poller flipped
        // unhealthy between the pre-handshake gate and now, the
        // verifier that validated this peer's cert may have been
        // operating against a stale CRL — drop the connection.
        if !self.runtime.is_healthy() {
            return Err(EdgeError::MtlsFailed(self.runtime.health_gate_class()));
        }

        // Pull the leaf cert out of the negotiated session. rustls
        // surfaces the peer cert chain in handshake-order: leaf
        // first, intermediates after.
        let (_, session) = tls.get_ref();
        let leaf = session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(EdgeError::MtlsFailed("no-peer-cert"))?;

        // Permissionless on-chain admission gate. In CA mode the
        // WebPkiClientVerifier already vouched for the cert, so there
        // is nothing more to check. In on-chain mode the cert is
        // self-signed, so trust comes from the chain: bind the SAN
        // node_id to the cert key (anti-impersonation), then require
        // the node_id to be in the live registered+`Active` set. The
        // is_healthy() gates above already fail closed on a stale
        // registry snapshot.
        if let Some(registry) = self.runtime.registry() {
            let node_id = onchain_verifier::bound_node_id_from_leaf(leaf.as_ref())
                .map_err(|_| EdgeError::MtlsFailed("identity-binding"))?;
            if !registry.contains(&node_id) {
                return Err(EdgeError::MtlsFailed("not-registered"));
            }
            // H9: the attribution `PeerId` (stamped as `x-hippius-peer-id`
            // for telemetry/heartbeat) MUST be the KEY-BOUND node id, not
            // the first SAN URI. `extract_from_leaf` returns the first SAN
            // URI of any scheme, so a self-signed miner could set a
            // victim's id as a decoy first URI while binding its OWN key
            // via a `hippius-node:` URI to pass the gate above — spoofing
            // attribution. `bound_node_id_from_leaf` also rejects a
            // multi-URI decoy cert. Derive the PeerId from the verified
            // node id so attribution == the proven key.
            let peer_id = PeerId::new(&format!(
                "{}{}",
                onchain_verifier::NODE_URI_SCHEME,
                hex::encode(node_id)
            ));
            return Ok((peer_id, tls));
        }

        // CA mode: the CA vouched for the cert's SAN, so the first-SAN-URI
        // identity is trustworthy for attribution.
        let peer_id = peer_id::extract_from_leaf(leaf.as_ref())
            .map_err(|_| EdgeError::MtlsFailed("peer-id"))?;
        Ok((peer_id, tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn mint_minimal_pki() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ca");
        let ca = ca_params.self_signed(&ca_kp).unwrap();

        let srv_kp = KeyPair::generate().unwrap();
        let mut srv_params = CertificateParams::new(vec!["edge.test".to_string()]).unwrap();
        srv_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "edge.test");
        let srv = srv_params.signed_by(&srv_kp, &ca, &ca_kp).unwrap();

        let mut tf_ca = NamedTempFile::new().unwrap();
        tf_ca.write_all(ca.pem().as_bytes()).unwrap();
        let mut tf_cert = NamedTempFile::new().unwrap();
        tf_cert.write_all(srv.pem().as_bytes()).unwrap();
        let mut tf_key = NamedTempFile::new().unwrap();
        tf_key.write_all(srv_kp.serialize_pem().as_bytes()).unwrap();
        (tf_ca, tf_cert, tf_key)
    }

    #[test]
    fn mtls_runtime_healthy_when_no_crl_configured() {
        // Build a minimal runtime with no CRL. `is_healthy` must
        // return `true` — the operator opted out of CRL revocation
        // (runbook §B Q11), so there's no gate.
        let (ca, cert, key) = mint_minimal_pki();
        let paths = CertPaths {
            ca: ca.path().to_path_buf(),
            cert: cert.path().to_path_buf(),
            key: key.path().to_path_buf(),
            crl: None,
        };
        let runtime = MtlsRuntime::load(paths).unwrap();
        assert!(runtime.is_healthy());
        assert!(!runtime.has_crl_store());
    }

    #[test]
    fn mtls_runtime_unhealthy_when_crl_path_set_but_file_missing() {
        // Boot scenario where the operator configured a CRL path
        // but the file isn't on disk yet — runtime must come up
        // unhealthy (fail-closed) so accept() refuses every
        // connection until the poller flips it.
        let (ca, cert, key) = mint_minimal_pki();
        let dir = TempDir::new().unwrap();
        let missing_crl = dir.path().join("crl.pem");
        let paths = CertPaths {
            ca: ca.path().to_path_buf(),
            cert: cert.path().to_path_buf(),
            key: key.path().to_path_buf(),
            crl: Some(missing_crl),
        };
        let runtime = MtlsRuntime::load(paths).unwrap();
        assert!(runtime.has_crl_store());
        assert!(!runtime.is_healthy());
    }

    #[test]
    fn refresh_is_no_op_when_no_crl_configured() {
        // `refresh()` on a runtime built without `EDGE_MTLS_CRL_PATH`
        // must succeed silently (no work to do) so the poller —
        // not spawned in this case, but defensively here — wouldn't
        // misbehave.
        let (ca, cert, key) = mint_minimal_pki();
        let paths = CertPaths {
            ca: ca.path().to_path_buf(),
            cert: cert.path().to_path_buf(),
            key: key.path().to_path_buf(),
            crl: None,
        };
        let runtime = MtlsRuntime::load(paths).unwrap();
        runtime.refresh().unwrap();
    }

    #[test]
    fn refresh_error_class_is_stable() {
        let crl_err = MtlsRefreshError::Crl(CrlError::Read);
        let rebuild_err = MtlsRefreshError::Rebuild(CertStoreError::Read("ca"));
        assert_eq!(crl_err.class(), "crl-read");
        assert_eq!(rebuild_err.class(), "mtls-read");
    }
}
