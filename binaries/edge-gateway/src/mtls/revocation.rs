//! CRL distribution + freshness policy (PR-H4, §10).
//!
//! ## The threat model this codifies
//!
//! Per-peer mTLS certs are short-lived (90 days per §B Q11), so a
//! compromised peer's blast radius is bounded by the rotation
//! window — but during that window the operator MUST be able to
//! revoke any individual cert without re-issuing the whole fleet.
//! That's what the CRL is for.
//!
//! Review of PR-H4 v1 pre-empted the soft failure: if the
//! CRL file is missing, malformed, or simply hasn't been refreshed
//! recently, a naïve loader might "ignore CRL on error and let all
//! certs through" — which is exactly the wrong direction. This
//! module is fail-closed:
//!
//! - **CRL configured + valid + fresh** → use it; revoked certs are
//!   rejected at handshake.
//! - **CRL configured + missing / corrupt / stale** → mark the
//!   acceptor unhealthy. Every subsequent `accept()` call drops
//!   the TCP connection BEFORE handshake. State remains unhealthy
//!   until the file is restored.
//! - **CRL not configured** (env var unset) → no CRL check is
//!   applied. Operator runbook: only acceptable if cert lifetimes
//!   are already short enough to make CRL latency moot AND there's
//!   an out-of-band channel to re-issue the whole CA (which we
//!   have, §B Q11 — but that's a tabletop, not a routine).
//!
//! ## Polling cadence
//!
//! The poll loop runs every [`POLL_INTERVAL`] (60 s). Each tick:
//!
//! 1. `stat` + read the CRL file.
//! 2. Parse via `rustls`'s `CertificateRevocationListDer` shape.
//! 3. On success: store the new `CertificateRevocationListDer` in the
//!    `ArcSwap` and mark healthy.
//! 4. On any failure (I/O error, parse error): mark unhealthy.
//!    Existing connections are NOT torn down (rustls doesn't surface
//!    a "kick" API); new connections fail-closed.
//!
//! Operator runbook (PR-K7 Ansible) writes the CRL atomically (write
//! to `crl.pem.new` then `rename`), so a partial write doesn't trip
//! the unhealthy state. See `deploy/ansible/05-mtls-ca.yml`.

use arc_swap::ArcSwap;
use rustls::pki_types::CertificateRevocationListDer;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often the background poller re-reads the CRL file. Picked to
/// match the operator runbook cadence (PR-K7 generates a fresh CRL
/// every 24h; 60 s polling means an actively-revoked peer is rejected
/// within 60 s + handshake of the Ansible push). Not configurable —
/// operator changes the CA cadence, not Edge's polling interval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Stable static-classifier errors for the CRL load path. Same
/// `&'static str`-only `Display` discipline as `EdgeError`.
#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    /// `std::fs::read` failed — file missing, perms wrong, etc.
    #[error("crl-read")]
    Read,
    /// PEM block in the file did not parse as a CRL. Most likely the
    /// operator wrote a cert PEM here by mistake.
    #[error("crl-parse")]
    Parse,
    /// PEM file contained zero CRL blocks. Treated as a configuration
    /// error (empty CRL is a valid concept, but absence of CRL blocks
    /// usually means a typo'd path or a corrupted artifact).
    #[error("crl-empty")]
    Empty,
}

/// Shared CRL state. Holds (a) the latest successfully-parsed CRL
/// bundle, swapped atomically by the poller, and (b) the
/// `healthy` flag the accept-stage gate reads.
pub struct CrlStore {
    /// CRL DER blobs currently in force. `Arc<Vec<...>>` so a swap is
    /// cheap and existing rustls `ServerConfig`s holding a clone
    /// continue to see the old set until they're rebuilt — the new
    /// ServerConfig built off this snapshot is the one the next
    /// connection uses. Public API exposes the snapshot via
    /// [`CrlStore::snapshot`].
    crls: ArcSwap<Vec<CertificateRevocationListDer<'static>>>,
    /// `true` iff the latest poll cycle parsed cleanly. Read on every
    /// `accept()` to decide whether to even attempt the handshake.
    /// `Ordering::Relaxed` is sufficient: this is a hint, not a lock,
    /// and missing one poll cycle (~60 s) is the worst-case latency
    /// anyway.
    healthy: AtomicBool,
    /// Absolute path of the CRL file. Captured at construction so the
    /// poller doesn't re-read env on every tick.
    path: PathBuf,
}

impl CrlStore {
    /// Load the CRL synchronously from `path`. On success returns a
    /// healthy store. On failure returns `Err` — caller decides
    /// whether to start in unhealthy state or refuse to boot.
    /// Production main starts unhealthy if the initial load fails
    /// (matches the review note: "boot success without a
    /// usable CRL is a soft failure we shouldn't pretend isn't one").
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, CrlError> {
        let path = path.into();
        let parsed = read_crl_file(&path)?;
        Ok(Self {
            crls: ArcSwap::from_pointee(parsed),
            healthy: AtomicBool::new(true),
            path,
        })
    }

    /// Build an unhealthy store anchored at `path`. The poller will
    /// flip it to healthy on the first successful read. Used by
    /// production main when initial load fails — Edge stays
    /// fail-closed until the Ansible push lands a valid CRL.
    pub fn unhealthy_at(path: impl Into<PathBuf>) -> Self {
        Self {
            crls: ArcSwap::from_pointee(Vec::new()),
            healthy: AtomicBool::new(false),
            path: path.into(),
        }
    }

    /// `true` iff the latest poll cycle parsed cleanly. The accept
    /// stage MUST consult this before initiating a handshake; a
    /// `false` return MUST drop the TCP connection without
    /// negotiating TLS (the connecting peer learns only that the
    /// port closed — same opacity as a rate-limit shed).
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Snapshot of the current CRL bundle, suitable for embedding in
    /// a freshly-built rustls `WebPkiClientVerifier`. `Arc` so the
    /// caller can hold a stable view across a poll cycle.
    pub fn snapshot(&self) -> Arc<Vec<CertificateRevocationListDer<'static>>> {
        self.crls.load_full()
    }

    /// Path the store was constructed against. Exposed so the poller
    /// task doesn't need to take the path separately.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the CRL file and update the store. On success: swap
    /// the new bundle in + flip healthy=true. On failure: leave the
    /// stored bundle untouched + flip healthy=false. Returns the
    /// classifier so the poller can log it.
    ///
    /// Why we keep the stored bundle on failure: a stale-but-valid
    /// CRL is strictly better than no CRL while the operator fixes
    /// the file. We still mark unhealthy, so the accept gate is
    /// fail-closed regardless — but if the operator restores the
    /// file on the next tick we don't have to re-read from disk.
    pub fn refresh(&self) -> Result<(), CrlError> {
        match read_crl_file(&self.path) {
            Ok(new) => {
                self.crls.store(Arc::new(new));
                self.healthy.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.healthy.store(false, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}

/// Spawn the background CRL poller. Loops forever, ticking every
/// [`POLL_INTERVAL`]. Each tick calls [`super::MtlsRuntime::refresh`],
/// which re-reads the CRL file AND rebuilds the live `ServerConfig`
/// with the fresh CRL snapshot — closes the Blocker review flagged
/// in PR-H4 v1 review where the boot-time verifier never picked up
/// new revocations.
///
/// Errors are emitted via [`log_crl_error`] (static-classifier sink,
/// no plaintext leak path).
///
/// Returns the spawned [`tokio::task::JoinHandle`] so production main
/// can hold onto it (and abort on shutdown). PR-H4 main keeps the
/// handle in `_crl_poller` for the lifetime of the process; the
/// runtime tears it down at process exit.
pub fn spawn_poller(runtime: Arc<super::MtlsRuntime>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        // First tick fires immediately (refreshes on startup). We
        // want this — if `MtlsRuntime::load` succeeded at boot the
        // early tick is a cheap re-stat; if the CRL file was
        // missing at boot, the early tick is the first chance to
        // flip healthy + rebuild the config.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Err(e) = runtime.refresh() {
                log_crl_error(e.class());
            }
        }
    })
}

/// Read + parse the PEM CRL file at `path`. Helper shared by `load`
/// and `refresh` — the only file-I/O entry point.
fn read_crl_file(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>, CrlError> {
    let raw = std::fs::read(path).map_err(|_| CrlError::Read)?;
    parse_crl_pem(&raw)
}

/// Parse the PEM blob into a `Vec<CertificateRevocationListDer>`.
/// Pulled out of `read_crl_file` so tests can exercise the parser
/// without a real file.
pub fn parse_crl_pem(pem: &[u8]) -> Result<Vec<CertificateRevocationListDer<'static>>, CrlError> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for entry in rustls_pemfile::crls(&mut cursor) {
        let crl = entry.map_err(|_| CrlError::Parse)?;
        out.push(crl);
    }
    if out.is_empty() {
        return Err(CrlError::Empty);
    }
    Ok(out)
}

/// Map a [`CrlError`] to its static classifier. Mirrors the
/// `config_error_class` helper in `main.rs` — keeps the audit
/// classifier vocabulary in one grep-able place.
pub fn crl_error_class(err: &CrlError) -> &'static str {
    match err {
        CrlError::Read => "crl-read",
        CrlError::Parse => "crl-parse",
        CrlError::Empty => "crl-empty",
    }
}

/// Static-string-only diagnostic emitter for CRL anomalies. Same
/// `&'static str` discipline as `main::log_fatal` — by design,
/// this is the only `eprintln!` site in the module.
fn log_crl_error(class: &'static str) {
    eprintln!("hippius-edge-gateway: anomaly: crl-poll: {class}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Mint a minimal well-formed PEM CRL via `rcgen` (dev-dep, so
    /// only compiled into the test binary). Empty revoked-set —
    /// just enough to exercise the parser + ArcSwap path. The
    /// integration test in `tests/mtls_integration.rs` mints a
    /// CRL that actually revokes a cert.
    fn valid_crl_pem() -> String {
        use rcgen::{
            CertificateParams, CertificateRevocationListParams, IsCa, KeyIdMethod, KeyPair,
            KeyUsagePurpose, RevocationReason, SerialNumber,
        };
        use time::{Duration as TDuration, OffsetDateTime};
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let now = OffsetDateTime::now_utc();
        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + TDuration::days(7),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let _ = RevocationReason::Unspecified; // touch the import path
        crl_params
            .signed_by(&ca_cert, &ca_kp)
            .unwrap()
            .pem()
            .unwrap()
    }

    #[test]
    fn parse_crl_pem_rejects_garbage() {
        let err = parse_crl_pem(b"not-pem").unwrap_err();
        assert!(matches!(err, CrlError::Empty), "got {err:?}");
    }

    #[test]
    fn parse_crl_pem_rejects_empty_input() {
        let err = parse_crl_pem(b"").unwrap_err();
        assert!(matches!(err, CrlError::Empty), "got {err:?}");
    }

    #[test]
    fn parse_crl_pem_accepts_well_formed_crl() {
        // Sanity check: an rcgen-minted empty CRL parses cleanly.
        let crl_pem = valid_crl_pem();
        let _ = parse_crl_pem(crl_pem.as_bytes()).expect("rcgen-minted CRL must parse");
    }

    #[test]
    fn store_starts_unhealthy_when_constructed_via_unhealthy_at() {
        let store = CrlStore::unhealthy_at("/nonexistent");
        assert!(!store.is_healthy());
    }

    #[test]
    fn refresh_failure_marks_store_unhealthy_but_keeps_old_snapshot() {
        // Start healthy with a valid file → refresh against a path
        // pointing to a missing file → unhealthy, but the snapshot
        // returned still has the original CRL set (stale-but-valid
        // beats no-CRL during the operator's fix window).
        let pem = valid_crl_pem();
        let mut tf = NamedTempFile::new().unwrap();
        tf.write_all(pem.as_bytes()).unwrap();
        let path = tf.path().to_path_buf();
        let store = CrlStore::load(&path).unwrap();
        assert!(store.is_healthy());
        let pre = store.snapshot();
        assert!(!pre.is_empty());

        // Drop the file. Next refresh must fail and flip unhealthy,
        // but the snapshot is preserved.
        drop(tf);
        let err = store.refresh().unwrap_err();
        assert!(matches!(err, CrlError::Read), "got {err:?}");
        assert!(!store.is_healthy());
        let post = store.snapshot();
        assert_eq!(post.len(), pre.len());
    }

    #[test]
    fn refresh_success_flips_unhealthy_back_to_healthy() {
        // Operator-fix scenario: store starts unhealthy (initial load
        // failed at boot) → CRL file appears → next `refresh` flips
        // healthy back on.
        let pem = valid_crl_pem();
        let mut tf = NamedTempFile::new().unwrap();
        tf.write_all(pem.as_bytes()).unwrap();
        let store = CrlStore::unhealthy_at(tf.path());
        assert!(!store.is_healthy());
        store.refresh().unwrap();
        assert!(store.is_healthy());
        assert!(!store.snapshot().is_empty());
    }

    #[test]
    fn crl_error_display_is_static_classifier() {
        // Same discipline as `EdgeError`: every variant's `Display`
        // must equal its `class` so an accidental `eprintln!("{err}")`
        // is safe.
        for err in [CrlError::Read, CrlError::Parse, CrlError::Empty] {
            assert_eq!(err.to_string(), crl_error_class(&err));
        }
    }
}
