//! On-chain miner registry — the permissionless Edge admission set.
//!
//! The structural twin of [`super::revocation::CrlStore`], but instead
//! of a revocation list it holds the **allow** set: the node_ids that
//! are registered + `Active` on `pallet-compute-scoring` (§23). A
//! background poller refreshes it every [`DEFAULT_POLL_INTERVAL`] (or
//! the operator-configured interval) from the **vali feed** — the
//! in-cluster `GET /v1/edge/registry` endpoint.
//!
//! ## Why a vali feed, not a direct chain read
//!
//! The Edge pod's egress is deliberately locked (kbs / vali / mesh /
//! dns only) — it cannot reach the external chain RPC. vali, which has
//! internet egress, reads the chain (`read-miner-status`) and re-serves
//! the snapshot; the Edge polls vali over plain in-cluster HTTP. Both
//! parse the same [`hippius_onchain_registry`] shapes, so there is one
//! definition and no drift.
//!
//! Fail-closed, exactly like the CRL gate: a failed poll flips the
//! store **unhealthy** (the last good set is retained but
//! [`super::MtlsAcceptor::accept`] refuses every connection while
//! unhealthy), so a stale snapshot can never silently admit a
//! slashed / quarantined miner. Revocation is free: a node that leaves
//! the `Active` set on-chain is dropped on the next refresh — no CRL.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hippius_onchain_registry::{fetch_feed_verified, RegistryError, RegistrySnapshot};

/// Default registry refresh cadence. The on-chain status state machine
/// (quarantine / decommission / slash) takes effect at the Edge within
/// this window + one handshake. Operator-overridable via config.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Injectable fetch — production polls the vali feed via [`fetch_feed`];
/// tests inject a stub so the poller / gate are exercised without a
/// server. Takes the feed URL.
type FetchFn = Arc<dyn Fn(&str) -> Result<RegistrySnapshot, RegistryError> + Send + Sync>;

/// Live snapshot of the registered+`Active` node_id set + a fail-closed
/// health flag, fed by the vali registry endpoint.
pub struct RegistryStore {
    /// The admitted node_ids. `ArcSwap` so a refresh is a cheap atomic
    /// swap and in-flight `contains` reads see a consistent set.
    active: ArcSwap<HashSet<[u8; 32]>>,
    /// `true` iff the latest poll cycle read cleanly. Read on every
    /// `accept()`; `Relaxed` is sufficient (a hint, not a lock).
    healthy: AtomicBool,
    /// The vali feed URL (`http://vali…/v1/edge/registry`).
    feed_url: String,
    fetch: FetchFn,
}

impl RegistryStore {
    /// Production constructor — polls the vali feed via
    /// [`fetch_feed_verified`], verifying the feed's Ed25519 signature
    /// against `feed_pubkey` when it is `Some` (audit M-registry-mTLS).
    /// Starts **unhealthy** with an empty set: the Edge fails closed
    /// until the first successful poll populates the allow set.
    pub fn new(feed_url: impl Into<String>, feed_pubkey: Option<[u8; 32]>) -> Self {
        Self::with_fetcher(
            feed_url,
            Arc::new(move |url: &str| fetch_feed_verified(url, feed_pubkey)),
        )
    }

    /// Test/seam constructor with an injected fetch.
    pub fn with_fetcher(feed_url: impl Into<String>, fetch: FetchFn) -> Self {
        Self {
            active: ArcSwap::from_pointee(HashSet::new()),
            healthy: AtomicBool::new(false),
            feed_url: feed_url.into(),
            fetch,
        }
    }

    /// `true` iff the latest poll succeeded. The accept gate fails
    /// closed while this is false.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Is `node_id` registered + `Active` per the last good snapshot?
    pub fn contains(&self, node_id: &[u8; 32]) -> bool {
        self.active.load().contains(node_id)
    }

    /// Count of admitted miners in the live snapshot (diagnostics).
    pub fn active_count(&self) -> usize {
        self.active.load().len()
    }

    /// Re-read the registry. On success: swap in the fresh active set
    /// and mark healthy. On failure: mark **unhealthy** (gate fails
    /// closed) but retain the last good set. Blocking (network IO) —
    /// the poller runs it on a blocking thread.
    pub fn refresh(&self) -> Result<(), RegistryError> {
        match (self.fetch)(&self.feed_url) {
            Ok(snapshot) => {
                self.active.store(Arc::new(snapshot.active_node_ids()));
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

/// Spawn the background refresh task. The first tick fires immediately
/// (the boot store is unhealthy/empty, so the early tick is the first
/// chance to populate it). The blocking chain read runs on a blocking
/// thread so it never stalls the Edge's `current_thread` runtime.
pub fn spawn_poller(store: Arc<RegistryStore>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let s = Arc::clone(&store);
            match tokio::task::spawn_blocking(move || s.refresh()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => log_registry_error(e.category),
                // The blocking task panicked / was cancelled — treat as
                // a poll failure so the next tick retries.
                Err(_) => log_registry_error("join"),
            }
        }
    })
}

/// Static-classifier sink for poll anomalies. Mirrors the CRL poller's
/// single-`eprintln!` discipline — never echoes the RPC URL (§20).
fn log_registry_error(class: &str) {
    eprintln!("hippius-edge-gateway: anomaly: registry-poll: {class}");
}

// ── Env-driven mode selection (mirrors `CertPaths::from_env`) ─────────

/// `EDGE_MINER_AUTH` = `ca` (default) | `onchain`. The migration flag
/// from `docs/design/permissionless-miner-auth.md`.
pub const ENV_MINER_AUTH: &str = "EDGE_MINER_AUTH";
/// vali registry feed URL (`http://vali…/v1/edge/registry`); required
/// in `onchain` mode. The Edge polls vali (allowed egress) rather than
/// the chain directly (egress-locked).
pub const ENV_FEED_URL: &str = "EDGE_REGISTRY_FEED_URL";
/// Registry refresh cadence in seconds; default [`DEFAULT_POLL_INTERVAL`].
pub const ENV_REFRESH_SECS: &str = "EDGE_REGISTRY_REFRESH_SECS";

/// Resolved on-chain miner-auth config (only in `onchain` mode).
pub struct RegistryEnv {
    pub feed_url: String,
    pub refresh: Duration,
    /// Pinned Ed25519 pubkey the vali registry feed is signed with (audit
    /// M-registry-mTLS). `Some` ⇒ every poll's signature is verified
    /// fail-closed; `None` (env unset) ⇒ the pre-pin backward-compat
    /// window (feed parsed unverified).
    pub feed_pubkey: Option<[u8; 32]>,
}

/// Failure resolving the miner-auth env. Fail-closed: a malformed
/// `onchain` config is boot-fatal, never a silent fallback to CA.
#[derive(Debug, thiserror::Error)]
pub enum RegistryEnvError {
    /// `EDGE_MINER_AUTH` was neither `ca` nor `onchain`.
    #[error("registry-mode-invalid")]
    ModeInvalid,
    /// `onchain` mode but `EDGE_REGISTRY_FEED_URL` is unset / empty.
    #[error("registry-feed-url-missing")]
    FeedUrlMissing,
    /// `EDGE_REGISTRY_REFRESH_SECS` was not a positive integer.
    #[error("registry-refresh-invalid")]
    RefreshInvalid,
    /// `EDGE_REGISTRY_FEED_PUBKEY` was set but not 32 bytes of hex.
    #[error("registry-feed-pubkey-invalid")]
    FeedPubkeyInvalid,
}

impl RegistryEnvError {
    /// Static classifier for the boot-fatal log line.
    pub fn class(&self) -> &'static str {
        match self {
            RegistryEnvError::ModeInvalid => "registry-mode-invalid",
            RegistryEnvError::FeedUrlMissing => "registry-feed-url-missing",
            RegistryEnvError::RefreshInvalid => "registry-refresh-invalid",
            RegistryEnvError::FeedPubkeyInvalid => "registry-feed-pubkey-invalid",
        }
    }
}

/// Env naming the pinned Ed25519 pubkey (64-hex) the vali registry feed is
/// signed with (audit M-registry-mTLS). Unset ⇒ the feed is trusted
/// unverified (pre-pin backward-compat window).
pub const ENV_FEED_PUBKEY: &str = "EDGE_REGISTRY_FEED_PUBKEY";

/// Read the miner-auth mode from the environment. `Ok(None)` ⇒ CA mode
/// (the default, backward-compatible with every existing deployment);
/// `Ok(Some(_))` ⇒ permissionless on-chain mode with its registry
/// config.
pub fn from_env() -> Result<Option<RegistryEnv>, RegistryEnvError> {
    let mode = std::env::var(ENV_MINER_AUTH).unwrap_or_default();
    match mode.trim() {
        "" | "ca" => Ok(None),
        "onchain" => {
            let feed_url = std::env::var(ENV_FEED_URL)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .ok_or(RegistryEnvError::FeedUrlMissing)?;
            let refresh = match std::env::var(ENV_REFRESH_SECS) {
                Ok(s) => {
                    let n: u64 = s
                        .trim()
                        .parse()
                        .map_err(|_| RegistryEnvError::RefreshInvalid)?;
                    if n == 0 {
                        return Err(RegistryEnvError::RefreshInvalid);
                    }
                    Duration::from_secs(n)
                }
                Err(_) => DEFAULT_POLL_INTERVAL,
            };
            let feed_pubkey = match std::env::var(ENV_FEED_PUBKEY) {
                Ok(s) if !s.trim().is_empty() => {
                    let bytes =
                        hex::decode(s.trim()).map_err(|_| RegistryEnvError::FeedPubkeyInvalid)?;
                    let arr: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| RegistryEnvError::FeedPubkeyInvalid)?;
                    Some(arr)
                }
                _ => None,
            };
            Ok(Some(RegistryEnv {
                feed_url,
                refresh,
                feed_pubkey,
            }))
        }
        _ => Err(RegistryEnvError::ModeInvalid),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_onchain_registry::{MinerRecord, MinerStatus};

    fn snapshot_with(node_ids: &[[u8; 32]]) -> RegistrySnapshot {
        RegistrySnapshot {
            current_epoch: 1,
            pallet_live: true,
            miners: node_ids
                .iter()
                .map(|id| MinerRecord {
                    node_id: *id,
                    status: MinerStatus::Active,
                    last_transition_epoch: 0,
                    data_epoch: 1,
                    quality: 1,
                    price: None,
                })
                .collect(),
        }
    }

    #[test]
    fn boots_unhealthy_and_empty() {
        let store = RegistryStore::new("http://vali/v1/edge/registry", None);
        assert!(!store.is_healthy());
        assert_eq!(store.active_count(), 0);
        assert!(!store.contains(&[1u8; 32]));
    }

    #[test]
    fn refresh_populates_the_active_set_and_marks_healthy() {
        let id = [7u8; 32];
        let store = RegistryStore::with_fetcher(
            "http://vali/v1/edge/registry",
            Arc::new(move |_| Ok(snapshot_with(&[id]))),
        );
        store.refresh().unwrap();
        assert!(store.is_healthy());
        assert!(store.contains(&id));
        assert!(!store.contains(&[8u8; 32]));
    }

    #[test]
    fn failed_refresh_marks_unhealthy_but_keeps_last_good_set() {
        let id = [7u8; 32];
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let store = RegistryStore::with_fetcher(
            "http://vali/v1/edge/registry",
            Arc::new(move |_| {
                // First call succeeds, second fails.
                if calls2.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(snapshot_with(&[id]))
                } else {
                    Err(RegistryError::new("rpc-request", "down".to_string()))
                }
            }),
        );
        store.refresh().unwrap();
        assert!(store.is_healthy());
        // Second refresh fails: unhealthy, but the set is retained so a
        // transient RPC blip doesn't lose the allow list (the gate
        // still fails closed via is_healthy()).
        assert!(store.refresh().is_err());
        assert!(!store.is_healthy());
        assert!(store.contains(&id));
    }
}
