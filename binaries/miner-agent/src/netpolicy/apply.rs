//! Keeping the persisted policy loaded on the host.
//!
//! [`NetPolicyEnforcer`] owns the order → persist → load sequence and the
//! later reloads:
//!
//! - **Order.** The order is checked to be renderable, persisted (the
//!   revision floor moves first), then loaded with one `nft -f`. The ack
//!   `applied:<rev>:<sha>` is returned only once the rules are in the
//!   kernel, so vali's stored ack means "installed", not "received". A
//!   failed load leaves the previous ruleset in place (one transaction)
//!   and answers `net-policy-apply/…`; vali's re-send retries it, and the
//!   persisted record makes the re-send idempotent.
//! - **Agent start.** [`NetPolicyEnforcer::reconcile`] loads the persisted
//!   policy again. With no persisted policy nothing is created.
//! - **Drift.** [`NetPolicyEnforcer::run`] re-renders every
//!   [`DRIFT_CHECK_INTERVAL`]. A different text (the uplink or an exempt
//!   VM's tap changed) is loaded. Otherwise the tables' structure, read
//!   without counters or set contents and normalised
//!   ([`super::snapshot`]: NetBird's injected accepts, dynamic meter
//!   state and element order left out), is compared with the one read
//!   right after the last load, and a mismatch (a table deleted or
//!   edited) reloads it, logging the first differing line. An unchanged
//!   ruleset is never reloaded, so the counters keep counting.
//! - **Caps.** Every install, the order's included, then brings the
//!   guests' NICs to `vm_caps` ([`super::caps`]), so the ack covers the
//!   caps too and a cap removed out of band is put back on the next
//!   drift check.
//!
//! Each loaded ruleset is also written to [`RULESET_FILE`] beside the
//! policy, where the `hippius-guest-fw` unit loads it at boot before
//! libvirt starts any guest.
//!
//! ## The launch latch
//!
//! Once an edge-mode policy is persisted, [`NetPolicyEnforcer::check_launch`]
//! refuses launch and migrate-in until that policy's rules are loaded by
//! this process. This agent renders no edge-mode rules, so an edge-mode
//! record (written by a newer agent before a rollback) keeps launches
//! refused, while the boot unit keeps that agent's last ruleset in place.
//! A local-mode policy never blocks a launch.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use super::caps::VmCaps;
use super::render::{self, SmtpTap, BRIDGE_TABLE, INET_TABLE};
use super::store::{write_durable, AppliedNetPolicy, NetPolicyStore};
use crate::error::{MinerAgentError, Result};
use crate::lifecycle::{DomainId, DomainState, LibvirtDriver, VmId};
use crate::orders::types::NetPolicyOrder;

/// The ruleset last loaded, in the policy directory.
pub const RULESET_FILE: &str = "ruleset.nft";

/// How often the loaded rules are checked against the policy.
pub const DRIFT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Longest an `nft` invocation may take.
const NFT_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest stderr excerpt logged for a failed load.
const NFT_STDERR_LOG_MAX: usize = 512;

/// The kernel's main routing table, for the default-route interface.
const PROC_NET_ROUTE: &str = "/proc/net/route";

/// Loads rulesets and reads back the agent's tables.
#[async_trait]
pub trait NftRunner: Send + Sync {
    /// Load `ruleset` in one transaction. On failure nothing changed.
    async fn apply(&self, ruleset: &str) -> Result<()>;

    /// The structure of both agent tables, without counters or set
    /// contents. Fails when either table is missing.
    async fn snapshot(&self) -> Result<String>;
}

/// The production runner, `nft` on the host.
pub struct NftCommand {
    nft_path: PathBuf,
}

impl NftCommand {
    pub fn new(nft_path: PathBuf) -> Self {
        Self { nft_path }
    }

    fn nft(&self) -> Command {
        let mut cmd = Command::new(&self.nft_path);
        cmd.kill_on_drop(true);
        cmd
    }
}

impl Default for NftCommand {
    /// The Debian/Ubuntu install path of `nft`.
    fn default() -> Self {
        Self::new(PathBuf::from("/usr/sbin/nft"))
    }
}

#[async_trait]
impl NftRunner for NftCommand {
    async fn apply(&self, ruleset: &str) -> Result<()> {
        let fail = || MinerAgentError::NetPolicyApply("nft");
        let mut cmd = self.nft();
        cmd.arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|_| fail())?;
        let mut stdin = child.stdin.take().ok_or_else(fail)?;
        let run = async {
            stdin
                .write_all(ruleset.as_bytes())
                .await
                .map_err(|_| fail())?;
            drop(stdin);
            child.wait_with_output().await.map_err(|_| fail())
        };
        let output = tokio::time::timeout(NFT_TIMEOUT, run)
            .await
            .map_err(|_| fail())??;
        if !output.status.success() {
            // The ruleset is ours and carries no secret; nft quotes the
            // offending line, which is what an operator needs.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let excerpt: String = stderr.chars().take(NFT_STDERR_LOG_MAX).collect();
            eprintln!(
                "hippius-miner-agent: net-policy: nft load failed: {}",
                excerpt.trim()
            );
            return Err(fail());
        }
        Ok(())
    }

    async fn snapshot(&self) -> Result<String> {
        let mut out = String::new();
        // `-t` hides every set's elements, the meters' included; the
        // exemption set is listed again on its own so an edit to it
        // counts as drift.
        let listings: [&[&str]; 3] = [
            &["-s", "-t", "list", "table", "inet", INET_TABLE],
            &["-s", "-t", "list", "table", "bridge", BRIDGE_TABLE],
            &[
                "-s",
                "list",
                "set",
                "bridge",
                BRIDGE_TABLE,
                render::SMTP_SET,
            ],
        ];
        for args in listings {
            let mut cmd = self.nft();
            cmd.args(args).stdin(Stdio::null()).stderr(Stdio::null());
            let output = tokio::time::timeout(NFT_TIMEOUT, cmd.output())
                .await
                .map_err(|_| MinerAgentError::NetPolicyApply("nft"))?
                .map_err(|_| MinerAgentError::NetPolicyApply("nft"))?;
            if !output.status.success() {
                return Err(MinerAgentError::NetPolicyApply("nft"));
            }
            out.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        Ok(out)
    }
}

#[derive(Default)]
struct MockNftState {
    applied: Vec<String>,
    live: Option<String>,
    fail_apply: bool,
    listing: Option<String>,
}

/// An in-memory [`NftRunner`] for tests: records every load, and its
/// snapshot is the last loaded text until [`MockNft::flush`] drops it.
#[derive(Default)]
pub struct MockNft {
    state: Mutex<MockNftState>,
}

impl MockNft {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every ruleset loaded so far, in order.
    pub fn applied(&self) -> Vec<String> {
        self.lock().applied.clone()
    }

    /// What the kernel holds now, `None` when no table is loaded.
    pub fn live(&self) -> Option<String> {
        self.lock().live.clone()
    }

    /// Make the next loads fail (or succeed again).
    pub fn set_fail_apply(&self, fail: bool) {
        self.lock().fail_apply = fail;
    }

    /// Make the snapshot print `listing` (what `nft list` shows on a
    /// host) instead of the loaded text, while tables are loaded.
    pub fn set_listing(&self, listing: &str) {
        self.lock().listing = Some(listing.to_string());
    }

    /// Someone deleted the tables.
    pub fn flush(&self) {
        self.lock().live = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockNftState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl NftRunner for MockNft {
    async fn apply(&self, ruleset: &str) -> Result<()> {
        let mut state = self.lock();
        if state.fail_apply {
            return Err(MinerAgentError::NetPolicyApply("nft"));
        }
        state.applied.push(ruleset.to_string());
        state.live = Some(ruleset.to_string());
        Ok(())
    }

    async fn snapshot(&self) -> Result<String> {
        let state = self.lock();
        let live = state
            .live
            .clone()
            .ok_or(MinerAgentError::NetPolicyApply("nft"))?;
        Ok(state.listing.clone().unwrap_or(live))
    }
}

/// Where exempt VMs' taps are found.
#[async_trait]
pub trait GuestTaps: Send + Sync {
    /// The running taps of `vms`, with their MACs. A VM that is not
    /// running has none. Fails `net-policy-apply/taps` when libvirt
    /// cannot be read: the caller then keeps the loaded rules rather than
    /// dropping an exemption on a transient error.
    async fn taps(&self, vms: &[VmId]) -> Result<Vec<SmtpTap>>;
}

/// [`GuestTaps`] from the tenant domain's live XML.
pub struct LibvirtGuestTaps {
    driver: Arc<dyn LibvirtDriver>,
}

impl LibvirtGuestTaps {
    pub fn new(driver: Arc<dyn LibvirtDriver>) -> Self {
        Self { driver }
    }
}

#[async_trait]
impl GuestTaps for LibvirtGuestTaps {
    async fn taps(&self, vms: &[VmId]) -> Result<Vec<SmtpTap>> {
        let unreadable = |_| MinerAgentError::NetPolicyApply("taps");
        let domains = self.driver.list_domains().await.map_err(unreadable)?;
        let mut out = Vec::new();
        for vm_id in vms {
            let Ok(domain) = DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str())) else {
                continue;
            };
            let live = domains.iter().any(|(id, state)| {
                *id == domain && !matches!(state, DomainState::ShutOff | DomainState::NoState)
            });
            if !live {
                continue;
            }
            let xml = self.driver.domain_xml(&domain).await.map_err(unreadable)?;
            out.extend(
                crate::lifecycle::adopt::interface_taps(&xml)
                    .iter()
                    .filter_map(|(dev, mac)| SmtpTap::new(dev, &mac.to_ascii_lowercase()).ok()),
            );
        }
        Ok(out)
    }
}

/// The ruleset this process loaded last.
struct Loaded {
    /// The rules, without the `#` header (revision and hash): a new
    /// revision whose rules are the same is not reloaded.
    rules: String,
    /// [`NftRunner::snapshot`] right after the load; `None` if it failed,
    /// which makes the next check reload.
    snapshot: Option<String>,
}

/// Applies the persisted policy and keeps it applied (see the module
/// docs).
pub struct NetPolicyEnforcer {
    store: Arc<NetPolicyStore>,
    nft: Arc<dyn NftRunner>,
    taps: Arc<dyn GuestTaps>,
    caps: Arc<VmCaps>,
    route_table: PathBuf,
    /// Serialises orders, the start-up load and drift checks.
    loaded: tokio::sync::Mutex<Option<Loaded>>,
    /// Content hash of the policy whose rules this process loaded, for
    /// the synchronous launch latch.
    loaded_sha: Mutex<Option<String>>,
}

impl NetPolicyEnforcer {
    pub fn new(
        store: Arc<NetPolicyStore>,
        nft: Arc<dyn NftRunner>,
        taps: Arc<dyn GuestTaps>,
        caps: Arc<VmCaps>,
    ) -> Self {
        Self {
            store,
            nft,
            taps,
            caps,
            route_table: PathBuf::from(PROC_NET_ROUTE),
            loaded: tokio::sync::Mutex::new(None),
            loaded_sha: Mutex::new(None),
        }
    }

    /// Read the default-route interface from `path` instead of
    /// `/proc/net/route`.
    pub fn with_route_table(mut self, path: impl Into<PathBuf>) -> Self {
        self.route_table = path.into();
        self
    }

    pub fn store(&self) -> &NetPolicyStore {
        &self.store
    }

    /// Handle a `net-policy` order at `now`: persist it, load it, and
    /// return the ack.
    pub async fn accept(&self, order: NetPolicyOrder, now: u64) -> Result<String> {
        render::check_supported(&order)?;
        let mut loaded = self.loaded.lock().await;
        let applied = self.store.accept(order, now)?;
        self.install(&mut loaded, &applied).await?;
        Ok(applied.ack())
    }

    /// Load the persisted policy if it is not loaded as rendered now.
    /// `Ok(false)`: nothing persisted, or nothing to change.
    pub async fn reconcile(&self) -> Result<bool> {
        let mut loaded = self.loaded.lock().await;
        let Some(applied) = self.store.current()? else {
            return Ok(false);
        };
        self.install(&mut loaded, &applied).await
    }

    /// The launch latch (see the module docs).
    pub fn check_launch(&self) -> Result<()> {
        let Some(stored) = self.store.current()? else {
            return Ok(());
        };
        // Read from the JSON so a record of another schema is judged
        // too; anything but an explicit `local` is held to edge rules.
        if stored.policy.get("mode").and_then(|m| m.as_str()) == Some("local") {
            return Ok(());
        }
        let loaded = self
            .loaded_sha
            .lock()
            .map_err(|_| MinerAgentError::NetPolicyStore("lock"))?;
        if loaded.as_deref() == Some(stored.content_sha256.as_str()) {
            Ok(())
        } else {
            Err(MinerAgentError::NetPolicyNotLoaded)
        }
    }

    /// Re-check every [`DRIFT_CHECK_INTERVAL`] until `cancel`. A failure
    /// is logged when its class changes, not on every tick.
    pub async fn run(self: Arc<Self>, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(DRIFT_CHECK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_error: Option<String> = None;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = tick.tick() => {}
            }
            match self.reconcile().await {
                // What was re-applied, and why, is logged where it happens
                // (`load_rules`, `VmCaps::apply`).
                Ok(_) => {
                    if last_error.take().is_some() {
                        eprintln!("hippius-miner-agent: net-policy: rules loaded again");
                    }
                }
                Err(err) => {
                    let class = err.to_string();
                    if last_error.as_deref() != Some(class.as_str()) {
                        eprintln!("hippius-miner-agent: net-policy: reload failed: {class}");
                        last_error = Some(class);
                    }
                }
            }
        }
    }

    /// Load the rules, then set the caps. `Ok(true)` when either changed
    /// anything.
    async fn install(
        &self,
        loaded: &mut Option<Loaded>,
        applied: &AppliedNetPolicy,
    ) -> Result<bool> {
        let order = applied.order()?;
        render::check_supported(&order)?;
        let reloaded = self.load_rules(loaded, applied, &order).await?;
        let tuned = self.caps.apply(&order.vm_caps).await?;
        Ok(reloaded || tuned > 0)
    }

    async fn load_rules(
        &self,
        loaded: &mut Option<Loaded>,
        applied: &AppliedNetPolicy,
        order: &NetPolicyOrder,
    ) -> Result<bool> {
        let uplink = match &order.uplink_hint {
            Some(hint) => hint.clone(),
            None => default_route_ifname(&self.route_table)?,
        };
        let taps = if order.smtp_allowed_vms.is_empty() {
            Vec::new()
        } else {
            self.taps.taps(&order.smtp_allowed_vms).await?
        };
        let text = render::render(order, &applied.content_sha256, &uplink, &taps)?;
        let rules = rules_of(&text);

        let reason = match loaded.as_ref() {
            None => "first load by this process".to_string(),
            Some(current) if current.rules != rules => "rules changed".to_string(),
            Some(current) => match (&current.snapshot, self.read_tables().await) {
                (Some(then), Ok(now)) if *then == now => {
                    self.set_loaded_sha(&applied.content_sha256)?;
                    // The header may be new, or a previous write failed.
                    self.persist_ruleset(&text)?;
                    return Ok(false);
                }
                (Some(then), Ok(now)) => {
                    format!(
                        "tables edited out of band: {}",
                        first_difference(then, &now)
                    )
                }
                // Never read back: the first good reading needs a reload
                // to be a baseline; while none can be read, do not reload
                // every tick (the counters would never count).
                (None, Ok(_)) => "no baseline snapshot".to_string(),
                (None, Err(err)) => return Err(err),
                // The tables are gone (or nft failed): load them.
                (Some(_), Err(_)) => "tables missing".to_string(),
            },
        };
        self.nft.apply(&text).await?;
        eprintln!("hippius-miner-agent: net-policy: nft rules re-applied ({reason})");
        self.set_loaded_sha(&applied.content_sha256)?;
        let snapshot = self.read_tables().await.ok();
        *loaded = Some(Loaded {
            rules: rules.to_string(),
            snapshot,
        });
        self.persist_ruleset(&text)?;
        Ok(true)
    }

    /// The tables as the drift compare sees them.
    async fn read_tables(&self) -> Result<String> {
        self.nft
            .snapshot()
            .await
            .map(|text| super::snapshot::normalise(&text))
    }

    fn set_loaded_sha(&self, sha: &str) -> Result<()> {
        *self
            .loaded_sha
            .lock()
            .map_err(|_| MinerAgentError::NetPolicyStore("lock"))? = Some(sha.to_string());
        Ok(())
    }

    fn persist_ruleset(&self, text: &str) -> Result<()> {
        let path = self.store.dir().join(RULESET_FILE);
        if std::fs::read(&path).is_ok_and(|on_disk| on_disk == text.as_bytes()) {
            return Ok(());
        }
        write_durable(self.store.dir(), RULESET_FILE, text.as_bytes())
            .map_err(|_| MinerAgentError::NetPolicyApply("persist"))
    }
}

/// The first line where `then` and `now` differ, for the log.
fn first_difference(then: &str, now: &str) -> String {
    let mut a = then.lines();
    let mut b = now.lines();
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (x, y) => {
                let show = |l: Option<&str>| {
                    l.map_or("<none>".to_string(), |l| {
                        l.trim().chars().take(200).collect::<String>()
                    })
                };
                return format!("loaded {:?}, now {:?}", show(x), show(y));
            }
        }
    }
}

/// `text` without its leading `#` comment lines.
fn rules_of(text: &str) -> &str {
    let mut rest = text;
    while rest.starts_with('#') {
        rest = rest.split_once('\n').map_or("", |(_, tail)| tail);
    }
    rest
}

/// The interface of the main table's default route with the lowest
/// metric, from a `/proc/net/route`-format file. Fails `net-policy-
/// apply/uplink` when there is none or it is never an uplink (`wt0`, a
/// guest bridge).
pub fn default_route_ifname(route_table: &Path) -> Result<String> {
    let uplink = || MinerAgentError::NetPolicyApply("uplink");
    let text = std::fs::read_to_string(route_table).map_err(|_| uplink())?;
    // Iface Destination Gateway Flags RefCnt Use Metric Mask …
    const RTF_UP: u32 = 0x1;
    let mut best: Option<(u32, &str)> = None;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [iface, dest, _gw, flags, _refcnt, _use, metric, mask, ..] = fields[..] else {
            continue;
        };
        let up = u32::from_str_radix(flags, 16).is_ok_and(|f| f & RTF_UP != 0);
        if dest != "00000000" || mask != "00000000" || !up {
            continue;
        }
        let Ok(metric) = metric.parse::<u32>() else {
            continue;
        };
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, iface));
        }
    }
    let (_, iface) = best.ok_or_else(uplink)?;
    if !super::is_uplink_name(iface) {
        return Err(uplink());
    }
    Ok(iface.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::lifecycle::MockLibvirtDriver;
    use crate::netpolicy::caps::tests::FakeTuner;
    use crate::netpolicy::tests::{policy, NOW};
    use crate::orders::types::{NetPolicyLocalAction, NetPolicyMode};

    const ROUTES: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
        wt0\t0040A864\t00000000\t0001\t0\t0\t0\t00C0FFFF\t0\t0\t0\n\
        eno2\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n\
        eno1\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        virbr0\t007AA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";

    #[derive(Default)]
    struct FakeTaps {
        taps: Mutex<HashMap<String, Vec<SmtpTap>>>,
        unreadable: std::sync::atomic::AtomicBool,
    }

    impl FakeTaps {
        fn set(&self, vm: &str, taps: &[(&str, &str)]) {
            self.taps.lock().unwrap().insert(
                vm.to_string(),
                taps.iter()
                    .map(|(t, m)| SmtpTap::new(t, m).unwrap())
                    .collect(),
            );
        }
    }

    #[async_trait]
    impl GuestTaps for FakeTaps {
        async fn taps(&self, vms: &[VmId]) -> Result<Vec<SmtpTap>> {
            if self.unreadable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(MinerAgentError::NetPolicyApply("taps"));
            }
            let taps = self.taps.lock().unwrap();
            Ok(vms
                .iter()
                .flat_map(|vm| taps.get(vm.as_str()).cloned().unwrap_or_default())
                .collect())
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        nft: Arc<MockNft>,
        taps: Arc<FakeTaps>,
        libvirt: Arc<MockLibvirtDriver>,
        tuner: Arc<FakeTuner>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("route"), ROUTES).unwrap();
            let libvirt = Arc::new(MockLibvirtDriver::new());
            let tuner = Arc::new(FakeTuner::default());
            Self {
                dir,
                nft: Arc::new(MockNft::new()),
                taps: Arc::new(FakeTaps::default()),
                libvirt,
                tuner,
            }
        }

        fn policy_dir(&self) -> PathBuf {
            self.dir.path().join("net-policy")
        }

        /// A fresh enforcer over the same state: what a restarted agent
        /// builds.
        fn enforcer(&self) -> NetPolicyEnforcer {
            NetPolicyEnforcer::new(
                Arc::new(NetPolicyStore::new(self.policy_dir())),
                self.nft.clone(),
                self.taps.clone(),
                Arc::new(VmCaps::new(self.libvirt.clone(), self.tuner.clone())),
            )
            .with_route_table(self.dir.path().join("route"))
        }

        fn ruleset_file(&self) -> Option<String> {
            std::fs::read_to_string(self.policy_dir().join(RULESET_FILE)).ok()
        }
    }

    #[tokio::test]
    async fn no_policy_creates_nothing() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        assert!(!enforcer.reconcile().await.unwrap());
        enforcer.check_launch().unwrap();
        assert!(fx.nft.applied().is_empty());
        assert_eq!(fx.ruleset_file(), None);
    }

    #[tokio::test]
    async fn an_order_is_acked_only_once_its_rules_are_loaded() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        let ack = enforcer.accept(policy(3), NOW).await.unwrap();
        let sha = crate::netpolicy::content_sha256_hex(&policy(3)).unwrap();
        assert_eq!(ack, format!("applied:3:{sha}"));
        let applied = fx.nft.applied();
        assert_eq!(applied.len(), 1);
        // No hint: the lowest-metric default route.
        assert!(applied[0].contains("oifname != { \"eno1\", \"virbr0\" }"));
        assert!(applied[0].contains(&sha));
        assert_eq!(fx.ruleset_file().as_deref(), Some(applied[0].as_str()));
    }

    #[tokio::test]
    async fn a_failed_load_is_not_acked_and_a_resend_retries_it() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        let first = fx.nft.live().unwrap();

        fx.nft.set_fail_apply(true);
        let mut stricter = policy(2);
        stricter.local_action = NetPolicyLocalAction::Drop;
        assert_eq!(
            enforcer
                .accept(stricter.clone(), NOW)
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-apply/nft"
        );
        // The previous rules stay loaded and on disk for the boot unit;
        // the revision floor already moved.
        assert_eq!(fx.nft.live().as_deref(), Some(first.as_str()));
        assert_eq!(fx.ruleset_file().as_deref(), Some(first.as_str()));
        assert_eq!(
            enforcer
                .accept(policy(1), NOW)
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-stale-revision"
        );

        fx.nft.set_fail_apply(false);
        let ack = enforcer.accept(stricter, NOW).await.unwrap();
        assert!(ack.starts_with("applied:2:"), "{ack}");
        let live = fx.nft.live().unwrap();
        assert!(live.contains("counter drop"), "{live}");
        assert_eq!(fx.ruleset_file().as_deref(), Some(live.as_str()));
    }

    #[tokio::test]
    async fn a_resend_does_not_reload_unchanged_rules() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        let mut renewed = policy(1);
        renewed.not_after_unix += 600;
        enforcer.accept(renewed, NOW).await.unwrap();
        assert!(!enforcer.reconcile().await.unwrap());
        assert_eq!(fx.nft.applied().len(), 1);
    }

    #[tokio::test]
    async fn a_rollback_to_count_is_a_higher_revision() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        let mut dropping = policy(4);
        dropping.local_action = NetPolicyLocalAction::Drop;
        enforcer.accept(dropping, NOW).await.unwrap();
        enforcer.accept(policy(5), NOW).await.unwrap();
        let live = fx.nft.live().unwrap();
        assert!(!live.contains(" drop"), "{live}");
    }

    #[tokio::test]
    async fn a_restarted_agent_reloads_the_persisted_policy() {
        let fx = Fixture::new();
        fx.enforcer().accept(policy(6), NOW).await.unwrap();
        let before = fx.nft.applied();
        // Reboot: the kernel lost the tables (the boot unit would have
        // loaded the file; the agent loads again on start).
        fx.nft.flush();
        let restarted = fx.enforcer();
        assert!(restarted.reconcile().await.unwrap());
        assert_eq!(fx.nft.live().as_deref(), before.last().map(String::as_str));
    }

    #[tokio::test]
    async fn drift_is_repaired_and_an_unchanged_table_is_left_alone() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        assert!(!enforcer.reconcile().await.unwrap());
        assert_eq!(fx.nft.applied().len(), 1);

        fx.nft.flush();
        assert!(enforcer.reconcile().await.unwrap());
        assert_eq!(fx.nft.applied().len(), 2);

        // The uplink moved: the text changes and is loaded.
        std::fs::write(
            fx.dir.path().join("route"),
            ROUTES.replace("\t100\t", "\t300\t"),
        )
        .unwrap();
        assert!(enforcer.reconcile().await.unwrap());
        assert!(fx
            .nft
            .live()
            .unwrap()
            .contains("oifname != { \"eno2\", \"virbr0\" }"));

        // The boot file is rewritten if it went missing.
        std::fs::remove_file(fx.policy_dir().join(RULESET_FILE)).unwrap();
        assert!(!enforcer.reconcile().await.unwrap());
        assert_eq!(fx.ruleset_file(), fx.nft.live());
    }

    #[tokio::test]
    async fn smtp_exemptions_follow_the_exempt_vms_taps() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        let mut p = policy(1);
        p.smtp_allowed_vms = vec![VmId::new("tenant-1").unwrap()];
        // Not running yet: no exemption.
        enforcer.accept(p.clone(), NOW).await.unwrap();
        assert!(!fx.nft.live().unwrap().contains("elements"));

        fx.taps.set("tenant-1", &[("vnet4", "52:54:00:12:34:56")]);
        fx.taps.set("tenant-2", &[("vnet5", "52:54:00:12:34:57")]);
        assert!(enforcer.reconcile().await.unwrap());
        let live = fx.nft.live().unwrap();
        assert!(
            live.contains("elements = { \"vnet4\" . 52:54:00:12:34:56 }"),
            "{live}"
        );
        assert!(!live.contains("vnet5"));

        // Relaunched on another tap.
        fx.taps.set("tenant-1", &[("vnet9", "52:54:00:12:34:56")]);
        assert!(enforcer.reconcile().await.unwrap());
        let live = fx.nft.live().unwrap();
        assert!(live.contains("\"vnet9\" . 52:54:00:12:34:56"), "{live}");
        assert!(!live.contains("vnet4"));
    }

    #[tokio::test]
    async fn an_unreadable_libvirt_keeps_the_loaded_exemptions() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        let mut p = policy(1);
        p.smtp_allowed_vms = vec![VmId::new("tenant-1").unwrap()];
        fx.taps.set("tenant-1", &[("vnet4", "52:54:00:12:34:56")]);
        enforcer.accept(p, NOW).await.unwrap();
        let loaded = fx.nft.live().unwrap();

        fx.taps
            .unreadable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            enforcer.reconcile().await.unwrap_err().to_string(),
            "net-policy-apply/taps"
        );
        assert_eq!(fx.nft.live().as_deref(), Some(loaded.as_str()));
        assert_eq!(fx.nft.applied().len(), 1);
    }

    #[tokio::test]
    async fn a_new_revision_with_the_same_rules_is_not_reloaded() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        // vm_caps does not reach local-mode rules.
        let mut next = policy(2);
        next.vm_caps.insert("tenant-9".into(), 250);
        let ack = enforcer.accept(next.clone(), NOW).await.unwrap();
        assert!(ack.starts_with("applied:2:"), "{ack}");
        assert_eq!(fx.nft.applied().len(), 1);
        // The boot file carries the new header.
        let sha = crate::netpolicy::content_sha256_hex(&next).unwrap();
        assert!(fx.ruleset_file().unwrap().contains(&sha));
        // What the latch compares: revision 2 counts as loaded.
        assert_eq!(
            enforcer.loaded_sha.lock().unwrap().as_deref(),
            Some(sha.as_str())
        );
    }

    /// `policy()` caps `tenant-1` at 100 Mbit/s.
    fn seed_tenant_1(fx: &Fixture) {
        fx.libvirt.seed_domain_xml(
            DomainId::new("hippius-tenant-tenant-1").unwrap(),
            DomainState::Running,
            "<domain><name>hippius-tenant-tenant-1</name><devices>\
             <interface type='network'><mac address='52:54:00:12:34:56'/>\
             <target dev='vnet4'/></interface></devices></domain>",
        );
    }

    #[tokio::test]
    async fn the_ack_covers_the_caps_and_drift_puts_them_back() {
        let fx = Fixture::new();
        seed_tenant_1(&fx);
        let enforcer = fx.enforcer();
        fx.tuner
            .fail
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // The rules load, but a cap that cannot be set is not acked.
        assert_eq!(
            enforcer
                .accept(policy(1), NOW)
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-apply/caps"
        );
        assert_eq!(fx.nft.applied().len(), 1);

        fx.tuner
            .fail
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let ack = enforcer.accept(policy(1), NOW).await.unwrap();
        assert!(ack.starts_with("applied:1:"), "{ack}");
        assert_eq!(fx.tuner.calls.lock().unwrap().len(), 1);
        assert_eq!(
            fx.nft.applied().len(),
            1,
            "unchanged rules are not reloaded"
        );
        assert!(!enforcer.reconcile().await.unwrap());

        // The cap was cleared out of band: the drift check sets it again.
        fx.tuner
            .clear("hippius-tenant-tenant-1", "52:54:00:12:34:56");
        assert!(enforcer.reconcile().await.unwrap());
        let calls = fx.tuner.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1, "52:54:00:12:34:56");
        assert_eq!(calls[1].2, crate::netpolicy::Rate::from_mbps(100));
        assert_eq!(fx.nft.applied().len(), 1);
    }

    /// The canary: caps in place, as `virsh domiftune` prints them, and
    /// unchanged tables — drift checks re-apply nothing, ever.
    #[tokio::test]
    async fn drift_checks_leave_caps_in_place_alone() {
        let fx = Fixture::new();
        seed_tenant_1(&fx);
        fx.tuner.report(
            "hippius-tenant-tenant-1",
            "52:54:00:12:34:56",
            crate::netpolicy::caps::tests::DOMIFTUNE_100,
        );
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        for _ in 0..5 {
            assert!(!enforcer.reconcile().await.unwrap());
        }
        assert!(fx.tuner.calls.lock().unwrap().is_empty());
        assert_eq!(fx.nft.applied().len(), 1);
    }

    /// The canary: NetBird re-injects its accepts after every load and
    /// the DNS meter fills; neither is drift, an edit to our rules is.
    #[tokio::test]
    async fn netbird_accepts_and_meter_state_are_not_drift() {
        use crate::netpolicy::snapshot::tests::{LIVE_INET, LIVE_METER, LOADED_INET, LOADED_METER};
        let fx = Fixture::new();
        fx.nft.set_listing(&format!("{LOADED_INET}{LOADED_METER}"));
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap();
        fx.nft.set_listing(&format!("{LIVE_INET}{LIVE_METER}"));
        for _ in 0..5 {
            assert!(!enforcer.reconcile().await.unwrap());
        }
        assert_eq!(fx.nft.applied().len(), 1);

        let edited = LIVE_INET.replace("\t\tcounter comment \"guest-host\"\n", "");
        fx.nft.set_listing(&format!("{edited}{LIVE_METER}"));
        assert!(enforcer.reconcile().await.unwrap());
        assert_eq!(fx.nft.applied().len(), 2);
    }

    #[test]
    fn the_first_difference_is_named() {
        assert_eq!(
            first_difference("a\nb\nc\n", "a\nx\nc\n"),
            "loaded \"b\", now \"x\""
        );
        assert_eq!(
            first_difference("a\nb\n", "a\n"),
            "loaded \"b\", now \"<none>\""
        );
    }

    #[test]
    fn the_header_is_not_part_of_the_rules() {
        assert_eq!(rules_of("# a\n# b\ntable x\n"), "table x\n");
        assert_eq!(rules_of("table x\n# c\n"), "table x\n# c\n");
        assert_eq!(rules_of("# only"), "");
    }

    #[tokio::test]
    async fn no_usable_uplink_refuses_the_load() {
        let fx = Fixture::new();
        std::fs::write(
            fx.dir.path().join("route"),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             wt0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n",
        )
        .unwrap();
        let enforcer = fx.enforcer();
        assert_eq!(
            enforcer
                .accept(policy(1), NOW)
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-apply/uplink"
        );
        assert!(fx.nft.applied().is_empty());
        // A hint needs no route. (Revision 1 is persisted already: the
        // floor moves before the load.)
        let mut hinted = policy(2);
        hinted.uplink_hint = Some("bond0".into());
        enforcer.accept(hinted, NOW).await.unwrap();
        assert!(fx.nft.live().unwrap().contains("\"bond0\""));
    }

    #[tokio::test]
    async fn an_edge_order_is_refused_before_it_is_persisted() {
        let fx = Fixture::new();
        let enforcer = fx.enforcer();
        let mut edge = policy(1);
        edge.mode = NetPolicyMode::Edge;
        assert_eq!(
            enforcer.accept(edge, NOW).await.unwrap_err().to_string(),
            "net-policy-unsupported/edge-mode"
        );
        assert_eq!(enforcer.store().current().unwrap(), None);
        enforcer.check_launch().unwrap();
    }

    /// A local policy never blocks a launch, loaded or not.
    #[tokio::test]
    async fn the_latch_ignores_local_mode() {
        let fx = Fixture::new();
        fx.nft.set_fail_apply(true);
        let enforcer = fx.enforcer();
        enforcer.accept(policy(1), NOW).await.unwrap_err();
        enforcer.check_launch().unwrap();
    }

    /// An edge-mode record left by a newer agent: this one cannot load
    /// it, keeps the tables it finds, and refuses launches.
    #[tokio::test]
    async fn the_latch_holds_an_unloadable_edge_policy() {
        let fx = Fixture::new();
        fx.enforcer().accept(policy(1), NOW).await.unwrap();
        let loaded_before = fx.nft.applied().len();

        let mut edge = policy(2);
        edge.mode = NetPolicyMode::Edge;
        crate::netpolicy::store::write_record_for_tests(&fx.policy_dir(), &edge);
        let mut record = NetPolicyStore::new(fx.policy_dir())
            .current()
            .unwrap()
            .unwrap();

        let restarted = fx.enforcer();
        assert_eq!(
            restarted.reconcile().await.unwrap_err().to_string(),
            "net-policy-unsupported/edge-mode"
        );
        assert_eq!(fx.nft.applied().len(), loaded_before);
        assert_eq!(
            restarted.check_launch().unwrap_err().to_string(),
            "net-policy-not-loaded"
        );

        // A record of a schema this agent cannot read at all is held to
        // the same rule unless it says `local`.
        record.policy["future_field"] = serde_json::json!(1);
        std::fs::write(
            fx.policy_dir().join("policy.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert_eq!(
            fx.enforcer().check_launch().unwrap_err().to_string(),
            "net-policy-not-loaded"
        );
        record.policy["mode"] = serde_json::json!("local");
        std::fs::write(
            fx.policy_dir().join("policy.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        fx.enforcer().check_launch().unwrap();
    }

    #[tokio::test]
    async fn a_damaged_store_refuses_launches() {
        let fx = Fixture::new();
        fx.enforcer().accept(policy(1), NOW).await.unwrap();
        std::fs::write(fx.policy_dir().join("policy.json"), b"{").unwrap();
        assert_eq!(
            fx.enforcer().check_launch().unwrap_err().to_string(),
            "net-policy-store/parse"
        );
    }

    #[test]
    fn the_default_route_is_the_lowest_metric_up_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("route");
        std::fs::write(&path, ROUTES).unwrap();
        assert_eq!(default_route_ifname(&path).unwrap(), "eno1");
        // Down routes are skipped.
        std::fs::write(&path, ROUTES.replace("0003\t0\t0\t100", "0002\t0\t0\t100")).unwrap();
        assert_eq!(default_route_ifname(&path).unwrap(), "eno2");
        std::fs::write(&path, "Iface\tDestination\n").unwrap();
        assert!(default_route_ifname(&path).is_err());
        assert!(default_route_ifname(&dir.path().join("missing")).is_err());
    }
}
