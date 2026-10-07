//! Per-VM bandwidth caps — the policy's `vm_caps` on the guests' NICs
//! (`docs/design/egress-and-bandwidth.md` §7).
//!
//! [`VmCaps::apply`] lists each listed VM's interfaces from its domain
//! XML, reads each one's bandwidth back with `virsh domiftune <dom>
//! <mac>` (`--live` on a running domain, `--config` otherwise) and, where
//! it differs from the cap, sets it with `virsh domiftune --config`
//! (plus `--live` on a running domain): a
//! running guest is capped at once, and the persistent definition keeps
//! the cap for the next start. This works on every domain, whatever XML
//! it was launched with, so no relaunch is needed.
//!
//! The interface is named by its MAC, never its tap: a domain launched
//! before deterministic tap names has an auto-named `vnet*` tap that
//! exists only in the live XML, and `--config` must find the interface
//! in the persistent definition too.
//!
//! The read-back is the same `domiftune` view the setter writes, so a
//! cap that is in place always compares equal. Only `average` and
//! `burst` are compared: libvirt applies `peak` on inbound only and may
//! not report it on outbound, so comparing it could re-tune every pass.
//! A re-tune logs every field that differed, wanted and found.
//!
//! The tc qdiscs libvirt installs are on the host side of the tap, so
//! SEV-SNP changes nothing here: QEMU and the guest are not involved.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::adopt::{attr, sections, tag_attrs};
use crate::lifecycle::{DomainId, DomainState, LibvirtDriver};

/// Smallest burst, KiB: the edge's `htb_burst_bytes` floor.
const MIN_BURST_KIB: u64 = 64;

/// Longest a `virsh domiftune` may take.
const VIRSH_TIMEOUT: Duration = Duration::from_secs(30);

/// One direction of a libvirt `<bandwidth>`: `average` and `peak` in
/// KiB/s, `burst` in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub average_kib: u64,
    pub peak_kib: u64,
    pub burst_kib: u64,
}

impl Rate {
    /// `mbps` Mbit/s as libvirt units (§7): `average = mbps × 125000 /
    /// 1024` rounded down, `peak = average`, and `burst` 10 ms at the
    /// rate, at least 64 KiB.
    pub fn from_mbps(mbps: u32) -> Self {
        let mbps = u64::from(mbps);
        let average = (mbps * 125_000 / 1024).max(1);
        Self {
            average_kib: average,
            peak_kib: average,
            burst_kib: (mbps * 1_250 / 1024).max(MIN_BURST_KIB),
        }
    }

    /// The attributes of an `<inbound>` / `<outbound>` element.
    pub fn xml_attrs(&self) -> String {
        format!(
            "average='{}' peak='{}' burst='{}'",
            self.average_kib, self.peak_kib, self.burst_kib
        )
    }

    /// The `average,peak,burst` argument of `virsh domiftune`.
    fn virsh_arg(&self) -> String {
        format!("{},{},{}", self.average_kib, self.peak_kib, self.burst_kib)
    }

    /// The fields where `got` differs from this rate in either
    /// direction, as `inbound.average want 12207 got 0`. Empty when the
    /// cap is in place.
    fn drift(&self, got: &IfaceRates) -> Vec<String> {
        let mut out = Vec::new();
        for (dir, live) in [("inbound", &got.inbound), ("outbound", &got.outbound)] {
            for (field, want, have) in [
                ("average", self.average_kib, live.average_kib),
                ("burst", self.burst_kib, live.burst_kib),
            ] {
                if want != have {
                    out.push(format!("{dir}.{field} want {want} got {have}"));
                }
            }
        }
        out
    }
}

/// One direction as `virsh domiftune <dom> <mac>` reports it; a field
/// libvirt does not report is 0 (unset).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LiveRate {
    pub average_kib: u64,
    pub peak_kib: u64,
    pub burst_kib: u64,
}

/// Both directions of an interface, as libvirt reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfaceRates {
    pub inbound: LiveRate,
    pub outbound: LiveRate,
}

impl From<Rate> for IfaceRates {
    fn from(rate: Rate) -> Self {
        let live = LiveRate {
            average_kib: rate.average_kib,
            peak_kib: rate.peak_kib,
            burst_kib: rate.burst_kib,
        };
        Self {
            inbound: live,
            outbound: live,
        }
    }
}

/// Parse the query form of `virsh domiftune`:
///
/// ```text
/// inbound.average: 12207
/// inbound.peak   : 12207
/// inbound.burst  : 122
/// inbound.floor  : 0
/// outbound.average: 12207
/// ```
///
/// Keys are padded before the colon; unknown keys (`floor`) are ignored.
/// Fails when no known key is present or a known one is not a number.
fn parse_domiftune(text: &str) -> Result<IfaceRates> {
    let bad = || MinerAgentError::NetPolicyApply("caps-parse");
    let mut rates = IfaceRates::default();
    let mut seen = false;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some((dir, field)) = key.trim().split_once('.') else {
            continue;
        };
        let live = match dir {
            "inbound" => &mut rates.inbound,
            "outbound" => &mut rates.outbound,
            _ => continue,
        };
        let slot = match field {
            "average" => &mut live.average_kib,
            "peak" => &mut live.peak_kib,
            "burst" => &mut live.burst_kib,
            _ => continue,
        };
        *slot = value.trim().parse().map_err(|_| bad())?;
        seen = true;
    }
    if !seen {
        return Err(bad());
    }
    Ok(rates)
}

/// The MAC of every `<interface>` of a domain XML, lower-case.
fn interface_macs(xml: &str) -> Vec<String> {
    sections(xml, "interface")
        .iter()
        .filter_map(|block| tag_attrs(block, "mac").and_then(|a| attr(&a, "address")))
        .map(|mac| mac.to_ascii_lowercase())
        .collect()
}

/// Reads and sets an interface's bandwidth.
#[async_trait]
pub trait IfaceTuner: Send + Sync {
    /// The bandwidth of the interface with MAC `mac` on `domain`: the
    /// running domain's when `live`, else the persistent definition's.
    async fn get(&self, domain: &DomainId, mac: &str, live: bool) -> Result<IfaceRates>;

    /// Set both directions of the interface with MAC `mac` on `domain`
    /// to `rate`, in the persistent definition and, when `live`, in the
    /// running domain too.
    async fn set(&self, domain: &DomainId, mac: &str, rate: Rate, live: bool) -> Result<()>;
}

/// The production tuner, `virsh domiftune`.
pub struct VirshTuner {
    virsh_path: PathBuf,
}

impl VirshTuner {
    pub fn new(virsh_path: PathBuf) -> Self {
        Self { virsh_path }
    }

    /// The argument vector of the query, after `virsh`.
    fn get_args(domain: &DomainId, mac: &str, live: bool) -> Vec<String> {
        vec![
            "--connect".to_string(),
            "qemu:///system".to_string(),
            "domiftune".to_string(),
            domain.as_str().to_string(),
            mac.to_string(),
            if live { "--live" } else { "--config" }.to_string(),
        ]
    }

    /// Run `virsh` with `args`; its stdout.
    async fn run(&self, domain: &DomainId, mac: &str, args: Vec<String>) -> Result<String> {
        let fail = || MinerAgentError::NetPolicyApply("caps");
        if !is_mac(mac) {
            return Err(fail());
        }
        let mut cmd = Command::new(&self.virsh_path);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(VIRSH_TIMEOUT, cmd.output())
            .await
            .map_err(|_| fail())?
            .map_err(|_| fail())?;
        if !output.status.success() {
            // virsh names the domain and the interface, nothing secret.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let excerpt: String = stderr.chars().take(512).collect();
            eprintln!(
                "hippius-miner-agent: net-policy: domiftune {domain} {mac} failed: {}",
                excerpt.trim()
            );
            return Err(fail());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The argument vector of the setter, after `virsh` (tests read it).
    fn args(domain: &DomainId, mac: &str, rate: Rate, live: bool) -> Vec<String> {
        let mut args = vec![
            "--connect".to_string(),
            "qemu:///system".to_string(),
            "domiftune".to_string(),
            domain.as_str().to_string(),
            mac.to_string(),
            "--inbound".to_string(),
            rate.virsh_arg(),
            "--outbound".to_string(),
            rate.virsh_arg(),
            "--config".to_string(),
        ];
        if live {
            args.push("--live".to_string());
        }
        args
    }
}

impl Default for VirshTuner {
    /// The Debian/Ubuntu install path of `virsh`.
    fn default() -> Self {
        Self::new(PathBuf::from("/usr/bin/virsh"))
    }
}

#[async_trait]
impl IfaceTuner for VirshTuner {
    async fn get(&self, domain: &DomainId, mac: &str, live: bool) -> Result<IfaceRates> {
        let out = self
            .run(domain, mac, Self::get_args(domain, mac, live))
            .await?;
        parse_domiftune(&out)
    }

    async fn set(&self, domain: &DomainId, mac: &str, rate: Rate, live: bool) -> Result<()> {
        self.run(domain, mac, Self::args(domain, mac, rate, live))
            .await
            .map(drop)
    }
}

/// `xx:xx:xx:xx:xx:xx`, lower-case hex.
fn is_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts.iter().all(|p| {
            p.len() == 2
                && p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Applies `vm_caps` to the tenant domains (see the module docs).
pub struct VmCaps {
    driver: Arc<dyn LibvirtDriver>,
    tuner: Arc<dyn IfaceTuner>,
}

impl VmCaps {
    pub fn new(driver: Arc<dyn LibvirtDriver>, tuner: Arc<dyn IfaceTuner>) -> Self {
        Self { driver, tuner }
    }

    /// Bring every interface of every listed VM's domain to its cap.
    /// A VM with no domain on this host is skipped. Returns how many
    /// interfaces were changed. Fails `net-policy-apply/caps` when
    /// libvirt cannot be read or an interface could not be set; the
    /// other VMs are still capped first.
    pub async fn apply(&self, caps: &BTreeMap<String, u32>) -> Result<usize> {
        let fail = || MinerAgentError::NetPolicyApply("caps");
        if caps.is_empty() {
            return Ok(0);
        }
        let domains = self.driver.list_domains().await.map_err(|_| fail())?;
        let mut changed = 0usize;
        let mut failed = false;
        for (vm_id, &mbps) in caps {
            let Ok(domain) = DomainId::new(&format!("hippius-tenant-{vm_id}")) else {
                continue;
            };
            let Some(state) = domains
                .iter()
                .find(|(id, _)| *id == domain)
                .map(|(_, s)| *s)
            else {
                continue;
            };
            let outcome = match self.cap_domain(vm_id, &domain, state, mbps).await {
                Ok(n) => Ok(n),
                // A domain that stopped, started or went away since the
                // listing (a stop, a relaunch's undefine/define) is not a
                // failure: skip it if gone, else try once more with the
                // state it has now.
                Err(err) => match self.state_now(&domain).await {
                    Ok(None) => Ok(0),
                    Ok(Some(now)) if is_live(now) != is_live(state) => {
                        self.cap_domain(vm_id, &domain, now, mbps).await
                    }
                    _ => Err(err),
                },
            };
            match outcome {
                Ok(n) => changed += n,
                Err(_) => failed = true,
            }
        }
        if failed {
            return Err(fail());
        }
        Ok(changed)
    }

    /// Bring `domain`'s interfaces to `mbps`; how many were changed.
    async fn cap_domain(
        &self,
        vm_id: &str,
        domain: &DomainId,
        state: DomainState,
        mbps: u32,
    ) -> Result<usize> {
        let xml = self.driver.domain_xml(domain).await?;
        let rate = Rate::from_mbps(mbps);
        let live = is_live(state);
        let mut changed = 0usize;
        for mac in interface_macs(&xml) {
            let drift = rate.drift(&self.tuner.get(domain, &mac, live).await?);
            if drift.is_empty() {
                continue;
            }
            self.tuner.set(domain, &mac, rate, live).await?;
            changed += 1;
            eprintln!(
                "hippius-miner-agent: net-policy: caps re-applied {domain} {mac} \
                 (vm {vm_id}, {mbps} Mbit/s): {}",
                drift.join(", ")
            );
        }
        Ok(changed)
    }

    /// `domain`'s state now; `None` when libvirt no longer has it.
    async fn state_now(&self, domain: &DomainId) -> Result<Option<DomainState>> {
        Ok(self
            .driver
            .list_domains()
            .await?
            .into_iter()
            .find(|(id, _)| id == domain)
            .map(|(_, s)| s))
    }
}

/// Whether QEMU runs for a domain in `state`, so `--live` applies.
/// (`crashed` is QEMU kept after a crash; a destroyed one is `shut off`.)
fn is_live(state: DomainState) -> bool {
    !matches!(state, DomainState::ShutOff | DomainState::NoState)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::lifecycle::MockLibvirtDriver;

    /// `virsh domiftune <dom> <mac>` on a live host for a VM capped at
    /// 100 Mbit/s, verbatim (libvirt 12).
    pub(crate) const DOMIFTUNE_100: &str = "\
inbound.average: 12207
inbound.peak   : 12207
inbound.burst  : 122
inbound.floor  : 0
outbound.average: 12207
outbound.peak  : 12207
outbound.burst : 122

";

    /// The same for a VM capped at 250 Mbit/s.
    const DOMIFTUNE_250: &str = "\
inbound.average: 30517
inbound.peak   : 30517
inbound.burst  : 305
inbound.floor  : 0
outbound.average: 30517
outbound.peak  : 30517
outbound.burst : 305

";

    /// An interface with no bandwidth set.
    const DOMIFTUNE_UNSET: &str = "\
inbound.average: 0
inbound.peak   : 0
inbound.burst  : 0
inbound.floor  : 0
outbound.average: 0
outbound.peak  : 0
outbound.burst : 0

";

    /// An [`IfaceTuner`] over an in-memory libvirt: `set` stores the rate
    /// where `get` reads it, and every `set` is recorded.
    #[derive(Default)]
    pub(crate) struct FakeTuner {
        pub calls: Mutex<Vec<(String, String, Rate, bool)>>,
        pub fail: std::sync::atomic::AtomicBool,
        pub rates: Mutex<HashMap<(String, String), IfaceRates>>,
    }

    impl FakeTuner {
        /// Someone ran `virsh domiftune … 0` (or the domain never had one).
        pub(crate) fn clear(&self, domain: &str, mac: &str) {
            self.rates
                .lock()
                .unwrap()
                .remove(&(domain.to_string(), mac.to_string()));
        }

        /// libvirt reports `text` for this interface.
        pub(crate) fn report(&self, domain: &str, mac: &str, text: &str) {
            self.rates.lock().unwrap().insert(
                (domain.to_string(), mac.to_string()),
                parse_domiftune(text).unwrap(),
            );
        }
    }

    #[async_trait]
    impl IfaceTuner for FakeTuner {
        async fn get(&self, domain: &DomainId, mac: &str, _live: bool) -> Result<IfaceRates> {
            Ok(self
                .rates
                .lock()
                .unwrap()
                .get(&(domain.to_string(), mac.to_string()))
                .copied()
                .unwrap_or_default())
        }

        async fn set(&self, domain: &DomainId, mac: &str, rate: Rate, live: bool) -> Result<()> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(MinerAgentError::NetPolicyApply("caps"));
            }
            self.calls
                .lock()
                .unwrap()
                .push((domain.to_string(), mac.to_string(), rate, live));
            self.rates
                .lock()
                .unwrap()
                .insert((domain.to_string(), mac.to_string()), rate.into());
            Ok(())
        }
    }

    /// A running domain launched before deterministic taps.
    fn old_style(vm: &str) -> String {
        format!(
            "<domain type='kvm' id='3'><name>hippius-tenant-{vm}</name><devices>\
             <interface type='network'>\
             <mac address='52:54:00:AB:CD:01'/>\
             <source network='default' bridge='virbr0'/>\
             <target dev='vnet7'/>\
             <model type='virtio'/>\
             </interface></devices></domain>"
        )
    }

    fn domain(vm: &str) -> DomainId {
        DomainId::new(&format!("hippius-tenant-{vm}")).unwrap()
    }

    const MAC: &str = "52:54:00:ab:cd:01";

    fn fixture() -> (Arc<MockLibvirtDriver>, Arc<FakeTuner>, VmCaps) {
        let driver = Arc::new(MockLibvirtDriver::new());
        let tuner = Arc::new(FakeTuner::default());
        let caps = VmCaps::new(driver.clone(), tuner.clone());
        (driver, tuner, caps)
    }

    fn cap_map(entries: &[(&str, u32)]) -> BTreeMap<String, u32> {
        entries.iter().map(|(v, m)| (v.to_string(), *m)).collect()
    }

    fn caps_of(vm: &str, mbps: u32) -> BTreeMap<String, u32> {
        cap_map(&[(vm, mbps)])
    }

    #[test]
    fn units_follow_the_spec() {
        // 100 Mbit/s = 12_500_000 B/s = 12207.03 KiB/s; 10 ms = 122 KiB.
        assert_eq!(
            Rate::from_mbps(100),
            Rate {
                average_kib: 12_207,
                peak_kib: 12_207,
                burst_kib: 122
            }
        );
        // The burst floor.
        assert_eq!(Rate::from_mbps(1).burst_kib, 64);
        assert_eq!(Rate::from_mbps(1).average_kib, 122);
        assert_eq!(Rate::from_mbps(250).average_kib, 30_517);
        assert_eq!(Rate::from_mbps(100_000).burst_kib, 122_070);
    }

    #[test]
    fn virsh_domiftune_output_parses_and_matches_the_cap() {
        let got = parse_domiftune(DOMIFTUNE_100).unwrap();
        assert_eq!(got, IfaceRates::from(Rate::from_mbps(100)));
        assert!(Rate::from_mbps(100).drift(&got).is_empty());
        let got = parse_domiftune(DOMIFTUNE_250).unwrap();
        assert!(Rate::from_mbps(250).drift(&got).is_empty());
        assert_eq!(
            Rate::from_mbps(100).drift(&parse_domiftune(DOMIFTUNE_UNSET).unwrap()),
            vec![
                "inbound.average want 12207 got 0",
                "inbound.burst want 122 got 0",
                "outbound.average want 12207 got 0",
                "outbound.burst want 122 got 0",
            ]
        );
        // A cap of 250 found where 100 is wanted.
        assert_eq!(Rate::from_mbps(100).drift(&got).len(), 4);
        assert!(parse_domiftune("").is_err());
        assert!(parse_domiftune("error: failed to get domain").is_err());
        assert!(parse_domiftune("inbound.average: x\n").is_err());
    }

    #[test]
    fn macs_are_read_from_the_domain_xml() {
        assert_eq!(interface_macs(&old_style("t")), vec![MAC.to_string()]);
        assert!(interface_macs("<domain><devices></devices></domain>").is_empty());
    }

    /// The canary bug: caps already in place, as libvirt reports them,
    /// must never be re-applied.
    #[tokio::test]
    async fn caps_in_place_are_not_re_applied() {
        let (driver, tuner, caps) = fixture();
        driver.seed_domain_xml(domain("small"), DomainState::Running, &old_style("small"));
        driver.seed_domain_xml(domain("med"), DomainState::Running, &old_style("med"));
        tuner.report("hippius-tenant-small", MAC, DOMIFTUNE_100);
        tuner.report("hippius-tenant-med", MAC, DOMIFTUNE_250);
        for _ in 0..3 {
            assert_eq!(
                caps.apply(&cap_map(&[("small", 100), ("med", 250)]))
                    .await
                    .unwrap(),
                0
            );
        }
        assert!(tuner.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_old_domain_is_capped_live_by_mac() {
        let (driver, tuner, caps) = fixture();
        driver.seed_domain_xml(domain("old-1"), DomainState::Running, &old_style("old-1"));
        assert_eq!(caps.apply(&caps_of("old-1", 100)).await.unwrap(), 1);
        let calls = tuner.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![(
                "hippius-tenant-old-1".to_string(),
                MAC.to_string(),
                Rate::from_mbps(100),
                true
            )]
        );
        // Applied: the next pass changes nothing.
        assert_eq!(caps.apply(&caps_of("old-1", 100)).await.unwrap(), 0);
        assert_eq!(tuner.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn drift_is_re_applied() {
        let (driver, tuner, caps) = fixture();
        driver.seed_domain_xml(domain("new-1"), DomainState::Running, &old_style("new-1"));
        tuner.report("hippius-tenant-new-1", MAC, DOMIFTUNE_250);
        assert_eq!(caps.apply(&caps_of("new-1", 250)).await.unwrap(), 0);
        // Someone cleared it: put back.
        tuner.clear("hippius-tenant-new-1", MAC);
        assert_eq!(caps.apply(&caps_of("new-1", 250)).await.unwrap(), 1);
        // A new cap in the policy (a public IP attached).
        assert_eq!(caps.apply(&caps_of("new-1", 500)).await.unwrap(), 1);
        // Only the burst differs: drift too.
        tuner.report(
            "hippius-tenant-new-1",
            MAC,
            &DOMIFTUNE_250.replace("outbound.burst : 305", "outbound.burst : 1"),
        );
        assert_eq!(caps.apply(&caps_of("new-1", 250)).await.unwrap(), 1);
        // A different peak alone is not drift (libvirt ignores it outbound).
        tuner.report(
            "hippius-tenant-new-1",
            MAC,
            &DOMIFTUNE_250.replace("outbound.peak  : 30517", "outbound.peak  : 0"),
        );
        assert_eq!(caps.apply(&caps_of("new-1", 250)).await.unwrap(), 0);
        assert_eq!(tuner.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_stopped_domain_gets_the_cap_in_its_definition_only() {
        let (driver, tuner, caps) = fixture();
        let inactive = old_style("off-1").replace("<target dev='vnet7'/>", "");
        driver.seed_domain_xml(domain("off-1"), DomainState::ShutOff, &inactive);
        assert_eq!(caps.apply(&caps_of("off-1", 100)).await.unwrap(), 1);
        assert!(
            !tuner.calls.lock().unwrap()[0].3,
            "no --live on a stopped domain"
        );
    }

    #[tokio::test]
    async fn vms_without_a_domain_are_skipped() {
        let (driver, tuner, caps) = fixture();
        driver.seed_domain_xml(domain("here"), DomainState::Running, &old_style("here"));
        let n = caps
            .apply(&cap_map(&[("elsewhere", 100), ("here", 100)]))
            .await
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(tuner.calls.lock().unwrap().len(), 1);
        assert_eq!(caps.apply(&BTreeMap::new()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_failed_tune_fails_the_pass_after_the_others() {
        let (driver, tuner, caps) = fixture();
        driver.seed_domain_xml(domain("a"), DomainState::Running, &old_style("a"));
        tuner.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            caps.apply(&caps_of("a", 100))
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-apply/caps"
        );
        tuner.fail.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(caps.apply(&caps_of("a", 100)).await.unwrap(), 1);
    }

    /// Fails the first `set`, after making the domain stop or vanish;
    /// succeeds afterwards.
    struct RacingTuner {
        driver: Arc<MockLibvirtDriver>,
        vanish: bool,
        calls: Mutex<Vec<bool>>,
    }

    #[async_trait]
    impl IfaceTuner for RacingTuner {
        async fn get(&self, _domain: &DomainId, _mac: &str, _live: bool) -> Result<IfaceRates> {
            Ok(IfaceRates::default())
        }

        async fn set(&self, domain: &DomainId, _mac: &str, _rate: Rate, live: bool) -> Result<()> {
            let first = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(live);
                calls.len() == 1
            };
            if !first {
                return Ok(());
            }
            if self.vanish {
                self.driver.destroy_domain(domain, false).await?;
                self.driver.undefine_domain(domain).await?;
            } else {
                let xml = self.driver.domain_xml(domain).await?;
                self.driver
                    .seed_domain_xml(domain.clone(), DomainState::ShutOff, &xml);
            }
            Err(MinerAgentError::NetPolicyApply("caps"))
        }
    }

    #[tokio::test]
    async fn a_domain_that_stops_or_vanishes_mid_pass_does_not_fail_it() {
        for vanish in [false, true] {
            let driver = Arc::new(MockLibvirtDriver::new());
            driver.seed_domain_xml(domain("racy"), DomainState::Running, &old_style("racy"));
            let tuner = Arc::new(RacingTuner {
                driver: driver.clone(),
                vanish,
                calls: Mutex::new(Vec::new()),
            });
            let caps = VmCaps::new(driver.clone(), tuner.clone());
            let changed = caps.apply(&caps_of("racy", 100)).await.unwrap();
            let calls = tuner.calls.lock().unwrap().clone();
            if vanish {
                assert_eq!((changed, calls), (0, vec![true]));
            } else {
                // Retried on the stopped domain, definition only.
                assert_eq!((changed, calls), (1, vec![true, false]));
            }
        }
    }

    #[test]
    fn the_virsh_calls_name_the_interface_by_mac() {
        let rate = Rate::from_mbps(100);
        assert_eq!(
            VirshTuner::args(&domain("a"), MAC, rate, true).join(" "),
            "--connect qemu:///system domiftune hippius-tenant-a 52:54:00:ab:cd:01 \
             --inbound 12207,12207,122 --outbound 12207,12207,122 --config --live"
        );
        assert!(!VirshTuner::args(&domain("a"), MAC, rate, false).contains(&"--live".to_string()));
        assert_eq!(
            VirshTuner::get_args(&domain("a"), MAC, true).join(" "),
            "--connect qemu:///system domiftune hippius-tenant-a 52:54:00:ab:cd:01 --live"
        );
        assert_eq!(
            VirshTuner::get_args(&domain("a"), MAC, false)
                .last()
                .unwrap(),
            "--config"
        );
    }

    /// The real tuner against a fake `virsh` that records its argv and
    /// answers queries with the live output.
    #[tokio::test]
    async fn the_virsh_tuner_runs_domiftune() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv");
        let answer = dir.path().join("answer");
        std::fs::write(&answer, DOMIFTUNE_100).unwrap();
        let virsh = dir.path().join("virsh");
        std::fs::write(
            &virsh,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\ncat '{}'\n",
                log.display(),
                answer.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&virsh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let tuner = VirshTuner::new(virsh.clone());
        assert_eq!(
            tuner.get(&domain("a"), MAC, true).await.unwrap(),
            IfaceRates::from(Rate::from_mbps(100))
        );
        tuner
            .set(&domain("a"), MAC, Rate::from_mbps(100), true)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "--connect qemu:///system domiftune hippius-tenant-a 52:54:00:ab:cd:01 --live\n\
             --connect qemu:///system domiftune hippius-tenant-a 52:54:00:ab:cd:01 \
             --inbound 12207,12207,122 --outbound 12207,12207,122 --config --live\n"
        );
        // A bad MAC never reaches virsh; a failing virsh is an error.
        assert!(tuner
            .set(&domain("a"), "52:54:00:ab:cd:0g", Rate::from_mbps(1), true)
            .await
            .is_err());
        std::fs::write(&virsh, "#!/bin/sh\nexit 1\n").unwrap();
        assert_eq!(
            tuner
                .get(&domain("a"), MAC, true)
                .await
                .unwrap_err()
                .to_string(),
            "net-policy-apply/caps"
        );
    }
}
