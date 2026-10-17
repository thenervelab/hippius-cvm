//! The libvirt driver — [`LibvirtDriver`] trait + the production
//! [`VirshDriver`] and the test [`MockLibvirtDriver`].
//!
//! ## Why `virsh` shell-out, not the `virt` crate
//!
//! The `virt` crate (libvirt-rs) is a thin FFI binding to `libvirt`'s
//! C API. It would pull a C-library link dependency and an `unsafe`
//! FFI surface into a crate the workspace builds with
//! `unsafe_code = "forbid"`. The miner-agent drives at most a handful
//! of domains and is not latency-sensitive, so the cost of one
//! `virsh` process per operation is irrelevant. `virsh` is a stable,
//! well-documented CLI; its argument vector is built with
//! [`tokio::process::Command`] arguments — **never a shell string** —
//! so there is no command-injection surface, and a failed call is
//! trivially reproducible by hand. The trait keeps the production
//! driver swappable for [`MockLibvirtDriver`] in tests.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::{MinerAgentError, Result};

/// libvirt connection URI. `qemu:///system` is the host-wide,
/// privileged QEMU/KVM instance — the only one that can launch
/// SEV-SNP domains. The miner-agent runs as a systemd service with
/// the libvirt access to reach it.
const LIBVIRT_URI: &str = "qemu:///system";

/// Upper bound on a libvirt domain name the driver will accept.
const DOMAIN_NAME_MAX_LEN: usize = 128;

/// A libvirt domain identifier — the domain *name*.
///
/// `virsh` accepts a name, a UUID, or a numeric id for every
/// operation; the name is used because the agent derives it
/// deterministically from the [`crate::lifecycle::cvm_handle::VmId`]
/// (`hippius-tenant-<vm_id>`) and so knows it before `virsh define`.
/// Construction validates the charset, so a `DomainId` is always a
/// safe `virsh` argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainId(String);

impl DomainId {
    /// Validate + wrap a libvirt domain name. The charset
    /// (`[a-z0-9._-]`) is a strict subset of a shell-safe token, so a
    /// `DomainId` never needs escaping in a `virsh` argv.
    pub fn new(raw: &str) -> Result<Self> {
        let len = raw.len();
        if len == 0 || len > DOMAIN_NAME_MAX_LEN {
            return Err(MinerAgentError::LibvirtDriver("name-parse"));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(MinerAgentError::LibvirtDriver("name-parse"));
        }
        Ok(Self(raw.to_string()))
    }

    /// The domain name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A libvirt domain runtime state — the `virsh domstate` value set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// libvirt has no state for the domain.
    NoState,
    /// The domain is running.
    Running,
    /// The domain is blocked / idle on a resource.
    Blocked,
    /// The domain is paused (suspended by the operator).
    Paused,
    /// The domain is in the middle of a graceful shutdown.
    Shutdown,
    /// The domain is defined but not running.
    ShutOff,
    /// The domain crashed.
    Crashed,
    /// The domain is suspended by guest power management.
    PmSuspended,
}

impl DomainState {
    /// Parse a `virsh domstate` line into a [`DomainState`]. An
    /// unrecognised value fails closed — never silently mapped to
    /// `Running`.
    fn from_virsh(raw: &str) -> Result<Self> {
        Ok(match raw.trim() {
            "running" => Self::Running,
            "idle" => Self::Blocked,
            "paused" => Self::Paused,
            "in shutdown" => Self::Shutdown,
            "shut off" => Self::ShutOff,
            "crashed" => Self::Crashed,
            "pmsuspended" => Self::PmSuspended,
            "no state" => Self::NoState,
            _ => return Err(MinerAgentError::LibvirtDriver("state-parse")),
        })
    }
}

/// Extract the `<name>` element from a domain XML document.
///
/// The only caller feeds it the agent's own well-formed XML, but the
/// extracted name is still validated through [`DomainId::new`] —
/// defence in depth against a malformed template ever producing an
/// unsafe `virsh` argument.
fn parse_domain_name(xml: &str) -> Result<DomainId> {
    const OPEN: &str = "<name>";
    const CLOSE: &str = "</name>";
    let after_open = xml
        .find(OPEN)
        .and_then(|i| xml.get(i + OPEN.len()..))
        .ok_or(MinerAgentError::LibvirtDriver("name-parse"))?;
    let end = after_open
        .find(CLOSE)
        .ok_or(MinerAgentError::LibvirtDriver("name-parse"))?;
    DomainId::new(&after_open[..end])
}

/// The libvirt domain lifecycle operations the agent needs.
///
/// `Send + Sync` so a single `Arc<dyn LibvirtDriver>` is shared by the
/// lifecycle state machine across tasks.
#[async_trait]
pub trait LibvirtDriver: Send + Sync {
    /// Register a domain definition from its XML; returns its
    /// [`DomainId`]. Does not start the domain.
    async fn define_domain(&self, xml: &str) -> Result<DomainId>;

    /// Start a previously-defined domain.
    async fn create_domain(&self, id: &DomainId) -> Result<()>;

    /// Stop a domain. `graceful` requests an ACPI shutdown; otherwise
    /// the domain is force-destroyed. The domain definition is left in
    /// place — a follow-up `undefine_domain` removes the record once
    /// the caller has confirmed the domain is `shut off`.
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()>;

    /// Remove a domain *definition*. The domain must already be down
    /// (callers run this after `destroy_domain` + a `shut off`-state
    /// confirmation, never against a running domain). A domain that
    /// has already vanished — e.g. undefined out-of-band by an
    /// operator between `destroy_domain` and this call — returns
    /// `Ok(())`: every other observable outcome of "the record is no
    /// longer here" is identical, so the operation is idempotent.
    async fn undefine_domain(&self, id: &DomainId) -> Result<()>;

    /// Query a domain's current [`DomainState`].
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState>;

    /// List every domain libvirt knows, with its state.
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>>;

    /// The domain's LIVE definition XML (`virsh dumpxml`).
    ///
    /// This is libvirt's own record of what the host is really running:
    /// the vCPU count, the RAM, the `<vsock>` CID and the disk backing
    /// files QEMU actually opened. Startup re-adoption
    /// ([`crate::lifecycle::CvmLifecycle::readopt_running`]) reads it as
    /// the GROUND TRUTH to cross-check — and, for a domain with no
    /// persisted sidecar at all, to reconstruct — the agent's own
    /// bookkeeping. Note that libvirt normalises the document (units
    /// become `KiB`, aliases/addresses are added), so callers must parse
    /// the emitted form, not the form the agent defined.
    async fn domain_xml(&self, id: &DomainId) -> Result<String>;

    // ── live storage move (block copy) ──────────────────────────────
    // Defaults refuse: only the drivers that implement a move have them.

    /// The domain's PERSISTENT definition (`virsh dumpxml --inactive`):
    /// what the next `virsh start` boots, which a pivot does not change.
    async fn domain_xml_inactive(&self, _id: &DomainId) -> Result<String> {
        Err(MinerAgentError::LibvirtDriver("dumpxml-inactive"))
    }

    /// Start copying `disk` (`vda`) into the pre-created file described
    /// by the disk XML at `dest_xml` (`virsh blockcopy … --xml
    /// --reuse-external --transient-job --bandwidth`); returns once the
    /// job runs. No pivot.
    async fn blockcopy_start(
        &self,
        _id: &DomainId,
        _disk: &str,
        _dest_xml: &std::path::Path,
        _bandwidth_mib_s: u32,
    ) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("blockcopy"))
    }

    /// The block job on `disk`, `None` when there is none.
    async fn blockjob_info(&self, _id: &DomainId, _disk: &str) -> Result<Option<BlockJobInfo>> {
        Err(MinerAgentError::LibvirtDriver("blockjob-info"))
    }

    /// Switch `disk` to the copy (`virsh blockjob --pivot`).
    async fn blockjob_pivot(&self, _id: &DomainId, _disk: &str) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("blockjob-pivot"))
    }

    /// Abort the block job on `disk`, the copy left as it is
    /// (`virsh blockjob --abort`); no job is success.
    async fn blockjob_abort(&self, _id: &DomainId, _disk: &str) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("blockjob-abort"))
    }
}

/// A block job's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockJobInfo {
    /// Bytes copied.
    pub cur: u64,
    /// Bytes to copy (it can grow while the guest writes).
    pub end: u64,
    /// The mirror is in sync: a pivot can happen.
    pub ready: bool,
}

/// `cur=` / `end=` of `virsh blockjob --info --raw` (`None`: no job).
fn parse_blockjob_raw(out: &str) -> Option<(u64, u64)> {
    let field = |name: &str| {
        out.split([',', '\n'])
            .filter_map(|kv| kv.trim().strip_prefix(name)?.strip_prefix('='))
            .find_map(|v| v.trim().parse::<u64>().ok())
    };
    Some((field("cur")?, field("end")?))
}

/// The `<driver type=…>` of the domain XML's `vda` (`raw`, `qcow2`).
pub(crate) fn vda_driver_type(xml: &str) -> Option<String> {
    let block = xml.split("<disk ").find(|block| {
        block
            .split("</disk>")
            .next()
            .is_some_and(|b| b.contains("dev='vda'"))
    })?;
    let driver = block.split("<driver ").nth(1)?.split('>').next()?;
    let rest = driver.split("type='").nth(1)?;
    Some(rest.split('\'').next()?.to_string())
}

/// Whether the live XML's `vda` carries a mirror libvirt marked ready.
fn mirror_ready(xml: &str, disk: &str) -> bool {
    xml.split("<disk ")
        .filter(|block| block.contains(&format!("dev='{disk}'")))
        .any(|block| {
            block.split("<mirror ").nth(1).is_some_and(|m| {
                m.split('>')
                    .next()
                    .is_some_and(|a| a.contains("ready='yes'"))
            })
        })
}

/// Run a built `virsh` command, mapping a spawn failure or a non-zero
/// exit to `op`. Captures stdout; stderr is intentionally **not**
/// echoed into the error (the §H leak discipline — virsh output can
/// carry a path).
async fn run_virsh(mut cmd: Command, op: &'static str) -> Result<String> {
    let output = cmd
        .output()
        .await
        .map_err(|_| MinerAgentError::LibvirtDriver("virsh-spawn"))?;
    if !output.status.success() {
        return Err(MinerAgentError::LibvirtDriver(op));
    }
    String::from_utf8(output.stdout).map_err(|_| MinerAgentError::LibvirtDriver(op))
}

/// The error for a failed `virsh start`, from its stderr.
///
/// `cid-in-use` when the CID the XML pins is taken, which shows up two
/// ways: QEMU cannot bind the guest CID, or — for a domain whose tap is
/// named after its CID (`hvt<cid>`, egress design §6.1) — libvirt
/// cannot create the tap because an orphan QEMU on that CID still holds
/// it. libvirt creates the tap before it starts QEMU, so the second form
/// comes first. Both make the lifecycle burn the CID and retry on a
/// fresh one (and so a fresh tap name). Only these closed-vocabulary
/// markers are matched; the stderr itself is never surfaced.
fn classify_start_failure(stderr: &str) -> MinerAgentError {
    let cid_bound = stderr.contains("set guest cid") && stderr.contains("Address already in use");
    let tap_taken = stderr.contains(super::qemu_config::TENANT_TAP_PREFIX)
        && (stderr.contains("Device or resource busy") || stderr.contains("already exists"));
    if cid_bound || tap_taken {
        MinerAgentError::VsockCid("cid-in-use")
    } else {
        MinerAgentError::LibvirtDriver("create")
    }
}

/// Production driver — shells out to `virsh`.
pub struct VirshDriver {
    /// Absolute path to the `virsh` binary.
    virsh_path: PathBuf,
}

impl VirshDriver {
    /// Construct a driver that invokes `virsh` at `virsh_path`.
    pub fn new(virsh_path: PathBuf) -> Self {
        Self { virsh_path }
    }

    /// A `virsh` command pre-pointed at the system QEMU connection.
    ///
    /// `kill_on_drop`: a caller that times out or is cancelled drops the
    /// future — without this the `virsh` child keeps running, so a hung
    /// libvirtd would accumulate one stuck process per retry.
    fn virsh(&self) -> Command {
        let mut cmd = Command::new(&self.virsh_path);
        cmd.arg("--connect").arg(LIBVIRT_URI).kill_on_drop(true);
        cmd
    }
}

impl Default for VirshDriver {
    /// The default Debian/RHEL install path of `virsh`.
    fn default() -> Self {
        Self::new(PathBuf::from("/usr/bin/virsh"))
    }
}

#[async_trait]
impl LibvirtDriver for VirshDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        // Parse (and validate) the id before touching libvirt.
        let domain = parse_domain_name(xml)?;
        // `virsh define` reads a file, so the XML is staged through an
        // `O_EXCL` temp file (mode 0600). The handle is held across
        // the await so the file outlives the `virsh` read, then drops.
        let mut tmp = tempfile::Builder::new()
            .prefix(".hippius-cvm-domain-")
            .suffix(".xml")
            .tempfile()
            .map_err(|_| MinerAgentError::LibvirtDriver("define"))?;
        tmp.write_all(xml.as_bytes())
            .and_then(|()| tmp.flush())
            .map_err(|_| MinerAgentError::LibvirtDriver("define"))?;
        let mut cmd = self.virsh();
        cmd.arg("define").arg(tmp.path());
        run_virsh(cmd, "define").await?;
        Ok(domain)
    }

    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        // `virsh start` fails with `error: Failed to start domain … /
        // failed to set guest cid: Address already in use` when the guest
        // CID this domain's XML pins is already bound in the kernel by
        // another (possibly ORPHAN) qemu. Capture stderr and match ONLY
        // that closed-vocabulary, non-secret marker (same discipline as
        // `undefine_domain`) so the lifecycle can retry with a fresh CID;
        // every other create failure stays the opaque `LibvirtDriver
        // ("create")`.
        let mut cmd = self.virsh();
        cmd.arg("start").arg(id.as_str());
        crate::host_health::record_domain_start();
        let output = cmd
            .output()
            .await
            .map_err(|_| MinerAgentError::LibvirtDriver("virsh-spawn"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(classify_start_failure(&String::from_utf8_lossy(
            &output.stderr,
        )))
    }

    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        let mut cmd = self.virsh();
        // `shutdown` asks the guest to power off via ACPI; `destroy`
        // force-stops it. The lifecycle does the shutdown→wait→destroy
        // escalation; this method performs exactly the one op asked.
        cmd.arg(if graceful { "shutdown" } else { "destroy" })
            .arg(id.as_str());
        run_virsh(cmd, "destroy").await?;
        Ok(())
    }

    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        // Capture stderr alongside the exit status: the only way to
        // distinguish "domain already gone" (idempotent success) from
        // "libvirt is unreachable" (real failure) at the virsh CLI is
        // the error string. Exit codes alone collapse both to 1.
        //
        // `run_virsh` is bypassed here because it discards stderr by
        // design (§H — stderr can carry a path); we inspect just the
        // closed-vocabulary prefix that means "no such domain", never
        // surface the bytes to a log or error variant.
        let mut cmd = self.virsh();
        // The flags drop every piece of per-domain libvirt state along
        // with the record, so nothing is left for a later `define` of the
        // same vm_id to trip over. Each is a no-op on a domain that has no
        // such state — a tenant domain boots a stateless `type='rom'`
        // OVMF with no NVRAM, no snapshots and no checkpoints — which was
        // verified against libvirt 11.6 on a miner (a ROM-loader domain
        // undefines cleanly with all four).
        cmd.arg("undefine")
            .arg(id.as_str())
            .arg("--managed-save")
            .arg("--snapshots-metadata")
            .arg("--checkpoints-metadata")
            .arg("--nvram");
        let output = cmd
            .output()
            .await
            .map_err(|_| MinerAgentError::LibvirtDriver("virsh-spawn"))?;
        if output.status.success() {
            return Ok(());
        }
        // virsh / libvirt's "no such domain" surfaces a handful of
        // closed-vocabulary prefixes depending on whether the lookup
        // failed at libvirt's name table or at the connection layer.
        // Match the prefix only — never echo the bytes.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Domain not found")
            || stderr.contains("failed to get domain")
            || stderr.contains("domain not defined")
        {
            return Ok(());
        }
        Err(MinerAgentError::LibvirtDriver("undefine"))
    }

    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        let mut cmd = self.virsh();
        cmd.arg("domstate").arg(id.as_str());
        let out = run_virsh(cmd, "domstate").await?;
        DomainState::from_virsh(&out)
    }

    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        let mut cmd = self.virsh();
        cmd.arg("list").arg("--all").arg("--name");
        let out = run_virsh(cmd, "list").await?;
        let mut domains = Vec::new();
        for line in out.lines() {
            let name = line.trim();
            if name.is_empty() {
                continue;
            }
            // A foreign VM (not agent-created) may carry a name outside
            // the agent's strict charset — skip it rather than failing
            // the whole enumeration. Every agent domain is
            // `hippius-tenant-*` and always parses.
            let Ok(id) = DomainId::new(name) else {
                continue;
            };
            let state = self.query_domain_state(&id).await?;
            domains.push((id, state));
        }
        Ok(domains)
    }

    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        let mut cmd = self.virsh();
        cmd.arg("dumpxml").arg(id.as_str());
        run_virsh(cmd, "dumpxml").await
    }

    async fn domain_xml_inactive(&self, id: &DomainId) -> Result<String> {
        let mut cmd = self.virsh();
        cmd.arg("dumpxml")
            .arg("--inactive")
            .arg("--security-info")
            .arg(id.as_str());
        run_virsh(cmd, "dumpxml-inactive").await
    }

    async fn blockcopy_start(
        &self,
        id: &DomainId,
        disk: &str,
        dest_xml: &std::path::Path,
        bandwidth_mib_s: u32,
    ) -> Result<()> {
        let mut cmd = self.virsh();
        cmd.arg("blockcopy")
            .arg(id.as_str())
            .arg(disk)
            .arg("--xml")
            .arg(dest_xml)
            .arg("--reuse-external")
            .arg("--transient-job")
            .arg("--bandwidth")
            .arg(bandwidth_mib_s.to_string());
        run_virsh(cmd, "blockcopy").await.map(|_| ())
    }

    async fn blockjob_info(&self, id: &DomainId, disk: &str) -> Result<Option<BlockJobInfo>> {
        let mut cmd = self.virsh();
        cmd.arg("blockjob")
            .arg(id.as_str())
            .arg(disk)
            .arg("--info")
            .arg("--raw");
        let out = run_virsh(cmd, "blockjob-info").await?;
        let Some((cur, end)) = parse_blockjob_raw(&out) else {
            return Ok(None);
        };
        let ready = mirror_ready(&self.domain_xml(id).await?, disk);
        Ok(Some(BlockJobInfo { cur, end, ready }))
    }

    async fn blockjob_pivot(&self, id: &DomainId, disk: &str) -> Result<()> {
        let mut cmd = self.virsh();
        cmd.arg("blockjob")
            .arg(id.as_str())
            .arg(disk)
            .arg("--pivot");
        run_virsh(cmd, "blockjob-pivot").await.map(|_| ())
    }

    async fn blockjob_abort(&self, id: &DomainId, disk: &str) -> Result<()> {
        if self.blockjob_info(id, disk).await?.is_none() {
            return Ok(());
        }
        let mut cmd = self.virsh();
        cmd.arg("blockjob")
            .arg(id.as_str())
            .arg(disk)
            .arg("--abort");
        run_virsh(cmd, "blockjob-abort").await.map(|_| ())
    }
}

/// In-memory test double — no `virsh`, no libvirt, deterministic.
///
/// `define_domain` records the domain `ShutOff`; `create_domain`
/// transitions it to `post_create_state` (default [`DomainState::
/// Running`], overridable so a test can drive the launch-timeout and
/// crashed-domain paths); `destroy_domain` transitions it to
/// `ShutOff`.
pub struct MockLibvirtDriver {
    domains: Mutex<HashMap<DomainId, DomainState>>,
    /// The XML each domain was defined with, so `domain_xml` can serve
    /// it back the way `virsh dumpxml` does. Seeded domains
    /// ([`Self::seed_domain_xml`]) supply their own.
    xml: Mutex<HashMap<DomainId, String>>,
    post_create_state: DomainState,
    /// Count of `destroy_domain` calls — lets a test prove a code
    /// path issued (or, on a digest failure, did NOT issue) a virsh
    /// stop.
    destroy_calls: AtomicUsize,
    /// Count of `undefine_domain` calls — paired with
    /// [`Self::destroy_calls`] so tests can prove the lifecycle
    /// removes both the runtime AND the definition on clean stops
    /// and on `teardown_failed_launch`.
    undefine_calls: AtomicUsize,
    /// How many of the next `create_domain` calls fail with the vsock
    /// CID-collision error before one succeeds — exercises the
    /// `run_domain` burn-and-retry path (AUDIT-3). 0 = happy path.
    cid_conflicts_remaining: AtomicUsize,
    /// States the next `query_domain_state` calls answer, in order, before
    /// falling back to the real map — lets a test change a domain's state
    /// between two reads (a start racing a check).
    scripted_states: Mutex<std::collections::VecDeque<DomainState>>,
    /// The LIVE definition where it differs from the persistent one (after
    /// a pivot): `domain_xml` serves it, `domain_xml_inactive` never does.
    live_xml: Mutex<HashMap<DomainId, String>>,
    /// The block job on each domain's `vda` (one at a time).
    jobs: Mutex<HashMap<DomainId, MockBlockJob>>,
    /// The next `blockjob_pivot` fails.
    fail_pivot: std::sync::atomic::AtomicBool,
    fail_abort: std::sync::atomic::AtomicBool,
    /// The next pivot happens, but its answer times out.
    pivot_times_out: std::sync::atomic::AtomicBool,
    /// The next blockcopy times out, its job showing up only after this
    /// many `blockjob --info` calls (0 = no late job).
    late_job: Mutex<Option<(usize, std::path::PathBuf)>>,
    /// How many of the next `domain_xml` calls fail (a stressed libvirtd).
    domain_xml_failures: AtomicUsize,
}

/// A [`MockLibvirtDriver`] block copy.
#[derive(Debug, Clone)]
struct MockBlockJob {
    dest: std::path::PathBuf,
    info: BlockJobInfo,
}

impl MockLibvirtDriver {
    /// A mock whose domains reach [`DomainState::Running`] on
    /// `create_domain` — the happy path.
    pub fn new() -> Self {
        Self {
            domains: Mutex::new(HashMap::new()),
            xml: Mutex::new(HashMap::new()),
            post_create_state: DomainState::Running,
            destroy_calls: AtomicUsize::new(0),
            undefine_calls: AtomicUsize::new(0),
            cid_conflicts_remaining: AtomicUsize::new(0),
            scripted_states: Mutex::new(std::collections::VecDeque::new()),
            live_xml: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            fail_pivot: std::sync::atomic::AtomicBool::new(false),
            fail_abort: std::sync::atomic::AtomicBool::new(false),
            pivot_times_out: std::sync::atomic::AtomicBool::new(false),
            late_job: Mutex::new(None),
            domain_xml_failures: AtomicUsize::new(0),
        }
    }

    /// A mock whose domains reach `post_create_state` on
    /// `create_domain` — e.g. `Paused` to exercise the launch-poll
    /// timeout, or `Crashed` for the failed-domain path.
    pub fn with_post_create_state(post_create_state: DomainState) -> Self {
        Self {
            domains: Mutex::new(HashMap::new()),
            xml: Mutex::new(HashMap::new()),
            post_create_state,
            destroy_calls: AtomicUsize::new(0),
            undefine_calls: AtomicUsize::new(0),
            cid_conflicts_remaining: AtomicUsize::new(0),
            scripted_states: Mutex::new(std::collections::VecDeque::new()),
            live_xml: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            fail_pivot: std::sync::atomic::AtomicBool::new(false),
            fail_abort: std::sync::atomic::AtomicBool::new(false),
            pivot_times_out: std::sync::atomic::AtomicBool::new(false),
            late_job: Mutex::new(None),
            domain_xml_failures: AtomicUsize::new(0),
        }
    }

    /// Answer the next `query_domain_state` calls with `states`, in order.
    pub fn script_states(&self, states: Vec<DomainState>) {
        if let Ok(mut q) = self.scripted_states.lock() {
            q.extend(states);
        }
    }

    /// Number of domains currently defined — a test assertion helper.
    pub fn defined_count(&self) -> Result<usize> {
        Ok(self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .len())
    }

    /// Number of `destroy_domain` calls made so far — a test helper
    /// (counts the call regardless of whether the domain existed).
    /// Pre-populate a domain in a chosen state, WITHOUT going through
    /// `define`/`create`. Lets a test model the case §24's `destroy`
    /// guards against: libvirt knows a running domain while the agent
    /// holds no handle for it (a lost adopt record after a restart).
    pub fn seed_domain(&self, id: DomainId, state: DomainState) {
        if let Ok(mut d) = self.domains.lock() {
            d.insert(id, state);
        }
    }

    /// Pre-populate a domain in a chosen state WITH its definition XML —
    /// the ORPHAN case startup re-adoption has to reconstruct from
    /// libvirt alone (a live `hippius-tenant-*` domain the agent holds
    /// neither a handle nor an `adopt` sidecar for).
    pub fn seed_domain_xml(&self, id: DomainId, state: DomainState, xml: &str) {
        self.seed_domain(id.clone(), state);
        if let Ok(mut x) = self.xml.lock() {
            x.insert(id, xml.to_string());
        }
    }

    pub fn destroy_count(&self) -> usize {
        self.destroy_calls.load(Ordering::Relaxed)
    }

    /// Number of `undefine_domain` calls made so far — paired with
    /// [`Self::destroy_count`] so a test can assert the lifecycle
    /// removes the libvirt *record* and not only the runtime on every
    /// stop / teardown path.
    pub fn undefine_count(&self) -> usize {
        self.undefine_calls.load(Ordering::Relaxed)
    }

    /// Make the next `n` `create_domain` calls fail with the vsock
    /// CID-collision error before one succeeds — models `n` orphan-qemu
    /// CID collisions so a test can drive the `run_domain` burn-and-retry
    /// path (AUDIT-3).
    pub fn set_cid_conflicts(&self, n: usize) {
        self.cid_conflicts_remaining.store(n, Ordering::Relaxed);
    }

    /// Force EVERY currently-defined domain to `state` out-of-band —
    /// models an external `virsh destroy` / a crash the agent did not
    /// initiate, so the in-process handle lingers while libvirt no
    /// longer runs the domain. Test helper for the idempotent-admission
    /// reclaim path in `CvmLifecycle::launch`.
    /// The domain's block job copied `cur` of `end` bytes, `ready` or not.
    pub fn set_block_job(&self, id: &DomainId, cur: u64, end: u64, ready: bool) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(job) = jobs.get_mut(id) {
                job.info = BlockJobInfo { cur, end, ready };
            }
        }
    }

    /// The domain's block job dies (libvirtd restarted, QEMU exited): no
    /// job, nothing pivoted.
    pub fn kill_block_job(&self, id: &DomainId) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(id);
        }
    }

    /// Whether the domain has a block job.
    pub fn has_block_job(&self, id: &DomainId) -> bool {
        self.jobs.lock().is_ok_and(|j| j.contains_key(id))
    }

    /// The next `n` `domain_xml` calls fail.
    pub fn fail_domain_xml(&self, n: usize) {
        self.domain_xml_failures.store(n, Ordering::Relaxed);
    }

    /// The next pivot fails.
    pub fn fail_next_pivot(&self) {
        self.fail_pivot.store(true, Ordering::Relaxed);
    }

    /// What the running domain's live definition says from now on.
    pub fn set_live_xml(&self, id: &DomainId, xml: &str) {
        if let Ok(mut live) = self.live_xml.lock() {
            live.insert(id.clone(), xml.to_string());
        }
    }

    /// The next pivot lands, but its answer times out.
    pub fn pivot_lands_then_times_out(&self) {
        self.pivot_times_out.store(true, Ordering::Relaxed);
    }

    /// The next blockcopy answers a timeout; its job appears after
    /// `after_infos` `blockjob --info` calls.
    pub fn blockcopy_times_out_job_appears_after(&self, after_infos: usize) {
        if let Ok(mut late) = self.late_job.lock() {
            *late = Some((after_infos, std::path::PathBuf::new()));
        }
    }

    /// A late job armed by [`Self::blockcopy_times_out_job_appears_after`]
    /// that never showed up (nobody looked for it).
    pub fn late_job_pending(&self) -> bool {
        self.late_job.lock().map(|l| l.is_some()).unwrap_or(true)
    }

    /// The next `blockjob --abort` fails (a job libvirt is pivoting).
    pub fn fail_next_abort(&self) {
        self.fail_abort.store(true, Ordering::Relaxed);
    }

    pub fn force_all_to_state(&self, state: DomainState) -> Result<()> {
        let mut domains = self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        for s in domains.values_mut() {
            *s = state;
        }
        Ok(())
    }
}

impl Default for MockLibvirtDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LibvirtDriver for MockLibvirtDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        let domain = parse_domain_name(xml)?;
        self.domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .entry(domain.clone())
            .or_insert(DomainState::ShutOff);
        // Keep the definition so `domain_xml` can serve it back, exactly
        // as `virsh dumpxml` does for a real domain.
        self.xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .insert(domain.clone(), xml.to_string());
        Ok(domain)
    }

    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        // Simulate an orphan-qemu CID collision for the first `n` calls
        // (AUDIT-3): fail with the same error the VirshDriver maps the
        // `Address already in use` marker to, so `run_domain` burns +
        // retries. The stale definition is left for the lifecycle's
        // `undefine_domain` retry step, matching production.
        if self
            .cid_conflicts_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n > 0).then(|| n - 1)
            })
            .is_ok()
        {
            return Err(MinerAgentError::VsockCid("cid-in-use"));
        }
        let mut domains = self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        let state = domains
            .get_mut(id)
            .ok_or(MinerAgentError::LibvirtDriver("create"))?;
        *state = self.post_create_state;
        Ok(())
    }

    async fn destroy_domain(&self, id: &DomainId, _graceful: bool) -> Result<()> {
        // Count the call before anything else — a test asserts this is
        // zero when a launch fails closed at the pre-flight digest.
        self.destroy_calls.fetch_add(1, Ordering::Relaxed);
        let mut domains = self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        let state = domains
            .get_mut(id)
            .ok_or(MinerAgentError::LibvirtDriver("destroy"))?;
        *state = DomainState::ShutOff;
        // QEMU is gone: so is its block job and its live definition.
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(id);
        }
        if let Ok(mut live) = self.live_xml.lock() {
            live.remove(id);
        }
        Ok(())
    }

    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        // Mirror the real driver: count + idempotent. An undefine of an
        // unknown domain is a clean `Ok(())` so the lifecycle's
        // teardown / clean-stop paths can call this without first
        // proving the record still exists.
        self.undefine_calls.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .remove(id);
        let _ = self
            .xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .remove(id);
        Ok(())
    }

    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        if let Some(state) = self
            .scripted_states
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .pop_front()
        {
            return Ok(state);
        }
        self.domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .get(id)
            .copied()
            .ok_or(MinerAgentError::LibvirtDriver("domstate"))
    }

    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        Ok(self
            .domains
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .iter()
            .map(|(id, state)| (id.clone(), *state))
            .collect())
    }

    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        if self
            .domain_xml_failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n > 0).then(|| n - 1)
            })
            .is_ok()
        {
            return Err(MinerAgentError::LibvirtDriver("dumpxml"));
        }
        if let Some(live) = self
            .live_xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .get(id)
        {
            return Ok(live.clone());
        }
        self.xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .get(id)
            .cloned()
            .ok_or(MinerAgentError::LibvirtDriver("dumpxml"))
    }

    async fn domain_xml_inactive(&self, id: &DomainId) -> Result<String> {
        self.xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .get(id)
            .cloned()
            .ok_or(MinerAgentError::LibvirtDriver("dumpxml-inactive"))
    }

    async fn blockcopy_start(
        &self,
        id: &DomainId,
        disk: &str,
        dest_xml: &std::path::Path,
        _bandwidth_mib_s: u32,
    ) -> Result<()> {
        if disk != "vda" || self.query_domain_state(id).await? != DomainState::Running {
            return Err(MinerAgentError::LibvirtDriver("blockcopy"));
        }
        let xml = std::fs::read_to_string(dest_xml)
            .map_err(|_| MinerAgentError::LibvirtDriver("blockcopy"))?;
        let dest = xml
            .split("file='")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .ok_or(MinerAgentError::LibvirtDriver("blockcopy"))?;
        let dest = std::path::PathBuf::from(dest);
        if !dest.is_file() {
            // `--reuse-external`: the file must exist.
            return Err(MinerAgentError::LibvirtDriver("blockcopy"));
        }
        {
            let mut late = self
                .late_job
                .lock()
                .map_err(|_| MinerAgentError::LockPoisoned)?;
            if let Some((after, _)) = late.take() {
                *late = Some((after, dest));
                return Err(MinerAgentError::StorageMove("move-libvirt-timeout"));
            }
        }
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?;
        if jobs.contains_key(id) {
            return Err(MinerAgentError::LibvirtDriver("blockcopy"));
        }
        jobs.insert(
            id.clone(),
            MockBlockJob {
                dest,
                info: BlockJobInfo {
                    cur: 0,
                    end: 1,
                    ready: false,
                },
            },
        );
        Ok(())
    }

    async fn blockjob_info(&self, id: &DomainId, _disk: &str) -> Result<Option<BlockJobInfo>> {
        {
            let mut late = self
                .late_job
                .lock()
                .map_err(|_| MinerAgentError::LockPoisoned)?;
            if let Some((after, dest)) = late.take() {
                if dest.as_os_str().is_empty() {
                    // Armed, the blockcopy not sent yet.
                    *late = Some((after, dest));
                } else if after == 0 {
                    self.jobs
                        .lock()
                        .map_err(|_| MinerAgentError::LockPoisoned)?
                        .insert(
                            id.clone(),
                            MockBlockJob {
                                dest,
                                info: BlockJobInfo {
                                    cur: 0,
                                    end: 1,
                                    ready: false,
                                },
                            },
                        );
                } else {
                    *late = Some((after - 1, dest));
                }
            }
        }
        Ok(self
            .jobs
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .get(id)
            .map(|j| j.info))
    }

    async fn blockjob_pivot(&self, id: &DomainId, _disk: &str) -> Result<()> {
        if self.fail_pivot.swap(false, Ordering::Relaxed) {
            return Err(MinerAgentError::LibvirtDriver("blockjob-pivot"));
        }
        let job = {
            let jobs = self
                .jobs
                .lock()
                .map_err(|_| MinerAgentError::LockPoisoned)?;
            match jobs.get(id) {
                Some(job) if job.info.ready => job.clone(),
                _ => return Err(MinerAgentError::LibvirtDriver("blockjob-pivot")),
            }
        };
        // The live definition now names the copy; the persistent one is
        // unchanged (`--transient-job`).
        let current = {
            let live = self
                .live_xml
                .lock()
                .map_err(|_| MinerAgentError::LockPoisoned)?;
            match live.get(id) {
                Some(xml) => xml.clone(),
                None => self
                    .xml
                    .lock()
                    .map_err(|_| MinerAgentError::LockPoisoned)?
                    .get(id)
                    .cloned()
                    .ok_or(MinerAgentError::LibvirtDriver("blockjob-pivot"))?,
            }
        };
        let pivoted = replace_vda_source(&current, &job.dest)
            .ok_or(MinerAgentError::LibvirtDriver("blockjob-pivot"))?;
        self.live_xml
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .insert(id.clone(), pivoted);
        self.jobs
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .remove(id);
        if self.pivot_times_out.swap(false, Ordering::Relaxed) {
            return Err(MinerAgentError::StorageMove("move-libvirt-timeout"));
        }
        Ok(())
    }

    async fn blockjob_abort(&self, id: &DomainId, _disk: &str) -> Result<()> {
        if self.fail_abort.swap(false, Ordering::Relaxed) {
            return Err(MinerAgentError::LibvirtDriver("blockjob-abort"));
        }
        self.jobs
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)?
            .remove(id);
        Ok(())
    }
}

/// `xml` with the `vda` disk's `<source file=…>` set to `path` (the first
/// source of the vda block); `None` if there is no such source.
pub(crate) fn replace_vda_source(xml: &str, path: &std::path::Path) -> Option<String> {
    let start = xml.match_indices("<disk ").map(|(i, _)| i).find(|&i| {
        xml[i..]
            .split("</disk>")
            .next()
            .is_some_and(|b| b.contains("dev='vda'"))
    })?;
    let block_end = start + xml[start..].find("</disk>")?;
    let rel = xml[start..block_end].find("<source file='")?;
    let value_start = start + rel + "<source file='".len();
    let value_end = value_start + xml[value_start..].find('\'')?;
    let path = path.to_str()?;
    if path.contains(['\'', '<', '>', '&', '"']) {
        return None;
    }
    Some(format!(
        "{}{}{}",
        &xml[..value_start],
        path,
        &xml[value_end..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_state_parses_every_virsh_value() {
        assert_eq!(
            DomainState::from_virsh("running\n").unwrap(),
            DomainState::Running
        );
        assert_eq!(
            DomainState::from_virsh(" shut off ").unwrap(),
            DomainState::ShutOff
        );
        assert_eq!(
            DomainState::from_virsh("in shutdown").unwrap(),
            DomainState::Shutdown
        );
        assert_eq!(
            DomainState::from_virsh("crashed").unwrap(),
            DomainState::Crashed
        );
        assert_eq!(
            DomainState::from_virsh("no state").unwrap(),
            DomainState::NoState
        );
    }

    #[test]
    fn domain_state_rejects_unknown_value() {
        assert!(matches!(
            DomainState::from_virsh("on fire"),
            Err(MinerAgentError::LibvirtDriver("state-parse"))
        ));
    }

    #[test]
    fn parse_domain_name_extracts_the_name() {
        let xml = "<domain><name>hippius-tenant-abc</name><uuid>x</uuid></domain>";
        assert_eq!(
            parse_domain_name(xml).unwrap().as_str(),
            "hippius-tenant-abc"
        );
    }

    #[test]
    fn parse_domain_name_fails_closed_without_a_name() {
        assert!(matches!(
            parse_domain_name("<domain></domain>"),
            Err(MinerAgentError::LibvirtDriver("name-parse"))
        ));
    }

    #[test]
    fn a_taken_cid_or_cid_named_tap_is_cid_in_use() {
        for stderr in [
            "error: Failed to start domain 'hippius-tenant-a'\nerror: internal error: \
             qemu unexpectedly closed the monitor: failed to set guest cid: Address already in use",
            "error: Failed to start domain 'hippius-tenant-a'\nerror: Unable to create tap \
             device hvt12: Device or resource busy",
            "error: Failed to start domain 'hippius-tenant-a'\nerror: The hvt12 interface \
             already exists",
        ] {
            assert_eq!(
                classify_start_failure(stderr).to_string(),
                MinerAgentError::VsockCid("cid-in-use").to_string(),
                "{stderr}"
            );
        }
        for stderr in [
            "error: Failed to start domain 'hippius-tenant-a'\nerror: Unable to create tap \
             device vnet3: Device or resource busy",
            "error: referenced filter 'clean-traffic' is missing",
            "",
        ] {
            assert_eq!(
                classify_start_failure(stderr).to_string(),
                MinerAgentError::LibvirtDriver("create").to_string(),
                "{stderr}"
            );
        }
    }

    #[test]
    fn domain_id_rejects_unsafe_characters() {
        for bad in ["", "Tenant", "a b", "a/b", "a;b", "a&b", "a<b"] {
            assert!(
                DomainId::new(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }
}
