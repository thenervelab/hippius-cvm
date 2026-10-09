//! Per-VM **guest-poweroff policy**: what the agent does when a tenant
//! guest powers itself off — start it again (`restart`, the historic
//! behaviour) or leave it stopped (`stop`, e.g. a single-use CI runner
//! that powers off when its job is done).
//!
//! ## Telling a guest poweroff from everything else
//!
//! SEV-SNP vCPUs cannot be reset, so QEMU terminates on a guest REBOOT
//! too ("cpus are not resettable"): libvirt's lifecycle stream shows the
//! same `Stopped` for a reboot, a poweroff and a crash. The one place the
//! cause survives is QEMU's QMP `SHUTDOWN` event, which libvirt forwards
//! verbatim on `virsh qemu-monitor-event`:
//!
//! - `{"guest":true,"reason":"guest-shutdown"}` — the guest powered off
//!   (ACPI S5 / `poweroff`);
//! - `{"guest":true,"reason":"guest-reset"}` — a guest reboot on SNP;
//! - `guest-panic`, `host-signal`, … — everything else;
//! - no event at all — QEMU was killed or crashed.
//!
//! libvirt then kills QEMU itself, and QEMU may answer that SIGTERM with a
//! second `SHUTDOWN` (`host-signal`), so only the FIRST event of a run
//! counts ([`GuestRuns::note_shutdown`]). A run begins at libvirt's
//! `Started` and ends when its `Stopped` is handled; a line stamped before
//! the run began, or arriving after it ended, is an older run's straggler
//! and is never credited to it.
//!
//! A host-side ACPI powerdown (`virsh shutdown` by an operator, outside the
//! agent's own stops) also reads `guest-shutdown`: the guest does power
//! itself off. A miner can stop a VM anyway; it only changes the label.
//!
//! A guest poweroff is honoured as `stop` only once the guest's userspace
//! has reached the host relay in that run ([`GuestRuns::note_guest_up`]):
//! the initramfs powers the VM off when it fails closed (KBS refused, no
//! ticket, unlock failed), and that is a boot failure, not the tenant's
//! choice — it keeps being retried, as before.
//!
//! Everything that is not a proven guest poweroff after userspace is
//! RESTARTED, whatever the policy ([`decide`]). Missing evidence (the QMP
//! stream was down, the agent restarted under the guest) therefore costs
//! one extra boot, never a VM left down after a crash.
//!
//! ## Persistence
//!
//! One small JSON file per VM under `<state_root>/power-policy/`, on the
//! same durable volume as the re-adoption snapshots, read fresh on every
//! decision — so a SIGKILL agent swap loses nothing. It holds the policy
//! and, once a `stop` VM powered itself off, the time it did: the
//! `domain-state` probe reports `stop_reason: guest-poweroff` from it so
//! vali settles the VM `stopped` instead of relaunching it. A launch
//! rewrites the file from its order (absent field ⇒ the file is removed
//! ⇒ `restart`); a §24 destroy removes it.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::cvm_handle::VmId;
use crate::error::{MinerAgentError, Result};
use crate::orders::OnGuestPoweroff;

/// Subdirectory (under the state-disk root) holding one JSON per VM.
const POLICY_SUBDIR: &str = "power-policy";

/// The on-disk record for one VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecord {
    /// The tenant's choice.
    pub on_guest_poweroff: OnGuestPoweroff,
    /// Unix seconds at which the agent left this VM stopped after its
    /// guest powered off. Cleared by the next launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_poweroff_at: Option<u64>,
}

fn policy_dir(state_root: &Path) -> PathBuf {
    state_root.join(POLICY_SUBDIR)
}

fn policy_path(state_root: &Path, vm_id: &VmId) -> PathBuf {
    policy_dir(state_root).join(format!("{}.json", vm_id.as_str()))
}

/// The VM's record, `None` when it has none (⇒ `restart`).
pub fn load(state_root: &Path, vm_id: &VmId) -> Result<Option<PolicyRecord>> {
    let bytes = match std::fs::read(policy_path(state_root, vm_id)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(MinerAgentError::PowerPolicyStore("read")),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| MinerAgentError::PowerPolicyStore("parse"))
}

/// The VM's policy (`restart` when it has no record).
pub fn policy(state_root: &Path, vm_id: &VmId) -> Result<OnGuestPoweroff> {
    Ok(load(state_root, vm_id)?.map_or(OnGuestPoweroff::Restart, |r| r.on_guest_poweroff))
}

/// Serialises every write (and read-modify-write) of the store in this
/// process: a launch, a `power-policy` order and a guest-poweroff mark can
/// race on one VM's record.
static STORE_LOCK: Mutex<()> = Mutex::new(());

fn locked<R>(f: impl FnOnce() -> Result<R>) -> Result<R> {
    let _guard = STORE_LOCK
        .lock()
        .map_err(|_| MinerAgentError::PowerPolicyStore("lock"))?;
    f()
}

/// Apply a launch order's field: `Some` is persisted, `None` removes the
/// record (⇒ `restart`). Either way any guest-poweroff mark is gone: the
/// VM is being started.
pub fn apply_launch(
    state_root: &Path,
    vm_id: &VmId,
    policy: Option<OnGuestPoweroff>,
) -> Result<()> {
    locked(|| match policy {
        Some(p) => write(
            state_root,
            vm_id,
            &PolicyRecord {
                on_guest_poweroff: p,
                guest_poweroff_at: None,
            },
        ),
        None => remove_unlocked(state_root, vm_id),
    })
}

/// Change the VM's policy in place (a `power-policy` order). Keeps a
/// guest-poweroff mark: only a launch says the VM is up again.
pub fn change(state_root: &Path, vm_id: &VmId, policy: OnGuestPoweroff) -> Result<()> {
    locked(|| {
        let mark = load(state_root, vm_id)?.and_then(|r| r.guest_poweroff_at);
        write(
            state_root,
            vm_id,
            &PolicyRecord {
                on_guest_poweroff: policy,
                guest_poweroff_at: mark,
            },
        )
    })
}

/// Mark the VM as left stopped after its guest powered off, at `now`.
pub fn record_guest_poweroff(state_root: &Path, vm_id: &VmId, now: u64) -> Result<()> {
    locked(|| {
        let policy = policy(state_root, vm_id)?;
        write(
            state_root,
            vm_id,
            &PolicyRecord {
                on_guest_poweroff: policy,
                guest_poweroff_at: Some(now),
            },
        )
    })
}

/// Whether the VM was left stopped after its guest powered off. A record
/// that cannot be read answers `false`: the probe then reports a plain
/// "down", which vali treats as before.
pub fn stopped_by_guest(state_root: &Path, vm_id: &VmId) -> bool {
    matches!(
        load(state_root, vm_id),
        Ok(Some(PolicyRecord {
            guest_poweroff_at: Some(_),
            ..
        }))
    )
}

/// Remove the VM's record. Idempotent.
pub fn remove(state_root: &Path, vm_id: &VmId) -> Result<()> {
    locked(|| remove_unlocked(state_root, vm_id))
}

fn remove_unlocked(state_root: &Path, vm_id: &VmId) -> Result<()> {
    match std::fs::remove_file(policy_path(state_root, vm_id)) {
        Ok(()) => sync_dir(state_root),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(MinerAgentError::PowerPolicyStore("remove")),
    }
}

/// Make a rename / unlink in the store durable: without it a host power
/// loss can bring back a record that was replaced or removed.
fn sync_dir(state_root: &Path) -> Result<()> {
    std::fs::File::open(policy_dir(state_root))
        .and_then(|d| d.sync_all())
        .map_err(|_| MinerAgentError::PowerPolicyStore("sync"))
}

/// Write `record` through a synced temp file and a rename, so a crash or
/// a full disk never leaves a truncated record behind. Callers hold
/// [`STORE_LOCK`].
fn write(state_root: &Path, vm_id: &VmId, record: &PolicyRecord) -> Result<()> {
    let dir = policy_dir(state_root);
    std::fs::create_dir_all(&dir).map_err(|_| MinerAgentError::PowerPolicyStore("mkdir"))?;
    let json =
        serde_json::to_vec(record).map_err(|_| MinerAgentError::PowerPolicyStore("encode"))?;
    let final_path = policy_path(state_root, vm_id);
    let tmp_path = final_path.with_extension("json.tmp");
    let mut file =
        std::fs::File::create(&tmp_path).map_err(|_| MinerAgentError::PowerPolicyStore("write"))?;
    file.write_all(&json)
        .map_err(|_| MinerAgentError::PowerPolicyStore("write"))?;
    file.sync_all()
        .map_err(|_| MinerAgentError::PowerPolicyStore("sync"))?;
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|_| MinerAgentError::PowerPolicyStore("rename"))?;
    sync_dir(state_root)
}

/// The cause of one QMP `SHUTDOWN` event, reduced to what [`decide`]
/// needs plus a static label for the log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownCause {
    /// `guest: true, reason: "guest-shutdown"` — the guest powered off.
    GuestPoweroff,
    /// Any other reason (a guest reset, a panic, a host signal, …).
    Other(&'static str),
}

/// Map a QMP `SHUTDOWN` payload to a [`ShutdownCause`]. Only the exact
/// guest-initiated poweroff is [`ShutdownCause::GuestPoweroff`].
pub fn shutdown_cause(guest: bool, reason: &str) -> ShutdownCause {
    if guest && reason == "guest-shutdown" {
        return ShutdownCause::GuestPoweroff;
    }
    ShutdownCause::Other(match reason {
        "guest-shutdown" => "guest-shutdown-not-guest",
        "guest-reset" => "guest-reset",
        "guest-panic" => "guest-panic",
        "host-signal" => "host-signal",
        "host-error" => "host-error",
        "host-qmp-quit" => "host-qmp-quit",
        "host-qmp-system-reset" => "host-qmp-system-reset",
        "host-ui" => "host-ui",
        "subsystem-reset" => "subsystem-reset",
        "snapshot-load" => "snapshot-load",
        "none" => "none",
        _ => "unknown",
    })
}

/// Parse one `virsh qemu-monitor-event` line for a `SHUTDOWN` event:
///
/// ```text
/// event SHUTDOWN at 1760000000.123456 for domain 'NAME': {"guest":true,"reason":"guest-shutdown"}
/// ```
///
/// One parsed `SHUTDOWN` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownEvent<'a> {
    /// The libvirt domain name.
    pub domain: &'a str,
    /// What caused it.
    pub cause: ShutdownCause,
    /// QEMU's own timestamp of the event, in Unix microseconds (`None` if
    /// the line carries none that parses).
    pub at_us: Option<u64>,
}

/// Returns the domain, the cause and QEMU's timestamp; `None` for any
/// other line. A payload without a boolean `guest` is not guest-initiated.
pub fn parse_shutdown_event(line: &str) -> Option<ShutdownEvent<'_>> {
    let rest = line.strip_prefix("event SHUTDOWN ")?;
    let at_us = rest
        .strip_prefix("at ")
        .and_then(|r| r.split_whitespace().next())
        .and_then(parse_unix_us);
    let after_for = rest.find("for domain '")?;
    let rest = &rest[after_for + "for domain '".len()..];
    let close = rest.find("': ")?;
    let domain = &rest[..close];
    let details: serde_json::Value =
        serde_json::from_str(rest[close + "': ".len()..].trim()).ok()?;
    let guest = details
        .get("guest")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let reason = details
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    Some(ShutdownEvent {
        domain,
        cause: shutdown_cause(guest, reason),
        at_us,
    })
}

/// `<seconds>.<6 digits>` → Unix microseconds.
fn parse_unix_us(s: &str) -> Option<u64> {
    let (secs, micros) = s.split_once('.')?;
    if micros.len() != 6 {
        return None;
    }
    let secs: u64 = secs.parse().ok()?;
    let micros: u64 = micros.parse().ok()?;
    secs.checked_mul(1_000_000)?.checked_add(micros)
}

/// What the agent observed about one run of a VM (Started → Stopped).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunEvidence {
    /// The cause of the run's FIRST QMP `SHUTDOWN` event.
    pub first_shutdown: Option<ShutdownCause>,
    /// The guest's userspace reached the host relay during the run.
    pub guest_up: bool,
}

/// Per-VM [`RunEvidence`] for the current run, fed by the QMP stream,
/// the vsock relay and libvirt's `Started` events. In memory only: what
/// it would lose on an agent restart is covered by [`decide`] restarting
/// on missing evidence.
#[derive(Debug, Default)]
pub struct GuestRuns {
    runs: Mutex<HashMap<VmId, RunState>>,
}

/// One VM's tracked run.
#[derive(Debug, Default)]
struct RunState {
    evidence: RunEvidence,
    /// When the run began (`Started`), Unix µs. A `SHUTDOWN` stamped
    /// earlier belongs to an older run whose line arrived late. `None`
    /// when no `Started` was seen (the agent started under the guest).
    started_at_us: Option<u64>,
    /// The run's `Stopped` was handled: nothing more is credited to it,
    /// so a straggler line can never become the next run's first event.
    ended: bool,
}

impl GuestRuns {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut HashMap<VmId, RunState>) -> R) -> Option<R> {
        self.runs.lock().ok().map(|mut runs| f(&mut runs))
    }

    /// A new run of `vm_id` began (libvirt `Started`) at `started_at_us`:
    /// forget the last one.
    pub fn begin_run(&self, vm_id: &VmId, started_at_us: u64) {
        self.with(|runs| {
            runs.insert(
                vm_id.clone(),
                RunState {
                    started_at_us: Some(started_at_us),
                    ..RunState::default()
                },
            )
        });
    }

    /// The guest's userspace reached the host relay.
    pub fn note_guest_up(&self, vm_id: &VmId) {
        self.with(|runs| {
            let run = runs.entry(vm_id.clone()).or_default();
            if !run.ended {
                run.evidence.guest_up = true;
            }
        });
    }

    /// A QMP `SHUTDOWN` stamped `at_us` arrived. Only the first of a run
    /// is kept, and never one stamped before the run began or arriving
    /// after it ended.
    pub fn note_shutdown(&self, vm_id: &VmId, cause: ShutdownCause, at_us: Option<u64>) {
        self.with(|runs| {
            let run = runs.entry(vm_id.clone()).or_default();
            let stale = match run.started_at_us {
                Some(start) => at_us.is_none_or(|at| at < start),
                None => false,
            };
            if !run.ended && !stale && run.evidence.first_shutdown.is_none() {
                run.evidence.first_shutdown = Some(cause);
            }
        });
    }

    /// The run's first shutdown cause so far, without consuming it.
    pub fn first_shutdown(&self, vm_id: &VmId) -> Option<ShutdownCause> {
        self.with(|runs| runs.get(vm_id).and_then(|r| r.evidence.first_shutdown))
            .flatten()
    }

    /// Consume the run's evidence: its `Stopped` is being handled.
    pub fn take(&self, vm_id: &VmId) -> RunEvidence {
        self.with(|runs| {
            let run = runs.entry(vm_id.clone()).or_default();
            run.ended = true;
            std::mem::take(&mut run.evidence)
        })
        .unwrap_or_default()
    }

    /// Drop everything about `vm_id` (its CID was released).
    pub fn forget(&self, vm_id: &VmId) {
        self.with(|runs| runs.remove(vm_id));
    }
}

/// What to do with a tenant domain that stopped on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoweroffVerdict {
    /// Start it again; the label says why (for the log line).
    Restart(&'static str),
    /// Leave it stopped: a `stop` VM whose booted guest powered off.
    StayStopped,
}

/// The decision. `StayStopped` needs ALL of: policy `stop`, the run's
/// first `SHUTDOWN` a guest poweroff, and the guest's userspace up. Any
/// gap in that evidence restarts.
pub fn decide(policy: OnGuestPoweroff, evidence: RunEvidence) -> PoweroffVerdict {
    if policy == OnGuestPoweroff::Restart {
        return PoweroffVerdict::Restart("policy-restart");
    }
    match evidence.first_shutdown {
        None => PoweroffVerdict::Restart("no-shutdown-event"),
        Some(ShutdownCause::Other(reason)) => PoweroffVerdict::Restart(reason),
        Some(ShutdownCause::GuestPoweroff) if !evidence.guest_up => {
            PoweroffVerdict::Restart("poweroff-before-userspace")
        }
        Some(ShutdownCause::GuestPoweroff) => PoweroffVerdict::StayStopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(s: &str) -> VmId {
        VmId::new(s).unwrap()
    }

    #[test]
    fn absent_record_is_restart() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path(), &vm("a")).unwrap(), None);
        assert_eq!(
            policy(dir.path(), &vm("a")).unwrap(),
            OnGuestPoweroff::Restart
        );
        assert!(!stopped_by_guest(dir.path(), &vm("a")));
    }

    #[test]
    fn set_record_and_launch_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let v = vm("a");
        apply_launch(dir.path(), &v, Some(OnGuestPoweroff::Stop)).unwrap();
        assert_eq!(policy(dir.path(), &v).unwrap(), OnGuestPoweroff::Stop);
        record_guest_poweroff(dir.path(), &v, 1_760_000_000).unwrap();
        assert!(stopped_by_guest(dir.path(), &v));
        assert_eq!(
            load(dir.path(), &v).unwrap(),
            Some(PolicyRecord {
                on_guest_poweroff: OnGuestPoweroff::Stop,
                guest_poweroff_at: Some(1_760_000_000),
            })
        );
        // A policy change in place keeps the mark.
        change(dir.path(), &v, OnGuestPoweroff::Restart).unwrap();
        assert!(stopped_by_guest(dir.path(), &v));
        assert_eq!(policy(dir.path(), &v).unwrap(), OnGuestPoweroff::Restart);
        // A relaunch carrying `stop` sets the policy and drops the mark.
        apply_launch(dir.path(), &v, Some(OnGuestPoweroff::Stop)).unwrap();
        assert!(!stopped_by_guest(dir.path(), &v));
        assert_eq!(policy(dir.path(), &v).unwrap(), OnGuestPoweroff::Stop);
        // One without the field is `restart`, with no record left.
        apply_launch(dir.path(), &v, None).unwrap();
        assert_eq!(load(dir.path(), &v).unwrap(), None);
        // Removing twice is fine.
        remove(dir.path(), &v).unwrap();
        // No temp file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(policy_dir(dir.path()))
            .unwrap()
            .flatten()
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn the_record_survives_a_new_reader() {
        // An agent restart is a new process reading the same file.
        let dir = tempfile::tempdir().unwrap();
        apply_launch(dir.path(), &vm("a"), Some(OnGuestPoweroff::Stop)).unwrap();
        let bytes = std::fs::read(policy_path(dir.path(), &vm("a"))).unwrap();
        assert_eq!(bytes, br#"{"on_guest_poweroff":"stop"}"#);
        assert_eq!(policy(dir.path(), &vm("a")).unwrap(), OnGuestPoweroff::Stop);
    }

    #[test]
    fn a_corrupt_record_is_an_error_not_a_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(policy_dir(dir.path())).unwrap();
        std::fs::write(
            policy_path(dir.path(), &vm("a")),
            b"{\"on_guest_poweroff\":",
        )
        .unwrap();
        assert!(matches!(
            policy(dir.path(), &vm("a")),
            Err(MinerAgentError::PowerPolicyStore("parse"))
        ));
        assert!(!stopped_by_guest(dir.path(), &vm("a")));
    }

    fn ev(domain: &str, cause: ShutdownCause, at_us: Option<u64>) -> Option<ShutdownEvent<'_>> {
        Some(ShutdownEvent {
            domain,
            cause,
            at_us,
        })
    }

    #[test]
    fn parses_the_virsh_qemu_monitor_event_lines() {
        let poweroff = r#"event SHUTDOWN at 1760000000.123456 for domain 'hippius-tenant-a': {"guest":true,"reason":"guest-shutdown"}"#;
        assert_eq!(
            parse_shutdown_event(poweroff),
            ev(
                "hippius-tenant-a",
                ShutdownCause::GuestPoweroff,
                Some(1_760_000_000_123_456)
            )
        );
        let reboot = r#"event SHUTDOWN at 1760000000.000001 for domain 'hippius-tenant-a': {"guest":true,"reason":"guest-reset"}"#;
        assert_eq!(
            parse_shutdown_event(reboot),
            ev(
                "hippius-tenant-a",
                ShutdownCause::Other("guest-reset"),
                Some(1_760_000_000_000_001)
            )
        );
        // A timestamp that is not `<s>.<6 digits>` parses as none.
        let killed = r#"event SHUTDOWN at 1760000000.2 for domain 'hippius-tenant-a': {"guest":false,"reason":"host-signal"}"#;
        assert_eq!(
            parse_shutdown_event(killed),
            ev(
                "hippius-tenant-a",
                ShutdownCause::Other("host-signal"),
                None
            )
        );
        // A host-side ACPI request still shows `guest-shutdown`, but a
        // `guest:false` one is not the guest's own poweroff.
        let host = r#"event SHUTDOWN at 1.000000 for domain 'x': {"guest":false,"reason":"guest-shutdown"}"#;
        assert_eq!(
            parse_shutdown_event(host),
            ev(
                "x",
                ShutdownCause::Other("guest-shutdown-not-guest"),
                Some(1_000_000)
            )
        );
        // Old QEMU without a reason, or no payload at all.
        assert_eq!(
            parse_shutdown_event("event SHUTDOWN at 1.000000 for domain 'x': {}"),
            ev("x", ShutdownCause::Other("unknown"), Some(1_000_000))
        );
        assert_eq!(
            parse_shutdown_event("event SHUTDOWN at 1.000000 for domain 'x': (null)"),
            None
        );
        assert_eq!(
            parse_shutdown_event(r#"event RESET at 1.000000 for domain 'x': {"guest":true}"#),
            None
        );
        assert_eq!(parse_shutdown_event("events received: 3"), None);
    }

    const T0: u64 = 1_760_000_000_000_000;

    #[test]
    fn only_the_first_shutdown_of_a_run_counts() {
        let runs = GuestRuns::new();
        let v = vm("a");
        runs.begin_run(&v, T0);
        runs.note_guest_up(&v);
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, Some(T0 + 10));
        // libvirt's own SIGTERM that follows.
        runs.note_shutdown(&v, ShutdownCause::Other("host-signal"), Some(T0 + 20));
        assert_eq!(
            runs.take(&v),
            RunEvidence {
                first_shutdown: Some(ShutdownCause::GuestPoweroff),
                guest_up: true,
            }
        );
        // And the reverse: a reboot followed by a poweroff-looking event.
        runs.begin_run(&v, T0 + 100);
        runs.note_shutdown(&v, ShutdownCause::Other("guest-reset"), Some(T0 + 110));
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, Some(T0 + 120));
        assert_eq!(
            runs.take(&v).first_shutdown,
            Some(ShutdownCause::Other("guest-reset"))
        );
        // Taken evidence is gone.
        assert_eq!(runs.take(&v), RunEvidence::default());
    }

    #[test]
    fn a_new_run_forgets_the_last() {
        let runs = GuestRuns::new();
        let v = vm("a");
        runs.note_guest_up(&v);
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, Some(T0));
        runs.begin_run(&v, T0 + 1);
        assert_eq!(runs.take(&v), RunEvidence::default());
    }

    #[test]
    fn a_straggler_from_an_older_run_is_never_credited_to_the_next() {
        let runs = GuestRuns::new();
        let v = vm("a");
        // Run N ended (its Stopped handled): a late line is dropped…
        runs.begin_run(&v, T0);
        runs.take(&v);
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, Some(T0 + 5));
        runs.note_guest_up(&v);
        assert_eq!(runs.first_shutdown(&v), None);
        // …and once run N+1 began, a line stamped before it is too.
        runs.begin_run(&v, T0 + 1_000);
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, Some(T0 + 5));
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, None);
        assert_eq!(runs.first_shutdown(&v), None);
        // Run N+1's own event counts.
        runs.note_shutdown(&v, ShutdownCause::Other("guest-reset"), Some(T0 + 2_000));
        assert_eq!(
            runs.first_shutdown(&v),
            Some(ShutdownCause::Other("guest-reset"))
        );
    }

    #[test]
    fn without_a_seen_start_any_event_counts() {
        // The agent started under a running guest: no `Started` to compare.
        let runs = GuestRuns::new();
        let v = vm("a");
        runs.note_shutdown(&v, ShutdownCause::GuestPoweroff, None);
        assert_eq!(runs.first_shutdown(&v), Some(ShutdownCause::GuestPoweroff));
        runs.forget(&v);
        assert_eq!(runs.first_shutdown(&v), None);
    }

    #[test]
    fn stay_stopped_needs_policy_stop_a_guest_poweroff_and_userspace() {
        let poweroff_up = RunEvidence {
            first_shutdown: Some(ShutdownCause::GuestPoweroff),
            guest_up: true,
        };
        assert_eq!(
            decide(OnGuestPoweroff::Stop, poweroff_up),
            PoweroffVerdict::StayStopped
        );
        // `restart` never stays stopped.
        assert_eq!(
            decide(OnGuestPoweroff::Restart, poweroff_up),
            PoweroffVerdict::Restart("policy-restart")
        );
        // A crash (QEMU killed: no SHUTDOWN at all) always restarts.
        assert_eq!(
            decide(
                OnGuestPoweroff::Stop,
                RunEvidence {
                    first_shutdown: None,
                    guest_up: true
                }
            ),
            PoweroffVerdict::Restart("no-shutdown-event")
        );
        // A reboot, a panic, a host signal: restart.
        for reason in ["guest-reset", "guest-panic", "host-signal"] {
            assert_eq!(
                decide(
                    OnGuestPoweroff::Stop,
                    RunEvidence {
                        first_shutdown: Some(ShutdownCause::Other(reason)),
                        guest_up: true
                    }
                ),
                PoweroffVerdict::Restart(reason)
            );
        }
        // The initramfs failing closed before userspace: restart.
        assert_eq!(
            decide(
                OnGuestPoweroff::Stop,
                RunEvidence {
                    first_shutdown: Some(ShutdownCause::GuestPoweroff),
                    guest_up: false
                }
            ),
            PoweroffVerdict::Restart("poweroff-before-userspace")
        );
    }
}
