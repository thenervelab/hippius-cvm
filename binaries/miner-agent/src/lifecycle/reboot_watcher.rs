//! libvirt-event watcher that re-pushes the cached COSE OrderTicket
//! over AF_VSOCK every time a tracked tenant CVM restarts.
//!
//! ## Why this exists
//!
//! `<on_reboot>restart</on_reboot>` in the domain XML tells libvirt to
//! relaunch the domain when the guest issues `system_reset` (which
//! `sudo reboot`, `shutdown -r now`, kernel panic w/ panic=N etc. all
//! emit). libvirt obliges: same domain UUID, same XML, same SEV-SNP
//! measured launch — the §F launch_digest does not shift, so the
//! pinned §22 allowlist entry still admits the boot.
//!
//! BUT the initial vsock push that hands the L1-signed OrderTicket to
//! the in-guest keyscript is a ONE-SHOT in
//! [`crate::vsock::ticket_push`]. Without a re-push the keyscript on
//! the post-reboot boot waits 180 s on `vsock-accept-timeout`, then
//! cryptsetup-initramfs gives up — the guest stalls in the initramfs.
//!
//! This module closes that gap. A single long-running tokio task
//! subprocesses `virsh event --all --event lifecycle --loop`, parses
//! each line, and on every `Started` event for `hippius-tenant-*`
//! looks up the cached ticket via [`CvmLifecycle::ticket_for_vm`] and
//! re-pushes via the lifecycle's [`TicketPusher`].
//!
//! ## §20 secret discipline
//!
//! The COSE OrderTicket is a PUBLIC placement assertion — its body
//! holds vm_id / lease_id / measurement / vault POINTERS (no plaintext
//! KEK, no plaintext user-data) and is L1-signed for authn, not
//! confidentiality. Persisting it in the in-memory [`CvmHandle`] is
//! §20-safe; the bytes the miner sees during the initial vsock push
//! are the same bytes we re-push here.
//!
//! ## Lifecycle
//!
//! The watcher is spawned at miner-agent startup (`serve --` boot) and
//! runs until the cancel token fires. A `virsh` exit, parse failure,
//! or empty stream is recovered by re-spawning with a 1 s backoff —
//! the watcher is best-effort glue, NOT load-bearing for launch
//! correctness (the initial launch path still pushes synchronously
//! from [`crate::orders::handler::handle_launch`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

use crate::lifecycle::cvm_handle::VmId;
use crate::lifecycle::CvmLifecycle;
use crate::vsock::ticket_push::TicketPusher;

/// Prefix every tenant domain name carries.
const DOMAIN_PREFIX: &str = "hippius-tenant-";

/// Backoff between `virsh event` respawns. A short delay so a
/// transient libvirtd hiccup doesn't lose more than ~1 s of events;
/// not so short we burn the CPU re-spawning on a permanent failure.
const RESPAWN_BACKOFF: Duration = Duration::from_secs(1);

/// Rate-limit for the SEV-SNP restart loop. SNP vCPU state cannot be
/// reset, so a guest `sudo reboot` arrives at the host as a
/// Stopped/Shutdown event (QEMU terminates with "cpus are not
/// resettable"); the watcher re-issues `virsh start` to relaunch the
/// domain. Without a rate limit a crash-looping kernel would burn CPU
/// + KBS rate-limit budget. `MAX_RESTARTS_PER_WINDOW` per
///   `RESTART_WINDOW` per vm_id, sliding.
const MAX_RESTARTS_PER_WINDOW: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Polling for the `virsh start` precondition. Libvirt may still be
/// reaping the qemu process when the Stopped event lands, so we wait
/// for `virsh domstate` to settle to `shut off` (typed below) before
/// the restart attempt. Bounded to keep a hung libvirtd from stalling
/// the watcher forever.
const DOMSTATE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const DOMSTATE_POLL_DEADLINE: Duration = Duration::from_secs(30);

/// #294 — vsock push retry window. The libvirt `Started` event fires
/// the instant QEMU returns from `qemu_init_main_loop`, well before
/// the SEV-SNP firmware has handed control to the guest kernel and
/// the guest's `hippius-vsock-ticket` listener has bound on
/// `(GUEST_CID, PORT)`. A single push at `Started` races and loses
/// the race ~every time on fresh launches (the guest binds at ~4 s
/// post-launch on a typical noble bake; the push happens at <1 s).
/// The 30-s vsock-accept-timeout inside the guest then kills the
/// keyscript and cryptsetup-initramfs gives up on the LUKS open.
///
/// Fix: spawn a retry task that re-pushes every `RETRY_INTERVAL` up
/// to `MAX_RETRIES` times. Successful pushes after the guest has the
/// ticket are no-ops on the guest side (the receiver `accept()`-and-
/// `exit()`-s, so subsequent connect attempts get ECONNRESET, which
/// the pusher logs and the loop tolerates).
///
/// The window has been widened from the original 60 s (5 s × 12)
/// to 10 min (5 s × 120) after the 2026-06-01 schema-v2 deploy
/// surfaced legitimate boots taking 7+ min to reach the keyscript
/// stage. Cause appears to be SEV-SNP firmware overhead variability
/// on freshly-restarted host kernel state — the cmdline / kernel /
/// initrd are byte-identical to fast-boot launches the day prior.
/// A push that arrives BEFORE the guest's listener binds is silently
/// dropped (no listener = no socket); a push AFTER the listener
/// `accept()`-s + `exit()`-s gets ECONNRESET; only the narrow window
/// where the listener is bound succeeds. With 5 s intervals over a
/// 10-min window we have ~120 attempts spaced across the boot, so
/// any guest that opens its listener within the window catches at
/// least one push. The cost is ~120 ECONNRESET log entries per
/// successful launch (the receiver consumes the ticket on first
/// success then exits) — acceptable given the cost of the
/// alternative (a 7-min boot that wedges 30 s into the keyscript).
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RETRIES: u32 = 120; // 10 min total — covers slow SEV-SNP firmware boots.

/// Per-vm timestamps of recent restarts. Pruned to the sliding
/// `RESTART_WINDOW` on every check.
type RestartHistory = HashMap<VmId, Vec<Instant>>;

/// Drive the watcher until `cancel` fires. Owns the long-lived
/// `virsh event` child and re-spawns it on exit.
pub async fn run(
    lifecycle: Arc<CvmLifecycle>,
    pusher: Arc<dyn TicketPusher>,
    migration: Arc<crate::orders::MigrationStore>,
    cancel: CancellationToken,
) {
    eprintln!("hippius-miner-agent: reboot-watcher: up");
    let history: Arc<Mutex<RestartHistory>> = Arc::new(Mutex::new(HashMap::new()));
    loop {
        if cancel.is_cancelled() {
            break;
        }
        match spawn_virsh_event() {
            Ok(child) => {
                run_one(child, &lifecycle, &pusher, &migration, &history, &cancel).await;
            }
            Err(class) => {
                eprintln!("hippius-miner-agent: reboot-watcher: spawn-failed:{class}");
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(RESPAWN_BACKOFF) => {}
        }
    }
    eprintln!("hippius-miner-agent: reboot-watcher: drained");
}

/// One `virsh event` lifetime — read lines until the child exits OR
/// the cancel token fires (in which case we kill the child and
/// return).
async fn run_one(
    mut child: Child,
    lifecycle: &Arc<CvmLifecycle>,
    pusher: &Arc<dyn TicketPusher>,
    migration: &Arc<crate::orders::MigrationStore>,
    history: &Arc<Mutex<RestartHistory>>,
    cancel: &CancellationToken,
) {
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            eprintln!("hippius-miner-agent: reboot-watcher: no-stdout");
            let _ = child.kill().await;
            return;
        }
    };
    let mut lines = BufReader::new(stdout).lines();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                return;
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        handle_event_line(&text, lifecycle, pusher, migration, history).await
                    }
                    Ok(None) => return, // child closed stdout
                    Err(_) => return,
                }
            }
        }
    }
}

/// Parse one line emitted by `virsh event` and act on it:
/// - `Started` → re-push the cached COSE ticket via vsock.
/// - `Stopped` → SEV-SNP cannot warm-reset the vCPUs, so a guest
///   `sudo reboot` lands here too (QEMU terminates with "cpus are not
///   resettable"). Re-issue `virsh start` so the domain relaunches
///   under the SAME XML — same kernel/initrd/cmdline → same SNP
///   launch_digest → KBS releases the same KEK on the new
///   attestation. Rate-limited per-vm to absorb a crash-loop.
async fn handle_event_line(
    line: &str,
    lifecycle: &Arc<CvmLifecycle>,
    pusher: &Arc<dyn TicketPusher>,
    migration: &Arc<crate::orders::MigrationStore>,
    history: &Arc<Mutex<RestartHistory>>,
) {
    let Some(parsed) = parse_lifecycle_event(line) else {
        return;
    };
    let Some(vm_id) = parsed
        .domain
        .strip_prefix(DOMAIN_PREFIX)
        .and_then(|s| VmId::new(s).ok())
    else {
        return;
    };
    match parsed.event {
        "Started" => handle_started(&vm_id, lifecycle, pusher).await,
        "Stopped" => handle_stopped(&vm_id, parsed.domain, lifecycle, migration, history).await,
        _ => {}
    }
}

/// Re-push the cached COSE ticket on a Started event — covers both
/// the initial launch's vsock listener race AND every subsequent
/// `virsh start` after a guest reboot.
///
/// #294 — the `Started` event arrives well before the guest's vsock
/// listener has bound, so a single push at this point races and loses
/// on fresh launches. Spawn a retry task that re-pushes every
/// [`RETRY_INTERVAL`] up to [`MAX_RETRIES`] times. The keyscript's
/// receiver `accept()`-and-`exit()`-s, so once it has the ticket
/// subsequent pushes get ECONNRESET — that's logged but doesn't
/// break the boot (we already won).
async fn handle_started(
    vm_id: &VmId,
    lifecycle: &Arc<CvmLifecycle>,
    pusher: &Arc<dyn TicketPusher>,
) {
    let Some((cid, cose_ticket)) = lifecycle.ticket_for_vm(vm_id) else {
        return;
    };
    eprintln!(
        "hippius-miner-agent: reboot-watcher: vm={} event=Started cid={cid} re-push attempt=initial",
        vm_id.as_str()
    );
    // First, immediate push. Most common outcome: ECONNRESET because
    // the guest listener isn't up yet. That's fine — the retry task
    // below covers it.
    if let Err(err) = pusher
        .push(cid, hippius_types::ticket_vsock::PORT, &cose_ticket)
        .await
    {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} re-push attempt=initial failed: {err} (expected on fresh launches; retry task will cover)",
            vm_id.as_str(),
        );
    }

    // Retry task — fire-and-forget. The watcher's process lifetime
    // bounds the task; on cancel the parent task exits + drops the
    // tokio runtime, sweeping these in turn.
    let pusher = Arc::clone(pusher);
    let vm_id_owned = vm_id.clone();
    let ticket_owned = cose_ticket.clone();
    tokio::spawn(async move {
        for attempt in 1..=MAX_RETRIES {
            tokio::time::sleep(RETRY_INTERVAL).await;
            match pusher
                .push(cid, hippius_types::ticket_vsock::PORT, &ticket_owned)
                .await
            {
                Ok(()) => {
                    eprintln!(
                        "hippius-miner-agent: reboot-watcher: vm={} re-push attempt={attempt}/{MAX_RETRIES} ok",
                        vm_id_owned.as_str(),
                    );
                }
                Err(err) => {
                    // ECONNRESET after the guest has the ticket is
                    // expected (receiver exits after one accept). Other
                    // errors (no route, libvirt down) also just log —
                    // the next interval retry covers transients.
                    eprintln!(
                        "hippius-miner-agent: reboot-watcher: vm={} re-push attempt={attempt}/{MAX_RETRIES} failed: {err}",
                        vm_id_owned.as_str(),
                    );
                }
            }
        }
    });
}

/// `virsh start` the domain after the qemu process exits, under the
/// per-vm rate limit. Bails if the vm_id isn't admitted by the
/// lifecycle (foreign / already-destroyed domain), or if the rate
/// limit window is full.
async fn handle_stopped(
    vm_id: &VmId,
    domain_name: &str,
    lifecycle: &Arc<CvmLifecycle>,
    migration: &Arc<crate::orders::MigrationStore>,
    history: &Arc<Mutex<RestartHistory>>,
) {
    // §25 cold migration — a `migrate-quiesce` deliberately STOPS the
    // source domain so its encrypted volume is crash-consistent for the
    // snapshot, and the VM must then stay stopped (it is moving to the
    // destination miner; restarting it here would both corrupt the
    // snapshot mid-stream AND re-create the split-brain the generation
    // fence exists to prevent).
    //
    // `Activated` is the ONE phase that must not suppress a restart: it
    // means THIS host is the migration's DESTINATION and the tenant is
    // now running here normally. SEV-SNP cannot warm-reset vCPUs, so an
    // in-guest `reboot` terminates QEMU and arrives here as `Stopped` —
    // this watcher is the only thing that brings it back. Treating the
    // dest's terminal phase like the source's left every migrated VM
    // unable to survive its first reboot, silently, until the agent
    // restarted and cleared the in-memory store.
    match migration.phase(vm_id) {
        Some(crate::orders::MigrationPhase::Activated) | None => {}
        Some(_) => {
            eprintln!(
                "hippius-miner-agent: reboot-watcher: vm={} event=Stopped → migration in progress, not restarting",
                vm_id.as_str()
            );
            return;
        }
    }
    // Only act on domains we admitted. A Stopped event for a domain
    // we never tracked (orphan, foreign tenant on the same libvirtd,
    // a transient test domain) is benign — ignore it.
    if lifecycle.ticket_for_vm(vm_id).is_none() {
        return;
    }
    if !claim_restart_slot(vm_id, history) {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} restart-rate-limited \
             (more than {MAX_RESTARTS_PER_WINDOW} attempts in {} s)",
            vm_id.as_str(),
            RESTART_WINDOW.as_secs(),
        );
        return;
    }
    if !wait_for_shut_off(domain_name).await {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} domstate-poll-timeout",
            vm_id.as_str()
        );
        return;
    }
    match virsh_start(domain_name).await {
        Ok(()) => {
            eprintln!(
                "hippius-miner-agent: reboot-watcher: vm={} event=Stopped → virsh start ok",
                vm_id.as_str()
            );
        }
        Err(class) => {
            eprintln!(
                "hippius-miner-agent: reboot-watcher: vm={} virsh start failed: {class}",
                vm_id.as_str()
            );
        }
    }
}

/// Reserve a restart slot in the sliding window. Prunes stale
/// timestamps in place. Returns false if the window is already full
/// — the caller logs + bails.
fn claim_restart_slot(vm_id: &VmId, history: &Arc<Mutex<RestartHistory>>) -> bool {
    let now = Instant::now();
    let Ok(mut h) = history.lock() else {
        return false;
    };
    let slot = h.entry(vm_id.clone()).or_default();
    slot.retain(|t| now.duration_since(*t) < RESTART_WINDOW);
    if slot.len() >= MAX_RESTARTS_PER_WINDOW {
        return false;
    }
    slot.push(now);
    true
}

/// Poll `virsh domstate <name>` until it reports `shut off` or the
/// deadline expires. Libvirt's Stopped event lands BEFORE qemu's
/// pid is fully reaped on busy hosts; a `virsh start` issued mid-
/// teardown returns `operation invalid`. Polling avoids both a
/// fixed-sleep race (too short → invalid op; too long → slow user
/// reboot) and the ad-hoc retry loop alternative.
async fn wait_for_shut_off(domain_name: &str) -> bool {
    let deadline = Instant::now() + DOMSTATE_POLL_DEADLINE;
    while Instant::now() < deadline {
        match virsh_domstate(domain_name).await {
            Ok(state) => {
                let trimmed = state.trim();
                if trimmed == "shut off" {
                    return true;
                }
            }
            Err(_) => return false,
        }
        tokio::time::sleep(DOMSTATE_POLL_INTERVAL).await;
    }
    false
}

/// Run `virsh domstate <name>` and return stdout trimmed.
async fn virsh_domstate(name: &str) -> Result<String, &'static str> {
    let out = Command::new("virsh")
        .args(["domstate", name])
        .output()
        .await
        .map_err(|_| "spawn")?;
    if !out.status.success() {
        return Err("non-zero");
    }
    String::from_utf8(out.stdout).map_err(|_| "decode")
}

/// `virsh start <name>` — relaunch a shut-off persistent domain.
/// The XML / measurement is unchanged so the §22 allowlist + KBS
/// release path still admits the boot.
async fn virsh_start(name: &str) -> Result<(), &'static str> {
    let out = Command::new("virsh")
        .args(["start", name])
        .output()
        .await
        .map_err(|_| "spawn")?;
    if !out.status.success() {
        return Err("non-zero");
    }
    Ok(())
}

/// One parsed lifecycle event from `virsh event` stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleEvent<'a> {
    domain: &'a str,
    event: &'a str,
}

/// The virsh stdout shape we parse:
///     event 'lifecycle' for domain 'NAME': EVENT SUBEVENT
fn parse_lifecycle_event(line: &str) -> Option<LifecycleEvent<'_>> {
    // Find the domain name between single quotes after "for domain".
    let after_for = line.find("for domain '")?;
    let rest = &line[after_for + "for domain '".len()..];
    let close = rest.find("': ")?;
    let domain = &rest[..close];
    let tail = &rest[close + "': ".len()..];
    // First whitespace-separated token after the colon is the event.
    let event = tail.split_whitespace().next()?;
    Some(LifecycleEvent { domain, event })
}

/// Subprocess `virsh event --all --event lifecycle --loop`. Stdout is
/// captured; stdin/stderr inherit so libvirt's own error messages
/// surface in the miner-agent journal.
fn spawn_virsh_event() -> Result<Child, &'static str> {
    // `--event lifecycle` and `--all` are mutually exclusive in this
    // libvirt-clients build (Debian bookworm ≥ 9.x): the former
    // subscribes to one event class but defaults to one domain, the
    // latter subscribes to every event class across every domain.
    // The combination we want — lifecycle ONLY, across ALL domains —
    // is spelled as just `--event lifecycle` (the absence of a
    // `--domain` filter scopes it to every domain on the connection).
    Command::new("virsh")
        .args(["event", "--event", "lifecycle", "--loop"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "spawn-virsh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_lifecycle_line() {
        let line = "event 'lifecycle' for domain 'hippius-tenant-vm-1': Started Booted";
        let parsed = parse_lifecycle_event(line).unwrap();
        assert_eq!(parsed.domain, "hippius-tenant-vm-1");
        assert_eq!(parsed.event, "Started");
    }

    #[test]
    fn parses_stopped_event() {
        let line = "event 'lifecycle' for domain 'hippius-tenant-vm-2': Stopped Shutdown";
        let parsed = parse_lifecycle_event(line).unwrap();
        assert_eq!(parsed.event, "Stopped");
    }

    #[test]
    fn rejects_unrelated_line() {
        assert!(parse_lifecycle_event("Welcome to virsh, the virtualization tool.").is_none());
        assert!(parse_lifecycle_event("").is_none());
    }

    #[test]
    fn extracts_vm_id_from_domain_prefix() {
        let line = "event 'lifecycle' for domain 'hippius-tenant-vm-z': Started Booted";
        let parsed = parse_lifecycle_event(line).unwrap();
        let stripped = parsed.domain.strip_prefix(DOMAIN_PREFIX).unwrap();
        assert_eq!(stripped, "vm-z");
    }

    #[test]
    fn restart_rate_limit_blocks_after_window_full() {
        let history: Arc<Mutex<RestartHistory>> = Arc::new(Mutex::new(HashMap::new()));
        let vm = VmId::new("vm-burst").unwrap();
        // First MAX_RESTARTS_PER_WINDOW claims must succeed.
        for _ in 0..MAX_RESTARTS_PER_WINDOW {
            assert!(claim_restart_slot(&vm, &history));
        }
        // The next one fails — sliding window full.
        assert!(!claim_restart_slot(&vm, &history));
    }

    #[test]
    fn restart_rate_limit_is_per_vm() {
        let history: Arc<Mutex<RestartHistory>> = Arc::new(Mutex::new(HashMap::new()));
        let a = VmId::new("vm-a").unwrap();
        let b = VmId::new("vm-b").unwrap();
        // Filling A's window must not affect B's.
        for _ in 0..MAX_RESTARTS_PER_WINDOW {
            assert!(claim_restart_slot(&a, &history));
        }
        assert!(!claim_restart_slot(&a, &history));
        assert!(claim_restart_slot(&b, &history));
    }
}
