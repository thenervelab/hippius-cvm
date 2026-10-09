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
//! ## Guest poweroff
//!
//! A VM whose guest-poweroff policy is `stop`
//! ([`crate::lifecycle::power_policy`]) is NOT restarted when its booted
//! guest powers itself off: the watcher leaves it stopped and marks it so
//! the `domain-state` probe tells vali. The cause comes from QEMU's QMP
//! `SHUTDOWN` event, read on a second stream (`virsh qemu-monitor-event`)
//! this module also owns; everything else (a crash, a reboot, a panic, a
//! missing event) is restarted as before.
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

use async_trait::async_trait;

use crate::lifecycle::cvm_handle::VmId;
use crate::lifecycle::power_policy::{self, PoweroffVerdict};
use crate::lifecycle::{CvmLifecycle, TicketPushState};
use crate::orders::OnGuestPoweroff;
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

/// How long a `stop`-policy VM's `Stopped` waits for the run's QMP
/// `SHUTDOWN` event once the domain is shut off. QEMU emits it before
/// libvirt kills the process, so it is normally already there; it travels
/// on another `virsh` stream, though, and this covers the skew. A VM still
/// without one is restarted (no evidence of a guest poweroff).
const SHUTDOWN_EVIDENCE_GRACE: Duration = Duration::from_secs(3);
const SHUTDOWN_EVIDENCE_POLL: Duration = Duration::from_millis(50);

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
const MAX_RETRIES: u32 = 120;
/// Wall-clock bound on the whole re-push task. Each push can itself spin
/// in its connect loop for `PUSH_TIMEOUT_SECS` (180 s), so `MAX_RETRIES`
/// alone stretched the "10 min" window to ~6 h.
const RETRY_WINDOW: Duration = Duration::from_secs(10 * 60);

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
    let control: Arc<dyn DomainControl> = Arc::new(VirshControl);
    let shutdown_events = tokio::spawn(run_shutdown_events(
        Arc::clone(&lifecycle),
        "virsh".into(),
        cancel.clone(),
    ));
    loop {
        if cancel.is_cancelled() {
            break;
        }
        match spawn_virsh_event() {
            Ok(child) => {
                let ctx = WatchCtx {
                    lifecycle: &lifecycle,
                    pusher: &pusher,
                    migration: &migration,
                    history: &history,
                    control: control.as_ref(),
                };
                run_one(child, &ctx, &cancel).await;
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
    let _ = shutdown_events.await;
    eprintln!("hippius-miner-agent: reboot-watcher: drained");
}

/// Wall-clock now in Unix µs — the clock QEMU stamps QMP events with.
fn unix_now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Everything one lifecycle event is handled with.
struct WatchCtx<'a> {
    lifecycle: &'a Arc<CvmLifecycle>,
    pusher: &'a Arc<dyn TicketPusher>,
    migration: &'a Arc<crate::orders::MigrationStore>,
    history: &'a Arc<Mutex<RestartHistory>>,
    control: &'a dyn DomainControl,
}

/// The two libvirt calls the `Stopped` path makes — a seam so tests can
/// drive the real decision without a libvirtd.
#[async_trait]
trait DomainControl: Send + Sync {
    /// `virsh domstate <name>`, trimmed.
    async fn domstate(&self, name: &str) -> Result<String, &'static str>;
    /// `virsh start <name>`.
    async fn start(&self, name: &str) -> Result<(), &'static str>;
}

/// Production [`DomainControl`]: shells out to `virsh`.
struct VirshControl;

#[async_trait]
impl DomainControl for VirshControl {
    async fn domstate(&self, name: &str) -> Result<String, &'static str> {
        virsh_domstate(name).await
    }
    async fn start(&self, name: &str) -> Result<(), &'static str> {
        virsh_start(name).await
    }
}

/// Feed every tenant domain's QMP `SHUTDOWN` events into the lifecycle's
/// [`power_policy::GuestRuns`] until `cancel` fires, re-spawning
/// `virsh qemu-monitor-event` like the lifecycle stream. While this
/// stream is down a poweroff carries no evidence and is restarted.
async fn run_shutdown_events(
    lifecycle: Arc<CvmLifecycle>,
    virsh: std::path::PathBuf,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            break;
        }
        match spawn_virsh_shutdown_events(&virsh) {
            Ok(mut child) => match child.stdout.take() {
                Some(stdout) => {
                    let mut lines = BufReader::new(stdout).lines();
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                let _ = child.kill().await;
                                return;
                            }
                            line = lines.next_line() => match line {
                                Ok(Some(text)) => note_shutdown_line(&text, &lifecycle),
                                Ok(None) | Err(_) => break,
                            }
                        }
                    }
                    let _ = child.kill().await;
                }
                None => {
                    eprintln!("hippius-miner-agent: reboot-watcher: qmp-events: no-stdout");
                    let _ = child.kill().await;
                }
            },
            Err(class) => {
                eprintln!("hippius-miner-agent: reboot-watcher: qmp-events: spawn-failed:{class}");
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(RESPAWN_BACKOFF) => {}
        }
    }
}

/// Record one `virsh qemu-monitor-event` line, if it is a tenant's
/// `SHUTDOWN`.
fn note_shutdown_line(line: &str, lifecycle: &CvmLifecycle) {
    let Some(event) = power_policy::parse_shutdown_event(line) else {
        return;
    };
    let cause = event.cause;
    let Some(vm_id) = event
        .domain
        .strip_prefix(DOMAIN_PREFIX)
        .and_then(|s| VmId::new(s).ok())
    else {
        return;
    };
    eprintln!(
        "hippius-miner-agent: reboot-watcher: vm={} event=SHUTDOWN cause={cause:?}",
        vm_id.as_str()
    );
    lifecycle
        .guest_runs()
        .note_shutdown(&vm_id, cause, event.at_us);
}

/// Subprocess `virsh qemu-monitor-event --event SHUTDOWN --loop`: every
/// domain's QMP `SHUTDOWN`, payload verbatim. Registering for monitor
/// events does not taint a domain.
fn spawn_virsh_shutdown_events(virsh: &std::path::Path) -> Result<Child, &'static str> {
    Command::new(virsh)
        .args(["qemu-monitor-event", "--event", "SHUTDOWN", "--loop"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "spawn-virsh")
}

/// One `virsh event` lifetime — read lines until the child exits OR
/// the cancel token fires (in which case we kill the child and
/// return).
async fn run_one(mut child: Child, ctx: &WatchCtx<'_>, cancel: &CancellationToken) {
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
                    Ok(Some(text)) => handle_event_line(&text, ctx).await,
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
async fn handle_event_line(line: &str, ctx: &WatchCtx<'_>) {
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
        "Started" => {
            // A new run: what was observed of the last one no longer
            // describes this guest.
            ctx.lifecycle.guest_runs().begin_run(&vm_id, unix_now_us());
            handle_started(&vm_id, ctx.lifecycle, ctx.pusher).await
        }
        "Stopped" => handle_stopped(&vm_id, parsed.domain, ctx).await,
        _ => {}
    }
}

/// Re-push the cached COSE ticket on a Started event — covers both
/// the initial launch's vsock listener race AND every subsequent
/// `virsh start` after a guest reboot.
///
/// #294 — the `Started` event arrives well before the guest's vsock
/// listener has bound, so a single push at this point races and loses
/// on fresh launches. Spawn a task that pushes every [`RETRY_INTERVAL`]
/// for at most [`MAX_RETRIES`] attempts inside [`RETRY_WINDOW`].
///
/// The task keeps pushing after a delivery on purpose: the legacy LUKS
/// keyscript runs under cryptroot's retry loop, and every rerun binds a
/// fresh listener that needs the ticket again. That is only ever THIS
/// VM's own guest asking — which is what the ownership guard below
/// enforces on every attempt.
///
/// What the task must never do is outlive its VM. A CID is an address,
/// not an identity: once the VM is stopped its CID is free and the next
/// launch may take it. The task is registered with the lifecycle
/// ([`CvmLifecycle::begin_ticket_push`]) so a stop / §24 destroy cancels
/// it before the CID is released, a new `Started` for the same VM
/// supersedes it, and every connect re-checks
/// [`CvmLifecycle::ticket_push_current`] — so a dead VM's ticket can
/// never reach the guest that inherits its CID (observed live
/// 2026-09-24: a destroyed VM's hours-long retry loop delivered its
/// ticket to the new VM on the reused CID first → KBS 403 → the golden
/// initramfs fails closed and the new tenant never boots).
async fn handle_started(
    vm_id: &VmId,
    lifecycle: &Arc<CvmLifecycle>,
    pusher: &Arc<dyn TicketPusher>,
) {
    let Some((cid, cose_ticket)) = lifecycle.ticket_for_vm(vm_id) else {
        return;
    };
    eprintln!(
        "hippius-miner-agent: reboot-watcher: vm={} event=Started cid={cid} re-push window open",
        vm_id.as_str()
    );
    // A re-adopted VM whose cid is still unconfirmed: its restarted guest
    // is now waiting for this ticket, which waits on that confirmation.
    lifecycle.expedite_cid_check(vm_id);
    let cancel = lifecycle.begin_ticket_push(vm_id);
    tokio::spawn(repush_ticket(
        vm_id.clone(),
        cose_ticket,
        Arc::clone(lifecycle),
        Arc::clone(pusher),
        cancel,
        RetrySchedule::PRODUCTION,
    ));
}

/// Timing of one re-push task — a parameter so the tests can run the
/// real loop in milliseconds.
#[derive(Debug, Clone, Copy)]
struct RetrySchedule {
    interval: Duration,
    max_attempts: u32,
    window: Duration,
}

impl RetrySchedule {
    const PRODUCTION: Self = Self {
        interval: RETRY_INTERVAL,
        max_attempts: MAX_RETRIES,
        window: RETRY_WINDOW,
    };
}

/// The re-push loop for one `Started` event. Ends on the first of:
/// cancellation (stop / destroy / superseded), the VM no longer owning
/// `cid` with this ticket, the attempt budget, or the wall-clock window
/// — each push is bounded by the window too, since one connect loop can
/// otherwise spin for `PUSH_TIMEOUT_SECS`.
async fn repush_ticket(
    vm_id: VmId,
    cose_ticket: Vec<u8>,
    lifecycle: Arc<CvmLifecycle>,
    pusher: Arc<dyn TicketPusher>,
    cancel: CancellationToken,
    schedule: RetrySchedule,
) {
    // However the loop ends, this task is no longer trying: cancelling its
    // own (still registered) token is what tells `ticket_lost` so.
    let _no_longer_trying = cancel.clone().drop_guard();
    let deadline = tokio::time::Instant::now() + schedule.window;
    let mut last_cid = 0u32;
    for attempt in 1..=schedule.max_attempts {
        if cancel.is_cancelled() {
            return;
        }
        // Re-resolve the VM's CURRENT cid every attempt: a launch may have
        // re-allocated it after an orphan collision, and a re-adopted cid
        // may since have been re-keyed to the live one.
        let (state, cid) = lifecycle.ticket_push_target(&vm_id, &cose_ticket);
        last_cid = cid;
        match state {
            TicketPushState::Deliver => {}
            // Not yet provable: a fresh launch's `Started` fires while the
            // lifecycle is still `Launching`, and a re-adopted cid may still
            // await confirmation against the live XML. Sit this one out.
            TicketPushState::Wait => {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = tokio::time::sleep(schedule.interval) => {}
                }
                continue;
            }
            TicketPushState::Abort => {
                eprintln!(
                    "hippius-miner-agent: reboot-watcher: vm={} cid={cid} re-push stopped at \
                     attempt={attempt}: VM stopped, superseded, or no longer owns the cid",
                    vm_id.as_str(),
                );
                return;
            }
        }
        let still_owner = {
            let lifecycle = Arc::clone(&lifecycle);
            let cancel = cancel.clone();
            let vm_id = vm_id.clone();
            let cose_ticket = cose_ticket.clone();
            move || {
                !cancel.is_cancelled() && lifecycle.ticket_push_current(&vm_id, cid, &cose_ticket)
            }
        };
        let push = pusher.push_guarded(
            cid,
            hippius_types::ticket_vsock::PORT,
            &cose_ticket,
            &still_owner,
        );
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            outcome = tokio::time::timeout_at(deadline, push) => outcome,
        };
        match outcome {
            Ok(Ok(())) => {
                lifecycle.note_ticket_delivered(&vm_id, cid, &cose_ticket);
                eprintln!(
                    "hippius-miner-agent: reboot-watcher: vm={} cid={cid} re-push \
                     attempt={attempt}/{} ok",
                    vm_id.as_str(),
                    schedule.max_attempts,
                )
            }
            // Before the guest listener binds the connect times out; after
            // it has consumed the ticket the connect is reset. Both are the
            // normal shape of a boot — the next attempt covers transients.
            Ok(Err(err)) => eprintln!(
                "hippius-miner-agent: reboot-watcher: vm={} cid={cid} re-push \
                 attempt={attempt}/{} failed: {err}",
                vm_id.as_str(),
                schedule.max_attempts,
            ),
            Err(_) => break,
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tokio::time::sleep(schedule.interval) => {}
        }
    }
    eprintln!(
        "hippius-miner-agent: reboot-watcher: vm={} cid={last_cid} re-push window closed",
        vm_id.as_str(),
    );
}

/// `virsh start` the domain after the qemu process exits, under the
/// per-vm rate limit. Bails if the vm_id isn't admitted by the
/// lifecycle (foreign / already-destroyed domain), or if the rate
/// limit window is full.
async fn handle_stopped(vm_id: &VmId, domain_name: &str, ctx: &WatchCtx<'_>) {
    let WatchCtx {
        lifecycle,
        migration,
        history,
        control,
        ..
    } = *ctx;
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
    // Only act on domains we admitted AND that went down on their own.
    // A Stopped event for a domain we never tracked (orphan, foreign
    // tenant on the same libvirtd, a transient test domain) is benign —
    // ignore it. So is one the agent itself is stopping (`Stopping`
    // phase: a stop / §24 destroy in flight) — restarting it would
    // resurrect the VM being torn down.
    if !lifecycle.restart_eligible(vm_id) {
        return;
    }
    // The tenant's guest-poweroff policy. `restart` (or a record the agent
    // cannot read — logged) takes the historic path below unchanged.
    let policy = lifecycle.power_policy(vm_id).unwrap_or_else(|err| {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} power-policy unreadable ({err}) \
             — treated as restart",
            vm_id.as_str()
        );
        OnGuestPoweroff::Restart
    });
    if policy == OnGuestPoweroff::Stop {
        if leave_stopped_after_guest_poweroff(vm_id, domain_name, lifecycle, control).await {
            return;
        }
    } else {
        lifecycle.guest_runs().take(vm_id);
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
    if !wait_for_shut_off(domain_name, control).await {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} domstate-poll-timeout",
            vm_id.as_str()
        );
        return;
    }
    // Re-check after the wait: a stop / §24 destroy that began while we
    // polled for shut-off owns this domain now.
    if !lifecycle.restart_eligible(vm_id) {
        eprintln!(
            "hippius-miner-agent: reboot-watcher: vm={} stopped by the agent meanwhile, not restarting",
            vm_id.as_str()
        );
        return;
    }
    match control.start(domain_name).await {
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

/// The `stop`-policy branch of a `Stopped` event. `true` when the VM is
/// handled and must NOT be restarted: left stopped after a guest poweroff,
/// or taken over meanwhile by an agent-initiated stop. `false` sends it
/// down the restart path — any doubt about the cause is a restart.
async fn leave_stopped_after_guest_poweroff(
    vm_id: &VmId,
    domain_name: &str,
    lifecycle: &Arc<CvmLifecycle>,
    control: &dyn DomainControl,
) -> bool {
    if !wait_for_shut_off(domain_name, control).await {
        // The restart path waits again and gives up the same way.
        return false;
    }
    let runs = lifecycle.guest_runs();
    let deadline = Instant::now() + SHUTDOWN_EVIDENCE_GRACE;
    while runs.first_shutdown(vm_id).is_none() && Instant::now() < deadline {
        tokio::time::sleep(SHUTDOWN_EVIDENCE_POLL).await;
    }
    let evidence = runs.take(vm_id);
    match power_policy::decide(OnGuestPoweroff::Stop, evidence) {
        PoweroffVerdict::Restart(reason) => {
            eprintln!(
                "hippius-miner-agent: reboot-watcher: vm={} event=Stopped policy=stop \
                 not a guest poweroff ({reason}) → restart",
                vm_id.as_str()
            );
            false
        }
        PoweroffVerdict::StayStopped => {
            if !lifecycle.restart_eligible(vm_id) {
                // A stop / §24 destroy began meanwhile and owns the domain.
                return true;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            match lifecycle.settle_guest_poweroff(vm_id, now).await {
                Ok(()) => {
                    eprintln!(
                        "hippius-miner-agent: reboot-watcher: vm={} event=Stopped policy=stop \
                         guest poweroff → left stopped (stop_reason=guest-poweroff)",
                        vm_id.as_str()
                    );
                    true
                }
                Err(err) => {
                    eprintln!(
                        "hippius-miner-agent: reboot-watcher: vm={} guest poweroff could not \
                         be settled ({err}) → restart",
                        vm_id.as_str()
                    );
                    false
                }
            }
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
async fn wait_for_shut_off(domain_name: &str, control: &dyn DomainControl) -> bool {
    let deadline = Instant::now() + DOMSTATE_POLL_DEADLINE;
    while Instant::now() < deadline {
        match control.domstate(domain_name).await {
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
    crate::host_health::record_domain_start();
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

    // ── Ticket re-push must never outlive its VM ────────────────────────
    //
    // The live failure (2026-09-24): VM A's re-push task was still spinning
    // when A was destroyed; B launched on A's freed CID, B's initramfs
    // listener came up, and A's task delivered A's ticket into it → KBS 403,
    // and the golden initramfs never retries. These tests drive the real
    // `repush_ticket` loop against the real lifecycle + CID allocator.

    use crate::error::{MinerAgentError, Result};
    use crate::lifecycle::{CvmPhase, HostResources, MockLaunchDigest, MockLibvirtDriver};
    use crate::orders::LaunchOrder;
    use async_trait::async_trait;
    use ciborium::value::Value;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use std::collections::HashSet;
    use std::path::PathBuf;

    const FAST: RetrySchedule = RetrySchedule {
        interval: Duration::from_millis(2),
        max_attempts: 100_000,
        window: Duration::from_secs(30),
    };

    /// Models guests' vsock listeners per CID. A push behaves like the
    /// production connect loop: it spins (re-checking the guard, as
    /// `push_ticket_guarded` does) until a listener is bound on the CID,
    /// then delivers. `ignore_guard` models a pusher that never re-checks.
    #[derive(Default)]
    struct ListenerPusher {
        listening: Mutex<HashSet<u32>>,
        delivered: Mutex<Vec<(u32, Vec<u8>)>>,
        ignore_guard: bool,
    }

    impl ListenerPusher {
        fn listen(&self, cid: u32) {
            self.listening.lock().unwrap().insert(cid);
        }
        fn delivered(&self) -> Vec<(u32, Vec<u8>)> {
            self.delivered.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TicketPusher for ListenerPusher {
        async fn push(&self, cid: u32, port: u32, cose: &[u8]) -> Result<()> {
            self.push_guarded(cid, port, cose, &|| true).await
        }
        async fn push_guarded(
            &self,
            cid: u32,
            _port: u32,
            cose: &[u8],
            still_owner: &(dyn Fn() -> bool + Send + Sync),
        ) -> Result<()> {
            loop {
                if !self.ignore_guard && !still_owner() {
                    return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
                }
                if self.listening.lock().unwrap().contains(&cid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if !self.ignore_guard && !still_owner() {
                return Err(MinerAgentError::TicketDelivery("cid-not-owned"));
            }
            self.delivered.lock().unwrap().push((cid, cose.to_vec()));
            Ok(())
        }
    }

    /// A structurally valid COSE ticket (flavor `medium` ↔ 2 vCPUs, the
    /// launch-time peek) whose bytes are unique per `tag`.
    fn ticket(tag: &str) -> Vec<u8> {
        let payload = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("flavor".into()), Value::Text("medium".into())),
            (Value::Text("vm".into()), Value::Text(tag.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf).unwrap();
        CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::EdDSA)
                    .build(),
            )
            .payload(buf)
            .create_signature(b"", |_| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    fn order(vm: &str) -> LaunchOrder {
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        LaunchOrder {
            vm_id: VmId::new(vm).unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet panic=0".to_string(),
            luks_disk_path: PathBuf::from(format!("/var/lib/hippius-miner/{vm}.img")),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 0,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: serde_bytes::ByteBuf::from(ticket(vm)),
            require_existing_disks: false,
            guardian_ep: None,
            net: None,
            on_guest_poweroff: None,
        }
    }

    fn lifecycle() -> Arc<CvmLifecycle> {
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        Arc::new(
            CvmLifecycle::new_with_poll(
                Arc::new(MockLibvirtDriver::new()),
                Arc::new(MockLaunchDigest::fixed([0u8; 48])),
                HostResources {
                    total_cpus: 16,
                    total_memory_mb: 65536,
                    total_disk_gb: 0,
                },
                Duration::from_millis(1),
                5,
            )
            .skip_state_disk_provision_for_tests(),
        )
    }

    /// Launch `vm` and start its re-push task exactly as `handle_started`
    /// does. Returns the CID and ticket it holds, and the task.
    async fn launch_and_repush(
        lc: &Arc<CvmLifecycle>,
        pusher: &Arc<ListenerPusher>,
        vm: &str,
        cancel: Option<CancellationToken>,
    ) -> (u32, Vec<u8>, tokio::task::JoinHandle<()>) {
        let vm_id = lc.launch(order(vm)).await.unwrap();
        let (cid, t) = lc.ticket_for_vm(&vm_id).unwrap();
        let cancel = cancel.unwrap_or_else(|| lc.begin_ticket_push(&vm_id));
        let pusher: Arc<dyn TicketPusher> = pusher.clone();
        let task = tokio::spawn(repush_ticket(
            vm_id,
            t.clone(),
            Arc::clone(lc),
            pusher,
            cancel,
            FAST,
        ));
        (cid, t, task)
    }

    /// Stop A while its push is spinning, launch B on A's freed CID, bring
    /// B's listener up. Returns what reached that CID, plus both tickets.
    async fn reuse_cid_scenario(
        pusher: Arc<ListenerPusher>,
        a_cancel: Option<CancellationToken>,
    ) -> (Vec<(u32, Vec<u8>)>, Vec<u8>, Vec<u8>) {
        let lc = lifecycle();
        let (cid_a, ticket_a, task_a) = launch_and_repush(&lc, &pusher, "vm-a", a_cancel).await;
        // A's guest never binds its listener: A's push is mid connect-loop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        lc.stop(&VmId::new("vm-a").unwrap(), false).await.unwrap();

        let (cid_b, ticket_b, task_b) = launch_and_repush(&lc, &pusher, "vm-b", None).await;
        assert_eq!(cid_a, cid_b, "precondition: B must inherit A's freed CID");
        assert_ne!(ticket_a, ticket_b);
        pusher.listen(cid_b);
        tokio::time::sleep(Duration::from_millis(100)).await;

        lc.stop(&VmId::new("vm-b").unwrap(), false).await.unwrap();
        for task in [task_a, task_b] {
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("a re-push task outlived its VM's stop")
                .unwrap();
        }
        (pusher.delivered(), ticket_a, ticket_b)
    }

    fn assert_only_b(delivered: &[(u32, Vec<u8>)], ticket_a: &[u8], ticket_b: &[u8]) {
        assert!(
            delivered.iter().any(|(_, t)| t == ticket_b),
            "B's own ticket must reach B"
        );
        assert!(
            delivered.iter().all(|(_, t)| t != ticket_a),
            "a stopped VM's ticket reached the guest that inherited its CID"
        );
    }

    #[tokio::test]
    async fn a_stopped_vms_repush_never_reaches_the_vm_that_inherits_its_cid() {
        let (delivered, a, b) = reuse_cid_scenario(Arc::new(ListenerPusher::default()), None).await;
        assert_only_b(&delivered, &a, &b);
    }

    #[tokio::test]
    async fn the_ownership_guard_alone_stops_a_stale_push() {
        // Defence in depth: even if A's task was never cancelled (a token
        // the lifecycle does not know), the per-connect guard refuses to
        // deliver A's ticket once A no longer owns the CID.
        let untracked = CancellationToken::new();
        let (delivered, a, b) =
            reuse_cid_scenario(Arc::new(ListenerPusher::default()), Some(untracked)).await;
        assert_only_b(&delivered, &a, &b);
    }

    #[tokio::test]
    async fn stop_cancels_a_push_even_through_a_pusher_that_ignores_the_guard() {
        // And the other layer on its own: a pusher that never re-checks the
        // guard mid-connect is still cut off by the stop's cancellation.
        let pusher = Arc::new(ListenerPusher {
            ignore_guard: true,
            ..Default::default()
        });
        let (delivered, a, b) = reuse_cid_scenario(pusher, None).await;
        assert_only_b(&delivered, &a, &b);
    }

    #[tokio::test]
    async fn a_new_started_supersedes_the_previous_repush_for_the_same_vm() {
        let lc = lifecycle();
        let vm = VmId::new("vm-s").unwrap();
        let first = lc.begin_ticket_push(&vm);
        let second = lc.begin_ticket_push(&vm);
        assert!(
            first.is_cancelled(),
            "the superseded task must be cancelled"
        );
        assert!(!second.is_cancelled());
    }

    #[tokio::test]
    async fn the_repush_window_bounds_a_push_that_never_returns() {
        // One production push can spin for PUSH_TIMEOUT_SECS; the attempt
        // count alone let the "10 min" window run for hours.
        struct Hang;
        #[async_trait]
        impl TicketPusher for Hang {
            async fn push(&self, _: u32, _: u32, _: &[u8]) -> Result<()> {
                std::future::pending().await
            }
        }
        let lc = lifecycle();
        let vm_id = lc.launch(order("vm-h")).await.unwrap();
        let (_, t) = lc.ticket_for_vm(&vm_id).unwrap();
        let cancel = lc.begin_ticket_push(&vm_id);
        let schedule = RetrySchedule {
            window: Duration::from_millis(50),
            ..FAST
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            repush_ticket(vm_id, t, lc, Arc::new(Hang), cancel, schedule),
        )
        .await
        .expect("the re-push task must end when its window closes");
    }

    #[tokio::test]
    async fn a_running_vm_keeps_receiving_its_own_ticket() {
        // The legacy keyscript's cryptroot retry re-binds its listener and
        // needs the ticket again — the guard must not block the VM's OWN
        // guest.
        let lc = lifecycle();
        let pusher = Arc::new(ListenerPusher::default());
        let (cid, t, task) = launch_and_repush(&lc, &pusher, "vm-own", None).await;
        pusher.listen(cid);
        tokio::time::sleep(Duration::from_millis(50)).await;
        lc.stop(&VmId::new("vm-own").unwrap(), false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let delivered = pusher.delivered();
        assert!(delivered.len() > 1, "own-guest re-deliveries must continue");
        assert!(delivered.iter().all(|(c, d)| *c == cid && d == &t));
    }

    #[tokio::test]
    async fn a_launching_vm_waits_then_gets_its_ticket_once_running() {
        // The fresh launch's `Started` fires while the lifecycle is still
        // `Launching` — the CID is selected but not yet proven (an orphan
        // may hold it). The task must wait, not deliver and not give up.
        let lc = lifecycle();
        let vm_id = lc.launch(order("vm-l")).await.unwrap();
        let (cid, t) = lc.ticket_for_vm(&vm_id).unwrap();
        lc.force_phase_for_tests(&vm_id, CvmPhase::Launching);
        assert_eq!(lc.ticket_push_state(&vm_id, cid, &t), TicketPushState::Wait);

        let pusher = Arc::new(ListenerPusher::default());
        pusher.listen(cid);
        let dyn_pusher: Arc<dyn TicketPusher> = pusher.clone();
        let cancel = lc.begin_ticket_push(&vm_id);
        let task = tokio::spawn(repush_ticket(
            vm_id.clone(),
            t.clone(),
            Arc::clone(&lc),
            dyn_pusher,
            cancel,
            FAST,
        ));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pusher.delivered().is_empty(), "delivered while Launching");
        assert!(!task.is_finished(), "gave up while Launching");

        lc.force_phase_for_tests(&vm_id, CvmPhase::Running);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pusher.delivered().iter().any(|(c, d)| *c == cid && d == &t));
        lc.stop(&vm_id, false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_repush_follows_an_unverified_cid_rekeyed_to_the_live_one() {
        // Re-adoption with an unreadable XML holds the sidecar's cid 7
        // unverified. A guest reboot's `Started` starts a re-push that must
        // WAIT, and once the live XML shows cid 9 it must deliver to 9 —
        // never to 7, which belongs to whoever the kernel gave it.
        let tmp = tempfile::tempdir().unwrap();
        let t = ticket("vm-rk");
        let dir = tmp.path().join("adopt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("vm-rk.json"),
            format!(
                r#"{{"vm_id":"vm-rk","domain_id":"hippius-tenant-vm-rk",
                "domain_uuid":"11111111-2222-4333-8444-555555555555",
                "launch_digest_hex":"{}","cpu_count":2,"memory_mb":2048,
                "data_disk_size_gb":0,"luks_disk_path":"/var/lib/hippius-miner/x.img",
                "cid":7,"cose_ticket_hex":"{}"}}"#,
                "00".repeat(48),
                hex::encode(&t),
            ),
        )
        .unwrap();
        let driver = Arc::new(MockLibvirtDriver::new());
        let domain = crate::lifecycle::DomainId::new("hippius-tenant-vm-rk").unwrap();
        driver.seed_domain(domain.clone(), crate::lifecycle::DomainState::Running);
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        let lc = Arc::new(
            CvmLifecycle::new_with_poll(
                driver.clone(),
                Arc::new(MockLaunchDigest::fixed([0u8; 48])),
                HostResources {
                    total_cpus: 16,
                    total_memory_mb: 65536,
                    total_disk_gb: 0,
                },
                Duration::from_millis(1),
                5,
            )
            .skip_state_disk_provision_for_tests()
            .with_state_disk_root(tmp.path().to_path_buf()),
        );
        assert_eq!(lc.readopt_running().await.unwrap(), 1);
        let vm_id = VmId::new("vm-rk").unwrap();

        let pusher = Arc::new(ListenerPusher::default());
        pusher.listen(7);
        pusher.listen(9);
        let dyn_pusher: Arc<dyn TicketPusher> = pusher.clone();
        let cancel = lc.begin_ticket_push(&vm_id);
        let task = tokio::spawn(repush_ticket(
            vm_id.clone(),
            t.clone(),
            Arc::clone(&lc),
            dyn_pusher,
            cancel,
            FAST,
        ));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            pusher.delivered().is_empty(),
            "delivered on an unverified cid"
        );

        driver.seed_domain_xml(
            domain,
            crate::lifecycle::DomainState::Running,
            "<domain type='kvm'><name>hippius-tenant-vm-rk</name>\
                 <uuid>11111111-2222-4333-8444-555555555555</uuid>\
                 <memory unit='KiB'>2097152</memory><vcpu>2</vcpu><devices>\
                 <disk type='file' device='disk'><source file='/var/lib/hippius-miner/x.img'/>\
                 <target dev='vda' bus='virtio'/></disk>\
                 <vsock model='virtio'><cid auto='no' address='9'/></vsock>\
                 </devices></domain>",
        );
        let verdicts = lc
            .verify_pending_cids(std::time::Instant::now() + Duration::from_secs(3600))
            .await;
        assert_eq!(
            verdicts,
            vec![(vm_id.clone(), crate::lifecycle::CidVerdict::Rekeyed)]
        );
        tokio::time::sleep(Duration::from_millis(30)).await;

        lc.stop(&vm_id, false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let delivered = pusher.delivered();
        assert!(
            delivered.iter().any(|(c, d)| *c == 9 && d == &t),
            "the live cid got nothing"
        );
        assert!(
            delivered.iter().all(|(c, _)| *c == 9),
            "a push hit the stale cid"
        );
    }

    #[tokio::test]
    async fn a_launch_whose_cid_is_not_yet_created_waits_rather_than_aborts() {
        // The libvirt `Started` event can beat `create_domain`'s
        // `mark_verified`: the re-push must wait for it, not give up.
        let lc = lifecycle();
        let vm_id = lc.launch(order("vm-pc")).await.unwrap();
        let (cid, t) = lc.ticket_for_vm(&vm_id).unwrap();
        lc.force_phase_for_tests(&vm_id, CvmPhase::Launching);
        let alloc = lc.cid_allocator();
        alloc.release(&vm_id).unwrap();
        assert_eq!(
            alloc.allocate(&vm_id).unwrap(),
            cid,
            "same slot, now pending-create"
        );
        assert_eq!(lc.ticket_push_state(&vm_id, cid, &t), TicketPushState::Wait);
    }

    // ── Guest poweroff vs crash (guest-poweroff policy) ─────────────────
    //
    // These drive the REAL event path — `handle_event_line` on libvirt's
    // `virsh event` lines and `note_shutdown_line` on `virsh
    // qemu-monitor-event` lines, verbatim formats — against the real
    // lifecycle, with only the two `virsh` calls of the `Stopped` path
    // faked over the mock driver.

    mod guest_poweroff {
        use super::*;
        use crate::lifecycle::{DomainId, DomainState, LibvirtDriver};
        use crate::orders::OnGuestPoweroff;

        /// `domstate` / `start` over the mock driver; records starts.
        struct FakeVirsh {
            driver: Arc<MockLibvirtDriver>,
            starts: Mutex<Vec<String>>,
        }

        #[async_trait]
        impl DomainControl for FakeVirsh {
            async fn domstate(&self, name: &str) -> std::result::Result<String, &'static str> {
                let id = DomainId::new(name).map_err(|_| "id")?;
                match self.driver.query_domain_state(&id).await {
                    Ok(DomainState::ShutOff) => Ok("shut off".into()),
                    Ok(DomainState::Running) => Ok("running".into()),
                    Ok(_) => Ok("other".into()),
                    Err(_) => Err("non-zero"),
                }
            }
            async fn start(&self, name: &str) -> std::result::Result<(), &'static str> {
                self.starts.lock().unwrap().push(name.to_string());
                self.driver
                    .force_all_to_state(DomainState::Running)
                    .map_err(|_| "start")
            }
        }

        struct Rig {
            lc: Arc<CvmLifecycle>,
            driver: Arc<MockLibvirtDriver>,
            virsh: FakeVirsh,
            pusher: Arc<dyn TicketPusher>,
            migration: Arc<crate::orders::MigrationStore>,
            history: Arc<Mutex<RestartHistory>>,
            _root: tempfile::TempDir,
        }

        impl Rig {
            fn new() -> Self {
                crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
                    cbitpos: 51,
                    reduced_phys_bits: 1,
                });
                let root = tempfile::tempdir().unwrap();
                let driver = Arc::new(MockLibvirtDriver::new());
                let lc = Arc::new(
                    CvmLifecycle::new_with_poll(
                        driver.clone(),
                        Arc::new(MockLaunchDigest::fixed([0u8; 48])),
                        HostResources {
                            total_cpus: 16,
                            total_memory_mb: 65536,
                            total_disk_gb: 0,
                        },
                        Duration::from_millis(1),
                        5,
                    )
                    .skip_state_disk_provision_for_tests()
                    .with_state_disk_root(root.path().to_path_buf()),
                );
                Self {
                    lc,
                    virsh: FakeVirsh {
                        driver: driver.clone(),
                        starts: Mutex::new(Vec::new()),
                    },
                    driver,
                    pusher: Arc::new(ListenerPusher::default()),
                    migration: Arc::new(crate::orders::MigrationStore::new()),
                    history: Arc::new(Mutex::new(HashMap::new())),
                    _root: root,
                }
            }

            async fn launch(&self, vm: &str, policy: Option<OnGuestPoweroff>) -> VmId {
                let mut o = order(vm);
                o.on_guest_poweroff = policy;
                let vm_id = self.lc.launch(o).await.unwrap();
                self.event(&format!(
                    "event 'lifecycle' for domain 'hippius-tenant-{vm}': Started Booted"
                ))
                .await;
                vm_id
            }

            async fn event(&self, line: &str) {
                let ctx = WatchCtx {
                    lifecycle: &self.lc,
                    pusher: &self.pusher,
                    migration: &self.migration,
                    history: &self.history,
                    control: &self.virsh,
                };
                handle_event_line(line, &ctx).await;
            }

            /// A QMP `SHUTDOWN` line stamped now, as QEMU stamps it.
            fn qmp(&self, vm: &str, payload: &str) {
                self.qmp_at(vm, payload, unix_now_us());
            }

            fn qmp_at(&self, vm: &str, payload: &str, at_us: u64) {
                note_shutdown_line(
                    &format!(
                        "event SHUTDOWN at {}.{:06} for domain 'hippius-tenant-{vm}': {payload}",
                        at_us / 1_000_000,
                        at_us % 1_000_000
                    ),
                    &self.lc,
                );
            }

            /// The guest's userspace dialled the relay (what the vsock
            /// listener records for a verified CID).
            fn guest_up(&self, vm_id: &VmId) {
                self.lc.guest_runs().note_guest_up(vm_id);
            }

            /// QEMU went away and libvirt reports it.
            async fn stopped(&self, vm: &str, detail: &str) {
                self.driver
                    .force_all_to_state(DomainState::ShutOff)
                    .unwrap();
                self.event(&format!(
                    "event 'lifecycle' for domain 'hippius-tenant-{vm}': Stopped {detail}"
                ))
                .await;
            }

            fn starts(&self) -> usize {
                self.virsh.starts.lock().unwrap().len()
            }
        }

        const POWEROFF: &str = r#"{"guest":true,"reason":"guest-shutdown"}"#;
        const REBOOT: &str = r#"{"guest":true,"reason":"guest-reset"}"#;
        const HOST_SIGNAL: &str = r#"{"guest":false,"reason":"host-signal"}"#;

        #[tokio::test]
        async fn a_stop_vm_whose_guest_powers_off_stays_stopped_and_says_so() {
            let rig = Rig::new();
            let vm = rig.launch("gp-1", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.qmp("gp-1", POWEROFF);
            // libvirt's own SIGTERM, answered by QEMU, comes second.
            rig.qmp("gp-1", HOST_SIGNAL);
            rig.stopped("gp-1", "Shutdown").await;

            assert_eq!(
                rig.starts(),
                0,
                "a guest poweroff in stop mode was restarted"
            );
            assert!(rig.lc.stopped_by_guest(&vm));
            assert!(!rig.lc.restart_eligible(&vm), "the handle is released");
            assert!(rig.lc.ticket_for_vm(&vm).is_none());
            assert!(rig.lc.cid_allocator().cid_for_vm(&vm).unwrap().is_none());
            assert_eq!(
                rig.lc.tenant_domain_liveness(&vm).await,
                crate::lifecycle::DomainLiveness::Down
            );
            // The policy itself survives (a start relaunches with it anyway).
            assert_eq!(rig.lc.power_policy(&vm).unwrap(), OnGuestPoweroff::Stop);

            // A start (vali relaunch) clears the mark.
            let mut relaunch = order("gp-1");
            relaunch.on_guest_poweroff = Some(OnGuestPoweroff::Stop);
            rig.lc.launch(relaunch).await.unwrap();
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_crash_is_restarted_whatever_the_policy() {
            // QEMU killed: no SHUTDOWN event at all, libvirt says Failed.
            let rig = Rig::new();
            let vm = rig.launch("gp-2", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.stopped("gp-2", "Failed").await;
            assert_eq!(rig.starts(), 1, "a crash must always be restarted");
            assert!(!rig.lc.stopped_by_guest(&vm));
            assert!(rig.lc.restart_eligible(&vm));
        }

        #[tokio::test]
        async fn a_host_signal_kill_is_restarted_in_stop_mode() {
            let rig = Rig::new();
            let vm = rig.launch("gp-3", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.qmp("gp-3", HOST_SIGNAL);
            rig.stopped("gp-3", "Shutdown").await;
            assert_eq!(rig.starts(), 1);
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_guest_reboot_is_restarted_in_stop_mode() {
            // SNP: a reboot terminates QEMU too, but its cause is guest-reset.
            let rig = Rig::new();
            let vm = rig.launch("gp-4", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.qmp("gp-4", REBOOT);
            rig.qmp("gp-4", HOST_SIGNAL);
            rig.stopped("gp-4", "Shutdown").await;
            assert_eq!(rig.starts(), 1);
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn an_initramfs_fail_closed_poweroff_is_restarted_in_stop_mode() {
            // The guest never reached userspace: a boot failure, retried.
            let rig = Rig::new();
            let vm = rig.launch("gp-5", Some(OnGuestPoweroff::Stop)).await;
            rig.qmp("gp-5", POWEROFF);
            rig.stopped("gp-5", "Shutdown").await;
            assert_eq!(rig.starts(), 1);
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_restart_vm_whose_guest_powers_off_is_restarted() {
            let rig = Rig::new();
            let vm = rig.launch("gp-6", None).await;
            rig.guest_up(&vm);
            rig.qmp("gp-6", POWEROFF);
            rig.stopped("gp-6", "Shutdown").await;
            assert_eq!(rig.starts(), 1);
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn the_evidence_of_one_run_does_not_leak_into_the_next() {
            // Run 1 is a reboot (restarted). Run 2's guest powers off: the
            // first SHUTDOWN of run 2 must decide, not run 1's guest-reset.
            let rig = Rig::new();
            let vm = rig.launch("gp-7", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.qmp("gp-7", REBOOT);
            rig.stopped("gp-7", "Shutdown").await;
            assert_eq!(rig.starts(), 1);
            // Run 1's trailing host-signal SHUTDOWN read only now, after
            // its Stopped was handled.
            rig.qmp("gp-7", HOST_SIGNAL);
            // The restart's own Started opens run 2 — userspace not up yet.
            rig.event("event 'lifecycle' for domain 'hippius-tenant-gp-7': Started Booted")
                .await;
            rig.guest_up(&vm);
            rig.qmp("gp-7", POWEROFF);
            rig.stopped("gp-7", "Shutdown").await;
            assert_eq!(rig.starts(), 1, "run 2's poweroff was restarted");
            assert!(rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_late_qmp_event_inside_the_grace_still_counts() {
            // The QMP stream is a separate process: its line may land just
            // after libvirt's Stopped.
            let rig = Arc::new(Rig::new());
            let vm = rig.launch("gp-8", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            let late = {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    rig.qmp("gp-8", POWEROFF);
                })
            };
            rig.stopped("gp-8", "Shutdown").await;
            late.await.unwrap();
            assert_eq!(rig.starts(), 0);
            assert!(rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_policy_change_in_place_is_read_by_the_next_poweroff() {
            let rig = Rig::new();
            let vm = rig.launch("gp-9", None).await;
            rig.lc
                .set_power_policy(&vm, OnGuestPoweroff::Stop)
                .await
                .unwrap();
            rig.guest_up(&vm);
            rig.qmp("gp-9", POWEROFF);
            rig.stopped("gp-9", "Shutdown").await;
            assert_eq!(rig.starts(), 0);
            assert!(rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn the_policy_survives_an_agent_restart() {
            // A SIGKILL swap: a new process, same state root, empty memory.
            let rig = Rig::new();
            let vm = rig.launch("gp-10", Some(OnGuestPoweroff::Stop)).await;
            let fresh = CvmLifecycle::new_with_poll(
                Arc::new(MockLibvirtDriver::new()),
                Arc::new(MockLaunchDigest::fixed([0u8; 48])),
                HostResources {
                    total_cpus: 16,
                    total_memory_mb: 65536,
                    total_disk_gb: 0,
                },
                Duration::from_millis(1),
                5,
            )
            .with_state_disk_root(rig._root.path().to_path_buf());
            assert_eq!(fresh.power_policy(&vm).unwrap(), OnGuestPoweroff::Stop);
        }

        #[tokio::test]
        async fn an_agent_stop_in_flight_is_never_settled_or_restarted() {
            // A stop / §24 destroy owns the domain: the watcher stays out.
            let rig = Rig::new();
            let vm = rig.launch("gp-11", Some(OnGuestPoweroff::Stop)).await;
            rig.guest_up(&vm);
            rig.qmp("gp-11", POWEROFF);
            rig.lc.force_phase_for_tests(&vm, CvmPhase::Stopping);
            rig.stopped("gp-11", "Shutdown").await;
            assert_eq!(rig.starts(), 0);
            assert!(!rig.lc.stopped_by_guest(&vm));
        }

        #[tokio::test]
        async fn a_policy_change_needs_the_vm_on_this_host() {
            let rig = Rig::new();
            let ghost = VmId::new("gp-ghost").unwrap();
            assert!(matches!(
                rig.lc.set_power_policy(&ghost, OnGuestPoweroff::Stop).await,
                Err(crate::error::MinerAgentError::VmNotFound)
            ));
            assert_eq!(
                rig.lc.power_policy(&ghost).unwrap(),
                OnGuestPoweroff::Restart
            );
        }

        #[tokio::test]
        async fn destroy_removes_the_policy() {
            let rig = Rig::new();
            let vm = rig.launch("gp-12", Some(OnGuestPoweroff::Stop)).await;
            rig.lc.destroy(&vm, None).await.unwrap();
            assert!(power_policy::load(rig._root.path(), &vm).unwrap().is_none());
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn the_qmp_stream_reads_a_virsh_qemu_monitor_event_process() {
            // The real spawn + line loop, against a stand-in `virsh` that
            // prints what libvirt prints (and checks it was asked for the
            // SHUTDOWN events of every domain).
            use std::os::unix::fs::PermissionsExt;
            let rig = Rig::new();
            let vm = rig.launch("gp-13", Some(OnGuestPoweroff::Stop)).await;
            let dir = tempfile::tempdir().unwrap();
            let virsh = dir.path().join("virsh");
            std::fs::write(
                &virsh,
                r#"#!/bin/sh
[ "$*" = "qemu-monitor-event --event SHUTDOWN --loop" ] || exit 3
printf "event SHUTDOWN at %s.000000 for domain 'hippius-tenant-gp-13': {\"guest\":true,\"reason\":\"guest-shutdown\"}\n" "$(( $(date +%s) + 1 ))"
exec sleep 30
"#,
            )
            .unwrap();
            std::fs::set_permissions(&virsh, std::fs::Permissions::from_mode(0o755)).unwrap();
            let cancel = CancellationToken::new();
            let task = tokio::spawn(run_shutdown_events(
                Arc::clone(&rig.lc),
                virsh,
                cancel.clone(),
            ));
            let deadline = Instant::now() + Duration::from_secs(10);
            while rig.lc.guest_runs().first_shutdown(&vm).is_none() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            cancel.cancel();
            task.await.unwrap();
            assert_eq!(
                rig.lc.guest_runs().first_shutdown(&vm),
                Some(power_policy::ShutdownCause::GuestPoweroff)
            );
        }
    }
}
