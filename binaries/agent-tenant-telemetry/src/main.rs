//! `hippius-agent-tenant-telemetry` — the §23 telemetry agent service.
//!
//! Started by systemd after `switch_root`. PR-E2.1 establishes the
//! per-VM telemetry signer key (generate → attest → KBS-certify →
//! verify); PR-E2.2 then runs the periodic receipt loop — building,
//! signing, and buffering a `ServedDeliveryReceipt` every interval —
//! until a shutdown signal arrives. PR-E2.3 adds the vsock pusher: a
//! dedicated thread that drains the shared receipt queue to the host
//! miner-agent over `AF_VSOCK`, started before the loop and joined
//! after it so the buffered receipts get a final drain on shutdown.
//!
//! On any establishment failure the agent exits non-zero (fail-closed;
//! systemd does not restart it into a half-established state). On a
//! clean shutdown it returns **normally** so the telemetry key's
//! `Zeroize`-on-drop fires before the process exits.

use std::process::ExitCode;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use hippius_agent_tenant_telemetry::challenge::StaticChallengeSource;
use hippius_agent_tenant_telemetry::config::Config;
use hippius_agent_tenant_telemetry::error::Result;
use hippius_agent_tenant_telemetry::establish::{establish, Established};
use hippius_agent_tenant_telemetry::receipt_builder::ReceiptBuilder;
use hippius_agent_tenant_telemetry::receipt_loop::{run_receipt_loop, unix_now, ReceiptLoopConfig};
use hippius_agent_tenant_telemetry::receipt_queue::ReceiptQueue;
use hippius_agent_tenant_telemetry::served_work::StaticServedWorkSource;
use hippius_agent_tenant_telemetry::shutdown::{self, Shutdown};
#[cfg(target_os = "linux")]
use hippius_agent_tenant_telemetry::vsock_pusher::{VsockPusher, VSOCK_HOST_CID};

/// Upper bound on waiting for the PR-E2.3 vsock pusher to drain + exit
/// on shutdown. The pusher's vsock dial is a blocking syscall the
/// `vsock` crate offers no timed variant for (and `forbid(unsafe_code)`
/// rules out a hand-rolled non-blocking connect) — a wedged host could
/// park the pusher thread. This bound caps the graceful-shutdown wait:
/// past it, `main` proceeds and process exit reaps the abandoned
/// thread. Comfortably above the pusher's `WRITE_TIMEOUT` (10 s) so a
/// healthy final drain is never cut short.
const PUSHER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        // §20: log only the static error class — never dynamic text,
        // never any key material.
        Err(e) => {
            eprintln!("hippius-agent-tenant-telemetry: fail-closed: {}", e.class());
            ExitCode::FAILURE
        }
    }
}

/// The service body. Returns `Ok(())` only after a clean shutdown — and
/// MUST return rather than `process::exit`, so the established signer's
/// destructor (zeroize) runs.
fn run() -> Result<()> {
    // Install the shutdown handler FIRST — before any key is generated.
    // From here a SIGTERM/SIGINT only latches a flag; even one delivered
    // mid-establishment cannot kill the process before the key's
    // `Zeroize`-on-drop runs.
    let shutdown = shutdown::install()?;

    let cfg = Config::resolve()?;

    // §23 telemetry-key establishment: derive the telemetry signer from
    // the §7 lifecycle key the KBS released to this attested guest (no
    // second attestation / KBS round-trip — see `establish`).
    let established: Established = establish(&cfg)?;
    eprintln!("hippius-agent-tenant-telemetry: telemetry signer established");

    // PR-E2.2 — the periodic ServedDeliveryReceipt loop. Returns when a
    // shutdown signal latches.
    run_receipts(&cfg, &established, &shutdown)?;

    // Drop the established signer explicitly: its `TelemetrySigner`
    // holds a `ZeroizeOnDrop` `SigningKey`, so the telemetry key wipes
    // here — before the process exits. `run` MUST return normally (no
    // `process::exit`) for this to fire.
    drop(established);
    eprintln!("hippius-agent-tenant-telemetry: shutdown — telemetry key zeroized");
    Ok(())
}

/// Build the receipt-loop components from `cfg`, start the PR-E2.3
/// vsock pusher, and run the loop until `shutdown` latches.
fn run_receipts(cfg: &Config, established: &Established, shutdown: &Shutdown) -> Result<()> {
    // The first receipt covers `[genesis, genesis + interval]`.
    let genesis = unix_now()?;
    let mut builder = ReceiptBuilder::new(
        cfg.vm_id.clone(),
        cfg.lease_id.clone(),
        cfg.family_id.clone(),
        cfg.node_id.clone(),
        cfg.resource_class.clone(),
        genesis,
    );

    // PR-E2.3 — the receipt queue is shared: this thread's receipt
    // loop fills it; the vsock pusher (its own thread) drains it to
    // the host miner-agent. Spawn the pusher BEFORE the loop so a
    // receipt is never built with nowhere to drain.
    let queue = Arc::new(Mutex::new(ReceiptQueue::new()));
    let pusher = spawn_vsock_pusher(cfg, Arc::clone(&queue), shutdown.clone())?;

    // No challenge provisioned ⇒ the loop runs idle (a later refinement
    // wires the live Edge-pulled challenge source).
    let challenge_source = match &cfg.challenge {
        Some(challenge) => StaticChallengeSource::new(challenge.clone()),
        None => StaticChallengeSource::idle(),
    };
    let work_source = StaticServedWorkSource::new(cfg.observed_degradation_bps)?;

    let loop_config = ReceiptLoopConfig {
        interval: Duration::from_secs(cfg.interval_secs),
        ttl_secs: cfg.receipt_ttl_secs,
    };

    let loop_result = run_receipt_loop(
        &mut builder,
        &queue,
        &challenge_source,
        &work_source,
        established.signer.as_ref(),
        shutdown,
        &loop_config,
    );

    // The receipt loop has ended — on a shutdown signal, or (defence
    // in depth) an error. Latch shutdown unconditionally so the pusher
    // thread observes it; its final drain then flushes the buffered
    // receipts. The join is time-bounded so a wedged blocking vsock
    // dial cannot stall the process (and its key-zeroizing exit).
    shutdown.trigger();
    if let Some(handle) = pusher {
        join_pusher_bounded(handle);
    }
    loop_result
}

/// Join the vsock-pusher thread, but never block shutdown longer than
/// [`PUSHER_JOIN_TIMEOUT`].
///
/// A helper thread does the blocking `join`; if it does not report
/// back in time — the pusher is parked in a blocking vsock syscall on
/// a wedged host — `main` proceeds anyway and process exit reaps the
/// abandoned threads. The key still zeroizes: that `Drop` runs on the
/// main thread, which is no longer blocked.
fn join_pusher_bounded(handle: std::thread::JoinHandle<Result<()>>) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(handle.join());
    });
    match rx.recv_timeout(PUSHER_JOIN_TIMEOUT) {
        Ok(Ok(Ok(()))) => {
            eprintln!("hippius-agent-tenant-telemetry: vsock pusher drained")
        }
        Ok(Ok(Err(e))) => eprintln!(
            "hippius-agent-tenant-telemetry: vsock pusher exited: {}",
            e.class()
        ),
        Ok(Err(_)) => {
            eprintln!("hippius-agent-tenant-telemetry: vsock pusher thread panicked")
        }
        Err(_) => {
            eprintln!("hippius-agent-tenant-telemetry: vsock pusher join timed out — abandoning")
        }
    }
}

/// Spawn the PR-E2.3 vsock pusher thread.
///
/// Linux-only: the pusher dials the host miner-agent over `AF_VSOCK`,
/// a Linux socket family. On a non-Linux dev host it is a no-op — the
/// receipt loop still runs (the queue simply fills); that host never
/// serves production traffic.
#[cfg(target_os = "linux")]
fn spawn_vsock_pusher(
    cfg: &Config,
    queue: Arc<Mutex<ReceiptQueue>>,
    shutdown: Shutdown,
) -> Result<Option<std::thread::JoinHandle<Result<()>>>> {
    let pusher = VsockPusher::new(VSOCK_HOST_CID, cfg.vsock_port, queue, shutdown);
    Ok(Some(pusher.spawn()?))
}

#[cfg(not(target_os = "linux"))]
fn spawn_vsock_pusher(
    _cfg: &Config,
    _queue: Arc<Mutex<ReceiptQueue>>,
    _shutdown: Shutdown,
) -> Result<Option<std::thread::JoinHandle<Result<()>>>> {
    eprintln!("hippius-agent-tenant-telemetry: vsock pusher disabled (non-Linux build)");
    Ok(None)
}
