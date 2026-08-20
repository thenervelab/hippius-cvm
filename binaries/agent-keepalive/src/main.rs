//! `hippius-agent-keepalive` — long-running daemon (#322 Phase B).
//!
//! Runs inside the tenant SEV-SNP CVM as a systemd service. Each
//! tick: read epoch from `--epoch-file`, fetch a single-use nonce
//! from KBS, ask `/dev/sev-guest` for an SNP report bound to
//! `(nonce, vm_id)`, POST it to `${kbs_url}/v1/attest/keepalive`.
//! KBS verifies the report against AMD silicon + §22 allowlist
//! and signs a `SignedLiveAttestation` the validator submits on-
//! chain via `pallet-compute-scoring::submit_live_attestation`.
//!
//! ## Trust model
//!
//! The in-VM agent IS the trust anchor — the kernel inside a
//! measured CVM cannot fake what `/dev/sev-guest` reports; KBS
//! will not sign a report it cannot verify against AMD's silicon
//! root. A miner that lets the tenant VM go down stops producing
//! attestations and loses uptime weight for that epoch.
//!
//! ## Logging discipline
//!
//! Diagnostics go to stderr using closed-vocabulary `&'static str`
//! classifiers — no plaintext interpolation of secrets / paths /
//! inner library messages, same posture as `agent-initramfs`. A
//! transient KBS hiccup (`kbs-connect`) is logged once per tick;
//! the daemon never spins on retry beyond the configured interval.
//!
//! ## Exit codes
//!
//! - `0` — never (the daemon runs until SIGTERM).
//! - `1` — usage / config error at startup.
//! - `2` — `/dev/sev-guest` open failure (unrecoverable; the VM
//!   isn't a real SNP guest, so signing attestations would be a
//!   lie). systemd should NOT restart on this.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use clap::Parser;
use hippius_agent_initramfs::stages::snp_report::SnpReportProvider;
use hippius_agent_keepalive::client::KbsClient;
use hippius_agent_keepalive::relay::AttestationSink;
use hippius_agent_keepalive::tick::{run_once_and_push, TickInputs};
use std::process::ExitCode;
use std::time::Duration;

const EXIT_USAGE: u8 = 1;
const EXIT_SNP_UNAVAILABLE: u8 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "hippius-agent-keepalive",
    version,
    about = "Periodic SEV-SNP live-attestation keepalive to KBS (#322 Phase B)."
)]
struct Cli {
    /// HTTPS base URL for the KBS, e.g. `https://kbs.hippius.network`.
    #[arg(long)]
    kbs_url: String,

    /// Stable tenant VM identifier — same value the §K heartbeat +
    /// the §20 release request used.
    #[arg(long)]
    vm_id: String,

    /// 32-byte miner node identity, hex. Copied into the signed body
    /// so the pallet credits the right miner; injected at boot by
    /// the miner-agent via cloud-init / kernel cmdline / a sealed
    /// secret (the keepalive agent itself does not authenticate it
    /// — the §22 chain + measurement bind the booted UKI, the
    /// `node_id` is operator-asserted).
    #[arg(long, value_name = "HEX64")]
    node_id_hex: String,

    /// Path to a text file containing the current compute-pallet
    /// epoch as decimal (e.g. `42\n`). The miner-agent (or a
    /// companion process) keeps it fresh; the keepalive agent
    /// re-reads it each tick. Absent / unreadable ⇒ the tick fails
    /// with `epoch-read` — we never ship attestations for epoch 0
    /// the pallet would silently reject.
    #[arg(long, value_name = "PATH")]
    epoch_file: std::path::PathBuf,

    /// Tick interval, seconds. Default 300 (5 min). Operators tune
    /// against the pallet's `expected_attestations_per_epoch`: too
    /// long produces gaps that look like downtime, too short burns
    /// nonce-store capacity + KBS CPU.
    #[arg(long, default_value_t = 300)]
    interval_secs: u64,

    /// `LiveAttestation::expiry_unix` is `now_unix + expiry_offset`.
    /// Default 600 (10 min) — covers the validator's worst-case
    /// batch latency. The pallet rejects expired bodies, so a
    /// value < tick interval would let valid attestations expire
    /// before the next one even gets minted.
    #[arg(long, default_value_t = 600)]
    expiry_offset_secs: u64,

    /// AF_VSOCK port of the host miner-agent's guest-frame listener.
    /// Each successful tick pushes the KBS-signed `SignedLiveAttestation`
    /// there as a `vm-live-attestation` frame; the miner-agent relays it
    /// to the Edge, which relays it to vali's uptime-coverage ingest.
    ///
    /// Without this, vali never learns the VM was alive — and once the
    /// §23 uptime-liveness gate is armed, an uncovered window credits
    /// ZERO. `0` disables the push (attestations are still minted +
    /// archived KBS-side), which is the shape a fleet runs in while the
    /// operator is still on step 2 of the arming sequence.
    #[arg(long, default_value_t = 0)]
    relay_vsock_port: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let node_id = match parse_hex32(&cli.node_id_hex) {
        Ok(n) => n,
        Err(cls) => {
            eprintln!("hippius-agent-keepalive: fail-closed: node_id_hex:{cls}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let provider = match snp_provider() {
        Ok(p) => p,
        Err(cls) => {
            eprintln!("hippius-agent-keepalive: fail-closed: snp-provider:{cls}");
            return ExitCode::from(EXIT_SNP_UNAVAILABLE);
        }
    };

    let kbs = match KbsClient::new(&cli.kbs_url) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("hippius-agent-keepalive: fail-closed: kbs-client-build");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let sink = attestation_sink(cli.relay_vsock_port);

    eprintln!(
        "hippius-agent-keepalive: ready: vm_id={} interval={}s expiry_offset={}s relay_port={}",
        cli.vm_id, cli.interval_secs, cli.expiry_offset_secs, cli.relay_vsock_port
    );

    let inputs = TickInputs {
        vm_id: &cli.vm_id,
        node_id: &node_id,
        epoch_file: &cli.epoch_file,
        expiry_offset_secs: cli.expiry_offset_secs,
    };

    // Run forever — systemd RestartSec=10s catches a panicking exit
    // from a transient failure (e.g. clock skew) but in normal
    // operation we just log + sleep + retry. A successful tick
    // produces a `tick-ok` line; a failed one a `tick-err:<class>`
    // line — both single-line so the operator can grep the journal
    // for keepalive health without cardinality explosions.
    loop {
        match run_once_and_push(&inputs, provider.as_ref(), &kbs, sink.as_ref()) {
            Ok((_, None)) => {
                eprintln!("hippius-agent-keepalive: tick-ok vm_id={}", cli.vm_id);
            }
            Ok((_, Some(relay_class))) => {
                // The attestation WAS minted; only the last hop failed.
                // Logged loudly: a persistent `relay-*` class means vali
                // is not seeing this VM's liveness, which once the gate
                // is armed means this VM's uptime is not creditable.
                eprintln!(
                    "hippius-agent-keepalive: tick-ok-relay-err:{relay_class} vm_id={}",
                    cli.vm_id
                );
            }
            Err(e) => {
                eprintln!(
                    "hippius-agent-keepalive: tick-err:{e:?} vm_id={}",
                    cli.vm_id
                );
            }
        }
        std::thread::sleep(Duration::from_secs(cli.interval_secs));
    }
}

/// Build the per-tick attestation sink. Port `0` ⇒ the push is
/// disabled (`NullSink`).
#[cfg(target_os = "linux")]
fn attestation_sink(port: u32) -> Box<dyn AttestationSink> {
    use hippius_agent_keepalive::relay::{NullSink, VsockSink, VSOCK_HOST_CID};
    if port == 0 {
        return Box::new(NullSink);
    }
    Box::new(VsockSink {
        host_cid: VSOCK_HOST_CID,
        port,
    })
}

/// Non-Linux dev hosts have no `AF_VSOCK`; the push is a no-op there.
#[cfg(not(target_os = "linux"))]
fn attestation_sink(_port: u32) -> Box<dyn AttestationSink> {
    Box::new(hippius_agent_keepalive::relay::NullSink)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], &'static str> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("len");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "hex")?;
        out[i] = byte;
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn snp_provider() -> Result<Box<dyn SnpReportProvider>, &'static str> {
    use hippius_agent_initramfs::stages::snp_ioctl::SevGuestProvider;
    // `SevGuestProvider::new()` doesn't probe the device; it returns
    // an opener handle that the `get_report` call exercises lazily.
    // The keepalive path can therefore boot even before the first
    // tick — surfacing the device hole at the per-tick classifier
    // rather than at startup, which keeps systemd from disabling the
    // unit on a transient device-availability blip.
    Ok(Box::new(SevGuestProvider::new()))
}

#[cfg(not(target_os = "linux"))]
fn snp_provider() -> Result<Box<dyn SnpReportProvider>, &'static str> {
    // Non-Linux dev hosts don't have `/dev/sev-guest`; a real
    // production run cannot reach this branch (the binary is built
    // for linux x86_64). The mock provider produces a fixed-shape
    // 1184-byte payload, used by the unit tests.
    Ok(Box::new(
        hippius_agent_initramfs::stages::snp_report::MockSnpReportProvider::with_zeroed_response(),
    ))
}
