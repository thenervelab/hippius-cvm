//! `hippius-vsock-ticket` — receive one host-pushed COSE `OrderTicket`
//! from AF_VSOCK and write the raw bytes to a file. Invoked from the
//! BYO base-OS initramfs `hippius-luks-keyscript` when the operator
//! did not pre-stage a ticket via `hippius.ticket_path=`.
//!
//! Wraps [`hippius_agent_initramfs::stages::ticket_vsock::recv_ticket`]
//! so the wire format (`u32` BE length + COSE_Sign1 body, accept
//! timeout, host-CID peer pin) stays single-sourced with both the
//! legacy custom-Rust agent-initramfs path and the `miner-agent` push
//! side. Changing the protocol in one place forces a recompile here
//! too.
//!
//! ## §20 logging discipline
//!
//! Every diagnostic goes to stderr and only uses the closed-vocabulary
//! [`AgentError::class`] (`&'static str`) — never the raw error type's
//! `Display`. The received COSE bytes are NOT public secrets but are
//! never logged either, on principle.
//!
//! ## Exit codes
//!
//! - `0` — one framed ticket received and written to `--out`.
//! - `2` — usage / argument parsing failure (handled by `clap`).
//! - `3` — vsock bind / accept / read failure, or output write failure.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use clap::Parser;
use hippius_agent_initramfs::stages::ticket_vsock;
use hippius_agent_initramfs::AgentError;
use hippius_types::ticket_vsock::PORT as DEFAULT_PORT;
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_VSOCK_FAILED: u8 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "hippius-vsock-ticket",
    version,
    about = "Receive one COSE OrderTicket from AF_VSOCK and write to --out."
)]
struct Cli {
    /// Absolute path the received raw COSE_Sign1 bytes are written
    /// to. The keyscript then passes this path to
    /// `hippius-guest-release --ticket`.
    #[arg(long)]
    out: std::path::PathBuf,

    /// AF_VSOCK port to listen on. Defaults to
    /// [`hippius_types::ticket_vsock::PORT`] so the receiver and the
    /// `miner-agent::vsock::ticket_push` sender agree without flag
    /// plumbing.
    #[arg(long)]
    port: Option<u32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let port = cli.port.unwrap_or(DEFAULT_PORT);

    let bytes = match ticket_vsock::recv_ticket(port) {
        Ok(b) => b,
        Err(e) => {
            log_fatal(&e);
            return ExitCode::from(EXIT_VSOCK_FAILED);
        }
    };

    if let Err(e) = std::fs::write(&cli.out, &bytes) {
        // §20: don't interpolate path. Use a static classifier.
        eprintln!(
            "hippius-vsock-ticket: fail-closed: write-out:{}",
            io_kind(&e)
        );
        return ExitCode::from(EXIT_VSOCK_FAILED);
    }

    ExitCode::from(EXIT_OK)
}

fn log_fatal(err: &AgentError) {
    match err.sub_class() {
        Some(sub) => eprintln!("hippius-vsock-ticket: fail-closed: {}:{}", err.class(), sub),
        None => eprintln!("hippius-vsock-ticket: fail-closed: {}", err.class()),
    }
}

fn io_kind(err: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match err.kind() {
        NotFound => "not-found",
        PermissionDenied => "permission-denied",
        AlreadyExists => "already-exists",
        InvalidInput => "invalid-input",
        WriteZero => "write-zero",
        Interrupted => "interrupted",
        _ => "other",
    }
}
