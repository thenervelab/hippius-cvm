//! Generates a small known-good audit-log fixture for the
//! `hippius-sentinel` PR-S2 Python verifier tests.
//!
//! Run from the repo root:
//!
//! ```sh
//! cargo run --example audit_fixture -- sentinel/tests/fixtures/audit_known_good
//! ```
//!
//! The resulting directory contains `audit.log` + `head.sha256` produced by
//! the same `FileAuditSink` used in production. The Python verifier must
//! be able to walk this chain and recompute the same head.
//!
//! Re-run only when the audit record schema changes (in which case the
//! Python verifier also changes). The fixture is committed so neither
//! CI nor the python tests need cargo at all.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use kbs_core::audit::FileAuditSink;

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let dir = args
        .next()
        .map(PathBuf::from)
        .ok_or("usage: cargo run --example audit_fixture -- <out-dir>")?;

    // Start from a clean directory so the fixture is reproducible.
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;

    let sink = FileAuditSink::open(&dir)?;

    // Deterministic records — fixed timestamps + ids so the resulting
    // audit.log bytes are stable across runs.
    sink.append(
        true,
        Some("tk-0001"),
        Some("vm-a"),
        "released",
        1_700_000_000,
    )?;
    sink.append(
        false,
        Some("tk-0002"),
        Some("vm-b"),
        "ticket_expired",
        1_700_000_060,
    )?;
    sink.append(
        true,
        Some("tk-0003"),
        Some("vm-c"),
        "released",
        1_700_000_120,
    )?;

    let verified = sink.verify()?;
    println!(
        "wrote {} records, head={} into {}",
        verified.records,
        hex::encode(verified.head),
        dir.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("audit_fixture: {e}");
            ExitCode::FAILURE
        }
    }
}
