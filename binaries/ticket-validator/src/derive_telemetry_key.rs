//! `derive-telemetry-key` subcommand — vali's helper to derive the per-VM
//! tenant telemetry PUBLIC key from the §7 lifecycle seed.
//!
//! ## Why a subcommand
//!
//! vali has no Python crypto dependency (see `gen-lifecycle-key`). The
//! telemetry signing key is NOT a fresh secret — it is HKDF-derived from
//! the lifecycle seed vali already generated
//! (`hippius_guest::telemetry_key::derive_telemetry_signing_key`), so the
//! guest can reproduce it from the lifecycle key it receives in the §21
//! release. vali only needs the PUBLIC key here — to provision the
//! `TelemetrySource` it verifies the guest's served-receipts against.
//!
//! ## Wire contract
//!
//! - stdin: the 32-byte lifecycle seed as hex (SECRET — read from stdin,
//!   never argv, so it stays out of `ps`).
//! - stdout: `{"vk_hex":"<64 hex>"}` — the derived telemetry verifying key
//!   (PUBLIC, non-secret). The derived signing seed is NEVER emitted: vali
//!   does not stage it (the guest derives its own copy).
//! - exit: `0` ok, `2` bad stdin (missing / not 32-byte hex), `1` IO.
//!
//! ## §20 secret discipline
//!
//! The lifecycle seed on stdin IS a secret; it is held in a `Zeroizing`
//! buffer and never logged (stderr carries only static error classes).

use std::io::{self, Read, Write};
use std::process::ExitCode;

use hippius_guest::telemetry_key::derive_telemetry_signing_key;
use zeroize::Zeroizing;

const EXIT_STRUCTURED: u8 = 2;
const EXIT_IO: u8 = 1;

pub fn run() -> ExitCode {
    // Read the lifecycle seed hex from stdin (bounded — a seed is 64 hex
    // chars; allow a little slack for a trailing newline).
    let mut raw = Zeroizing::new(String::new());
    if io::stdin()
        .lock()
        .take(256)
        .read_to_string(&mut raw)
        .is_err()
    {
        eprintln!("hippius-ticket-validator: derive-telemetry-key stdin read failed");
        return ExitCode::from(EXIT_IO);
    }
    let seed_hex = raw.trim();

    let seed_vec = match hex::decode(seed_hex) {
        Ok(v) => Zeroizing::new(v),
        Err(_) => {
            eprintln!("hippius-ticket-validator: lifecycle seed is not valid hex");
            return ExitCode::from(EXIT_STRUCTURED);
        }
    };
    let seed: Zeroizing<[u8; 32]> = match <[u8; 32]>::try_from(seed_vec.as_slice()) {
        Ok(arr) => Zeroizing::new(arr),
        Err(_) => {
            eprintln!("hippius-ticket-validator: lifecycle seed must be 32 bytes");
            return ExitCode::from(EXIT_STRUCTURED);
        }
    };

    let vk_hex = hex::encode(
        derive_telemetry_signing_key(&seed)
            .verifying_key()
            .to_bytes(),
    );

    // Emit the PUBLIC key only — the derived seed never leaves this process.
    let out = io::stdout();
    let mut h = out.lock();
    if writeln!(h, "{{\"vk_hex\":\"{vk_hex}\"}}").is_err() {
        eprintln!("hippius-ticket-validator: derive-telemetry-key stdout write failed");
        return ExitCode::from(EXIT_IO);
    }
    ExitCode::SUCCESS
}
