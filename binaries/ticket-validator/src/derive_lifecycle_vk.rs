//! `derive-lifecycle-vk` subcommand — vali's helper to re-derive the §7
//! lifecycle PUBLIC key from an already-staged lifecycle seed.
//!
//! ## Why a subcommand
//!
//! vali has no Python crypto dependency (see `gen-lifecycle-key`). The KBS
//! reads the per-VM lifecycle seed at PINNED Vault version 1 forever
//! (`kbs-core/src/release.rs` `LIFECYCLE_KEY_VERSION`), so a re-launch of
//! an existing vm_id must NOT rotate the key — vali reuses the version-1
//! seed and needs the matching PUBLIC key to (re-)persist `Vm.lifecycle_vk`
//! and the derived telemetry source in lockstep with what the guest
//! actually holds.
//!
//! ## Wire contract
//!
//! - stdin: the 32-byte lifecycle seed as hex (SECRET — read from stdin,
//!   never argv, so it stays out of `ps`).
//! - stdout: `{"vk_hex":"<64 hex>"}` — the Ed25519 verifying key (PUBLIC,
//!   non-secret). The seed is never emitted.
//! - exit: `0` ok, `2` bad stdin (missing / not 32-byte hex), `1` IO.
//!
//! ## §20 secret discipline
//!
//! The seed on stdin IS a secret; it is held in `Zeroizing` buffers and
//! never logged (stderr carries only static error classes).

use std::io::{self, Read, Write};
use std::process::ExitCode;

use ed25519_dalek::SigningKey;
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
        eprintln!("hippius-ticket-validator: derive-lifecycle-vk stdin read failed");
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

    let vk_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());

    // Emit the PUBLIC key only — the seed never leaves this process.
    let out = io::stdout();
    let mut h = out.lock();
    if writeln!(h, "{{\"vk_hex\":\"{vk_hex}\"}}").is_err() {
        eprintln!("hippius-ticket-validator: derive-lifecycle-vk stdout write failed");
        return ExitCode::from(EXIT_IO);
    }
    ExitCode::SUCCESS
}
