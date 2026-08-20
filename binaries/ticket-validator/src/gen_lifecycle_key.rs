//! `gen-lifecycle-key` subcommand — vali's helper to generate a per-VM
//! §7 guest lifecycle Ed25519 keypair.
//!
//! ## Why a subcommand
//!
//! vali has no Python crypto dependency (`cryptography` / `pynacl` are
//! deliberately absent — see `vali/pyproject.toml`). Every Ed25519
//! operation it needs is already shelled out to this Rust binary
//! (`verify-stopped-ack`, `verify-ticket`, …). Generating the §7
//! lifecycle keypair here keeps the crypto single-sourced and matches
//! the existing call pattern.
//!
//! ## What it does
//!
//! 1. Draw 32 bytes of OS entropy (`rand_core::OsRng`) into an Ed25519
//!    seed (the PRIVATE / signing key).
//! 2. Derive the 32-byte Ed25519 PUBLIC (verifying) key.
//! 3. Emit `{"seed_hex": "...", "vk_hex": "..."}` on stdout.
//!
//! vali then:
//! - stages `seed_hex` (decoded) into Vault at the per-VM
//!   `…/lifecycle-key` path (the PRIVATE key the KBS releases to the
//!   attested guest), and
//! - records `vk_hex` (decoded) as `Vm.lifecycle_vk` (the PUBLIC key
//!   `_verify_ack` / `lifecycle_vk_hex()` use).
//!
//! ## §20 secret discipline
//!
//! The seed IS a secret. It is held in a `Zeroizing` buffer (wiped on
//! drop) and is written to stdout exactly ONCE as hex — vali reads it,
//! stages it in Vault, and drops it. NOTHING about the seed is ever
//! logged: stderr carries only `&'static` error classes, and the seed
//! is never interpolated into a log/format macro (the `no-seed-logging`
//! gate scans for `{seed_bytes}` / `{signing_key}` / `{lifecycle_key}`).
//! The keypair is generated fresh per VM — there is no key file on disk.

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use std::io::Write;
use std::process::ExitCode;
use zeroize::Zeroizing;

/// IO error writing stdout — surfaced as exit `1` (matches the
/// other subcommands' transient-IO exit code).
const EXIT_IO: u8 = 1;

/// Generate the keypair and print the JSON envelope.
pub fn run() -> ExitCode {
    // 32 bytes of OS entropy → the Ed25519 seed (private key). Held in
    // `Zeroizing` so the raw seed wipes on drop; `SigningKey` is itself
    // `ZeroizeOnDrop` (ed25519-dalek `zeroize` feature off here, but the
    // seed buffer is the sensitive copy and IS zeroized).
    let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let signing = SigningKey::from_bytes(&seed);
    let vk = signing.verifying_key().to_bytes();

    // Hex-encode. The seed hex is also a secret — hold it in `Zeroizing`
    // so the encoded form wipes too, then write it out once.
    let seed_hex = Zeroizing::new(hex::encode(seed.as_ref()));
    let vk_hex = hex::encode(vk);

    // Emit the JSON by hand (no serde struct) so the secret never lands
    // in a `Debug`/`Serialize` derive path. The §20 no-seed-logging
    // scan looks for log macros; `writeln!` to stdout here is the ONE
    // intentional emission of the seed — to vali, its trusted consumer.
    let out = std::io::stdout();
    let mut h = out.lock();
    if writeln!(
        h,
        "{{\"seed_hex\":\"{}\",\"vk_hex\":\"{}\"}}",
        seed_hex.as_str(),
        vk_hex
    )
    .is_err()
    {
        eprintln!("hippius-ticket-validator: gen-lifecycle-key: stdout-write");
        return ExitCode::from(EXIT_IO);
    }
    if h.flush().is_err() {
        eprintln!("hippius-ticket-validator: gen-lifecycle-key: stdout-flush");
        return ExitCode::from(EXIT_IO);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

    #[test]
    fn seed_derives_a_consistent_verifying_key() {
        // The seed→vk derivation must be the standard Ed25519 one, so a
        // guest that loads the seed as a `SigningKey` produces a vk that
        // matches what vali records. Generate via the same path and
        // cross-check the signature verifies.
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk_bytes = sk.verifying_key().to_bytes();

        // Reconstruct the vk from bytes (vali round-trips it through hex
        // and `Vm.lifecycle_vk`), sign + verify.
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let msg = b"stopped-ack-body";
        let sig: Signature = sk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn two_invocations_produce_distinct_seeds() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        assert_ne!(a, b, "OsRng must not repeat a 32-byte seed");
    }
}
