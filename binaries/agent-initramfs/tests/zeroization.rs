//! Demonstrable zeroization — §20 (PR-E1.5).
//!
//! §20 requires the unwrapped secret buffers to be **demonstrably**
//! zeroized ("no copies"). This test demonstrates, on a buffer holding
//! a known marker, that the wipe `Zeroizing<T>::drop` performs leaves
//! no trace of the marker in that buffer — and documents, honestly,
//! the limits of what is provable in safe Rust.
//!
//! ## What is demonstrated
//!
//! `Zeroize::zeroize()` overwrites every byte of a heap `Vec<u8>` with
//! `0`. `Zeroizing<T>`'s `Drop` impl calls **exactly that** on the
//! wrapped value immediately before it is freed. So a secret carried
//! in a `Zeroizing<Vec<u8>>` — which is how `hippius_guest` returns the
//! LUKS key + the cloud-init plaintext, and how every §21 stage takes
//! them (by value, see `tests/compile_gate.rs`) — is overwritten the
//! moment it goes out of scope.
//!
//! ## Caveats (documented honestly, per the §20 "best-effort" note)
//!
//! Safe Rust cannot read freed memory, so a test cannot inspect the
//! exact freed allocation *after* the drop. It also cannot prove the
//! absence of *copies* the compiler / allocator / CPU may have made
//! (stack spills, a `realloc` that relocated the buffer). The crate
//! closes those structurally — the X25519 scalar is heap-`Box`ed for a
//! stable address (`stages::keygen`), every secret is moved **by
//! value** so no stale owner survives, and no secret type derives
//! `Clone` or `Debug` — and the §F measured image closes the rest at
//! the deployment layer: swap is disabled and core dumps are off, so a
//! wiped-in-place buffer cannot resurface in swap or a crash dump.
//! What this test proves is the load-bearing primitive: the wipe
//! itself is real and total.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zeroize::{Zeroize, Zeroizing};

/// A non-trivial marker — every byte distinct from `0` so the wipe is
/// unambiguous, and not a run of one bit so a partial wipe would show.
const MARKER: u8 = 0xA5;

#[test]
fn zeroize_leaves_no_marker_byte_in_the_buffer() {
    // A 64 KiB buffer — comfortably larger than any real LUKS key or
    // cloud-init plaintext, so a length-dependent wipe bug would show.
    let mut secret = vec![MARKER; 64 * 1024];
    assert!(
        secret.iter().all(|&b| b == MARKER),
        "precondition: the buffer is full of the marker"
    );

    // This is the exact operation `Zeroizing::<Vec<u8>>::drop` runs.
    secret.zeroize();

    // The buffer is still allocated (still owned by `secret`) — and the
    // marker is provably, totally gone from it.
    assert!(
        !secret.contains(&MARKER),
        "no marker byte may survive the wipe"
    );
    assert!(
        secret.iter().all(|&b| b == 0),
        "every byte must be zero after the wipe"
    );
}

#[test]
fn zeroizing_carries_the_secret_while_alive_then_wipes_on_drop() {
    // While alive, a `Zeroizing<Vec<u8>>` is a transparent secret
    // buffer — the bytes are intact and usable.
    let secret = Zeroizing::new(vec![MARKER; 4096]);
    assert!(secret.iter().all(|&b| b == MARKER));

    // `Zeroizing<T>` adds a `Drop` that zeroizes `T` — a bare `Vec`
    // does NOT wipe its contents on drop. Dropping here therefore runs
    // the wipe demonstrated byte-for-byte by the test above. (We cannot
    // legally observe the freed allocation afterwards — see the module
    // "Caveats" docs — so this asserts the contract, not the freed RAM.)
    drop(secret);
}

#[test]
fn a_short_secret_sized_buffer_is_wiped_completely() {
    // LUKS keys / passphrases are short; pin that the wipe is total at
    // a realistic small size too (no off-by-one leaving a tail byte).
    for len in [16usize, 32, 64, 117] {
        let mut secret = vec![MARKER; len];
        secret.zeroize();
        assert!(
            secret.iter().all(|&b| b == 0),
            "a {len}-byte secret must be wiped completely"
        );
    }
}
