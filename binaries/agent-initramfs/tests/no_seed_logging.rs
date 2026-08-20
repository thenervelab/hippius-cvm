//! §20 "no seed logging" — source-level guard (PR-E1.5).
//!
//! Scans the crate's own `src/` tree and fails if any print / log /
//! format macro interpolates a secret-bearing identifier, or if
//! `dbg!(` appears at all. This is defence-in-depth on top of the
//! structural discipline already in place — every [`AgentError`] class
//! is a closed `&'static str`, and the binary's `log_fatal` /
//! `log_eol` loggers take `&'static str` only — so a leak would need
//! someone to add a brand-new ad-hoc `eprintln!`. This test (and the
//! mirrored `no-seed-logging` CI step) makes that attempt fail loudly.
//!
//! [`AgentError`]: hippius_agent_initramfs::AgentError

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

/// Macros that emit to a log, the console, a panic message, or a
/// formatted string that could then be logged.
const LOG_MACROS: &[&str] = &[
    "println!",
    "eprintln!",
    "print!",
    "eprint!",
    "panic!",
    "write!",
    "writeln!",
    "format!",
    "log::",
    "info!",
    "warn!",
    "error!",
    "debug!",
    "trace!",
];

/// Secret-bearing identifiers that must never be interpolated into a
/// formatted string (§20). Matched as `{name}` / `{name:…}` format
/// placeholders. Kept to unambiguous secret variable names so the scan
/// has no false positives on the crate's many benign `format!`s
/// (cmdline-token prefixes, URL joins, path joins).
const SECRET_IDENTS: &[&str] = &[
    "luks",
    "userdata",
    "user_data",
    "plaintext",
    "passphrase",
    "guest_sk",
    "signing_key",
    "lifecycle_key",
    "seed_bytes",
];

/// Recursively collect every `*.rs` file under `dir`.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The crate `src/` trees that handle release plaintext (LUKS KEK,
/// user-data, §7 lifecycle SIGNING key). Scanned together so a leak in
/// ANY of them fails this gate — kept in lockstep with
/// `scripts/check-no-seed-logging.sh`.
///
/// `CARGO_MANIFEST_DIR` is `binaries/agent-initramfs`; the two siblings
/// are reached relative to it (`../guest-release`, `../../hippius-guest`).
fn scan_roots() -> Vec<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        manifest.join("src"),
        manifest.join("../guest-release/src"),
        manifest.join("../../hippius-guest/src"),
    ]
}

#[test]
fn no_secret_is_interpolated_into_a_log_line() {
    let mut files = Vec::new();
    for root in scan_roots() {
        if root.is_dir() {
            rs_files(&root, &mut files);
        }
    }
    assert!(!files.is_empty(), "found no src/*.rs files to scan");

    let mut violations = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for (idx, line) in text.lines().enumerate() {
            let lineno = idx + 1;
            // Skip comment lines — a commented-out line cannot leak.
            if line.trim_start().starts_with("//") {
                continue;
            }
            // `dbg!` is banned outright: it dumps its argument via
            // `Debug` with no `{}` placeholder, so the interpolation
            // check below would never see it.
            if line.contains("dbg!(") {
                violations.push(format!("{}:{lineno} — dbg!()", file.display()));
                continue;
            }
            if !LOG_MACROS.iter().any(|m| line.contains(m)) {
                continue;
            }
            for ident in SECRET_IDENTS {
                if line.contains(&format!("{{{ident}}}")) || line.contains(&format!("{{{ident}:")) {
                    violations.push(format!(
                        "{}:{lineno} — interpolates {{{ident}}}",
                        file.display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "§20 no-seed-logging violations:\n{}",
        violations.join("\n")
    );
}
