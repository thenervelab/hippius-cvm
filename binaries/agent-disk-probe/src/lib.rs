//! `hippius-agent-disk-probe` — the disk-tier probe
//! (docs/design/disk-tier-verification.md §3.2, §3.3, §4.2).
//!
//! Dormant in every tenant VM: its unit starts only when
//! `/run/hippius/disk-probe/request.json` exists, which vali's
//! KBS-released probe userdata writes. It then waits the requested
//! delay, probes each target one at a time ([`profiles`]), and leaves
//! the result for the telemetry agent to sign into its receipts. A
//! tenant running it on their own VM gains nothing: vali accepts a
//! `disk_probe` only from a VM it launched as a probe.

pub mod crypt;
pub mod engine;
pub mod error;
pub mod hist;
pub mod profiles;
pub mod request;
pub mod result;
