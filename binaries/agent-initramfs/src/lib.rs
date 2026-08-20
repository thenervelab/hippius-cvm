//! # hippius-agent-initramfs — library surface
//!
//! The production entry point is the `hippius-agent-initramfs` binary
//! (`src/main.rs`). This `lib.rs` re-exports the pipeline and the
//! per-stage modules so integration tests can drive them directly
//! without needing `/dev/sev-guest`, the network, or root privileges.
//!
//! Spec of record: `ARCHITECTURE.md` §11 (measured boot), §20 (crypto
//! profile + `REPORT_DATA` layout), §21 (boot → attest → release →
//! switch_root sequence), §24/§25 (end-of-life ack — handled later in
//! PR-E1.5).
//!
//! ## Skeleton scope (PR-E1.1 + PR-E1.2)
//!
//! - **PR-E1.1**: every stage returns [`pipeline::AgentError::Todo`]
//!   — no real I/O, no `pivot_root(2)`. Pins the §21 step order
//!   ([`pipeline::run`]), per-stage type signatures, and the fail-
//!   closed contract.
//! - **PR-E1.2**: real [`stages::keygen::generate_ephemeral`]
//!   (X25519 via `x25519-dalek`, secret in `Zeroizing<[u8; 32]>`) +
//!   real [`stages::snp_ioctl::SevGuestProvider`] (production
//!   `/dev/sev-guest` ioctl via the `sev` crate, Linux/x86_64 only)
//!   behind a [`stages::snp_report::SnpReportProvider`] trait so
//!   tests + non-SNP dev hosts can drive the pipeline through a
//!   [`stages::snp_report::MockSnpReportProvider`] without claiming
//!   attestation. The pipeline still aborts at the next stub
//!   (`KbsRelease`) — by typestate, every later stage runs only on
//!   bytes produced by the gate.
//!
//! The dependency on `hippius-guest` is real (not stubbed): the
//! [`stages::verify`] stage wraps
//! [`hippius_guest::verify_and_unwrap_release`] directly so future PRs
//! cannot accidentally bypass the §6/§7/§19/§20 binding gate.

#![deny(rust_2018_idioms, unreachable_pub)]
// Stage unit tests use unwrap()/panic!() — workspace denies these in
// library code. Same pattern as `hippius-guest/src/lib.rs`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod pipeline;
pub mod stages;
pub mod trust_anchors;

pub use pipeline::{resolve_handoff_mode, run, AgentError, Config, HandoffMode, Stage};
pub use stages::eol::{
    eol_teardown, run_eol, run_eol_sign_only, EolSink, MockEolSink, StoppedAckParams,
};
pub use stages::hardening::{assert_hardened_cmdline, poweroff, suppress_kernel_console};
pub use stages::kbs_client::{
    resolve_kbs_url, HttpClient, HttpResponse, KbsNonce, ReqwestHttpClient,
};
pub use stages::kbs_vsock_client::{is_vsock_url, VsockHttpClient};
pub use stages::network::{bring_up_dhcp, teardown_for_switchroot};
pub use stages::seed::{MockSeedWriter, RealSeedWriter, SeedWriter, NOCLOUD_SEED_DIR};
pub use stages::snp_report::{
    MockSnpReportProvider, ReportData, SnpReport, SnpReportProvider, SNP_REPORT_LEN,
};
pub use stages::switch_root::{
    MockRootfsPivot, PivotConfig, PivotMode, RootfsPivot, ROOTFS_MAPPER,
};
pub use stages::ticket::Ticket;
pub use stages::unlock::{
    resolve_luks_device, LuksUnlocker, MockLuksUnlocker, MockUnlockCall, MAPPER_NAME,
};
pub use stages::verity::{
    resolve_rootfs_devices, resolve_verity_root_hash, MockOpenCall as MockVerityOpenCall,
    MockRootfsVerity, RootfsVerity, MAPPER_NAME as VERITY_MAPPER_NAME,
};
pub use trust_anchors::{PINNED_KBS_RESPONSE_KID, PINNED_KBS_RESPONSE_VK};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use stages::snp_ioctl::SevGuestProvider;

#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
pub use stages::luks_cryptsetup::RealLuksUnlocker;

#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
pub use stages::verity_cryptsetup::RealRootfsVerity;

#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
pub use stages::eol::RealEolSink;

#[cfg(target_os = "linux")]
pub use stages::switch_root::RealRootfsPivot;
