//! Per-stage modules for the §21 boot pipeline.
//!
//! Each submodule contains exactly one stage of the [`crate::pipeline`]
//! and a single entry function. PR-E1.1 leaves every stage stubbed; the
//! exact `TODO(PR-E1.x)` follow-up is named in each module's doc-comment.

pub mod eol;
pub mod hardening;
pub mod kbs_client;
pub mod kbs_vsock_client;
pub mod keygen;
pub mod luks_cryptsetup;
pub mod network;
pub mod seed;
pub mod snp_ioctl;
pub mod snp_report;
pub mod switch_root;
pub mod ticket;
pub mod ticket_vsock;
pub mod unlock;
pub mod verify;
pub mod verity;
pub mod verity_cryptsetup;
