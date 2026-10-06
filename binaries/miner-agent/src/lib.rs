//! # hippius-miner-agent — library surface
//!
//! The miner-agent runs on an **untrusted** bare-metal miner host
//! (`project_hippius_compute_locked_decisions.md`: miners are untrusted
//! by design). It:
//!
//! - **self-generates** the miner's persistent Ed25519 identity
//!   ([`identity`]) — never Vault-issued; the secret half never leaves
//!   the host; the public half is printed for the operator to register
//!   out-of-band with vali;
//! - fetches + **§22-verifies** UKI images ([`image_cache`]) via the
//!   `miner-uki-fetch` library;
//! - launches tenant SEV-SNP confidential VMs via libvirt + QEMU
//!   ([`lifecycle`], MA-3) — a fail-closed CVM state machine with a
//!   pre-flight launch digest;
//! - relays guest-CVM control-plane traffic over AF_VSOCK
//!   ([`vsock`], MA-4) — a length-prefixed, size-capped framing whose
//!   per-CVM identity is the host-assigned context id, never a
//!   guest-declared field;
//! - serves signed lifecycle orders ([`orders`], MA-5) — a small axum
//!   HTTP server, bound to the NetBird interface only, that
//!   `verify_strict`-checks every launch / stop / destroy / migrate
//!   order against the pinned Edge key before dispatch and is
//!   idempotent per `order_id`;
//! - carries the skeleton for the Edge gateway mTLS client
//!   ([`edge_client`]) — wired in a later MA-* PR.
//!
//! ## Trust boundary
//!
//! The miner **never** authenticates to the hippius-compute Vault and
//! **never** speaks to the KBS — only the tenant guest VMs do. The
//! miner-agent's only outward surface, the Edge client, is still a
//! `not-yet-wired` skeleton. The CVM lifecycle drives the **local**
//! libvirt host only.
#![deny(rust_2018_idioms, unreachable_pub)]
// Unit + integration tests use unwrap/expect/panic — the workspace
// denies these in library code, so opt in only under `cfg(test)`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod backup;
pub mod config;
pub mod edge_client;
pub mod error;
pub mod heartbeat;
pub mod host_health;
pub mod identity;
pub mod image_cache;
pub mod lifecycle;
pub mod netpolicy;
pub mod orders;
pub mod sev_asid;
pub mod snp_config;
pub mod vsock;

pub use config::Config;
pub use edge_client::{EdgeClient, EnvelopeKind};
pub use error::{MinerAgentError, Result};
pub use heartbeat::{
    build_edge_mtls_client, run_builder, run_pusher, HeartbeatBuilder, HeartbeatClient,
    HeartbeatQueue, MetricsSource, MinerHeartbeat, ProcMetricsSource, ReqwestHeartbeatClient,
    SequenceStore, SignedMinerHeartbeat,
};
pub use identity::MinerIdentity;
pub use image_cache::ImageCache;
#[cfg(feature = "snp")]
pub use lifecycle::compute_launch_digest_for_generation;
pub use lifecycle::{
    compute_launch_digest, load_cmdline, CvmLifecycle, CvmPhase, DomainLiveness, DomainProfile,
    DomainUuid, HostResources, InfraDomainConfig, InfraLaunchOrder, QemuConfig, SevLaunchDigest,
    VirshDriver, VmId, INFRA_VM_ID,
};
pub use orders::LaunchOrder;
