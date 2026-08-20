//! `hippius-agent-host-attestor` — the blackbox **host attestor** agent.
//!
//! Runs on the bare-metal SEV-SNP host (a small measured guest, PID1,
//! **synchronous** — no tokio) as the trust anchor for the *host
//! itself*, complementing the in-CVM blackbox that proves a *guest* is
//! alive:
//!
//! 1. **establish** ([`establish`]) — fetch the measurement-bound SNP
//!    derived key ONCE and HKDF-derive the per-boot Ed25519
//!    [`HostAttestorSigner`];
//! 2. **enrol** ([`enroll`]) — request ONE platform SNP report whose
//!    `REPORT_DATA` binds the signer pubkey + `node_id`, and ship a
//!    [`HostEnrollment`](hippius_types::host_attestor::HostEnrollment) the
//!    KBS verifies against AMD's silicon root + the platform allowlist;
//! 3. **beat** ([`beacon_loop`]) — emit periodic
//!    [`SignedHostBeacon`](hippius_types::host_attestor::SignedHostBeacon)s
//!    signed by the enrolled key (Ed25519 only — the SNP report is minted
//!    once, at enrollment), pushed to the host over vsock.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! The two device interactions — the derived-key fetch (establish) and
//! the report request (enrol) — MUST NOT race: `/dev/sev-guest` is a
//! single serialized, sequence-numbered channel and a bad request
//! poisons it. The agent runs them strictly sequentially on the one main
//! thread (establish fully returns, closing its transient `Firmware`
//! handle, before enrol opens a new one); nothing spawns a thread that
//! touches the device, and the beacon loop signs with Ed25519 only.
//!
//! ## Nonce (PR-10)
//!
//! The **enrollment** nonce is a fresh, single-use, **vali-minted** value
//! pulled over the miner-agent vsock challenge channel ([`challenge`] /
//! [`ChallengeNonceSource`]) — fail-closed, never a local fallback, so a
//! guest cannot pre-generate an enrollment report and replay it. The
//! periodic **beacon** nonces stay locally-random ([`OsRngNonceSource`]):
//! beacon anti-replay rests on the monotonic `seq` + hard `expiry`, not
//! the nonce (see [`nonce`]).
//!
//! ## Ships inert
//!
//! The binary is functional but is **not launched** by anything yet
//! (PR-7 wires the boot/launch path) and **not consumed** by vali yet
//! (PR-8 wires ingest) — so the feature is inert end-to-end. Off-target
//! (non-Linux/x86_64) the binary stays a deliberate placeholder.
//!
//! ## Secret discipline (§20)
//!
//! - The SNP derived key is fetched **once**, HKDF-stretched into the
//!   signer, and both live only in RAM (zeroized on drop). Only the
//!   public key crosses the wire.
//! - The derived-key provider is **fail-closed**: an error propagates,
//!   NEVER a random-key fallback.
//! - Nothing logs the derived key, the seed, the signer key, or a beacon
//!   body; errors carry only static classifiers.
//!
//! `unsafe` code is forbidden crate-wide via the workspace `[lints]`
//! (`unsafe_code = "forbid"`) — the one `unsafe` ioctl lives inside the
//! `sev` crate.

pub mod beacon_builder;
pub mod beacon_loop;
pub mod beacon_queue;
pub mod challenge;
pub mod config;
pub mod derived_key;
pub mod enroll;
pub mod error;
pub mod establish;
pub mod frame;
pub mod nonce;
pub mod platform;
pub mod reenroll;
pub mod shutdown;
pub mod signer;
pub mod snp;
pub mod vsock_pusher;

pub use beacon_builder::BeaconBuilder;
pub use beacon_loop::{run_beacon_loop, tick, unix_now, BeaconLoopConfig, TickOutcome};
pub use beacon_queue::{BeaconQueue, PushOutcome};
pub use challenge::HostChallenge;
pub use config::Config;
pub use derived_key::{
    fetch_host_attestor_derived_key, DerivedKeyProvider, HostAttestorDerivedKeyRequest,
    MockDerivedKeyProvider, SnpDerivedKey,
};
pub use enroll::{enroll, Enrolled};
pub use error::{HostAttestorError, Result};
pub use establish::{establish, Established};
pub use frame::{encode_beacon_frame, encode_enroll_frame, BEACON_KIND, ENROLL_KIND};
pub use nonce::{ChallengeNonceSource, NonceSource, OsRngNonceSource, NONCE_LEN};
pub use platform::PlatformClaims;
pub use reenroll::{
    reenroll_once, run_reenroll_loop, ChallengeSource, EnrollFrameSlot, ReenrollParams,
};
pub use shutdown::{Shutdown, ShutdownWatch};
pub use signer::{HostAttestorSigner, KEY_LEN, SIG_LEN};
pub use snp::{MockSnpReportProvider, SnpReport, SnpReportProvider};
pub use vsock_pusher::{VsockPusher, VSOCK_HOST_CID};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use derived_key::SevGuestDerivedKeyProvider;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use reenroll::spawn_reenroll_loop;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use snp::SevGuestProvider;
