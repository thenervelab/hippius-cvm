//! `hippius-agent-tenant-telemetry` — §23 telemetry agent.
//!
//! Runs **inside** the tenant SEV-SNP VM, as a systemd service started
//! after `switch_root` — separate from the initramfs agent.
//!
//! - **PR-E2.1 — key establishment.** Generate the per-VM Ed25519
//!   telemetry signer key, attest the public key via `/dev/sev-guest`
//!   with the §23 `tenant_telemetry` `REPORT_DATA` layout, obtain and
//!   verify a KBS-signed telemetry certificate, hold the key behind the
//!   [`TelemetrySigner`] trait.
//! - **PR-E2.2 — receipt loop.** On a fixed interval, build a §23
//!   [`ServedDeliveryReceipt`](hippius_types::served_receipt::ServedDeliveryReceipt),
//!   sign it with the established signer ([`TelemetrySigner::sign_served_receipt`]),
//!   and buffer it in a bounded [`ReceiptQueue`]. The loop is
//!   synchronous and signal-interruptible.
//! - **PR-E2.3 — vsock push.** A dedicated thread ([`VsockPusher`])
//!   drains the [`ReceiptQueue`] over `AF_VSOCK` to the host
//!   miner-agent, which HTTP-forwards the receipts to the Edge gateway
//!   and on to vali. The queue is shared between the receipt loop and
//!   the pusher through an `Arc<Mutex<…>>`.
//!
//! ## Secret discipline (§20/§23)
//!
//! - The signer key is **generated in the guest**, lives **only in
//!   RAM**, and never touches disk. Only the public key crosses the
//!   wire (folded into `REPORT_DATA`, certified by the KBS).
//! - A receipt is encoded + signed in one step inside the signer — a
//!   caller can never obtain or buffer an unsigned receipt.
//! - `main` runs the loop, then returns **normally** on a shutdown
//!   signal, so the signer's `Drop` (and its `Zeroize`) runs before the
//!   process exits.
//! - Nothing logs the key, a receipt body, or any derivative; errors
//!   carry only static classifiers.

pub mod challenge;
pub mod config;
pub mod error;
pub mod establish;
pub mod kbs_client;
pub mod receipt_builder;
pub mod receipt_loop;
pub mod receipt_queue;
pub mod served_work;
pub mod shutdown;
pub mod signer;
pub mod snp;
pub mod vsock_pusher;

pub use challenge::{Challenge, ChallengeSource, StaticChallengeSource};
pub use config::Config;
pub use error::{Result, TelemetryError};
pub use establish::{establish, Established};
pub use receipt_builder::ReceiptBuilder;
pub use receipt_loop::{run_receipt_loop, tick, ReceiptLoopConfig, TickOutcome};
pub use receipt_queue::{PushOutcome, ReceiptQueue};
pub use served_work::{ServedWorkSource, StaticServedWorkSource};
pub use shutdown::{Shutdown, ShutdownWatch};
pub use signer::{Ed25519TelemetrySigner, TelemetrySigner};
pub use vsock_pusher::{encode_frame, VsockPusher, VSOCK_HOST_CID};
