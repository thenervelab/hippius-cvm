//! `hippius-miner-agent` — CLI entrypoint.
//!
//! Subcommands (see [`Command`]):
//!
//! - `init-identity` — self-generate the miner's persistent Ed25519
//!   identity on first boot; idempotent (refuses to overwrite an
//!   existing key without `--force`);
//! - `image-fetch` — fetch + §22-verify a UKI from Hippius S3;
//! - `launch-test` — manually provision + launch one tenant SEV-SNP
//!   CVM via libvirt (or, with `--digest-only`, just compute the
//!   pre-flight launch digest — MA-3);
//! - `serve` — the long-running daemon (MA-4 + MA-5 + MA-6): the
//!   AF_VSOCK guest relay, the signed-order HTTP server, and the §K
//!   signed-heartbeat subsystem, with an ordered graceful shutdown.
//!
//! The miner is untrusted: it never authenticates to the Vault and
//! never speaks to the KBS — only the tenant guest VMs do.
//! `launch-test` drives the **local** libvirt host. The §K heartbeat
//! (MA-6) is the miner-agent's first real outward surface — it relays
//! a signed liveness envelope to the Edge over mTLS; the legacy
//! `EdgeClient::send_envelope` skeleton (used by the vsock relay)
//! stays `not-yet-wired`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use hippius_image_provenance::store::HippiusS3ImageStore;
use hippius_miner_agent::orders::{IdempotencyStore, OrderState, OrderVerifier, OrdersServer};
use hippius_miner_agent::vsock::MIN_GUEST_CID;
use hippius_miner_agent::{
    compute_launch_digest, load_cmdline, run_builder, run_pusher, Config, CvmLifecycle, DomainUuid,
    EdgeClient, HeartbeatBuilder, HeartbeatClient, HeartbeatQueue, HostResources, ImageCache,
    LaunchOrder, MetricsSource, MinerAgentError, MinerIdentity, ProcMetricsSource, QemuConfig,
    ReqwestHeartbeatClient, Result, SequenceStore, SevLaunchDigest, VirshDriver, VmId,
};

/// Graceful-shutdown grace for the orders HTTP server — in-flight
/// requests get this long to drain after the shutdown signal.
const ORDERS_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Graceful-shutdown grace for the detached order-dispatch tasks — a
/// launch/stop/destroy whose HTTP client already disconnected gets
/// this long to run to completion before `shutdown_all`. A launch
/// still polling libvirt past this grace is left to the runtime; the
/// `stop` phase gate keeps `shutdown_all` from corrupting it.
const DISPATCH_DRAIN_GRACE: Duration = Duration::from_secs(15);

/// Graceful-shutdown grace for the AF_VSOCK relay — in-flight guest
/// relays get this long to disconnect cleanly. Linux-only: the relay
/// listener itself is `cfg(target_os = "linux")`.
#[cfg(target_os = "linux")]
const VSOCK_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Graceful-shutdown grace for the §K heartbeat pusher — its final
/// best-effort queue drain gets this long before shutdown moves on, so
/// an unreachable Edge cannot stall process exit.
const HEARTBEAT_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// Exit code for any fail-closed error path.
const EXIT_FAIL: u8 = 2;

#[derive(Parser)]
#[command(
    name = "hippius-miner-agent",
    version,
    about = "Hippius miner-agent — untrusted-host miner daemon (identity self-gen + UKI image fetch)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the miner's persistent Ed25519 identity (first boot
    /// only). Idempotent: a second run is a no-op unless `--force`.
    InitIdentity {
        /// Secret key output path (written 0400).
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.key")]
        key_output: PathBuf,
        /// Public key output path (written 0444).
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.pub")]
        pub_output: PathBuf,
        /// Print the public key (hex) to stdout for operator
        /// registration with vali.
        #[arg(long)]
        print_pubkey: bool,
        /// Regenerate even if an identity already exists. DESTRUCTIVE
        /// — the previous miner identity is irrecoverably replaced.
        #[arg(long)]
        force: bool,
    },
    /// Fetch + §22-verify a UKI image from Hippius S3 (delegates to
    /// the miner-uki-fetch library).
    ImageFetch {
        /// SHA-256 of the UKI to fetch (64 hex chars).
        #[arg(long)]
        hash: String,
        /// Content-addressed local image cache directory.
        #[arg(long, default_value = "/var/lib/hippius-miner/images")]
        cache_dir: PathBuf,
        /// Directory the verified image is installed into.
        #[arg(long, default_value = "/var/lib/hippius-miner/staging")]
        output: PathBuf,
        /// Hippius S3 endpoint.
        #[arg(long, default_value = "https://s3.hippius.com")]
        s3_endpoint: String,
        /// Hippius S3 bucket holding the published UKIs.
        #[arg(long, default_value = "hippius-compute-images")]
        s3_bucket: String,
    },
    /// Provision + launch one tenant SEV-SNP CVM via libvirt (MA-3),
    /// or — with `--digest-only` — just compute the pre-flight launch
    /// digest. A manual validation tool; the real order-intake loop
    /// is MA-5.
    LaunchTest(LaunchTestArgs),
    /// Sign an on-chain `register_child` node-authorisation for this
    /// miner's identity (§23 `pallet-compute-scoring`). Loads the
    /// persistent identity and emits the Ed25519 `node_sig` (hex) the
    /// **family** account submits with `register_child(family, child,
    /// node_id, node_sig)`. The node_id is this identity's public key.
    /// Output is one JSON object on stdout for the register-miner
    /// submitter (`deploy/register-miner/`). Signs only — never
    /// touches the chain (the agent holds no funds / family key).
    SignRegistration {
        /// Secret identity key (the same file `init-identity` wrote).
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.key")]
        key_path: PathBuf,
        /// Public identity key path.
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.pub")]
        pub_path: PathBuf,
        /// Family account (the on-chain owner submitting
        /// `register_child`) — 32-byte AccountId as `0x`-hex.
        #[arg(long)]
        family: String,
        /// Child account being registered — 32-byte AccountId as
        /// `0x`-hex.
        #[arg(long)]
        child: String,
        /// `NodeIdNonce` for this node_id on-chain (0 for a first
        /// registration; bump on re-registration after a cooldown).
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
    /// Print this host's SEV-SNP CPU-unique CHIP_ID (the 64-byte AMD
    /// platform identifier) as lowercase hex. This is the `platform_id`
    /// the operator registers in vali's `MinerIdentity` AND the value a
    /// launch ticket pins to bind the miner's VCEK for §21 attestation —
    /// reading it from the hardware (host `/dev/sev` GET_ID) instead of
    /// hand-typing a label removes the placeholder-CHIP_ID class of bug.
    /// Requires a real SEV-SNP host + a `--features snp` build.
    PlatformId,
    /// Self-request a graceful exit: sign a `GracefulExitRequest` with
    /// this miner's identity key and POST it to the **Edge gateway** over
    /// mTLS (exactly like a heartbeat), which relays it to vali. vali —
    /// after verifying the signature against the registered key —
    /// quarantines the miner so its tenant VMs are warm-migrated off
    /// before it stops. The Ed25519 signature is the credential; a real
    /// miner box cannot reach vali directly, so the transport is the
    /// already-provisioned Edge mTLS leg (the same `[edge]` material the
    /// heartbeat pusher uses).
    RequestGracefulExit {
        /// Secret identity key (the same file `init-identity` wrote).
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.key")]
        key_path: PathBuf,
        /// Public identity key path.
        #[arg(long, default_value = "/var/lib/hippius-miner/identity.pub")]
        pub_path: PathBuf,
        /// This miner's registry id — MUST match vali's
        /// `MinerIdentity.miner_id` (the key under which its public key
        /// is registered).
        #[arg(long)]
        miner_id: String,
        /// Edge gateway base URL, e.g. `https://edge.hippius.network:443`
        /// (the same endpoint the `[edge]` heartbeat config targets).
        #[arg(long)]
        edge_url: String,
        /// CA cert (PEM) pinning the Edge server — the same
        /// `[edge].ca_cert` the heartbeat pusher uses.
        #[arg(long, default_value = "/var/lib/hippius-miner/edge-ca.crt")]
        ca_cert: PathBuf,
        /// Optional operator-issued client cert (PEM). Omit (the prod
        /// default) to mTLS with a self-signed cert minted from the
        /// identity key. Must be set together with `--client-key`.
        #[arg(long)]
        client_cert: Option<PathBuf>,
        /// Optional operator-issued client key (PEM); see `--client-cert`.
        #[arg(long)]
        client_key: Option<PathBuf>,
        /// Monotonic replay-defence counter; bump on a re-request.
        #[arg(long, default_value_t = 1)]
        sequence: u64,
    },
    /// Emit ONE `v2` graceful-exit heartbeat (transport (B)). Samples the
    /// SAME live host metrics + CVM counts the periodic heartbeat does,
    /// draws the next monotonic `sequence` from the daemon's on-disk
    /// counter, builds a `schema_version=2` heartbeat with
    /// `graceful_exit_requested=true`, and POSTs it ONCE over the existing
    /// Edge mTLS heartbeat transport (`/v1/edge/heartbeat`). vali accepts
    /// the heartbeat (the miner is alive) AND quarantines it so the
    /// §13/§25 auto-migration warm-migrates its VMs off.
    ///
    /// This is the always-on passive COMPLEMENT to `request-graceful-exit`
    /// (the active `SignedGracefulExit` request): both quarantine the
    /// miner; the flag rides the liveness channel so a graceful exit is
    /// signalled even if the dedicated request path is unavailable. It
    /// reuses the daemon `--config` so the `[edge]` transport + the
    /// `[heartbeat].sequence_path` counter are IDENTICAL to the serve
    /// loop's — the sequence stays monotone across both.
    GracefulExitHeartbeat {
        /// Operator config file — the SAME one `serve` reads, so the
        /// Edge transport + the monotonic sequence counter line up.
        #[arg(long, default_value = "/etc/hippius-miner/config.toml")]
        config: PathBuf,
    },
    /// Long-running daemon (MA-4 + MA-5 + MA-6). Loads + validates the
    /// config and identity, then hosts the AF_VSOCK guest relay, the
    /// signed-order HTTP server and the §K signed-heartbeat subsystem
    /// until SIGTERM/SIGINT, with an ordered graceful shutdown.
    Serve {
        /// Operator config file.
        #[arg(long, default_value = "/etc/hippius-miner/config.toml")]
        config: PathBuf,
    },
}

/// Arguments for the `launch-test` subcommand.
///
/// The launch components are passed separately (Option A, PR-MA-3):
/// the pinned OVMF firmware plus the kernel / initrd / cmdline — the
/// exact tuple the SEV-SNP launch digest is measured over.
#[derive(Args)]
struct LaunchTestArgs {
    /// Pinned, SEV-SNP-capable OVMF firmware.
    #[arg(long)]
    ovmf: PathBuf,
    /// Guest kernel image.
    #[arg(long)]
    kernel: PathBuf,
    /// Guest initrd archive.
    #[arg(long)]
    initrd: PathBuf,
    /// File holding the guest kernel command line.
    #[arg(long)]
    cmdline: PathBuf,
    /// Tenant VM id (`[a-z0-9-]`; used in the libvirt domain name).
    #[arg(long, default_value = "test-cvm-1")]
    vm_id: String,
    /// LUKS data disk image (created blank if absent).
    #[arg(long, default_value = "/var/lib/hippius-miner/luks-test.img")]
    disk: PathBuf,
    /// Data disk size in GiB.
    #[arg(long, default_value_t = 10)]
    disk_size: u32,
    /// #365 — tenant data disk size in GiB, attached at `/dev/vde` for
    /// the guest to format fresh at first boot. 0 (default) attaches
    /// none, preserving the legacy single-disk `launch-test` behaviour.
    #[arg(long, default_value_t = 0)]
    data_disk_size: u32,
    /// Read-only dm-verity rootfs data image (squashfs from the §F
    /// tenant-uki build). Attached at `/dev/vdb` in the guest.
    #[arg(long, default_value = "/var/lib/hippius-miner/rootfs.img")]
    rootfs_data: PathBuf,
    /// Read-only dm-verity rootfs hash tree (`rootfs.verity` from the
    /// §F tenant-uki build). Attached at `/dev/vdc` in the guest.
    #[arg(long, default_value = "/var/lib/hippius-miner/rootfs.verity")]
    rootfs_hash: PathBuf,
    /// vCPUs for the CVM. Defaults to 1 — the vCPU count is folded
    /// into the SEV-SNP launch digest, and the §F allowlist is pinned
    /// at 1 vCPU, so `--digest-only` matches the allowlist by default.
    #[arg(long, default_value_t = 1)]
    cpus: u8,
    /// Guest RAM in MiB.
    #[arg(long, default_value_t = 2048)]
    memory: u32,
    /// Host vCPU budget for resource accounting.
    #[arg(long, default_value_t = 8)]
    host_cpus: u32,
    /// Host RAM budget (MiB) for resource accounting.
    #[arg(long, default_value_t = 16384)]
    host_memory_mb: u64,
    /// Declared tenant data-disk budget in GiB (0 = disk reservation off).
    #[arg(long, default_value_t = 0)]
    host_disk_gb: u64,
    /// Only compute + print the pre-flight launch digest; do not
    /// launch. For known-answer validation against the §F allowlist.
    #[arg(long)]
    digest_only: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `MinerAgentError`'s Display is a fixed classifier — no
            // path, no key byte, no run-time value is echoed here.
            eprintln!("hippius-miner-agent: error: {e}");
            ExitCode::from(EXIT_FAIL)
        }
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::InitIdentity {
            key_output,
            pub_output,
            print_pubkey,
            force,
        } => cmd_init_identity(&key_output, &pub_output, print_pubkey, force),
        Command::ImageFetch {
            hash,
            cache_dir,
            output,
            s3_endpoint,
            s3_bucket,
        } => cmd_image_fetch(&hash, cache_dir, &output, &s3_endpoint, &s3_bucket),
        Command::LaunchTest(args) => cmd_launch_test(args),
        Command::SignRegistration {
            key_path,
            pub_path,
            family,
            child,
            nonce,
        } => cmd_sign_registration(&key_path, &pub_path, &family, &child, nonce),
        Command::PlatformId => cmd_platform_id(),
        Command::RequestGracefulExit {
            key_path,
            pub_path,
            miner_id,
            edge_url,
            ca_cert,
            client_cert,
            client_key,
            sequence,
        } => cmd_request_graceful_exit(
            &key_path,
            &pub_path,
            &miner_id,
            &edge_url,
            &ca_cert,
            client_cert.as_deref(),
            client_key.as_deref(),
            sequence,
        ),
        Command::GracefulExitHeartbeat { config } => cmd_graceful_exit_heartbeat(&config),
        Command::Serve { config } => cmd_serve(&config),
    }
}

/// Print the host SEV-SNP CHIP_ID (64-byte AMD platform identifier) as
/// lowercase hex — the `platform_id` for vali registration + the launch
/// ticket's VCEK binding. Reads `/dev/sev` GET_ID via the `sev` crate;
/// only meaningful on a real SEV-SNP host built with `--features snp`.
#[cfg(all(target_os = "linux", feature = "snp"))]
fn cmd_platform_id() -> Result<()> {
    use sev::firmware::host::Firmware;
    let mut fw = Firmware::open().map_err(|_| MinerAgentError::SnpProbe("sev-open-failed"))?;
    let id = fw
        .get_identifier()
        .map_err(|_| MinerAgentError::SnpProbe("get-id-failed"))?;
    // Lowercase hex — matches the AMD KDS chip_id URL convention + the
    // value vali stores in `MinerIdentity.platform_id`. (The `sev`
    // crate's `Display` is UPPERCASE, so format the bytes here.)
    let hex: String = Vec::from(id).iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
    Ok(())
}

/// Fallback for non-Linux / non-`snp` builds: the GET_ID ioctl needs the
/// host SEV device + the `sev`/`snp` feature, so a build without them
/// cannot answer — fail loudly rather than print a wrong value.
#[cfg(not(all(target_os = "linux", feature = "snp")))]
fn cmd_platform_id() -> Result<()> {
    Err(MinerAgentError::SnpProbe("snp-feature-disabled"))
}

/// `request-graceful-exit` — sign a `GracefulExitRequest` with this
/// miner's identity key and POST the canonical `SignedGracefulExit` to
/// the **Edge gateway** `/v1/edge/graceful-exit` route over mTLS (exactly
/// like a heartbeat). The Edge relays it opaquely to vali, which verifies
/// the signature against the registered key (resolved from the Edge-
/// stamped mTLS peer identity), then quarantines the miner so the §13/§25
/// auto-migration warm-migrates its VMs off. The body + signing are
/// unchanged from the direct-to-vali path; only the transport differs —
/// a real miner box cannot reach vali directly, but it reaches the Edge
/// over the already-provisioned mTLS leg. Signs + sends only.
#[allow(clippy::too_many_arguments)]
fn cmd_request_graceful_exit(
    key_path: &Path,
    pub_path: &Path,
    miner_id: &str,
    edge_url: &str,
    ca_cert: &Path,
    client_cert: Option<&Path>,
    client_key: Option<&Path>,
    sequence: u64,
) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use hippius_miner_agent::build_edge_mtls_client;
    use hippius_miner_agent::config::EdgeSection;
    use hippius_miner_agent::EnvelopeKind;
    use hippius_types::graceful_exit::{
        GracefulExitRequest, SignedGracefulExit, DOMAIN, SCHEMA_VERSION,
    };

    let identity = MinerIdentity::load(key_path, pub_path)?;
    // A real binary on real hardware — wall-clock is the signed
    // `timestamp_unix` vali anti-skew-checks (±300 s).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let request = GracefulExitRequest {
        schema_version: SCHEMA_VERSION,
        miner_id: miner_id.to_string(),
        timestamp_unix: now,
        sequence,
        domain: DOMAIN.to_string(),
    };
    let body = request
        .canonical()
        .map_err(|_| MinerAgentError::GracefulExit("encode"))?;
    let sig = identity.sign(&body);
    let envelope = SignedGracefulExit {
        body,
        sig: sig.to_bytes().to_vec(),
    }
    .canonical()
    .map_err(|_| MinerAgentError::GracefulExit("encode"))?;

    // Reuse the SAME mTLS client builder the heartbeat pusher uses — the
    // CLI args map onto the `[edge]` config shape (endpoint + CA + the
    // optional operator-issued client cert/key, else the self-signed
    // identity cert). The miner never reaches vali directly; the Edge is
    // the transport.
    let edge = EdgeSection {
        endpoint: edge_url.to_string(),
        client_cert: client_cert.map(Path::to_path_buf),
        client_key: client_key.map(Path::to_path_buf),
        ca_cert: ca_cert.to_path_buf(),
        // Unused for this one-shot transport — `order_signing_pubkey`
        // only gates inbound lifecycle orders (MA-5), never an outbound
        // POST. A placeholder keeps the struct buildable here.
        order_signing_pubkey: String::new(),
    };
    let client = build_edge_mtls_client(&edge, &identity)?;
    let url = format!(
        "{}{}",
        edge_url.trim_end_matches('/'),
        EnvelopeKind::GracefulExit.edge_route(),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| MinerAgentError::GracefulExit("runtime"))?;
    runtime.block_on(async move {
        let resp = client
            .post(&url)
            .header("content-type", "application/cbor")
            .body(envelope)
            .send()
            .await
            .map_err(|_| MinerAgentError::GracefulExit("client"))?;
        if !resp.status().is_success() {
            eprintln!(
                "hippius-miner-agent: request-graceful-exit: edge returned HTTP {}",
                resp.status().as_u16(),
            );
            return Err(MinerAgentError::GracefulExit("rejected"));
        }
        Ok::<(), MinerAgentError>(())
    })?;

    println!("graceful-exit requested via edge: miner_id={miner_id} sequence={sequence}");
    Ok(())
}

/// `graceful-exit-heartbeat` — emit ONE `v2` graceful-exit heartbeat
/// (transport (B)) over the existing Edge mTLS heartbeat transport.
///
/// Wires the SAME components the §K heartbeat subsystem uses — the
/// `ProcMetricsSource`, the `CvmLifecycle` (for live VM counts), the
/// on-disk monotonic `SequenceStore`, and the mTLS `ReqwestHeartbeatClient`
/// targeting `/v1/edge/heartbeat` — but builds a single `schema_version=2`
/// heartbeat with `graceful_exit_requested=true` via
/// [`HeartbeatBuilder::build_graceful_exit`] and POSTs it ONCE. Reusing
/// the daemon `--config` means the sequence counter is the SAME file the
/// serve loop bumps, so this heartbeat's sequence stays monotone and vali
/// does not reject it as a replay.
///
/// Fail-closed: a non-2xx Edge response or any transport error is an
/// error exit, so an operator scripting a drain learns the signal did
/// NOT land (and can fall back to `request-graceful-exit`).
fn cmd_graceful_exit_heartbeat(config_path: &Path) -> Result<()> {
    use std::sync::Arc;

    use hippius_miner_agent::heartbeat::PushOutcome;

    let config = Config::load(config_path)?;
    let identity = Arc::new(MinerIdentity::load(
        &config.identity.key_path,
        &config.identity.pub_path,
    )?);

    // The CVM lifecycle supplies the live VM counts — same construction
    // as the serve loop (host budget from `[host]`, storage roots from
    // `[storage]`). `list()` is read-only, so this never touches a CVM.
    let lifecycle = Arc::new(
        CvmLifecycle::new(
            Arc::new(VirshDriver::default()),
            Arc::new(SevLaunchDigest),
            HostResources {
                total_cpus: config.host.cvm_cpu_budget,
                total_memory_mb: config.host.cvm_memory_mb_budget,
                total_disk_gb: config.host.cvm_disk_gb_budget,
            },
        )
        .with_storage_roots(
            config.storage.data_disk_root.clone(),
            config.storage.state_disk_root.clone(),
        ),
    );

    let metrics: Arc<dyn MetricsSource> = Arc::new(ProcMetricsSource);
    let builder = HeartbeatBuilder::new(
        config.miner.miner_id.clone(),
        Arc::clone(&identity),
        Arc::clone(&lifecycle),
        metrics,
    );
    // The SAME on-disk counter the serve loop uses — so this one-shot
    // heartbeat's sequence is strictly greater than the last periodic
    // one and vali accepts it.
    let mut seq = SequenceStore::open(&config.heartbeat.sequence_path)?;
    // Build the mTLS client up front (boot-fatal on a misconfigured edge),
    // mirroring the serve loop's heartbeat client.
    let client = ReqwestHeartbeatClient::new(&config.edge, &identity)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| MinerAgentError::GracefulExit("runtime"))?;
    runtime.block_on(async move {
        let signed = builder.build_graceful_exit(&mut seq).await?;
        match client.push(&signed).await {
            PushOutcome::Delivered => Ok(()),
            PushOutcome::Rejected => {
                eprintln!(
                    "hippius-miner-agent: graceful-exit-heartbeat: edge rejected the heartbeat"
                );
                Err(MinerAgentError::GracefulExit("rejected"))
            }
            PushOutcome::Transport => {
                eprintln!("hippius-miner-agent: graceful-exit-heartbeat: edge transport failure");
                Err(MinerAgentError::GracefulExit("client"))
            }
        }
    })?;

    println!(
        "graceful-exit heartbeat delivered via edge: miner_id={}",
        config.miner.miner_id
    );
    Ok(())
}

/// Parse a 32-byte AccountId from `0x`-prefixed (or bare) hex.
fn parse_account32(s: &str, which: &'static str) -> Result<[u8; 32]> {
    let trimmed = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(trimmed).map_err(|_| MinerAgentError::RegistrationArg(which))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| MinerAgentError::RegistrationArg(which))?;
    Ok(arr)
}

/// `sign-registration` — sign a §23 `register_child` authorisation.
fn cmd_sign_registration(
    key_path: &Path,
    pub_path: &Path,
    family: &str,
    child: &str,
    nonce: u64,
) -> Result<()> {
    let identity = MinerIdentity::load(key_path, pub_path)?;
    let family = parse_account32(family, "family")?;
    let child = parse_account32(child, "child")?;
    let sig = identity.sign_registration(&family, &child, nonce);
    // One JSON object on stdout for the register-miner submitter. Only
    // public values (node_id, the detached signature, the nonce) — no
    // secret ever crosses this boundary (§20).
    println!(
        "{{\"node_id\":\"{}\",\"node_sig\":\"{}\",\"nonce\":{}}}",
        identity.pubkey_hex(),
        hex::encode(sig.to_bytes()),
        nonce
    );
    Ok(())
}

/// `init-identity` — self-generate + persist the miner identity.
fn cmd_init_identity(
    key_output: &Path,
    pub_output: &Path,
    print_pubkey: bool,
    force: bool,
) -> Result<()> {
    if MinerIdentity::key_present(key_output) && !force {
        // Idempotent no-op — never silently overwrite a live identity.
        eprintln!(
            "hippius-miner-agent: identity already present at {key_output:?} \
             — no-op (pass --force to regenerate, which is DESTRUCTIVE)"
        );
        if print_pubkey {
            // Re-print the existing public key so the operator can
            // still capture it for registration.
            let existing = MinerIdentity::load(key_output, pub_output)?;
            println!("{}", existing.pubkey_hex());
        }
        return Ok(());
    }

    let identity = MinerIdentity::generate()?;
    identity.persist(key_output, pub_output)?;
    eprintln!(
        "hippius-miner-agent: identity generated — key {key_output:?} (0400), \
         pub {pub_output:?} (0444). Register the public key below with vali."
    );
    if print_pubkey {
        println!("{}", identity.pubkey_hex());
    }
    Ok(())
}

/// `image-fetch` — fetch + §22-verify a UKI.
fn cmd_image_fetch(
    hash: &str,
    cache_dir: PathBuf,
    output: &Path,
    s3_endpoint: &str,
    s3_bucket: &str,
) -> Result<()> {
    let store = HippiusS3ImageStore::new(s3_bucket.to_string(), s3_endpoint.to_string())?;
    let cache = ImageCache::new(Box::new(store), cache_dir)?;
    let (outcome, path) = cache.fetch_verified(hash, output)?;
    eprintln!("hippius-miner-agent: image {outcome:?} — installed {path:?}");
    Ok(())
}

/// `serve` — the long-running miner-agent daemon (MA-4 + MA-5).
///
/// Loads the config + identity, wires the CVM lifecycle, and hosts
/// the subsystems for the process lifetime: the AF_VSOCK guest relay
/// (MA-4, Linux only), the signed-order HTTP server (MA-5), and the §K
/// heartbeat subsystem (MA-6 — a signed-heartbeat builder + an mTLS
/// pusher). Parks on SIGTERM/SIGINT, then shuts down in a fixed
/// order — see [`serve`].
fn cmd_serve(config_path: &Path) -> Result<()> {
    // Fail-fast: a serve binary built WITHOUT `--features snp` cannot
    // compute the pre-flight SEV-SNP launch digest and therefore
    // cannot honour ANY tenant launch order — every dispatch would
    // fail closed at `cvm-launch-digest/feature-disabled` (HTTP 422
    // `launch-input`). Observed live 2026-05-28: a `cargo build`
    // omitting `--features snp` produced a binary that silently
    // started + heartbeated but rejected every order at dispatch
    // time, so the operator had no clue from systemd that the deploy
    // was unusable. Refuse to start.
    //
    // `cfg!()` evaluates at compile time → the optimizer drops the
    // dead arm; the surviving branch is the one matching the build's
    // feature set. Both branches still need to type-check, so
    // everything below stays compilable under both configs.
    if !cfg!(feature = "snp") {
        return Err(MinerAgentError::LaunchInput("snp-feature-disabled"));
    }

    let config = Config::load(config_path)?;
    // The identity must already exist — fail closed pointing the
    // operator at `init-identity` (the error classifier is
    // `identity-missing`).
    let identity = MinerIdentity::load(&config.identity.key_path, &config.identity.pub_path)?;

    // The serve loop hosts several async subsystems; a current-thread
    // runtime is enough — the agent is not a high-RPS server.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config, identity))
}

/// The async serve loop — wire the subsystems, run until a shutdown
/// signal, then drain.
///
/// ## Shutdown ordering
///
/// A single [`CancellationToken`] fans the shutdown out. On the signal
/// the order is deliberate: **(1)** the vsock relay drains — guest
/// connections close cleanly; **(2)** the orders HTTP server drains —
/// in-flight handlers finish, no new order is accepted; **(2b)** the
/// detached order-dispatch tasks drain — a launch/stop/destroy whose
/// HTTP client already disconnected still completes; **(3)** only then
/// does `shutdown_all` gracefully stop every CVM. Draining the order
/// intake AND every in-flight dispatch before stopping the CVMs means
/// no order can race the teardown.
async fn serve(config: Config, identity: MinerIdentity) -> Result<()> {
    let pubkey = identity.pubkey_hex();
    // Shared — the skeleton Edge client and the §K heartbeat builder
    // both sign with the miner identity.
    let identity = Arc::new(identity);
    // The Edge client is consumed only by the AF_VSOCK relay, which is
    // Linux-only — so on a non-Linux dev build it is unused.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let edge = Arc::new(EdgeClient::connect(&config.edge, &identity)?);
    // Wired for the config→component path; the launch-order image
    // resolution that consumes it is a follow-up.
    let store = HippiusS3ImageStore::new(
        config.image.s3_bucket.clone(),
        config.image.s3_endpoint.clone(),
    )?;
    let _image_cache = ImageCache::new(Box::new(store), config.image.cache_dir.clone())?;

    // Display-only guest-boot progress sink (§K) — signs each milestone
    // with the miner identity and POSTs it to vali over the SAME Edge
    // mTLS leg the heartbeat uses. Built ONCE and shared: the lifecycle
    // fires `booting` when a tenant domain starts, and the kbs-proxy
    // fires `kek-released` on a successful KBS release, so a single
    // identity signs the whole `booting → kek-released → running`
    // sequence. Fail-open: a build failure (bad mTLS material) leaves the
    // sink OFF (no reporting); it is NEVER serve-fatal and NEVER touches
    // the launch or release path.
    let progress: Option<Arc<dyn hippius_miner_agent::vsock::VmProgressSink>> =
        match hippius_miner_agent::vsock::EdgeVmProgressSink::new(
            &config.edge,
            Arc::clone(&identity),
            config.miner.miner_id.clone(),
        ) {
            Ok(sink) => Some(Arc::new(sink) as Arc<dyn hippius_miner_agent::vsock::VmProgressSink>),
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: serve — vm-progress sink disabled (build failed: {err}); boot progress will not be reported"
                );
                None
            }
        };

    // The CVM lifecycle, accounted against the operator-declared host
    // budget (`[host]` config). Per-VM data/state disk roots come from
    // `[storage]` (default `/var/lib/hippius-miner`) so tenant data can
    // live on a dedicated mount without a code change.
    let lifecycle = Arc::new(
        CvmLifecycle::new(
            Arc::new(VirshDriver::default()),
            Arc::new(SevLaunchDigest),
            HostResources {
                total_cpus: config.host.cvm_cpu_budget,
                total_memory_mb: config.host.cvm_memory_mb_budget,
                total_disk_gb: config.host.cvm_disk_gb_budget,
            },
        )
        .with_storage_roots(
            config.storage.data_disk_root.clone(),
            config.storage.state_disk_root.clone(),
        )
        .with_progress_sink(progress.clone()),
    );

    // Re-adopt any tenant CVMs that survived a prior agent lifetime
    // (`[host].skip_shutdown_teardown` leaves them running across a
    // restart). MUST run before the orders server + reboot-watcher come
    // up so the handle-map, capacity accounting, CID allocator + vsock
    // relay all know about the survivors — otherwise a new launch could
    // over-commit or collide their CID, and their billing relay stops.
    match lifecycle.readopt_running().await {
        Ok(0) => {}
        Ok(n) => eprintln!("hippius-miner-agent: serve — re-adopted {n} running tenant CVM(s)"),
        Err(err) => eprintln!("hippius-miner-agent: serve — re-adopt sweep failed: {err}"),
    }

    // The orders subsystem — verifier (the pinned Edge order key),
    // idempotency store, shared state. The `TaskTracker` collects the
    // detached order-dispatch tasks so this loop can drain them at
    // shutdown rather than the runtime cancelling one mid-launch.
    let verifier = Arc::new(OrderVerifier::from_hex(&config.edge.order_signing_pubkey)?);
    let idem = Arc::new(IdempotencyStore::new());
    let dispatch_tasks = TaskTracker::new();
    // `self_miner_id` + `clock` close the gemini-r1 High findings:
    // every order body MUST name this host (target binding) AND fall
    // within ±MAX_ORDER_AGE_SECS of this clock (freshness window).
    let clock: Arc<dyn hippius_miner_agent::orders::Clock> =
        Arc::new(hippius_miner_agent::orders::SystemClock);
    // Production ticket pusher — real AF_VSOCK push to the assigned
    // guest CID after `lifecycle.launch` Ok. The integration tests
    // inject a `MockTicketPusher` in their fixtures.
    let ticket_pusher: Arc<dyn hippius_miner_agent::vsock::ticket_push::TicketPusher> =
        Arc::new(hippius_miner_agent::vsock::ticket_push::VsockTicketPusher::new());
    // §25 migration M1 — the source-side quiesce + snapshot state map
    // and the production streaming S3 uploader. A failure building the
    // uploader's `reqwest` client is boot-fatal (a miner that cannot
    // upload a snapshot must not silently advertise migration support).
    let migration = Arc::new(hippius_miner_agent::orders::MigrationStore::new());
    let uploader: Arc<dyn hippius_miner_agent::orders::SnapshotUploader> =
        Arc::new(hippius_miner_agent::orders::ReqwestSnapshotUploader::new()?);
    // §25 migration M2 — the dest-side snapshot downloader (streams the
    // encrypted LUKS volume DOWN from a presigned S3 GET on a
    // `migrate-activate`). Same boot-fatal rationale as the uploader.
    let downloader: Arc<dyn hippius_miner_agent::orders::SnapshotDownloader> =
        Arc::new(hippius_miner_agent::orders::ReqwestSnapshotDownloader::new()?);
    // §25 — the source ack signer. Production wires the COLD-migration
    // EOL shutdown-sign producer (`EolShutdownAckSigner`): the source guest
    // signs its `stopped{}` ack from its baked cmdline during the clean
    // shutdown the quiesce drives. It is fail-closed (returns no ack) until
    // the shutdown-hook bake ships: vali then fences, times out, quarantines
    // the source, and never activates the dest. See `EolShutdownAckSigner`.
    let ack_signer: Arc<dyn hippius_miner_agent::orders::GuestStoppedAckSigner> =
        Arc::new(hippius_miner_agent::orders::EolShutdownAckSigner::new());
    let state = OrderState::new(
        Arc::clone(&lifecycle),
        verifier,
        idem,
        config.miner.miner_id.clone(),
        clock,
        Arc::clone(&ticket_pusher),
        Arc::clone(&migration),
        uploader,
        downloader,
        ack_signer,
        dispatch_tasks.clone(),
    );

    // Bind the orders HTTP server. `Config::validate` already proved
    // `bind_addr` is a NetBird-mesh address; a bind failure here is a
    // host-level fault (address not present, port busy).
    let bind_addr: SocketAddr = config
        .orders
        .bind_addr
        .parse()
        .map_err(|_| MinerAgentError::ConfigInvalid("orders.bind_addr"))?;
    let orders = OrdersServer::bind(bind_addr)
        .await
        .map_err(|_| MinerAgentError::ConfigInvalid("orders.bind_addr"))?;
    let orders_addr = orders.local_addr();

    // One token, fanned out to every subsystem.
    let cancel = CancellationToken::new();

    let orders_task = tokio::spawn(orders.serve(state, cancel.clone()));

    // The §K heartbeat subsystem (PR-MA-6): a builder task that signs
    // one `MinerHeartbeat` every `interval_secs` onto a bounded queue,
    // and a pusher task that relays that queue to the Edge gateway's
    // `/v1/edge/heartbeat` route over mTLS. The `sequence` counter is
    // persisted to disk (`SequenceStore`) so it stays monotone across
    // a restart — vali rejects a regressed sequence as a replay. A
    // failure building the mTLS client or opening the counter file is
    // boot-fatal: a miner that cannot heartbeat must not silently run.
    let heartbeat_seq = SequenceStore::open(&config.heartbeat.sequence_path)?;
    let heartbeat_queue = Arc::new(HeartbeatQueue::new(config.heartbeat.max_pending));
    let metrics: Arc<dyn MetricsSource> = Arc::new(ProcMetricsSource);
    let heartbeat_builder = Arc::new(HeartbeatBuilder::new(
        config.miner.miner_id.clone(),
        Arc::clone(&identity),
        Arc::clone(&lifecycle),
        metrics,
    ));
    let heartbeat_client: Arc<dyn HeartbeatClient> =
        Arc::new(ReqwestHeartbeatClient::new(&config.edge, &identity)?);
    let heartbeat_build_task = tokio::spawn(run_builder(
        heartbeat_builder,
        Arc::clone(&heartbeat_queue),
        heartbeat_seq,
        Duration::from_secs(config.heartbeat.interval_secs),
        cancel.clone(),
    ));
    let heartbeat_push_task = tokio::spawn(run_pusher(
        heartbeat_queue,
        heartbeat_client,
        cancel.clone(),
    ));

    // The AF_VSOCK relay is Linux-only — `tokio-vsock` is target-gated.
    #[cfg(target_os = "linux")]
    let vsock_task = tokio::spawn(hippius_miner_agent::vsock::run_vsock_listener(
        lifecycle.cid_allocator(),
        Arc::clone(&edge),
        cancel.clone(),
    ));

    // The KBS-over-vsock proxy (Linux-only). When `[kbs].endpoint` is
    // configured, tenant guests relay their §21 release exchange
    // through the agent over AF_VSOCK instead of reaching the KBS over
    // the network (the robust permissionless path — the guest needs no
    // route/DNS/mesh). Absent ⇒ guests use a network `hippius.kbs_url`.
    //
    // The SAME proxy ALSO carries the §24/§25 guest stopped-ack push
    // (`/v1/lifecycle/stopped`) when `[lifecycle]` is configured: the
    // confidential guest has no IP route to vali either, so its signed
    // ack rides this vsock channel and the agent forwards the OPAQUE
    // bytes (plus the `?vm_id=&generation=` query) to vali's ingress.
    // The agent never decodes/forges the ack — vali's verifier is the
    // §25 split-brain fence (§5.6 opacity).
    #[cfg(target_os = "linux")]
    let kbs_proxy_task = match &config.kbs {
        Some(kbs) => {
            // When `[kbs].ca_cert` is set, trust it on top of the webpki
            // roots — the KBS is an INTERNAL mesh service that may serve a
            // private-CA / pinned cert (dialed by its DNS/IP SAN) instead
            // of a public ACME cert. Absent ⇒ webpki built-ins only.
            // Mirrors the `[lifecycle]` hop below.
            let kbs_backend = Arc::new(match &kbs.ca_cert {
                Some(ca) => hippius_miner_agent::vsock::ReqwestKbsBackend::new_with_ca(
                    kbs.endpoint.clone(),
                    ca,
                    "kbs.ca_cert",
                )?,
                None => hippius_miner_agent::vsock::ReqwestKbsBackend::new_for(
                    kbs.endpoint.clone(),
                    "kbs.endpoint",
                )?,
            }) as Arc<dyn hippius_miner_agent::vsock::KbsBackend>;
            // The vali lifecycle backend is opt-in (`[lifecycle]`).
            // Absent ⇒ the stopped-ack path is refused (fail-closed).
            let vali_backend = match &config.lifecycle {
                Some(lc_cfg) => {
                    // When `[lifecycle].ca_cert` is set, trust it on top
                    // of the webpki roots — the Edge stopped-ack relay
                    // serves the private hippius-compute CA's cert (dialed
                    // by its IP SAN). Absent ⇒ webpki built-ins only.
                    let backend = match &lc_cfg.ca_cert {
                        Some(ca) => hippius_miner_agent::vsock::ReqwestKbsBackend::new_with_ca(
                            lc_cfg.vali_url.clone(),
                            ca,
                            "lifecycle.ca_cert",
                        )?,
                        None => hippius_miner_agent::vsock::ReqwestKbsBackend::new_for(
                            lc_cfg.vali_url.clone(),
                            "lifecycle.vali_url",
                        )?,
                    };
                    Some(Arc::new(backend) as Arc<dyn hippius_miner_agent::vsock::KbsBackend>)
                }
                None => None,
            };
            // The kbs-proxy fires the `kek-released` milestone through the
            // SAME shared progress sink the lifecycle uses for `booting`
            // (built once above). Cloning the `Arc` keeps a single signing
            // identity across the whole boot-phase sequence.
            let backends = Arc::new(hippius_miner_agent::vsock::ProxyBackends {
                kbs: kbs_backend,
                vali: vali_backend,
                progress: progress.clone(),
            });
            Some(tokio::spawn(
                hippius_miner_agent::vsock::kbs_proxy::run_kbs_proxy_listener(
                    lifecycle.cid_allocator(),
                    backends,
                    cancel.clone(),
                ),
            ))
        }
        None => None,
    };

    // Reboot watcher — re-push the cached COSE OrderTicket via vsock
    // every time libvirt restarts a tenant domain (guest `sudo reboot`
    // → `<on_reboot>restart</on_reboot>` → new boot, new keyscript
    // run, new vsock listener). Best-effort: a watcher failure does
    // NOT abort the agent. `virsh event` is Linux-only by transitive
    // dependency on libvirtd, so the spawn stays under the same
    // `target_os` gate as the vsock relay.
    #[cfg(target_os = "linux")]
    let reboot_watcher_task = tokio::spawn(hippius_miner_agent::lifecycle::reboot_watcher::run(
        Arc::clone(&lifecycle),
        Arc::clone(&ticket_pusher),
        Arc::clone(&migration),
        cancel.clone(),
    ));

    // PR-7 (INERT) — the diskless blackbox host-attestor supervisor.
    // Spawned ONLY when the operator opts in via `[host_attestor].enabled`.
    // Absent that (the default), the Infra domain is NEVER launched and no
    // supervision runs — the tenant launch/heartbeat/billing paths are
    // entirely unchanged. The auto-spawn trigger (vali, on miner-join)
    // arrives in a later PR; here the seam ships fully wired but dark.
    let infra_supervisor_task = match &config.host_attestor {
        Some(ha) if ha.enabled => {
            let order = hippius_miner_agent::lifecycle::infra::InfraLaunchOrder {
                ovmf_path: ha.ovmf_path.clone(),
                kernel_path: ha.kernel_path.clone(),
                initrd_path: ha.initrd_path.clone(),
                cmdline: ha.cmdline.clone(),
                expected_measurement_hex: ha.measurement_sha256.clone(),
            };
            eprintln!(
                "hippius-miner-agent: serve — host-attestor supervisor ENABLED \
                 (diskless blackbox Infra CVM; measurement pinned)"
            );
            Some(tokio::spawn(
                hippius_miner_agent::lifecycle::infra::run_infra_supervisor(
                    Arc::clone(&lifecycle),
                    order,
                    cancel.clone(),
                ),
            ))
        }
        _ => None,
    };

    // PR-10 (INERT) — the blackbox host-attestor nonce-challenge vsock
    // listener. Spawned ONLY when `[host_attestor].enabled` (same gate as
    // the supervisor above); Linux-only (`tokio-vsock`). The attestor guest
    // dials it to pull a fresh vali-minted single-use enrollment nonce; the
    // miner relays the request UP to the Edge and the nonce back DOWN. A
    // default deploy (host-attestor disabled) NEVER binds this port.
    #[cfg(target_os = "linux")]
    let host_challenge_task = match &config.host_attestor {
        Some(ha) if ha.enabled => Some(tokio::spawn(
            hippius_miner_agent::vsock::host_challenge::run_host_challenge_listener(
                Arc::clone(&edge),
                cancel.clone(),
            ),
        )),
        _ => None,
    };

    // PR-10b-S2a (INERT) — the blackbox host-attestor enroll/beacon UP-relay
    // vsock listener. Spawned ONLY when `[host_attestor].enabled` (same gate
    // as the supervisor + challenge listener above); Linux-only
    // (`tokio-vsock`). The attestor guest pushes its once-per-boot
    // enrollment + periodic liveness beacons here; the miner relays each
    // opaque body UP to the Edge (enroll → KBS mint → vali cert; beacon →
    // vali heartbeat). A default deploy (host-attestor disabled) NEVER binds
    // this port.
    #[cfg(target_os = "linux")]
    let host_relay_task = match &config.host_attestor {
        Some(ha) if ha.enabled => Some(tokio::spawn(
            hippius_miner_agent::vsock::host_relay::run_host_relay_listener(
                Arc::clone(&edge),
                cancel.clone(),
            ),
        )),
        _ => None,
    };

    eprintln!(
        "hippius-miner-agent: serve — up (miner_id={}, identity={pubkey}, \
         orders={orders_addr}). Awaiting shutdown signal.",
        config.miner.miner_id
    );

    wait_for_shutdown().await;
    eprintln!("hippius-miner-agent: serve — shutdown signal, draining");

    // (1) Signal every subsystem to stop.
    cancel.cancel();

    // (1b) Drain the host-attestor supervisor FIRST (if it was armed) so
    // it cannot relaunch the Infra domain while `shutdown_all` (step 4)
    // is stopping it. It returns promptly on cancel (it selects on the
    // token between waits). No-op when the supervisor was never spawned.
    if let Some(task) = infra_supervisor_task {
        if tokio::time::timeout(ORDERS_DRAIN_GRACE, task)
            .await
            .is_err()
        {
            eprintln!("hippius-miner-agent: serve — infra-supervisor-drain-timeout");
        }
    }

    // (2) Drain the vsock relay — guest connections close cleanly.
    #[cfg(target_os = "linux")]
    if tokio::time::timeout(VSOCK_DRAIN_GRACE, vsock_task)
        .await
        .is_err()
    {
        eprintln!("hippius-miner-agent: serve — vsock-drain-timeout");
    }

    // (2a) Drain the KBS-over-vsock proxy (if it was spawned).
    #[cfg(target_os = "linux")]
    if let Some(task) = kbs_proxy_task {
        if tokio::time::timeout(VSOCK_DRAIN_GRACE, task).await.is_err() {
            eprintln!("hippius-miner-agent: serve — kbs-proxy-drain-timeout");
        }
    }

    // (2a-bis) Drain the host-attestor nonce-challenge listener (PR-10),
    // if it was spawned (host-attestor enabled).
    #[cfg(target_os = "linux")]
    if let Some(task) = host_challenge_task {
        if tokio::time::timeout(VSOCK_DRAIN_GRACE, task).await.is_err() {
            eprintln!("hippius-miner-agent: serve — host-attestor-challenge-drain-timeout");
        }
    }

    // (2a-ter) Drain the host-attestor enroll/beacon UP-relay listener
    // (PR-10b-S2a), if it was spawned (host-attestor enabled).
    #[cfg(target_os = "linux")]
    if let Some(task) = host_relay_task {
        if tokio::time::timeout(VSOCK_DRAIN_GRACE, task).await.is_err() {
            eprintln!("hippius-miner-agent: serve — host-attestor-relay-drain-timeout");
        }
    }

    // (2b) Drain the reboot-watcher. The `virsh event` child is
    // killed on cancel (the watcher loop checks the token between
    // each line read), so this returns promptly. Reuses the vsock
    // drain budget — `tokio::process` cleanup is sub-second.
    #[cfg(target_os = "linux")]
    if tokio::time::timeout(VSOCK_DRAIN_GRACE, reboot_watcher_task)
        .await
        .is_err()
    {
        eprintln!("hippius-miner-agent: serve — reboot-watcher-drain-timeout");
    }

    // (3) Drain the orders server — in-flight HTTP handlers finish.
    if tokio::time::timeout(ORDERS_DRAIN_GRACE, orders_task)
        .await
        .is_err()
    {
        eprintln!("hippius-miner-agent: serve — orders-drain-timeout");
    }
    // (3c) Drain the §K heartbeat subsystem. The builder breaks on
    // cancel at once; the pusher makes one final best-effort drain
    // pass of the queue (the graceful "drain once" invariant), capped
    // by HEARTBEAT_DRAIN_GRACE so an unreachable Edge cannot stall exit.
    let _ = heartbeat_build_task.await;
    if tokio::time::timeout(HEARTBEAT_DRAIN_GRACE, heartbeat_push_task)
        .await
        .is_err()
    {
        eprintln!("hippius-miner-agent: serve — heartbeat-drain-timeout");
    }

    // (3b) Drain the detached order-dispatch tasks. The orders HTTP
    // server is now down (no new handler can spawn one); `close` lets
    // `wait` complete once the in-flight launch/stop/destroy tasks —
    // including any whose HTTP client already disconnected — finish.
    dispatch_tasks.close();
    if tokio::time::timeout(DISPATCH_DRAIN_GRACE, dispatch_tasks.wait())
        .await
        .is_err()
    {
        eprintln!("hippius-miner-agent: serve — dispatch-drain-timeout");
    }

    // (4) Only now stop the tenant CVMs — the order intake AND every
    // in-flight dispatch are drained, so no order can race the teardown.
    //
    // `[host].skip_shutdown_teardown` leaves the CVMs RUNNING across a
    // graceful restart/upgrade: the qemu domains are libvirt-`define`d
    // and live in libvirtd's own cgroup, so they survive the agent
    // process exiting — making an agent restart transparent to tenants.
    if config.host.skip_shutdown_teardown {
        eprintln!(
            "hippius-miner-agent: serve — shutdown: skip_shutdown_teardown set — \
             leaving tenant CVMs running (they survive the agent restart)"
        );
    } else if lifecycle.shutdown_all().await.is_err() {
        eprintln!("hippius-miner-agent: serve — shutdown: some CVMs did not stop cleanly");
    }
    eprintln!("hippius-miner-agent: serve — shutdown complete");
    Ok(())
}

/// Park until SIGTERM (k8s / systemd stop) or SIGINT (Ctrl-C).
///
/// Panic-free: if a handler cannot be installed its branch is dropped
/// and the other still arms; if neither can, the process runs until
/// the runtime is torn down. Mirrors the edge-gateway `main`.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).ok();
    let mut sigint = signal(SignalKind::interrupt()).ok();
    match (sigterm.as_mut(), sigint.as_mut()) {
        (Some(term), Some(int)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
        (Some(term), None) => {
            term.recv().await;
        }
        (None, Some(int)) => {
            int.recv().await;
        }
        (None, None) => std::future::pending::<()>().await,
    }
}

/// `launch-test` — manually provision + launch one tenant SEV-SNP CVM,
/// or (with `--digest-only`) just compute the pre-flight launch digest.
fn cmd_launch_test(args: LaunchTestArgs) -> Result<()> {
    let cmdline = load_cmdline(&args.cmdline)?;
    let vm_id = VmId::new(&args.vm_id)?;

    if args.digest_only {
        // The digest depends only on (OVMF, kernel, initrd, cmdline,
        // vcpus) — the vm-id / uuid / disk are irrelevant here.
        let config = QemuConfig {
            vm_id,
            domain_uuid: DomainUuid::generate()?,
            ovmf_path: args.ovmf,
            kernel_path: args.kernel,
            initrd_path: args.initrd,
            cmdline,
            luks_disk_path: args.disk,
            luks_disk_size_gb: args.disk_size,
            rootfs_data_path: args.rootfs_data,
            rootfs_hash_path: args.rootfs_hash,
            // `--digest-only` does not provision a state disk; the
            // launch_digest is independent of it. A placeholder under
            // MINER_ROOT keeps validate() happy.
            state_disk_path: std::path::PathBuf::from(
                "/var/lib/hippius-miner/state/digest-only.raw",
            ),
            // The data disk is not a measured launch input.
            data_disk_path: None,
            data_disk_size_gb: 0,
            cpu_count: args.cpus,
            memory_mb: args.memory,
            // The launch digest ignores the disk + golden mode (only
            // OVMF/kernel/initrd/cmdline/vcpus are folded); the
            // `--digest-only` path carries the legacy default.
            golden: false,
            // The launch digest is CID-independent — the lowest guest
            // CID is a fine placeholder for the `--digest-only` path.
            cid: MIN_GUEST_CID,
        };
        let digest = compute_launch_digest(&config)?;
        // stdout: the digest is the §F allowlist measurement — pipe it
        // straight into a known-answer comparison.
        println!("{}", hex::encode(digest));
        return Ok(());
    }

    let host = HostResources {
        total_cpus: args.host_cpus,
        total_memory_mb: args.host_memory_mb,
        total_disk_gb: args.host_disk_gb,
    };
    ensure_test_disk(&args.disk, args.disk_size)?;
    let order = LaunchOrder {
        vm_id,
        ovmf_path: args.ovmf,
        kernel_path: args.kernel,
        initrd_path: args.initrd,
        cmdline,
        luks_disk_path: args.disk,
        luks_disk_size_gb: args.disk_size,
        data_disk_size_gb: args.data_disk_size,
        rootfs_data_path: args.rootfs_data,
        rootfs_hash_path: args.rootfs_hash,
        cpu_count: args.cpus,
        memory_mb: args.memory,
        // `launch-test` exercises the lifecycle directly — it never
        // reaches the orders HTTP intake path that pushes the ticket
        // over vsock. An empty COSE buffer is the right placeholder
        // here; the production push lives in `orders::handler::handle_launch`.
        cose_ticket: serde_bytes::ByteBuf::new(),
    };

    // The lifecycle is async (`tokio::process` drives `virsh`); a
    // current-thread runtime is built just for this one launch.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let lifecycle = CvmLifecycle::new(
            Arc::new(VirshDriver::default()),
            Arc::new(SevLaunchDigest),
            host,
        );
        let launched = lifecycle.launch(order).await?;
        eprintln!("hippius-miner-agent: launch-test — cvm {launched} is running");
        Ok(())
    })
}

/// Create a blank sparse data-disk image at `path` if it is absent.
///
/// A `launch-test` convenience only: a real per-VM LUKS volume is
/// sealed by the vali / Packer side (§11), never created by the
/// untrusted miner.
fn ensure_test_disk(path: &Path, size_gb: u32) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = u64::from(size_gb)
        .checked_mul(1024 * 1024 * 1024)
        .ok_or(MinerAgentError::LaunchInput("disk-size"))?;
    std::fs::File::create(path)?.set_len(bytes)?;
    eprintln!("hippius-miner-agent: launch-test — created a blank {size_gb} GiB test disk");
    Ok(())
}
