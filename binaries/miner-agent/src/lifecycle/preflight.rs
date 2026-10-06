//! `tenant-preflight` lifecycle — fetch artifacts via S3 presigned URLs,
//! sha256-verify the bytes, stage them under `<STAGING_ROOT>/<vm-id>/`,
//! then run the same `snp_calc_launch_digest` the launch path uses and
//! return the digest as hex.
//!
//! Vali dispatches this BEFORE the launch order so it can mint the
//! `OrderTicket` with the matching `allowed_measurement_hex` and pin the
//! §22 allowlist entry — all without the operator having to SSH the
//! miner to run `hippius-miner-agent launch-test --digest-only`.
//!
//! ## §20 discipline
//!
//! - The presigned URL is treated as a secret (short-TTL, single-object,
//!   carries a signature in the query string). It crosses one process
//!   boundary into `reqwest::get` and is never re-emitted on stderr.
//! - Downloaded bytes are written to a `*.partial` tmpfile and renamed
//!   only after the sha256 verify; a partial file never claims a
//!   canonical staging path on failure.
//! - The returned JSON carries only the digest hex + staged absolute
//!   paths — never the URL or the bytes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::cvm_handle::{DomainUuid, LAUNCH_DIGEST_LEN};
use crate::lifecycle::launch_digest::compute_launch_digest;
use crate::lifecycle::qemu_config::QemuConfig;
use crate::orders::types::TenantPreflightOrder;

/// Static classifier reported in the JSON `classifier` field on
/// success — operator audit logs grep on it. The HTTP response body
/// is the JSON envelope, NOT this string.
pub const CLASS_OK: &str = "preflight-ok";

/// Canonical staging root the miner-agent uses for tenant artifacts.
/// Matches `scripts/tenant-image-bake.sh`'s default output dir layout
/// + the `--miner-staging-dir` flag in `vali_create_vm`.
pub const STAGING_ROOT: &str = "/var/lib/hippius-miner/staging";

/// Content-addressed cache of already-verified baked artifacts, keyed by
/// the **expected sha256** (`image-cache/<sha256_hex>`). A relaunch of the
/// SAME bake (same URL+sha256, via `bake_id` reuse) materializes the
/// multi-GB LUKS qcow2 from this local cache instead of re-fetching it
/// from S3 — the dominant launch latency once the bake itself is reused.
/// Sibling of the existing `staging`/`images`/`base-images` dirs.
pub const IMAGE_CACHE_ROOT: &str = "/var/lib/hippius-miner/image-cache";

/// Default upper bound on the total bytes held under [`IMAGE_CACHE_ROOT`].
/// The cache is content-addressed and only ever grows otherwise — an
/// unbounded cache is the recurring miner rootfs-full hazard. Before
/// populating a new entry the reaper evicts the least-recently-used
/// entries (by mtime, bumped on every cache HIT) until the cache fits.
/// Operators override with the `HIPPIUS_IMAGE_CACHE_MAX_BYTES` env var
/// (systemd unit `Environment=`). Fail-open: an unparseable value falls
/// back to this default, and any reaper error is logged, never fatal.
const IMAGE_CACHE_DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024 * 1024;

/// Resolve the cache byte-cap: `HIPPIUS_IMAGE_CACHE_MAX_BYTES` if set to a
/// parseable non-zero `u64`, else [`IMAGE_CACHE_DEFAULT_MAX_BYTES`].
pub(crate) fn image_cache_max_bytes() -> u64 {
    std::env::var("HIPPIUS_IMAGE_CACHE_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(IMAGE_CACHE_DEFAULT_MAX_BYTES)
}

/// JSON envelope returned in the HTTP response body on success. Vali
/// parses this to recover `launch_digest_hex` + the staged paths for
/// the subsequent ticket-mint + launch-dispatch.
#[derive(Debug, Clone, Serialize)]
pub struct PreflightOutput {
    /// Static classifier — the same string [`CLASS_OK`] would log.
    pub classifier: &'static str,
    /// Lower-case hex of the 48-byte SNP launch digest.
    pub launch_digest_hex: String,
    /// Absolute path to the verified boot disk. LEGACY: the per-VM
    /// `tenant.qcow2`. GOLDEN: the shared golden `rootfs.img` (same value
    /// as [`Self::rootfs_data_path`]) — there is no per-VM qcow2, so this
    /// points at the staged golden base data image.
    pub luks_disk_path: String,
    /// Absolute path to the verified kernel.
    pub kernel_path: String,
    /// Absolute path to the verified initrd.
    pub initrd_path: String,
    /// GOLDEN-mode only: staged golden `rootfs.img` (`/dev/vdb`). Absent
    /// (`None`) on the LEGACY path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_data_path: Option<String>,
    /// GOLDEN-mode only: staged golden `rootfs.verity` (`/dev/vdc`).
    /// Absent (`None`) on the LEGACY path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_hash_path: Option<String>,
}

/// Canonical file names inside a per-VM staging dir. Every path the
/// miner-agent stages an artifact to is `vm_staging_dir(vm_id)/<one of
/// these>` — the launch preflight below and the §25 dest-activation
/// (`orders::migration::stage_dest_artifacts`) MUST agree byte-for-byte,
/// because §24's reclaim and the "never clobber a shared base" invariant
/// both key off "everything this VM boots lives under its own dir".
pub(crate) const ARTIFACT_KERNEL: &str = "tenant.vmlinuz";
pub(crate) const ARTIFACT_INITRD: &str = "tenant.initrd.img";
pub(crate) const ARTIFACT_ROOTFS_IMG: &str = "rootfs.img";
pub(crate) const ARTIFACT_ROOTFS_VERITY: &str = "rootfs.verity";
pub(crate) const ARTIFACT_OVMF: &str = "ovmf.fd";

/// Per-VM staging dir built off [`STAGING_ROOT`] + `vm_id`.
///
/// `pub(crate)` so §24's `destroy` can reclaim it: the staged kernel /
/// initrd / rootfs are per-VM and hundreds of MB, and nothing else ever
/// deletes them.
///
/// ⚠️ **Do not make this configurable or order-supplied.** §24's reclaim
/// derives the footprint from `vm_id` alone, with no lifecycle record to
/// consult, so a VM staged by ANY past agent version is still reclaimable
/// by ANY future one. That backward compatibility is a data-death
/// guarantee, not a nicety: a VM whose staging dir cannot be re-derived
/// leaks its base image forever.
pub(crate) fn vm_staging_dir(vm_id: &str) -> PathBuf {
    PathBuf::from(STAGING_ROOT).join(vm_id)
}

/// What staging is permitted to do to bytes that are ALREADY on disk at
/// the destination path.
///
/// ## Why this exists
///
/// Every path the agent stages to is now per-VM, but a VM can be asked to
/// re-stage its OWN artifacts while its domain is up: a re-dispatched
/// `tenant-preflight`, or a re-driven §25 `migrate-activate` (which stages
/// BEFORE its live-domain check and so used to re-download over a running
/// guest's boot artifacts unconditionally). Replacing the bytes a live
/// guest boots from — a dm-verity base above all — is a data-loss event.
///
/// The rule is content, not paths: staging over a live VM is allowed
/// **only when it is a no-op**, i.e. the file already hashes to the
/// expected digest. Anything that would CHANGE those bytes fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagePolicy {
    /// No domain for this VM is up — an existing file may be replaced.
    Replace,
    /// A domain for this VM is LIVE (or libvirt could not tell us, which
    /// is the same thing for a destructive write): a differing file is
    /// refused rather than overwritten.
    PinnedByLiveVm,
}

/// Reclaim ONE VM's staging directory **without ever following a symlink
/// out of it**.
///
/// ## The hazard
///
/// The staging root holds, side by side, the per-VM directories
/// (`staging/<vm_id>/`) and the SHARED, still-in-use base artifacts
/// (`staging/ovmf.fd`, `staging/rootfs.img`, `staging/rootfs.verity` —
/// verified live on all three miners). Deployments have also linked the
/// shared artifacts INTO a per-VM directory instead of copying them.
/// Deleting through such a link would destroy other tenants' running VMs
/// — the exact hazard that made the 2026-07-29 data-death sweep a
/// hand-audited operation.
///
/// ## Honest note on why this replaces `remove_dir_all`
///
/// It is NOT a behaviour fix: `std::fs::remove_dir_all` on the current
/// toolchain is already symlink-safe (measured — the tests below pass
/// against it too). It is here because that safety is an implementation
/// property of the standard library which has CHANGED before
/// (CVE-2022-21658 reworked exactly this traversal), and this is a
/// deletion path that runs, unattended, over an untrusted miner's
/// filesystem. Making the two rules explicit means they are asserted at
/// the call site that needs them rather than inherited silently.
///
/// Two rules make deleting through a link impossible by construction:
///
/// 1. **The directory itself is `symlink_metadata`-checked.** If
///    `staging/<vm_id>` is a SYMLINK (to the shared base dir, say), we
///    unlink the LINK and stop. Recursing through it would delete the
///    target's contents.
/// 2. **Entries are removed with `remove_file` when they are not real
///    directories.** `symlink_metadata` does not traverse, so a symlink
///    entry is removed AS A LINK; its target is untouched. Only an entry
///    whose own (un-traversed) metadata says `is_dir` is recursed into.
///
/// Best-effort by contract: the caller (§24/§25 reclaim) treats a failure
/// here as disk space, never as correctness — the data-death guarantee is
/// the KEK destroy, and the per-VM disks are unlinked separately by exact
/// path. `NotFound` is success (idempotent).
pub(crate) fn reclaim_staging_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.is_dir() {
        // A symlink (or a stray file) where the per-VM directory should
        // be. Remove the ENTRY, never what it points at.
        return std::fs::remove_file(dir);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // `symlink_metadata`, NOT `metadata`: a symlink-to-directory must
        // be unlinked as a link, not recursed into. Defence in depth — the
        // top-of-function check above catches it on the recursive call too
        // (mutating this line alone does not break the property), but a
        // guard that only works one frame later is not one to rely on.
        let child = std::fs::symlink_metadata(&path)?;
        if child.is_dir() {
            reclaim_staging_dir(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    std::fs::remove_dir(dir)
}

/// Run the fetch + verify + measure pipeline for one preflight order.
/// On success, returns the JSON-serialised envelope ready to be sent
/// as the HTTP response body.
pub async fn run(order: TenantPreflightOrder, policy: StagePolicy) -> Result<String> {
    let output = run_inner(order, policy).await?;
    serde_json::to_string(&output).map_err(|_| MinerAgentError::Preflight("json-encode"))
}

async fn run_inner(order: TenantPreflightOrder, policy: StagePolicy) -> Result<PreflightOutput> {
    let TenantPreflightOrder {
        vm_id,
        ovmf_path,
        luks_disk,
        kernel,
        initrd,
        rootfs_hash,
        cmdline,
        cpu_count,
    } = order;

    if !ovmf_path.is_file() {
        return Err(MinerAgentError::Preflight("ovmf-missing"));
    }
    if cpu_count == 0 {
        return Err(MinerAgentError::Preflight("cpu-count-zero"));
    }

    // GOLDEN-mode is signalled by the MEASURED cmdline (golden-bake PR4):
    // `dm-verity.root=` present AND `hippius.luks_header_sha256=` absent.
    // In golden mode there is NO per-VM `tenant.qcow2` to fetch — the OS
    // is the SHARED read-only golden dm-verity base. So the `luks_disk`
    // slot carries the golden `rootfs.img` and `rootfs_hash` carries the
    // golden `rootfs.verity`; both go through the SAME content-addressed
    // cache (#823) so a same-distro relaunch HITs instead of re-fetching.
    let golden = crate::lifecycle::golden::is_golden_cmdline(&cmdline);

    let staging = vm_staging_dir(vm_id.as_str());
    fs::create_dir_all(&staging).map_err(|_| MinerAgentError::Preflight("staging-mkdir"))?;

    // Filenames mirror the bake-script convention so an operator-side
    // `ls /var/lib/hippius-miner/staging/<vm-id>/` shows the same layout
    // as a manual `scp` workflow. The launch path's
    // `vali_create_vm::--image-base-sha` flag goes away because the path
    // is now derived deterministically from the vm_id, not from a hash.
    let kernel_path = staging.join(ARTIFACT_KERNEL);
    let initrd_path = staging.join(ARTIFACT_INITRD);

    // Kernel + initrd are fetched identically in both modes.
    fetch_verify_stage(&kernel.url, &kernel.sha256_hex, &kernel_path, policy).await?;
    fetch_verify_stage(&initrd.url, &initrd.sha256_hex, &initrd_path, policy).await?;

    // Boot-disk staging diverges by mode.
    let (luks_disk_path, rootfs_data_out, rootfs_hash_out) = if golden {
        // GOLDEN: fetch the SHARED golden base (rootfs.img + rootfs.verity)
        // by sha — NO per-VM qcow2. `rootfs_hash` is REQUIRED here; a
        // golden cmdline without it is a producer bug ⇒ fail closed.
        let rootfs_hash =
            rootfs_hash.ok_or(MinerAgentError::Preflight("golden-missing-rootfs-hash"))?;
        let rootfs_img_path = staging.join(ARTIFACT_ROOTFS_IMG);
        let rootfs_verity_path = staging.join(ARTIFACT_ROOTFS_VERITY);
        fetch_verify_stage(
            &luks_disk.url,
            &luks_disk.sha256_hex,
            &rootfs_img_path,
            policy,
        )
        .await?;
        fetch_verify_stage(
            &rootfs_hash.url,
            &rootfs_hash.sha256_hex,
            &rootfs_verity_path,
            policy,
        )
        .await?;
        let img = rootfs_img_path.display().to_string();
        let verity = rootfs_verity_path.display().to_string();
        // `luks_disk_path` mirrors the golden data image (the "boot disk"
        // artifact) for a uniform response shape; the launch path derives
        // the per-VM blank overlay vda itself (golden.rs) and never boots
        // this file as vda.
        (rootfs_img_path, Some(img), Some(verity))
    } else {
        // LEGACY: the per-VM baked LUKS `tenant.qcow2` (byte-identical).
        let qcow2_path = staging.join("tenant.qcow2");
        fetch_verify_stage(&luks_disk.url, &luks_disk.sha256_hex, &qcow2_path, policy).await?;
        (qcow2_path, None, None)
    };

    // Build a `QemuConfig` with placeholder values for the fields
    // `compute_launch_digest` does NOT touch (rootfs + luks_disk_size
    // etc.). Only `ovmf_path`, `kernel_path`, `initrd_path`, `cmdline`,
    // `cpu_count` are folded into `snp_calc_launch_digest` — keeping
    // the mapping byte-identical to the launch path is the point.
    let domain_uuid = DomainUuid::generate()?;
    let cfg = QemuConfig {
        vm_id,
        domain_uuid,
        ovmf_path,
        kernel_path: kernel_path.clone(),
        initrd_path: initrd_path.clone(),
        cmdline,
        luks_disk_path: luks_disk_path.clone(),
        luks_disk_size_gb: 0,
        rootfs_data_path: PathBuf::from("/dev/null"),
        rootfs_hash_path: PathBuf::from("/dev/null"),
        // `compute_launch_digest` does not touch the state disk path
        // either — a placeholder under MINER_ROOT keeps validate()
        // happy without provisioning anything during preflight.
        state_disk_path: PathBuf::from("/var/lib/hippius-miner/state/preflight.raw"),
        // #365 — the data disk is not a measured launch input, so the
        // digest-only preflight config carries none.
        data_disk_path: None,
        data_disk_size_gb: 0,
        cpu_count,
        memory_mb: 0,
        // Digest-only config: `compute_launch_digest` never validates or
        // renders the disk, so the golden flag is inert here.
        golden: false,
        cid: crate::vsock::peer::MIN_GUEST_CID,
    };

    let digest: [u8; LAUNCH_DIGEST_LEN] = compute_launch_digest(&cfg)?;
    let launch_digest_hex = hex::encode(digest);

    Ok(PreflightOutput {
        classifier: CLASS_OK,
        launch_digest_hex,
        luks_disk_path: luks_disk_path.display().to_string(),
        kernel_path: kernel_path.display().to_string(),
        initrd_path: initrd_path.display().to_string(),
        rootfs_data_path: rootfs_data_out,
        rootfs_hash_path: rootfs_hash_out,
    })
}

async fn fetch_verify_stage(
    url: &str,
    expected_sha256_hex: &str,
    out_path: &Path,
    policy: StagePolicy,
) -> Result<()> {
    fetch_verify_stage_cached(
        url,
        expected_sha256_hex,
        out_path,
        Path::new(IMAGE_CACHE_ROOT),
        image_cache_max_bytes(),
        policy,
    )
    .await
}

/// Fetch (or reuse from cache) → sha256-verify → stage one artifact.
///
/// ## Security invariant (make-or-break)
/// The bytes that end up at `out_path` (the disk that boots) are ALWAYS
/// gated on a sha256 that equals `expected_sha256_hex`:
/// - **Cache HIT** — the cached entry is re-hashed from disk; it is
///   trusted (and copied to `out_path`) ONLY when that hash matches
///   `expected`. A corrupt/tampered cache entry (hash mismatch) is
///   detected, bypassed, and re-downloaded — never booted.
/// - **Cache MISS** — the downloaded bytes are hashed in memory and
///   staged only on a match; the same verified bytes populate the cache.
///
/// The cache is a pure perf optimization gated on re-verify: it can only
/// make a launch faster, never boot an unverified disk. Cache-side I/O
/// (materialize, populate, reap) is fail-open — errors fall through to a
/// fresh download and can never block or corrupt a launch.
///
/// ## Second invariant (P9/#16): a live VM's base is never rewritten
///
/// Before ANY write, the bytes already at `out_path` are hashed:
/// - they match `expected` ⇒ nothing to do, return without writing (this
///   is what makes a re-dispatched preflight / re-driven §25 activate a
///   true no-op instead of a multi-GB re-download over a booted guest);
/// - they differ and [`StagePolicy::PinnedByLiveVm`] ⇒ `base-in-use`,
///   fail closed. The caller resolves the policy from the domain's
///   liveness, so "the VM is up" and "the bytes would change" is the
///   exact conjunction that is refused.
async fn fetch_verify_stage_cached(
    url: &str,
    expected_sha256_hex: &str,
    out_path: &Path,
    cache_root: &Path,
    cache_max_bytes: u64,
    policy: StagePolicy,
) -> Result<()> {
    let expected = parse_sha256_hex(expected_sha256_hex)
        .ok_or(MinerAgentError::Preflight("bad-sha256-hex"))?;

    // ── Stage-time content check on what is ALREADY there ────────────
    if out_path.exists() {
        if file_sha256_matches(out_path, &expected) {
            // Already exactly the artifact this order asks for.
            return Ok(());
        }
        if policy == StagePolicy::PinnedByLiveVm {
            return Err(MinerAgentError::Preflight("base-in-use"));
        }
    }
    // Content-addressed key = lower-case hex of the *expected* digest
    // (normalized, so an upper-case order hash still hits the same slot).
    let cache_key = hex::encode(expected);
    let cache_path = cache_root.join(&cache_key);

    // ── Cache HIT path — re-verify then materialize, NO S3 download ──
    // Materialize failure (I/O) is fail-open: fall through to download.
    if cache_path.is_file()
        && file_sha256_matches(&cache_path, &expected)
        && materialize_from_cache(&cache_path, out_path).is_ok()
    {
        // Bump the entry's mtime so the LRU reaper treats a re-used image
        // as recently used (best-effort; a failure just makes it look
        // older to the reaper — never fatal).
        let _ = fs::File::open(&cache_path).and_then(|f| f.set_modified(SystemTime::now()));
        return Ok(());
    }

    // ── Cache MISS / corruption — download, verify, stage, populate ──
    // `download_verified` returns ONLY bytes that hash to `expected`.
    let bytes = download_verified(url, &expected, &DOWNLOAD_RETRY_PAUSES).await?;

    // Atomic-ish stage: write to `<out>.partial`, fsync, rename. A
    // crash mid-write leaves the previous good file (if any) in place.
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|_| MinerAgentError::Preflight("stage-mkdir"))?;
    }
    let partial = out_path.with_extension("partial");
    {
        let mut f =
            fs::File::create(&partial).map_err(|_| MinerAgentError::Preflight("stage-create"))?;
        f.write_all(&bytes)
            .map_err(|_| MinerAgentError::Preflight("stage-write"))?;
        f.sync_all()
            .map_err(|_| MinerAgentError::Preflight("stage-sync"))?;
    }
    fs::rename(&partial, out_path).map_err(|_| MinerAgentError::Preflight("stage-rename"))?;

    // Best-effort populate the content-addressed cache with the SAME
    // verified bytes so the next relaunch of this bake skips the S3 fetch.
    // Fail-open: `out_path` is already staged+verified, so a cache write
    // error must never turn a good launch into a failure.
    populate_cache(cache_root, &cache_path, &bytes, &expected, cache_max_bytes);
    Ok(())
}

/// Pauses between download attempts on a TRANSIENT failure (three
/// attempts in all). Object stores answer `SlowDown` (HTTP 503), other
/// 5xx and throttling (408/429) under load, connections stall or drop, and
/// a presigned GET has once returned a 200 whose bytes did not hash to the
/// pin (a migration, 2026-09) while the next GET was byte-exact. One
/// of those used to fail the whole launch.
#[cfg(not(test))]
const DOWNLOAD_RETRY_PAUSES: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];
#[cfg(test)]
const DOWNLOAD_RETRY_PAUSES: [Duration; 2] = [Duration::ZERO, Duration::ZERO];

/// No retry is started past this budget, measured from the first attempt:
/// it stays under the Edge/vali preflight dispatch timeout (30 min), so a
/// late retry cannot land a stage nobody is waiting for.
const DOWNLOAD_BUDGET: Duration = Duration::from_secs(25 * 60);

/// Connect timeout for an artifact GET.
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle timeout: a GET that delivers no bytes for this long is a failed
/// attempt, not a hang. There is deliberately no whole-request timeout —
/// a legacy tenant qcow2 can be many GB.
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(60);

fn download_client() -> Result<&'static reqwest::Client> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
        .read_timeout(DOWNLOAD_READ_TIMEOUT)
        .build()
        .map_err(|_| MinerAgentError::Preflight("fetch-client"))?;
    Ok(CLIENT.get_or_init(|| client))
}

/// One GET of `url`, verified against `expected`. `Err((class, transient,
/// detail))`: a connection/body error, a 5xx, a 408/429 or a digest
/// mismatch is transient; any other status (a 403/404: an expired or wrong
/// URL, a missing object) will answer the same way again.
async fn download_once(
    url: &str,
    expected: &[u8; 32],
) -> std::result::Result<bytes::Bytes, (&'static str, bool, String)> {
    let resp = download_client()
        .map_err(|_| ("fetch-client", false, String::new()))?
        .get(url)
        .send()
        .await
        .map_err(|_| ("fetch-network", true, String::new()))?;
    let status = resp.status();
    if !status.is_success() {
        let transient = status.is_server_error()
            || status == reqwest::StatusCode::REQUEST_TIMEOUT
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
        return Err((
            "fetch-http-status",
            transient,
            format!("http {}", status.as_u16()),
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| ("fetch-body", true, String::new()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    if hasher.finalize().as_slice() != expected.as_slice() {
        return Err(("sha256-mismatch", true, format!("{} bytes", bytes.len())));
    }
    Ok(bytes)
}

/// Whether a retry after `pause` still starts inside [`DOWNLOAD_BUDGET`],
/// `elapsed` being the time since the first attempt.
fn retry_fits(elapsed: Duration, pause: Duration) -> bool {
    elapsed + pause < DOWNLOAD_BUDGET
}

/// GET `url` until it yields bytes hashing to `expected`, retrying a
/// transient failure after each of `pauses` while within
/// [`DOWNLOAD_BUDGET`]. Returns ONLY verified bytes; the last failure's
/// class otherwise. The URL is a presigned secret and is never logged.
async fn download_verified(
    url: &str,
    expected: &[u8; 32],
    pauses: &[Duration],
) -> Result<bytes::Bytes> {
    let started = std::time::Instant::now();
    let mut pauses = pauses.iter();
    loop {
        let (class, transient, detail) = match download_once(url, expected).await {
            Ok(bytes) => return Ok(bytes),
            Err(failure) => failure,
        };
        match pauses.next() {
            Some(pause) if transient && retry_fits(started.elapsed(), *pause) => {
                eprintln!(
                    "hippius-miner-agent: preflight — transient download failure \
                     ({class} {detail}), retrying in {}s",
                    pause.as_secs()
                );
                tokio::time::sleep(*pause).await;
            }
            _ => return Err(MinerAgentError::Preflight(class)),
        }
    }
}

/// Read `path` and return whether its sha256 equals `expected`. Any I/O
/// error reads as "does not match" (fail-closed on the trust question:
/// an unreadable cache entry is not trusted and triggers a re-download).
pub(crate) fn file_sha256_matches(path: &Path, expected: &[u8; 32]) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    if std::io::copy(&mut f, &mut hasher).is_err() {
        return false;
    }
    hasher.finalize().as_slice() == expected.as_slice()
}

/// Materialize `out_path` from an already-verified cache entry WITHOUT a
/// network fetch. Prefers `cp --reflink=auto` (an instant CoW clone on
/// btrfs/xfs; `cp` itself falls back to a full copy on non-CoW fs), and
/// falls back to `fs::copy` only if the `cp` binary is unavailable.
///
/// The copy goes to `<out>.partial` then renames — the cache entry stays
/// pristine (the per-VM qcow2 is written during boot; a hardlink would
/// corrupt the shared cache entry, so we never hardlink).
pub(crate) fn materialize_from_cache(cache_path: &Path, out_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let partial = out_path.with_extension("partial");
    let _ = fs::remove_file(&partial);

    let reflinked = Command::new("cp")
        .arg("--reflink=auto")
        .arg(cache_path)
        .arg(&partial)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !reflinked {
        // `cp` missing/failed — plain byte copy (still local, no S3).
        fs::copy(cache_path, &partial)?;
    }
    fs::rename(&partial, out_path)
}

/// Populate `cache_path` with `bytes` (already sha256-verified against
/// `expected`) via a temp-file + fsync + re-verify + atomic rename, so a
/// concurrent reader never observes a partial entry and a racing writer
/// is idempotent (last-writer-wins on identical content). Reaps LRU
/// entries first to stay under `max_bytes`. Entirely best-effort.
pub(crate) fn populate_cache(
    cache_root: &Path,
    cache_path: &Path,
    bytes: &[u8],
    expected: &[u8; 32],
    max_bytes: u64,
) {
    if cache_path.is_file() && file_sha256_matches(cache_path, expected) {
        return; // Already cached + verified (a prior launch populated it).
    }
    // A missing OR corrupt entry falls through: the atomic rename below
    // overwrites a poisoned slot so the cache self-heals (otherwise a
    // corrupt entry would force an S3 re-download on every relaunch).
    if fs::create_dir_all(cache_root).is_err() {
        return;
    }
    // Evict oldest entries to make room for the incoming one (fail-open).
    reap_cache(cache_root, max_bytes, bytes.len() as u64);

    // Temp name is per-process/per-nanos so two racing populates don't
    // clobber each other's temp; the final rename is the atomic step.
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = cache_root.join(format!(".tmp-{}-{}", std::process::id(), nonce));

    let write_ok = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })()
    .is_ok();
    // Re-verify the on-disk temp before publishing it — guards against a
    // bad write silently poisoning the cache. Only a verified temp is
    // ever renamed into the content-addressed slot.
    if write_ok && file_sha256_matches(&tmp, expected) {
        let _ = fs::rename(&tmp, cache_path);
    }
    let _ = fs::remove_file(&tmp);
}

/// Evict least-recently-used cache entries (oldest mtime first) until the
/// total cached bytes + `incoming` fit within `max_bytes`. Only genuine
/// 64-hex content-addressed entries are counted/evicted; transient
/// `.tmp-*` files and anything else are ignored. Fully best-effort — any
/// error aborts the reap without blocking the caller.
fn reap_cache(cache_root: &Path, max_bytes: u64, incoming: u64) {
    let Ok(read_dir) = fs::read_dir(cache_root) else {
        return;
    };
    let mut entries: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    let mut total: u64 = 0;
    for dent in read_dir.flatten() {
        let name = dent.file_name();
        let Some(name) = name.to_str() else { continue };
        // Only real content-addressed entries (64 lower-case hex chars).
        if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(meta) = dent.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        total = total.saturating_add(meta.len());
        entries.push((dent.path(), meta.len(), mtime));
    }

    let target = max_bytes.saturating_sub(incoming);
    if total <= target {
        return;
    }
    // Oldest first (LRU: mtime is bumped on every cache HIT).
    entries.sort_by_key(|(_, _, mtime)| *mtime);
    for (path, len, _) in entries {
        if total <= target {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
}

fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── staging reclaim: never follow a link out of the per-VM dir ────
    //
    // The §25 source reclaim (P9/#15) and the §24 destroy both run this
    // on an UNTRUSTED miner's staging tree. The staging ROOT holds the
    // shared `ovmf.fd` / `rootfs.img` / `rootfs.verity` beside the per-VM
    // directories; deleting through a link into them takes out other
    // tenants' RUNNING VMs.

    #[test]
    fn staging_reclaim_removes_the_whole_per_vm_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let vm_dir = tmp.path().join("staging").join("tenant-a");
        std::fs::create_dir_all(vm_dir.join("nested")).unwrap();
        std::fs::write(vm_dir.join("tenant.vmlinuz"), b"kernel").unwrap();
        std::fs::write(vm_dir.join("nested").join("x"), b"x").unwrap();

        reclaim_staging_dir(&vm_dir).unwrap();
        assert!(!vm_dir.exists(), "the per-VM staging dir must be reclaimed");
    }

    #[test]
    fn staging_reclaim_unlinks_a_symlink_but_never_its_target() {
        // A deployment that LINKS the shared golden base into the per-VM
        // dir instead of copying it. Following the link would destroy the
        // base image every other tenant on this host boots from.
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("staging").join("rootfs.img");
        std::fs::create_dir_all(shared.parent().unwrap()).unwrap();
        std::fs::write(&shared, b"SHARED GOLDEN BASE").unwrap();

        let vm_dir = tmp.path().join("staging").join("tenant-a");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let link = vm_dir.join("rootfs.img");
        std::os::unix::fs::symlink(&shared, &link).unwrap();
        std::fs::write(vm_dir.join("tenant.vmlinuz"), b"kernel").unwrap();

        reclaim_staging_dir(&vm_dir).unwrap();

        assert!(!vm_dir.exists(), "the per-VM staging dir must be reclaimed");
        assert!(
            shared.exists(),
            "the SHARED base image must survive — reclaim followed the link"
        );
        assert_eq!(std::fs::read(&shared).unwrap(), b"SHARED GOLDEN BASE");
    }

    #[test]
    fn staging_reclaim_does_not_recurse_through_a_linked_subdirectory() {
        // Same hazard, one level up: a per-VM subdirectory that is itself
        // a symlink to the shared image directory.
        let tmp = tempfile::tempdir().unwrap();
        let shared_dir = tmp.path().join("base-images");
        std::fs::create_dir_all(&shared_dir).unwrap();
        std::fs::write(shared_dir.join("rootfs.img"), b"SHARED").unwrap();

        let vm_dir = tmp.path().join("staging").join("tenant-a");
        std::fs::create_dir_all(&vm_dir).unwrap();
        std::os::unix::fs::symlink(&shared_dir, vm_dir.join("base")).unwrap();

        reclaim_staging_dir(&vm_dir).unwrap();

        assert!(!vm_dir.exists());
        assert!(
            shared_dir.join("rootfs.img").exists(),
            "reclaim recursed through a symlinked subdirectory"
        );
    }

    #[test]
    fn staging_reclaim_refuses_to_recurse_when_the_vm_dir_is_itself_a_link() {
        // `staging/<vm_id>` replaced by a link to the shared root. The
        // LINK is removed; nothing under the target is.
        let tmp = tempfile::tempdir().unwrap();
        let shared_dir = tmp.path().join("staging");
        std::fs::create_dir_all(&shared_dir).unwrap();
        std::fs::write(shared_dir.join("ovmf.fd"), b"OVMF").unwrap();
        std::fs::write(shared_dir.join("rootfs.img"), b"SHARED").unwrap();

        let vm_dir = tmp.path().join("staging").join("tenant-a");
        std::os::unix::fs::symlink(&shared_dir, &vm_dir).unwrap();

        reclaim_staging_dir(&vm_dir).unwrap();

        assert!(
            vm_dir.symlink_metadata().is_err(),
            "the dangling per-VM link must be unlinked"
        );
        assert!(shared_dir.join("ovmf.fd").exists(), "shared OVMF destroyed");
        assert!(
            shared_dir.join("rootfs.img").exists(),
            "shared rootfs destroyed"
        );
    }

    #[test]
    fn staging_reclaim_is_idempotent_on_an_absent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        reclaim_staging_dir(&tmp.path().join("staging").join("never-here")).unwrap();
    }

    #[test]
    fn parse_sha256_hex_round_trip() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let s = hex::encode(bytes);
        assert_eq!(parse_sha256_hex(&s), Some(bytes));
    }

    #[test]
    fn parse_sha256_hex_rejects_short() {
        assert!(parse_sha256_hex("abc").is_none());
    }

    #[test]
    fn parse_sha256_hex_rejects_non_hex() {
        let mut s = "0".repeat(63);
        s.push('z');
        assert!(parse_sha256_hex(&s).is_none());
    }

    #[test]
    fn parse_sha256_hex_accepts_uppercase() {
        let bytes = [0xAB_u8; 32];
        let s = hex::encode_upper(bytes);
        assert_eq!(parse_sha256_hex(&s), Some(bytes));
    }

    // ── content-addressed image-cache tests ─────────────────────────

    fn sha256_hex_of(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// One-shot raw-TCP HTTP server (dependency-free) serving `body` for a
    /// single GET; returns its `http://127.0.0.1:port/` URL. Mirrors the
    /// migration.rs staging tests so no real S3 is touched.
    async fn serve_once(body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            }
        });
        format!("http://{addr}/")
    }

    /// Raw-TCP HTTP server answering successive connections with the
    /// scripted `(status, body)` list; returns its URL and a counter of the
    /// connections it accepted.
    async fn serve_seq(
        answers: Vec<(u16, Vec<u8>)>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            for (status, body) in answers {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}/"), hits)
    }

    fn hits(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn sha_of(bytes: &[u8]) -> [u8; 32] {
        parse_sha256_hex(&sha256_hex_of(bytes)).unwrap()
    }

    async fn get(url: &str, want: &[u8]) -> Result<bytes::Bytes> {
        download_verified(url, &sha_of(want), &DOWNLOAD_RETRY_PAUSES).await
    }

    #[test]
    fn no_retry_starts_past_the_download_budget() {
        let pause = Duration::from_secs(5);
        assert!(retry_fits(Duration::ZERO, pause));
        assert!(retry_fits(
            DOWNLOAD_BUDGET - pause - Duration::from_secs(1),
            pause
        ));
        assert!(!retry_fits(DOWNLOAD_BUDGET - pause, pause));
        assert!(!retry_fits(DOWNLOAD_BUDGET, Duration::ZERO));
    }

    #[tokio::test]
    async fn a_slowdown_503_is_retried_until_the_download_lands() {
        let (url, n) = serve_seq(vec![(503, b"SlowDown".to_vec()), (200, b"img".to_vec())]).await;
        assert_eq!(&get(&url, b"img").await.unwrap()[..], b"img");
        assert_eq!(hits(&n), 2);
    }

    #[tokio::test]
    async fn throttling_429_and_timeout_408_are_transient() {
        for code in [429, 408] {
            let (url, n) = serve_seq(vec![(code, vec![]), (200, b"img".to_vec())]).await;
            assert_eq!(&get(&url, b"img").await.unwrap()[..], b"img", "{code}");
            assert_eq!(hits(&n), 2, "{code}");
        }
    }

    #[tokio::test]
    async fn a_5xx_that_persists_fails_after_the_retries() {
        let (url, n) = serve_seq(vec![(503, vec![]); 3]).await;
        let err = get(&url, b"img").await.unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Preflight("fetch-http-status")),
            "{err:?}"
        );
        assert_eq!(hits(&n), 3);
    }

    #[tokio::test]
    async fn a_permanent_4xx_fails_at_once() {
        let (url, n) = serve_seq(vec![(404, vec![]), (200, b"img".to_vec())]).await;
        let err = get(&url, b"img").await.unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Preflight("fetch-http-status")),
            "{err:?}"
        );
        assert_eq!(hits(&n), 1);
    }

    #[tokio::test]
    async fn a_truncated_body_is_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // First answer promises 100 bytes and sends 3; the second is whole.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let n = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = n.clone();
        tokio::spawn(async move {
            for (len, body) in [(100usize, &b"img"[..]), (3, &b"img"[..])] {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            }
        });
        let url = format!("http://{addr}/");
        assert_eq!(&get(&url, b"img").await.unwrap()[..], b"img");
        assert_eq!(hits(&n), 2);
    }

    #[tokio::test]
    async fn a_digest_mismatch_is_retried_and_only_the_pinned_bytes_return() {
        let (url, n) = serve_seq(vec![(200, b"bad".to_vec()), (200, b"img".to_vec())]).await;
        assert_eq!(&get(&url, b"img").await.unwrap()[..], b"img");
        assert_eq!(hits(&n), 2);
    }

    #[tokio::test]
    async fn an_unreachable_store_fails_as_a_network_error_after_the_retries() {
        let err = get("http://127.0.0.1:1/", b"img").await.unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Preflight("fetch-network")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn the_stage_path_retries_and_still_verifies_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm/rootfs.img");
        let body = b"golden-base".to_vec();
        let sha = sha256_hex_of(&body);
        let (url, n) = serve_seq(vec![(503, vec![]), (200, body.clone())]).await;
        fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), body);
        assert_eq!(hits(&n), 2);
    }

    #[tokio::test]
    async fn the_stage_path_never_stages_bytes_that_miss_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm/rootfs.img");
        let sha = sha256_hex_of(b"golden-base");
        let (url, n) = serve_seq(vec![
            (503, vec![]),
            (200, b"tampered".to_vec()),
            (200, b"tampered".to_vec()),
        ])
        .await;
        let err =
            fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
                .await
                .unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Preflight("sha256-mismatch")),
            "{err:?}"
        );
        assert_eq!(hits(&n), 3);
        assert!(!out.exists(), "unverified bytes must never be staged");
        assert!(!cache.join(&sha).exists(), "nor cached");
    }

    #[tokio::test]
    async fn cache_miss_downloads_and_populates_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm/tenant.qcow2");
        let body = b"baked-luks-qcow2-bytes".to_vec();
        let sha = sha256_hex_of(&body);
        let url = serve_once(body.clone()).await;

        fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();

        // out_path is the exact verified bytes.
        assert_eq!(std::fs::read(&out).unwrap(), body);
        // The content-addressed cache entry now exists and hashes right.
        let entry = cache.join(&sha);
        assert!(entry.is_file(), "cache entry must be populated on a miss");
        assert_eq!(std::fs::read(&entry).unwrap(), body);
        // Atomic populate leaves no temp behind.
        let temps: Vec<_> = std::fs::read_dir(&cache)
            .unwrap()
            .flatten()
            .filter(|d| d.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(temps.is_empty(), "no stranded .tmp- populate file");
        assert!(!out.with_extension("partial").exists());
    }

    #[tokio::test]
    async fn cache_hit_skips_the_download() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        std::fs::create_dir_all(&cache).unwrap();
        let out = dir.path().join("staging/vm/tenant.qcow2");
        let body = b"pre-staged-distro-image".to_vec();
        let sha = sha256_hex_of(&body);
        // Pre-populate the cache with the correct verified bytes.
        std::fs::write(cache.join(&sha), &body).unwrap();

        // Point the URL at an unreachable address: if the cache HIT path
        // ever fell through to a download, this would error. Success here
        // PROVES the S3 fetch was skipped.
        let dead_url = "http://127.0.0.1:1/";
        fetch_verify_stage_cached(dead_url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();

        // out_path is a faithful (sha256-correct) copy of the cache entry.
        assert_eq!(std::fs::read(&out).unwrap(), body);
        assert_eq!(sha256_hex_of(&std::fs::read(&out).unwrap()), sha);
    }

    #[tokio::test]
    async fn corrupt_cache_entry_is_detected_and_bypassed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        std::fs::create_dir_all(&cache).unwrap();
        let out = dir.path().join("staging/vm/tenant.qcow2");
        let real = b"the-authentic-measured-image".to_vec();
        let sha = sha256_hex_of(&real);
        // Poison the cache slot with WRONG bytes under the right key.
        std::fs::write(cache.join(&sha), b"tampered-garbage-not-the-image").unwrap();

        // The real image is available over HTTP; the corrupt cache must be
        // bypassed (re-hash mismatch) and the authentic bytes fetched.
        let url = serve_once(real.clone()).await;
        fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();

        // The booted disk is the verified authentic image, never the
        // tampered cache bytes.
        assert_eq!(std::fs::read(&out).unwrap(), real);
        // The poisoned entry was replaced by the verified content.
        assert_eq!(std::fs::read(cache.join(&sha)).unwrap(), real);
    }

    #[tokio::test]
    async fn sha_mismatch_on_download_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm/tenant.qcow2");
        // Every attempt returns bytes that do NOT match the expected sha
        // (a mismatch is retried, so the server answers each attempt).
        let (url, _) = serve_seq(vec![(200, b"wrong-bytes".to_vec()); 3]).await;
        let sha = sha256_hex_of(b"the-expected-image");

        let err =
            fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
                .await
                .unwrap_err();
        assert!(matches!(err, MinerAgentError::Preflight("sha256-mismatch")));
        assert!(!out.exists(), "a mismatched disk must never be staged");
        assert!(!cache.join(&sha).exists(), "and must never be cached");
    }

    #[tokio::test]
    async fn reaper_caps_the_cache_and_evicts_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm/tenant.qcow2");
        // Seed two old entries (~4 bytes each) with distinct mtimes.
        std::fs::create_dir_all(&cache).unwrap();
        let older = "a".repeat(64);
        let newer = "b".repeat(64);
        std::fs::write(cache.join(&older), b"OLD1").unwrap();
        std::fs::write(cache.join(&newer), b"NEW2").unwrap();
        // Make `older` genuinely older.
        let old_t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let new_t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000);
        std::fs::File::open(cache.join(&older))
            .unwrap()
            .set_modified(old_t)
            .unwrap();
        std::fs::File::open(cache.join(&newer))
            .unwrap()
            .set_modified(new_t)
            .unwrap();

        // Cap so tight that only the incoming entry + newest survive.
        let body = b"incoming-image-bytes".to_vec();
        let sha = sha256_hex_of(&body);
        let url = serve_once(body.clone()).await;
        let cap = (body.len() as u64) + 4; // room for incoming + one 4-byte entry

        fetch_verify_stage_cached(&url, &sha, &out, &cache, cap, StagePolicy::Replace)
            .await
            .unwrap();

        assert!(cache.join(&sha).is_file(), "incoming entry cached");
        assert!(
            !cache.join(&older).exists(),
            "oldest (LRU) entry evicted under the cap"
        );
        assert!(cache.join(&newer).is_file(), "newest entry retained");
    }

    // ── P9/#16: a live VM's base image can never be replaced ─────────
    //
    // The staged `rootfs.img` IS the dm-verity base a golden guest boots
    // its whole OS from. Rewriting it under a running domain is a
    // data-loss event, and both the launch preflight and the §25
    // dest-activation can be re-dispatched against a VM that is already
    // up. The rule is content-shaped: identical bytes are a no-op,
    // DIFFERENT bytes under a live domain fail closed.

    #[tokio::test]
    async fn staging_refuses_to_replace_a_base_a_live_vm_is_using() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm-a/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        // The base the LIVE guest is booted from, right now.
        let in_use = b"the-dm-verity-base-a-running-guest-boots".to_vec();
        std::fs::write(&out, &in_use).unwrap();

        // A re-dispatched order naming a DIFFERENT base. The bytes are
        // authentic (the server really serves what the sha says) — the
        // refusal is not about authenticity, it is about clobbering.
        let replacement = b"a-different-perfectly-valid-base".to_vec();
        let sha = sha256_hex_of(&replacement);
        let url = serve_once(replacement.clone()).await;

        let err = fetch_verify_stage_cached(
            &url,
            &sha,
            &out,
            &cache,
            u64::MAX,
            StagePolicy::PinnedByLiveVm,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, MinerAgentError::Preflight("base-in-use")));
        assert_eq!(
            std::fs::read(&out).unwrap(),
            in_use,
            "the live VM's base image was replaced under it"
        );
        assert!(
            !out.with_extension("partial").exists(),
            "no partial write may be left beside a live VM's base"
        );
    }

    #[tokio::test]
    async fn staging_over_a_live_vm_is_a_no_op_when_the_content_matches() {
        // The legitimate re-dispatch: same order, same bytes, VM already
        // up. This must succeed WITHOUT touching the file (and without a
        // multi-GB re-download) — otherwise the guard above would turn
        // every retry into a launch failure.
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm-a/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        let base = b"the-exact-base-this-order-names".to_vec();
        let sha = sha256_hex_of(&base);
        std::fs::write(&out, &base).unwrap();
        let before = std::fs::metadata(&out).unwrap().modified().unwrap();

        // Unreachable URL: success PROVES no fetch happened.
        fetch_verify_stage_cached(
            "http://127.0.0.1:1/",
            &sha,
            &out,
            &cache,
            u64::MAX,
            StagePolicy::PinnedByLiveVm,
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), base);
        assert_eq!(
            std::fs::metadata(&out).unwrap().modified().unwrap(),
            before,
            "a content-identical stage must not rewrite the file at all"
        );
    }

    #[tokio::test]
    async fn staging_replaces_a_stale_artifact_when_no_domain_is_up() {
        // The guard must not freeze a DOWN VM's staging: a relaunch onto a
        // new base (exactly what P1 needs to move a VM to a keepalive-
        // bearing image) has to be able to replace the old bytes.
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm-a/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::write(&out, b"the-stale-2026-07-29-base").unwrap();

        let fresh = b"the-keepalive-bearing-base".to_vec();
        let sha = sha256_hex_of(&fresh);
        let url = serve_once(fresh.clone()).await;

        fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), fresh);
    }

    #[tokio::test]
    async fn an_existing_artifact_is_hash_checked_not_trusted_by_name() {
        // "It is already at the right path" is NOT evidence it is the
        // right image — the whole P9/#16 divergence is two miners holding
        // different bytes at the same path. A file whose content does not
        // match the order's sha must be re-fetched, never reused.
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("image-cache");
        let out = dir.path().join("staging/vm-a/rootfs.img");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::write(&out, b"host-bs-divergent-2026-07-29-rootfs").unwrap();

        let authentic = b"the-base-this-spec-actually-names".to_vec();
        let sha = sha256_hex_of(&authentic);
        let url = serve_once(authentic.clone()).await;

        fetch_verify_stage_cached(&url, &sha, &out, &cache, u64::MAX, StagePolicy::Replace)
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(&out).unwrap(),
            authentic,
            "a same-path different-content artifact was trusted by name"
        );
        assert_eq!(sha256_hex_of(&std::fs::read(&out).unwrap()), sha);
    }

    // ── §24 backward compatibility: the staging root stays derivable ──

    #[test]
    fn the_per_vm_staging_dir_is_derived_from_the_vm_id_alone() {
        // §24's reclaim has NO lifecycle record to consult — it rebuilds
        // the footprint from `vm_id`. If this derivation ever became
        // configurable or order-supplied, every VM staged under the old
        // scheme would become unreclaimable and leak its base forever.
        assert_eq!(
            vm_staging_dir("legacy-tenant-1"),
            PathBuf::from("/var/lib/hippius-miner/staging/legacy-tenant-1"),
        );
        // And the artifact names the reclaim sweeps are the SAME names
        // both the launch preflight and the §25 dest-activation write.
        let dir = vm_staging_dir("vm-a");
        for name in [
            ARTIFACT_KERNEL,
            ARTIFACT_INITRD,
            ARTIFACT_ROOTFS_IMG,
            ARTIFACT_ROOTFS_VERITY,
            ARTIFACT_OVMF,
        ] {
            assert_eq!(dir.join(name).parent().unwrap(), dir);
        }
    }

    // ── golden-bake PR6: cache HIT ⟂ per-VM overlay allocation ───────
    //
    // The SHARED golden base fetch (rootfs.img / rootfs.verity, cache-
    // keyed by sha via #823) and the per-VM blank overlay-UPPER
    // allocation (`golden::ensure_overlay_disk`, keyed by vm_id) MUST be
    // fully independent code paths: a cache HIT on the shared base must
    // NOT read/write/allocate any per-VM upper, and allocating a per-VM
    // upper must NOT touch (or evict) any shared cache entry. They
    // address DISJOINT trees (content-addressed `image-cache/<sha>` vs
    // per-VM `overlay/<vm>.img`) — this test pins that disjointness so a
    // future refactor can't accidentally cross-wire shared and per-VM
    // state (which would be a cross-tenant hazard).
    #[tokio::test]
    async fn golden_base_cache_hit_and_overlay_alloc_are_independent() {
        use crate::lifecycle::cvm_handle::VmId;
        use crate::lifecycle::golden;

        let dir = tempfile::tempdir().unwrap();
        let miner_root = dir.path();
        let cache = miner_root.join("image-cache");
        std::fs::create_dir_all(&cache).unwrap();

        // Pre-populate the cache with the golden base pair (as a warm
        // pre-stage would) so both fetches are HITs.
        let rootfs_img = b"golden-squashfs-rootfs.img-bytes".to_vec();
        let rootfs_verity = b"golden-dm-verity-hash-tree-bytes".to_vec();
        let img_sha = sha256_hex_of(&rootfs_img);
        let verity_sha = sha256_hex_of(&rootfs_verity);
        std::fs::write(cache.join(&img_sha), &rootfs_img).unwrap();
        std::fs::write(cache.join(&verity_sha), &rootfs_verity).unwrap();

        // Golden base fetch: two cache HITs into per-VM staging. A dead
        // URL proves no S3 download happened.
        let dead = "http://127.0.0.1:1/";
        let stage_img = miner_root.join("staging/vm-a/rootfs.img");
        let stage_verity = miner_root.join("staging/vm-a/rootfs.verity");
        fetch_verify_stage_cached(
            dead,
            &img_sha,
            &stage_img,
            &cache,
            u64::MAX,
            StagePolicy::Replace,
        )
        .await
        .unwrap();
        fetch_verify_stage_cached(
            dead,
            &verity_sha,
            &stage_verity,
            &cache,
            u64::MAX,
            StagePolicy::Replace,
        )
        .await
        .unwrap();

        // The cache HIT path allocated NO per-VM overlay upper.
        assert!(
            !miner_root.join("overlay").exists(),
            "golden base cache HIT must not create any per-VM overlay upper"
        );

        // Now allocate the per-VM overlay upper (the independent path).
        // A 4 MiB fixture proves the same separation as a GiB one without
        // asking CI for a spare GiB of free disk; the free-space gate is
        // covered deliberately in `golden`'s own tests.
        let vm = VmId::new("vm-a").unwrap();
        let overlay = golden::ensure_overlay_disk_bytes(miner_root, &vm, 4 * 1024 * 1024).unwrap();
        assert!(overlay.exists());
        // The overlay upper lives under `overlay/`, NEVER in the cache.
        assert!(overlay.starts_with(miner_root.join("overlay")));
        assert!(
            !overlay.starts_with(&cache),
            "overlay upper must never land in the shared image-cache"
        );

        // Allocating the per-VM upper did NOT touch (or evict) either
        // shared cache entry — they are byte-identical + still present.
        assert_eq!(std::fs::read(cache.join(&img_sha)).unwrap(), rootfs_img);
        assert_eq!(
            std::fs::read(cache.join(&verity_sha)).unwrap(),
            rootfs_verity
        );
        // No overlay-shaped file leaked into the cache dir (still exactly
        // the two content-addressed base entries).
        let cache_entries = std::fs::read_dir(&cache).unwrap().count();
        assert_eq!(
            cache_entries, 2,
            "cache holds only the 2 golden base entries"
        );
    }
}
