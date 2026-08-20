//! `hippius-uki-measure` — UKI launch-measurement extractor.
//!
//! Reads a built UKI (Unified Kernel Image PE binary) plus its
//! kernel / initrd / cmdline component inputs, computes a launch
//! measurement, and emits a stable JSON envelope.
//!
//! ## Two build modes — the `snp` feature is the discriminator
//!
//! * **default build** — `measurement_kind = "uki_sha384"`: a plain
//!   SHA-384 over the UKI bytes. This is a *content hash*, NOT the
//!   value an AMD SEV-SNP hypervisor measures at launch. It is a
//!   pre-production placeholder.
//! * **`--features snp` (PR-F3)** — `measurement_kind =
//!   "snp_launch_digest_v1"`: the real SEV-SNP launch digest, computed
//!   by [`sev::measurement::snp::snp_calc_launch_digest`] over a
//!   pinned OVMF + the kernel / initrd / cmdline. This is the value
//!   the §22 offline allowlist gates secret release on.
//!
//! The `snp` feature is non-default and Linux-only (the `sev`
//! `measurement` module is `cfg(target_os = "linux")` + needs
//! `openssl`). `make measure` builds with it inside the pinned Linux
//! Docker image; `cargo test --workspace` stays cross-platform on the
//! default build.
//!
//! ## Three-belt defence — placeholder ≠ trust anchor
//!
//! PR-F2 used the `measurement_kind` tag itself as the "not for prod"
//! signal. PR-F3 legitimately reaches `snp_launch_digest_v1`, so the
//! defence moves to the **IDBLOCK**: until an operator replaces the
//! `packer/kbs-uki/idblock/` placeholder (all-zero, carrying a loud
//! `DO-NOT-TRUST-IN-PROD` marker file) with a real SEV-SNP launch
//! policy signed by a real author key, the launch digest describes a
//! guest whose ID-block is unauthenticated. The §22 ceremony signer
//! still enforces `measurement_kind == "snp_launch_digest_v1"`; the
//! IDBLOCK marker is the belt that stops a *dev* SNP digest from being
//! mistaken for a production one.
//!
//! ## Stable JSON envelope
//!
//! ```json
//! {
//!   "measurement_kind": "snp_launch_digest_v1",
//!   "measurement_hex": "<96 hex chars>",
//!   "components": {
//!     "kernel_sha256": "<64 hex>",
//!     "initrd_sha256": "<64 hex>",
//!     "cmdline_sha256": "<64 hex>",
//!     "ovmf_sha256": "<64 hex>",
//!     "rootfs_verity_root": "<64 hex>",
//!     "snp_launch_config": { "vcpus": 1, "vcpu_type": "EpycV4",
//!                            "guest_features": "0x1" }
//!   },
//!   "uki_basename": "<filename only, no path>",
//!   "uki_size_bytes": <u64>,
//!   "note": "..."
//! }
//! ```
//!
//! `uki_basename` is the filename only — two `make uki-reproducible-
//! check` runs write into different output dirs, so a full path would
//! break the byte-identical contract. The `components` block is the
//! audit trail: every input that feeds `measurement_hex` is finger-
//! printed so a consumer can re-derive the digest independently.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
// `Sha384` measures the UKI bytes only on the default (non-SNP) build;
// the SNP build's measurement comes from `snp_calc_launch_digest`.
#[cfg(not(feature = "snp"))]
use sha2::Sha384;

#[cfg(not(feature = "snp"))]
const NOTE: &str = "Default build: measurement_kind=uki_sha384 is a CONTENT HASH, \
                    not an SEV-SNP launch digest — pre-production. Build with \
                    --features snp for the real snp_launch_digest_v1. The §22 \
                    allowlist signer MUST refuse measurement_kind != \
                    snp_launch_digest_v1.";

#[cfg(feature = "snp")]
const NOTE: &str = "measurement_kind=snp_launch_digest_v1 is the real AMD SEV-SNP \
                    launch digest. It is only a PRODUCTION trust anchor once the \
                    packer/kbs-uki/idblock/ placeholder (all-zero, DO-NOT-TRUST-IN-PROD) \
                    is replaced with a real signed launch policy and the OVMF in \
                    packer/kbs-uki/ovmf/ovmf.lock is pinned to a verified release.";

#[derive(Parser, Debug)]
#[command(name = "hippius-uki-measure", version)]
struct Args {
    /// Path to the assembled UKI (the signed PE binary).
    #[arg(long)]
    uki: PathBuf,
    /// Path to the kernel image used in the UKI (`vmlinuz`-like).
    #[arg(long)]
    kernel: PathBuf,
    /// Path to the initrd cpio archive used in the UKI.
    #[arg(long)]
    initrd: PathBuf,
    /// Path to the cmdline text file used in the UKI. The raw bytes
    /// are fingerprinted; for the SNP digest the content is taken as
    /// the kernel cmdline with at most one trailing newline stripped.
    #[arg(long)]
    cmdline: PathBuf,
    /// Optional output path for the JSON envelope (stdout if omitted).
    #[arg(long)]
    out: Option<PathBuf>,

    // ── SNP-only inputs (used by `--features snp`; ignored otherwise) ──
    /// Path to the pinned OVMF firmware (required by `--features snp`).
    #[arg(long)]
    ovmf: Option<PathBuf>,
    /// dm-verity root hash of the rootfs (PR-F3). Recorded in the
    /// audit trail; it is also embedded in the cmdline, so it already
    /// feeds the digest via `--cmdline`.
    #[arg(long)]
    rootfs_verity_root: Option<String>,
    /// Diskless (initrd-as-root) launch — the blackbox host-attestor
    /// UKI carries NO dm-verity rootfs, so `--rootfs-verity-root` is
    /// neither required nor recorded. The measured cmdline carries no
    /// `dm-verity.root=`, so nothing anchors a rootfs into the digest.
    /// Mutually exclusive with `--rootfs-verity-root`: passing both
    /// fails closed rather than silently measuring a non-existent
    /// anchor. Ignored on the default (non-`snp`) build.
    #[arg(long, default_value_t = false)]
    diskless: bool,
    /// vCPU count of the measured launch (affects the digest).
    #[arg(long, default_value_t = 1)]
    vcpus: u32,
    /// vCPU model of the measured launch (affects the digest).
    #[arg(long, default_value = "EpycGenoa")]
    vcpu_type: String,
    /// SEV-SNP guest-features bitmap (hex or decimal). 0x1 = SNPActive.
    #[arg(long, default_value = "0x1")]
    guest_features: String,
}

#[derive(Serialize)]
struct Envelope {
    /// `"uki_sha384"` (default) or `"snp_launch_digest_v1"` (`snp`).
    /// The §22 allowlist signer enforces the production value.
    measurement_kind: &'static str,
    /// Hex-encoded measurement. SHA-384 of the UKI (default) or the
    /// 48-byte SEV-SNP launch digest (`snp`) — both 96 hex chars.
    measurement_hex: String,
    components: Components,
    /// Filename of the UKI, NOT the full path — keeps the envelope
    /// byte-identical across reproducibility runs in different dirs.
    uki_basename: String,
    uki_size_bytes: u64,
    note: &'static str,
}

#[derive(Serialize)]
struct Components {
    kernel_sha256: String,
    initrd_sha256: String,
    cmdline_sha256: String,
    /// SHA-256 of the pinned OVMF — SNP path only.
    #[serde(skip_serializing_if = "Option::is_none")]
    ovmf_sha256: Option<String>,
    /// dm-verity root hash of the rootfs — SNP path only.
    #[serde(skip_serializing_if = "Option::is_none")]
    rootfs_verity_root: Option<String>,
    /// Pinned launch parameters that feed the SNP digest — SNP path only.
    #[serde(skip_serializing_if = "Option::is_none")]
    snp_launch_config: Option<SnpLaunchConfig>,
}

#[derive(Serialize)]
struct SnpLaunchConfig {
    vcpus: u32,
    vcpu_type: String,
    guest_features: String,
}

/// The fingerprints common to both build modes.
struct CommonInputs {
    kernel_sha256: String,
    initrd_sha256: String,
    cmdline_sha256: String,
    uki_basename: String,
    uki_size_bytes: u64,
    /// Full UKI bytes — hashed only by the default build's SHA-384
    /// path; the SNP build measures via `snp_calc_launch_digest` and
    /// never reads this.
    #[cfg_attr(feature = "snp", allow(dead_code))]
    uki_bytes: Vec<u8>,
}

fn read_common(args: &Args) -> Result<CommonInputs, MeasureError> {
    let uki_bytes =
        fs::read(&args.uki).map_err(|e| MeasureError::Read("uki", args.uki.clone(), e))?;
    let kernel_bytes =
        fs::read(&args.kernel).map_err(|e| MeasureError::Read("kernel", args.kernel.clone(), e))?;
    let initrd_bytes =
        fs::read(&args.initrd).map_err(|e| MeasureError::Read("initrd", args.initrd.clone(), e))?;
    let cmdline_bytes = fs::read(&args.cmdline)
        .map_err(|e| MeasureError::Read("cmdline", args.cmdline.clone(), e))?;

    Ok(CommonInputs {
        kernel_sha256: hex::encode(Sha256::digest(&kernel_bytes)),
        initrd_sha256: hex::encode(Sha256::digest(&initrd_bytes)),
        cmdline_sha256: hex::encode(Sha256::digest(&cmdline_bytes)),
        uki_basename: args
            .uki
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        uki_size_bytes: uki_bytes.len() as u64,
        uki_bytes,
    })
}

/// SHA-256 of a file — used by the SNP path for the OVMF audit entry.
#[cfg(feature = "snp")]
fn sha256_file(label: &'static str, path: &Path) -> Result<String, MeasureError> {
    let bytes = fs::read(path).map_err(|e| MeasureError::Read(label, path.to_path_buf(), e))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn main() -> ExitCode {
    let args = Args::parse();
    match build_envelope(&args) {
        Ok(env) => emit(env, args.out.as_deref()),
        Err(e) => {
            eprintln!("hippius-uki-measure: {e}");
            ExitCode::from(1)
        }
    }
}

// ── Default build: UKI content hash ─────────────────────────────────

#[cfg(not(feature = "snp"))]
fn build_envelope(args: &Args) -> Result<Envelope, MeasureError> {
    let common = read_common(args)?;
    Ok(Envelope {
        measurement_kind: "uki_sha384",
        measurement_hex: hex::encode(Sha384::digest(&common.uki_bytes)),
        components: Components {
            kernel_sha256: common.kernel_sha256,
            initrd_sha256: common.initrd_sha256,
            cmdline_sha256: common.cmdline_sha256,
            ovmf_sha256: None,
            rootfs_verity_root: None,
            snp_launch_config: None,
        },
        uki_basename: common.uki_basename,
        uki_size_bytes: common.uki_size_bytes,
        note: NOTE,
    })
}

// ── `--features snp`: real SEV-SNP launch digest ────────────────────

/// True iff `s` is exactly 64 lowercase-hex characters — the shape of
/// a dm-verity (SHA-256) root hash.
#[cfg(feature = "snp")]
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(feature = "snp")]
fn build_envelope(args: &Args) -> Result<Envelope, MeasureError> {
    let common = read_common(args)?;
    let ovmf = args.ovmf.as_ref().ok_or(MeasureError::MissingOvmf)?;

    // Two rootfs shapes:
    //   - the tenant/kbs UKI is dm-verity-anchored, so the rootfs verity
    //     root hash is mandatory + well-formed — a missing or malformed
    //     value must fail closed, never silently produce an
    //     `snp_launch_digest_v1` envelope with an absent anchor.
    //   - the diskless blackbox host-attestor UKI (initrd-as-root) has NO
    //     rootfs at all: the measured cmdline carries no `dm-verity.root=`,
    //     so nothing anchors a rootfs into the digest and there is nothing
    //     to record. `--diskless` selects that shape; passing a stray
    //     `--rootfs-verity-root` alongside it fails closed.
    let verity_root: Option<String> = if args.diskless {
        if args.rootfs_verity_root.is_some() {
            return Err(MeasureError::DisklessWithVerityRoot);
        }
        None
    } else {
        let vr = args
            .rootfs_verity_root
            .as_deref()
            .ok_or(MeasureError::MissingVerityRoot)?;
        if !is_lower_hex_64(vr) {
            return Err(MeasureError::BadVerityRoot(vr.to_string()));
        }
        Some(vr.to_string())
    };

    let digest = snp::launch_digest(args, ovmf)?;

    Ok(Envelope {
        measurement_kind: "snp_launch_digest_v1",
        measurement_hex: digest,
        components: Components {
            kernel_sha256: common.kernel_sha256,
            initrd_sha256: common.initrd_sha256,
            cmdline_sha256: common.cmdline_sha256,
            ovmf_sha256: Some(sha256_file("ovmf", ovmf)?),
            rootfs_verity_root: verity_root,
            snp_launch_config: Some(SnpLaunchConfig {
                vcpus: args.vcpus,
                vcpu_type: args.vcpu_type.clone(),
                guest_features: args.guest_features.clone(),
            }),
        },
        uki_basename: common.uki_basename,
        uki_size_bytes: common.uki_size_bytes,
        note: NOTE,
    })
}

/// SEV-SNP launch-digest computation — isolated so the `sev` crate is
/// only referenced under `cfg(feature = "snp")` (Linux-only).
#[cfg(feature = "snp")]
mod snp {
    use super::{Args, MeasureError};
    use std::path::Path;

    use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
    use sev::measurement::vcpu_types::CpuType;
    use sev::measurement::vmsa::GuestFeatures;

    /// The kernel cmdline embedded by `ukify` carries no trailing
    /// newline; the cmdline file may. Strip exactly one so the
    /// `append` fed to the digest matches what the guest boots with.
    fn cmdline_append(path: &Path) -> Result<String, MeasureError> {
        let raw = std::fs::read(path)
            .map_err(|e| MeasureError::Read("cmdline", path.to_path_buf(), e))?;
        let text = String::from_utf8(raw).map_err(|_| MeasureError::CmdlineNotUtf8)?;
        Ok(text.strip_suffix('\n').unwrap_or(&text).to_string())
    }

    fn parse_cpu_type(s: &str) -> Result<CpuType, MeasureError> {
        // Matched case-insensitively against the `sev` crate's QEMU
        // vCPU model set. The choice feeds the VMSA and therefore the
        // digest — it is a pinned launch parameter, never guessed.
        let t = match s.to_ascii_lowercase().as_str() {
            "epyc" => CpuType::Epyc,
            "epyc-v1" | "epycv1" => CpuType::EpycV1,
            "epyc-v2" | "epycv2" => CpuType::EpycV2,
            "epyc-ibpb" | "epycibpb" => CpuType::EpycIBPB,
            "epyc-v3" | "epycv3" => CpuType::EpycV3,
            "epyc-v4" | "epycv4" => CpuType::EpycV4,
            "epyc-rome" | "epycrome" => CpuType::EpycRome,
            "epyc-rome-v1" | "epycromev1" => CpuType::EpycRomeV1,
            "epyc-rome-v2" | "epycromev2" => CpuType::EpycRomeV2,
            "epyc-rome-v3" | "epycromev3" => CpuType::EpycRomeV3,
            "epyc-milan" | "epycmilan" => CpuType::EpycMilan,
            "epyc-milan-v1" | "epycmilanv1" => CpuType::EpycMilanV1,
            "epyc-milan-v2" | "epycmilanv2" => CpuType::EpycMilanV2,
            "epyc-genoa" | "epycgenoa" => CpuType::EpycGenoa,
            "epyc-genoa-v1" | "epycgenoav1" => CpuType::EpycGenoaV1,
            "epyc-turin" | "epycturin" => CpuType::EpycTurin,
            "epyc-turin-v1" | "epycturinv1" => CpuType::EpycTurinV1,
            _ => return Err(MeasureError::BadVcpuType(s.to_string())),
        };
        Ok(t)
    }

    fn parse_guest_features(s: &str) -> Result<GuestFeatures, MeasureError> {
        let trimmed = s.trim();
        let value = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            trimmed.parse::<u64>()
        }
        .map_err(|_| MeasureError::BadGuestFeatures(s.to_string()))?;
        Ok(GuestFeatures(value))
    }

    /// Compute the SEV-SNP launch digest as a 96-char hex string.
    pub(super) fn launch_digest(args: &Args, ovmf: &Path) -> Result<String, MeasureError> {
        let append = cmdline_append(&args.cmdline)?;
        let snp_args = SnpMeasurementArgs {
            vcpus: args.vcpus,
            vcpu_type: parse_cpu_type(&args.vcpu_type)?,
            ovmf_file: ovmf.to_path_buf(),
            guest_features: parse_guest_features(&args.guest_features)?,
            kernel_file: Some(args.kernel.clone()),
            initrd_file: Some(args.initrd.clone()),
            append: Some(append.as_str()),
            // `None` → the digest is computed over the OVMF file's
            // bytes (the measured-firmware path), not a pre-supplied
            // hash. `vmm_type` `None` → QEMU, the bare-metal launch path.
            ovmf_hash_str: None,
            vmm_type: None,
        };
        let digest = snp_calc_launch_digest(snp_args).map_err(MeasureError::Sev)?;
        Ok(digest.get_hex_ld())
    }
}

fn emit(env: Envelope, out: Option<&Path>) -> ExitCode {
    // Pretty-printed for human review; consumers (§22 signer, the
    // reproducibility diff) byte-equal the file regardless.
    let json = match serde_json::to_string_pretty(&env) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hippius-uki-measure: serialize: {e}");
            return ExitCode::from(1);
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = fs::write(path, &json) {
                eprintln!("hippius-uki-measure: write {path:?}: {e}");
                return ExitCode::from(1);
            }
        }
        None => println!("{json}"),
    }
    ExitCode::from(0)
}

#[derive(Debug, thiserror::Error)]
enum MeasureError {
    #[error("read {0} from {1:?}: {2}")]
    Read(&'static str, PathBuf, std::io::Error),
    #[cfg(feature = "snp")]
    #[error("--ovmf is required for the SNP launch digest")]
    MissingOvmf,
    #[cfg(feature = "snp")]
    #[error("--rootfs-verity-root is required for the SNP launch digest")]
    MissingVerityRoot,
    #[cfg(feature = "snp")]
    #[error("--diskless and --rootfs-verity-root are mutually exclusive (a diskless UKI has no rootfs to anchor)")]
    DisklessWithVerityRoot,
    #[cfg(feature = "snp")]
    #[error("--rootfs-verity-root {0:?} is not 64 lowercase-hex chars (a SHA-256 root hash)")]
    BadVerityRoot(String),
    #[cfg(feature = "snp")]
    #[error("cmdline file is not valid UTF-8")]
    CmdlineNotUtf8,
    #[cfg(feature = "snp")]
    #[error("unknown --vcpu-type {0:?} (expected an EPYC model, e.g. EpycV4)")]
    BadVcpuType(String),
    #[cfg(feature = "snp")]
    #[error("--guest-features {0:?} is not a valid u64 bitmap")]
    BadGuestFeatures(String),
    #[cfg(feature = "snp")]
    #[error("SEV-SNP launch digest: {0}")]
    Sev(#[from] sev::error::MeasurementError),
}

// ── Tests: default build (uki_sha384) ───────────────────────────────

#[cfg(all(test, not(feature = "snp")))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    fn fixture(tmp: &Path) -> Args {
        Args {
            uki: write_file(tmp, "kbs.uki", b"fake-uki-bytes"),
            kernel: write_file(tmp, "vmlinuz", b"fake-kernel"),
            initrd: write_file(tmp, "initrd.cpio", b"fake-initrd"),
            cmdline: write_file(tmp, "cmdline", b"quiet panic=0"),
            out: None,
            ovmf: None,
            rootfs_verity_root: None,
            diskless: false,
            vcpus: 1,
            vcpu_type: "EpycGenoa".to_string(),
            guest_features: "0x1".to_string(),
        }
    }

    #[test]
    fn default_kind_is_uki_sha384_placeholder() {
        let tmp = TempDir::new().unwrap();
        let env = build_envelope(&fixture(tmp.path())).unwrap();
        // The §22 signer enforces this discriminator; the `snp` build
        // bumps it to `snp_launch_digest_v1`.
        assert_eq!(env.measurement_kind, "uki_sha384");
    }

    #[test]
    fn measurement_is_sha384_of_uki_bytes() {
        let tmp = TempDir::new().unwrap();
        let env = build_envelope(&fixture(tmp.path())).unwrap();
        assert_eq!(
            env.measurement_hex,
            hex::encode(Sha384::digest(b"fake-uki-bytes"))
        );
        assert_eq!(env.measurement_hex.len(), 96);
    }

    #[test]
    fn components_have_per_input_sha256() {
        let tmp = TempDir::new().unwrap();
        let env = build_envelope(&fixture(tmp.path())).unwrap();
        assert_eq!(
            env.components.kernel_sha256,
            hex::encode(Sha256::digest(b"fake-kernel"))
        );
        assert_eq!(
            env.components.initrd_sha256,
            hex::encode(Sha256::digest(b"fake-initrd"))
        );
        assert_eq!(
            env.components.cmdline_sha256,
            hex::encode(Sha256::digest(b"quiet panic=0"))
        );
    }

    #[test]
    fn default_components_omit_snp_only_fields() {
        let tmp = TempDir::new().unwrap();
        let env = build_envelope(&fixture(tmp.path())).unwrap();
        assert!(env.components.ovmf_sha256.is_none());
        assert!(env.components.rootfs_verity_root.is_none());
        assert!(env.components.snp_launch_config.is_none());
        // The skipped Options keep the default envelope byte-shape
        // exactly what PR-F2 consumers parse.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("ovmf_sha256"));
        assert!(!json.contains("snp_launch_config"));
    }

    #[test]
    fn measurement_is_deterministic_across_runs() {
        let tmp = TempDir::new().unwrap();
        let a = build_envelope(&fixture(tmp.path())).unwrap();
        let b = build_envelope(&fixture(tmp.path())).unwrap();
        assert_eq!(a.measurement_hex, b.measurement_hex);
    }

    #[test]
    fn json_envelope_is_path_independent() {
        let tmp_a = TempDir::new().unwrap();
        let tmp_b = TempDir::new().unwrap();
        let a = serde_json::to_string(&build_envelope(&fixture(tmp_a.path())).unwrap()).unwrap();
        let b = serde_json::to_string(&build_envelope(&fixture(tmp_b.path())).unwrap()).unwrap();
        assert_eq!(a, b, "envelope must be byte-identical across dirs");
    }

    #[test]
    fn missing_uki_returns_read_error() {
        let tmp = TempDir::new().unwrap();
        let mut args = fixture(tmp.path());
        args.uki = tmp.path().join("does-not-exist");
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::Read("uki", _, _))
        ));
    }
}

// ── Tests: `--features snp` (snp_launch_digest_v1) ──────────────────

#[cfg(all(test, feature = "snp"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod snp_tests {
    use super::*;

    /// `test_vectors/snp/` — pinned inputs for the known-answer test.
    fn vectors_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/snp")
    }

    fn snp_fixture() -> Args {
        let v = vectors_dir();
        Args {
            uki: v.join("uki.bin"),
            kernel: v.join("kernel.bin"),
            initrd: v.join("initrd.bin"),
            cmdline: v.join("cmdline"),
            out: None,
            ovmf: Some(v.join("ovmf.bin")),
            rootfs_verity_root: Some(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            ),
            diskless: false,
            vcpus: 1,
            vcpu_type: "EpycGenoa".to_string(),
            guest_features: "0x1".to_string(),
        }
    }

    /// Known-answer vector. Frozen so a `sev`-crate bump that changes
    /// the digest computation fails CI loudly instead of silently
    /// shifting every production measurement. Computed by
    /// `snp_calc_launch_digest` over the pinned `test_vectors/snp/`
    /// tuple using our vendored sev (`vendor/sev/`, 7.1.0 with the
    /// `EpycGenoa` stepping=1 patch — see `vendor/sev/HIPPIUS_PATCH.md`).
    /// Regenerate deliberately (and re-attest the §22 allowlist) via
    /// `test_vectors/snp/REGENERATE.md`.
    const EXPECTED_SNP_DIGEST: &str =
        "b98f249b158891a3d1bd5e5e136be52daabf42f1c87571649f0186086d1f907b3debcbdfac7e52498555334f937ed794";

    #[test]
    fn snp_kind_is_snp_launch_digest_v1() {
        let env = build_envelope(&snp_fixture()).unwrap();
        assert_eq!(env.measurement_kind, "snp_launch_digest_v1");
    }

    #[test]
    fn snp_digest_is_48_bytes() {
        let env = build_envelope(&snp_fixture()).unwrap();
        assert_eq!(
            env.measurement_hex.len(),
            96,
            "SNP launch digest is 48 bytes"
        );
        assert!(env.measurement_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn snp_digest_matches_known_answer() {
        let env = build_envelope(&snp_fixture()).unwrap();
        assert_eq!(
            env.measurement_hex, EXPECTED_SNP_DIGEST,
            "SNP launch digest changed — a sev-crate bump or fixture edit \
             shifted the measurement. If intentional, regenerate per \
             test_vectors/snp/REGENERATE.md and re-attest the §22 allowlist."
        );
    }

    #[test]
    fn snp_digest_is_deterministic() {
        let a = build_envelope(&snp_fixture()).unwrap();
        let b = build_envelope(&snp_fixture()).unwrap();
        assert_eq!(a.measurement_hex, b.measurement_hex);
    }

    #[test]
    fn snp_components_carry_the_audit_trail() {
        let env = build_envelope(&snp_fixture()).unwrap();
        assert!(env.components.ovmf_sha256.is_some());
        let cfg = env.components.snp_launch_config.unwrap();
        assert_eq!(cfg.vcpus, 1);
        assert_eq!(cfg.vcpu_type, "EpycGenoa");
        assert_eq!(
            env.components.rootfs_verity_root.unwrap().len(),
            64,
            "verity root hash is a 32-byte SHA-256"
        );
    }

    #[test]
    fn snp_requires_ovmf() {
        let mut args = snp_fixture();
        args.ovmf = None;
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::MissingOvmf)
        ));
    }

    #[test]
    fn snp_requires_verity_root() {
        let mut args = snp_fixture();
        args.rootfs_verity_root = None;
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::MissingVerityRoot)
        ));
    }

    #[test]
    fn snp_rejects_malformed_verity_root() {
        // Uppercase hex, wrong length, and non-hex must all fail closed.
        for bad in [
            "00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff",
            "abc123",
            "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ] {
            let mut args = snp_fixture();
            args.rootfs_verity_root = Some(bad.to_string());
            assert!(
                matches!(build_envelope(&args), Err(MeasureError::BadVerityRoot(_))),
                "expected BadVerityRoot for {bad:?}"
            );
        }
    }

    #[test]
    fn snp_rejects_unknown_vcpu_type() {
        let mut args = snp_fixture();
        args.vcpu_type = "PentiumII".to_string();
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::BadVcpuType(_))
        ));
    }

    #[test]
    fn snp_accepts_turin_vcpu_type() {
        // The build-time allowlist path must be able to measure a Turin
        // (EPYC 9255) UKI: `--vcpu-type EpycTurin` is accepted and folds
        // the genuine silicon signature into a distinct digest.
        let mut args = snp_fixture();
        args.vcpu_type = "EpycTurin".to_string();
        let env = build_envelope(&args).unwrap();
        assert_eq!(env.measurement_kind, "snp_launch_digest_v1");
        // Distinct from the frozen Genoa digest — the cpu_sig differs.
        assert_ne!(env.measurement_hex, EXPECTED_SNP_DIGEST);
        assert_eq!(
            env.components.snp_launch_config.unwrap().vcpu_type,
            "EpycTurin"
        );
    }

    #[test]
    fn snp_rejects_bad_guest_features() {
        let mut args = snp_fixture();
        args.guest_features = "not-a-number".to_string();
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::BadGuestFeatures(_))
        ));
    }

    // ── Diskless (blackbox host-attestor UKI) ───────────────────────

    /// The diskless blackbox fixture: initrd-as-root, so NO verity root.
    fn diskless_fixture() -> Args {
        let mut args = snp_fixture();
        args.diskless = true;
        args.rootfs_verity_root = None;
        args
    }

    #[test]
    fn diskless_produces_snp_digest_without_verity_root() {
        // A diskless UKI still yields a real `snp_launch_digest_v1` (over
        // OVMF + kernel + initrd + cmdline); it just carries no rootfs
        // anchor, so the audit field is omitted.
        let env = build_envelope(&diskless_fixture()).unwrap();
        assert_eq!(env.measurement_kind, "snp_launch_digest_v1");
        assert_eq!(env.measurement_hex.len(), 96);
        assert!(env.components.rootfs_verity_root.is_none());
        // OVMF + launch-config audit fields are still present.
        assert!(env.components.ovmf_sha256.is_some());
        assert!(env.components.snp_launch_config.is_some());
        // The omitted anchor must not leak into the JSON.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("rootfs_verity_root"));
    }

    #[test]
    fn diskless_is_deterministic() {
        let a = build_envelope(&diskless_fixture()).unwrap();
        let b = build_envelope(&diskless_fixture()).unwrap();
        assert_eq!(a.measurement_hex, b.measurement_hex);
    }

    #[test]
    fn diskless_rejects_stray_verity_root() {
        // `--diskless` + `--rootfs-verity-root` is a mis-wired launch
        // config — fail closed, never silently measure a phantom anchor.
        let mut args = diskless_fixture();
        args.rootfs_verity_root =
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string());
        assert!(matches!(
            build_envelope(&args),
            Err(MeasureError::DisklessWithVerityRoot)
        ));
    }
}
