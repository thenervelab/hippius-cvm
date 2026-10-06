//! `hippius-launch-digest` — independently recompute the SEV-SNP launch
//! digest (audit C2).
//!
//! vali runs this over the launch inputs IT controls — the pinned OVMF
//! plus the kernel / initrd / cmdline / vcpus / vcpu-type / guest-features
//! it baked into the `LaunchOrder` — to get the digest a HONEST guest
//! MUST produce. It then refuses any miner-reported digest that differs,
//! so a miner that boots a BACKDOORED guest (a different measurement)
//! cannot have that measurement auto-pinned into the §22 allowlist and
//! released a tenant KEK.
//!
//! The computation is byte-identical to the miner-agent's
//! `lifecycle::launch_digest` — both call the SAME
//! `sev::measurement::snp::snp_calc_launch_digest` with the SAME
//! `SnpMeasurementArgs` mapping (`ovmf_hash_str = None` ⇒ measure the
//! OVMF file bytes; `vmm_type = None` ⇒ QEMU). So for a legitimate launch
//! vali's value equals the miner's; a mismatch is a real divergence.
//!
//! Prints the 96-hex (48-byte) launch digest to stdout on success.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "hippius-launch-digest", version)]
struct Args {
    /// Pinned OVMF firmware file (measured by its bytes).
    #[arg(long)]
    ovmf: PathBuf,
    /// Guest kernel image (the exact bytes the guest boots).
    #[arg(long)]
    kernel: PathBuf,
    /// Guest initrd cpio archive.
    #[arg(long)]
    initrd: PathBuf,
    /// Kernel cmdline text file. At most one trailing newline is stripped
    /// so `append` matches what the guest boots with (as `ukify` embeds).
    #[arg(long)]
    cmdline: PathBuf,
    /// vCPU count of the measured launch (`flavor.cpu_count`).
    #[arg(long)]
    vcpus: u32,
    /// vCPU model — `EpycMilan` | `EpycGenoa` | `EpycTurin` (from the
    /// miner generation).
    #[arg(long)]
    vcpu_type: String,
    /// SEV-SNP guest-features bitmap (hex `0x…` or decimal). Default
    /// `0x1` = SNPActive — the miner's `SNP_GUEST_FEATURES`.
    #[arg(long, default_value = "0x1")]
    guest_features: String,
}

#[derive(Debug, thiserror::Error)]
// Without `--features snp` only `SnpFeatureDisabled` is constructed (the
// digest path is compiled out); the rest are live under `snp`.
#[cfg_attr(not(feature = "snp"), allow(dead_code))]
enum DigestError {
    #[error("read {0}: {1}")]
    Read(&'static str, std::io::Error),
    #[error("cmdline is not valid UTF-8")]
    CmdlineNotUtf8,
    #[error("unknown --vcpu-type {0:?} (expected EpycMilan | EpycGenoa | EpycTurin | …)")]
    BadVcpuType(String),
    #[error("bad --guest-features {0:?}")]
    BadGuestFeatures(String),
    #[cfg(not(feature = "snp"))]
    #[error("this binary must be built with --features snp")]
    SnpFeatureDisabled,
    #[error("sev launch-digest computation failed")]
    Sev,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(hex) => {
            println!("{hex}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hippius-launch-digest: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "snp"))]
fn run(_args: &Args) -> Result<String, DigestError> {
    Err(DigestError::SnpFeatureDisabled)
}

#[cfg(feature = "snp")]
fn run(args: &Args) -> Result<String, DigestError> {
    snp::launch_digest(args)
}

#[cfg(feature = "snp")]
mod snp {
    use super::{Args, DigestError};
    use sev::measurement::snp::{snp_calc_launch_digest, SnpMeasurementArgs};
    use sev::measurement::vcpu_types::CpuType;
    use sev::measurement::vmsa::GuestFeatures;

    /// Strip exactly one trailing newline (the cmdline file may carry one;
    /// `ukify` embeds none) so `append` matches the booted cmdline.
    fn cmdline_append(args: &Args) -> Result<String, DigestError> {
        let raw = std::fs::read(&args.cmdline).map_err(|e| DigestError::Read("cmdline", e))?;
        let text = String::from_utf8(raw).map_err(|_| DigestError::CmdlineNotUtf8)?;
        Ok(text.strip_suffix('\n').unwrap_or(&text).to_string())
    }

    /// Mirror `uki-measure` / miner-agent's case-insensitive vCPU map.
    fn parse_cpu_type(s: &str) -> Result<CpuType, DigestError> {
        let t = match s.to_ascii_lowercase().as_str() {
            "epyc" => CpuType::Epyc,
            "epyc-v1" | "epycv1" => CpuType::EpycV1,
            "epyc-v2" | "epycv2" => CpuType::EpycV2,
            "epyc-ibpb" | "epycibpb" => CpuType::EpycIBPB,
            "epyc-v3" | "epycv3" => CpuType::EpycV3,
            "epyc-v4" | "epycv4" => CpuType::EpycV4,
            "epyc-rome" | "epycrome" => CpuType::EpycRome,
            "epyc-milan" | "epycmilan" => CpuType::EpycMilan,
            "epyc-genoa" | "epycgenoa" => CpuType::EpycGenoa,
            "epyc-genoa-v1" | "epycgenoav1" => CpuType::EpycGenoaV1,
            "epyc-turin" | "epycturin" => CpuType::EpycTurin,
            "epyc-turin-v1" | "epycturinv1" => CpuType::EpycTurinV1,
            _ => return Err(DigestError::BadVcpuType(s.to_string())),
        };
        Ok(t)
    }

    fn parse_guest_features(s: &str) -> Result<GuestFeatures, DigestError> {
        let trimmed = s.trim();
        let value = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            trimmed.parse::<u64>()
        }
        .map_err(|_| DigestError::BadGuestFeatures(s.to_string()))?;
        Ok(GuestFeatures(value))
    }

    pub(super) fn launch_digest(args: &Args) -> Result<String, DigestError> {
        let append = cmdline_append(args)?;
        let snp_args = SnpMeasurementArgs {
            vcpus: args.vcpus,
            vcpu_type: parse_cpu_type(&args.vcpu_type)?,
            ovmf_file: args.ovmf.clone(),
            guest_features: parse_guest_features(&args.guest_features)?,
            kernel_file: Some(args.kernel.clone()),
            initrd_file: Some(args.initrd.clone()),
            append: Some(append.as_str()),
            ovmf_hash_str: None,
            vmm_type: None,
        };
        let digest = snp_calc_launch_digest(snp_args).map_err(|_| DigestError::Sev)?;
        Ok(digest.get_hex_ld())
    }
}
