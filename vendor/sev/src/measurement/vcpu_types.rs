// SPDX-License-Identifier: Apache-2.0

//! Exisiting AMD EPYC vCPUs
use std::{convert::TryFrom, fmt};

use crate::error::MeasurementError;

/// All currently available QEMU vCPU types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CpuType {
    /// EPYC
    Epyc,
    /// EPYC V1
    EpycV1,
    /// EPYC V2
    EpycV2,
    /// EPYC Indirect Branch Predictor Barrier
    EpycIBPB,
    /// EPYC V3
    EpycV3,
    /// EPYC V4
    EpycV4,
    /// EPYC ROME
    EpycRome,
    /// EPYC ROME V1
    EpycRomeV1,
    /// EPYC ROME V2
    EpycRomeV2,
    /// EPYC ROME V3
    EpycRomeV3,
    /// EPYC MILAN
    EpycMilan,
    /// EPYC MILAN V1
    EpycMilanV1,
    /// EPYC MILAN V2
    EpycMilanV2,
    /// EPYC GENOA
    EpycGenoa,
    /// EPYC GENOA V1
    EpycGenoaV1,
    /// EPYC TURIN
    EpycTurin,
    /// EPYC TURIN V1
    EpycTurinV1,
}

impl TryFrom<u8> for CpuType {
    type Error = MeasurementError;

    fn try_from(value: u8) -> Result<Self, MeasurementError> {
        match value {
            0 => Ok(CpuType::Epyc),
            1 => Ok(CpuType::EpycV1),
            3 => Ok(CpuType::EpycIBPB),
            4 => Ok(CpuType::EpycV3),
            5 => Ok(CpuType::EpycV4),
            6 => Ok(CpuType::EpycRome),
            7 => Ok(CpuType::EpycRomeV1),
            8 => Ok(CpuType::EpycRomeV2),
            9 => Ok(CpuType::EpycRomeV3),
            10 => Ok(CpuType::EpycMilan),
            11 => Ok(CpuType::EpycMilanV1),
            12 => Ok(CpuType::EpycMilanV2),
            13 => Ok(CpuType::EpycGenoa),
            14 => Ok(CpuType::EpycGenoaV1),
            15 => Ok(CpuType::EpycTurin),
            16 => Ok(CpuType::EpycTurinV1),
            _ => Err(MeasurementError::InvalidVcpuTypeError(value.to_string())),
        }
    }
}

impl TryFrom<i32> for CpuType {
    type Error = MeasurementError;

    fn try_from(value: i32) -> Result<Self, MeasurementError> {
        match value {
            sig if sig == cpu_sig(23, 1, 2) => Ok(CpuType::Epyc),
            sig if sig == cpu_sig(23, 49, 0) => Ok(CpuType::EpycRome),
            sig if sig == cpu_sig(25, 1, 1) => Ok(CpuType::EpycMilan),
            sig if sig == cpu_sig(25, 17, 0) => Ok(CpuType::EpycGenoa),
            // HIPPIUS PATCH: real EPYC 9255 Turin silicon reports
            // family=26, model=2, stepping=1 (CPUID 0x00B00F21) — see
            // the `sig()` note below.
            sig if sig == cpu_sig(26, 2, 1) => Ok(CpuType::EpycTurin),
            _ => Err(MeasurementError::InvalidVcpuSignatureError(
                value.to_string(),
            )),
        }
    }
}

impl CpuType {
    /// Matching CPU-Type with its CPU signature
    ///
    /// HIPPIUS PATCH (see ../../HIPPIUS_PATCH.md): upstream sev 7.1.0
    /// ships `EpycGenoa => cpu_sig(25, 17, 0)` (stepping=0). Real Genoa
    /// silicon (measured on an EPYC 9254) reports stepping=1
    /// (CPUID 0x00A10F11). QEMU `-cpu host` writes the actual silicon
    /// CPUID into the BSP VMSA's rdx field, so AMD-SP's launch_digest
    /// is computed over different VMSA bytes than `snp_calc_launch_digest`
    /// predicted upstream → every §22 allowlist entry was 8 bytes off
    /// and every KBS release fail-closed `attestation: measurement not
    /// in ticket's allowed set`. Proven 2026-05-26 with a patched local
    /// build; this vendor copy bakes the fix.
    pub fn sig(&self) -> i32 {
        match self {
            CpuType::Epyc => cpu_sig(23, 1, 2),
            CpuType::EpycV1 => cpu_sig(23, 1, 2),
            CpuType::EpycV2 => cpu_sig(23, 1, 2),
            CpuType::EpycIBPB => cpu_sig(23, 1, 2),
            CpuType::EpycV3 => cpu_sig(23, 1, 2),
            CpuType::EpycV4 => cpu_sig(23, 1, 2),
            CpuType::EpycRome => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV1 => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV2 => cpu_sig(23, 49, 0),
            CpuType::EpycRomeV3 => cpu_sig(23, 49, 0),
            CpuType::EpycMilan => cpu_sig(25, 1, 1),
            CpuType::EpycMilanV1 => cpu_sig(25, 1, 1),
            CpuType::EpycMilanV2 => cpu_sig(25, 1, 1),
            // HIPPIUS PATCH: stepping=1 (upstream: 0). See above.
            CpuType::EpycGenoa => cpu_sig(25, 17, 1),
            CpuType::EpycGenoaV1 => cpu_sig(25, 17, 0),
            // HIPPIUS PATCH: upstream sev (PR #392) ships
            // `EpycTurin => cpu_sig(26, 0, 0)` (model=0, stepping=0) =
            // CPUID 0x00B00F00 — a generic family-26 placeholder, NOT
            // any shipping silicon. Real Turin silicon (measured on an
            // EPYC 9255) reports family=26, model=2,
            // stepping=1, i.e. CPUID 0x00B00F21 — read straight off
            // `/dev/cpu/0/cpuid` leaf 1 EAX on an EPYC 9255 host:
            // `0x00B00F21`, and `cpu_sig(26, 2, 1) == 0x00B00F21`
            // byte-for-byte. QEMU `-cpu host` writes the actual silicon
            // CPUID into the BSP VMSA's rdx field, so AMD-SP's
            // launch_digest is computed over *these* VMSA bytes — the
            // generic `cpu_sig(26, 0, 0)` would be 0x21 off in the RDX
            // low byte and every KBS release would fail-closed
            // `attestation: measurement not in ticket's allowed set`,
            // exactly the Genoa-stepping bug above. We therefore pin the
            // genuine silicon value, not the upstream placeholder.
            CpuType::EpycTurin => cpu_sig(26, 2, 1),
            CpuType::EpycTurinV1 => cpu_sig(26, 0, 0),
        }
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuType::Epyc => write!(f, "EPYC"),
            CpuType::EpycV1 => write!(f, "EPYC-v1"),
            CpuType::EpycV2 => write!(f, "EPYC-v2"),
            CpuType::EpycIBPB => write!(f, "EPYC-IBPB"),
            CpuType::EpycV3 => write!(f, "EPYC-v3"),
            CpuType::EpycV4 => write!(f, "EPYC-v4"),
            CpuType::EpycRome => write!(f, "EPYC-Rome"),
            CpuType::EpycRomeV1 => write!(f, "EPYC-Rome-v1"),
            CpuType::EpycRomeV2 => write!(f, "EPYC-Rome-v2"),
            CpuType::EpycRomeV3 => write!(f, "EPYC-Rome-v3"),
            CpuType::EpycMilan => write!(f, "EPYC-Milan"),
            CpuType::EpycMilanV1 => write!(f, "EPYC-Milan-v1"),
            CpuType::EpycMilanV2 => write!(f, "EPYC-Milan-v2"),
            CpuType::EpycGenoa => write!(f, "EPYC-Genoa"),
            CpuType::EpycGenoaV1 => write!(f, "EPYC-Genoa-v1"),
            CpuType::EpycTurin => write!(f, "EPYC-Turin"),
            CpuType::EpycTurinV1 => write!(f, "EPYC-Turin-v1"),
        }
    }
}

impl TryFrom<&str> for CpuType {
    type Error = MeasurementError;

    fn try_from(value: &str) -> Result<Self, MeasurementError> {
        match value.to_lowercase().as_str() {
            "epyc" => Ok(CpuType::Epyc),
            "epyc-v1" => Ok(CpuType::EpycV1),
            "epyc-v2" => Ok(CpuType::EpycV2),
            "epyc-ibpb" => Ok(CpuType::EpycIBPB),
            "epyc-v3" => Ok(CpuType::EpycV3),
            "epyc-v4" => Ok(CpuType::EpycV4),
            "epyc-rome" => Ok(CpuType::EpycRome),
            "epyc-rome-v1" => Ok(CpuType::EpycRomeV1),
            "epyc-rome-v2" => Ok(CpuType::EpycRomeV2),
            "epyc-rome-v3" => Ok(CpuType::EpycRomeV3),
            "epyc-milan" => Ok(CpuType::EpycMilan),
            "epyc-milan-v1" => Ok(CpuType::EpycMilanV1),
            "epyc-milan-v2" => Ok(CpuType::EpycMilanV2),
            "epyc-genoa" => Ok(CpuType::EpycGenoa),
            "epyc-genoa-v1" => Ok(CpuType::EpycGenoaV1),
            "epyc-turin" => Ok(CpuType::EpycTurin),
            "epyc-turin-v1" => Ok(CpuType::EpycTurinV1),
            _ => Err(MeasurementError::InvalidVcpuTypeError(value.to_string())),
        }
    }
}

/// Compute the 32-bit CPUID signature from family, model, and stepping.
///
/// This computation is described in AMD's CPUID Specification, publication #25481
/// https://www.amd.com/system/files/TechDocs/25481.pdf
/// See section: CPUID Fn0000_0001_EAX Family, Model, Stepping Identifiers
pub fn cpu_sig(family: i32, model: i32, stepping: i32) -> i32 {
    let family_low;
    let family_high;

    if family > 0xf {
        family_low = 0xf;
        family_high = (family - 0x0f) & 0xff;
    } else {
        family_low = family;
        family_high = 0;
    }

    let model_low = model & 0xf;
    let model_high = (model >> 4) & 0xf;

    let stepping_low = stepping & 0xf;

    (family_high << 20) | (model_high << 16) | (family_low << 8) | (model_low << 4) | stepping_low
}
