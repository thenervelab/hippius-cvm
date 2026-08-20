//! Parser for the `hippius-uki-measure` JSON envelope.
//!
//! This is the input to provenance: the envelope `binaries/uki-measure`
//! emits for an SNP build. The structs mirror that tool's `Envelope`
//! exactly and use `deny_unknown_fields` — a schema drift in the
//! measure tool must surface here as a loud parse error, never a
//! silently-dropped field.

use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The full `hippius-uki-measure` envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementEnvelope {
    /// `"snp_launch_digest_v1"` for an SNP build, `"uki_sha384"` for a
    /// placeholder build. Provenance requires the former.
    pub measurement_kind: String,
    /// Hex of the measurement bytes (96 hex chars for an SNP digest).
    pub measurement_hex: String,
    pub components: MeasurementComponents,
    /// UKI filename only (no path) — see `hippius-uki-measure`.
    pub uki_basename: String,
    pub uki_size_bytes: u64,
    /// Human-readable provenance note; carried but unused here.
    pub note: String,
}

/// The `components` block: per-input fingerprints. The SNP-only fields
/// are `Option` because a placeholder build omits them — provenance
/// then fails closed when it finds them absent.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementComponents {
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub cmdline_sha256: String,
    pub ovmf_sha256: Option<String>,
    pub rootfs_verity_root: Option<String>,
    pub snp_launch_config: Option<SnpLaunchConfigJson>,
}

/// The pinned launch config recorded by `hippius-uki-measure`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpLaunchConfigJson {
    pub vcpus: u32,
    pub vcpu_type: String,
    pub guest_features: String,
}

impl MeasurementEnvelope {
    /// Read + parse a measurement envelope from a JSON file.
    pub fn load(path: &Path) -> Result<MeasurementEnvelope> {
        let bytes = std::fs::read(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| Error::MeasurementJson {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SNP_ENVELOPE: &str = r#"{
      "measurement_kind": "snp_launch_digest_v1",
      "measurement_hex": "aa",
      "components": {
        "kernel_sha256": "11",
        "initrd_sha256": "22",
        "cmdline_sha256": "33",
        "ovmf_sha256": "44",
        "rootfs_verity_root": "55",
        "snp_launch_config": { "vcpus": 1, "vcpu_type": "EpycV4", "guest_features": "0x1" }
      },
      "uki_basename": "kbs.uki",
      "uki_size_bytes": 4096,
      "note": "test"
    }"#;

    #[test]
    fn parses_a_full_snp_envelope() {
        let env: MeasurementEnvelope = serde_json::from_str(SNP_ENVELOPE).unwrap();
        assert_eq!(env.measurement_kind, "snp_launch_digest_v1");
        assert_eq!(env.components.snp_launch_config.unwrap().vcpus, 1);
    }

    #[test]
    fn rejects_an_unknown_field() {
        // `deny_unknown_fields` — a drift in the measure tool fails loud.
        let drifted = SNP_ENVELOPE.replace(r#""note": "test""#, r#""note": "t", "rogue": 1"#);
        assert!(serde_json::from_str::<MeasurementEnvelope>(&drifted).is_err());
    }

    #[test]
    fn parses_a_placeholder_envelope_without_snp_fields() {
        // A default `uki_sha384` build omits the SNP-only fields; the
        // parse must still succeed (build-time rejects it, not parse).
        let placeholder = r#"{
          "measurement_kind": "uki_sha384",
          "measurement_hex": "bb",
          "components": {
            "kernel_sha256": "11", "initrd_sha256": "22", "cmdline_sha256": "33"
          },
          "uki_basename": "kbs.uki", "uki_size_bytes": 1, "note": "n"
        }"#;
        let env: MeasurementEnvelope = serde_json::from_str(placeholder).unwrap();
        assert!(env.components.ovmf_sha256.is_none());
    }
}
