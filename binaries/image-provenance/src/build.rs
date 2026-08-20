//! Build a [`ProvenanceMap`] from a measurement envelope + artifact.
//!
//! This is the "map launch digest → all inputs" step. It is
//! fail-closed: a non-SNP envelope, a missing SNP field, a malformed
//! hex digest, or an artifact that does not match the measured one all
//! abort before any provenance map is produced.

use std::path::Path;

use hippius_types::provenance::{
    ProvenanceMap, SnpLaunchConfig, LAUNCH_MEASUREMENT_LEN, MEASUREMENT_KIND_SNP,
    PROVENANCE_SCHEMA_VERSION, SHA256_LEN,
};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::measurement::MeasurementEnvelope;

/// The content-addressed S3 key prefix. Every object for one image
/// (the artifact + its `provenance.cbor`) lives under
/// `images/<artifact-sha256-hex>/`.
const KEY_PREFIX: &str = "images";

/// The reserved object name of an image's signed provenance. An
/// artifact may not use this basename — it would collide the artifact
/// key with the provenance key under the same content-addressed prefix.
const PROVENANCE_OBJECT_NAME: &str = "provenance.cbor";

/// Everything `build_provenance` needs that is not in the envelope.
pub struct BuildInputs<'a> {
    pub envelope: &'a MeasurementEnvelope,
    /// Raw bytes of the published artifact (the signed UKI). Its
    /// SHA-256 becomes `artifact_sha256` and the content address.
    pub artifact_bytes: &'a [u8],
    /// Target S3 bucket (e.g. `hippius-compute-images`).
    pub s3_bucket: &'a str,
    /// Unix seconds the provenance was built. Passed in explicitly —
    /// never read from the wall clock here — so callers (and the KAT)
    /// stay deterministic.
    pub built_at_unix: u64,
    /// The §22 root public key that will sign the map.
    pub signer_pubkey: [u8; SHA256_LEN],
}

/// Build the provenance map for one measured image.
pub fn build_provenance(inputs: &BuildInputs) -> Result<ProvenanceMap> {
    let env = inputs.envelope;

    // Provenance exists to anchor the §22 allowlist, which gates only
    // on the real SEV-SNP launch digest. A `uki_sha384` placeholder
    // has no launch-digest trust value — refuse it outright.
    if env.measurement_kind != MEASUREMENT_KIND_SNP {
        return Err(Error::Measurement(format!(
            "measurement_kind is {:?} — provenance requires {MEASUREMENT_KIND_SNP:?} \
             (a uki_sha384 placeholder build is not a trust anchor)",
            env.measurement_kind
        )));
    }

    validate_basename(&env.uki_basename, "uki_basename")?;
    if inputs.s3_bucket.is_empty() {
        return Err(Error::Field {
            field: "s3_bucket",
            reason: "must not be empty".into(),
        });
    }

    // The artifact passed MUST be the one that was measured — guard
    // against signing provenance for a UKI that was never measured.
    if inputs.artifact_bytes.len() as u64 != env.uki_size_bytes {
        return Err(Error::ArtifactMismatch(format!(
            "artifact is {} bytes but the measurement envelope records {}",
            inputs.artifact_bytes.len(),
            env.uki_size_bytes
        )));
    }

    let launch_measurement =
        decode_hex_array::<LAUNCH_MEASUREMENT_LEN>("measurement_hex", &env.measurement_hex)?;

    let artifact_sha256: [u8; SHA256_LEN] = Sha256::digest(inputs.artifact_bytes).into();
    let kernel_sha256 =
        decode_hex_array::<SHA256_LEN>("components.kernel_sha256", &env.components.kernel_sha256)?;
    let initrd_sha256 =
        decode_hex_array::<SHA256_LEN>("components.initrd_sha256", &env.components.initrd_sha256)?;
    let cmdline_sha256 = decode_hex_array::<SHA256_LEN>(
        "components.cmdline_sha256",
        &env.components.cmdline_sha256,
    )?;

    let ovmf_hex = env
        .components
        .ovmf_sha256
        .as_deref()
        .ok_or_else(|| Error::Measurement("components.ovmf_sha256 is absent".into()))?;
    let ovmf_sha256 = decode_hex_array::<SHA256_LEN>("components.ovmf_sha256", ovmf_hex)?;

    let verity_hex = env
        .components
        .rootfs_verity_root
        .as_deref()
        .ok_or_else(|| Error::Measurement("components.rootfs_verity_root is absent".into()))?;
    let verity_root_hash =
        decode_hex_array::<SHA256_LEN>("components.rootfs_verity_root", verity_hex)?;

    let snp = env
        .components
        .snp_launch_config
        .as_ref()
        .ok_or_else(|| Error::Measurement("components.snp_launch_config is absent".into()))?;

    let s3_key = format!(
        "{KEY_PREFIX}/{}/{}",
        hex::encode(artifact_sha256),
        env.uki_basename
    );

    Ok(ProvenanceMap {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        measurement_kind: MEASUREMENT_KIND_SNP.to_string(),
        launch_measurement,
        artifact_sha256,
        verity_root_hash,
        kernel_sha256,
        initrd_sha256,
        cmdline_sha256,
        ovmf_sha256,
        snp_launch_config: SnpLaunchConfig {
            vcpus: snp.vcpus,
            vcpu_type: snp.vcpu_type.clone(),
            guest_features: snp.guest_features.clone(),
        },
        s3_bucket: inputs.s3_bucket.to_string(),
        s3_key,
        built_at_unix: inputs.built_at_unix,
        signer_pubkey: inputs.signer_pubkey,
    })
}

/// The content-addressed S3 key of an image's `provenance.cbor`,
/// derived from the artifact's SHA-256.
pub fn provenance_object_key(artifact_sha256: &[u8; SHA256_LEN]) -> String {
    format!(
        "{KEY_PREFIX}/{}/{PROVENANCE_OBJECT_NAME}",
        hex::encode(artifact_sha256)
    )
}

/// Validate that `s3_key` is the content-addressed key for an artifact
/// with SHA-256 `artifact_sha256` — exactly
/// `images/<artifact-sha256-hex>/<plain-basename>`.
///
/// A signed provenance map could carry any `s3_key` string; the
/// publish path pins it to the content address so a verified image
/// can never be parked at an attacker-chosen key.
pub fn validate_artifact_key(s3_key: &str, artifact_sha256: &[u8; SHA256_LEN]) -> Result<()> {
    let prefix = format!("{KEY_PREFIX}/{}/", hex::encode(artifact_sha256));
    let basename = s3_key.strip_prefix(&prefix).ok_or_else(|| {
        Error::ArtifactMismatch(format!(
            "s3_key {s3_key:?} is not content-addressed under {prefix:?}"
        ))
    })?;
    validate_basename(basename, "s3_key")
}

/// A basename is a plain filename — it forms the tail of an S3 object
/// key, so a path separator or `..` could escape the content-addressed
/// prefix. Reject anything that is not a simple name, and reject the
/// reserved `provenance.cbor` (it would collide an artifact key with
/// the provenance key under the same content-addressed prefix).
fn validate_basename(name: &str, field: &'static str) -> Result<()> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name == PROVENANCE_OBJECT_NAME
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0');
    if bad {
        return Err(Error::Field {
            field,
            reason: format!("{name:?} is not a valid artifact basename"),
        });
    }
    Ok(())
}

/// Hex-decode a field into a fixed-size array, with a precise error.
fn decode_hex_array<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value.trim()).map_err(|e| Error::Field {
        field,
        reason: format!("not valid hex: {e}"),
    })?;
    bytes.as_slice().try_into().map_err(|_| Error::Field {
        field,
        reason: format!("expected {N} bytes, got {}", bytes.len()),
    })
}

/// Read an artifact file fully into memory.
pub fn read_artifact(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::measurement::{MeasurementComponents, SnpLaunchConfigJson};

    fn snp_envelope(artifact_len: u64) -> MeasurementEnvelope {
        MeasurementEnvelope {
            measurement_kind: MEASUREMENT_KIND_SNP.to_string(),
            measurement_hex: "ab".repeat(LAUNCH_MEASUREMENT_LEN),
            components: MeasurementComponents {
                kernel_sha256: "11".repeat(SHA256_LEN),
                initrd_sha256: "22".repeat(SHA256_LEN),
                cmdline_sha256: "33".repeat(SHA256_LEN),
                ovmf_sha256: Some("44".repeat(SHA256_LEN)),
                rootfs_verity_root: Some("55".repeat(SHA256_LEN)),
                snp_launch_config: Some(SnpLaunchConfigJson {
                    vcpus: 1,
                    vcpu_type: "EpycV4".to_string(),
                    guest_features: "0x1".to_string(),
                }),
            },
            uki_basename: "kbs.uki".to_string(),
            uki_size_bytes: artifact_len,
            note: "test".to_string(),
        }
    }

    fn inputs<'a>(env: &'a MeasurementEnvelope, artifact: &'a [u8]) -> BuildInputs<'a> {
        BuildInputs {
            envelope: env,
            artifact_bytes: artifact,
            s3_bucket: "hippius-compute-images",
            built_at_unix: 1_700_000_000,
            signer_pubkey: [0x99; SHA256_LEN],
        }
    }

    #[test]
    fn builds_a_valid_provenance_map() {
        let artifact = b"a-fake-uki-binary".to_vec();
        let env = snp_envelope(artifact.len() as u64);
        let map = build_provenance(&inputs(&env, &artifact)).unwrap();
        // Content-addressed key uses the real artifact SHA-256.
        let expected_sha: [u8; 32] = Sha256::digest(&artifact).into();
        assert_eq!(map.artifact_sha256, expected_sha);
        assert_eq!(
            map.s3_key,
            format!("images/{}/kbs.uki", hex::encode(expected_sha))
        );
        // The map encodes cleanly (all canonical() invariants hold).
        map.canonical().unwrap();
    }

    #[test]
    fn rejects_a_non_snp_envelope() {
        let artifact = b"x".to_vec();
        let mut env = snp_envelope(artifact.len() as u64);
        env.measurement_kind = "uki_sha384".to_string();
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::Measurement(_))
        ));
    }

    #[test]
    fn rejects_a_missing_snp_field() {
        let artifact = b"x".to_vec();
        let mut env = snp_envelope(artifact.len() as u64);
        env.components.rootfs_verity_root = None;
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::Measurement(_))
        ));
    }

    #[test]
    fn rejects_an_artifact_size_mismatch() {
        let artifact = b"actual-bytes".to_vec();
        let env = snp_envelope(artifact.len() as u64 + 1); // envelope lies
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::ArtifactMismatch(_))
        ));
    }

    #[test]
    fn rejects_a_malformed_measurement_hex() {
        let artifact = b"x".to_vec();
        let mut env = snp_envelope(artifact.len() as u64);
        env.measurement_hex = "zz".to_string();
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::Field {
                field: "measurement_hex",
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_path_traversing_basename() {
        let artifact = b"x".to_vec();
        let mut env = snp_envelope(artifact.len() as u64);
        env.uki_basename = "../../etc/evil".to_string();
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::Field {
                field: "uki_basename",
                ..
            })
        ));
    }

    #[test]
    fn rejects_the_reserved_provenance_basename() {
        // A UKI named `provenance.cbor` would collide the artifact key
        // with the provenance key — refuse it.
        let artifact = b"x".to_vec();
        let mut env = snp_envelope(artifact.len() as u64);
        env.uki_basename = "provenance.cbor".to_string();
        assert!(matches!(
            build_provenance(&inputs(&env, &artifact)),
            Err(Error::Field {
                field: "uki_basename",
                ..
            })
        ));
    }

    #[test]
    fn validate_artifact_key_rejects_a_mismatched_prefix() {
        let sha = [0xAB; SHA256_LEN];
        // Right shape, wrong hash prefix.
        assert!(validate_artifact_key("images/0000/kbs.uki", &sha).is_err());
        // Right prefix, path-traversing tail.
        let prefix = format!("images/{}", hex::encode(sha));
        assert!(validate_artifact_key(&format!("{prefix}/../evil"), &sha).is_err());
        // Correct content-addressed key.
        validate_artifact_key(&format!("{prefix}/kbs.uki"), &sha).unwrap();
    }

    #[test]
    fn provenance_key_is_content_addressed() {
        let sha = [0xAB; SHA256_LEN];
        assert_eq!(
            provenance_object_key(&sha),
            format!("images/{}/provenance.cbor", hex::encode(sha))
        );
    }
}
