//! Idempotent publish orchestration — push artifact + provenance.
//!
//! `publish` writes two content-addressed objects to an [`ImageStore`]:
//! the artifact (the signed UKI) and its `provenance.cbor`.
//!
//! `publish` **verifies the §22 signature itself** before touching the
//! store — it is a public API and must never push an unverified or
//! wrong-root provenance, even if a caller forgot to verify. It then
//! pins the artifact↔provenance hash binding and the content-addressed
//! key shape.
//!
//! Idempotency contract: re-publishing the **same** `provenance.cbor`
//! is a pair of no-ops, and a crash between the two writes is
//! recovered (both writes always run). Re-*signing* the same artifact
//! with different metadata produces a different `provenance.cbor`;
//! publishing that is a deliberate `ImageStoreError::Conflict` —
//! one artifact has exactly one provenance. Pass a fixed `--built-at`
//! (e.g. `SOURCE_DATE_EPOCH`) so a re-sign is byte-reproducible.

use ed25519_dalek::VerifyingKey;
use hippius_types::provenance::SignedProvenance;
use sha2::{Digest, Sha256};

use crate::build::{provenance_object_key, validate_artifact_key};
use crate::error::{Error, Result};
use crate::sign::verify_provenance;
use crate::store::{ImageStore, PutOutcome, PutReceipt};

/// Outcome of a [`publish`] call.
#[derive(Debug, Clone)]
pub struct PublishReport {
    pub artifact_key: String,
    pub artifact: PutReceipt,
    pub provenance_key: String,
    pub provenance: PutReceipt,
}

impl PublishReport {
    /// True iff both objects were already present — i.e. this image
    /// hash had been fully published by an earlier run.
    pub fn was_already_published(&self) -> bool {
        self.artifact.outcome == PutOutcome::AlreadyPresent
            && self.provenance.outcome == PutOutcome::AlreadyPresent
    }
}

/// Verify a signed provenance against `expected_root`, then
/// idempotently publish the artifact and the provenance.
pub fn publish(
    store: &dyn ImageStore,
    signed_provenance: &SignedProvenance,
    artifact_bytes: &[u8],
    expected_root: &VerifyingKey,
) -> Result<PublishReport> {
    // Authoritative gate: verify the §22 signature here. `publish` is
    // a public API — it must never push an unverified or wrong-root
    // provenance, regardless of what the caller did beforehand.
    let map = verify_provenance(signed_provenance, expected_root)?;

    // Integrity gate: the artifact MUST hash to what the signed
    // provenance commits to. A mismatch means the wrong file was
    // handed in — fail closed before touching the store.
    let actual_sha: [u8; 32] = Sha256::digest(artifact_bytes).into();
    if actual_sha != map.artifact_sha256 {
        return Err(Error::ArtifactMismatch(format!(
            "artifact SHA-256 {} does not match the signed provenance's artifact_sha256 {}",
            hex::encode(actual_sha),
            hex::encode(map.artifact_sha256)
        )));
    }

    // Key-shape gate: the signed `s3_key` MUST be the content address
    // of this artifact. A signed map could otherwise park the image
    // at an arbitrary key, defeating content-addressed idempotency.
    validate_artifact_key(&map.s3_key, &map.artifact_sha256)?;

    let provenance_bytes = signed_provenance.encode()?;
    let artifact_key = map.s3_key.clone();
    let provenance_key = provenance_object_key(&map.artifact_sha256);

    // Both puts always run (idempotent) so a prior run that crashed
    // after the artifact write but before the provenance write is
    // completed here.
    let artifact = store.put(&artifact_key, artifact_bytes)?;
    let provenance = store.put(&provenance_key, &provenance_bytes)?;

    Ok(PublishReport {
        artifact_key,
        artifact,
        provenance_key,
        provenance,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::sign::{public_key_bytes, sign_provenance};
    use crate::store::MemoryImageStore;
    use ed25519_dalek::SigningKey;
    use hippius_types::provenance::{
        ProvenanceMap, SnpLaunchConfig, LAUNCH_MEASUREMENT_LEN, MEASUREMENT_KIND_SNP,
        PROVENANCE_SCHEMA_VERSION, SHA256_LEN,
    };

    /// Build a provenance map for `artifact` with `artifact_sha256` +
    /// the content-addressed `s3_key` correctly set.
    fn map_for(sk: &SigningKey, artifact: &[u8]) -> ProvenanceMap {
        let artifact_sha256: [u8; SHA256_LEN] = Sha256::digest(artifact).into();
        ProvenanceMap {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            measurement_kind: MEASUREMENT_KIND_SNP.to_string(),
            launch_measurement: [0xC1; LAUNCH_MEASUREMENT_LEN],
            artifact_sha256,
            verity_root_hash: [0xC3; SHA256_LEN],
            kernel_sha256: [0xC4; SHA256_LEN],
            initrd_sha256: [0xC5; SHA256_LEN],
            cmdline_sha256: [0xC6; SHA256_LEN],
            ovmf_sha256: [0xC7; SHA256_LEN],
            snp_launch_config: SnpLaunchConfig {
                vcpus: 2,
                vcpu_type: "EpycV4".to_string(),
                guest_features: "0x1".to_string(),
            },
            s3_bucket: "hippius-compute-images".to_string(),
            s3_key: format!("images/{}/kbs.uki", hex::encode(artifact_sha256)),
            built_at_unix: 1_700_000_000,
            signer_pubkey: public_key_bytes(sk),
        }
    }

    /// A signed provenance for `artifact`, with everything well-formed.
    fn signed_for(sk: &SigningKey, artifact: &[u8]) -> SignedProvenance {
        sign_provenance(sk, &map_for(sk, artifact)).unwrap()
    }

    #[test]
    fn first_publish_creates_both_objects() {
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let artifact = b"the-uki-bytes".to_vec();
        let signed = signed_for(&sk, &artifact);

        let report = publish(&store, &signed, &artifact, &sk.verifying_key()).unwrap();
        assert_eq!(report.artifact.outcome, PutOutcome::Created);
        assert_eq!(report.provenance.outcome, PutOutcome::Created);
        assert!(!report.was_already_published());
        assert_eq!(store.len().unwrap(), 2);
    }

    #[test]
    fn re_publish_is_an_idempotent_noop() {
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let artifact = b"the-uki-bytes".to_vec();
        let signed = signed_for(&sk, &artifact);

        publish(&store, &signed, &artifact, &sk.verifying_key()).unwrap();
        let second = publish(&store, &signed, &artifact, &sk.verifying_key()).unwrap();
        assert!(second.was_already_published());
        // Still exactly two objects — no duplication.
        assert_eq!(store.len().unwrap(), 2);
    }

    #[test]
    fn publish_rejects_an_unverifiable_provenance() {
        // `publish` verifies the §22 signature itself — a provenance
        // signed by the wrong key is refused before anything is stored,
        // even though the artifact hash + schema are fine.
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let artifact = b"the-uki-bytes".to_vec();
        let signed = signed_for(&sk, &artifact);
        let wrong_root = SigningKey::from_bytes(&[6u8; 32]).verifying_key();
        assert!(matches!(
            publish(&store, &signed, &artifact, &wrong_root),
            Err(Error::Signature(_))
        ));
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn publish_rejects_a_non_content_addressed_s3_key() {
        // A signed provenance whose `s3_key` is not the artifact's
        // content address must be refused — a verified image cannot be
        // parked at an attacker-chosen key.
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let artifact = b"the-uki-bytes".to_vec();
        let mut map = map_for(&sk, &artifact);
        map.s3_key = "images/deadbeef/evil.uki".to_string(); // wrong prefix
        let signed = sign_provenance(&sk, &map).unwrap();
        assert!(matches!(
            publish(&store, &signed, &artifact, &sk.verifying_key()),
            Err(Error::ArtifactMismatch(_))
        ));
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn publish_rejects_an_artifact_that_does_not_match_provenance() {
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let signed = signed_for(&sk, b"the-real-uki");
        // Hand `publish` a different artifact than the one signed.
        assert!(matches!(
            publish(&store, &signed, b"a-different-uki", &sk.verifying_key()),
            Err(Error::ArtifactMismatch(_))
        ));
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn publish_recovers_a_partial_prior_run() {
        // Simulate a prior run that wrote the artifact but crashed
        // before the provenance: publish must complete the provenance.
        let store = MemoryImageStore::new();
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let artifact = b"the-uki-bytes".to_vec();
        let signed = signed_for(&sk, &artifact);
        let map = ProvenanceMap::decode(&signed.body).unwrap();
        store.put(&map.s3_key, &artifact).unwrap(); // artifact only

        let report = publish(&store, &signed, &artifact, &sk.verifying_key()).unwrap();
        assert_eq!(report.artifact.outcome, PutOutcome::AlreadyPresent);
        assert_eq!(report.provenance.outcome, PutOutcome::Created);
        assert_eq!(store.len().unwrap(), 2);
    }
}
