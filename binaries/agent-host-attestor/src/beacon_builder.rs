//! Builds and signs the next liveness beacon.
//!
//! The builder holds the per-boot context that is constant across the
//! attestor's lifetime — `node_id`, `boot_id`, the `chain_genesis` /
//! `pallet_instance` replay domains, the enrolled `signer_pubkey`, and
//! the attested [`PlatformClaims`] — plus the one piece of loop state
//! that advances every beacon: the monotonic `seq`. Each
//! [`BeaconBuilder::build_next`] produces ONE
//! [`SignedHostBeacon`](hippius_types::host_attestor::SignedHostBeacon)
//! and advances the sequence — but only AFTER the signature succeeds, so
//! a failed beat burns no sequence number.
//!
//! ## Cheap by design — no SNP report per beat
//!
//! A beacon is an **Ed25519 signature only**: the expensive SNP report
//! is minted ONCE at enrollment. The platform fields (`chip_id`,
//! `measurement`, TCB, `policy`) are the attested values captured at
//! enrollment ([`PlatformClaims`]), so each beat re-asserts the same
//! measured platform without touching `/dev/sev-guest`.

use hippius_types::host_attestor::{
    HostAliveBeacon, PlatformTcb, SignedHostBeacon, CHIP_ID_LEN, DIGEST_LEN, MEASUREMENT_LEN,
    PUBKEY_LEN,
};

use crate::error::{HostAttestorError, Result};
use crate::platform::PlatformClaims;
use crate::signer::HostAttestorSigner;

/// The first `seq` a builder emits. Per PR-1 the first beacon after
/// enrollment uses `1` and each subsequent beacon increments.
const FIRST_SEQ: u64 = 1;

/// Builds successive signed beacons for one enrolled `(node_id, boot_id)`.
pub struct BeaconBuilder {
    node_id: String,
    boot_id: String,
    chain_genesis: [u8; DIGEST_LEN],
    pallet_instance: [u8; DIGEST_LEN],
    signer_pubkey: [u8; PUBKEY_LEN],
    chip_id: [u8; CHIP_ID_LEN],
    measurement: [u8; MEASUREMENT_LEN],
    platform_tcb: PlatformTcb,
    policy: u64,
    /// `seq` for the NEXT beacon.
    next_seq: u64,
}

impl BeaconBuilder {
    /// A builder for the enrolled host.
    ///
    /// `signer_pubkey` MUST be the enrolled key
    /// ([`crate::establish::Established::pubkey`]); `platform` is the
    /// [`PlatformClaims`] lifted from the enrollment report.
    pub fn new(
        node_id: String,
        boot_id: String,
        chain_genesis: [u8; DIGEST_LEN],
        pallet_instance: [u8; DIGEST_LEN],
        signer_pubkey: [u8; PUBKEY_LEN],
        platform: &PlatformClaims,
    ) -> Self {
        Self {
            node_id,
            boot_id,
            chain_genesis,
            pallet_instance,
            signer_pubkey,
            chip_id: platform.chip_id(),
            measurement: platform.measurement(),
            platform_tcb: platform.tcb(),
            policy: platform.policy(),
            next_seq: FIRST_SEQ,
        }
    }

    /// The `seq` the next [`build_next`](Self::build_next) will emit.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Build + sign the beacon observed at `observed_at_unix`.
    ///
    /// `expiry_unix = observed_at_unix + window_secs` (`window_secs`
    /// MUST be ≥ 1 so expiry is strictly after observed — the PR-1
    /// beacon invariant). `nonce` is a fresh single-use nonce.
    ///
    /// On success the builder advances `seq`; on ANY failure it advances
    /// nothing — a failed beat burns no sequence number.
    pub fn build_next(
        &mut self,
        signer: &HostAttestorSigner,
        nonce: [u8; DIGEST_LEN],
        observed_at_unix: u64,
        window_secs: u64,
    ) -> Result<SignedHostBeacon> {
        let expiry_unix = observed_at_unix
            .checked_add(window_secs)
            .ok_or(HostAttestorError::Beacon("expiry-overflow"))?;
        // Compute the post-beacon sequence BEFORE signing, so once a
        // signature exists no fallible step remains — the state commit
        // below is pure infallible assignment.
        let next_seq_after = self
            .next_seq
            .checked_add(1)
            .ok_or(HostAttestorError::Beacon("seq-overflow"))?;

        let beacon = HostAliveBeacon {
            schema_version: hippius_types::host_attestor::HOST_ATTESTOR_SCHEMA_VERSION,
            chain_genesis: self.chain_genesis,
            pallet_instance: self.pallet_instance,
            chip_id: self.chip_id,
            measurement: self.measurement,
            node_id: self.node_id.clone(),
            boot_id: self.boot_id.clone(),
            seq: self.next_seq,
            observed_at_unix,
            platform_tcb: self.platform_tcb,
            policy: self.policy,
            nonce,
            signer_pubkey: self.signer_pubkey,
            expiry_unix,
        };

        // Encode the canonical to-be-signed body (also runs the PR-1
        // `validate`), then Ed25519-sign it. A `canonical()` failure is
        // collapsed to a static class — no inner text reaches a log.
        let body = beacon
            .canonical()
            .map_err(|_| HostAttestorError::Beacon("beacon-encode"))?;
        let sig = signer.sign(&body);
        let signed = SignedHostBeacon { body, sig };

        // Signature obtained — commit. Infallible.
        self.next_seq = next_seq_after;
        Ok(signed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::snp::{SnpReport, SNP_REPORT_LEN};
    use ed25519_dalek::{Signature, Verifier};
    use hippius_types::host_attestor::{HostAliveBeacon, HOST_ATTESTOR_BEACON_DOMAIN};
    use zeroize::Zeroizing;

    fn platform() -> PlatformClaims {
        let mut b = vec![0u8; SNP_REPORT_LEN];
        for (i, byte) in b.iter_mut().skip(0x1A0).take(64).enumerate() {
            *byte = 0x80 | (i as u8);
        }
        PlatformClaims::from_report(&SnpReport(b)).unwrap()
    }

    fn signer() -> HostAttestorSigner {
        HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([3u8; 32])).unwrap()
    }

    fn builder(signer: &HostAttestorSigner) -> BeaconBuilder {
        BeaconBuilder::new(
            "node-host-1".to_string(),
            "boot-abc".to_string(),
            [0xAAu8; DIGEST_LEN],
            [0xDDu8; DIGEST_LEN],
            signer.pubkey(),
            &platform(),
        )
    }

    #[test]
    fn build_next_signs_a_well_formed_beacon() {
        let s = signer();
        let mut b = builder(&s);
        let signed = b
            .build_next(&s, [0x11u8; DIGEST_LEN], 1_800_000_000, 300)
            .unwrap();

        // The body decodes as a beacon with the expected fields.
        let beacon = HostAliveBeacon::decode(&signed.body).unwrap();
        assert_eq!(beacon.seq, 1);
        assert_eq!(beacon.node_id, "node-host-1");
        assert_eq!(beacon.observed_at_unix, 1_800_000_000);
        assert_eq!(beacon.expiry_unix, 1_800_000_300);
        assert_eq!(beacon.signer_pubkey, s.pubkey());
        assert_eq!(beacon.chip_id[0], 0x80);

        // The signature verifies over the canonical body under the
        // enrolled key.
        let sig = Signature::from_bytes(&signed.sig);
        s.verifying_key().verify(&signed.body, &sig).unwrap();
    }

    #[test]
    fn body_leads_with_the_beacon_domain() {
        let s = signer();
        let mut b = builder(&s);
        let signed = b
            .build_next(&s, [0x11u8; DIGEST_LEN], 1_800_000_000, 300)
            .unwrap();
        // The beacon-domain tag is part of the signed body (decode
        // rejects a swapped domain — the frozen wire contract).
        assert!(signed
            .body
            .windows(HOST_ATTESTOR_BEACON_DOMAIN.len())
            .any(|w| w == HOST_ATTESTOR_BEACON_DOMAIN.as_bytes()));
    }

    #[test]
    fn successive_beacons_increment_seq_and_are_byte_distinct() {
        let s = signer();
        let mut b = builder(&s);
        let r1 = b.build_next(&s, [0x01u8; DIGEST_LEN], 1_000, 60).unwrap();
        assert_eq!(b.next_seq(), 2);
        let r2 = b.build_next(&s, [0x02u8; DIGEST_LEN], 1_060, 60).unwrap();
        assert_eq!(b.next_seq(), 3);
        assert_eq!(HostAliveBeacon::decode(&r1.body).unwrap().seq, 1);
        assert_eq!(HostAliveBeacon::decode(&r2.body).unwrap().seq, 2);
        assert_ne!(r1.body, r2.body);
    }

    #[test]
    fn expiry_overflow_fails_and_burns_no_seq() {
        let s = signer();
        let mut b = builder(&s);
        let err = b
            .build_next(&s, [0x11u8; DIGEST_LEN], 200, u64::MAX)
            .expect_err("observed + window overflowing u64 must fail");
        assert_eq!(err.class(), "expiry-overflow");
        assert_eq!(b.next_seq(), 1);
    }

    #[test]
    fn a_wrong_key_does_not_verify_the_beacon() {
        let s = signer();
        let mut b = builder(&s);
        let signed = b.build_next(&s, [0x11u8; DIGEST_LEN], 1_000, 60).unwrap();
        let other = HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([9u8; 32])).unwrap();
        let sig = Signature::from_bytes(&signed.sig);
        assert!(other.verifying_key().verify(&signed.body, &sig).is_err());
    }
}
