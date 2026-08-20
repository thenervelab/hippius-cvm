//! The redeem gate — the security heart of the broker.
//!
//! Pure, trait-driven so it's fully testable without real SNP hardware
//! or a live Vault. The transport (`handlers.rs`) + the concrete
//! [`SelfReportVerifier`] / Vault client / challenge store plug in.
//!
//! Gate order (any failure ⇒ no token minted, fail-closed):
//!
//! 1. **Consume the challenge** (single-use). The nonce must be one the
//!    broker issued, unexpired, unspent, AND bound to *this exact*
//!    scope (a challenge issued for scope A cannot be redeemed for
//!    scope B — anti-scope-swap). Consuming spends it (replay-proof).
//! 2. **Verify the SNP report** via the AMD-rooted [`SelfReportVerifier`].
//! 3. **`REPORT_DATA` binding**: `report_data == challenge_nonce ‖
//!    auth_pubkey`. This is the anti-replay/anti-proxy anchor — the
//!    report was minted by an enclave that knew this fresh nonce + is
//!    bound to this channel key.
//! 4. **KBS measurement ∈ allowlist** — only an allowlisted KBS image
//!    may mint capabilities.
//! 5. **TCB ≥ floor + launch-policy bits** — no rolled-back/debug KBS.
//! 6. **Mint** a per-VM-scoped, short-TTL Vault token.

use hippius_types::vault_broker::{RedeemRequest, RedeemResponse, AUTH_PUBKEY_LEN, NONCE_LEN};
use kbs_core::snp::{LaunchPolicy, VerifiedReport};

use crate::error::BrokerError;

/// Verifies a KBS self-report against the AMD chain, preferring the
/// VEK carried in the report (`vek_der`, from the host PSP cert table)
/// over any operator-mounted fallback. The ARK trust anchor is always
/// built-in. Impl: [`crate::verifier::BrokerVerifier`].
pub trait SelfReportVerifier: Send + Sync {
    fn verify(&self, raw_report: &[u8], vek_der: &[u8]) -> kbs_core::error::Result<VerifiedReport>;
}

/// Issues + consumes single-use challenge nonces, each bound to the
/// scope it was issued for. `consume` MUST be atomic + fail-closed:
/// unknown / expired / already-spent / scope-mismatch all return
/// `Err`, and a successful consume spends the nonce so a replay fails.
pub trait ChallengeStore: Send + Sync {
    /// Bind a fresh nonce to `scope` with `expiry_unix`. Returns the
    /// nonce. (CSPRNG impl in `challenge.rs`.)
    fn issue(
        &self,
        scope: &hippius_types::vault_broker::BrokerScope,
        now_unix: u64,
    ) -> Result<([u8; NONCE_LEN], u64), BrokerError>;

    /// Atomically verify + spend `nonce`: it must exist, be unexpired
    /// at `now_unix`, be unspent, and have been issued for a scope
    /// equal to `scope`. Spends it on success.
    fn consume(
        &self,
        nonce: &[u8; NONCE_LEN],
        scope: &hippius_types::vault_broker::BrokerScope,
        now_unix: u64,
    ) -> Result<(), BrokerError>;
}

/// Decides whether a verified KBS measurement may mint capabilities.
pub trait KbsMeasurementAllowlist: Send + Sync {
    fn accepts(&self, measurement: &[u8; 48]) -> bool;
}

/// Mints a per-VM-scoped, short-TTL Vault token authorizing read on
/// exactly the scope's two `path@version` refs.
pub trait VaultTokenMinter: Send + Sync {
    /// Returns `(token_bytes, expiry_unix)`. The token MUST be a child
    /// token scoped to read-only on `secret/data/<luks_path>` +
    /// `<userdata_path>`, short TTL, num_uses bounded — never a copy of
    /// the broker's own privileged token.
    fn mint_scoped(
        &self,
        scope: &hippius_types::vault_broker::BrokerScope,
        now_unix: u64,
    ) -> Result<(zeroize::Zeroizing<Vec<u8>>, u64), BrokerError>;
}

/// The full redeem decision. See module docs for the gate order.
pub fn redeem(
    req: &RedeemRequest,
    verifier: &dyn SelfReportVerifier,
    challenges: &dyn ChallengeStore,
    allowlist: &dyn KbsMeasurementAllowlist,
    policy: &LaunchPolicy,
    vault: &dyn VaultTokenMinter,
    now_unix: u64,
) -> Result<RedeemResponse, BrokerError> {
    // 0. Shape (defence-in-depth; the decoder already validated).
    req.validate()
        .map_err(|e| BrokerError::BadRequest(format!("{e}")))?;

    // 1. Consume the challenge — single-use, scope-bound, unexpired.
    challenges.consume(&req.challenge_nonce, &req.scope, now_unix)?;

    // 2. Verify the SNP report against the AMD chain (report-carried
    //    VEK preferred — see SelfReportVerifier).
    let verified = verifier
        .verify(&req.snp_report, &req.vek_der)
        .map_err(|e| {
            // On a chain/VEK failure, surface the report's CHIP_ID +
            // reported-TCB (parsed structurally from the raw bytes, which
            // are public — not secret). This tells the operator EXACTLY
            // which per-chip VCEK to stage for the host the KBS pod runs
            // on (the usual cause: the staged VEK is for a different host
            // or TCB than the one that signed the self-report). Server-side
            // log only; the peer still gets the closed-vocab reason.
            BrokerError::Attestation(format!("{e}{}", chip_id_hint(&req.snp_report)))
        })?;

    // 3. REPORT_DATA binding: report_data == nonce ‖ auth_pubkey.
    //    Constant-time-ish exact compare over the fixed 64-byte layout.
    let mut expected = [0u8; NONCE_LEN + AUTH_PUBKEY_LEN];
    expected[..NONCE_LEN].copy_from_slice(&req.challenge_nonce);
    expected[NONCE_LEN..].copy_from_slice(&req.auth_pubkey);
    if verified.report_data != expected {
        return Err(BrokerError::Attestation(
            "REPORT_DATA does not bind {challenge_nonce ‖ auth_pubkey}".into(),
        ));
    }

    // 4. KBS measurement allowlist. The presented measurement hex goes
    // into the error so the SERVER-SIDE log carries the pin candidate
    // (the launch measurement is public — it's in every SNP report;
    // the transport sends only the closed-vocab `reason()` to the
    // peer). This is how the operator reads the live KBS measurement
    // to pin at the #102 PR C flip — chain + REPORT_DATA binding have
    // already been verified above, so the value is attested, not
    // attacker-chosen.
    if !allowlist.accepts(&verified.measurement) {
        return Err(BrokerError::Attestation(format!(
            "KBS measurement not allowlisted for Vault auth \
             (pin candidate: {})",
            hex::encode(verified.measurement)
        )));
    }

    // 5. TCB floor + launch-policy bits.
    if verified.tcb < policy.min_tcb {
        return Err(BrokerError::Attestation("KBS TCB below floor".into()));
    }
    if verified.policy & policy.required_bits != policy.required_bits {
        return Err(BrokerError::Attestation(
            "KBS launch-policy bits unset".into(),
        ));
    }
    // Positive allowlist (RA-L4) — mirror the guest gate
    // (`kbs_core::snp::check_attestation`): reject a KBS whose launch
    // policy carries ANY bit outside `required_bits | allowed_mask`
    // (e.g. DEBUG / MIGRATE_MA). The broker gates the trusted,
    // measurement-pinned KBS enclave, so this is defense-in-depth, but
    // the two policy checks must be identical — a required-bits-only
    // check would admit a KBS self-report with extra out-of-bounds bits.
    if verified.policy & !(policy.required_bits | policy.allowed_mask) != 0 {
        return Err(BrokerError::Attestation(
            "KBS launch-policy bits out of bounds".into(),
        ));
    }

    // 6. Mint the scoped short-TTL token.
    let (token, expiry) = vault.mint_scoped(&req.scope, now_unix)?;

    Ok(RedeemResponse {
        scope: req.scope.clone(),
        cap_expiry_unix: expiry,
        vault_token: token.to_vec(),
    })
}

/// Operator hint from a raw SNP report when chain/VEK verification
/// fails: which per-chip endorsement key to stage. Parsed with the
/// vendored sev `AttestationReport` (version-aware — Turin v3 shifts
/// fields vs Genoa v2, so a fixed-offset parse reads garbage), so it
/// reports the SIGNING KEY type (VCEK fetchable from AMD KDS vs VLEK
/// loaded by the host), whether the chip key is masked, and the
/// chip_id + reported_tcb. All are public report fields, never secret.
fn chip_id_hint(report: &[u8]) -> String {
    use sev::firmware::guest::AttestationReport;
    use sev::parser::ByteParser as _;
    let Ok(r) = AttestationReport::from_bytes(report) else {
        return String::new();
    };
    let signer = match r.key_info.signing_key() {
        0 => "vcek (fetch from AMD KDS)",
        1 => "vlek (host-loaded; KDS fetch N/A)",
        7 => "none",
        _ => "unknown",
    };
    format!(
        " [self-report signing_key={signer} mask_chip_key={} chip_id={} reported_tcb={:?}]",
        r.key_info.mask_chip_key(),
        hex::encode(r.chip_id),
        r.reported_tcb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use hippius_types::vault_broker::BrokerScope;
    use kbs_core::error::{KbsError, Result as KbsResult};
    use kbs_core::snp::VerifiedReport;

    fn scope() -> BrokerScope {
        BrokerScope {
            vm_id: "vm-1".into(),
            luks_path: "hippius-compute/kbs/tenants/vm-1/luks-kek".into(),
            luks_version: 1,
            userdata_path: "hippius-compute/kbs/tenants/vm-1/userdata".into(),
            userdata_version: 1,
            lifecycle_path: None,
            lifecycle_version: None,
        }
    }

    const NONCE: [u8; 32] = [7u8; 32];
    const PUBKEY: [u8; 32] = [9u8; 32];

    fn report_data() -> [u8; 64] {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&NONCE);
        rd[32..].copy_from_slice(&PUBKEY);
        rd
    }

    fn good_request() -> RedeemRequest {
        RedeemRequest {
            scope: scope(),
            challenge_nonce: NONCE,
            auth_pubkey: PUBKEY,
            snp_report: vec![0u8; 1184],
            vek_der: Vec::new(),
        }
    }

    // --- mocks ---

    struct MockVerifier {
        report: VerifiedReport,
    }
    impl SelfReportVerifier for MockVerifier {
        fn verify(&self, _raw: &[u8], _vek: &[u8]) -> KbsResult<VerifiedReport> {
            Ok(self.report.clone())
        }
    }
    struct DenyVerifier;
    impl SelfReportVerifier for DenyVerifier {
        fn verify(&self, _raw: &[u8], _vek: &[u8]) -> KbsResult<VerifiedReport> {
            Err(KbsError::Attestation("chain denied".into()))
        }
    }
    fn verified(meas: u8, tcb: u64, pol: u64, rd: [u8; 64]) -> VerifiedReport {
        VerifiedReport {
            measurement: [meas; 48],
            report_data: rd,
            tcb,
            policy: pol,
            chip_id: [1u8; 64],
            chain_pem: Vec::new(),
        }
    }

    /// Challenge store that accepts NONCE once; `consume` spends it.
    struct OneShotChallenges {
        spent: AtomicBool,
        expect_scope: BrokerScope,
    }
    impl ChallengeStore for OneShotChallenges {
        fn issue(&self, _s: &BrokerScope, now: u64) -> Result<([u8; 32], u64), BrokerError> {
            Ok((NONCE, now + 30))
        }
        fn consume(&self, nonce: &[u8; 32], s: &BrokerScope, _now: u64) -> Result<(), BrokerError> {
            if nonce != &NONCE {
                return Err(BrokerError::Challenge("unknown nonce".into()));
            }
            if s != &self.expect_scope {
                return Err(BrokerError::Challenge("scope mismatch".into()));
            }
            if self.spent.swap(true, Ordering::SeqCst) {
                return Err(BrokerError::Challenge("already spent".into()));
            }
            Ok(())
        }
    }

    struct AllowAll;
    impl KbsMeasurementAllowlist for AllowAll {
        fn accepts(&self, _m: &[u8; 48]) -> bool {
            true
        }
    }
    struct DenyAll;
    impl KbsMeasurementAllowlist for DenyAll {
        fn accepts(&self, _m: &[u8; 48]) -> bool {
            false
        }
    }

    struct MockMinter;
    impl VaultTokenMinter for MockMinter {
        fn mint_scoped(
            &self,
            _s: &BrokerScope,
            now: u64,
        ) -> Result<(zeroize::Zeroizing<Vec<u8>>, u64), BrokerError> {
            Ok((zeroize::Zeroizing::new(b"hvs.scoped".to_vec()), now + 60))
        }
    }

    fn pol() -> LaunchPolicy {
        LaunchPolicy {
            min_tcb: 5,
            required_bits: 0b10,
            allowed_mask: 0,
        }
    }

    fn store() -> OneShotChallenges {
        OneShotChallenges {
            spent: AtomicBool::new(false),
            expect_scope: scope(),
        }
    }

    #[test]
    fn happy_path_mints_scoped_token() {
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b10, report_data()),
        };
        let out = redeem(
            &good_request(),
            &v,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100,
        )
        .expect("redeem");
        assert_eq!(out.scope.vm_id, "vm-1");
        assert_eq!(out.vault_token, b"hvs.scoped");
        assert!(out.cap_expiry_unix > 100);
    }

    #[test]
    fn rejects_when_report_data_unbound() {
        // report_data does not match nonce ‖ pubkey → reject.
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b10, [0u8; 64]),
        };
        let err = redeem(
            &good_request(),
            &v,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::Attestation(_)));
    }

    #[test]
    fn rejects_measurement_not_allowlisted() {
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b10, report_data()),
        };
        let err = redeem(
            &good_request(),
            &v,
            &store(),
            &DenyAll,
            &pol(),
            &MockMinter,
            100,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::Attestation(_)));
    }

    #[test]
    fn rejects_tcb_below_floor() {
        let v = MockVerifier {
            report: verified(0xAB, 1, 0b10, report_data()),
        };
        assert!(redeem(
            &good_request(),
            &v,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100
        )
        .is_err());
    }

    #[test]
    fn rejects_missing_policy_bit() {
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b00, report_data()),
        };
        assert!(redeem(
            &good_request(),
            &v,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100
        )
        .is_err());
    }

    #[test]
    fn rejects_policy_bits_out_of_bounds() {
        // RA-L4 — the required bit (0b10) IS set, but 0b100 is outside
        // `required_bits | allowed_mask` (allowed_mask=0). The positive
        // allowlist must reject it (a required-bits-only check would admit
        // this KBS self-report with an out-of-bounds bit e.g. DEBUG).
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b110, report_data()),
        };
        assert!(redeem(
            &good_request(),
            &v,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100
        )
        .is_err());
    }

    #[test]
    fn rejects_bad_chain() {
        assert!(redeem(
            &good_request(),
            &DenyVerifier,
            &store(),
            &AllowAll,
            &pol(),
            &MockMinter,
            100
        )
        .is_err());
    }

    #[test]
    fn challenge_is_single_use() {
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b10, report_data()),
        };
        let s = store();
        // First redeem consumes the nonce.
        redeem(&good_request(), &v, &s, &AllowAll, &pol(), &MockMinter, 100).unwrap();
        // Replay with the same nonce → rejected (spent).
        let err = redeem(&good_request(), &v, &s, &AllowAll, &pol(), &MockMinter, 100).unwrap_err();
        assert!(matches!(err, BrokerError::Challenge(_)));
    }

    #[test]
    fn rejects_scope_swap() {
        // Challenge bound to scope() but request carries a different scope.
        let v = MockVerifier {
            report: verified(0xAB, 10, 0b10, report_data()),
        };
        let mut req = good_request();
        // A WELL-FORMED but DIFFERENT scope (all vm-evil, so it passes
        // BrokerScope::validate) must still be rejected by the challenge
        // binding — not silently accepted.
        req.scope.vm_id = "vm-evil".into();
        req.scope.luks_path = "hippius-compute/kbs/tenants/vm-evil/luks-kek".into();
        req.scope.userdata_path = "hippius-compute/kbs/tenants/vm-evil/userdata".into();
        let err = redeem(&req, &v, &store(), &AllowAll, &pol(), &MockMinter, 100).unwrap_err();
        assert!(matches!(err, BrokerError::Challenge(_)));
    }
}
