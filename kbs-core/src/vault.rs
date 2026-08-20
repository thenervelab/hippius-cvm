//! Vault access (ARCHITECTURE.md §8 + §19).
//!
//! §8: there is NO static KBS AppRole secret. The KBS obtains a per-VM,
//! short-TTL, no-list capability ONLY by a challenge/response bound to a
//! verified KBS SNP attestation ("the attester is itself attested"):
//! - the authenticator issues a single-use, short-expiry challenge;
//! - the KBS presents SNP evidence whose `REPORT_DATA` binds `{challenge, requested scope, KBS auth pubkey/TLS-exporter}`;
//! - the authenticator verifies measurement in allowlist + TCB >= floor + launch policy, then returns a short-TTL, scope-bound capability.
//!
//! The production authenticator is the native Vault SNP-auth plugin or a
//! Tier-0 minimal attested broker (no reusable fleet token); that is the
//! §17 wiring. This trait pins the SHAPE so no static-secret path exists.
//!
//! §19: reads are at the EXACT signed `path@version` — never "latest";
//! reject deleted/destroyed/not-found/alias/missing; full-object only.

use crate::error::{KbsError, Result};
use crate::snp::{LaunchPolicy, VerifiedReport, MEASUREMENT_LEN};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultScope {
    pub vm_id: String,
    pub luks_path: String,
    pub luks_version: u64,
    pub userdata_path: String,
    pub userdata_version: u64,
    /// §7 per-VM guest lifecycle SIGNING key path@version. `None` for
    /// pre-§7 VMs whose launch never staged a lifecycle key — the
    /// capability then authorizes exactly luks+userdata, wire-identical
    /// to the pre-§7 shape. When `Some`, the broker grants a THIRD
    /// read-only path so the KBS can read the seed and HPKE-wrap it to
    /// the attested guest. The two move together (path + version).
    pub lifecycle_path: Option<String>,
    pub lifecycle_version: Option<u64>,
}

/// Single-use, short-expiry challenge issued by the Vault-side authenticator.
#[derive(Debug, Clone)]
pub struct VaultChallenge {
    pub nonce: [u8; 32],
    pub expiry_unix: u64,
}

/// What the KBS presents to redeem a challenge (§8). `verified` is the
/// KBS's own SNP report (AMD-chain verified upstream); `auth_pubkey` is
/// the KBS channel/TLS-exporter key the capability is bound to.
pub struct KbsAuthEvidence<'a> {
    pub verified: &'a VerifiedReport,
    pub challenge: &'a VaultChallenge,
    pub scope: &'a VaultScope,
    pub auth_pubkey: &'a [u8],
}

/// Opaque, per-VM-scoped, short-TTL capability bound to the redemption.
/// Never a reusable fleet token.
pub struct VaultCapability {
    pub scope: VaultScope,
    pub expiry_unix: u64,
    token: Zeroizing<Vec<u8>>,
}

impl VaultCapability {
    /// Construct a capability from broker-minted parts (§8 / #102).
    ///
    /// For production [`AttestedVaultAuth`] implementations that
    /// receive the token from the SNP-attestation-bound Vault broker
    /// (the KBS-side `RemoteBrokerVaultAuth` client). The `token`
    /// field stays private — this constructor is the only way to
    /// build a capability outside this module, and it takes the token
    /// already `Zeroizing`-wrapped so the secret is wiped on drop.
    pub fn new(scope: VaultScope, expiry_unix: u64, token: Zeroizing<Vec<u8>>) -> Self {
        Self {
            scope,
            expiry_unix,
            token,
        }
    }

    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

pub trait AttestedVaultAuth {
    fn issue_challenge(&self, scope: &VaultScope, now_unix: u64) -> Result<VaultChallenge>;
    /// Verify the SNP evidence + challenge freshness + scope binding and
    /// mint a short-TTL scoped capability. No static credential exists.
    fn redeem(&self, ev: &KbsAuthEvidence, now_unix: u64) -> Result<VaultCapability>;
}

pub trait VaultKv {
    /// §19 exact read. The capability MUST authorize exactly `path`.
    fn read_exact(
        &self,
        cap: &VaultCapability,
        path: &str,
        version: u64,
    ) -> Result<Zeroizing<Vec<u8>>>;

    /// Phase 2 (KEK-HSM) — transit-decrypt a Vault-Transit-wrapped KEK.
    /// `ciphertext` is a Vault Transit ciphertext string (`vault:v1:…`);
    /// the plaintext KEK exists ONLY transiently inside the attested KBS
    /// CVM (returned `Zeroizing`) before it is HPKE-wrapped to the guest.
    /// `transit_key` is the PER-VM Transit key name (`kek-<vm_id>`) — so
    /// the `cap`'s `update` grant on `transit/decrypt/kek-<vm_id>` lets the
    /// KBS decrypt ONLY THIS VM's KEK (a shared key would make the cap a
    /// general decryption oracle for any ciphertext, even one obtained
    /// out-of-band). Default: unsupported — release only calls this when it
    /// detects a wrapped KEK, so a plaintext-only deployment (or a test
    /// double) never needs it.
    fn transit_decrypt(
        &self,
        _cap: &VaultCapability,
        _transit_key: &str,
        _ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(KbsError::Vault(
            "transit_decrypt: not supported by this VaultKv".into(),
        ))
    }
}

/// Reference authenticator standing in for the production Vault SNP-auth
/// (§8/§17). It still refuses to mint without a fresh challenge + a
/// measurement-allowlisted, TCB/policy-valid KBS attestation — no
/// static-secret path. `challenge_ttl` bounds the challenge; `cap_ttl`
/// bounds the minted capability.
pub struct ChallengeVaultAuth<F: Fn(&[u8; MEASUREMENT_LEN]) -> bool> {
    pub kbs_measurement_ok: F,
    pub policy: LaunchPolicy,
    pub challenge_ttl: u64,
    pub cap_ttl: u64,
    pub challenge_nonce: [u8; 32],
}

impl<F: Fn(&[u8; MEASUREMENT_LEN]) -> bool> AttestedVaultAuth for ChallengeVaultAuth<F> {
    fn issue_challenge(&self, _scope: &VaultScope, now_unix: u64) -> Result<VaultChallenge> {
        Ok(VaultChallenge {
            nonce: self.challenge_nonce,
            expiry_unix: now_unix.saturating_add(self.challenge_ttl),
        })
    }

    fn redeem(&self, ev: &KbsAuthEvidence, now_unix: u64) -> Result<VaultCapability> {
        if now_unix >= ev.challenge.expiry_unix {
            return Err(KbsError::Vault("challenge expired".into()));
        }
        if !(self.kbs_measurement_ok)(&ev.verified.measurement) {
            return Err(KbsError::Vault(
                "KBS measurement not allowlisted for Vault auth".into(),
            ));
        }
        if ev.verified.tcb < self.policy.min_tcb {
            return Err(KbsError::Vault("KBS TCB below floor".into()));
        }
        if ev.verified.policy & self.policy.required_bits != self.policy.required_bits {
            return Err(KbsError::Vault("KBS launch-policy bits unset".into()));
        }
        // Capability token is bound to {challenge, scope, auth pubkey};
        // it is never a stored/static secret.
        let mut tok = b"vcap\0".to_vec();
        tok.extend_from_slice(&ev.challenge.nonce);
        tok.extend_from_slice(ev.scope.vm_id.as_bytes());
        tok.push(0);
        tok.extend_from_slice(ev.auth_pubkey);
        Ok(VaultCapability {
            scope: ev.scope.clone(),
            expiry_unix: now_unix.saturating_add(self.cap_ttl),
            token: Zeroizing::new(tok),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> VaultScope {
        VaultScope {
            vm_id: "abc".into(),
            luks_path: "kbs/vm/abc/luks".into(),
            luks_version: 1,
            userdata_path: "kbs/vm/abc/ud".into(),
            userdata_version: 1,
            lifecycle_path: None,
            lifecycle_version: None,
        }
    }
    fn rep(meas: u8, tcb: u64, pol: u64) -> VerifiedReport {
        VerifiedReport {
            measurement: [meas; 48],
            report_data: [0u8; 64],
            tcb,
            policy: pol,
            chip_id: [1u8; 64],
            chain_pem: Vec::new(),
        }
    }
    fn auth(ok: fn(&[u8; 48]) -> bool) -> ChallengeVaultAuth<fn(&[u8; 48]) -> bool> {
        ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 5,
                required_bits: 0b10,
                allowed_mask: 0b1,
            },
            challenge_ttl: 30,
            cap_ttl: 30,
            challenge_nonce: [9u8; 32],
        }
    }

    #[test]
    fn happy_redeem() {
        let a = auth(|_m| true);
        let s = scope();
        let ch = a.issue_challenge(&s, 100).unwrap();
        let r = rep(7, 10, 0b10);
        let ev = KbsAuthEvidence {
            verified: &r,
            challenge: &ch,
            scope: &s,
            auth_pubkey: b"pk",
        };
        let cap = a.redeem(&ev, 110).unwrap();
        assert_eq!(cap.scope.vm_id, "abc");
        assert!(cap.expiry_unix > 110);
        assert!(!cap.token().is_empty());
    }

    #[test]
    fn denies_bad_measurement_tcb_policy_and_expiry() {
        let s = scope();
        let r_ok = rep(7, 10, 0b10);

        let a = auth(|_m| false);
        let ch = a.issue_challenge(&s, 100).unwrap();
        let ev = KbsAuthEvidence {
            verified: &r_ok,
            challenge: &ch,
            scope: &s,
            auth_pubkey: b"p",
        };
        assert!(a.redeem(&ev, 110).is_err()); // measurement not allowlisted

        let a = auth(|_m| true);
        let ch = a.issue_challenge(&s, 100).unwrap();
        let low = rep(7, 1, 0b10);
        let ev = KbsAuthEvidence {
            verified: &low,
            challenge: &ch,
            scope: &s,
            auth_pubkey: b"p",
        };
        assert!(a.redeem(&ev, 110).is_err()); // tcb below floor

        let nopol = rep(7, 10, 0b00);
        let ev = KbsAuthEvidence {
            verified: &nopol,
            challenge: &ch,
            scope: &s,
            auth_pubkey: b"p",
        };
        assert!(a.redeem(&ev, 110).is_err()); // required policy bit unset

        let ev = KbsAuthEvidence {
            verified: &r_ok,
            challenge: &ch,
            scope: &s,
            auth_pubkey: b"p",
        };
        assert!(a.redeem(&ev, 999).is_err()); // challenge expired
    }
}
