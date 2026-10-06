//! Typed, fail-loud errors. The KBS denies on ANY error (ARCHITECTURE.md §7).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KbsError {
    #[error("ticket: {0}")]
    Ticket(String),
    #[error("attestation: {0}")]
    Attestation(String),
    #[error("vault: {0}")]
    Vault(String),
    /// The Vault path/version does not exist (HTTP 404) — as distinct from
    /// "the read failed" ([`KbsError::Vault`]).
    ///
    /// The distinction is load-bearing, not cosmetic: the OPTIONAL §7
    /// lifecycle-key read is allowed to proceed when nothing is staged
    /// (a pre-§7 VM), and only when nothing is staged. Collapsed into one
    /// variant, a 403 / 500 / transport failure was indistinguishable from
    /// a 404, so a Vault outage silently released the KEK to a guest that
    /// then held NO lifecycle signing key — the §24/§25 guest-signed fence
    /// gone, with no error anywhere. Every read that must fail closed
    /// therefore has to be able to tell the two apart.
    #[error("vault: not found: {0}")]
    VaultNotFound(String),
    #[error("lifecycle: {0}")]
    Lifecycle(String),
    #[error("replay: (ticket_id, nonce) already reserved/spent")]
    Replay,
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("user-data digest mismatch (ticket vs Vault)")]
    DigestMismatch,
    #[error("policy: {0}")]
    Policy(String),
}

pub type Result<T> = core::result::Result<T, KbsError>;

impl From<hippius_types::HippiusTypesError> for KbsError {
    fn from(e: hippius_types::HippiusTypesError) -> Self {
        use hippius_types::HippiusTypesError::*;
        match e {
            Cbor(s) => KbsError::Ticket(format!("cbor: {s}")),
            TicketSchema(s) => KbsError::Ticket(s),
            ProvenanceSchema(s) => KbsError::Ticket(format!("provenance: {s}")),
            AuditVmCertSchema(s) => KbsError::Crypto(format!("audit-vm cert: {s}")),
            EvidenceBundleSchema(s) => KbsError::Crypto(format!("evidence bundle: {s}")),
            LiveAttestationSchema(s) => KbsError::Crypto(format!("live attestation: {s}")),
            HostAttestorSchema(s) => KbsError::Crypto(format!("host-attestor: {s}")),
            VaultBrokerSchema(s) => KbsError::Vault(format!("broker wire: {s}")),
            CustodySchema(s) => KbsError::Crypto(format!("custody: {s}")),
            GuardianSchema(s) => KbsError::Crypto(format!("guardian: {s}")),
            RollbackCheckpointSchema(s) => KbsError::Crypto(format!("rollback checkpoint: {s}")),
        }
    }
}
