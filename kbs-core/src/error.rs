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
        }
    }
}
