//! Unified KBS VM lifecycle state model (ARCHITECTURE.md §24; spans §7/§25).
//!
//! ONE durable per-`vm_id` state, checked serializably by every release
//! BEFORE the Vault read AND again BEFORE the at-most-once commit.

use crate::error::{KbsError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmState {
    Active {
        gen: u64,
        host: String,
        lease_id: String,
    },
    /// §25: source fenced; only the destination at `new_gen` may unlock.
    Migrating {
        old_gen: u64,
        new_gen: u64,
        source: String,
        dest: String,
        lease_id: String,
    },
    Decommissioning,
    Destroyed {
        gen: u64,
    },
}

pub trait VmStateStore {
    fn get(&self, vm_id: &str) -> Result<VmState>;
}

/// Deny unless the ticket's `(generation, lease, intended host)` matches the
/// single authoritative state. `Decommissioning`/`Destroyed` ⇒ always deny
/// (tombstone). During `Migrating` only the destination at `new_gen` unlocks.
pub fn check_releasable(
    state: &VmState,
    ticket_gen: u64,
    ticket_lease: &str,
    attested_node: &str,
) -> Result<()> {
    match state {
        VmState::Active {
            gen,
            host,
            lease_id,
        } => {
            if *gen != ticket_gen {
                return Err(KbsError::Lifecycle("vm_generation mismatch".into()));
            }
            if lease_id != ticket_lease {
                return Err(KbsError::Lifecycle("lease_id mismatch".into()));
            }
            if host != attested_node {
                return Err(KbsError::Lifecycle("attested node != bound host".into()));
            }
            Ok(())
        }
        VmState::Migrating {
            new_gen,
            dest,
            lease_id,
            ..
        } => {
            if ticket_gen != *new_gen {
                return Err(KbsError::Lifecycle(
                    "migration: only new_gen may unlock".into(),
                ));
            }
            if lease_id != ticket_lease {
                return Err(KbsError::Lifecycle("lease_id mismatch".into()));
            }
            if dest != attested_node {
                return Err(KbsError::Lifecycle(
                    "migration: attested node != destination".into(),
                ));
            }
            Ok(())
        }
        VmState::Decommissioning => Err(KbsError::Lifecycle("vm is decommissioning".into())),
        VmState::Destroyed { .. } => Err(KbsError::Lifecycle("vm destroyed (tombstone)".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_match_ok() {
        let s = VmState::Active {
            gen: 5,
            host: "n1".into(),
            lease_id: "l".into(),
        };
        check_releasable(&s, 5, "l", "n1").unwrap();
    }

    #[test]
    fn gen_lease_host_mismatch_denied() {
        let s = VmState::Active {
            gen: 5,
            host: "n1".into(),
            lease_id: "l".into(),
        };
        assert!(check_releasable(&s, 6, "l", "n1").is_err());
        assert!(check_releasable(&s, 5, "other", "n1").is_err());
        assert!(check_releasable(&s, 5, "l", "n2").is_err());
    }

    #[test]
    fn decommissioning_and_destroyed_denied() {
        assert!(check_releasable(&VmState::Decommissioning, 1, "l", "n").is_err());
        assert!(check_releasable(&VmState::Destroyed { gen: 1 }, 1, "l", "n").is_err());
    }

    #[test]
    fn migration_only_new_gen_on_dest() {
        let s = VmState::Migrating {
            old_gen: 5,
            new_gen: 6,
            source: "n1".into(),
            dest: "n2".into(),
            lease_id: "l".into(),
        };
        check_releasable(&s, 6, "l", "n2").unwrap();
        assert!(check_releasable(&s, 5, "l", "n1").is_err()); // old gen / source fenced
        assert!(check_releasable(&s, 6, "l", "n1").is_err()); // not the destination
    }
}
