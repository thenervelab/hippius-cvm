//! Unified KBS VM lifecycle state model (ARCHITECTURE.md §24; spans §7/§25).
//!
//! ONE durable per-`vm_id` state, checked serializably by every release
//! BEFORE the Vault read AND again BEFORE the at-most-once commit.

use crate::error::{KbsError, Result};
use hippius_types::guardian::KeyMode;

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

impl VmState {
    /// Stable lowercase label for admin responses and audit rows.
    pub fn label(&self) -> &'static str {
        match self {
            VmState::Active { .. } => "active",
            VmState::Migrating { .. } => "migrating",
            VmState::Decommissioning => "decommissioning",
            VmState::Destroyed { .. } => "destroyed",
        }
    }
}

pub trait VmStateStore {
    fn get(&self, vm_id: &str) -> Result<VmState>;

    /// The key mode pinned for `vm_id` when it was registered
    /// (customer-held keys, `hippius_types::guardian::KeyMode`).
    ///
    /// A VM registered without a mode — every VM that predates the
    /// feature, and every M0 VM after it — answers
    /// [`KeyMode::Hippius`]; so does a vm_id the store has never seen (the
    /// release path has already refused that one at [`VmStateStore::get`]).
    /// Only a register can set it, and nothing can change it afterwards:
    /// mode switching is launch-time only.
    fn key_mode(&self, vm_id: &str) -> Result<KeyMode>;

    /// The launch this VM's row currently stands for (see
    /// [`LaunchBinding`]), or `None` when none was recorded yet. Stores
    /// that do not track it (test doubles) answer `None`, which keeps
    /// every release decision exactly as before.
    fn launch_binding(&self, _vm_id: &str) -> Result<Option<LaunchBinding>> {
        Ok(None)
    }

    /// Record `binding` as the VM's current launch — only ever called with
    /// a binding [`check_current_launch`] returned. The one write on the
    /// otherwise read-only release path: a release of a NEWER launch's
    /// ticket is what makes the older launch's tickets unusable when no
    /// register preceded it (a relaunch of a §25-moved VM).
    fn bind_launch(&self, _vm_id: &str, _binding: LaunchBinding) -> Result<()> {
        Ok(())
    }

    /// [`check_current_launch`] and, when it says so, [`Self::bind_launch`]
    /// — as ONE step, so two releases (or a release and a register) racing
    /// on the same VM cannot both decide against the same old binding. The
    /// default composes the two (test doubles); a durable store overrides
    /// it to decide and write under its lock.
    fn admit_launch(
        &self,
        vm_id: &str,
        measurement: &[u8; 48],
        ticket_issue_time: u64,
    ) -> Result<()> {
        if let Some(b) =
            check_current_launch(self.launch_binding(vm_id)?, measurement, ticket_issue_time)?
        {
            self.bind_launch(vm_id, b)?;
        }
        Ok(())
    }
}

/// OrderTicket `lifecycle_perms` entry: registering this ticket makes its
/// launch the VM's current one right away (see `admin::process_admin_register`).
pub const SUPERSEDE_PERM: &str = "supersede";

/// OrderTicket `lifecycle_perms` entry: vali registered this VM as a CDN
/// node. Required, together with a `cdn_node`-class measurement, for the
/// release to carry cdn-fleet material (`crate::snp::check_release_class`).
pub const CDN_NODE_PERM: &str = "cdn-node";

/// The launch a VM's KBS row stands for: its launch measurement, and the
/// `issue_time` of the ticket that established it.
///
/// Every launch (and every relaunch — a resize, a power start, a
/// reboot-recovery) is measured differently, and its ticket allows only
/// that measurement. Without this binding the KBS would release to ANY
/// of the VM's launches still in the allowlist with a ticket still in
/// its 24 h validity: a miner holding the pre-resize ticket could boot
/// the pre-resize size and get the disk key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchBinding {
    pub measurement: [u8; 48],
    pub issue_time: u64,
}

/// The release gate on the VM's current launch. `Ok(Some(b))` ⇒ release,
/// and record `b` as the new current launch; `Ok(None)` ⇒ release, the
/// binding stands; `Err` ⇒ deny.
///
/// - nothing recorded ⇒ this ticket's launch becomes the binding;
/// - the same measurement ⇒ always released, whatever the ticket's age
///   (re-minted tickets of the current launch, the ticket the miner
///   re-pushes on an in-guest reboot, a §25 destination — the same
///   measured guest);
/// - another measurement on a ticket issued AFTER the binding's ⇒ a later
///   launch: released, and it becomes the binding;
/// - another measurement on a ticket issued no later than the binding's ⇒
///   a superseded launch: denied. (A same-second tie is refused: two
///   launches of one VM are minutes apart, and letting a tie through would
///   let two launches take the binding from each other.)
pub fn check_current_launch(
    recorded: Option<LaunchBinding>,
    measurement: &[u8; 48],
    ticket_issue_time: u64,
) -> Result<Option<LaunchBinding>> {
    let candidate = LaunchBinding {
        measurement: *measurement,
        issue_time: ticket_issue_time,
    };
    match recorded {
        None => Ok(Some(candidate)),
        Some(b) if b.measurement == *measurement => Ok(None),
        Some(b) if ticket_issue_time > b.issue_time => Ok(Some(candidate)),
        Some(b) => Err(KbsError::Lifecycle(format!(
            "superseded-launch: the ticket (issued {ticket_issue_time}) is for a launch the VM's \
             current one (issued {}) replaced",
            b.issue_time
        ))),
    }
}

/// Deny unless the ticket's key mode is the one pinned at register.
///
/// The mode decides whether a release carries a KEK at all, so a ticket
/// minted under another mode for an already-registered VM is refused
/// outright, never reinterpreted: an M2 VM re-minted as M0 would send the
/// KBS after a KEK that was never staged, and an M0 VM re-minted as M2
/// would boot a guest that formats with a key only the guardian holds.
pub fn check_key_mode(recorded: KeyMode, ticket: KeyMode) -> Result<()> {
    if recorded != ticket {
        return Err(KbsError::Lifecycle(format!(
            "key-mode-mismatch: vm registered as {}, ticket says {}",
            recorded.as_wire(),
            ticket.as_wire()
        )));
    }
    Ok(())
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

/// What the KBS may say about a guest's custody lease (see
/// `hippius_types::custody`). Derived from the SAME `VmState`
/// [`check_releasable`] reads, so "the guest may keep its keys" can never
/// drift from "the guest may unlock its disk".
///
/// The load-bearing asymmetry: the two KILL verdicts ([`Self::Revoked`],
/// [`Self::Superseded`]) are only ever issued on POSITIVE evidence in the
/// store. Anything the store cannot positively place — no row, a counter
/// that was wiped or not re-seeded yet, a generation or counter AHEAD of
/// the store, a host or lease that does not match — is a
/// [`Self::Retry`]. A KBS whose state was wiped (every pod restart) or
/// only partly rebuilt therefore answers "retry" to healthy guests and
/// never powers one off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyStanding {
    Grant,
    Revoked { reason: &'static str },
    Superseded { reason: &'static str },
    Retry { reason: &'static str },
}

/// The identity a custody request claims for itself. Only ever built from
/// an AUTHENTICATED source: an attested + lifecycle-signed bind, or the
/// binding such a bind recorded (for renew/rekey, whose lease signature
/// proves the request comes from that bound guest).
#[derive(Debug, Clone, Copy)]
pub struct CustodyClaim<'a> {
    pub generation: u64,
    pub boot_counter: u64,
    /// The attested CHIP_ID (hex, ticket-length) of the host the guest
    /// bound from.
    pub node: &'a str,
    pub lease_id: &'a str,
}

/// The two public facts that revoke custody without any authentication:
/// the VM is being, or has been, decommissioned. Anyone may learn that a
/// VM is dead; telling a stranger so leaks nothing and harms nothing.
pub fn revoked_standing(state: Option<&VmState>) -> Option<CustodyStanding> {
    use hippius_types::custody::verdict_reason::{DECOMMISSIONING, DESTROYED};
    match state {
        Some(VmState::Decommissioning) => Some(CustodyStanding::Revoked {
            reason: DECOMMISSIONING,
        }),
        Some(VmState::Destroyed { .. }) => Some(CustodyStanding::Revoked { reason: DESTROYED }),
        _ => None,
    }
}

/// Custody standing of an AUTHENTICATED claim.
///
/// | KBS state | claim | standing |
/// |---|---|---|
/// | no row | any | Retry `unknown-vm` |
/// | `Decommissioning` / `Destroyed` | any | Revoked |
/// | `Active{gen}` / `Migrating{new_gen}` (call it `g*`) | `generation < g*` | Superseded (generation) |
/// | same | `generation > g*` | Retry (the store is behind) |
/// | same, `generation == g*` | lease or host mismatch | Retry |
/// | same, match | stored counter `0` (wiped, not re-seeded) | Retry |
/// | same, match | `boot_counter < stored` | Superseded (boot) |
/// | same, match | `boot_counter > stored` | Retry (the store is behind) |
/// | same, match | `boot_counter == stored` | Grant |
///
/// `Migrating{new_gen, dest}` is treated exactly as `Active{new_gen,
/// dest}` — the same equivalence [`check_releasable`] makes — so the §25
/// source (at `old_gen < new_gen`) is Superseded the moment the fence
/// moves, independently of whether the miner obeys the stop order.
pub fn custody_standing(
    state: Option<&VmState>,
    stored_boot_counter: u64,
    claim: &CustodyClaim,
) -> CustodyStanding {
    use hippius_types::custody::retry_reason::UNKNOWN_VM;
    use hippius_types::custody::verdict_reason::{BOOT_SUPERSEDED, GENERATION_SUPERSEDED};
    if let Some(revoked) = revoked_standing(state) {
        return revoked;
    }
    let (gen, host, lease_id) = match state {
        Some(VmState::Active {
            gen,
            host,
            lease_id,
        }) => (*gen, host.as_str(), lease_id.as_str()),
        Some(VmState::Migrating {
            new_gen,
            dest,
            lease_id,
            ..
        }) => (*new_gen, dest.as_str(), lease_id.as_str()),
        // Decommissioning / Destroyed were answered above.
        _ => return CustodyStanding::Retry { reason: UNKNOWN_VM },
    };
    if claim.generation < gen {
        return CustodyStanding::Superseded {
            reason: GENERATION_SUPERSEDED,
        };
    }
    if claim.generation > gen || claim.lease_id != lease_id || claim.node != host {
        return CustodyStanding::Retry { reason: UNKNOWN_VM };
    }
    if stored_boot_counter == 0 {
        return CustodyStanding::Retry { reason: UNKNOWN_VM };
    }
    match claim.boot_counter.cmp(&stored_boot_counter) {
        core::cmp::Ordering::Equal => CustodyStanding::Grant,
        core::cmp::Ordering::Less => CustodyStanding::Superseded {
            reason: BOOT_SUPERSEDED,
        },
        core::cmp::Ordering::Greater => CustodyStanding::Retry { reason: UNKNOWN_VM },
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
    fn a_superseded_launch_is_refused_and_a_later_one_takes_over() {
        let (old, new) = ([1u8; 48], [2u8; 48]);
        // First sight: the ticket's launch becomes the binding.
        let b = check_current_launch(None, &old, 100).unwrap().unwrap();
        assert_eq!(
            b,
            LaunchBinding {
                measurement: old,
                issue_time: 100
            }
        );
        // A re-mint / re-pushed ticket of the same launch: always fine.
        assert_eq!(check_current_launch(Some(b), &old, 50).unwrap(), None);
        assert_eq!(check_current_launch(Some(b), &old, 900).unwrap(), None);
        // The resize relaunch: newer ticket, new measurement ⇒ takes over.
        let b2 = check_current_launch(Some(b), &new, 200).unwrap().unwrap();
        assert_eq!(b2.measurement, new);
        // The pre-resize ticket is now refused…
        let err = check_current_launch(Some(b2), &old, 100)
            .unwrap_err()
            .to_string();
        assert!(err.contains("superseded-launch"), "{err}");
        // …and so is one minted in the same second as the binding's.
        assert!(check_current_launch(Some(b2), &old, 200).is_err());
    }

    #[test]
    fn a_re_mint_of_the_boot_that_runs_releases_after_an_already_launched_retry() {
        // A runs; relaunch B (ticket 200) answered as failed but booted and
        // released; the retry C (ticket 300) was answered `already-launched`
        // and never boots. vali records B, so a §25 hop / KBS recovery
        // re-mints B — with a ticket issued long after C's.
        let (a, b) = ([1u8; 48], [2u8; 48]);
        let bound = check_current_launch(None, &a, 100).unwrap().unwrap();
        let bound = check_current_launch(Some(bound), &b, 200).unwrap().unwrap();
        assert_eq!(check_current_launch(Some(bound), &b, 900).unwrap(), None);
        // Recovery wiped the binding: the re-minted B binds afresh.
        assert_eq!(
            check_current_launch(None, &b, 900).unwrap(),
            Some(LaunchBinding {
                measurement: b,
                issue_time: 900
            })
        );
    }

    #[test]
    fn key_mode_must_match_exactly() {
        use KeyMode::*;
        for recorded in [Hippius, Split, Customer] {
            for ticket in [Hippius, Split, Customer] {
                let r = check_key_mode(recorded, ticket);
                assert_eq!(r.is_ok(), recorded == ticket, "{recorded:?} vs {ticket:?}");
                if let Err(e) = r {
                    assert!(e.to_string().contains("key-mode-mismatch"), "{e}");
                }
            }
        }
    }

    #[test]
    fn decommissioning_and_destroyed_denied() {
        assert!(check_releasable(&VmState::Decommissioning, 1, "l", "n").is_err());
        assert!(check_releasable(&VmState::Destroyed { gen: 1 }, 1, "l", "n").is_err());
    }

    fn active() -> VmState {
        VmState::Active {
            gen: 5,
            host: "n1".into(),
            lease_id: "l".into(),
        }
    }

    fn claim(generation: u64, boot_counter: u64, node: &str) -> CustodyClaim<'_> {
        CustodyClaim {
            generation,
            boot_counter,
            node,
            lease_id: "l",
        }
    }

    const GRANT: CustodyStanding = CustodyStanding::Grant;
    const RETRY: CustodyStanding = CustodyStanding::Retry {
        reason: "unknown-vm",
    };
    const GEN_SUP: CustodyStanding = CustodyStanding::Superseded {
        reason: "generation-superseded",
    };
    const BOOT_SUP: CustodyStanding = CustodyStanding::Superseded {
        reason: "boot-superseded",
    };

    #[test]
    fn custody_grant_needs_gen_lease_host_and_counter_all_matching() {
        let s = active();
        assert_eq!(custody_standing(Some(&s), 7, &claim(5, 7, "n1")), GRANT);
        // The lease is part of the match: a claim under another lease is
        // not positively this guest.
        let other_lease = CustodyClaim {
            lease_id: "other",
            ..claim(5, 7, "n1")
        };
        assert_eq!(custody_standing(Some(&s), 7, &other_lease), RETRY);
        assert_eq!(custody_standing(Some(&s), 7, &claim(5, 7, "n2")), RETRY);
    }

    #[test]
    fn custody_kills_only_on_positive_evidence() {
        let s = active();
        // Older generation, older boot: positive evidence of a stale copy.
        assert_eq!(custody_standing(Some(&s), 7, &claim(4, 7, "n1")), GEN_SUP);
        assert_eq!(custody_standing(Some(&s), 7, &claim(5, 6, "n1")), BOOT_SUP);
        // Everything the store cannot place is a retry, never a kill:
        // no row, a wiped counter, a claim AHEAD of the store.
        assert_eq!(custody_standing(None, 7, &claim(5, 7, "n1")), RETRY);
        assert_eq!(custody_standing(Some(&s), 0, &claim(5, 7, "n1")), RETRY);
        assert_eq!(custody_standing(Some(&s), 7, &claim(6, 7, "n1")), RETRY);
        assert_eq!(custody_standing(Some(&s), 7, &claim(5, 8, "n1")), RETRY);
        // A wiped counter is a retry even for an older boot number.
        assert_eq!(custody_standing(Some(&s), 0, &claim(5, 1, "n1")), RETRY);
        // …and a claim of "boot 0" never matches a wiped/absent counter:
        // 0 == 0 is not evidence that this is the current boot.
        assert_eq!(custody_standing(Some(&s), 0, &claim(5, 0, "n1")), RETRY);
    }

    #[test]
    fn custody_revokes_decommissioned_and_destroyed_whatever_the_claim() {
        for s in [VmState::Decommissioning, VmState::Destroyed { gen: 5 }] {
            for c in [claim(5, 7, "n1"), claim(1, 1, "x"), claim(99, 99, "n1")] {
                assert!(matches!(
                    custody_standing(Some(&s), 7, &c),
                    CustodyStanding::Revoked { .. }
                ));
            }
            assert!(revoked_standing(Some(&s)).is_some());
        }
        assert_eq!(
            revoked_standing(Some(&VmState::Destroyed { gen: 1 })),
            Some(CustodyStanding::Revoked {
                reason: "destroyed"
            })
        );
        assert_eq!(
            revoked_standing(Some(&VmState::Decommissioning)),
            Some(CustodyStanding::Revoked {
                reason: "decommissioning"
            })
        );
        assert_eq!(revoked_standing(Some(&active())), None);
        assert_eq!(revoked_standing(None), None);
    }

    #[test]
    fn custody_migrating_admits_only_the_destination_and_supersedes_the_source() {
        let s = VmState::Migrating {
            old_gen: 5,
            new_gen: 6,
            source: "n1".into(),
            dest: "n2".into(),
            lease_id: "l".into(),
        };
        assert_eq!(custody_standing(Some(&s), 8, &claim(6, 8, "n2")), GRANT);
        // The fenced source is superseded, whatever its counter.
        assert_eq!(custody_standing(Some(&s), 8, &claim(5, 7, "n1")), GEN_SUP);
        assert_eq!(custody_standing(Some(&s), 8, &claim(5, 8, "n1")), GEN_SUP);
        // new_gen from the SOURCE host is not the destination.
        assert_eq!(custody_standing(Some(&s), 8, &claim(6, 8, "n1")), RETRY);
        assert_eq!(custody_standing(Some(&s), 8, &claim(6, 7, "n2")), BOOT_SUP);
    }

    #[test]
    fn custody_grant_iff_releasable_for_the_same_gen_host_lease() {
        // The drift guard: for every state and every (gen, host, lease)
        // probe, a Grant (at the stored counter) implies check_releasable
        // admits the same triple, and a releasable triple is granted.
        let states = [
            active(),
            VmState::Migrating {
                old_gen: 5,
                new_gen: 6,
                source: "n1".into(),
                dest: "n2".into(),
                lease_id: "l".into(),
            },
            VmState::Decommissioning,
            VmState::Destroyed { gen: 5 },
        ];
        for s in &states {
            for g in 4..=7u64 {
                for node in ["n1", "n2"] {
                    for lease in ["l", "m"] {
                        let c = CustodyClaim {
                            generation: g,
                            boot_counter: 3,
                            node,
                            lease_id: lease,
                        };
                        let granted = custody_standing(Some(s), 3, &c) == GRANT;
                        let releasable = check_releasable(s, g, lease, node).is_ok();
                        assert_eq!(granted, releasable, "{s:?} g={g} node={node} lease={lease}");
                    }
                }
            }
        }
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
