//! The persisted net policy and its replay rules.
//!
//! One JSON file, `policy.json`, holds the last accepted policy and its
//! content hash. It is replaced atomically (temp file → fsync → rename →
//! directory fsync, as the heartbeat sequence), and read again on every
//! order, so the rules survive a restart with no in-memory state. An
//! order is refused when:
//!
//! - its revision is lower than the stored one (`net-policy-stale-revision`);
//! - its revision equals the stored one but its content hash does not
//!   (`net-policy-revision-conflict`);
//! - it is past its `not_after_unix` (`net-policy-expired`).
//!
//! The same revision and content is accepted again, and a later
//! `not_after_unix` replaces the stored one. A file that cannot be read
//! or parsed fails every order (`net-policy-store`) rather than being
//! treated as absent: absent would let any revision through.
//!
//! The replay checks read only the record's top-level `revision`,
//! `not_after_unix` and `content_sha256`; the policy is kept as JSON. A
//! record written by a newer or older agent (a policy type with other
//! fields) still parses, so an agent rollback keeps the revision floor.
//!
//! vali sends each push under a fresh `order_id`. The generic order
//! pipeline answers a replayed `order_id` from its in-memory cache with
//! the first answer, without reaching this store.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::error::{MinerAgentError, Result};
use crate::orders::types::NetPolicyOrder;

/// Where the agent keeps the persisted policy.
pub const DEFAULT_NET_POLICY_DIR: &str = "/var/lib/hippius-miner/net-policy";

const POLICY_FILE: &str = "policy.json";

/// The last accepted policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedNetPolicy {
    pub revision: u64,
    pub not_after_unix: u64,
    /// [`super::content_sha256_hex`] of the policy.
    pub content_sha256: String,
    /// The accepted [`NetPolicyOrder`], as JSON (see the module docs).
    pub policy: serde_json::Value,
}

impl AppliedNetPolicy {
    fn new(order: &NetPolicyOrder, content_sha256: String) -> Result<Self> {
        Ok(Self {
            revision: order.revision,
            not_after_unix: order.not_after_unix,
            content_sha256,
            policy: serde_json::to_value(order)
                .map_err(|_| MinerAgentError::NetPolicyStore("encode"))?,
        })
    }

    /// The order response vali stores as the ack.
    pub fn ack(&self) -> String {
        format!("applied:{}:{}", self.revision, self.content_sha256)
    }

    /// The stored policy in this agent's type. Fails `net-policy-store/
    /// schema` on a record written by an agent with another policy type.
    pub fn order(&self) -> Result<NetPolicyOrder> {
        serde_json::from_value(self.policy.clone())
            .map_err(|_| MinerAgentError::NetPolicyStore("schema"))
    }
}

/// The on-disk policy, serialised by a lock so two concurrent orders
/// cannot both pass the revision check.
pub struct NetPolicyStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl NetPolicyStore {
    /// A store under `dir`, created on the first accepted order.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            lock: Mutex::new(()),
        }
    }

    /// The persisted policy, `None` when none was ever accepted.
    pub fn current(&self) -> Result<Option<AppliedNetPolicy>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MinerAgentError::NetPolicyStore("lock"))?;
        self.read()
    }

    /// Validate `order` at `now`, apply the replay rules and persist it.
    /// Returns what is now stored.
    pub fn accept(&self, order: NetPolicyOrder, now: u64) -> Result<AppliedNetPolicy> {
        super::validate(&order, now)?;
        let content_sha256 = super::content_sha256_hex(&order)?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MinerAgentError::NetPolicyStore("lock"))?;
        if let Some(stored) = self.read()? {
            if order.revision < stored.revision {
                return Err(MinerAgentError::NetPolicyStaleRevision);
            }
            if order.revision == stored.revision {
                if content_sha256 != stored.content_sha256 {
                    return Err(MinerAgentError::NetPolicyRevisionConflict);
                }
                if order.not_after_unix <= stored.not_after_unix {
                    // Nothing to write, but a previous attempt may have
                    // renamed the file and then failed its fsync: make it
                    // durable before acking it.
                    self.sync()?;
                    return Ok(stored);
                }
            }
        }
        let applied = AppliedNetPolicy::new(&order, content_sha256)?;
        self.persist(&applied)?;
        Ok(applied)
    }

    fn path(&self) -> PathBuf {
        self.dir.join(POLICY_FILE)
    }

    fn read(&self) -> Result<Option<AppliedNetPolicy>> {
        let bytes = match std::fs::read(self.path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(MinerAgentError::NetPolicyStore("read")),
        };
        let stored: AppliedNetPolicy =
            serde_json::from_slice(&bytes).map_err(|_| MinerAgentError::NetPolicyStore("parse"))?;
        // A policy this agent can read must agree with the replay fields
        // above it; one of another schema is judged by those fields alone.
        if let Ok(order) = stored.order() {
            let consistent = order.revision == stored.revision
                && order.not_after_unix == stored.not_after_unix
                && super::content_sha256_hex(&order)? == stored.content_sha256;
            if !consistent {
                return Err(MinerAgentError::NetPolicyStore("parse"));
            }
        }
        Ok(Some(stored))
    }

    /// Replace the record durably before the order is acked: an ack
    /// whose revision a power loss could undo would reopen the replay
    /// window, so every fsync, the directory's included, is fatal.
    fn persist(&self, applied: &AppliedNetPolicy) -> Result<()> {
        use std::io::Write;
        let write = || MinerAgentError::NetPolicyStore("write");
        let bytes = serde_json::to_vec_pretty(applied).map_err(|_| write())?;
        std::fs::create_dir_all(&self.dir).map_err(|_| write())?;
        let mut tmp = NamedTempFile::new_in(&self.dir).map_err(|_| write())?;
        tmp.write_all(&bytes).map_err(|_| write())?;
        tmp.as_file().sync_all().map_err(|_| write())?;
        tmp.persist(self.path()).map_err(|_| write())?;
        self.sync()
    }

    /// fsync the directory (the rename) and its parent (the directory's
    /// own entry, new on the first order).
    fn sync(&self) -> Result<()> {
        if let Some(parent) = self.dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
        sync_dir(&self.dir)
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|_| MinerAgentError::NetPolicyStore("sync"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netpolicy::tests::{policy, NOW};

    fn store() -> (tempfile::TempDir, NetPolicyStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = NetPolicyStore::new(dir.path().join("net-policy"));
        (dir, store)
    }

    #[test]
    fn a_first_policy_is_persisted_and_acked() {
        let (_dir, store) = store();
        assert_eq!(store.current().unwrap(), None);
        let applied = store.accept(policy(3), NOW).unwrap();
        assert_eq!(
            applied.ack(),
            format!(
                "applied:3:{}",
                crate::netpolicy::content_sha256_hex(&policy(3)).unwrap()
            )
        );
        assert_eq!(store.current().unwrap(), Some(applied));
    }

    #[test]
    fn the_replay_rules_hold_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-policy");
        NetPolicyStore::new(&path).accept(policy(5), NOW).unwrap();

        // A new store over the same directory: what a restarted agent sees.
        let restarted = NetPolicyStore::new(&path);
        assert_eq!(
            restarted.accept(policy(4), NOW).unwrap_err().to_string(),
            "net-policy-stale-revision"
        );
        let mut other = policy(5);
        other.local_action = crate::orders::types::NetPolicyLocalAction::Drop;
        assert_eq!(
            restarted.accept(other, NOW).unwrap_err().to_string(),
            "net-policy-revision-conflict"
        );
        assert_eq!(restarted.accept(policy(5), NOW).unwrap().revision, 5);
        assert_eq!(restarted.accept(policy(6), NOW).unwrap().revision, 6);
        assert_eq!(
            NetPolicyStore::new(&path)
                .current()
                .unwrap()
                .unwrap()
                .order()
                .unwrap(),
            policy(6)
        );
    }

    #[test]
    fn a_resend_with_a_later_expiry_renews_and_an_earlier_one_keeps_it() {
        let (_dir, store) = store();
        store.accept(policy(1), NOW).unwrap();
        let mut renewed = policy(1);
        renewed.not_after_unix += 600;
        assert_eq!(
            store.accept(renewed.clone(), NOW).unwrap().order().unwrap(),
            renewed
        );
        // The original order again: same content, ack unchanged, the
        // later expiry stays.
        let again = store.accept(policy(1), NOW).unwrap();
        assert_eq!(again.not_after_unix, renewed.not_after_unix);
        assert_eq!(again.order().unwrap(), renewed);
        assert_eq!(again.ack(), store.accept(renewed, NOW).unwrap().ack());
    }

    #[test]
    fn an_expired_or_invalid_order_never_reaches_the_file() {
        let (_dir, store) = store();
        assert_eq!(
            store
                .accept(policy(1), NOW + 86_401)
                .unwrap_err()
                .to_string(),
            "net-policy-expired"
        );
        assert_eq!(
            store.accept(policy(0), NOW).unwrap_err().to_string(),
            "net-policy-invalid/revision"
        );
        assert_eq!(store.current().unwrap(), None);
    }

    #[test]
    fn a_damaged_file_fails_closed() {
        let (_dir, store) = store();
        store.accept(policy(2), NOW).unwrap();
        std::fs::write(store.path(), b"{ not json").unwrap();
        assert_eq!(
            store.accept(policy(3), NOW).unwrap_err().to_string(),
            "net-policy-store/parse"
        );
        std::fs::write(store.path(), b"").unwrap();
        assert_eq!(
            store.current().unwrap_err().to_string(),
            "net-policy-store/parse"
        );

        // Replay fields edited away from the policy they describe.
        store.accept(policy(1), NOW).unwrap_err();
        std::fs::remove_file(store.path()).unwrap();
        store.accept(policy(5), NOW).unwrap();
        let mut record = store.current().unwrap().unwrap();
        record.revision = 2;
        std::fs::write(store.path(), serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(
            store.accept(policy(3), NOW).unwrap_err().to_string(),
            "net-policy-store/parse"
        );
    }

    /// An agent rolled back under a record whose policy carries a field
    /// it does not know still holds the revision floor.
    #[test]
    fn a_record_from_another_agent_version_keeps_the_floor() {
        let (_dir, store) = store();
        store.accept(policy(4), NOW).unwrap();
        let mut record = store.current().unwrap().unwrap();
        record.policy["future_field"] = serde_json::json!(true);
        std::fs::write(store.path(), serde_json::to_vec(&record).unwrap()).unwrap();

        assert_eq!(
            store.accept(policy(3), NOW).unwrap_err().to_string(),
            "net-policy-stale-revision"
        );
        assert_eq!(store.accept(policy(4), NOW).unwrap(), record);
        assert_eq!(
            record.order().unwrap_err().to_string(),
            "net-policy-store/schema"
        );
        assert_eq!(store.accept(policy(5), NOW).unwrap().revision, 5);
    }
}
