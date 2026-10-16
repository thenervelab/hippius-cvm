//! The `storage-config` order: vali's desired storage document
//! (`docs/design/disk-tier-verification.md` §9).
//!
//! The document is whole, never a patch: it is validated in full and
//! applied all or nothing.
//!
//! - **Static checks** (also re-run on the stored document at restart):
//!   revision, freshness, ids, count, order, path syntax, and the parts
//!   that stay local. `default` must be `[storage] data_disk_root` with the
//!   `[host] cvm_disk_gb_budget` budget, taking OS disks: every OS disk
//!   still lands there. A local `[[storage.pools]]` id may not change path.
//! - **Host checks** (on apply and dry run): every `active` pool passes
//!   the pool checks of [`super::pools::check_pools`] and every `active`
//!   dedicated disk the inventory of [`super::dedicated`]. A `draining`
//!   entry is not required to be usable: it is being emptied.
//! - **Live-disk safety**: a pool in force that holds a VM disk cannot be
//!   removed or moved (`pool-has-disks`), and no budget may drop below
//!   what its pool already holds (`pool-budget-below-committed`).
//!
//! A refusal is `422 {"code": "<code>", "pool"|"disk": "<id>"}`. `dry_run`
//! runs every check and persists nothing (`dry-run-ok:<rev>:<sha>`).
//!
//! An applied document is stored at `<state_disk_root>/storage-config.json`
//! with the net-policy replay rules (`netpolicy/store.rs`): a lower
//! revision is `409 storage-config-stale-revision`, the same revision with
//! other content `409 storage-config-revision-conflict`, the same document
//! again is acked as applied. It then replaces the set in force
//! ([`super::state`]) and the pools are bound to their filesystems
//! ([`super::registry`]) before the ack.
//!
//! At restart the stored document is the set in force (it takes
//! precedence over the local config) once its static checks pass against
//! the local config; otherwise the agent runs with the local set, logs
//! why, and reports `storage_config_revision` 0 so vali re-pushes. The
//! removed-pool guard of [`super::registry`] runs on whichever set wins.
//! The agent never formats, mounts or wipes anything.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use hippius_types::storage_report::{
    is_valid_dedicated_disk_id, is_valid_pool_id, DedicatedDiskState, MAX_DEDICATED_DISKS,
    MAX_DISK_POOLS,
};

use crate::config::{
    Config, DedicatedDiskConfig, PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig,
    StorageSection,
};
use crate::orders::types::{StorageConfigOrder, StorageDesiredState, StoragePoolClass};

use super::dedicated::{self, FactsSource};
use super::pools::{self, PoolFs};
use super::registry::{self, FsIdentitySource};
use super::state::{EffectiveStorage, StorageState};
use super::{StoragePools, DEFAULT_POOL_ID};

/// File name under `state_disk_root`.
pub const STORAGE_CONFIG_FILE: &str = "storage-config.json";

/// Longest validity window an order may claim (as `net-policy`).
pub const MAX_STORAGE_CONFIG_TTL_SECS: u64 = 7 * 24 * 3600;

/// What a refusal names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Document,
    Pool(String),
    Disk(String),
}

/// Why a `storage-config` order was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageConfigError {
    /// The document fails a check: `422`.
    Refused {
        code: &'static str,
        subject: Subject,
    },
    /// `409`: vali sends a higher revision.
    StaleRevision,
    /// `409`: the same revision with other content.
    RevisionConflict,
    /// `500`: the stored record or the registry could not be read or
    /// written.
    Store(&'static str),
}

fn refused(code: &'static str, subject: Subject) -> StorageConfigError {
    StorageConfigError::Refused { code, subject }
}

fn pool(code: &'static str, id: &str) -> StorageConfigError {
    refused(code, Subject::Pool(id.to_string()))
}

fn disk(code: &'static str, id: &str) -> StorageConfigError {
    refused(code, Subject::Disk(id.to_string()))
}

impl StorageConfigError {
    /// The HTTP status of the refusal.
    pub fn status(&self) -> u16 {
        match self {
            Self::Refused { .. } => 422,
            Self::StaleRevision | Self::RevisionConflict => 409,
            Self::Store(_) => 500,
        }
    }

    /// The closed-enum code (also the log class).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refused { code, .. } => code,
            Self::StaleRevision => "storage-config-stale-revision",
            Self::RevisionConflict => "storage-config-revision-conflict",
            Self::Store(_) => "storage-config-store",
        }
    }

    /// The response body: `{"code": …}` plus the pool or disk it names.
    pub fn body(&self) -> String {
        let mut body = serde_json::Map::new();
        body.insert("code".into(), self.code().into());
        if let Self::Refused { subject, .. } = self {
            match subject {
                Subject::Document => {}
                Subject::Pool(id) => {
                    body.insert("pool".into(), id.clone().into());
                }
                Subject::Disk(id) => {
                    body.insert("disk".into(), id.clone().into());
                }
            }
        }
        serde_json::Value::Object(body).to_string()
    }
}

type Outcome<T> = std::result::Result<T, StorageConfigError>;

/// What stays local: the roots, the host budget and the bootstrap config.
#[derive(Debug, Clone)]
pub struct LocalStorage {
    pub data_root: PathBuf,
    pub state_root: PathBuf,
    pub host_budget_gb: u64,
    pub pools: Vec<StoragePoolConfig>,
    pub dedicated: Vec<DedicatedDiskConfig>,
    /// Where pools other than `default` must be
    /// ([`super::pools::POOLS_ROOT`]); `None` = not enforced (tests).
    pub pools_root: Option<PathBuf>,
}

impl LocalStorage {
    pub fn from_config(config: &Config) -> Self {
        Self {
            data_root: config.storage.data_disk_root.clone(),
            state_root: config.storage.state_disk_root.clone(),
            host_budget_gb: config.host.cvm_disk_gb_budget,
            pools: config.storage.pools.clone(),
            dedicated: config.storage.dedicated_disks.clone(),
            pools_root: Some(PathBuf::from(super::pools::POOLS_ROOT)),
        }
    }

    fn section(
        &self,
        pools: Vec<StoragePoolConfig>,
        dedicated: Vec<DedicatedDiskConfig>,
    ) -> StorageSection {
        StorageSection {
            data_disk_root: self.data_root.clone(),
            state_disk_root: self.state_root.clone(),
            pools,
            dedicated_disks: dedicated,
        }
    }

    /// The local set: `[[storage.pools]]`, else the implicit `default`.
    pub fn local_set(&self) -> (StoragePools, Vec<DedicatedDiskConfig>) {
        let section = self.section(self.pools.clone(), self.dedicated.clone());
        (
            StoragePools::from_config(&section, self.host_budget_gb)
                .with_pools_root(self.pools_root.clone()),
            self.dedicated.clone(),
        )
    }

    /// The set a (statically valid) document describes.
    pub fn document_set(
        &self,
        doc: &StorageConfigOrder,
    ) -> (StoragePools, Vec<DedicatedDiskConfig>) {
        let dedicated = dedicated_of(doc);
        let section = self.section(pools_of(doc), dedicated.clone());
        (
            StoragePools::from_config(&section, self.host_budget_gb)
                .with_pools_root(self.pools_root.clone()),
            dedicated,
        )
    }
}

fn desired(state: StorageDesiredState) -> StorageDesiredStateConfig {
    match state {
        StorageDesiredState::Active => StorageDesiredStateConfig::Active,
        StorageDesiredState::Draining => StorageDesiredStateConfig::Draining,
    }
}

fn pools_of(doc: &StorageConfigOrder) -> Vec<StoragePoolConfig> {
    doc.pools
        .iter()
        .map(|p| StoragePoolConfig {
            id: p.id.clone(),
            path: PathBuf::from(&p.path),
            class: match p.class {
                StoragePoolClass::Nvme => PoolClassConfig::Nvme,
                StoragePoolClass::Ssd => PoolClassConfig::Ssd,
                StoragePoolClass::Hdd => PoolClassConfig::Hdd,
            },
            budget_gb: u64::from(p.budget_gb),
            os_disks: p.os_disks,
            state: desired(p.state),
        })
        .collect()
}

fn dedicated_of(doc: &StorageConfigOrder) -> Vec<DedicatedDiskConfig> {
    doc.dedicated_disks
        .iter()
        .map(|d| DedicatedDiskConfig {
            id: d.id.clone(),
            state: desired(d.state),
        })
        .collect()
}

/// SHA-256 of the order's canonical CBOR without `not_after_unix`: the
/// digest `hippius-ticket-validator storage-config-digest` computes.
pub fn content_sha256_hex(order: &StorageConfigOrder) -> Outcome<String> {
    let encode = || StorageConfigError::Store("encode");
    let Value::Map(entries) = Value::serialized(order).map_err(|_| encode())? else {
        return Err(encode());
    };
    let content = Value::Map(
        entries
            .into_iter()
            .filter(|(key, _)| key.as_text() != Some("not_after_unix"))
            .collect(),
    );
    let bytes = hippius_types::cbor::to_canonical_vec(&content).map_err(|_| encode())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// An absolute path in its one spelling: no `.`/`..`, no doubled or
/// trailing `/`, valid UTF-8.
fn is_plain_absolute(path: &str) -> bool {
    let p = Path::new(path);
    p.is_absolute()
        && !p.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && p.components().collect::<PathBuf>().as_os_str() == p.as_os_str()
}

/// The checks that need no host: shape, order, and what stays local.
/// `now` is `None` for the stored document at restart (its freshness
/// was judged when it was applied).
pub fn validate_static(
    doc: &StorageConfigOrder,
    now: Option<u64>,
    local: &LocalStorage,
) -> Outcome<()> {
    if doc.revision == 0 {
        return Err(refused(
            "storage-config-revision-invalid",
            Subject::Document,
        ));
    }
    if let Some(now) = now {
        if now > doc.not_after_unix {
            return Err(refused("storage-config-expired", Subject::Document));
        }
        if doc.not_after_unix - now > MAX_STORAGE_CONFIG_TTL_SECS {
            return Err(refused(
                "storage-config-not-after-invalid",
                Subject::Document,
            ));
        }
    }
    if doc.pools.len() > MAX_DISK_POOLS {
        return Err(refused("too-many-pools", Subject::Document));
    }
    let mut previous: Option<&str> = None;
    let mut paths = BTreeSet::new();
    for p in &doc.pools {
        // Sorted, so one document has one digest; a duplicate is unsorted.
        if !is_valid_pool_id(&p.id) || previous.is_some_and(|prev| prev >= p.id.as_str()) {
            return Err(pool("pool-id-invalid", &p.id));
        }
        previous = Some(&p.id);
        if !is_plain_absolute(&p.path) {
            return Err(pool("pool-path-invalid", &p.id));
        }
        if !paths.insert(p.path.as_str()) {
            return Err(pool("pool-shared-fs", &p.id));
        }
        if p.id != DEFAULT_POOL_ID && p.budget_gb == 0 {
            return Err(pool("pool-budget-invalid", &p.id));
        }
        if let Some(l) = local.pools.iter().find(|l| l.id == p.id) {
            if l.path != Path::new(&p.path) {
                return Err(pool("pool-conflicts-local", &p.id));
            }
        }
    }
    let Some(default) = doc.pools.iter().find(|p| p.id == DEFAULT_POOL_ID) else {
        return Err(pool("pool-default-required", DEFAULT_POOL_ID));
    };
    // Every OS disk, backup, restore and migration still works on
    // `data_disk_root` with the host budget: `default` is that, as the
    // local config requires.
    if Path::new(&default.path) != local.data_root
        || u64::from(default.budget_gb) != local.host_budget_gb
        || !default.os_disks
        || default.state != StorageDesiredState::Active
    {
        return Err(pool("pool-conflicts-local", DEFAULT_POOL_ID));
    }
    if doc.dedicated_disks.len() > MAX_DEDICATED_DISKS {
        return Err(refused("too-many-disks", Subject::Document));
    }
    let mut previous: Option<&str> = None;
    for d in &doc.dedicated_disks {
        if !is_valid_dedicated_disk_id(&d.id) {
            return Err(disk("disk-id-invalid", &d.id));
        }
        match previous {
            Some(prev) if prev == d.id => return Err(disk("disk-duplicate", &d.id)),
            Some(prev) if prev > d.id.as_str() => return Err(disk("disk-id-invalid", &d.id)),
            _ => {}
        }
        previous = Some(&d.id);
    }
    Ok(())
}

/// The record of the applied document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    revision: u64,
    not_after_unix: u64,
    content_sha256: String,
    document: StorageConfigOrder,
}

impl Applied {
    fn ack(&self) -> String {
        format!("applied:{}:{}", self.revision, self.content_sha256)
    }
}

fn record_path(state_root: &Path) -> PathBuf {
    state_root.join(STORAGE_CONFIG_FILE)
}

/// The stored record, `None` when nothing was ever applied. A record that
/// cannot be read, or whose digest does not match its document, is an
/// error: never treated as absent (absent would drop the revision floor).
fn read_record(state_root: &Path) -> Outcome<Option<Applied>> {
    let bytes = match std::fs::read(record_path(state_root)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StorageConfigError::Store("read")),
    };
    let record: Applied =
        serde_json::from_slice(&bytes).map_err(|_| StorageConfigError::Store("parse"))?;
    if record.document.revision != record.revision
        || record.document.not_after_unix != record.not_after_unix
        || content_sha256_hex(&record.document)? != record.content_sha256
    {
        return Err(StorageConfigError::Store("parse"));
    }
    Ok(Some(record))
}

/// The set the agent starts with: the stored document if it still passes
/// its static checks against the local config, else the local set. In
/// that fallback the document's other pools stay, `draining`: the disks
/// on them are still accounted and reclaimed, and the removed-pool guard
/// does not refuse the start over a local edit.
pub fn boot_set(local: &LocalStorage) -> (StoragePools, Vec<DedicatedDiskConfig>, u64) {
    match read_record(&local.state_root) {
        Ok(None) => {}
        Ok(Some(record)) => match validate_static(&record.document, None, local) {
            Ok(()) => {
                let (pools, dedicated) = local.document_set(&record.document);
                return (pools, dedicated, record.revision);
            }
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: storage: applied storage-config revision {} no longer \
                     fits the local config ({}); running with the local set, its other pools \
                     draining",
                    record.revision,
                    err.body()
                );
                let (pools, dedicated) = local.local_set();
                let remote: Vec<StoragePoolConfig> = pools_of(&record.document)
                    .into_iter()
                    .filter(|p| p.id != DEFAULT_POOL_ID)
                    .collect();
                return (pools.with_draining(&remote), dedicated, 0);
            }
        },
        Err(err) => eprintln!(
            "hippius-miner-agent: storage: {STORAGE_CONFIG_FILE} unreadable ({}); running with \
             the local set, storage-config orders refused until it is fixed",
            err.code()
        ),
    }
    let (pools, dedicated) = local.local_set();
    (pools, dedicated, 0)
}

/// Where the checks read the host. Real by default; scripted in tests.
pub struct Host {
    pub pool_fs: Box<dyn PoolFs + Send + Sync>,
    pub fs_identity: FsIdentitySource,
    /// The dedicated-disk facts (the collector's report).
    pub facts: Box<dyn FactsSource>,
}

impl Host {
    pub fn system() -> Self {
        Self {
            pool_fs: Box::new(pools::SystemPoolFs::default()),
            fs_identity: FsIdentitySource::default(),
            facts: Box::new(dedicated::FileFacts::default()),
        }
    }
}

/// Serves `storage-config` orders against the shared set in force.
pub struct StorageConfigService {
    local: LocalStorage,
    state: Arc<StorageState>,
    host: Host,
    /// The dedicated-disk identities, shared with the heartbeat reporter.
    /// Held from the inventory to the save, so the two never bind a disk
    /// from diverging copies.
    identities: Arc<dedicated::IdentityStore>,
    /// One order at a time: two cannot both pass the revision check.
    lock: Mutex<()>,
    /// Taken by the route before it starts a blocking worker, so a burst
    /// of orders waits here instead of filling the blocking pool.
    gate: tokio::sync::Mutex<()>,
}

impl StorageConfigService {
    pub fn new(
        local: LocalStorage,
        state: Arc<StorageState>,
        host: Host,
        identities: Arc<dedicated::IdentityStore>,
    ) -> Self {
        Self {
            local,
            state,
            host,
            identities,
            lock: Mutex::new(()),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// See [`Self::accept`]: hold it across the blocking call.
    pub fn gate(&self) -> &tokio::sync::Mutex<()> {
        &self.gate
    }

    /// Validate `order` at `now` and, unless it is a dry run, apply it.
    /// Blocking (it reads the host): run it off the async workers.
    ///
    /// The stored record is the commit point: once it is written the
    /// document is applied and put in force. The newly accepted disks'
    /// identities and the pool bindings follow it; if one of those writes
    /// fails the order still fails (`storage-config-store`), and vali's
    /// re-push of the same revision finds it in force and finishes the
    /// bindings (a restart in between binds both on its own).
    pub fn accept(&self, order: StorageConfigOrder, now: u64) -> Outcome<String> {
        validate_static(&order, Some(now), &self.local)?;
        let sha = content_sha256_hex(&order)?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| StorageConfigError::Store("lock"))?;
        let has_disks = order
            .dedicated_disks
            .iter()
            .any(|d| d.state == StorageDesiredState::Active);
        // Fresh disk facts before a decision on declared disks: the
        // collector runs now, outside the identity lock (which the
        // heartbeat shares). Not for a re-push of the document in force.
        if order.dry_run {
            if has_disks {
                self.host.facts.refresh();
            }
            // A dry run judges the document, not its place in the
            // revision sequence, and touches nothing.
            let candidate = self.validate_pools(&order)?;
            if has_disks {
                let mut ids = self.identities.lock();
                let ids =
                    ids.get_or_insert_with(|| dedicated::IdentityMap::load(&self.local.state_root));
                self.validate_disks(&order, &candidate, ids.as_ref())?;
            }
            return Ok(format!("dry-run-ok:{}:{sha}", order.revision));
        }
        let stored = read_record(&self.local.state_root)?;
        if let Some(stored) = &stored {
            if order.revision < stored.revision {
                return Err(StorageConfigError::StaleRevision);
            }
            if order.revision == stored.revision {
                if sha != stored.content_sha256 {
                    return Err(StorageConfigError::RevisionConflict);
                }
                if self.state.current().revision == stored.revision {
                    // Already the set in force: the re-push of drift
                    // repair (its host state is in the heartbeat), or the
                    // retry of an apply whose bindings did not all land.
                    self.finish_bindings(&order, has_disks)?;
                    return Ok(stored.ack());
                }
            }
        }
        if has_disks {
            self.host.facts.refresh();
        }
        let candidate = self.validate_pools(&order)?;
        // The identity lock only for a document that binds disks: a hung
        // disk read in the heartbeat must not hold up pool-only changes.
        let mut ids_guard = has_disks.then(|| self.identities.lock());
        let bound = match ids_guard.as_mut() {
            Some(ids) => {
                let ids =
                    ids.get_or_insert_with(|| dedicated::IdentityMap::load(&self.local.state_root));
                self.validate_disks(&order, &candidate, ids.as_ref())?
            }
            None => None,
        };
        let pools = Arc::new(candidate);
        let plan = registry::plan_with(&self.local.state_root, &pools, &self.host.fs_identity)
            .map_err(registry_error)?;
        let dedicated = dedicated_of(&order);
        let mut document = order;
        document.dry_run = false;
        let applied = Applied {
            revision: document.revision,
            not_after_unix: document.not_after_unix,
            content_sha256: sha,
            document,
        };
        let bytes =
            serde_json::to_vec_pretty(&applied).map_err(|_| StorageConfigError::Store("write"))?;
        // The rename is the commit point: once it is done the record is
        // the document (a failed directory fsync after it does not undo
        // it), so the set is put in force and the order reports 500.
        let mut complete = match crate::netpolicy::store::write_durable(
            &self.local.state_root,
            STORAGE_CONFIG_FILE,
            &bytes,
        ) {
            Ok(()) => true,
            Err("sync") => false,
            Err(step) => return Err(StorageConfigError::Store(step)),
        };
        if let (Some(bound), Some(ids)) = (bound, ids_guard.as_mut()) {
            if bound.save(&self.local.state_root).is_ok() {
                **ids = Some(Some(bound));
            } else {
                complete = false;
            }
        }
        drop(ids_guard);
        complete &= plan.commit().is_ok();
        self.state.replace(EffectiveStorage {
            pools,
            dedicated,
            revision: applied.revision,
            bindings: plan.bindings,
        });
        eprintln!(
            "hippius-miner-agent: storage: storage-config revision {} applied",
            applied.revision
        );
        if !complete {
            eprintln!(
                "hippius-miner-agent: storage: storage-config revision {}: a binding was not \
                 saved; the next push of this revision retries it",
                applied.revision
            );
            return Err(StorageConfigError::Store("bindings"));
        }
        Ok(applied.ack())
    }

    /// Write the registry for the set in force (a no-op when it already
    /// says it).
    fn finish_bindings(&self, order: &StorageConfigOrder, has_disks: bool) -> Outcome<()> {
        let current = self.state.current();
        // The newly accepted disks' identities, if their save failed.
        let unbound = |ids: &Option<dedicated::IdentityMap>| {
            ids.as_ref().is_some_and(|map| {
                order.dedicated_disks.iter().any(|d| {
                    d.state == StorageDesiredState::Active && !map.disks.contains_key(&d.id)
                })
            })
        };
        let refresh = has_disks && {
            let mut ids = self.identities.lock();
            let loaded =
                ids.get_or_insert_with(|| dedicated::IdentityMap::load(&self.local.state_root));
            unbound(loaded)
        };
        // Every active disk bound: no host read on a re-push.
        if refresh {
            self.host.facts.refresh();
            let mut ids = self.identities.lock();
            let loaded =
                ids.get_or_insert_with(|| dedicated::IdentityMap::load(&self.local.state_root));
            if !unbound(loaded) {
                // Bound meanwhile by the heartbeat.
            } else if let Ok(Some(bound)) =
                // Deliberately best-effort: the document is in force, so a
                // disk that now fails the inventory is not a refusal here
                // (the heartbeat reports its state), and nothing is bound
                // until every active disk passes.
                self.validate_disks(order, &current.pools, loaded.as_ref())
            {
                bound
                    .save(&self.local.state_root)
                    .map_err(|_| StorageConfigError::Store("identities"))?;
                *loaded = Some(bound);
            }
        }
        let plan = registry::plan_with(
            &self.local.state_root,
            &current.pools,
            &self.host.fs_identity,
        )
        .map_err(registry_error)?;
        plan.commit()
            .map_err(|_| StorageConfigError::Store("registry"))?;
        // Memory follows the file: a pool mounted since is bound now.
        self.state.replace(EffectiveStorage {
            bindings: plan.bindings,
            ..(*current).clone()
        });
        Ok(())
    }

    /// The pool checks and the live-disk safety rules, against the set in
    /// force. Returns the document's pool set.
    fn validate_pools(&self, doc: &StorageConfigOrder) -> Outcome<StoragePools> {
        let current = self.state.current();
        // A pool in force holding disks is never dropped or moved.
        for old in current.pools.non_default() {
            let kept = doc
                .pools
                .iter()
                .any(|p| p.id == old.id && Path::new(&p.path) == old.path);
            if !kept && pools::holds_vm_disks(&old.path) != Some(false) {
                return Err(pool("pool-has-disks", &old.id));
            }
        }
        let (candidate, _) = self.local.document_set(doc);
        // A new or moved pool is bound when applied; a kept one (same id,
        // same path) must still be on its filesystem.
        let in_force = |p: &pools::Pool| current.pools.get(&p.id).is_some_and(|c| c.path == p.path);
        let mut binding_errors = current
            .bindings
            .errors_now(&candidate, &self.host.fs_identity);
        binding_errors.retain(|id, error| {
            *error != "pool-unbound" && candidate.get(id).is_some_and(in_force)
        });
        let checks = pools::check_pools(&candidate, self.host.pool_fs.as_ref(), &binding_errors);
        for p in candidate.iter() {
            let error = checks.get(&p.id).map_or("pool-path-missing", |c| c.error);
            if p.is_default() {
                // Grandfathered, as at startup: it only has to exist.
                if error == "pool-path-missing" {
                    return Err(pool(error, &p.id));
                }
                continue;
            }
            // Only a pool already in force may be draining while unusable
            // (it is being emptied); a new or moved one must pass.
            let excused = p.draining && in_force(p);
            if !error.is_empty() && !excused {
                return Err(pool(error, &p.id));
            }
            if p.budget_gb < pools::committed_gb(&p.path) {
                return Err(pool("pool-budget-below-committed", &p.id));
            }
        }
        Ok(candidate)
    }

    /// The inventory of the document's active dedicated disks against the
    /// pools it declares. `identities` is the loaded map (`None`: the file
    /// is corrupt). `Some` carries it with the newly accepted disks bound,
    /// for the caller to save on apply.
    fn validate_disks(
        &self,
        doc: &StorageConfigOrder,
        candidate: &StoragePools,
        identities: Option<&dedicated::IdentityMap>,
    ) -> Outcome<Option<dedicated::IdentityMap>> {
        let active: Vec<DedicatedDiskConfig> = dedicated_of(doc)
            .into_iter()
            .filter(|d| d.state == StorageDesiredStateConfig::Active)
            .collect();
        let Some(first) = active.first() else {
            return Ok(None);
        };
        let Some(before) = identities else {
            return Err(disk("disk-identity-store-unreadable", &first.id));
        };
        let mut identities = before.clone();
        let facts = self.host.facts.facts();
        let reports = dedicated::inventory(
            &active,
            facts.as_ref().map_err(|e| *e),
            &super::system_devs(&self.local.state_root, candidate),
            &mut identities,
        );
        for report in reports {
            match report.state {
                DedicatedDiskState::Free => {}
                DedicatedDiskState::Replaced => return Err(disk("disk-replaced", &report.id)),
                _ => {
                    let code = dedicated_code(&report.error);
                    return Err(disk(code, &report.id));
                }
            }
        }
        Ok((identities != *before).then_some(identities))
    }
}

/// A registry verdict as a `storage-config` outcome.
fn registry_error(err: crate::error::MinerAgentError) -> StorageConfigError {
    match err {
        crate::error::MinerAgentError::ConfigInvalid("storage.pools-removed-pool-holds-disks") => {
            refused("pool-has-disks", Subject::Document)
        }
        _ => StorageConfigError::Store("registry"),
    }
}

/// The inventory's error as a `'static` refusal code (the closed set it
/// emits; anything else is `disk-unavailable`).
fn dedicated_code(error: &str) -> &'static str {
    const CODES: [&str; 18] = [
        "disk-facts-missing",
        "disk-facts-unreadable",
        "disk-facts-stale",
        "disk-not-found",
        "disk-not-whole-device",
        "disk-offline",
        "disk-not-block-device",
        "disk-sysfs-mismatch",
        "disk-virtual",
        "disk-has-partitions",
        "disk-holder-busy",
        "disk-is-system",
        "disk-in-use",
        "disk-no-identity",
        "disk-too-small",
        "disk-has-signature",
        "disk-probe-failed",
        "disk-duplicate",
    ];
    CODES
        .into_iter()
        .find(|code| *code == error)
        .unwrap_or("disk-unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orders::types::{DedicatedDiskSpec, StoragePoolSpec};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const NOW: u64 = 1_770_000_000;
    const GIB: u64 = 1024 * 1024 * 1024;

    /// Every path is a root-owned 0755 xfs mount of its own, on a device
    /// of its own, except those in `missing`.
    #[derive(Default)]
    struct Fs {
        missing: Vec<PathBuf>,
    }

    impl PoolFs for Fs {
        fn canonical(&self, path: &Path) -> Option<PathBuf> {
            Some(path.to_path_buf())
        }
        fn stat(&self, path: &Path) -> Option<pools::DirStat> {
            if self.missing.iter().any(|m| m == path) {
                return None;
            }
            let dev = if path == Path::new("/") {
                1
            } else {
                let mut h = DefaultHasher::new();
                path.hash(&mut h);
                h.finish() | 2
            };
            Some(pools::DirStat {
                dev,
                uid: 0,
                mode: 0o040755,
                is_dir: true,
            })
        }
        fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)> {
            Some((path.to_path_buf(), "xfs".into()))
        }
        fn odirect_ok(&self, _path: &Path) -> bool {
            true
        }
        fn total_bytes(&self, _path: &Path) -> Option<u64> {
            Some(10_000 * GIB)
        }
    }

    struct Clean;
    impl dedicated::SignatureProbe for Clean {
        fn has_signature(&self, _device: &Path) -> Result<bool, dedicated::ProbeFailed> {
            Ok(false)
        }
    }

    /// A miner: a data root, two spare pool directories, a scripted host.
    struct Miner {
        root: tempfile::TempDir,
        hdd0: tempfile::TempDir,
        hdd1: tempfile::TempDir,
        host_dir: tempfile::TempDir,
    }

    impl Miner {
        fn new() -> Self {
            let m = Self {
                root: tempfile::tempdir().unwrap(),
                hdd0: tempfile::tempdir().unwrap(),
                hdd1: tempfile::tempdir().unwrap(),
                host_dir: tempfile::tempdir().unwrap(),
            };
            let h = m.host_dir.path();
            for d in ["by-id", "sys", "by-uuid"] {
                std::fs::create_dir_all(h.join(d)).unwrap();
            }
            std::fs::write(h.join("swaps"), "Filename\n").unwrap();
            // Every pool directory is a mount of its own filesystem
            // directory (the tempdirs share one real st_dev).
            let mounts: String = [("hdd0", m.hdd0.path()), ("hdd1", m.hdd1.path())]
                .iter()
                .map(|(name, p)| format!("36 1 8:17 /{name} {} rw - xfs none rw\n", p.display()))
                .collect();
            std::fs::write(h.join("mountinfo"), mounts).unwrap();
            m
        }

        fn local(&self, pools: Vec<StoragePoolConfig>) -> LocalStorage {
            LocalStorage {
                data_root: self.root.path().to_path_buf(),
                state_root: self.root.path().to_path_buf(),
                host_budget_gb: 3000,
                pools,
                dedicated: Vec::new(),
                pools_root: None,
            }
        }

        fn host(&self, fs: Fs) -> Host {
            let h = self.host_dir.path();
            Host {
                pool_fs: Box::new(fs),
                fs_identity: FsIdentitySource {
                    mountinfo: h.join("mountinfo"),
                    udev_data: h.join("udev"),
                    sys_class_block: h.join("class-block"),
                    by_uuid: h.join("by-uuid"),
                },
                facts: Box::new(self.live_facts()),
            }
        }

        /// The fixture host's disks, read directly (the collector's view).
        fn live_facts(&self) -> dedicated::LiveFacts {
            let h = self.host_dir.path();
            dedicated::LiveFacts {
                paths: dedicated::SysPaths {
                    by_id: h.join("by-id"),
                    sys_block: h.join("sys"),
                    mountinfo: h.join("mountinfo"),
                    swaps: h.join("swaps"),
                    require_block_device: false,
                },
                probe: Box::new(Clean),
            }
        }

        /// The service as `main` builds it: boot set, registry, state.
        fn service_with(
            &self,
            local: LocalStorage,
            fs: Fs,
        ) -> (StorageConfigService, Arc<StorageState>) {
            let host = self.host(fs);
            let (pools, dedicated, revision) = boot_set(&local);
            let pools = Arc::new(pools);
            let bindings =
                registry::enforce_with(&local.state_root, &pools, &host.fs_identity).unwrap();
            let state = Arc::new(StorageState::new(EffectiveStorage {
                pools,
                dedicated,
                revision,
                bindings,
            }));
            (
                StorageConfigService::new(local, Arc::clone(&state), host, Arc::default()),
                state,
            )
        }

        fn service(&self) -> (StorageConfigService, Arc<StorageState>) {
            self.service_with(self.local(Vec::new()), Fs::default())
        }

        fn default_spec(&self) -> StoragePoolSpec {
            StoragePoolSpec {
                id: "default".into(),
                path: self.root.path().to_str().unwrap().into(),
                class: StoragePoolClass::Nvme,
                budget_gb: 3000,
                os_disks: true,
                state: StorageDesiredState::Active,
            }
        }

        fn hdd(&self, id: &str, dir: &tempfile::TempDir) -> StoragePoolSpec {
            StoragePoolSpec {
                id: id.into(),
                path: dir.path().to_str().unwrap().into(),
                class: StoragePoolClass::Hdd,
                budget_gb: 1000,
                os_disks: false,
                state: StorageDesiredState::Active,
            }
        }

        fn doc(&self, revision: u64, extra: Vec<StoragePoolSpec>) -> StorageConfigOrder {
            let mut pools = vec![self.default_spec()];
            pools.extend(extra);
            pools.sort_by(|a, b| a.id.cmp(&b.id));
            StorageConfigOrder {
                revision,
                not_after_unix: NOW + 86_400,
                dry_run: false,
                pools,
                dedicated_disks: Vec::new(),
            }
        }
    }

    fn put_disk(dir: &Path, gib: u64) {
        std::fs::create_dir_all(dir.join("overlay")).unwrap();
        std::fs::File::create(dir.join("overlay/vm-1.img"))
            .unwrap()
            .set_len(gib * GIB)
            .unwrap();
    }

    fn code(r: Outcome<String>) -> (&'static str, Subject) {
        match r.unwrap_err() {
            StorageConfigError::Refused { code, subject } => (code, subject),
            other => (other.code(), Subject::Document),
        }
    }

    fn p(id: &str) -> Subject {
        Subject::Pool(id.into())
    }

    #[test]
    fn the_digest_is_the_shared_vector_digest() {
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../test_vectors/orders/storage_config_v1.json"
            ))
            .unwrap(),
        )
        .unwrap();
        for case in v["cases"].as_array().unwrap() {
            let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            let order: crate::orders::OrderBody<StorageConfigOrder> =
                ciborium::de::from_reader(body.as_slice()).unwrap();
            assert_eq!(
                content_sha256_hex(&order.payload).unwrap(),
                case["content_sha256"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn a_valid_document_is_applied_persisted_and_in_force() {
        let m = Miner::new();
        let (svc, state) = m.service();
        assert_eq!(state.current().revision, 0);
        let doc = m.doc(3, vec![m.hdd("hdd0", &m.hdd0)]);
        let sha = content_sha256_hex(&doc).unwrap();
        assert_eq!(
            svc.accept(doc.clone(), NOW).unwrap(),
            format!("applied:3:{sha}")
        );
        let now = state.current();
        assert_eq!(now.revision, 3);
        assert!(now.pools.get("hdd0").is_some());
        assert_eq!(
            now.pools.get("hdd0").unwrap().insufficient_class(),
            "insufficient-disk:hdd0"
        );
        // The same document again: acked, nothing re-judged.
        assert_eq!(svc.accept(doc, NOW).unwrap(), format!("applied:3:{sha}"));
        // Bound in the registry.
        let reg = std::fs::read_to_string(registry::registry_path(m.root.path())).unwrap();
        assert!(reg.contains("hdd0"));
    }

    #[test]
    fn a_dry_run_judges_and_persists_nothing() {
        let m = Miner::new();
        let (svc, state) = m.service();
        let mut doc = m.doc(5, vec![m.hdd("hdd0", &m.hdd0)]);
        doc.dry_run = true;
        let sha = content_sha256_hex(&doc).unwrap();
        assert_eq!(
            svc.accept(doc.clone(), NOW).unwrap(),
            format!("dry-run-ok:5:{sha}")
        );
        assert_eq!(state.current().revision, 0);
        assert!(!record_path(m.root.path()).exists());
        assert!(!registry::registry_path(m.root.path()).exists());
        // …and a failing one says why, still touching nothing.
        let (svc, state) = m.service_with(
            m.local(Vec::new()),
            Fs {
                missing: vec![m.hdd0.path().to_path_buf()],
            },
        );
        assert_eq!(code(svc.accept(doc, NOW)), ("pool-path-missing", p("hdd0")));
        assert_eq!(state.current().revision, 0);
        assert!(!record_path(m.root.path()).exists());
    }

    #[test]
    fn the_replay_rules_hold_and_survive_a_restart() {
        let m = Miner::new();
        let (svc, _) = m.service();
        svc.accept(m.doc(4, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        assert_eq!(
            svc.accept(m.doc(3, vec![m.hdd("hdd0", &m.hdd0)]), NOW),
            Err(StorageConfigError::StaleRevision)
        );
        assert_eq!(
            svc.accept(m.doc(4, vec![m.hdd("hdd1", &m.hdd1)]), NOW),
            Err(StorageConfigError::RevisionConflict)
        );
        // A restart reloads the document as the set in force, and keeps
        // the floor.
        let (svc, state) = m.service();
        assert_eq!(state.current().revision, 4);
        assert!(state.current().pools.get("hdd0").is_some());
        assert_eq!(
            svc.accept(m.doc(3, Vec::new()), NOW),
            Err(StorageConfigError::StaleRevision)
        );
    }

    #[test]
    fn a_stored_document_that_no_longer_fits_the_local_config_falls_back_to_local() {
        let m = Miner::new();
        let (svc, _) = m.service();
        svc.accept(m.doc(4, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        // The operator changed the host budget locally.
        let mut local = m.local(Vec::new());
        local.host_budget_gb = 2000;
        let (pools, _, revision) = boot_set(&local);
        assert_eq!(revision, 0);
        // The document's pool stays, draining; `default` is the local one.
        let hdd0 = pools.get("hdd0").unwrap();
        assert!(hdd0.draining);
        assert_eq!(hdd0.path, m.hdd0.path());
        assert_eq!(pools.default_pool().budget_gb, 2000);
        // …so a pool holding disks does not stop the start.
        put_disk(m.hdd0.path(), 1);
        let (svc, state) = m.service_with(local, Fs::default());
        assert!(state.current().pools.get("hdd0").unwrap().draining);
        drop(svc);
        std::fs::remove_file(m.hdd0.path().join("overlay/vm-1.img")).unwrap();
        // A corrupt record: local set, and orders refused.
        std::fs::write(record_path(m.root.path()), b"{").unwrap();
        let (svc, state) = m.service();
        assert_eq!(state.current().revision, 0);
        assert_eq!(
            svc.accept(m.doc(9, Vec::new()), NOW),
            Err(StorageConfigError::Store("parse"))
        );
    }

    #[test]
    fn the_same_revision_is_re_judged_when_it_is_not_in_force() {
        let m = Miner::new();
        let (svc, _) = m.service();
        svc.accept(m.doc(4, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        // Restart with a local config the stored document conflicts with.
        let mut local = m.local(Vec::new());
        local.host_budget_gb = 2000;
        let (svc, state) = m.service_with(local, Fs::default());
        assert_eq!(state.current().revision, 0);
        assert_eq!(
            code(svc.accept(m.doc(4, vec![m.hdd("hdd0", &m.hdd0)]), NOW)),
            ("pool-conflicts-local", p("default"))
        );
    }

    type Mutation = Box<dyn Fn(&mut StorageConfigOrder)>;

    #[test]
    fn the_same_revision_in_force_is_acked_without_re_judging_the_host() {
        let m = Miner::new();
        let (svc, _) = m.service();
        let doc = m.doc(4, vec![m.hdd("hdd0", &m.hdd0)]);
        svc.accept(doc.clone(), NOW).unwrap();
        // The pool's mount has gone since: the document in force is still
        // acked (the heartbeat reports the pool unavailable)…
        let gone = Fs {
            missing: vec![m.hdd0.path().to_path_buf()],
        };
        let (svc, state) = m.service_with(m.local(Vec::new()), gone);
        assert_eq!(state.current().revision, 4);
        assert!(svc
            .accept(doc.clone(), NOW)
            .unwrap()
            .starts_with("applied:4:"));
        // …but a set in force that is not that document re-judges it.
        state.replace(EffectiveStorage::local(
            Arc::new(m.local(Vec::new()).local_set().0),
            Vec::new(),
            registry::PoolBindings::default(),
        ));
        assert_eq!(code(svc.accept(doc, NOW)), ("pool-path-missing", p("hdd0")));
        assert_eq!(state.current().revision, 0);
    }

    #[test]
    fn static_refusals_name_their_pool_or_disk() {
        let m = Miner::new();
        let (svc, _) = m.service();
        let base = m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]);
        let cases: Vec<(Mutation, &str, Subject)> = vec![
            (
                Box::new(|d| d.revision = 0),
                "storage-config-revision-invalid",
                Subject::Document,
            ),
            (
                Box::new(|d| d.not_after_unix = NOW - 1),
                "storage-config-expired",
                Subject::Document,
            ),
            (
                Box::new(|d| d.not_after_unix = NOW + MAX_STORAGE_CONFIG_TTL_SECS + 1),
                "storage-config-not-after-invalid",
                Subject::Document,
            ),
            (
                Box::new(|d| d.pools[1].id = "HDD".into()),
                "pool-id-invalid",
                p("HDD"),
            ),
            (
                Box::new(|d| d.pools.swap(0, 1)),
                "pool-id-invalid",
                p("default"),
            ),
            (
                Box::new(|d| d.pools[1].path = "srv/x".into()),
                "pool-path-invalid",
                p("hdd0"),
            ),
            (
                Box::new(|d| d.pools[1].path.push('/')),
                "pool-path-invalid",
                p("hdd0"),
            ),
            (
                Box::new(|d| d.pools[1].path.push_str("/../x")),
                "pool-path-invalid",
                p("hdd0"),
            ),
            (
                Box::new(|d| d.pools[1].path = d.pools[0].path.clone()),
                "pool-shared-fs",
                p("hdd0"),
            ),
            (
                Box::new(|d| d.pools[1].budget_gb = 0),
                "pool-budget-invalid",
                p("hdd0"),
            ),
            (
                Box::new(|d| {
                    d.pools.remove(0);
                }),
                "pool-default-required",
                p("default"),
            ),
            (
                Box::new(|d| d.pools[0].budget_gb = 10),
                "pool-conflicts-local",
                p("default"),
            ),
            (
                Box::new(|d| d.pools[0].path = "/srv/elsewhere".into()),
                "pool-conflicts-local",
                p("default"),
            ),
            (
                Box::new(|d| d.pools[0].os_disks = false),
                "pool-conflicts-local",
                p("default"),
            ),
            (
                Box::new(|d| d.pools[0].state = StorageDesiredState::Draining),
                "pool-conflicts-local",
                p("default"),
            ),
            (
                Box::new(|d| {
                    for i in 0..4 {
                        d.pools.push(StoragePoolSpec {
                            id: format!("z{i}"),
                            ..d.pools[1].clone()
                        });
                    }
                }),
                "too-many-pools",
                Subject::Document,
            ),
            (
                Box::new(|d| {
                    d.dedicated_disks = vec![DedicatedDiskSpec {
                        id: "sda".into(),
                        state: StorageDesiredState::Active,
                    }]
                }),
                "disk-id-invalid",
                Subject::Disk("sda".into()),
            ),
            (
                Box::new(|d| {
                    let disk = DedicatedDiskSpec {
                        id: "wwn-0x1".into(),
                        state: StorageDesiredState::Draining,
                    };
                    d.dedicated_disks = vec![disk.clone(), disk];
                }),
                "disk-duplicate",
                Subject::Disk("wwn-0x1".into()),
            ),
            (
                Box::new(|d| {
                    d.dedicated_disks = (0..25)
                        .map(|i| DedicatedDiskSpec {
                            id: format!("wwn-0x{i:02}"),
                            state: StorageDesiredState::Draining,
                        })
                        .collect()
                }),
                "too-many-disks",
                Subject::Document,
            ),
        ];
        for (mutate, want, subject) in cases {
            let mut doc = base.clone();
            mutate(&mut doc);
            assert_eq!(code(svc.accept(doc, NOW)), (want, subject), "{want}");
        }
    }

    #[test]
    fn a_local_pool_cannot_change_path_remotely() {
        let m = Miner::new();
        let local_hdd = StoragePoolConfig {
            id: "hdd0".into(),
            path: m.hdd0.path().to_path_buf(),
            class: PoolClassConfig::Hdd,
            budget_gb: 1000,
            os_disks: false,
            state: StorageDesiredStateConfig::Active,
        };
        let default = StoragePoolConfig {
            id: "default".into(),
            path: m.root.path().to_path_buf(),
            class: PoolClassConfig::Nvme,
            budget_gb: 3000,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        };
        let (svc, _) = m.service_with(m.local(vec![default, local_hdd]), Fs::default());
        assert_eq!(
            code(svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd1)]), NOW)),
            ("pool-conflicts-local", p("hdd0"))
        );
        // The same path is fine.
        svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
    }

    #[test]
    fn host_checks_refuse_an_active_pool_but_not_a_draining_one_in_force() {
        let m = Miner::new();
        let gone = || Fs {
            missing: vec![m.hdd0.path().to_path_buf()],
        };
        let (svc, _) = m.service_with(m.local(Vec::new()), gone());
        assert_eq!(
            code(svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)),
            ("pool-path-missing", p("hdd0"))
        );
        // A new pool cannot be declared draining to skip the checks.
        let mut draining = m.hdd("hdd0", &m.hdd0);
        draining.state = StorageDesiredState::Draining;
        assert_eq!(
            code(svc.accept(m.doc(2, vec![draining.clone()]), NOW)),
            ("pool-path-missing", p("hdd0"))
        );
        // A pool in force whose mount has gone can be set draining.
        let (svc, _) = m.service();
        svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        let (svc, state) = m.service_with(m.local(Vec::new()), gone());
        assert_eq!(state.current().revision, 2);
        assert_eq!(
            code(svc.accept(m.doc(3, vec![m.hdd("hdd0", &m.hdd0)]), NOW)),
            ("pool-path-missing", p("hdd0"))
        );
        svc.accept(m.doc(3, vec![draining]), NOW).unwrap();
    }

    #[test]
    fn a_pool_holding_disks_is_never_dropped_or_moved() {
        let m = Miner::new();
        let (svc, state) = m.service();
        svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        put_disk(m.hdd0.path(), 1);
        // Dropped.
        assert_eq!(
            code(svc.accept(m.doc(3, Vec::new()), NOW)),
            ("pool-has-disks", p("hdd0"))
        );
        // Moved.
        assert_eq!(
            code(svc.accept(m.doc(3, vec![m.hdd("hdd0", &m.hdd1)]), NOW)),
            ("pool-has-disks", p("hdd0"))
        );
        // Swapped with another pool's path in one revision.
        assert_eq!(
            code(svc.accept(
                m.doc(3, vec![m.hdd("hdd0", &m.hdd1), m.hdd("hdd1", &m.hdd0)]),
                NOW
            )),
            ("pool-has-disks", p("hdd0"))
        );
        // Draining is the way out; nothing changed meanwhile.
        assert_eq!(state.current().revision, 2);
        let mut draining = m.hdd("hdd0", &m.hdd0);
        draining.state = StorageDesiredState::Draining;
        svc.accept(m.doc(3, vec![draining]), NOW).unwrap();
        // Once empty it can go.
        std::fs::remove_file(m.hdd0.path().join("overlay/vm-1.img")).unwrap();
        svc.accept(m.doc(4, Vec::new()), NOW).unwrap();
        assert!(state.current().pools.get("hdd0").is_none());
    }

    #[test]
    fn a_budget_below_what_the_pool_holds_is_refused() {
        let m = Miner::new();
        let (svc, _) = m.service();
        svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        put_disk(m.hdd0.path(), 150);
        let mut small = m.hdd("hdd0", &m.hdd0);
        small.budget_gb = 100;
        assert_eq!(
            code(svc.accept(m.doc(3, vec![small.clone()]), NOW)),
            ("pool-budget-below-committed", p("hdd0"))
        );
        // Draining too.
        small.state = StorageDesiredState::Draining;
        assert_eq!(
            code(svc.accept(m.doc(3, vec![small]), NOW)),
            ("pool-budget-below-committed", p("hdd0"))
        );
        // Growing is fine.
        let mut big = m.hdd("hdd0", &m.hdd0);
        big.budget_gb = 2000;
        svc.accept(m.doc(3, vec![big]), NOW).unwrap();
    }

    #[test]
    fn an_active_dedicated_disk_must_pass_the_inventory_a_draining_one_need_not() {
        let m = Miner::new();
        let (svc, _) = m.service();
        let mut doc = m.doc(2, Vec::new());
        doc.dedicated_disks = vec![DedicatedDiskSpec {
            id: "wwn-0x5000c500a1b2c3d4".into(),
            state: StorageDesiredState::Active,
        }];
        assert_eq!(
            code(svc.accept(doc.clone(), NOW)),
            (
                "disk-not-found",
                Subject::Disk("wwn-0x5000c500a1b2c3d4".into())
            )
        );
        doc.dedicated_disks[0].state = StorageDesiredState::Draining;
        svc.accept(doc, NOW).unwrap();
    }

    #[test]
    fn an_empty_pool_may_move_to_another_filesystem() {
        let m = Miner::new();
        let (svc, state) = m.service();
        svc.accept(m.doc(2, vec![m.hdd("hdd0", &m.hdd0)]), NOW)
            .unwrap();
        svc.accept(m.doc(3, vec![m.hdd("hdd0", &m.hdd1)]), NOW)
            .unwrap();
        assert_eq!(
            state.current().pools.get("hdd0").unwrap().path,
            m.hdd1.path()
        );
    }

    /// A clean 2 TiB whole disk `wwn-0x1` in the miner's fixture host.
    fn add_disk(m: &Miner) {
        let h = m.host_dir.path();
        for d in ["dev", "sys/sdb/device", "sys/sdb/holders"] {
            std::fs::create_dir_all(h.join(d)).unwrap();
        }
        std::fs::write(h.join("dev/sdb"), b"").unwrap();
        std::fs::write(h.join("sys/sdb/size"), format!("{}\n", 4u64 << 30)).unwrap();
        std::fs::write(h.join("sys/sdb/dev"), "8:16\n").unwrap();
        std::fs::write(h.join("sys/sdb/device/wwid"), "naa.1\n").unwrap();
        std::os::unix::fs::symlink(h.join("dev/sdb"), h.join("by-id/wwn-0x1")).unwrap();
    }

    #[test]
    fn an_accepted_disk_is_bound_to_its_identity_before_the_ack() {
        let m = Miner::new();
        add_disk(&m);
        let (svc, state) = m.service();
        let mut doc = m.doc(2, Vec::new());
        doc.dedicated_disks = vec![DedicatedDiskSpec {
            id: "wwn-0x1".into(),
            state: StorageDesiredState::Active,
        }];
        // A dry run binds nothing.
        let mut dry = doc.clone();
        dry.dry_run = true;
        svc.accept(dry, NOW).unwrap();
        let ids = dedicated::IdentityMap::load(m.root.path()).unwrap();
        assert!(ids.disks.is_empty());
        svc.accept(doc, NOW).unwrap();
        let ids = dedicated::IdentityMap::load(m.root.path()).unwrap();
        assert_eq!(ids.disks["wwn-0x1"], "naa.1");
        assert_eq!(state.current().dedicated.len(), 1);
        // Another disk behind the same name is refused from then on.
        std::fs::write(m.host_dir.path().join("sys/sdb/device/wwid"), "naa.2\n").unwrap();
        let mut again = m.doc(3, Vec::new());
        again.dedicated_disks = vec![DedicatedDiskSpec {
            id: "wwn-0x1".into(),
            state: StorageDesiredState::Active,
        }];
        assert_eq!(
            code(svc.accept(again, NOW)),
            ("disk-replaced", Subject::Disk("wwn-0x1".into()))
        );
    }

    #[test]
    fn the_heartbeat_inventory_sees_the_binding_the_route_made() {
        let m = Miner::new();
        add_disk(&m);
        let host = m.host(Fs::default());
        let identities: Arc<dedicated::IdentityStore> = Arc::default();
        // A locally declared disk, so the reporter reads the map at once.
        let mut local = m.local(Vec::new());
        local.dedicated = vec![DedicatedDiskConfig {
            id: "wwn-0x9".into(),
            state: StorageDesiredStateConfig::Draining,
        }];
        let (pools, dedicated, revision) = boot_set(&local);
        let pools = Arc::new(pools);
        let bindings =
            registry::enforce_with(&local.state_root, &pools, &host.fs_identity).unwrap();
        let state = Arc::new(StorageState::new(EffectiveStorage {
            pools,
            dedicated,
            revision,
            bindings,
        }));
        let svc =
            StorageConfigService::new(local, Arc::clone(&state), host, Arc::clone(&identities));
        let reporter = super::super::StorageReporter::with_host(
            Arc::clone(&state),
            m.root.path().to_path_buf(),
            Box::new(Fs::default()),
            Box::new(m.live_facts()),
        )
        .with_identities(Arc::clone(&identities));
        // The reporter has loaded the (empty) map before the apply.
        assert_eq!(reporter.report().dedicated_disks.len(), 1);
        let mut doc = m.doc(2, Vec::new());
        doc.dedicated_disks = vec![DedicatedDiskSpec {
            id: "wwn-0x1".into(),
            state: StorageDesiredState::Active,
        }];
        svc.accept(doc, NOW).unwrap();
        // Another disk behind the name before the next heartbeat: the
        // inventory knows the first one, so it reports the swap.
        std::fs::write(m.host_dir.path().join("sys/sdb/device/wwid"), "naa.2\n").unwrap();
        let report = reporter.report();
        let disk = report
            .dedicated_disks
            .iter()
            .find(|d| d.id == "wwn-0x1")
            .unwrap();
        assert_eq!(disk.state, DedicatedDiskState::Replaced);
        let ids = dedicated::IdentityMap::load(m.root.path()).unwrap();
        assert_eq!(ids.disks["wwn-0x1"], "naa.1");
    }

    #[test]
    fn a_re_push_in_force_binds_an_identity_the_apply_could_not_save() {
        let m = Miner::new();
        add_disk(&m);
        let (svc, _) = m.service();
        let mut doc = m.doc(2, Vec::new());
        doc.dedicated_disks = vec![DedicatedDiskSpec {
            id: "wwn-0x1".into(),
            state: StorageDesiredState::Active,
        }];
        svc.accept(doc.clone(), NOW).unwrap();
        // As if the identity save had failed after the record was written.
        std::fs::remove_file(m.root.path().join(dedicated::IDENTITY_FILE)).unwrap();
        let (svc, state) = m.service();
        assert_eq!(state.current().revision, 2);
        assert!(svc.accept(doc, NOW).unwrap().starts_with("applied:2:"));
        let ids = dedicated::IdentityMap::load(m.root.path()).unwrap();
        assert_eq!(ids.disks["wwn-0x1"], "naa.1");
    }

    #[test]
    fn refusal_bodies_are_the_wire_contract() {
        assert_eq!(
            pool("pool-has-disks", "hdd0").body(),
            r#"{"code":"pool-has-disks","pool":"hdd0"}"#
        );
        assert_eq!(
            disk("disk-has-signature", "wwn-0x1").body(),
            r#"{"code":"disk-has-signature","disk":"wwn-0x1"}"#
        );
        assert_eq!(
            refused("too-many-pools", Subject::Document).body(),
            r#"{"code":"too-many-pools"}"#
        );
        assert_eq!(StorageConfigError::StaleRevision.status(), 409);
        assert_eq!(
            StorageConfigError::StaleRevision.body(),
            r#"{"code":"storage-config-stale-revision"}"#
        );
        assert_eq!(StorageConfigError::Store("write").status(), 500);
        assert_eq!(dedicated_code("disk-in-use"), "disk-in-use");
        assert_eq!(dedicated_code("something-new"), "disk-unavailable");
    }
}
