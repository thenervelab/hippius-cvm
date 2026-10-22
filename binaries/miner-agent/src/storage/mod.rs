//! Storage pools and dedicated disks (docs/design/disk-tier-verification.md
//! §4, §9) — what the agent offers vali for OS disks and passthrough.
//!
//! - [`pools`] — the pool set (implicit `default`, or `[[storage.pools]]`),
//!   the host checks, per-pool committed space.
//! - [`registry`] — the guard that refuses to start when a pool holding VM
//!   disks was dropped from the config.
//! - [`dedicated`] — the read-only dedicated-disk inventory and identity
//!   binding.
//! - [`assignment`] — which VM holds which dedicated disk (launch claim,
//!   re-attach, §24 release), inside the agent's sandbox.
//! - [`dedicated_helper`] — the privileged hold and release wipe, run in
//!   systemd units outside the sandbox.
//! - [`state`] — the storage set in force, swapped whole by an applied
//!   `storage-config`.
//! - [`reclaim`] — the per-VM disks a destroy could not reach on a pool
//!   off its filesystem, unlinked once the pool is back.
//! - [`remote`] — the `storage-config` order: validation, dry run,
//!   persistence and the restart reload.
//! - [`StorageReporter`] — the `v7` heartbeat's storage report, built from
//!   all of it.

pub mod assignment;
pub mod check;
pub mod dedicated;
pub mod dedicated_helper;
pub mod pools;
pub mod reclaim;
pub mod registry;
pub mod remote;
pub mod state;

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use hippius_types::storage_report::{DiskPoolReport, PoolState, StorageReport};

pub use pools::{StoragePools, DEFAULT_POOL_ID};

/// Where the launch gate and destroy read the host: the pool checks and
/// the filesystem bindings. Real by default; scripted in tests.
pub struct PoolHost {
    pub pool_fs: Box<dyn pools::PoolFs + Send + Sync>,
    pub fs_identity: registry::FsIdentitySource,
}

impl PoolHost {
    pub fn system() -> Self {
        Self {
            pool_fs: Box::new(pools::SystemPoolFs::default()),
            fs_identity: registry::FsIdentitySource::default(),
        }
    }
}

impl std::fmt::Debug for PoolHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolHost")
            .field("fs_identity", &self.fs_identity)
            .finish_non_exhaustive()
    }
}

/// Builds the `v7` storage report. Reads the host on every call (pool
/// checks, sizes, the disk inventory): a vanished mount or a pulled disk
/// shows up on the next heartbeat.
pub struct StorageReporter {
    /// The set in force, read once per report.
    storage: Arc<state::StorageState>,
    state_root: PathBuf,
    pool_fs: Box<dyn pools::PoolFs + Send + Sync>,
    /// The dedicated-disk facts: the collector's report (the agent's
    /// sandbox shows no block device).
    facts: Box<dyn dedicated::FactsSource>,
    /// Loaded on first use; `None` inside = the file is corrupt, so no
    /// identity is recorded (and none forgotten) until an operator looks.
    /// Shared with the `storage-config` route.
    identities: Arc<dedicated::IdentityStore>,
    /// Who holds which dedicated disk, and whether the privileged helper
    /// is installed (shared with the lifecycle).
    dedicated: Arc<assignment::DedicatedDisks>,
}

/// `bytes` as whole GiB, saturating into `u32`.
fn gib_u32(bytes: u64) -> u32 {
    u32::try_from(bytes / (1024 * 1024 * 1024)).unwrap_or(u32::MAX)
}

impl StorageReporter {
    /// The production reporter: the real filesystem and the collector's
    /// disk facts.
    pub fn new(storage: Arc<state::StorageState>, state_root: PathBuf) -> Self {
        Self::with_host(
            storage,
            state_root,
            Box::new(pools::SystemPoolFs::default()),
            Box::new(dedicated::FileFacts::default()),
        )
    }

    /// A reporter over an injected host (tests).
    pub fn with_host(
        storage: Arc<state::StorageState>,
        state_root: PathBuf,
        pool_fs: Box<dyn pools::PoolFs + Send + Sync>,
        facts: Box<dyn dedicated::FactsSource>,
    ) -> Self {
        Self {
            storage,
            state_root,
            pool_fs,
            facts,
            identities: Arc::default(),
            dedicated: Arc::default(),
        }
    }

    /// Share the lifecycle's dedicated-disk service (its records and its
    /// helper).
    pub fn with_dedicated(mut self, dedicated: Arc<assignment::DedicatedDisks>) -> Self {
        self.dedicated = dedicated;
        self
    }

    /// Share the dedicated-disk identities with the `storage-config`
    /// route.
    pub fn with_identities(mut self, identities: Arc<dedicated::IdentityStore>) -> Self {
        self.identities = identities;
        self
    }

    /// The pools as the host check sees them, with sizes.
    pub fn pool_reports(&self) -> Vec<DiskPoolReport> {
        self.pool_reports_of(&self.storage.current())
    }

    fn pool_reports_of(&self, set: &state::EffectiveStorage) -> Vec<DiskPoolReport> {
        let binding_errors = set
            .bindings
            .errors_now(&set.pools, &registry::FsIdentitySource::default());
        let checks = pools::check_pools(&set.pools, self.pool_fs.as_ref(), &binding_errors);
        let mut reports = set
            .pools
            .iter()
            .map(|pool| {
                let check = checks.get(&pool.id).copied().unwrap_or(pools::PoolCheck {
                    state: PoolState::Unavailable,
                    error: "pool-path-missing",
                });
                let usable = check.state != PoolState::Unavailable;
                let total = if usable {
                    self.pool_fs.total_bytes(&pool.path).unwrap_or(0)
                } else {
                    0
                };
                // The figure the agent's own create gate admits against:
                // free space net of every disk's unwritten tail and of the
                // in-flight reservations.
                let available = if usable {
                    let reserved = *crate::lifecycle::disk_space::create_lock();
                    crate::lifecycle::disk_space::headroom_bytes(reserved, &pool.path, &pool.path)
                        .unwrap_or(0)
                } else {
                    0
                };
                let (total_gb, mut available_gb) = (gib_u32(total), gib_u32(available));
                if total_gb != 0 && available_gb > total_gb {
                    available_gb = total_gb;
                }
                DiskPoolReport {
                    id: pool.id.clone(),
                    class: pool.class,
                    total_gb,
                    available_gb,
                    budget_gb: u32::try_from(pool.budget_gb).unwrap_or(u32::MAX),
                    committed_gb: u32::try_from(pools::committed_gb(&pool.path))
                        .unwrap_or(u32::MAX),
                    os_disks: pool.os_disks,
                    state: check.state,
                    error: check.error.to_string(),
                }
            })
            .collect::<Vec<_>>();
        // At most the schema's pool count, `default` always among them:
        // pools kept only because they may hold disks can exceed it, and a
        // report the schema refuses would drop every pool and disk from
        // the heartbeat.
        // Declared pools first; those kept only because they may hold disks
        // (no class) go first when it overflows.
        if reports.len() > hippius_types::storage_report::MAX_DISK_POOLS {
            let mut others: Vec<(bool, String)> = reports
                .iter()
                .filter(|p| p.id != DEFAULT_POOL_ID)
                .map(|p| {
                    (
                        p.class == hippius_types::storage_report::PoolClass::Undeclared,
                        p.id.clone(),
                    )
                })
                .collect();
            others.sort();
            others.truncate(hippius_types::storage_report::MAX_DISK_POOLS - 1);
            reports.retain(|p| p.id == DEFAULT_POOL_ID || others.iter().any(|(_, id)| *id == p.id));
        }
        reports
    }

    /// `major:minor` of the filesystems the host itself needs: `/`, the
    /// state root and every pool. A dedicated disk carrying one is refused.
    fn system_devs(&self, set: &state::EffectiveStorage) -> BTreeSet<String> {
        system_devs(&self.state_root, &set.pools)
    }

    /// The whole `v7` storage report, `storage_config_revision` the
    /// applied `storage-config` (`0` for the local set).
    pub fn report(&self) -> StorageReport {
        let set = self.storage.current();
        let owners = assignment::owners(&self.state_root);
        let dedicated_disks =
            if set.dedicated.is_empty() && matches!(&owners, Ok(o) if o.is_empty()) {
                Vec::new()
            } else {
                self.dedicated_reports(&set, owners)
            };
        StorageReport {
            disk_pools: self.pool_reports_of(&set),
            dedicated_disks,
            storage_config_revision: set.revision,
        }
    }

    /// The dedicated disks: the inventory of the declared ones, then who
    /// holds which ([`assignment::apply_owners`]). A free disk is offered
    /// only where the privileged helper (hold, release wipe) is installed.
    fn dedicated_reports(
        &self,
        set: &state::EffectiveStorage,
        owners: std::result::Result<
            std::collections::BTreeMap<String, assignment::Owner>,
            assignment::Unreadable,
        >,
    ) -> Vec<hippius_types::storage_report::DedicatedDiskReport> {
        use hippius_types::storage_report::DedicatedDiskState;
        let facts = self.facts.facts();
        let mut reports = self.inventory_reports(set, facts.as_ref().map_err(|e| *e));
        match owners {
            Ok(owners) => {
                assignment::apply_owners(&mut reports, &owners, facts.as_ref().map_err(|e| *e));
            }
            Err(assignment::Unreadable) => {
                eprintln!(
                    "hippius-miner-agent: storage: dedicated-disk assignment records unreadable; \
                     dedicated disks reported unavailable"
                );
                for r in &mut reports {
                    r.state = DedicatedDiskState::Unavailable;
                    r.vm.clear();
                    r.error = "disk-assignment-unreadable".into();
                }
            }
        }
        if !self.dedicated.helper().installed() {
            for r in &mut reports {
                if r.state == DedicatedDiskState::Free {
                    r.state = DedicatedDiskState::Unavailable;
                    r.error = "disk-helper-missing".into();
                }
            }
        }
        reports
    }

    /// The inventory of the declared dedicated disks (binding new
    /// identities).
    fn inventory_reports(
        &self,
        set: &state::EffectiveStorage,
        facts: std::result::Result<&dedicated::DiskFacts, &'static str>,
    ) -> Vec<hippius_types::storage_report::DedicatedDiskReport> {
        if set.dedicated.is_empty() {
            Vec::new()
        } else {
            let mut guard = self.identities.lock();
            let loaded =
                guard.get_or_insert_with(|| dedicated::IdentityMap::load(&self.state_root));
            match loaded {
                Some(identities) => {
                    let before = identities.clone();
                    let reports = dedicated::inventory(
                        &set.dedicated,
                        facts,
                        &self.system_devs(set),
                        identities,
                    );
                    let mut reports = reports;
                    if *identities != before && identities.save(&self.state_root).is_err() {
                        eprintln!(
                            "hippius-miner-agent: storage: dedicated-disk identities not saved"
                        );
                        // A disk is accepted only once its identity is on
                        // disk: the newly bound ones are not offered.
                        for report in &mut reports {
                            if !before.disks.contains_key(&report.id)
                                && identities.disks.contains_key(&report.id)
                            {
                                report.state =
                                    hippius_types::storage_report::DedicatedDiskState::Unavailable;
                                report.error = "disk-identity-unsaved".into();
                            }
                        }
                        *identities = before;
                    }
                    reports
                }
                None => {
                    eprintln!(
                        "hippius-miner-agent: storage: {} is unreadable; dedicated disks \
                         reported unavailable",
                        dedicated::IDENTITY_FILE
                    );
                    let mut reports: Vec<_> = set
                        .dedicated
                        .iter()
                        .map(|d| hippius_types::storage_report::DedicatedDiskReport {
                            id: d.id.clone(),
                            size_mb: 0,
                            state: hippius_types::storage_report::DedicatedDiskState::Unavailable,
                            vm: String::new(),
                            error: "disk-identity-store-unreadable".into(),
                        })
                        .collect();
                    reports.sort_by(|a, b| a.id.cmp(&b.id));
                    reports
                }
            }
        }
    }
}

/// `major:minor` of the filesystems the host itself needs: `/`, the
/// state root and every pool. A dedicated disk carrying one is refused.
pub fn system_devs(state_root: &std::path::Path, pools: &StoragePools) -> BTreeSet<String> {
    let mut paths = vec![PathBuf::from("/"), state_root.to_path_buf()];
    paths.extend(pools.iter().map(|p| p.path.clone()));
    paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| dedicated::dev_string(m.dev()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DedicatedDiskConfig, PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig,
        StorageSection,
    };
    use hippius_types::storage_report::DedicatedDiskState;
    use std::path::Path;

    /// Every path exists as a root-owned 0755 mount of its own, on its own
    /// device, except those listed in `missing`.
    struct Fs {
        missing: Vec<PathBuf>,
    }

    impl pools::PoolFs for Fs {
        fn canonical(&self, path: &Path) -> Option<PathBuf> {
            Some(path.to_path_buf())
        }
        fn stat(&self, path: &Path) -> Option<pools::DirStat> {
            if self.missing.iter().any(|m| m == path) {
                return None;
            }
            // A distinct device per path (`/` is 1).
            let dev = path.as_os_str().len() as u64 + if path == Path::new("/") { 0 } else { 100 };
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
            Some(10_000 * 1024 * 1024 * 1024)
        }
    }

    use dedicated::ProbeFailed;

    struct Clean;
    impl dedicated::SignatureProbe for Clean {
        fn has_signature(&self, _device: &Path) -> Result<bool, ProbeFailed> {
            Ok(false)
        }
    }

    fn pools(default_root: &Path, hdd_root: &Path) -> Arc<StoragePools> {
        let pool = |id: &str, path: &Path| StoragePoolConfig {
            id: id.into(),
            path: path.to_path_buf(),
            class: PoolClassConfig::Hdd,
            budget_gb: 100,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        };
        Arc::new(StoragePools::from_config(
            &StorageSection {
                data_disk_root: default_root.to_path_buf(),
                state_disk_root: default_root.to_path_buf(),
                pools: vec![pool("default", default_root), pool("hdd0", hdd_root)],
                dedicated_disks: Vec::new(),
            },
            100,
        ))
    }

    /// The privileged helper as installed (or not).
    struct Helper(bool);
    impl assignment::DedicatedHelper for Helper {
        fn installed(&self) -> bool {
            self.0
        }
        fn hold(&self, _: &str) -> Result<(), &'static str> {
            Ok(())
        }
        fn unhold(&self, _: &str) -> Result<(), &'static str> {
            Ok(())
        }
        fn release(&self, _: &str) -> Result<(), &'static str> {
            Ok(())
        }
    }

    /// A 2 TiB clean whole disk `wwn-0x1` (`naa.1`) on a fixture host, the
    /// default pool and an absent `hdd0`, and a reporter over them whose
    /// helper is `installed`.
    struct Fixture {
        root: tempfile::TempDir,
        _hdd: tempfile::TempDir,
        _host: tempfile::TempDir,
        reporter: StorageReporter,
    }

    fn fixture(installed: bool) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let h = host.path();
        for d in ["dev", "by-id", "sys/sdb/device", "sys/sdb/holders"] {
            std::fs::create_dir_all(h.join(d)).unwrap();
        }
        std::fs::write(h.join("dev/sdb"), b"").unwrap();
        std::fs::write(h.join("sys/sdb/size"), format!("{}\n", 4u64 << 30)).unwrap();
        std::fs::write(h.join("sys/sdb/dev"), "8:16\n").unwrap();
        std::fs::write(h.join("sys/sdb/device/wwid"), "naa.1\n").unwrap();
        std::os::unix::fs::symlink(h.join("dev/sdb"), h.join("by-id/wwn-0x1")).unwrap();
        std::fs::write(h.join("mountinfo"), "").unwrap();
        std::fs::write(h.join("swaps"), "Filename\n").unwrap();

        let pools = pools(root.path(), hdd.path());
        let bindings = registry::enforce(root.path(), &pools).unwrap();
        let storage = Arc::new(state::StorageState::new(state::EffectiveStorage {
            pools,
            dedicated: vec![DedicatedDiskConfig {
                id: "wwn-0x1".into(),
                state: StorageDesiredStateConfig::Active,
            }],
            revision: 7,
            bindings,
        }));
        let facts = || {
            Box::new(dedicated::LiveFacts {
                paths: dedicated::SysPaths {
                    by_id: h.join("by-id"),
                    sys_block: h.join("sys"),
                    mountinfo: h.join("mountinfo"),
                    swaps: h.join("swaps"),
                    require_block_device: false,
                },
                probe: Box::new(Clean),
            })
        };
        let reporter = StorageReporter::with_host(
            storage,
            root.path().to_path_buf(),
            Box::new(Fs {
                missing: vec![hdd.path().to_path_buf()],
            }),
            facts(),
        )
        .with_dedicated(Arc::new(assignment::DedicatedDisks::new(
            facts(),
            Box::new(Helper(installed)),
            Arc::default(),
        )));
        Fixture {
            root,
            _hdd: hdd,
            _host: host,
            reporter,
        }
    }

    #[test]
    fn the_report_carries_every_pool_and_disk_and_is_valid() {
        let f = fixture(true);
        let report = f.reporter.report();
        assert_eq!(report.validate(), Ok(()));
        assert_eq!(report.storage_config_revision, 7);
        let ids: Vec<_> = report.disk_pools.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["default", "hdd0"]);
        let hdd0 = &report.disk_pools[1];
        assert_eq!(hdd0.state, PoolState::Unavailable);
        assert_eq!(hdd0.error, "pool-path-missing");
        assert_eq!((hdd0.total_gb, hdd0.available_gb), (0, 0));
        assert_eq!(hdd0.budget_gb, 100);
        assert_eq!(report.disk_pools[0].state, PoolState::Active);
        assert_eq!(report.dedicated_disks.len(), 1);
        assert_eq!(report.dedicated_disks[0].state, DedicatedDiskState::Free);
        // The accepted disk's identity is now on disk.
        let ids = dedicated::IdentityMap::load(f.root.path()).unwrap();
        assert_eq!(ids.disks["wwn-0x1"], "naa.1");
    }

    #[test]
    fn a_free_disk_is_offered_only_where_the_privileged_helper_is_installed() {
        let f = fixture(false);
        let report = f.reporter.report();
        assert_eq!(report.validate(), Ok(()));
        let disk = &report.dedicated_disks[0];
        assert_eq!(disk.state, DedicatedDiskState::Unavailable);
        assert_eq!(disk.error, "disk-helper-missing");
    }

    #[test]
    fn held_disks_report_assigned_with_their_vm_even_once_undeclared() {
        let f = fixture(true);
        let record = |id: &str, identity: &str| assignment::VmDedicatedRecord {
            disks: vec![assignment::AssignedDisk {
                slot: "x0".into(),
                disk_id: id.into(),
                identity: identity.into(),
            }],
        };
        assignment::write_vm(f.root.path(), "vm-a", &record("wwn-0x1", "naa.1")).unwrap();
        let report = f.reporter.report();
        assert_eq!(report.validate(), Ok(()));
        let disk = &report.dedicated_disks[0];
        assert_eq!(
            (disk.state, disk.vm.as_str()),
            (DedicatedDiskState::Assigned, "vm-a")
        );
        // A disk the declaration no longer lists is still reported: gone
        // from the host here, so `failed`.
        assignment::write_vm(f.root.path(), "vm-b", &record("wwn-0x9", "naa.9")).unwrap();
        let report = f.reporter.report();
        assert_eq!(report.validate(), Ok(()));
        let ids: Vec<_> = report
            .dedicated_disks
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(ids, ["wwn-0x1", "wwn-0x9"]);
        assert_eq!(report.dedicated_disks[1].state, DedicatedDiskState::Failed);
        // Unreadable records: nothing offered on a guess.
        std::fs::write(f.root.path().join("vm-dedicated/vm-c"), b"{").unwrap();
        let report = f.reporter.report();
        assert_eq!(report.validate(), Ok(()));
        assert!(report
            .dedicated_disks
            .iter()
            .all(|d| d.state == DedicatedDiskState::Unavailable
                && d.error == "disk-assignment-unreadable"));
    }

    #[test]
    fn more_pools_than_the_schema_takes_still_report_default_and_validate() {
        let root = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let set = (*pools(root.path(), hdd.path()))
            .clone()
            .with_draining_paths(&[
                ("a-old".to_string(), PathBuf::from("/srv/a")),
                ("b-old".to_string(), PathBuf::from("/srv/b")),
                ("c-old".to_string(), PathBuf::from("/srv/c")),
            ]);
        assert_eq!(set.iter().count(), 5);
        let reporter = StorageReporter::with_host(
            Arc::new(state::StorageState::with_pools(set)),
            root.path().to_path_buf(),
            Box::new(Fs {
                missing: Vec::new(),
            }),
            Box::new(dedicated::LiveFacts {
                paths: dedicated::SysPaths {
                    by_id: root.path().join("none"),
                    sys_block: root.path().join("none"),
                    mountinfo: root.path().join("none"),
                    swaps: root.path().join("none"),
                    require_block_device: false,
                },
                probe: Box::new(Clean),
            }),
        );
        let report = reporter.report();
        assert_eq!(report.validate(), Ok(()));
        let ids: Vec<_> = report.disk_pools.iter().map(|p| p.id.as_str()).collect();
        // Declared `hdd0` stays visible; the kept ones fill what is left.
        assert_eq!(ids, ["a-old", "b-old", "default", "hdd0"]);
    }
}
