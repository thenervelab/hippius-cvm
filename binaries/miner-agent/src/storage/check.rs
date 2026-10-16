//! `storage-check`: what the agent would make of its storage declaration
//! on this host, read-only, without touching the running agent.
//!
//! Run it with the agent unit's own sandbox (`systemd-run -p
//! PrivateDevices=yes -p ProtectSystem=strict -p ReadWritePaths=…`) to see
//! exactly what the agent sees: pools read through `/proc/self/mountinfo`
//! and the `O_DIRECT` write test, filesystems identified through udev,
//! dedicated disks through the collector's facts. Nothing is written but
//! the write test's own probe file (created and removed in each pool).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::Config;

use super::dedicated::{self, FactsSource};
use super::pools::{self, PoolFs};
use super::registry::{self, FsIdentitySource};
use super::remote::{self, LocalStorage};

/// The report for `config`: the declaration's own problem, the pools as
/// the startup check sees them, and every declared dedicated disk.
pub fn run(
    config: &Config,
    pools_root: &std::path::Path,
    pool_fs: &dyn PoolFs,
    src: &FsIdentitySource,
    facts: &dyn FactsSource,
) -> Value {
    let storage_error = config.storage_error();
    // What `serve` would run with: an invalid declaration is dropped.
    let mut effective = config.clone();
    effective.drop_invalid_storage();
    let local = LocalStorage {
        pools_root: Some(pools_root.to_path_buf()),
        ..LocalStorage::from_config(&effective)
    };
    let (set, dedicated_disks, revision) = remote::boot_set(&local);
    let state_root = &local.state_root;
    // As `serve` starts: a no-longer-declared pool that may hold disks is
    // kept, draining.
    let (set, registry_error) = match registry::removed_unproven(state_root, &set, src) {
        Ok(removed) => (set.with_draining_paths(&removed), None),
        Err(()) => (set, Some("storage.pools-registry-unreadable".to_string())),
    };
    // The registry, judged without writing it.
    let (registry_error, bindings) = match registry::plan_with(state_root, &set, src) {
        Ok(plan) if registry_error.is_none() => (None, plan.bindings),
        Ok(_) => (registry_error, registry::PoolBindings::default()),
        Err(e) => (Some(e.to_string()), registry::PoolBindings::default()),
    };
    let binding_errors = bindings.errors_now(&set, src);
    let checks = pools::check_pools(&set, pool_fs, &binding_errors);
    let pools_out: Vec<Value> = set
        .iter()
        .map(|p| {
            let check = checks.get(&p.id);
            json!({
                "id": p.id,
                "path": p.path,
                "class": p.class.as_str(),
                "budget_gb": p.budget_gb,
                "os_disks": p.os_disks,
                "draining": p.draining,
                "state": check.map(|c| c.state.as_str()),
                "error": check.map(|c| c.error),
                "fs_identity": registry::fs_identity(src, &p.path),
            })
        })
        .collect();
    let facts_result = facts.facts();
    let mut identities = dedicated::IdentityMap::load(state_root).unwrap_or_default();
    let disks = dedicated::inventory(
        &dedicated_disks,
        facts_result.as_ref().map_err(|e| *e),
        &super::system_devs(state_root, &set),
        &mut identities,
    );
    let disks_out: Vec<Value> = disks
        .iter()
        .map(|d| {
            json!({
                "id": d.id,
                "state": d.state.as_str(),
                "size_mb": d.size_mb,
                "error": d.error,
            })
        })
        .collect();
    let mut out = BTreeMap::new();
    out.insert("storage_error", json!(storage_error));
    out.insert("storage_config_revision", json!(revision));
    out.insert("registry_error", json!(registry_error));
    out.insert("pools", json!(pools_out));
    out.insert("dedicated_disks", json!(disks_out));
    out.insert("disk_facts_error", json!(facts_result.err()));
    json!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const BASE: &str = r#"
[miner]
miner_id = "miner-a"

[edge]
endpoint = "https://edge.hippius.network:443"
client_cert = "/var/lib/hippius-miner/edge-mtls.crt"
client_key = "/var/lib/hippius-miner/edge-mtls.key"
ca_cert = "/var/lib/hippius-miner/edge-ca.crt"
order_signing_pubkey = "1111111111111111111111111111111111111111111111111111111111111111"

[identity]
key_path = "/var/lib/hippius-miner/identity.key"
pub_path = "/var/lib/hippius-miner/identity.pub"

[image]
cache_dir = "/var/lib/hippius-miner/images"
staging_dir = "/var/lib/hippius-miner/staging"
s3_endpoint = "https://s3.hippius.com"
s3_bucket = "hippius-compute-images"

[orders]
bind_addr = "100.64.0.10:9700"

[host]
cvm_cpu_budget = 8
cvm_memory_mb_budget = 16384
cvm_disk_gb_budget = 100
"#;

    /// Every path a root-owned xfs mount of its own, except `read_only`.
    struct Fs {
        read_only: Vec<PathBuf>,
    }

    impl PoolFs for Fs {
        fn canonical(&self, path: &Path) -> Option<PathBuf> {
            Some(path.to_path_buf())
        }
        fn stat(&self, path: &Path) -> Option<pools::DirStat> {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            path.hash(&mut h);
            Some(pools::DirStat {
                dev: if path == Path::new("/") {
                    1
                } else {
                    h.finish() | 2
                },
                uid: 0,
                mode: 0o040755,
                is_dir: true,
            })
        }
        fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)> {
            Some((path.to_path_buf(), "xfs".into()))
        }
        fn odirect_ok(&self, path: &Path) -> bool {
            !self.read_only.iter().any(|p| p == path)
        }
        fn odirect(&self, path: &Path) -> pools::Odirect {
            if self.read_only.iter().any(|p| p == path) {
                pools::Odirect::ReadOnly
            } else {
                pools::Odirect::Ok
            }
        }
        fn total_bytes(&self, _path: &Path) -> Option<u64> {
            Some(10_000 * 1024 * 1024 * 1024)
        }
    }

    fn config(root: &Path, nvme0: &Path) -> Config {
        let text = format!(
            "{BASE}\n[storage]\ndata_disk_root = \"{r}\"\nstate_disk_root = \"{r}\"\n\
             [[storage.pools]]\nid = \"default\"\npath = \"{r}\"\nclass = \"nvme\"\nbudget_gb = 100\n\
             [[storage.pools]]\nid = \"nvme0\"\npath = \"{n}\"\nclass = \"nvme\"\nbudget_gb = 3200\n\
             [[storage.dedicated_disks]]\nid = \"wwn-0x5000c500a1b2c3d4\"\n",
            r = root.display(),
            n = nvme0.display()
        );
        let c: Config = toml::from_str(&text).unwrap();
        c.validate().unwrap();
        c
    }

    struct NoFacts;
    impl FactsSource for NoFacts {
        fn facts(&self) -> Result<dedicated::DiskFacts, &'static str> {
            Err("disk-facts-missing")
        }
    }

    fn src(dir: &Path) -> FsIdentitySource {
        FsIdentitySource {
            mountinfo: dir.join("mountinfo"),
            udev_data: dir.join("udev"),
            sys_class_block: dir.join("class-block"),
            by_uuid: dir.join("by-uuid"),
        }
    }

    #[test]
    fn a_pool_outside_the_agents_writable_paths_reads_read_only() {
        let root = tempfile::tempdir().unwrap();
        let pools_root = tempfile::tempdir().unwrap();
        let nvme0 = pools_root.path().join("nvme0");
        std::fs::create_dir(&nvme0).unwrap();
        let c = config(root.path(), &nvme0);
        let fs = Fs {
            read_only: vec![nvme0.clone()],
        };
        let r = run(&c, pools_root.path(), &fs, &src(root.path()), &NoFacts);
        assert_eq!(r["storage_error"], Value::Null);
        let pools = r["pools"].as_array().unwrap();
        let nvme = pools.iter().find(|p| p["id"] == "nvme0").unwrap();
        assert_eq!(nvme["error"], "pool-path-read-only");
        assert_eq!(nvme["state"], "unavailable");
        let disk = &r["dedicated_disks"][0];
        assert_eq!(disk["state"], "unavailable");
        assert_eq!(disk["error"], "disk-facts-missing");
        assert_eq!(r["disk_facts_error"], "disk-facts-missing");
        // Read-only: no registry, no identity written.
        assert!(!root.path().join(registry::REGISTRY_FILE).exists());
        assert!(!root.path().join(dedicated::IDENTITY_FILE).exists());
    }

    #[test]
    fn a_pool_outside_the_pools_root_is_refused_per_pool() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let pools_root = tempfile::tempdir().unwrap();
        let c = config(root.path(), elsewhere.path());
        let r = run(
            &c,
            pools_root.path(),
            &Fs {
                read_only: Vec::new(),
            },
            &src(root.path()),
            &NoFacts,
        );
        let pools = r["pools"].as_array().unwrap();
        let nvme = pools.iter().find(|p| p["id"] == "nvme0").unwrap();
        assert_eq!(nvme["error"], "pool-outside-pools-root");
        // `default` is not concerned, and nothing else is dropped.
        let default = pools.iter().find(|p| p["id"] == "default").unwrap();
        assert_eq!(default["state"], "active");
    }

    #[test]
    fn an_invalid_declaration_is_reported_and_dropped() {
        let root = tempfile::tempdir().unwrap();
        let pools_root = tempfile::tempdir().unwrap();
        let nvme0 = pools_root.path().join("nvme0");
        let mut c = config(root.path(), &nvme0);
        c.storage.pools.retain(|p| p.id != "default");
        let r = run(
            &c,
            pools_root.path(),
            &Fs {
                read_only: Vec::new(),
            },
            &src(root.path()),
            &NoFacts,
        );
        assert_eq!(r["storage_error"], "storage.pools-no-default");
        let ids: Vec<_> = r["pools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].clone())
            .collect();
        assert_eq!(ids, [Value::from("default")]);
    }
}
