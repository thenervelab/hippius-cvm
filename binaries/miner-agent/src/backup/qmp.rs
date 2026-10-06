//! QMP access to a libvirt-managed domain — the command builders, the
//! reply parsers and the [`QmpTransport`] seam.
//!
//! ## Why `virsh qemu-monitor-command`
//!
//! libvirt owns the domain's QMP socket; a second client cannot attach.
//! `virsh qemu-monitor-command` is the supported pass-through, and it is
//! the same shell-out style as [`crate::lifecycle::VirshDriver`] (argv
//! only, never a shell string). Its first use taints the domain
//! `custom-monitor` — cosmetic, accepted.
//!
//! ## Passing the backup target by fd
//!
//! The domain's AppArmor profile only allows the domain's own disks, so
//! QEMU cannot `open()` a backup target the agent names by path. The
//! agent opens the file itself and hands QEMU the descriptor:
//! `virsh qemu-monitor-command --pass-fds 0` sends the fd on virsh's
//! stdin along with an `add-fd` command (SCM_RIGHTS through libvirtd),
//! and the target node is `blockdev-add`ed on `/dev/fdset/<id>`.
//! Using stdin keeps this free of `unsafe` fd plumbing. AppArmor allows
//! a descriptor delegated by an unconfined process (the agent), which is
//! what makes this work under the per-domain profile.

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::DomainId;

/// libvirt connection URI — same as the lifecycle driver.
const LIBVIRT_URI: &str = "qemu:///system";

/// Wall-clock cap on one `virsh qemu-monitor-command`. Every command we
/// send returns immediately (the backup itself runs as a QEMU job).
const QMP_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// QEMU block-job id of a backup. One backup per VM at a time, and a
/// domain holds one VM, so a constant id is unique per domain and lets
/// restart cleanup find an abandoned job without any saved state.
pub const JOB_ID: &str = "hippius-bk";

/// Node name of the backup target (the raw file node, or the qcow2
/// format node for an incremental).
pub const TARGET_NODE: &str = "hippius-bk-tgt";

/// `opaque` tag on the fdset holding the target descriptor, so restart
/// cleanup can find and remove it.
pub const FDSET_OPAQUE: &str = "hippius-bk";

/// Dirty bitmaps the agent owns are named `hippius-bk-<run_id>`: "dirty
/// since that run's point in time".
pub const BITMAP_PREFIX: &str = "hippius-bk-";

/// Error class for "the domain is gone / not running" — whatever a backup
/// held inside that QEMU went with it.
pub const NO_DOMAIN: &str = "qmp-no-domain";

/// The seam every QMP command goes through.
#[async_trait]
pub trait QmpTransport: Send + Sync {
    /// Run one QMP `command` against `domain` and return its `return`
    /// value. `pass_fd`, when set, travels with the command (SCM_RIGHTS)
    /// — only `add-fd` consumes one. A QMP `error` reply is
    /// `Err(Backup("qmp-error"))`.
    async fn execute(
        &self,
        domain: &DomainId,
        command: &Value,
        pass_fd: Option<std::fs::File>,
    ) -> Result<Value>;
}

/// Production transport — `virsh qemu-monitor-command`.
pub struct VirshQmp {
    virsh_path: std::path::PathBuf,
}

impl VirshQmp {
    /// A transport invoking `virsh` at `virsh_path`.
    pub fn new(virsh_path: std::path::PathBuf) -> Self {
        Self { virsh_path }
    }
}

impl Default for VirshQmp {
    fn default() -> Self {
        Self::new(std::path::PathBuf::from("/usr/bin/virsh"))
    }
}

#[async_trait]
impl QmpTransport for VirshQmp {
    async fn execute(
        &self,
        domain: &DomainId,
        command: &Value,
        pass_fd: Option<std::fs::File>,
    ) -> Result<Value> {
        let mut cmd = Command::new(&self.virsh_path);
        cmd.arg("--connect")
            .arg(LIBVIRT_URI)
            .arg("qemu-monitor-command")
            .arg(domain.as_str());
        match pass_fd {
            Some(file) => {
                // The descriptor becomes virsh's fd 0; `--pass-fds 0`
                // forwards it to QEMU with the command.
                cmd.arg("--pass-fds").arg("0");
                cmd.stdin(std::process::Stdio::from(file));
            }
            None => {
                cmd.stdin(std::process::Stdio::null());
            }
        }
        cmd.arg(command.to_string());
        cmd.kill_on_drop(true);
        let output = tokio::time::timeout(QMP_CALL_TIMEOUT, cmd.output())
            .await
            .map_err(|_| MinerAgentError::Backup("qmp-timeout"))?
            .map_err(|_| MinerAgentError::Backup("qmp-spawn"))?;
        // virsh prints the raw QMP reply on stdout; an `error` reply
        // makes it exit non-zero on some versions and zero on others,
        // so the reply body — not the exit code — is authoritative.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            // Match only closed-vocabulary markers; stderr is never
            // echoed (it can carry a path).
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Domain not found")
                || stderr.contains("failed to get domain")
                || stderr.contains("domain is not running")
            {
                return Err(MinerAgentError::Backup(NO_DOMAIN));
            }
            return Err(MinerAgentError::Backup("qmp-virsh"));
        }
        parse_reply(&stdout)
    }
}

/// Parse a raw QMP reply: `{"return": …}` ⇒ the value, `{"error": …}`
/// ⇒ `qmp-error`, anything else ⇒ `qmp-reply`.
pub fn parse_reply(raw: &str) -> Result<Value> {
    let v: Value =
        serde_json::from_str(raw.trim()).map_err(|_| MinerAgentError::Backup("qmp-reply"))?;
    if v.get("error").is_some() {
        return Err(MinerAgentError::Backup("qmp-error"));
    }
    v.get("return")
        .cloned()
        .ok_or(MinerAgentError::Backup("qmp-reply"))
}

// ── command builders ────────────────────────────────────────────────

/// `query-named-block-nodes` (flat — one entry per node, no nesting).
pub fn query_named_block_nodes() -> Value {
    json!({"execute": "query-named-block-nodes", "arguments": {"flat": true}})
}

/// `add-fd` — the descriptor travels with the command.
pub fn add_fd() -> Value {
    json!({"execute": "add-fd", "arguments": {"opaque": FDSET_OPAQUE}})
}

/// `remove-fd` — drop a whole fdset.
pub fn remove_fd(fdset_id: i64) -> Value {
    json!({"execute": "remove-fd", "arguments": {"fdset-id": fdset_id}})
}

/// `query-fdsets`.
pub fn query_fdsets() -> Value {
    json!({"execute": "query-fdsets"})
}

/// The target's on-disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFormat {
    /// A raw file the size of the source — the full backup.
    Raw,
    /// A qcow2 without backing — the incremental; only the dirty
    /// clusters get allocated.
    Qcow2,
}

/// `blockdev-add` the target on `/dev/fdset/<fdset_id>`.
///
/// `locking: off` — the descriptor is ours and nothing else opens the
/// file; OFD locks on a delegated fd buy nothing. The qcow2 node sets
/// `backing: null` so QEMU never looks for a backing file (it has none:
/// unallocated clusters read as zeroes, and the restore rebases it).
///
/// `direct` MUST say whether the fdset's descriptor was opened
/// `O_DIRECT`: QEMU (`monitor_fdset_dup_fd_add`, 9.1+) hands out only a
/// member whose `O_ACCMODE | O_DIRECT` bits equal the flags the node
/// opens with, and `cache.direct` is what puts `O_DIRECT` in those. It
/// sits on the protocol node — the one that opens the fdset.
pub fn blockdev_add_target(format: TargetFormat, fdset_id: i64, direct: bool) -> Value {
    let file = json!({
        "driver": "file",
        "filename": format!("/dev/fdset/{fdset_id}"),
        "locking": "off",
        "cache": {"direct": direct},
    });
    let args = match format {
        TargetFormat::Raw => {
            let mut f = file;
            f["node-name"] = json!(TARGET_NODE);
            f
        }
        TargetFormat::Qcow2 => json!({
            "driver": "qcow2",
            "node-name": TARGET_NODE,
            "backing": null,
            "file": file,
        }),
    };
    json!({"execute": "blockdev-add", "arguments": args})
}

/// `blockdev-del`.
pub fn blockdev_del(node: &str) -> Value {
    json!({"execute": "blockdev-del", "arguments": {"node-name": node}})
}

/// The full backup: ONE `transaction` so the bitmap starts recording at
/// exactly the point in time the copy captures. `speed` caps the copy in
/// bytes/s (`0`: uncapped — no `speed` argument at all).
pub fn transaction_full(source_node: &str, bitmap: &str, speed: u64) -> Value {
    let mut t = json!({
        "execute": "transaction",
        "arguments": {"actions": [
            {"type": "block-dirty-bitmap-add", "data": {
                "node": source_node, "name": bitmap, "persistent": false,
            }},
            {"type": "blockdev-backup", "data": {
                "job-id": JOB_ID, "device": source_node, "target": TARGET_NODE,
                "sync": "full", "auto-dismiss": false,
            }},
        ]}
    });
    set_speed(&mut t, speed);
    t
}

/// Put `speed` on a backup transaction's `blockdev-backup` action, unless
/// it is `0` (uncapped).
fn set_speed(tx: &mut Value, speed: u64) {
    if speed > 0 {
        tx["arguments"]["actions"][1]["data"]["speed"] = json!(speed);
    }
}

/// The incremental: ONE `transaction` that starts the new point's
/// bitmap and copies what the PARENT point's bitmap marks dirty.
/// `sync: bitmap` with `bitmap-mode: never` leaves the parent bitmap
/// untouched, so a run that fails anywhere later — the job, the upload,
/// vali's CompleteMultipart — costs nothing: the next run reads the same
/// parent again. (`sync: incremental` would clear the parent's bits the
/// moment QEMU finished the LOCAL copy, before anything was durable.)
/// `speed` as in [`transaction_full`].
pub fn transaction_incremental(
    source_node: &str,
    parent: &str,
    new_bitmap: &str,
    speed: u64,
) -> Value {
    let mut t = json!({
        "execute": "transaction",
        "arguments": {"actions": [
            {"type": "block-dirty-bitmap-add", "data": {
                "node": source_node, "name": new_bitmap, "persistent": false,
            }},
            {"type": "blockdev-backup", "data": {
                "job-id": JOB_ID, "device": source_node, "target": TARGET_NODE,
                "sync": "bitmap", "bitmap": parent, "bitmap-mode": "never",
                "auto-dismiss": false,
            }},
        ]}
    });
    set_speed(&mut t, speed);
    t
}

/// `query-jobs`.
pub fn query_jobs() -> Value {
    json!({"execute": "query-jobs"})
}

/// `job-cancel`.
pub fn job_cancel(id: &str) -> Value {
    json!({"execute": "job-cancel", "arguments": {"id": id}})
}

/// `job-dismiss` (only valid on a `concluded` job).
pub fn job_dismiss(id: &str) -> Value {
    json!({"execute": "job-dismiss", "arguments": {"id": id}})
}

/// `block-dirty-bitmap-remove`.
pub fn bitmap_remove(node: &str, name: &str) -> Value {
    json!({"execute": "block-dirty-bitmap-remove", "arguments": {"node": node, "name": name}})
}

// ── reply parsers ───────────────────────────────────────────────────

/// A dirty bitmap on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapInfo {
    /// Bitmap name.
    pub name: String,
    /// Dirty bytes.
    pub count: u64,
}

/// The source node a backup reads from and the bitmaps on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceNode {
    /// libvirt's node name (`libvirt-N-storage`).
    pub node_name: String,
    /// The image's virtual size — the size a raw target must have.
    pub virtual_size: u64,
    /// Dirty bitmaps on the node.
    pub bitmaps: Vec<BitmapInfo>,
}

impl SourceNode {
    /// The named bitmap, if present.
    pub fn bitmap(&self, name: &str) -> Option<&BitmapInfo> {
        self.bitmaps.iter().find(|b| b.name == name)
    }
}

/// Find the protocol (`file`) node whose filename is `path` in a
/// `query-named-block-nodes` reply. That node is where the phase-0 spike
/// put the bitmap, and it is what the backup reads.
pub fn find_file_node(nodes: &Value, path: &std::path::Path) -> Option<SourceNode> {
    let want = path.to_str()?;
    nodes.as_array()?.iter().find_map(|n| {
        if n.get("drv")?.as_str()? != "file" || n.get("file")?.as_str()? != want {
            return None;
        }
        let node_name = n.get("node-name")?.as_str()?.to_string();
        let virtual_size = n.get("image")?.get("virtual-size")?.as_u64()?;
        let bitmaps = n
            .get("dirty-bitmaps")
            .and_then(Value::as_array)
            .map(|bs| {
                bs.iter()
                    .filter_map(|b| {
                        Some(BitmapInfo {
                            name: b.get("name")?.as_str()?.to_string(),
                            count: b.get("count")?.as_u64()?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(SourceNode {
            node_name,
            virtual_size,
            bitmaps,
        })
    })
}

/// Whether a node named `name` exists in a `query-named-block-nodes`
/// reply.
pub fn has_node(nodes: &Value, name: &str) -> bool {
    nodes.as_array().is_some_and(|ns| {
        ns.iter()
            .any(|n| n.get("node-name").and_then(Value::as_str) == Some(name))
    })
}

/// `add-fd` reply ⇒ the fdset id.
pub fn parse_add_fd(ret: &Value) -> Result<i64> {
    ret.get("fdset-id")
        .and_then(Value::as_i64)
        .ok_or(MinerAgentError::Backup("qmp-reply"))
}

/// The fdset ids tagged [`FDSET_OPAQUE`] in a `query-fdsets` reply.
pub fn our_fdsets(ret: &Value) -> Vec<i64> {
    ret.as_array()
        .map(|sets| {
            sets.iter()
                .filter(|s| {
                    s.get("fds").and_then(Value::as_array).is_some_and(|fds| {
                        fds.iter()
                            .any(|f| f.get("opaque").and_then(Value::as_str) == Some(FDSET_OPAQUE))
                    })
                })
                .filter_map(|s| s.get("fdset-id").and_then(Value::as_i64))
                .collect()
        })
        .unwrap_or_default()
}

/// One job from `query-jobs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobInfo {
    /// QEMU job status (`running`, `concluded`, …).
    pub status: String,
    /// The job's error, set once it concluded unsuccessfully.
    pub failed: bool,
    /// Bytes done so far.
    pub current_progress: u64,
    /// Total bytes.
    pub total_progress: u64,
}

/// The job `id` in a `query-jobs` reply.
pub fn find_job(ret: &Value, id: &str) -> Option<JobInfo> {
    ret.as_array()?.iter().find_map(|j| {
        if j.get("id")?.as_str()? != id {
            return None;
        }
        Some(JobInfo {
            status: j.get("status")?.as_str()?.to_string(),
            failed: j.get("error").is_some(),
            current_progress: j
                .get("current-progress")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            total_progress: j.get("total-progress").and_then(Value::as_u64).unwrap_or(0),
        })
    })
}

#[cfg(test)]
pub(crate) mod mock {
    //! A scripted [`QmpTransport`] — records every command (and whether
    //! an fd came with it), answers from a per-command handler.

    use super::*;
    use std::sync::Mutex;

    type Handler = Box<dyn Fn(&Value) -> Result<Value> + Send + Sync>;

    /// Scripted transport.
    pub(crate) struct MockQmp {
        pub(crate) calls: Mutex<Vec<(String, Value, bool)>>,
        /// `F_GETFL` of every descriptor passed along, in call order.
        pub(crate) fd_flags: Mutex<Vec<nix::fcntl::OFlag>>,
        handler: Handler,
    }

    impl MockQmp {
        pub(crate) fn new(
            handler: impl Fn(&Value) -> Result<Value> + Send + Sync + 'static,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fd_flags: Mutex::new(Vec::new()),
                handler: Box::new(handler),
            }
        }

        /// The `execute` names in call order.
        pub(crate) fn executed(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(_, c, _)| c["execute"].as_str().unwrap_or("").to_string())
                .collect()
        }
    }

    #[async_trait]
    impl QmpTransport for MockQmp {
        async fn execute(
            &self,
            domain: &DomainId,
            command: &Value,
            pass_fd: Option<std::fs::File>,
        ) -> Result<Value> {
            if let Some(f) = &pass_fd {
                let bits = nix::fcntl::fcntl(f, nix::fcntl::FcntlArg::F_GETFL).unwrap();
                self.fd_flags
                    .lock()
                    .unwrap()
                    .push(nix::fcntl::OFlag::from_bits_truncate(bits));
            }
            self.calls.lock().unwrap().push((
                domain.as_str().to_string(),
                command.clone(),
                pass_fd.is_some(),
            ));
            (self.handler)(command)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reply_return_error_and_garbage() {
        assert_eq!(
            parse_reply(r#"{"return":{"a":1},"id":"libvirt-7"}"#).unwrap(),
            json!({"a": 1})
        );
        assert!(matches!(
            parse_reply(r#"{"id":"x","error":{"class":"GenericError","desc":"/secret/path"}}"#),
            Err(MinerAgentError::Backup("qmp-error"))
        ));
        assert!(matches!(
            parse_reply("not json"),
            Err(MinerAgentError::Backup("qmp-reply"))
        ));
        assert!(matches!(
            parse_reply(r#"{"id":"x"}"#),
            Err(MinerAgentError::Backup("qmp-reply"))
        ));
    }

    #[test]
    fn full_is_one_transaction_bitmap_then_backup() {
        let t = transaction_full("libvirt-1-storage", "hippius-bk-c1", 7 << 20);
        assert_eq!(t["execute"], "transaction");
        let a = t["arguments"]["actions"].as_array().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0]["type"], "block-dirty-bitmap-add");
        assert_eq!(a[0]["data"]["node"], "libvirt-1-storage");
        assert_eq!(a[0]["data"]["persistent"], false);
        assert_eq!(a[1]["type"], "blockdev-backup");
        assert_eq!(a[1]["data"]["sync"], "full");
        assert_eq!(a[1]["data"]["device"], "libvirt-1-storage");
        assert_eq!(a[1]["data"]["target"], TARGET_NODE);
        assert_eq!(a[1]["data"]["auto-dismiss"], false);
        assert_eq!(a[1]["data"]["speed"], 7 << 20);
        assert!(a[1]["data"].get("bitmap").is_none());
    }

    #[test]
    fn incremental_starts_a_new_point_and_never_consumes_the_parent() {
        let t = transaction_incremental("libvirt-1-storage", "hippius-bk-r1", "hippius-bk-r2", 0);
        assert_eq!(t["execute"], "transaction");
        let a = t["arguments"]["actions"].as_array().unwrap();
        assert_eq!(a[0]["type"], "block-dirty-bitmap-add");
        assert_eq!(a[0]["data"]["name"], "hippius-bk-r2");
        assert_eq!(a[0]["data"]["persistent"], false);
        assert_eq!(a[1]["type"], "blockdev-backup");
        assert_eq!(a[1]["data"]["sync"], "bitmap");
        assert_eq!(a[1]["data"]["bitmap"], "hippius-bk-r1");
        assert_eq!(a[1]["data"]["bitmap-mode"], "never");
        assert_eq!(a[1]["data"]["job-id"], JOB_ID);
        assert!(a[1]["data"].get("speed").is_none(), "0 is uncapped");
    }

    #[test]
    fn target_nodes_open_the_fdset() {
        let raw = blockdev_add_target(TargetFormat::Raw, 3, true);
        assert_eq!(raw["arguments"]["driver"], "file");
        assert_eq!(raw["arguments"]["filename"], "/dev/fdset/3");
        assert_eq!(raw["arguments"]["node-name"], TARGET_NODE);
        assert_eq!(raw["arguments"]["cache"]["direct"], true);
        let q = blockdev_add_target(TargetFormat::Qcow2, 4, false);
        assert_eq!(q["arguments"]["driver"], "qcow2");
        assert_eq!(q["arguments"]["node-name"], TARGET_NODE);
        assert!(q["arguments"]["backing"].is_null());
        assert_eq!(q["arguments"]["file"]["filename"], "/dev/fdset/4");
        assert!(q["arguments"]["file"].get("node-name").is_none());
        assert_eq!(q["arguments"]["file"]["cache"]["direct"], false);
        assert!(q["arguments"].get("cache").is_none());
    }

    fn nodes_fixture() -> Value {
        // Trimmed from a real `query-named-block-nodes` on a golden VM.
        json!([
            {"node-name": "libvirt-1-format", "drv": "raw",
             "file": "/var/lib/hippius-miner/overlay/vm-a.img",
             "image": {"virtual-size": 42949672960u64}},
            {"node-name": "libvirt-1-storage", "drv": "file",
             "file": "/var/lib/hippius-miner/overlay/vm-a.img",
             "image": {"virtual-size": 42949672960u64},
             "dirty-bitmaps": [
                {"name": "hippius-bk-c1", "count": 196608, "granularity": 65536,
                 "recording": true, "busy": false, "persistent": false}
             ]},
            {"node-name": "libvirt-2-storage", "drv": "file",
             "file": "/var/lib/hippius-miner/rootfs.img",
             "image": {"virtual-size": 1024}}
        ])
    }

    #[test]
    fn finds_the_file_node_and_its_bitmaps() {
        let n = find_file_node(
            &nodes_fixture(),
            std::path::Path::new("/var/lib/hippius-miner/overlay/vm-a.img"),
        )
        .unwrap();
        assert_eq!(n.node_name, "libvirt-1-storage");
        assert_eq!(n.virtual_size, 42_949_672_960);
        assert_eq!(n.bitmap("hippius-bk-c1").unwrap().count, 196_608);
        assert!(n.bitmap("hippius-bk-other").is_none());
        assert!(find_file_node(&nodes_fixture(), std::path::Path::new("/nope")).is_none());
        assert!(has_node(&nodes_fixture(), "libvirt-2-storage"));
        assert!(!has_node(&nodes_fixture(), TARGET_NODE));
    }

    #[test]
    fn fdsets_and_jobs() {
        let sets = json!([
            {"fdset-id": 0, "fds": [{"fd": 30, "opaque": "something-else"}]},
            {"fdset-id": 2, "fds": [{"fd": 31, "opaque": FDSET_OPAQUE}]}
        ]);
        assert_eq!(our_fdsets(&sets), vec![2]);
        assert_eq!(parse_add_fd(&json!({"fdset-id": 2, "fd": 31})).unwrap(), 2);

        let jobs = json!([
            {"id": "other", "type": "mirror", "status": "running"},
            {"id": JOB_ID, "type": "backup", "status": "concluded",
             "current-progress": 10, "total-progress": 10, "error": "No space left"}
        ]);
        let j = find_job(&jobs, JOB_ID).unwrap();
        assert_eq!(j.status, "concluded");
        assert!(j.failed);
        assert_eq!(j.total_progress, 10);
        assert!(find_job(&jobs, "absent").is_none());
    }
}
