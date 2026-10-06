//! `qemu-img` — only ever run on images this agent creates itself (the
//! incremental backup target). Untrusted incrementals on the restore side
//! are applied by [`super::qcow2`], never by `qemu-img`.

use std::path::Path;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::{MinerAgentError, Result};

/// Wall-clock cap on a `qemu-img create`.
const CREATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The `qemu-img` operations a capture needs.
#[async_trait]
pub trait ImageTool: Send + Sync {
    /// `qemu-img create -f qcow2 <path> <size>` — no backing, default
    /// (64 KiB) clusters.
    async fn create_qcow2(&self, path: &Path, size: u64) -> Result<()>;
}

/// Production [`ImageTool`] — shells out to `qemu-img`.
pub struct QemuImg {
    bin: std::path::PathBuf,
}

impl QemuImg {
    /// Invoke `qemu-img` at `bin`.
    pub fn new(bin: std::path::PathBuf) -> Self {
        Self { bin }
    }
}

impl Default for QemuImg {
    fn default() -> Self {
        Self::new(std::path::PathBuf::from("/usr/bin/qemu-img"))
    }
}

#[async_trait]
impl ImageTool for QemuImg {
    async fn create_qcow2(&self, path: &Path, size: u64) -> Result<()> {
        let mut cmd = Command::new(&self.bin);
        cmd.arg("create")
            .arg("-q")
            .arg("-f")
            .arg("qcow2")
            .arg(path)
            .arg(size.to_string())
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let out = tokio::time::timeout(CREATE_TIMEOUT, cmd.output())
            .await
            .map_err(|_| MinerAgentError::Backup("qemu-img-create"))?
            .map_err(|_| MinerAgentError::Backup("qemu-img-spawn"))?;
        if !out.status.success() {
            return Err(MinerAgentError::Backup("qemu-img-create"));
        }
        Ok(())
    }
}
