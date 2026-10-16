//! The ephemeral dm-crypt mapping a dedicated disk is probed through
//! (design §3.3): plain mode, AES-XTS, a random key read from
//! `/dev/urandom` and never kept, no header written. It is the tenant's
//! cipher path, so the probe measures what a tenant would get.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{ProbeError, Result};

/// An open mapping; closed on drop.
pub struct Mapping {
    cryptsetup: PathBuf,
    name: String,
    pub device: PathBuf,
}

impl Mapping {
    /// Map `device` as `/dev/mapper/hippius-probe-<slot>`.
    pub fn open(cryptsetup: &Path, device: &Path, slot: &str) -> Result<Self> {
        let name = format!("hippius-probe-{slot}");
        let status = Command::new(cryptsetup)
            .args([
                "open",
                "--type",
                "plain",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--key-file",
                "/dev/urandom",
                "--keyfile-size",
                "64",
            ])
            .arg(device)
            .arg(&name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ProbeError::Target("crypt-open-failed"))?;
        if !status.success() {
            return Err(ProbeError::Target("crypt-open-failed"));
        }
        Ok(Self {
            cryptsetup: cryptsetup.to_path_buf(),
            device: PathBuf::from("/dev/mapper").join(&name),
            name,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let closed = Command::new(&self.cryptsetup)
            .arg("close")
            .arg(&self.name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !closed.is_ok_and(|s| s.success()) {
            eprintln!("hippius-agent-disk-probe: {} not closed", self.name);
        }
    }
}
