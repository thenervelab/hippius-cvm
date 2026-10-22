//! The ephemeral dm-crypt mapping a dedicated disk is probed through
//! (design §3.3): plain mode, AES-XTS, a random key read from
//! `/dev/urandom` and never kept, no header written. It is the tenant's
//! cipher path, so the probe measures what a tenant would get.
//!
//! On a guest that opens dedicated disks (guest release 6+), the probe VM's
//! measured cmdline carries `hippius.dedicated=` (vali sends a disk only
//! with its anchor), so the initramfs opener has already formatted each
//! blank slot as LUKS2 and opened it as `/dev/mapper/hippius-<slot>`
//! before the probe runs. That mapping holds the device, and
//! `cryptsetup open --type plain` needs it exclusively, so the probe closes
//! the opener's mapping first ([`close_opener_mapping`]). Nothing uses it on
//! a probe VM, and the LUKS header the opener wrote stays on the disk until
//! the miner's §24 release wipe.

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

/// Close the initramfs opener's `hippius-<slot>` mapping of the slot, if
/// there is one (see the module docs), so the probe's own mapping can take
/// the device. `Ok` when there was none or it is closed;
/// `opener-close-failed` when it stays.
pub fn close_opener_mapping(cryptsetup: &Path, mapper_root: &Path, slot: &str) -> Result<()> {
    let name = format!("hippius-{slot}");
    let node = mapper_root.join(&name);
    match std::fs::symlink_metadata(&node) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ProbeError::Target("opener-close-failed")),
        Ok(_) => {}
    }
    let closed = Command::new(cryptsetup)
        .arg("close")
        .arg(&name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !closed || std::fs::symlink_metadata(&node).is_ok() {
        return Err(ProbeError::Target("opener-close-failed"));
    }
    Ok(())
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

/// For tests that run a just-written stand-in script.
#[cfg(test)]
#[allow(clippy::panic)]
pub(crate) mod test_support {
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// Wait until the script at `path` can be executed, then remove the
    /// `log` its warm-up run may have written. Another test thread forking
    /// while the script was still open for writing holds it busy for a
    /// moment (ETXTBSY): without this, the first real run can fail to
    /// spawn and the test fails for nothing.
    pub(crate) fn exec_ready(path: &Path, log: &Path) {
        for _ in 0..200 {
            match Command::new(path)
                .arg("warm-up")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                Ok(_) => {
                    let _ = std::fs::remove_file(log);
                    return;
                }
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("cannot run {}: {e}", path.display()),
            }
        }
        panic!("{} stayed busy", path.display());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in `cryptsetup` that logs its arguments to `calls` and, on
    /// `close <name>`, removes `<mapper>/<name>` when `removes` and exits
    /// `close_code`; any other call exits 1.
    fn fake_cryptsetup(dir: &Path, mapper: &Path, close_code: i32, removes: bool) -> PathBuf {
        let path = dir.join(format!("cryptsetup-{close_code}-{removes}"));
        let calls = dir.join("calls");
        let rm = if removes {
            format!("rm -f '{}/'\"$2\"", mapper.display())
        } else {
            ":".to_string()
        };
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nif [ \"$1\" = close ]; then\n  {rm}\n  exit {close_code}\nfi\nexit 1\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        super::test_support::exec_ready(&path, &calls);
        path
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls")).unwrap_or_default()
    }

    #[test]
    fn the_openers_mapping_is_closed_before_the_probe_maps_the_slot() {
        let root = tempfile::tempdir().unwrap();
        let mapper = root.path().join("mapper");
        std::fs::create_dir_all(&mapper).unwrap();
        std::fs::write(mapper.join("hippius-x3"), b"").unwrap();
        let cs = fake_cryptsetup(root.path(), &mapper, 0, true);
        close_opener_mapping(&cs, &mapper, "x3").unwrap();
        assert_eq!(calls(root.path()), "close hippius-x3\n");
        assert!(!mapper.join("hippius-x3").exists());
    }

    #[test]
    fn no_opener_mapping_runs_nothing() {
        let root = tempfile::tempdir().unwrap();
        let mapper = root.path().join("mapper");
        std::fs::create_dir_all(&mapper).unwrap();
        // Another slot's mapping is not this slot's.
        std::fs::write(mapper.join("hippius-x1"), b"").unwrap();
        let cs = fake_cryptsetup(root.path(), &mapper, 0, true);
        close_opener_mapping(&cs, &mapper, "x0").unwrap();
        assert_eq!(calls(root.path()), "");
        assert!(mapper.join("hippius-x1").exists());
    }

    #[test]
    fn a_mapping_that_does_not_close_fails_the_target() {
        let root = tempfile::tempdir().unwrap();
        let mapper = root.path().join("mapper");
        std::fs::create_dir_all(&mapper).unwrap();
        std::fs::write(mapper.join("hippius-x0"), b"").unwrap();
        // `close` refused.
        let cs = fake_cryptsetup(root.path(), &mapper, 5, false);
        assert_eq!(
            close_opener_mapping(&cs, &mapper, "x0"),
            Err(ProbeError::Target("opener-close-failed"))
        );
        // `close` said yes but the mapping is still there.
        let cs = fake_cryptsetup(root.path(), &mapper, 0, false);
        assert_eq!(
            close_opener_mapping(&cs, &mapper, "x0"),
            Err(ProbeError::Target("opener-close-failed"))
        );
        // No cryptsetup at all.
        assert_eq!(
            close_opener_mapping(&root.path().join("none"), &mapper, "x0"),
            Err(ProbeError::Target("opener-close-failed"))
        );
    }
}
