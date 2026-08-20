//! Open the dm-verity rootfs mapping at `/dev/mapper/hippius-rootfs`
//! before the §21 `switch_root` stage mounts it.
//!
//! The tenant UKI's measured cmdline carries
//! `dm-verity.root=<64-hex>` — the dm-verity root hash that
//! `packer/tenant-uki/uki/scripts/build-rootfs.sh` computed for the
//! squashfs read-only rootfs. The launch digest covers that cmdline
//! byte-for-byte, so the root hash is integrity-anchored in the §F
//! measurement — anything the dm-verity target reads back at boot
//! that hashes to a different root is a §11 violation and the kernel
//! refuses to map it.
//!
//! ## What this stage does
//!
//! Wraps `libcryptsetup`'s dm-verity activation behind a thin trait
//! ([`RootfsVerity`]) so the §21 pipeline is testable without a
//! Linux kernel + device-mapper. Production: [`RealRootfsVerity`]
//! (Linux). Tests + non-Linux dev hosts: [`MockRootfsVerity`].
//!
//! 1. `crypt_init(<hash_device>)` — opens the verity hash-tree
//!    backing device. dm-verity superblock lives at the start of the
//!    hash device; libcryptsetup reads it via `crypt_load` next.
//! 2. `crypt_load(CRYPT_VERITY, NULL)` — parses the dm-verity
//!    superblock + locates the data device path from it. The data
//!    device is configured at format time (see `build-rootfs.sh`'s
//!    `veritysetup format <data> <hash>`) and recorded inside the
//!    superblock; libcryptsetup honours that pointer.
//! 3. `crypt_activate_by_volume_key(<MAPPER>, <root_hash_bytes>,
//!    CRYPT_ACTIVATE_READONLY)` — creates the dm-verity device-
//!    mapper target at `/dev/mapper/hippius-rootfs`. The kernel
//!    verifies every read against the hash tree; a hash mismatch
//!    fails the read with I/O error, propagating to the
//!    `switch_root` mount.
//!
//! The activated dm-verity mapping persists past `crypt_free`, the
//! same way the LUKS mapping does — the kernel device-mapper target
//! is independent of the libcryptsetup handle.
//!
//! ## Why this lives in `stages/verity.rs` and not `switch_root.rs`
//!
//! `switch_root.rs` is intentionally narrow — `mount(2)` +
//! `move-mount` + `chroot(2)` + `execv(2)`. Mixing in a device-mapper
//! call would force every `switch_root` test to fake the verity
//! contract. Keeping verity as its own stage keeps each stage's
//! responsibility — and its mock surface — small.
//!
//! ## Cmdline + env override
//!
//! Production: the agent reads the data and hash device paths from
//! `/proc/cmdline` tokens `hippius.rootfs_data=` and
//! `hippius.rootfs_hash=` (defaults `/dev/vdb` and `/dev/vdc` — what
//! [`crate::pipeline::Config`] holds when the tenant UKI cmdline
//! doesn't explicitly override). Dev override: the env vars
//! `HIPPIUS_ROOTFS_DATA` / `HIPPIUS_ROOTFS_HASH` win outright. Same
//! env-vs-cmdline-vs-default precedence as `resolve_luks_device`.
//!
//! ## Fail-closed
//!
//! Every libcryptsetup error maps to [`AgentError::Verity`] with a
//! closed-vocabulary [`cat`] classifier; the underlying `LibcryptErr`
//! is discarded (no plaintext to logs, §20).

#![allow(dead_code)] // Real impl is target-gated; trait + mock are platform-agnostic.

use crate::pipeline::AgentError;

/// `/dev/mapper/` name the verity rootfs is activated at. Fixed (not
/// configurable): the measured initramfs's `switch_root` stage
/// references this exact path (see [`crate::stages::switch_root::
/// ROOTFS_MAPPER`]), so a per-boot name would break the §11 boot
/// chain.
pub const MAPPER_NAME: &str = "hippius-rootfs";

/// Env var overrides for the rootfs data + hash device paths. Mirror
/// [`crate::stages::unlock::ENV_LUKS_DEVICE`].
pub const ENV_ROOTFS_DATA: &str = "HIPPIUS_ROOTFS_DATA";
pub const ENV_ROOTFS_HASH: &str = "HIPPIUS_ROOTFS_HASH";

/// `/proc/cmdline` tokens for the rootfs data + hash device paths.
/// Default values are baked into the tenant UKI cmdline so a typical
/// boot does not need an override.
pub const CMDLINE_ROOTFS_DATA_KEY: &str = "hippius.rootfs_data";
pub const CMDLINE_ROOTFS_HASH_KEY: &str = "hippius.rootfs_hash";

/// `/proc/cmdline` token carrying the dm-verity root hash (64 hex
/// chars). Same name `systemd-veritysetup-generator` reads, kept
/// stable so a future `init=` switch sees the same token.
pub const CMDLINE_VERITY_ROOT_KEY: &str = "dm-verity.root";

/// Defaults — match the second + third virtio-blk disks the miner-
/// agent's libvirt XML attaches (after `/dev/vda` for the LUKS data
/// volume).
pub const DEFAULT_ROOTFS_DATA: &str = "/dev/vdb";
pub const DEFAULT_ROOTFS_HASH: &str = "/dev/vdc";

/// Stable classifier strings for [`AgentError::Verity`] raised from
/// this stage.
pub(crate) mod cat {
    /// `/proc/cmdline` could not be read at all — the §21 pipeline
    /// has no way to learn the verity root hash. Distinct from
    /// `root-missing` (cmdline readable but token absent) so the
    /// operator can tell apart a pre-mount-procfs regression from a
    /// cmdline-token typo.
    pub(crate) const CMDLINE_READ: &str = "cmdline-read";
    /// `/proc/cmdline` was readable but did not carry the
    /// `dm-verity.root=` token — the tenant UKI cmdline was not
    /// assembled with `assemble-uki.sh` (which appends it from
    /// `rootfs.roothash`).
    pub(crate) const ROOT_MISSING: &str = "root-missing";
    /// `dm-verity.root=<value>` was present but the value was not a
    /// 64-character lower-hex string. The verity protocol's root
    /// hash for SHA-256 is exactly 32 bytes = 64 hex chars.
    pub(crate) const ROOT_HEX: &str = "root-hex";
    /// `crypt_init(<hash_device>)` failed — the hash backing device
    /// is missing, not a block device, or not openable. Under a
    /// measured UKI this means the §11 block-device layout is not
    /// what was attested (e.g. the rootfs.verity disk was not
    /// attached by miner-agent).
    pub(crate) const INIT: &str = "init";
    /// `crypt_load(CRYPT_VERITY)` failed — the device carries no
    /// valid dm-verity superblock (wrong format, corrupt header).
    pub(crate) const HEADER_LOAD: &str = "header-load";
    /// `crypt_activate_by_volume_key` failed — the kernel rejected
    /// the dm-verity activation (root hash mismatch against the
    /// hash tree, or the data device referenced by the superblock
    /// is not present).
    pub(crate) const ACTIVATE: &str = "activate";
}

/// Source of dm-verity rootfs activations.
///
/// Production: [`crate::stages::verity_cryptsetup::RealRootfsVerity`]
/// — drives `libcryptsetup` (Linux only). Tests + non-Linux dev
/// hosts: [`MockRootfsVerity`].
pub trait RootfsVerity {
    /// Open the verity mapping `data_device` + `hash_device` +
    /// `root_hash` (32 bytes) → `/dev/mapper/`[`MAPPER_NAME`].
    ///
    /// Fail-closed: any error is terminal; there is no retry and no
    /// alternative-root fallback.
    fn open(
        &self,
        data_device: &str,
        hash_device: &str,
        root_hash: &[u8],
    ) -> Result<(), AgentError>;
}

/// Stage entry function — open the dm-verity rootfs via `opener`.
///
/// A thin forwarder kept for parity with the other §21 stage modules
/// (each exposes one free entry function that [`crate::pipeline::run`]
/// calls).
pub fn open_rootfs(
    opener: &dyn RootfsVerity,
    data_device: &str,
    hash_device: &str,
    root_hash: &[u8],
) -> Result<(), AgentError> {
    opener.open(data_device, hash_device, root_hash)
}

/// Resolve the rootfs data + hash device paths the same way
/// [`crate::stages::unlock::resolve_luks_device`] resolves the LUKS
/// backing device: env override → `/proc/cmdline` token → default.
///
/// Defaults are the second / third virtio-blk disk paths the miner-
/// agent's libvirt XML attaches.
pub fn resolve_rootfs_devices() -> Result<(String, String), AgentError> {
    let env_data = std::env::var(ENV_ROOTFS_DATA).ok();
    let env_hash = std::env::var(ENV_ROOTFS_HASH).ok();
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|_| AgentError::Verity(cat::CMDLINE_READ))?;
    Ok(resolve_rootfs_devices_from(
        env_data.as_deref(),
        env_hash.as_deref(),
        &cmdline,
    ))
}

/// Pure resolver behind [`resolve_rootfs_devices`]. Env override wins
/// outright; absent / empty env value falls through to the cmdline
/// token; absent / empty cmdline token falls through to the default.
pub fn resolve_rootfs_devices_from(
    env_data: Option<&str>,
    env_hash: Option<&str>,
    cmdline: &str,
) -> (String, String) {
    let data = env_data
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| cmdline_token(cmdline, CMDLINE_ROOTFS_DATA_KEY))
        .unwrap_or_else(|| DEFAULT_ROOTFS_DATA.to_string());
    let hash = env_hash
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| cmdline_token(cmdline, CMDLINE_ROOTFS_HASH_KEY))
        .unwrap_or_else(|| DEFAULT_ROOTFS_HASH.to_string());
    (data, hash)
}

/// Read the dm-verity root hash from `/proc/cmdline`. Returns the 32
/// raw bytes decoded from the `dm-verity.root=<64-hex>` token.
pub fn resolve_verity_root_hash() -> Result<[u8; 32], AgentError> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|_| AgentError::Verity(cat::CMDLINE_READ))?;
    resolve_verity_root_hash_from(&cmdline)
}

/// Pure resolver behind [`resolve_verity_root_hash`].
pub fn resolve_verity_root_hash_from(cmdline: &str) -> Result<[u8; 32], AgentError> {
    let hex = cmdline_token(cmdline, CMDLINE_VERITY_ROOT_KEY)
        .ok_or(AgentError::Verity(cat::ROOT_MISSING))?;
    if hex.len() != 64 {
        return Err(AgentError::Verity(cat::ROOT_HEX));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let h = byte_from_hex(chunk[0]).ok_or(AgentError::Verity(cat::ROOT_HEX))?;
        let l = byte_from_hex(chunk[1]).ok_or(AgentError::Verity(cat::ROOT_HEX))?;
        out[i] = (h << 4) | l;
    }
    Ok(out)
}

fn byte_from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn cmdline_token(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// What a [`MockRootfsVerity`] observed on its last `open` call.
///
/// `root_hash_len` only — **never** the bytes. The mock deliberately
/// holds no key-shaped material (the verity root hash is integrity-
/// only, not secret, but the discipline matches [`crate::stages::
/// unlock::MockUnlockCall`] for review uniformity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockOpenCall {
    pub data_device: String,
    pub hash_device: String,
    pub root_hash_len: usize,
}

/// Test double for [`RootfsVerity`]. Records the last call's
/// arguments and returns a fixed outcome supplied at construction
/// time.
pub struct MockRootfsVerity {
    pub last_call: std::cell::RefCell<Option<MockOpenCall>>,
    pub outcome: Result<(), &'static str>,
}

impl MockRootfsVerity {
    pub fn ok() -> Self {
        Self {
            last_call: std::cell::RefCell::new(None),
            outcome: Ok(()),
        }
    }
    pub fn failing(sub: &'static str) -> Self {
        Self {
            last_call: std::cell::RefCell::new(None),
            outcome: Err(sub),
        }
    }
}

impl RootfsVerity for MockRootfsVerity {
    fn open(
        &self,
        data_device: &str,
        hash_device: &str,
        root_hash: &[u8],
    ) -> Result<(), AgentError> {
        *self.last_call.borrow_mut() = Some(MockOpenCall {
            data_device: data_device.to_string(),
            hash_device: hash_device.to_string(),
            root_hash_len: root_hash.len(),
        });
        self.outcome.map_err(AgentError::Verity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_token_parsing() {
        let line =
            "ro quiet hippius.rootfs_data=/dev/vdb hippius.rootfs_hash=/dev/vdc dm-verity.root=abcd console=ttyS0";
        let (data, hash) = resolve_rootfs_devices_from(None, None, line);
        assert_eq!(data, "/dev/vdb");
        assert_eq!(hash, "/dev/vdc");
    }

    #[test]
    fn cmdline_falls_back_to_default() {
        let line = "ro quiet dm-verity.root=abcd";
        let (data, hash) = resolve_rootfs_devices_from(None, None, line);
        assert_eq!(data, "/dev/vdb");
        assert_eq!(hash, "/dev/vdc");
    }

    #[test]
    fn env_overrides_cmdline_and_default() {
        let line = "ro quiet hippius.rootfs_data=/dev/cmdline-data";
        let (data, hash) =
            resolve_rootfs_devices_from(Some("/dev/env-data"), Some("/dev/env-hash"), line);
        assert_eq!(data, "/dev/env-data");
        assert_eq!(hash, "/dev/env-hash");
    }

    #[test]
    fn root_hash_decodes_64_hex() {
        let line =
            "dm-verity.root=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let h = resolve_verity_root_hash_from(line).unwrap();
        assert_eq!(h[0], 0x01);
        assert_eq!(h[31], 0xef);
    }

    #[test]
    fn root_hash_missing_token() {
        let err = resolve_verity_root_hash_from("ro quiet").unwrap_err();
        assert!(matches!(err, AgentError::Verity(cat::ROOT_MISSING)));
    }

    #[test]
    fn root_hash_wrong_length() {
        let err = resolve_verity_root_hash_from("dm-verity.root=abcd").unwrap_err();
        assert!(matches!(err, AgentError::Verity(cat::ROOT_HEX)));
    }

    #[test]
    fn root_hash_non_hex_char() {
        let line =
            "dm-verity.root=ZZZZ456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = resolve_verity_root_hash_from(line).unwrap_err();
        assert!(matches!(err, AgentError::Verity(cat::ROOT_HEX)));
    }

    #[test]
    fn open_rootfs_forwards_to_opener() {
        let opener = MockRootfsVerity::ok();
        let h = [0u8; 32];
        open_rootfs(&opener, "/dev/vdb", "/dev/vdc", &h).expect("mock open succeeds");
        let call = opener.last_call.borrow().clone().expect("call recorded");
        assert_eq!(call.data_device, "/dev/vdb");
        assert_eq!(call.hash_device, "/dev/vdc");
        assert_eq!(call.root_hash_len, 32);
    }

    #[test]
    fn open_rootfs_is_fail_closed_on_an_open_error() {
        let opener = MockRootfsVerity::failing(cat::ACTIVATE);
        let h = [0u8; 32];
        let err = open_rootfs(&opener, "/dev/vdb", "/dev/vdc", &h).expect_err("must Err");
        assert!(matches!(err, AgentError::Verity(cat::ACTIVATE)));
    }
}
