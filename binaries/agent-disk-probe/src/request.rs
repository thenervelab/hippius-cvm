//! The probe request vali's probe userdata leaves at
//! `/run/hippius/disk-probe/request.json` (KBS-released, so only vali can
//! have written it for this VM):
//!
//! ```json
//! { "vm_id": "…", "run_id": "<32 hex>", "nonce": "<64 hex>",
//!   "start_delay_s": 21600,
//!   "targets": [ {"slot": "os", "profile": "v1"},
//!                {"slot": "x0", "profile": "d1"} ] }
//! ```
//!
//! `targets` are probed one at a time, in slot order. `os` is the OS
//! disk (a file in the data filesystem); `x<N>` is the dedicated disk
//! whose virtio serial is `hippius-x<N>`.

use std::path::Path;

use hippius_types::disk_stats::{is_valid_slot, MAX_PROBE_TARGETS, MAX_PROBE_VM_ID_LEN};
use serde::Deserialize;

use crate::error::{ProbeError, Result};

/// Where the request is.
pub const REQUEST_PATH: &str = "/run/hippius/disk-probe/request.json";

/// The longest start delay honoured (vali picks 6-48 h).
pub const MAX_START_DELAY_S: u64 = 72 * 3600;

const MAX_REQUEST_BYTES: u64 = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    vm_id: String,
    run_id: String,
    nonce: String,
    start_delay_s: u64,
    targets: Vec<WireTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTarget {
    slot: String,
    profile: String,
}

/// A profile this binary runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The OS disk, on a pool.
    V1,
    /// A dedicated disk, through dm-crypt plain with an ephemeral key.
    D1,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::V1 => "v1",
            Profile::D1 => "d1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub slot: String,
    pub profile: Profile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub vm_id: String,
    pub run_id: [u8; 16],
    pub nonce: [u8; 32],
    pub start_delay_s: u64,
    /// Strictly sorted by slot.
    pub targets: Vec<Target>,
}

fn invalid(what: &'static str) -> ProbeError {
    ProbeError::Request(what)
}

impl Request {
    /// Parse and check a request. `os` takes `v1` only, `x<N>` `d1` only.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let w: Wire = serde_json::from_slice(bytes).map_err(|_| invalid("json"))?;
        if w.vm_id.is_empty()
            || w.vm_id.len() > MAX_PROBE_VM_ID_LEN
            || !w.vm_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid("vm_id"));
        }
        let run_id: [u8; 16] = hex::decode(&w.run_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(invalid("run_id"))?;
        let nonce: [u8; 32] = hex::decode(&w.nonce)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(invalid("nonce"))?;
        if w.start_delay_s > MAX_START_DELAY_S {
            return Err(invalid("start_delay_s"));
        }
        if w.targets.is_empty() || w.targets.len() > MAX_PROBE_TARGETS {
            return Err(invalid("targets"));
        }
        let mut targets = Vec::with_capacity(w.targets.len());
        for t in &w.targets {
            if !is_valid_slot(&t.slot) {
                return Err(invalid("slot"));
            }
            let profile = match (t.slot.as_str(), t.profile.as_str()) {
                ("os", "v1") => Profile::V1,
                (slot, "d1") if slot != "os" => Profile::D1,
                _ => return Err(invalid("profile")),
            };
            targets.push(Target {
                slot: t.slot.clone(),
                profile,
            });
        }
        targets.sort_by(|a, b| a.slot.cmp(&b.slot));
        if targets.windows(2).any(|p| p[0].slot == p[1].slot) {
            return Err(invalid("slot-duplicate"));
        }
        Ok(Self {
            vm_id: w.vm_id,
            run_id,
            nonce,
            start_delay_s: w.start_delay_s,
            targets,
        })
    }

    /// The request at `path`; `Ok(None)` when there is none (the dormant
    /// case). Not followed through a symlink; bounded in size.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(invalid("unreadable")),
        };
        if !meta.is_file() || meta.len() > MAX_REQUEST_BYTES {
            return Err(invalid("not-a-small-file"));
        }
        let bytes = std::fs::read(path).map_err(|_| invalid("unreadable"))?;
        Self::parse(&bytes).map(Some)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn req(targets: &str) -> String {
        format!(
            r#"{{"vm_id":"probe-1","run_id":"{}","nonce":"{}","start_delay_s":60,"targets":{targets}}}"#,
            "ab".repeat(16),
            "cd".repeat(32)
        )
    }

    #[test]
    fn a_request_parses_with_its_targets_in_slot_order() {
        let r = Request::parse(
            req(r#"[{"slot":"x1","profile":"d1"},{"slot":"os","profile":"v1"},{"slot":"x0","profile":"d1"}]"#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(r.vm_id, "probe-1");
        assert_eq!(r.run_id, [0xab; 16]);
        assert_eq!(r.nonce, [0xcd; 32]);
        let slots: Vec<_> = r.targets.iter().map(|t| t.slot.as_str()).collect();
        assert_eq!(slots, ["os", "x0", "x1"]);
        assert_eq!(r.targets[0].profile, Profile::V1);
        assert_eq!(r.targets[1].profile, Profile::D1);
    }

    #[test]
    fn a_malformed_request_is_refused() {
        for bad in [
            req(r#"[]"#),
            req(r#"[{"slot":"os","profile":"d1"}]"#),
            req(r#"[{"slot":"x0","profile":"v1"}]"#),
            req(r#"[{"slot":"x24","profile":"d1"}]"#),
            req(r#"[{"slot":"x0","profile":"d1"},{"slot":"x0","profile":"d1"}]"#),
            req(r#"[{"slot":"os","profile":"v1","extra":1}]"#),
            req(r#"[{"slot":"os","profile":"v1"}]"#).replace("\"probe-1\"", "\"\""),
            req(r#"[{"slot":"os","profile":"v1"}]"#).replace(&"ab".repeat(16), "ab"),
            req(r#"[{"slot":"os","profile":"v1"}]"#).replace("60", "999999999"),
            "not json".to_string(),
        ] {
            assert!(Request::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn no_request_file_is_the_dormant_case() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Request::load(&dir.path().join("request.json")).unwrap(),
            None
        );
        let p = dir.path().join("r.json");
        std::fs::write(&p, req(r#"[{"slot":"os","profile":"v1"}]"#)).unwrap();
        assert!(Request::load(&p).unwrap().is_some());
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(Request::load(&link).is_err());
    }
}
