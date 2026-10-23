//! The `software.auto_update` block: the miner-agent auto-updater
//! (`hippius-miner-update`, deploy/ansible/playbooks/miner-tasks/
//! AUTO_UPDATE.md) as its files show it. Read only — the updater is never
//! run, and nothing here writes.
//!
//! - `enabled`: no `.no-auto-update` flag, no `AUTO_UPDATE_DISABLED=true`
//!   in `auto-update.env`, and `hippius-miner-update.timer` enabled (its
//!   `timers.target.wants` link resolves to a unit file). The first opt-out
//!   found, in the updater's own order, is the `disabled_reason`; a timer
//!   that was never installed is `timer_disabled` too.
//! - `last_check_unix`: the updater's status file, written by each timer
//!   run that read the release list. Absent until such a run.
//! - `failed_tag`: the newest `.update-failed-<tag>` marker newer than this
//!   binary's own release (an older one no longer matters).
//!
//! A source that exists but cannot be read (permissions, I/O) makes the
//! whole block absent: unknown, never a guess.

use std::path::{Path, PathBuf};

use hippius_host_inventory::{
    is_release_tag, AutoUpdateDisabledReason, AutoUpdateStatus, MAX_UNIX_TIME,
};

use super::{dir_names, Source};

/// The updater's status file, under its state directory.
pub const STATUS_FILE: &str = "auto-update-status.json";
/// The updater's per-host opt-out flag, under its state directory.
pub const NO_UPDATE_FLAG: &str = ".no-auto-update";
/// A release that failed its health check: `<prefix><tag>`.
pub const FAILED_MARKER_PREFIX: &str = ".update-failed-";

/// A status file past this is not read (it holds a few dozen bytes).
const MAX_STATUS_BYTES: u64 = 4096;

/// Where the updater's facts live. Real paths by default; fixtures in
/// tests.
#[derive(Debug, Clone)]
pub struct AutoUpdatePaths {
    /// `MINER_STATE_DIR`: the flag, the markers and the status file.
    pub state_dir: PathBuf,
    /// The updater's `EnvironmentFile`.
    pub env_file: PathBuf,
    /// The link `systemctl enable hippius-miner-update.timer` creates.
    pub timer_wants: PathBuf,
}

impl Default for AutoUpdatePaths {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/hippius-miner"),
            env_file: PathBuf::from("/etc/hippius-miner/auto-update.env"),
            timer_wants: PathBuf::from(
                "/etc/systemd/system/timers.target.wants/hippius-miner-update.timer",
            ),
        }
    }
}

/// `(YYYY, MM, DD, N)` of a release tag, N = 0 when absent — the updater's
/// ordering.
pub fn tag_key(tag: &str) -> Option<(u32, u32, u32, u32)> {
    if !is_release_tag(tag) {
        return None;
    }
    let mut parts = tag[1..].split('.').map(str::parse::<u32>);
    let y = parts.next()?.ok()?;
    let m = parts.next()?.ok()?;
    let d = parts.next()?.ok()?;
    let n = parts.next().transpose().ok()?.unwrap_or(0);
    Some((y, m, d, n))
}

/// `Some(true)` for a regular file at `path` (symlinks followed, as the
/// updater's `[ -f ]`), `Some(false)` when there is none (or it is not a
/// regular file), `None` when it cannot be told.
fn is_file(path: &Path) -> Option<bool> {
    match std::fs::metadata(path) {
        Ok(m) => Some(m.is_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}

/// The last `AUTO_UPDATE_DISABLED=` of a sourced env file is `true`
/// (quotes and a trailing comment aside), as the updater's `= true` test.
fn env_disables(content: &str) -> bool {
    let mut value = None;
    for line in content.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, v)) = line.split_once('=') else {
            continue;
        };
        if key != "AUTO_UPDATE_DISABLED" {
            continue;
        }
        let v = v.split_whitespace().next().unwrap_or("");
        let v = ['"', '\'']
            .iter()
            .find_map(|q| v.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
            .unwrap_or(v);
        value = Some(v == "true");
    }
    value.unwrap_or(false)
}

/// `last_check_unix` of the status file; `None` when absent, unreadable,
/// malformed or out of the calendar (the rest of the block still stands).
fn last_check(state_dir: &Path) -> Option<i64> {
    use std::io::Read;
    let file = std::fs::File::open(state_dir.join(STATUS_FILE)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    // The crate refuses a time outside the calendar: drop it here rather
    // than lose the whole software section.
    v.get("last_check_unix")?
        .as_i64()
        .filter(|t| (0..=MAX_UNIX_TIME).contains(t))
}

/// The newest failed-release marker, when newer than `own_tag` (any
/// marker when `own_tag` is not a release, e.g. a `dev` build).
fn failed_tag(state_dir: &Path, own_tag: &str) -> Option<String> {
    let own = tag_key(own_tag);
    dir_names(state_dir)
        .into_iter()
        .filter_map(|n| n.strip_prefix(FAILED_MARKER_PREFIX).map(str::to_string))
        .filter_map(|t| tag_key(&t).map(|k| (k, t)))
        .filter(|(k, _)| own.is_none_or(|own| *k > own))
        .max()
        .map(|(_, t)| t)
}

/// The block, or `None` when a source cannot be read.
pub fn collect_auto_update(p: &AutoUpdatePaths, own_tag: &str) -> Option<AutoUpdateStatus> {
    let flagged = is_file(&p.state_dir.join(NO_UPDATE_FLAG))?;
    let env_off = match Source::read(&p.env_file) {
        Source::Found(content) => env_disables(&content),
        Source::Missing => false,
        Source::Failed => return None,
    };
    let timer_on = is_file(&p.timer_wants)?;
    let disabled_reason = if flagged {
        Some(AutoUpdateDisabledReason::NoAutoUpdateFile)
    } else if env_off {
        Some(AutoUpdateDisabledReason::DisabledInEnv)
    } else if !timer_on {
        Some(AutoUpdateDisabledReason::TimerDisabled)
    } else {
        None
    };
    Some(AutoUpdateStatus {
        enabled: disabled_reason.is_none(),
        disabled_reason,
        last_check_unix: last_check(&p.state_dir),
        failed_tag: failed_tag(&p.state_dir, own_tag),
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixture::Host;
    use super::*;

    const OWN: &str = "v2026.10.16";

    /// An updater installed and on: env file, enabled timer, a status file.
    fn installed(h: &Host) {
        h.write("var/lib/hippius-miner/installed-release", "v2026.10.16\n");
        h.write(
            "etc/hippius-miner/auto-update.env",
            "# comment\nAUTO_UPDATE_DISABLED=false\nRELEASE_REPO=thenervelab/hippius-cvm\n",
        );
        h.write("etc/systemd/system/hippius-miner-update.timer", "[Timer]\n");
        h.symlink(
            "etc/systemd/system/timers.target.wants/hippius-miner-update.timer",
            h.dir
                .path()
                .join("etc/systemd/system/hippius-miner-update.timer")
                .to_str()
                .unwrap(),
        );
        h.write(
            "var/lib/hippius-miner/auto-update-status.json",
            r#"{"schema":1,"last_check_unix":1792200000}"#,
        );
    }

    fn paths(h: &Host) -> AutoUpdatePaths {
        let r = h.dir.path();
        AutoUpdatePaths {
            state_dir: r.join("var/lib/hippius-miner"),
            env_file: r.join("etc/hippius-miner/auto-update.env"),
            timer_wants: r
                .join("etc/systemd/system/timers.target.wants/hippius-miner-update.timer"),
        }
    }

    fn collect(h: &Host) -> Option<AutoUpdateStatus> {
        collect_auto_update(&paths(h), OWN)
    }

    #[test]
    fn an_installed_updater_is_on_with_its_last_check() {
        let h = Host::new();
        installed(&h);
        assert_eq!(
            collect(&h),
            Some(AutoUpdateStatus {
                enabled: true,
                disabled_reason: None,
                last_check_unix: Some(1_792_200_000),
                failed_tag: None,
            })
        );
    }

    #[test]
    fn the_flag_file_wins_over_every_other_opt_out() {
        let h = Host::new();
        installed(&h);
        h.write("var/lib/hippius-miner/.no-auto-update", "");
        h.write(
            "etc/hippius-miner/auto-update.env",
            "AUTO_UPDATE_DISABLED=true\n",
        );
        let a = collect(&h).unwrap();
        assert!(!a.enabled);
        assert_eq!(
            a.disabled_reason,
            Some(AutoUpdateDisabledReason::NoAutoUpdateFile)
        );
        // The last check is still reported: it says how long ago it stopped.
        assert_eq!(a.last_check_unix, Some(1_792_200_000));
    }

    #[test]
    fn the_env_switch_disables() {
        let h = Host::new();
        installed(&h);
        for content in [
            "AUTO_UPDATE_DISABLED=true\n",
            "AUTO_UPDATE_DISABLED=\"true\"\n",
            "export AUTO_UPDATE_DISABLED='true'  # rendered\n",
            "AUTO_UPDATE_DISABLED=false\nAUTO_UPDATE_DISABLED=true\n",
        ] {
            h.write("etc/hippius-miner/auto-update.env", content);
            assert_eq!(
                collect(&h).unwrap().disabled_reason,
                Some(AutoUpdateDisabledReason::DisabledInEnv),
                "{content:?}"
            );
        }
        for content in [
            "AUTO_UPDATE_DISABLED=false\n",
            "AUTO_UPDATE_DISABLED=TRUE\n",
            "AUTO_UPDATE_DISABLED=true\nAUTO_UPDATE_DISABLED=false\n",
            "# AUTO_UPDATE_DISABLED=true\n",
            "",
        ] {
            h.write("etc/hippius-miner/auto-update.env", content);
            assert!(collect(&h).unwrap().enabled, "{content:?}");
        }
    }

    #[test]
    fn a_missing_env_file_is_the_updaters_default() {
        let h = Host::new();
        installed(&h);
        std::fs::remove_file(paths(&h).env_file).unwrap();
        assert!(collect(&h).unwrap().enabled);
    }

    #[test]
    fn a_timer_not_enabled_or_masked_is_off() {
        let h = Host::new();
        installed(&h);
        let wants = paths(&h).timer_wants;
        std::fs::remove_file(&wants).unwrap();
        assert_eq!(
            collect(&h).unwrap().disabled_reason,
            Some(AutoUpdateDisabledReason::TimerDisabled)
        );
        // Masked: the unit is a link to /dev/null.
        std::os::unix::fs::symlink("/dev/null", &wants).unwrap();
        assert_eq!(
            collect(&h).unwrap().disabled_reason,
            Some(AutoUpdateDisabledReason::TimerDisabled)
        );
        // Dangling: the unit file is gone.
        std::fs::remove_file(&wants).unwrap();
        std::os::unix::fs::symlink(h.dir.path().join("nowhere.timer"), &wants).unwrap();
        assert_eq!(
            collect(&h).unwrap().disabled_reason,
            Some(AutoUpdateDisabledReason::TimerDisabled)
        );
    }

    #[test]
    fn nothing_installed_is_off_without_a_last_check() {
        let h = Host::new();
        assert_eq!(
            collect(&h),
            Some(AutoUpdateStatus {
                enabled: false,
                disabled_reason: Some(AutoUpdateDisabledReason::TimerDisabled),
                last_check_unix: None,
                failed_tag: None,
            })
        );
    }

    #[test]
    fn an_unreadable_env_file_is_unknown() {
        let h = Host::new();
        installed(&h);
        let env = paths(&h).env_file;
        std::fs::remove_file(&env).unwrap();
        // A directory where the file should be: exists, cannot be read.
        std::fs::create_dir_all(&env).unwrap();
        assert_eq!(collect(&h), None);
    }

    #[test]
    fn a_malformed_status_file_drops_only_the_last_check() {
        let h = Host::new();
        installed(&h);
        for content in [
            "not json",
            r#"{"last_check_unix":-5}"#,
            r#"{"last_check_unix":253402300800}"#,
            r#"{"last_check_unix":"1792200000"}"#,
            "{}",
        ] {
            h.write("var/lib/hippius-miner/auto-update-status.json", content);
            let a = collect(&h).unwrap();
            assert!(a.enabled);
            assert_eq!(a.last_check_unix, None, "{content:?}");
        }
        h.write(
            "var/lib/hippius-miner/auto-update-status.json",
            format!("{{\"last_check_unix\":1,\"pad\":\"{}\"}}", "x".repeat(5000)),
        );
        assert_eq!(collect(&h).unwrap().last_check_unix, None);
    }

    #[test]
    fn the_failed_tag_is_the_newest_marker_above_the_running_release() {
        let h = Host::new();
        installed(&h);
        for m in [
            ".update-failed-v2026.10.08.1",
            ".update-failed-v2026.10.21",
            ".update-failed-v2026.10.21.2",
            ".update-failed-v2026.10.9",
            ".update-failed-garbage",
        ] {
            h.write(
                &format!("var/lib/hippius-miner/{m}"),
                "2026-10-21T00:00:00Z health\n",
            );
        }
        assert_eq!(
            collect(&h).unwrap().failed_tag.as_deref(),
            Some("v2026.10.21.2")
        );
        // Running a newer release: every marker is stale.
        let a = collect_auto_update(&paths(&h), "v2026.10.22").unwrap();
        assert_eq!(a.failed_tag, None);
        // Equal to the running release: not "newer", not reported.
        let a = collect_auto_update(&paths(&h), "v2026.10.21.2").unwrap();
        assert_eq!(a.failed_tag, None);
        // A dev build: any marker counts.
        let a = collect_auto_update(&paths(&h), "dev").unwrap();
        assert_eq!(a.failed_tag.as_deref(), Some("v2026.10.21.2"));
    }

    #[test]
    fn tags_order_like_the_updater() {
        assert!(tag_key("v2026.10.08").unwrap() < tag_key("v2026.10.08.1").unwrap());
        assert!(tag_key("v2026.10.08.1").unwrap() < tag_key("v2026.10.08.10").unwrap());
        assert!(tag_key("v2026.10.08.999").unwrap() < tag_key("v2026.10.09").unwrap());
        assert!(tag_key("v2026.09.30").unwrap() < tag_key("v2026.10.01").unwrap());
        assert_eq!(tag_key("v2026.10.08.0"), None);
        assert_eq!(tag_key("dev"), None);
    }

    #[test]
    fn the_block_passes_the_crate_validation() {
        let h = Host::new();
        installed(&h);
        h.write("var/lib/hippius-miner/.update-failed-v2026.10.21", "x\n");
        h.write("var/lib/hippius-miner/.no-auto-update", "");
        let mut sw = super::super::software::tests::empty_software();
        sw.auto_update = collect(&h);
        let mut body = hippius_host_inventory::HostInventory {
            schema_version: hippius_host_inventory::SCHEMA_VERSION,
            domain: hippius_host_inventory::DOMAIN.to_string(),
            miner_id: "m".to_string(),
            timestamp_unix: 1,
            sequence: 1,
            report: hippius_host_inventory::ReportKind::Change,
            sections: hippius_host_inventory::Sections {
                software: Some(sw),
                ..Default::default()
            },
        };
        body.normalize();
        assert_eq!(body.validate(), Ok(()));
    }
}
