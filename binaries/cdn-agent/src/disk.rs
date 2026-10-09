//! Node disk usage for the usage reports (`disk`): the data volume, the
//! cache's configured maximum, and what the cache holds.
//!
//! Every value is best effort: one that cannot be read is omitted, and a
//! report is never held back for it.
//! - Volume: `statvfs` of the data mount (used = total - free blocks).
//! - Cache maximum: `max_size` from OpenResty's generated include
//!   (`paths.cache_conf`), else the same computation `render.sh cache-auto`
//!   does (`fill_percent` of the volume holding the cache, in KiB).
//! - Cache used: nginx creates the cache tree 0700, so the agent cannot
//!   walk it. `hippius-cdn-cache-usage.timer` (as the OpenResty user, idle
//!   I/O priority, every 10 minutes) writes `du` of `<cache_dir>/objects`
//!   to `<cache_dir>/.hippius-cache-usage`; the agent reads that, and
//!   omits it once it is older than `CACHE_USAGE_MAX_AGE_S`.

use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::config::Config;
use crate::wire::DiskUsage;

/// The file the cache-usage timer writes in the cache directory.
pub const CACHE_USAGE_FILE: &str = ".hippius-cache-usage";
/// A cache-usage figure older than this is not reported (about two missed
/// timer runs: one runs 10 minutes after the previous one ended).
pub const CACHE_USAGE_MAX_AGE_S: u64 = 30 * 60;
/// Both files hold one short line.
const MAX_SMALL_FILE: u64 = 4096;

/// Sample everything the config points at, at `now` (Unix seconds).
pub fn sample(cfg: &Config, now: u64) -> Option<DiskUsage> {
    let paths = &cfg.paths;
    let (volume_size_bytes, volume_used_bytes) = match volume(&paths.data_mount) {
        Some((size, used)) => (Some(size), Some(used)),
        None => (None, None),
    };
    let cache_max_bytes = paths
        .cache_conf
        .as_deref()
        .and_then(cache_max_from_conf)
        .or_else(|| cache_max_computed(&paths.cache_dir, cfg.data_plane.cache_fill_percent));
    let cache_used_bytes = cache_used(&paths.cache_dir.join(CACHE_USAGE_FILE), now);
    let d = DiskUsage {
        cache_used_bytes,
        cache_max_bytes,
        volume_used_bytes,
        volume_size_bytes,
    };
    (!d.is_empty()).then_some(d)
}

/// `(size, used)` of the filesystem holding `path`, in bytes.
pub fn volume(path: &Path) -> Option<(u64, u64)> {
    let st = rustix::fs::statvfs(path).ok()?;
    let frsize = st.f_frsize;
    let size = st.f_blocks.checked_mul(frsize)?;
    let used = st.f_blocks.checked_sub(st.f_bfree)?.checked_mul(frsize)?;
    Some((size, used))
}

/// `max_size=<n>[kmg]` of the `proxy_cache_path` include at `path`.
pub fn cache_max_from_conf(path: &Path) -> Option<u64> {
    let text = read_small(path)?;
    parse_max_size(&text)
}

fn parse_max_size(text: &str) -> Option<u64> {
    let start = text.find("max_size=")? + "max_size=".len();
    let rest = &text[start..];
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 19 {
        return None;
    }
    let n: u64 = rest[..digits].parse().ok()?;
    let unit = match rest.as_bytes().get(digits) {
        Some(b'k' | b'K') => 1 << 10,
        Some(b'm' | b'M') => 1 << 20,
        Some(b'g' | b'G') => 1 << 30,
        _ => 1,
    };
    n.checked_mul(unit)
}

/// What `render.sh cache-auto` writes for the volume holding `dir`:
/// `blocks * bsize / 1024 * percent / 100` KiB.
pub fn cache_max_computed(dir: &Path, percent: u8) -> Option<u64> {
    let st = rustix::fs::statvfs(dir).ok()?;
    let kib = u128::from(st.f_blocks) * u128::from(st.f_frsize) / 1024 * u128::from(percent) / 100;
    u64::try_from(kib * 1024).ok()
}

/// The cache-usage timer's figure in `path`, if it is fresh at `now`.
pub fn cache_used(path: &Path, now: u64) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let at = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    if at > now.saturating_add(300) || now.saturating_sub(at) > CACHE_USAGE_MAX_AGE_S {
        return None;
    }
    let text = read_small(path)?;
    let v = text.trim();
    if v.is_empty() || v.len() > 20 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SMALL_FILE {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::clock::unix_now;

    #[test]
    fn max_size_is_read_from_the_include() {
        assert_eq!(
            parse_max_size(
                "proxy_cache_path /c/objects levels=1:2 keys_zone=hippius_cache:1024m max_size=245760k inactive=30d use_temp_path=off;\n"
            ),
            Some(245_760 * 1024)
        );
        assert_eq!(parse_max_size("max_size=3g;"), Some(3 << 30));
        assert_eq!(parse_max_size("max_size=512;"), Some(512));
        for bad in [
            "",
            "max_size=;",
            "max_size=k",
            "keys_zone=x:1m",
            "max_size=99999999999999999999k",
        ] {
            assert_eq!(parse_max_size(bad), None, "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.conf");
        std::fs::write(&p, "proxy_cache_path /x max_size=64m;\n").unwrap();
        assert_eq!(cache_max_from_conf(&p), Some(64 << 20));
        assert_eq!(cache_max_from_conf(&dir.path().join("absent")), None);
    }

    #[test]
    fn computed_max_matches_render_sh() {
        let dir = tempfile::tempdir().unwrap();
        let st = rustix::fs::statvfs(dir.path()).unwrap();
        let want = st.f_blocks * st.f_frsize / 1024 * 75 / 100 * 1024;
        assert_eq!(cache_max_computed(dir.path(), 75), Some(want));
        assert_eq!(cache_max_computed(&dir.path().join("absent"), 75), None);
    }

    #[test]
    fn cache_used_needs_a_fresh_number() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(CACHE_USAGE_FILE);
        let now = unix_now();
        assert_eq!(cache_used(&p, now), None, "no file yet");
        std::fs::write(&p, "123456\n").unwrap();
        assert_eq!(cache_used(&p, now), Some(123_456));
        assert_eq!(
            cache_used(&p, now + CACHE_USAGE_MAX_AGE_S + 10),
            None,
            "stale"
        );
        for bad in ["", "12a", "-1", "99999999999999999999999"] {
            std::fs::write(&p, bad).unwrap();
            assert_eq!(cache_used(&p, now), None, "{bad}");
        }
        std::fs::write(&p, "9".repeat(5000)).unwrap();
        assert_eq!(cache_used(&p, now), None, "oversized");
    }

    #[test]
    fn volume_is_size_and_used() {
        let dir = tempfile::tempdir().unwrap();
        let (size, used) = volume(dir.path()).unwrap();
        assert!(size > 0 && used <= size);
        assert_eq!(volume(&dir.path().join("absent")), None);
    }
}
