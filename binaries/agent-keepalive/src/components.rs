//! Which guest components release this guest booted, and whether its
//! agents run (docs/design/guest-component-rollout.md, "Component health
//! in `REPORT_DATA`").
//!
//! Folded into the PSP-signed report (live-attestation schema v4), so the
//! host that relays the keepalive cannot change or strip a value. vali's
//! guest-upgrade gate reads it: a launch of a release is good only once a
//! guest of that launch reports the release it was built from and every
//! check the release declares passing.
//!
//! - `release_version` / `security_epoch`: from the record the measured
//!   initramfs wrote (`/run/hippius/guest-components`). `0` when it is
//!   missing or malformed.
//! - `health` bits ([`components_health`]):
//!   - `MOUNTED`: the record says `mounted=yes`;
//!   - `KEEPALIVE_FROM_RELEASE`: this process's executable is under the
//!     release image's `bin/`;
//!   - `TELEMETRY_ACTIVE`: `hippius-tenant-telemetry.service` is active;
//!   - `EOL_SIGN_ARMED`: `hippius-eol-sign.service` is active (its
//!     `ExecStop` signs the stopped-ack) and the binary it runs is an
//!     executable file.
//!
//! - `instance`: drawn at random when the keepalive starts.
//! - `unhealthy_ticks`: this instance's checks that were not all passing
//!   ([`ComponentsTracker`]), counted HERE, before any request leaves the
//!   guest: a sample the host withholds or delays still shows in every
//!   later one. The checks also run on their own thread
//!   ([`ComponentsTracker::watch`]), independent of the KBS round trips, so
//!   a host that blocks or holds the nonce request while a check fails
//!   does not stop the count.
//!
//! A check that cannot be evaluated is a CLEARED bit, never an error: the
//! keepalive's uptime leg must not depend on this one. Every probe is
//! bounded ([`ComponentsProbe::timeout`]); a `systemctl` that overruns is
//! killed and reaped.

use hippius_types::live_attestation::{components_health, GuestComponents};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The telemetry agent's unit.
pub const TELEMETRY_UNIT: &str = "hippius-tenant-telemetry.service";
/// The EOL stopped-ack unit.
pub const EOL_SIGN_UNIT: &str = "hippius-eol-sign.service";
/// The binary the EOL unit's `ExecStop` runs, under the release `bin/`.
pub const EOL_SIGN_BINARY: &str = "hippius-agent-initramfs";

/// Where each check looks. [`ComponentsProbe::production`] in the guest;
/// fixtures in tests.
#[derive(Debug, Clone)]
pub struct ComponentsProbe {
    /// The record the initramfs wrote.
    pub record: PathBuf,
    /// The release image's `bin/`.
    pub release_bin: PathBuf,
    /// This process's executable (`/proc/self/exe`).
    pub self_exe: PathBuf,
    /// `systemctl`.
    pub systemctl: PathBuf,
    /// Upper bound for one `systemctl` call.
    pub timeout: Duration,
}

impl ComponentsProbe {
    pub fn production() -> Self {
        Self {
            record: PathBuf::from("/run/hippius/guest-components"),
            release_bin: PathBuf::from("/run/hippius/guest/bin"),
            self_exe: PathBuf::from("/proc/self/exe"),
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            timeout: Duration::from_secs(5),
        }
    }

    /// Run every check. Never fails. `instance` / `unhealthy_ticks` are
    /// left `0` — [`ComponentsTracker::tick`] fills them.
    pub fn read(&self) -> GuestComponents {
        let (release_version, security_epoch, mounted) = std::fs::read_to_string(&self.record)
            .ok()
            .and_then(|s| parse_record(&s))
            .unwrap_or((0, 0, false));
        let mut health = 0;
        if mounted {
            health |= components_health::MOUNTED;
        }
        if self.runs_from_release() {
            health |= components_health::KEEPALIVE_FROM_RELEASE;
        }
        if self.unit_active(TELEMETRY_UNIT) {
            health |= components_health::TELEMETRY_ACTIVE;
        }
        if self.unit_active(EOL_SIGN_UNIT) && is_executable(&self.release_bin.join(EOL_SIGN_BINARY))
        {
            health |= components_health::EOL_SIGN_ARMED;
        }
        GuestComponents {
            release_version,
            security_epoch,
            health,
            instance: 0,
            unhealthy_ticks: 0,
        }
    }

    fn runs_from_release(&self) -> bool {
        match (
            std::fs::canonicalize(&self.self_exe),
            std::fs::canonicalize(&self.release_bin),
        ) {
            (Ok(exe), Ok(bin)) => exe.starts_with(bin),
            _ => false,
        }
    }

    fn unit_active(&self, unit: &str) -> bool {
        bounded_output(
            Command::new(&self.systemctl).args(["show", "--property=ActiveState", "--value", unit]),
            self.timeout,
        )
        .is_some_and(|out| out.trim() == "active")
    }
}

/// One keepalive process's view: the probe, its random `instance`, and the
/// count of its ticks that found a check failing.
#[derive(Debug)]
pub struct ComponentsTracker {
    probe: ComponentsProbe,
    instance: u32,
    unhealthy_ticks: AtomicU32,
}

impl ComponentsTracker {
    pub fn new(probe: ComponentsProbe, instance: u32) -> Self {
        Self {
            probe,
            instance,
            unhealthy_ticks: AtomicU32::new(0),
        }
    }

    /// A tracker with a random instance (`/dev/urandom`; the pid and the
    /// clock when that cannot be read — it only has to differ from the
    /// previous process's).
    pub fn start(probe: ComponentsProbe) -> Self {
        Self::new(probe, random_instance())
    }

    /// Run the checks once and count a failing tick. Never fails.
    pub fn tick(&self) -> GuestComponents {
        let mut c = self.probe.read();
        let unhealthy = if c.health & components_health::ALL == components_health::ALL {
            self.unhealthy_ticks.load(Ordering::SeqCst)
        } else {
            let prev = self
                .unhealthy_ticks
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_add(1))
                })
                .unwrap_or(u32::MAX);
            prev.saturating_add(1)
        };
        c.instance = self.instance;
        c.unhealthy_ticks = unhealthy;
        c
    }
}

impl ComponentsTracker {
    /// Run the checks every `every` on a thread of their own, for the
    /// life of the process — the count must not depend on the keepalive
    /// loop, whose KBS round trips the host can stall.
    pub fn watch(self: &Arc<Self>, every: Duration) -> std::thread::JoinHandle<()> {
        let tracker = Arc::clone(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(every);
            tracker.tick();
        })
    }

    /// The failing checks counted so far.
    pub fn unhealthy_ticks(&self) -> u32 {
        self.unhealthy_ticks.load(Ordering::SeqCst)
    }
}

fn random_instance() -> u32 {
    use std::io::Read;
    let mut buf = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        return u32::from_le_bytes(buf);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ std::process::id().rotate_left(16)
}

/// `(version, security_epoch, mounted)` from the record, or `None` when a
/// field is missing or not a `u32`.
fn parse_record(s: &str) -> Option<(u32, u32, bool)> {
    let mut version = None;
    let mut epoch = None;
    let mut mounted = None;
    for line in s.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "version" => version = Some(value.parse::<u32>().ok()?),
            "security_epoch" => epoch = Some(value.parse::<u32>().ok()?),
            "mounted" => mounted = Some(value == "yes"),
            _ => {}
        }
    }
    Some((version?, epoch?, mounted?))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Stdout of `cmd` if it exits 0 within `timeout`; the child is killed
/// and reaped otherwise.
fn bounded_output(cmd: &mut Command, timeout: Duration) -> Option<String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut out = String::new();
                use std::io::Read;
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return Some(out);
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn path(&self, p: &str) -> PathBuf {
            self.dir.path().join(p)
        }
        fn write(&self, p: &str, body: &str, mode: u32) {
            let path = self.path(p);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        /// A `systemctl` stub answering `active` for the units listed.
        /// Each call writes a NEW executable: the tests run in parallel
        /// threads, and a child another thread forks while this one holds
        /// a file open for writing keeps that file busy (`ETXTBSY`) until
        /// it execs — so a stub is waited on until it runs before use, and
        /// never rewritten.
        fn systemctl(&self, active: &[&str], body_extra: &str) -> PathBuf {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let name = format!("systemctl-{}", N.fetch_add(1, Ordering::SeqCst));
            let cases: String = active
                .iter()
                .map(|u| format!("    {u}) echo active ;;\n"))
                .collect();
            self.write(
                &name,
                &format!(
                    "#!/bin/sh\n[ \"$1\" = --ready ] && exit 0\n{body_extra}\nfor last; do :; done\ncase \"$last\" in\n{cases}    *) echo inactive ;;\nesac\n"
                ),
                0o755,
            );
            let path = self.path(&name);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Command::new(&path).arg("--ready").status().is_err() {
                assert!(Instant::now() < deadline, "stub never became executable");
                std::thread::sleep(Duration::from_millis(10));
            }
            path
        }
        fn probe(&self, systemctl: PathBuf) -> ComponentsProbe {
            ComponentsProbe {
                record: self.path("run/guest-components"),
                release_bin: self.path("guest/bin"),
                self_exe: self.path("guest/bin/hippius-agent-keepalive"),
                systemctl,
                timeout: Duration::from_secs(5),
            }
        }
        fn healthy(&self) {
            self.write(
                "run/guest-components",
                "version=2\nsecurity_epoch=1\ncommit=abc\nmounted=yes\n",
                0o644,
            );
            self.write("guest/bin/hippius-agent-keepalive", "", 0o755);
            self.write("guest/bin/hippius-agent-initramfs", "", 0o755);
        }
    }

    #[test]
    fn a_healthy_release_sets_every_bit() {
        let f = Fixture::new();
        f.healthy();
        let probe = f.probe(f.systemctl(&[TELEMETRY_UNIT, EOL_SIGN_UNIT], ""));
        assert_eq!(
            probe.read(),
            GuestComponents {
                release_version: 2,
                security_epoch: 1,
                health: components_health::ALL,
                instance: 0,
                unhealthy_ticks: 0,
            }
        );
    }

    #[test]
    fn the_tracker_latches_failing_ticks_for_its_instance() {
        let f = Fixture::new();
        f.healthy();
        let tracker = ComponentsTracker::new(f.probe(f.systemctl(&[EOL_SIGN_UNIT], "")), 77);
        // Telemetry down: two failing ticks.
        assert_eq!(tracker.tick().unhealthy_ticks, 1);
        let c = tracker.tick();
        assert_eq!((c.instance, c.unhealthy_ticks), (77, 2));
        // Back up: the count stays — a passing tick never lowers it.
        let mut probe = tracker.probe.clone();
        probe.systemctl = f.systemctl(&[TELEMETRY_UNIT, EOL_SIGN_UNIT], "");
        let tracker = ComponentsTracker { probe, ..tracker };
        let c = tracker.tick();
        assert_eq!((c.health, c.unhealthy_ticks), (components_health::ALL, 2));
    }

    #[test]
    fn the_watch_thread_counts_failures_without_any_keepalive_tick() {
        let f = Fixture::new();
        f.healthy();
        let tracker = Arc::new(ComponentsTracker::new(
            f.probe(f.systemctl(&[EOL_SIGN_UNIT], "")),
            5,
        ));
        let _watch = tracker.watch(Duration::from_millis(20));
        let deadline = Instant::now() + Duration::from_secs(10);
        while tracker.unhealthy_ticks() < 2 {
            assert!(Instant::now() < deadline, "the watch never counted");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The release declares the checks this keepalive counts: a release
    /// with fewer would latch failures it does not judge, one with more
    /// would declare checks the keepalive never runs.
    #[test]
    fn the_release_declares_every_check_the_keepalive_runs() {
        let conf = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/guest/components/release.conf"
        ))
        .unwrap();
        let mask: u32 = conf
            .lines()
            .find_map(|l| l.strip_prefix("health_mask="))
            .expect("release.conf declares health_mask")
            .parse()
            .unwrap();
        assert_eq!(mask, components_health::ALL);
    }

    #[test]
    fn each_failing_check_clears_only_its_bit() {
        let f = Fixture::new();
        f.healthy();
        let probe = f.probe(f.systemctl(&[EOL_SIGN_UNIT], ""));
        assert_eq!(
            probe.read().health,
            components_health::ALL & !components_health::TELEMETRY_ACTIVE
        );

        let probe = f.probe(f.systemctl(&[TELEMETRY_UNIT, EOL_SIGN_UNIT], ""));
        f.write("guest/bin/hippius-agent-initramfs", "", 0o644);
        assert_eq!(
            probe.read().health,
            components_health::ALL & !components_health::EOL_SIGN_ARMED,
            "the EOL binary must be executable"
        );

        f.write("guest/bin/hippius-agent-initramfs", "", 0o755);
        let mut elsewhere = probe.clone();
        elsewhere.self_exe = f.path("usr/sbin/hippius-agent-keepalive");
        f.write("usr/sbin/hippius-agent-keepalive", "", 0o755);
        assert_eq!(
            elsewhere.read().health,
            components_health::ALL & !components_health::KEEPALIVE_FROM_RELEASE
        );

        f.write(
            "run/guest-components",
            "version=2\nsecurity_epoch=1\ncommit=abc\nmounted=no\n",
            0o644,
        );
        let c = probe.read();
        assert_eq!((c.release_version, c.security_epoch), (2, 1));
        assert_eq!(
            c.health,
            components_health::ALL & !components_health::MOUNTED
        );
    }

    #[test]
    fn a_missing_or_malformed_record_reports_zero_and_not_mounted() {
        let f = Fixture::new();
        f.healthy();
        let probe = f.probe(f.systemctl(&[TELEMETRY_UNIT, EOL_SIGN_UNIT], ""));
        for body in [
            "version=two\nsecurity_epoch=1\nmounted=yes\n",
            "mounted=yes\n",
        ] {
            f.write("run/guest-components", body, 0o644);
            let c = probe.read();
            assert_eq!((c.release_version, c.security_epoch), (0, 0), "{body:?}");
            assert_eq!(c.health & components_health::MOUNTED, 0, "{body:?}");
        }
        fs::remove_file(f.path("run/guest-components")).unwrap();
        assert_eq!(probe.read().release_version, 0);
    }

    #[test]
    fn a_hung_systemctl_is_killed_and_counts_as_inactive() {
        let f = Fixture::new();
        f.healthy();
        let mut probe = f.probe(f.systemctl(&[TELEMETRY_UNIT, EOL_SIGN_UNIT], "sleep 30"));
        probe.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let c = probe.read();
        assert!(started.elapsed() < Duration::from_secs(5), "bounded");
        assert_eq!(
            c.health,
            components_health::MOUNTED | components_health::KEEPALIVE_FROM_RELEASE
        );
    }

    #[test]
    fn a_missing_systemctl_counts_as_inactive() {
        let f = Fixture::new();
        f.healthy();
        let probe = f.probe(f.path("no-such-systemctl"));
        assert_eq!(
            probe.read().health,
            components_health::MOUNTED | components_health::KEEPALIVE_FROM_RELEASE
        );
    }
}
