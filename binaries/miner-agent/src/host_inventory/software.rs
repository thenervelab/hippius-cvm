//! The `software` section: kernel, OS (`/etc/os-release` `NAME` and
//! `VERSION_ID` only), the agent's release, the qemu / libvirt versions,
//! uptime and last boot.

use hippius_host_inventory::{SoftwareSection, MAX_NAME_LEN, MAX_TEXT_LEN};

use super::{clean_text, CommandRunner, HostPaths, Source, Tally};

/// `KEY` of an os-release file, unquoted.
fn os_release_value(content: &str, key: &str) -> Option<String> {
    let value = content
        .lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)?
        .1
        .trim();
    let unquoted = ['"', '\'']
        .iter()
        .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
        .unwrap_or(value);
    clean_text(unquoted.as_bytes(), MAX_TEXT_LEN)
}

/// The first dotted number of a tool's first line (`QEMU emulator version
/// 8.2.2 (Debian …)` → `8.2.2`, `libvirtd (libvirt) 10.0.0` → `10.0.0`).
/// Nothing else of the line is kept.
pub(crate) fn version_number(output: &str) -> Option<String> {
    output
        .lines()
        .next()?
        .split(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')' || c == ',')
        .find_map(|token| {
            let end = token
                .bytes()
                .position(|b| !(b.is_ascii_digit() || b == b'.'))
                .unwrap_or(token.len());
            let v = token.get(..end)?.trim_end_matches('.');
            let dotted = v.contains('.') && v.bytes().next().is_some_and(|b| b.is_ascii_digit());
            dotted.then(|| v.to_string())
        })
        .filter(|v| v.len() <= MAX_NAME_LEN)
}

/// The agent's release tag, as the `v6` heartbeat reports it.
fn agent_version() -> Option<String> {
    let tag = crate::release::RELEASE_TAG;
    hippius_types::heartbeat::is_valid_agent_version(tag).then(|| tag.to_string())
}

pub fn collect_software(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    now_unix: i64,
) -> SoftwareSection {
    let mut tally = Tally::default();
    let kernel = tally
        .required(Source::read(&paths.proc.join("sys/kernel/osrelease")))
        .and_then(|k| clean_text(k.as_bytes(), MAX_TEXT_LEN));
    let os_release = tally.required(
        paths
            .os_release
            .iter()
            .map(|p| Source::read(p))
            .find(|s| matches!(s, Source::Found(_)))
            .unwrap_or(Source::Missing),
    );
    let os_name = os_release
        .as_deref()
        .and_then(|c| os_release_value(c, "NAME"));
    let os_version_id = os_release
        .as_deref()
        .and_then(|c| os_release_value(c, "VERSION_ID"));
    let uptime_s = tally
        .required(Source::read(&paths.proc.join("uptime")))
        .and_then(|u| {
            u.split_ascii_whitespace()
                .next()?
                .split('.')
                .next()?
                .parse::<u64>()
                .ok()
        });
    let mut tool = |program: &str| {
        let out = runner.run(program, &["--version"]);
        tally.command(&out);
        out.ok().as_deref().and_then(version_number)
    };
    let qemu_version = tool("qemu-system-x86_64");
    let libvirt_version = tool("libvirtd");
    SoftwareSection {
        status: tally.status(),
        kernel,
        os_name,
        os_version_id,
        agent_version: agent_version(),
        qemu_version,
        libvirt_version,
        uptime_s: uptime_s.unwrap_or(0),
        last_boot_unix: uptime_s
            .and_then(|u| i64::try_from(u).ok())
            .map(|u| now_unix.saturating_sub(u)),
        auto_update: None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixture::{Host, Runner};
    use super::super::CommandError;
    use super::*;
    use hippius_host_inventory::SectionStatus;

    pub(crate) fn software_tree(h: &Host) {
        h.write("proc/sys/kernel/osrelease", "6.8.0-110-generic\n");
        h.write("proc/uptime", "3600.42 80000.10\n");
        h.write(
            "os-release",
            "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n\
             VERSION=\"24.04.3 LTS (Noble Numbat)\"\nID=ubuntu\n",
        );
    }

    pub(crate) fn runner(r: Runner) -> Runner {
        r.with(
            "qemu-system-x86_64 --version",
            Ok(
                "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.4)\n\
                Copyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers\n",
            ),
        )
        .with("libvirtd --version", Ok("libvirtd (libvirt) 10.0.0\n"))
    }

    #[test]
    fn reads_the_software_stack() {
        let h = Host::new();
        software_tree(&h);
        let s = collect_software(&h.paths(), &runner(Runner::default()), 1_800_000_000);
        assert_eq!(s.status, SectionStatus::Ok);
        assert_eq!(s.kernel.as_deref(), Some("6.8.0-110-generic"));
        assert_eq!(s.os_name.as_deref(), Some("Ubuntu"));
        assert_eq!(s.os_version_id.as_deref(), Some("24.04"));
        assert_eq!(
            s.agent_version.as_deref(),
            Some(crate::release::RELEASE_TAG)
        );
        assert_eq!(s.qemu_version.as_deref(), Some("8.2.2"));
        assert_eq!(s.libvirt_version.as_deref(), Some("10.0.0"));
        assert_eq!(s.uptime_s, 3600);
        assert_eq!(s.last_boot_unix, Some(1_800_000_000 - 3600));
    }

    #[test]
    fn version_numbers_only() {
        assert_eq!(
            version_number("QEMU emulator version 9.1.0\n").as_deref(),
            Some("9.1.0")
        );
        assert_eq!(
            version_number("libvirtd (libvirt) 10.0.0").as_deref(),
            Some("10.0.0")
        );
        assert_eq!(version_number("no version here"), None);
        assert_eq!(
            version_number("build 42"),
            None,
            "a bare number is not a version"
        );
        assert_eq!(version_number(""), None);
        assert_eq!(version_number("v 1.2.\n").as_deref(), Some("1.2"));
        assert_eq!(version_number(&"1.".repeat(100)), None, "over-long");
    }

    #[test]
    fn os_release_is_unquoted() {
        let c = "NAME='Debian GNU/Linux'\nVERSION_ID=12\nNAME_X=no\n";
        assert_eq!(
            os_release_value(c, "NAME").as_deref(),
            Some("Debian GNU/Linux")
        );
        assert_eq!(os_release_value(c, "VERSION_ID").as_deref(), Some("12"));
        assert_eq!(os_release_value(c, "ID"), None);
    }

    #[test]
    fn os_release_falls_back_to_usr_lib() {
        let h = Host::new();
        software_tree(&h);
        std::fs::remove_file(h.dir.path().join("os-release")).unwrap();
        h.write(
            "usr-lib-os-release",
            "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\n",
        );
        let s = collect_software(&h.paths(), &Runner::default(), 1);
        assert_eq!(s.status, SectionStatus::Ok);
        assert_eq!(s.os_name.as_deref(), Some("Debian GNU/Linux"));
        assert_eq!(s.os_version_id.as_deref(), Some("13"));
    }

    #[test]
    fn tool_failures_degrade_the_status() {
        let h = Host::new();
        software_tree(&h);
        // Neither tool installed: nothing to report, still ok.
        let s = collect_software(&h.paths(), &Runner::default(), 1);
        assert_eq!(s.status, SectionStatus::Ok);
        assert_eq!((s.qemu_version, s.libvirt_version), (None, None));
        let r = Runner::default()
            .with("qemu-system-x86_64 --version", Err(CommandError::Timeout))
            .with("libvirtd --version", Err(CommandError::Failed));
        assert_eq!(
            collect_software(&h.paths(), &r, 1).status,
            SectionStatus::Timeout
        );
        let r = Runner::default().with("libvirtd --version", Err(CommandError::Failed));
        assert_eq!(
            collect_software(&h.paths(), &r, 1).status,
            SectionStatus::Partial
        );
        // Nothing readable at all.
        let empty = Host::new();
        let s = collect_software(&empty.paths(), &Runner::default(), 1);
        assert_eq!(s.status, SectionStatus::Unavailable);
        assert_eq!((s.uptime_s, s.last_boot_unix), (0, None));
    }
}
