//! Production hardening — §20 "no-persistence / measured-image
//! discipline" (PR-E1.5).
//!
//! Three concerns, all of them §20 "no plaintext / no escape hatch":
//!
//! 1. **Measured-cmdline assertion** ([`assert_hardened_cmdline`]). The
//!    agent cannot *set* the kernel command line — it is baked into the
//!    measured UKI (§20) — but it CAN refuse to proceed unless the
//!    command line it booted with carries the hardened profile. Because
//!    the cmdline is folded into the SNP launch measurement, asserting
//!    it == asserting the measurement is the hardened image. Fail-closed
//!    on: an emergency/debug shell or `init=` / `rdinit=` override, a
//!    `crashkernel=` reservation, a missing/zero `panic=`, a missing
//!    `panic_on_oops=1`, or a datasource pin that is anything other
//!    than exactly `ds=nocloud` / `ds=nocloud-net`.
//! 2. **Serial-console suppression** ([`suppress_kernel_console`]).
//!    After attestation the agent lowers the kernel console log level
//!    so kernel diagnostics stop echoing to the serial console — a
//!    miner watching `ttyS0` must not get a post-attestation feed.
//! 3. **Fail-closed poweroff** ([`poweroff`]). On any fatal error the
//!    agent powers the VM **off** — it never drops to a shell and never
//!    returns control to a state a miner could inspect. This is also
//!    the single `reboot(2)` wrapper the §24/§25 EOL path reuses.
//!
//! "No emergency/debug shell" is enforced jointly here (the cmdline
//! assertion rejects `rd.shell` / `rd.break` / `init=/bin/sh` / …) and
//! by [`crate::main`], whose only fatal-error path is [`poweroff`].
//!
//! "No seed logging" is enforced structurally — [`AgentError`] classes
//! are closed `&'static str` vocabularies, [`crate::main`]'s logger
//! takes `&'static str` only — and is regression-guarded by the
//! `tests/no_seed_logging.rs` source scan + the `no-seed-logging` CI
//! step. Nothing in this module logs a byte of seed / key material.

use crate::pipeline::AgentError;

/// Stable classifier strings for [`AgentError::Hardening`]. `CONSOLE`
/// is raised only by the Linux-only console-suppression path — hence
/// the non-Linux `dead_code` allowance (on Linux every entry is
/// reachable).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod cat {
    /// The kernel command line carries an emergency / debug-shell entry
    /// (`rd.shell`, `rd.break`, `single`, `emergency`, `init=/bin/sh`,
    /// …) — a production measured image must not (§20).
    pub(crate) const DEBUG_SHELL: &str = "debug-shell";
    /// The command line carries a `crashkernel=` reservation — kdump /
    /// crashdump must be disabled in the measured image (§20).
    pub(crate) const CRASHKERNEL: &str = "crashkernel";
    /// `panic=` is absent or `0` — the kernel must reboot on panic, not
    /// hang at a prompt a miner could reach (§20).
    pub(crate) const PANIC: &str = "panic";
    /// `ds=nocloud` is absent — cloud-init must be hard-pinned to the
    /// NoCloud datasource so it never probes a miner-controlled
    /// datasource (§20 `[NoCloud, None]`).
    pub(crate) const DATASOURCE: &str = "datasource";
    /// Lowering the kernel console log level failed.
    pub(crate) const CONSOLE: &str = "console";
    /// `reboot(2)` itself failed — should be unreachable for uid 0.
    pub(crate) const POWEROFF: &str = "poweroff";
}

/// The single legitimate `init=` target: the measured initramfs agent
/// itself (the §F image factory bakes this onto the cmdline). Any other
/// `init=` value is an override into something else and is rejected.
const PINNED_INIT: &str = "/sbin/init-hippius";

/// Bare cmdline tokens that open an interactive shell, a rescue /
/// emergency mode, or override the boot init. Matched on the part
/// before any `=`, so a bare token AND a `<token>=value` form are both
/// caught (`rd.break=pre-mount`, any `rdinit=…` — `rdinit` overrides
/// the measured initramfs `/init` itself). Both the hyphen and the
/// underscore spelling of systemd's debug shell are listed — systemd
/// accepts `systemd.debug_shell` (and the `rd.`-prefixed initrd form),
/// and an exact-match denylist that knew only one spelling would miss
/// the other.
const SHELL_BARE_TOKENS: &[&str] = &[
    "rd.shell",
    "rd.break",
    "rdinit",
    "single",
    "emergency",
    "rescue",
    "systemd.debug_shell",
    "systemd.debug-shell",
    "rd.systemd.debug_shell",
    "rd.systemd.debug-shell",
];

/// SysV runlevel shortcuts that boot single-user / rescue. Matched only
/// as a whole bare token (`init=1` is a path, not a runlevel).
const RUNLEVEL_SHORTCUTS: &[&str] = &["1", "s", "S"];

/// Whether a single cmdline token is an escape hatch — an interactive
/// shell, a rescue/emergency mode, or an init override (see
/// [`SHELL_BARE_TOKENS`] / [`RUNLEVEL_SHORTCUTS`] / [`PINNED_INIT`]).
fn is_escape_hatch(tok: &str) -> bool {
    let (bare, value) = match tok.split_once('=') {
        Some((b, v)) => (b, Some(v)),
        None => (tok, None),
    };
    // A shell / rescue / rdinit token in either bare or `=value` form.
    if SHELL_BARE_TOKENS.contains(&bare) {
        return true;
    }
    // A runlevel shortcut — only as a whole bare token.
    if value.is_none() && RUNLEVEL_SHORTCUTS.contains(&tok) {
        return true;
    }
    // `init=` is permitted ONLY when it is exactly the pinned agent —
    // every other value (a shell, a different init, an empty value) is
    // an override. `init=` absent entirely is fine (the kernel runs the
    // initramfs `/init` regardless).
    if bare == "init" && value != Some(PINNED_INIT) {
        return true;
    }
    // A systemd unit override into rescue / emergency.
    if bare == "systemd.unit" && matches!(value, Some("rescue.target" | "emergency.target")) {
        return true;
    }
    false
}

/// Assert the (measured) kernel command line carries the §20 hardened
/// profile. Pure string analysis — unit-testable without `/proc`.
///
/// Fail-closed on the first violation. The returned
/// [`AgentError::Hardening`] carries only a closed-vocabulary
/// `&'static str`; its `Display` is the fixed `"hardening-failed"` tag.
pub fn assert_hardened_cmdline(cmdline: &str) -> Result<(), AgentError> {
    let tokens: Vec<&str> = cmdline.split_whitespace().collect();

    // (1) No emergency / debug shell, rescue mode, or init override.
    if tokens.iter().any(|t| is_escape_hatch(t)) {
        return Err(AgentError::Hardening(cat::DEBUG_SHELL));
    }

    // (2) No kdump / crashdump reservation.
    if tokens.iter().any(|t| t.starts_with("crashkernel=")) {
        return Err(AgentError::Hardening(cat::CRASHKERNEL));
    }

    // (3) Reboot-on-panic. EVERY `panic=` token must parse to a value
    //     >= 1 (a single `panic=0` anywhere — even alongside a
    //     `panic=1` — wins in the kernel's last-token-wins parse, so a
    //     contradictory pair is rejected, not averaged), at least one
    //     must be present, AND every `panic_on_oops=` token must be
    //     exactly `1`. Both keys are required explicitly — the kernel's
    //     defaults are not the hardened profile.
    let panic_values: Vec<&str> = tokens
        .iter()
        .filter_map(|t| t.strip_prefix("panic="))
        .collect();
    let panic_ok = !panic_values.is_empty()
        && panic_values
            .iter()
            .all(|v| v.parse::<i64>().map(|n| n >= 1).unwrap_or(false));
    let oops_values: Vec<&str> = tokens
        .iter()
        .filter_map(|t| t.strip_prefix("panic_on_oops="))
        .collect();
    let oops_ok = !oops_values.is_empty() && oops_values.iter().all(|v| *v == "1");
    if !panic_ok || !oops_ok {
        return Err(AgentError::Hardening(cat::PANIC));
    }

    // (4) cloud-init datasource hard-pinned to NoCloud. The token MUST
    //     be EXACTLY `ds=nocloud` or `ds=nocloud-net` — nothing else.
    //     A loose prefix match would let `ds=nocloud-net;s=http://…`
    //     (an embedded `seedfrom` / network seed source) through, which
    //     reintroduces an attacker-controlled datasource. There is no
    //     `ds=` token at all ⇒ cloud-init would probe EC2 / ConfigDrive
    //     / SMBIOS datasources a miner controls.
    let datasource_ok = tokens
        .iter()
        .any(|t| *t == "ds=nocloud" || *t == "ds=nocloud-net");
    // Any *other* `ds=` token (a different datasource, or a NoCloud
    // token carrying an `s=` / `seedfrom` payload) is an outright
    // rejection — not merely "the pinned one is also absent".
    let datasource_tainted = tokens
        .iter()
        .any(|t| t.starts_with("ds=") && *t != "ds=nocloud" && *t != "ds=nocloud-net");
    if !datasource_ok || datasource_tainted {
        return Err(AgentError::Hardening(cat::DATASOURCE));
    }

    Ok(())
}

/// Lower the kernel console log level so kernel messages stop echoing
/// to the serial console (§20 serial-console suppression). Called once,
/// post-attestation, by [`crate::main`].
///
/// Writes `/proc/sys/kernel/printk`: console log level `1` (only
/// `KERN_EMERG`). Linux-only — `/proc/sys` is a Linux interface; a
/// non-Linux dev build is a no-op (it never performs a real boot).
pub fn suppress_kernel_console() -> Result<(), AgentError> {
    #[cfg(target_os = "linux")]
    {
        // "console default minimum boot-default" — only the console
        // (first) field matters here; the others keep kernel defaults.
        std::fs::write("/proc/sys/kernel/printk", "1\t4\t1\t7\n")
            .map_err(|_| AgentError::Hardening(cat::CONSOLE))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Power the VM **off**. The §20 / §24 fail-closed terminal action:
/// the agent never drops to a shell and never returns control to a
/// state a miner could inspect.
///
/// On success this **never returns** (`reboot(2)` halts the VM). It
/// returns `Err` only if the syscall itself fails — which, for uid 0,
/// should be unreachable; the caller treats that residual as fatal.
/// Linux-only; a non-Linux dev build returns `Err` (it cannot — and
/// must not — power off the developer's host).
pub fn poweroff() -> Result<(), AgentError> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::reboot::{reboot, RebootMode};
        match reboot(RebootMode::RB_POWER_OFF) {
            // `reboot` returns `Infallible` on success — i.e. never;
            // matching the empty type is the panic-free way to say so.
            Ok(infallible) => match infallible {},
            Err(_) => Err(AgentError::Hardening(cat::POWEROFF)),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(AgentError::Hardening(cat::POWEROFF))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command line that satisfies every §20 hardening assertion.
    const HARDENED: &str = "ro quiet console=ttyS0 panic=1 panic_on_oops=1 \
         ds=nocloud hippius.kbs_url=https://kbs.vrack init=/sbin/init-hippius";

    #[test]
    fn a_hardened_cmdline_passes() {
        assert_hardened_cmdline(HARDENED).expect("the hardened profile must pass");
    }

    #[test]
    fn a_debug_shell_token_fails_closed() {
        // The debug-shell check is the first gate, so each line only
        // needs the offending token to be rejected.
        for bad in [
            "ro panic=1 ds=nocloud rd.shell",
            "ro panic=1 ds=nocloud rd.break=pre-mount",
            "ro panic=1 ds=nocloud single",
            "ro panic=1 ds=nocloud emergency",
            "ro panic=1 ds=nocloud init=/bin/sh",
            // `rdinit=` overrides the measured initramfs init itself —
            // any value is rejected.
            "ro panic=1 ds=nocloud rdinit=/bin/sh",
            "ro panic=1 ds=nocloud init=/bin/busybox",
            // A non-pinned `init=` of any kind — the whitelist rejects
            // everything but `/sbin/init-hippius`.
            "ro panic=1 ds=nocloud init=/usr/lib/systemd/systemd-other",
            "ro panic=1 ds=nocloud systemd.unit=rescue.target",
            "ro panic=1 ds=nocloud systemd.unit=emergency.target",
            // Both spellings of the systemd debug shell, with + without
            // value, with + without the initrd `rd.` prefix.
            "ro panic=1 ds=nocloud systemd.debug-shell=1",
            "ro panic=1 ds=nocloud systemd.debug_shell",
            "ro panic=1 ds=nocloud systemd.debug_shell=1",
            "ro panic=1 ds=nocloud rd.systemd.debug_shell",
            // SysV runlevel shortcuts that boot single-user / rescue.
            "ro panic=1 ds=nocloud 1",
            "ro panic=1 ds=nocloud s",
            "ro panic=1 ds=nocloud S",
        ] {
            assert!(
                matches!(
                    assert_hardened_cmdline(bad),
                    Err(AgentError::Hardening(cat::DEBUG_SHELL))
                ),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn the_legitimate_pinned_init_is_not_flagged_as_a_debug_shell() {
        // `init=/sbin/init-hippius` reduces to bare `init`, but it must
        // NOT collide with the `init=/bin/sh`-style exact-match entries.
        assert_hardened_cmdline(HARDENED).expect("the pinned init must pass");
    }

    #[test]
    fn a_crashkernel_reservation_fails_closed() {
        let line = "ro panic=1 ds=nocloud crashkernel=256M";
        assert!(matches!(
            assert_hardened_cmdline(line),
            Err(AgentError::Hardening(cat::CRASHKERNEL))
        ));
    }

    #[test]
    fn a_missing_or_zero_panic_fails_closed() {
        for bad in [
            // `panic=` absent entirely.
            "ro ds=nocloud panic_on_oops=1",
            // `panic=0` — the kernel would hang, not reboot.
            "ro panic=0 panic_on_oops=1 ds=nocloud",
            // `panic_on_oops` explicitly disabled.
            "ro panic=1 panic_on_oops=0 ds=nocloud",
            // `panic_on_oops` absent — required explicitly, not defaulted.
            "ro panic=1 ds=nocloud",
            // Contradictory tokens: a `panic=0` alongside a `panic=1`
            // (last-token-wins in the kernel → 0) must be rejected, not
            // averaged away.
            "ro panic=1 panic=0 panic_on_oops=1 ds=nocloud",
            // Same for a contradicting `panic_on_oops=0`.
            "ro panic=1 panic_on_oops=1 panic_on_oops=0 ds=nocloud",
            // A non-numeric `panic=` token is not a valid >=1 value.
            "ro panic=yes panic_on_oops=1 ds=nocloud",
        ] {
            assert!(
                matches!(
                    assert_hardened_cmdline(bad),
                    Err(AgentError::Hardening(cat::PANIC))
                ),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn a_missing_or_tainted_datasource_pin_fails_closed() {
        for bad in [
            // No `ds=` token — cloud-init would probe other datasources.
            "ro panic=1 panic_on_oops=1 quiet",
            // A NoCloud token carrying an embedded network seed source.
            "ro panic=1 panic_on_oops=1 ds=nocloud-net;s=http://evil/",
            "ro panic=1 panic_on_oops=1 ds=nocloud;seedfrom=http://evil/",
            // A different datasource entirely.
            "ro panic=1 panic_on_oops=1 ds=ec2",
        ] {
            assert!(
                matches!(
                    assert_hardened_cmdline(bad),
                    Err(AgentError::Hardening(cat::DATASOURCE))
                ),
                "must reject: {bad}"
            );
        }
        // The exact NoCloud tokens are accepted.
        for ok in [
            "ro panic=1 panic_on_oops=1 ds=nocloud init=/sbin/init-hippius",
            "ro panic=1 panic_on_oops=1 ds=nocloud-net init=/sbin/init-hippius",
        ] {
            assert_hardened_cmdline(ok).unwrap_or_else(|e| panic!("must pass {ok}: {e:?}"));
        }
    }

    #[test]
    fn hardening_error_class_is_a_static_tag() {
        let err = AgentError::Hardening(cat::DEBUG_SHELL);
        // §20: Display never interpolates the inner classifier.
        assert_eq!(err.to_string(), "hardening-failed");
        assert_eq!(err.class(), "hardening-failed");
    }
}
