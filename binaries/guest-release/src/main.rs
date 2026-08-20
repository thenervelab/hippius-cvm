//! `hippius-guest-release` — slim CLI invoked from a tenant cloud-
//! image initramfs `keyscript=` field. Runs the §21 release exchange:
//!
//!   1. Load the L1-signed COSE `OrderTicket` from `--ticket FILE`.
//!   2. Generate an ephemeral X25519 keypair (mlocked, §20).
//!   3. POST `--kbs-url/v1/kbs/nonce` → fresh single-use 32-byte nonce.
//!   4. `SNP_GET_REPORT` ioctl on `/dev/sev-guest` with
//!      `REPORT_DATA = nonce ‖ x25519_pub` (§20 byte-exact layout).
//!   5. POST `--kbs-url/v1/kbs/release` → KBS-signed wrapped response.
//!   6. `hippius_guest::verify_and_unwrap_release` (§6/§7/§19/§20 binding
//!      gate + HPKE unwrap) → `UnwrappedSecrets { luks, userdata }`.
//!   7. Write the LUKS KEK plaintext bytes to STDOUT (no newline).
//!   8. If `--userdata-out PATH` is set, write the unwrapped user-data
//!      bytes to that path (mode 0600, parent dir created 0755). The
//!      keyscript points this at `/run/cloud-init/seed/user-data` so
//!      cloud-init's NoCloud datasource picks it up post-pivot from
//!      tmpfs — the bytes never touch persistent storage, encrypted
//!      or otherwise.
//!
//!   §7 — if `--lifecycle-key-out PATH` is set AND the release carried a
//!   `lifecycle_key`, write the unwrapped Ed25519 SIGNING seed to that
//!   tmpfs path (mode 0600). The cmdline names it via
//!   `hippius.lifecycle_key_path`; the measured `eol` signer reads the
//!   SAME path to sign the §24/§25 StoppedAck. A pre-§7 release (no key)
//!   writes nothing — `eol` then signs nothing. The KBS HPKE-sealed this
//!   key to the attested guest only; the miner never sees it, and it
//!   never lands on the encrypted disk.
//!
//!   P9/#12 — that "tmpfs only" contract is now ENFORCED rather than
//!   assumed: `--lifecycle-key-out`, `--userdata-out` and
//!   `--volume-stamp-ctx-out` are refused (exit `EXIT_USAGE`, BEFORE
//!   any KBS traffic) unless the path is strictly under `/run/`. The
//!   lifecycle path in particular arrives from the measured cmdline
//!   (`hippius.lifecycle_key_path`), and the initramfs has the
//!   miner-provisioned PLAINTEXT state disk mounted at
//!   `/hippius-state` by the time the release runs — so an
//!   `--lifecycle-key-out /hippius-state/…` would hand the miner the
//!   §7 signing key in the clear. See [`check_secret_out_path`].
//!
//!   `kbs-core::volume_stamp` anti-rollback for the guest-keyed overlay —
//!   two SEPARATE invocations of this same binary:
//!
//!   - **This** (release-mode) invocation, when `--volume-stamp-ctx-out
//!     PATH` is set, writes `{vm_id, expected, target, token}` to PATH
//!     BEFORE the KEK ships (same fail-closed ordering as
//!     `--new-counter-file`). The caller is expected to compare
//!     `expected` against the stamp inside the encrypted overlay, write
//!     `target` into it, and only THEN invoke this binary a second time.
//!   - **`--confirm-volume-stamp CTX_PATH`** is a DISTINCT mode: it
//!     skips the release exchange entirely, reads the ctx file from the
//!     step above, and POSTs `/v1/kbs/volume-stamp/confirm` over the
//!     SAME transport selection (`--kbs-url`) release uses. Mutually
//!     exclusive with every release-mode flag.
//!
//! `cryptsetup-initramfs` (Debian/Ubuntu) calls this binary as the
//! `keyscript` for the `cryptroot` entry in `/etc/crypttab` and reads
//! the KEK from its stdout into libcryptsetup's mlocked buffer for
//! `crypt_activate_by_passphrase`. The §20 secret-discipline contract
//! is identical to what the legacy `agent-initramfs` enforced:
//!
//! - The unwrapped LUKS plaintext crosses one process boundary
//!   (stdout → cryptsetup-initramfs stdin → libcryptsetup mlocked
//!   buffer) and is dropped + wiped on every other code path via
//!   `Zeroizing`.
//! - User-data, when `--userdata-out` is set, is written byte-exact
//!   to a tmpfs path (the keyscript uses `/run/cloud-init/seed/`,
//!   which is `mount --move`'d across `switch_root` and never lands
//!   on the encrypted rootfs). The buffer drops + wipes immediately
//!   after the write returns.
//! - Every diagnostic goes to stderr and uses static `&'static str`
//!   classifiers from `hippius-agent-initramfs::AgentError::class()`
//!   and `sub_class()` — no plaintext interpolation (§20).
//!
//! Build envelope: dynamically linked against the tenant cloud
//! image's glibc, cross-built inside the pinned `tenant-uki` Docker
//! image (`packer/tenant-uki/uki/Dockerfile`) for byte-reproducibility
//! across operator workstations.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use ciborium::value::Value;
use clap::Parser;
use hippius_agent_initramfs::stages::{
    kbs_client, keygen, snp_report, ticket as ticket_stage, verify,
};
use hippius_agent_initramfs::{
    is_vsock_url, AgentError, HttpClient, ReqwestHttpClient, VsockHttpClient,
    PINNED_KBS_RESPONSE_KID, PINNED_KBS_RESPONSE_VK,
};
use hippius_guest::UnwrappedSecrets;
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use std::io::Write;
use std::process::ExitCode;

/// Exit codes the keyscript caller distinguishes.
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
/// Generic release-exchange failure (transport, decode, sig, binding).
/// Maps every closed-vocabulary `AgentError::class()` to this exit
/// code; the operator distinguishes on stderr classification tags.
const EXIT_RELEASE_FAILED: u8 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "hippius-guest-release",
    version,
    about = "Run the SEV-SNP / KBS release exchange and emit the LUKS KEK on stdout."
)]
struct Cli {
    /// HTTPS base URL for the KBS, e.g.
    /// `https://kbs.hippius.network`. The release POST hits
    /// `${KBS_URL}/v1/kbs/release`.
    #[arg(long)]
    kbs_url: String,

    /// Path to the raw COSE_Sign1 OrderTicket bytes (same bytes
    /// the miner-agent pushes over AF_VSOCK; the bake-time alternative
    /// is to pre-stage the file in the initramfs from a NoCloud seed).
    ///
    /// Required in release mode (the default). Absent + `--confirm-
    /// volume-stamp` set ⇒ confirm mode instead (see that flag).
    #[arg(long)]
    ticket: Option<std::path::PathBuf>,

    /// Optional path to write the unwrapped cloud-init user-data
    /// bytes to. The keyscript passes
    /// `/run/cloud-init/seed/user-data` so cloud-init's NoCloud
    /// datasource (cmdline `ds=nocloud;s=/run/cloud-init/seed/`) picks
    /// it up post-pivot from tmpfs. Parent directory is created
    /// `0755`, the file itself `0600`. Omitting the flag preserves
    /// the pre-#264 behavior of dropping user-data on the floor —
    /// useful for callers that ship their own NoCloud seed.
    ///
    /// P9/#12 — REFUSED (exit `EXIT_USAGE`, before the release
    /// exchange) if the path is not strictly under `/run/`. See
    /// [`check_secret_out_path`].
    #[arg(long)]
    userdata_out: Option<std::path::PathBuf>,

    /// §7 — optional path to write the unwrapped guest lifecycle
    /// SIGNING key (Ed25519 seed) to. The cmdline names this via
    /// `hippius.lifecycle_key_path`; the measured `hippius-agent-
    /// initramfs eol [--sign-only]` reads the SAME path to sign the
    /// §24/§25 StoppedAck. Written mode `0600`, parent dir `0755`, on
    /// TMPFS only — the key NEVER lands on the miner-backed encrypted
    /// disk. Omitting the flag (or a pre-§7 release that carries no
    /// lifecycle key) leaves no key file: `eol` then logs `eol-no-key`
    /// and signs nothing (fail-closed). The KBS HPKE-sealed this key
    /// to the attested guest only — the miner never sees plaintext.
    ///
    /// P9/#12 — REFUSED (exit `EXIT_USAGE`, before the release
    /// exchange) if the path is not strictly under `/run/`. See
    /// [`check_secret_out_path`].
    #[arg(long)]
    lifecycle_key_out: Option<std::path::PathBuf>,

    /// Phase 2A of audit follow-up Codex #2 — anti-rollback for
    /// valid-old-ciphertext replay. When set, read the previous
    /// KBS-issued boot counter from this file (newline-stripped
    /// ASCII decimal). On the FIRST boot the file should not exist
    /// or be empty: this binary then submits `1`. On subsequent
    /// boots it submits `prev + 1`. The path lives on the operator-
    /// chosen persistence channel (Phase 2B picks the on-disk
    /// location; for testing the operator passes any path).
    ///
    /// When the flag is OMITTED, no counter is sent — backward
    /// compat with pre-Phase-2A KBS (which short-circuits the CAS).
    #[arg(long)]
    last_counter_file: Option<std::path::PathBuf>,

    /// Phase 2A — companion to `--last-counter-file`. After a
    /// successful release, write the KBS-issued counter from the
    /// signed response to this path so the NEXT boot reads it as
    /// `--last-counter-file`. Required when `--last-counter-file`
    /// is set; otherwise the next boot has no way to know what
    /// value to submit. Written with mode `0600` and parent dir
    /// `0755`, same discipline as `--userdata-out`.
    #[arg(long)]
    new_counter_file: Option<std::path::PathBuf>,

    /// `kbs-core::volume_stamp` — optional path to write the anti-
    /// rollback confirm CONTEXT to, after a successful release and
    /// BEFORE the KEK ships (same fail-closed ordering as
    /// `--new-counter-file`: see step 7c in `run`). A 0600 JSON file:
    /// `{"vm_id":"…","expected":N,"target":N,"token":"64 hex chars"}`.
    ///
    /// `expected` is the stamp the KBS expects the encrypted overlay to
    /// already hold; the caller compares it, writes `target` (always
    /// `expected + 1`) into the overlay, and only THEN runs this binary
    /// again with `--confirm-volume-stamp` pointed at this same path.
    ///
    /// If the flag is given but the release carried no token (a KBS
    /// that predates this gate), that is FATAL — an operator who asked
    /// for the gate must not get a silent no-op — so the disk stays
    /// locked and the error surfaces on the serial, same discipline as
    /// every other `*_out` flag.
    ///
    /// P9/#12 — REFUSED (exit `EXIT_USAGE`, before the release
    /// exchange) if the path is not strictly under `/run/`: the confirm
    /// token is an authenticator and must not reach persistent storage.
    /// See [`check_secret_out_path`].
    #[arg(long)]
    volume_stamp_ctx_out: Option<std::path::PathBuf>,

    /// `kbs-core::volume_stamp` — companion to `--volume-stamp-ctx-out`
    /// for a POSIX-sh caller: writes ONLY the decimal `expected` value
    /// (`KbsResponse::expected_volume_stamp`, ASCII decimal + newline,
    /// e.g. `37\n`), mode `0644`, no JSON, no token, nothing secret.
    /// Written after a successful release, BEFORE the KEK ships — same
    /// fail-closed ordering as every other `*_out` flag.
    ///
    /// Deliberately a SEPARATE file from `--volume-stamp-ctx-out`: the
    /// initramfs shell gate that compares `expected` against the stamp
    /// inside the encrypted overlay has no business parsing JSON or
    /// going anywhere near the confirm token (that 0600 file is
    /// consumed ONLY by `--confirm-volume-stamp`).
    ///
    /// Independent of the token: `expected_volume_stamp` is always
    /// present on the wire (`0` for a pre-gate KBS / fresh VM), so this
    /// flag never fails-closed the way `--volume-stamp-ctx-out` can —
    /// there is always a value to write. Written strictly AFTER the
    /// `--volume-stamp-ctx-out` gate (see step 7c/7d in `run`), so a
    /// fatal no-token error on that flag returns before this file is
    /// ever created — no stale/half-written expectation left behind
    /// for the shell to trust.
    #[arg(long)]
    volume_stamp_expected_out: Option<std::path::PathBuf>,

    /// `kbs-core::volume_stamp` — CONFIRM MODE. When set, this binary
    /// does NOT run the release exchange at all: it reads the ctx file
    /// a PRIOR `--volume-stamp-ctx-out` invocation wrote, and POSTs
    /// `POST /v1/kbs/volume-stamp/confirm` over the transport `--kbs-
    /// url` selects (same `vsock://`/`https://` dispatch the release
    /// exchange uses). The caller runs this only AFTER durably writing
    /// `target` into the encrypted overlay — presenting the token any
    /// earlier is exactly the "remote brick" the module docs on
    /// `kbs-core::volume_stamp` warn about. Mutually exclusive with
    /// every release-mode flag.
    #[arg(long, conflicts_with_all = [
        "ticket",
        "userdata_out",
        "lifecycle_key_out",
        "last_counter_file",
        "new_counter_file",
        "volume_stamp_ctx_out",
        "volume_stamp_expected_out",
    ])]
    confirm_volume_stamp: Option<std::path::PathBuf>,
}

/// The tmpfs subtree every SECRET-bearing `*_out` file must live under.
/// `/run` is tmpfs in the guest (initramfs-tools and dracut both mount
/// it before the keyscript runs, and `mount --move` carries it across
/// `switch_root`), so a file written there lives in guest-private RAM
/// and never reaches a block device the miner can read.
const SECRET_OUT_PREFIX: &str = "/run";

/// P9/#12 — refuse a SECRET-bearing `--*-out` path that is not under
/// [`SECRET_OUT_PREFIX`].
///
/// Applied to the three flags whose file content is key material or an
/// authenticator: `--lifecycle-key-out` (the §7 Ed25519 signing seed),
/// `--userdata-out` (the tenant cloud-init seed: SSH keys and whatever
/// else the tenant put there) and `--volume-stamp-ctx-out` (the
/// `kbs-core::volume_stamp` confirm token). Deliberately NOT applied to:
///
/// - `--last-counter-file` / `--new-counter-file`, which point at the
///   per-VM state disk (`/hippius-state/boot-counter`) BY DESIGN — the
///   anti-rollback counter has to survive a power cycle, and it is a
///   boot count, not a secret. Guarding these would brick every VM.
/// - `--volume-stamp-expected-out`, a mode-`0644` file holding one
///   decimal integer that the KBS also puts on the wire in the clear.
/// - `--confirm-volume-stamp`, an INPUT path. Constraining where we
///   READ from buys no confidentiality (the writer is already
///   constrained) and only adds a way to refuse a good boot.
///
/// Two independent legs, in order:
///
/// 1. **Lexical.** The path must be absolute, must contain no `..`
///    component anywhere, and must be strictly under `prefix`
///    component-wise. This is what catches `/hippius-state/lc.key`,
///    `/run/../hippius-state/lc.key` and `/runaway/lc.key` (a plain
///    `starts_with("/run")` string match would accept the last two).
/// 2. **Resolved.** Canonicalize the deepest ancestor of `path` that
///    resolves, and require it to sit under the canonicalized `prefix`.
///    This catches a symlinked directory component — e.g. a
///    `/run/hippius` symlink pointing at the mounted state disk. It is
///    anchored on the RESOLVED prefix, so a system where `/run` is
///    itself a symlink still passes.
///
/// The resolved leg is skipped entirely when `prefix` does not
/// canonicalize. That is the deliberate not-too-strict choice: this
/// runs in the boot path of every tenant VM, and refusing a
/// lexically-correct `/run/...` path merely because `/run` had not been
/// mounted yet would make the VM unbootable — a far worse outcome than
/// the residual risk it would cover.
///
/// §20: the returned message names the offending PATH (a measured,
/// non-secret cmdline value the operator needs in order to fix the
/// launch) and never the bytes that were about to be written to it.
fn check_secret_out_path(flag: &str, path: &std::path::Path) -> Result<(), String> {
    check_secret_out_path_under(flag, path, std::path::Path::new(SECRET_OUT_PREFIX))
}

/// [`check_secret_out_path`] with the prefix injected, so the two legs
/// are testable against a temp dir instead of the live `/run`.
fn check_secret_out_path_under(
    flag: &str,
    path: &std::path::Path,
    prefix: &std::path::Path,
) -> Result<(), String> {
    use std::path::Component;

    // ── leg 1: lexical ──────────────────────────────────────────────
    if !path.is_absolute() {
        return Err(format!(
            "{flag}: refusing a relative path (secrets are written to \
             {} tmpfs only): {}",
            prefix.display(),
            path.display()
        ));
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(format!(
            "{flag}: refusing a path containing a `..` component (it can \
             traverse out of {} into persistent storage): {}",
            prefix.display(),
            path.display()
        ));
    }
    match path.strip_prefix(prefix) {
        // `prefix` itself (or `prefix/`) is a directory, not a file we
        // could ever write — treat it as "not under the prefix".
        Ok(rest) if rest.as_os_str().is_empty() => {
            return Err(outside_prefix_msg(flag, path, prefix))
        }
        Ok(_) => {}
        Err(_) => return Err(outside_prefix_msg(flag, path, prefix)),
    }

    // ── leg 2: resolved (symlink-aware) ─────────────────────────────
    // No prefix on the live filesystem ⇒ nothing to resolve against;
    // leg 1 stands alone rather than bricking the boot.
    let Ok(prefix_real) = std::fs::canonicalize(prefix) else {
        return Ok(());
    };
    // The file itself does not exist yet on a fresh boot, so walk up to
    // the deepest ancestor that DOES resolve. `/` always resolves, so
    // this yields a value for any absolute path.
    let Some(anchor) = path.ancestors().find_map(|a| std::fs::canonicalize(a).ok()) else {
        return Ok(());
    };
    if !anchor.starts_with(&prefix_real) {
        return Err(format!(
            "{flag}: refusing a path that RESOLVES outside {} (a symlinked \
             directory component pointing at persistent storage): {} -> {}",
            prefix_real.display(),
            path.display(),
            anchor.display()
        ));
    }
    Ok(())
}

/// The single "not under the tmpfs prefix" refusal string, shared by the
/// two lexical rejections so they read identically in the serial log.
fn outside_prefix_msg(flag: &str, path: &std::path::Path, prefix: &std::path::Path) -> String {
    format!(
        "{flag}: refusing a path outside {}/ — this file holds key \
         material and must live on guest tmpfs, never on miner-backed \
         storage: {}",
        prefix.display(),
        path.display()
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // P9/#12 — enforce the tmpfs-only contract on every SECRET-bearing
    // `*_out` path BEFORE anything else, so a mis-pointed path never
    // even reaches the KBS: no release exchange runs, no key is
    // unwrapped, and there is nothing in memory to spill. Exits
    // `EXIT_USAGE` (a configuration bug, not a release failure), which
    // the keyscript surfaces via `hippius_die` — the disk stays locked.
    //
    // In confirm mode all three of these are `None` (clap's
    // `conflicts_with_all` on `--confirm-volume-stamp` forbids them),
    // so this loop is a no-op there.
    for (flag, path) in [
        ("--lifecycle-key-out", cli.lifecycle_key_out.as_deref()),
        ("--userdata-out", cli.userdata_out.as_deref()),
        (
            "--volume-stamp-ctx-out",
            cli.volume_stamp_ctx_out.as_deref(),
        ),
    ] {
        let Some(path) = path else { continue };
        if let Err(msg) = check_secret_out_path(flag, path) {
            eprintln!("hippius-guest-release: fail-closed: {msg}");
            return ExitCode::from(EXIT_USAGE);
        }
    }

    // `kbs-core::volume_stamp` confirm mode — entirely separate from
    // the release exchange below (see the flag's doc comment / the
    // module doc). `clap`'s `conflicts_with_all` already refuses this
    // flag alongside any release-mode flag, so reaching here means
    // ONLY `--kbs-url` + `--confirm-volume-stamp` were given.
    if let Some(ctx_path) = cli.confirm_volume_stamp.as_deref() {
        return match run_confirm(&cli.kbs_url, ctx_path) {
            Ok(()) => ExitCode::from(EXIT_OK),
            Err(e) => {
                log_fatal(&e);
                ExitCode::from(EXIT_RELEASE_FAILED)
            }
        };
    }

    if cli.ticket.is_none() {
        eprintln!(
            "hippius-guest-release: fail-closed: usage: --ticket is required in release mode \
             (pass --confirm-volume-stamp instead to run confirm mode)"
        );
        return ExitCode::from(EXIT_USAGE);
    }

    let kek = match run(&cli) {
        Ok(secrets) => secrets,
        Err(e) => {
            log_fatal(&e);
            return ExitCode::from(EXIT_RELEASE_FAILED);
        }
    };

    // §20: drop user-data into a tmpfs path BEFORE emitting the KEK
    // on stdout. If we wrote the KEK first and then crashed on the
    // user-data write, cryptsetup-initramfs would have already
    // unlocked the rootfs and `switch_root`'d into a system whose
    // cloud-init has no NoCloud seed — a silent boot failure with
    // no SSH access. Failing closed BEFORE the KEK ships keeps the
    // disk locked, which surfaces the error on the serial.
    if let Some(path) = cli.userdata_out.as_deref() {
        if let Err(cls) = write_secret_0600(path, kek.userdata.as_slice()) {
            eprintln!("hippius-guest-release: fail-closed: userdata-out:{cls}");
            return ExitCode::from(EXIT_RELEASE_FAILED);
        }
    }

    // §7: materialise the lifecycle SIGNING key to its tmpfs path BEFORE
    // shipping the KEK, same fail-closed ordering as the user-data write.
    // The key is OPTIONAL: a pre-§7 release carries none, in which case
    // we write NOTHING (no empty file) and the `eol` signer logs
    // `eol-no-key` and signs nothing — fail-closed, never a crash. A
    // requested-but-unwritable key path IS fatal: we keep the disk
    // locked (the KEK never ships) so the error surfaces on the serial.
    if let Some(path) = cli.lifecycle_key_out.as_deref() {
        match kek.lifecycle_key.as_ref() {
            Some(seed) => {
                if let Err(cls) = write_secret_0600(path, seed.as_slice()) {
                    eprintln!("hippius-guest-release: fail-closed: lifecycle-key-out:{cls}");
                    return ExitCode::from(EXIT_RELEASE_FAILED);
                }
            }
            // Flag set but the release carried no key (older VM): not an
            // error — log a static class and proceed unsigned-EOL.
            None => eprintln!("hippius-guest-release: lifecycle-key-out: no-key-in-release"),
        }
    }

    // §20: write the LUKS KEK BYTES verbatim to stdout. NO trailing
    // newline — `cryptsetup-initramfs`'s `keyscript` reads bytes
    // byte-exact; a newline would corrupt the passphrase.
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = handle.write_all(kek.luks.as_slice()) {
        // Best we can do — diagnostics already on stderr.
        eprintln!(
            "hippius-guest-release: fail-closed: stdout-write {}",
            e.kind()
        );
        return ExitCode::from(EXIT_RELEASE_FAILED);
    }
    if let Err(e) = handle.flush() {
        eprintln!(
            "hippius-guest-release: fail-closed: stdout-flush {}",
            e.kind()
        );
        return ExitCode::from(EXIT_RELEASE_FAILED);
    }
    // `kek.luks` + `kek.userdata` drop + `Zeroizing`-wipe here.
    ExitCode::from(EXIT_OK)
}

/// Write `bytes` to `path` as mode `0600`, creating the parent dir as
/// `0755` if missing. Returns a `&'static str` classifier on failure;
/// the caller emits a single `fail-closed: <kind>:<class>` line
/// without interpolating the path or io message (§20). Shared by the
/// `--userdata-out` and the §7 `--lifecycle-key-out` writes — both are
/// secret-bearing tmpfs files with identical 0600 / parent-0755
/// discipline.
fn write_secret_0600(path: &std::path::Path, bytes: &[u8]) -> Result<(), &'static str> {
    write_secret_0600_at_mode(path, bytes, 0o600)
}

/// Shared body behind [`write_secret_0600`] (and, with a `0o644` mode,
/// [`write_volume_stamp_expected`]): create the parent dir `0755` if
/// missing, open `path` at `mode`, write `bytes`, flush. Returns a
/// `&'static str` classifier on failure — never the path or io message
/// (§20).
fn write_secret_0600_at_mode(
    path: &std::path::Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), &'static str> {
    use std::io::ErrorKind::*;

    let class = |e: std::io::Error| -> &'static str {
        match e.kind() {
            NotFound => "not-found",
            PermissionDenied => "permission-denied",
            AlreadyExists => "already-exists",
            InvalidInput => "invalid-input",
            WriteZero => "write-zero",
            Interrupted => "interrupted",
            _ => "other",
        }
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(class)?;
        }
    }

    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .map_err(class)?
    };
    #[cfg(not(unix))]
    let mut f = {
        let _ = mode;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(class)?
    };

    f.write_all(bytes).map_err(class)?;
    f.flush().map_err(class)?;
    Ok(())
}

fn run(cli: &Cli) -> Result<UnwrappedSecrets, AgentError> {
    // 1. Load the COSE ticket from disk. `ticket::load` accepts either
    //    a `vsock://CID:PORT` URI (production) or an absolute file
    //    path (smoke / dev), exactly as the legacy agent does.
    //    `main` already refused to call `run` with no `--ticket`; the
    //    `ok_or` here is a defensive re-statement of that invariant,
    //    never actually taken.
    let ticket_path = cli
        .ticket
        .as_deref()
        .ok_or(AgentError::Ticket("missing"))?
        .to_string_lossy()
        .into_owned();
    let ticket = ticket_stage::load(&ticket_path)?;

    // 2. X25519 ephemeral keygen — `Zeroizing<[u8; 32]>` for the
    //    secret scalar, public bytes exposed for the SNP REPORT_DATA.
    let keys = keygen::generate_ephemeral()?;

    // 3. KBS transport, selected by the `--kbs-url` scheme:
    //    - `vsock://CID:PORT` → relay the two KBS POSTs over AF_VSOCK
    //      to the miner-agent (the guest needs NO network to reach the
    //      KBS — the robust permissionless path, see
    //      `kbs_vsock_client`);
    //    - `https://…` → direct `reqwest`/`rustls` blocking client
    //      (legacy network path), §20 strict 5 s connect / 30 s request.
    let http: Box<dyn HttpClient> = if is_vsock_url(&cli.kbs_url) {
        Box::new(VsockHttpClient::new())
    } else {
        Box::new(ReqwestHttpClient::new().map_err(|e| AgentError::Kbs(e.class()))?)
    };

    // 4. Fresh single-use KBS nonce.
    let nonce = kbs_client::fetch_nonce(http.as_ref(), &cli.kbs_url)?;

    // 5. SEV-SNP report — `/dev/sev-guest` ioctl with the §20
    //    REPORT_DATA layout (`nonce ‖ x25519_pub`).
    let provider = snp_provider();
    let report = snp_report::request(provider.as_ref(), &nonce.0, keys.public_bytes())?;
    let measurement = snp_report::measurement(&report)?;

    // 5b. Phase 2A of audit follow-up Codex #2 — read the previous
    // KBS-issued boot counter from `--last-counter-file` (if set) and
    // submit `prev + 1`. Missing or empty file → first boot, submit
    // `1`. Bad content (non-ASCII-decimal) is a guest bug — fail
    // closed before the release request.
    let submitted_boot_counter = match cli.last_counter_file.as_deref() {
        Some(path) => Some(read_last_counter(path).map_err(AgentError::Kbs)?),
        None => None,
    };
    // Phase 2A operator invariant: if you opt in to submitting a
    // counter (`--last-counter-file`) you MUST give us somewhere to
    // record what KBS committed (`--new-counter-file`); otherwise
    // the NEXT boot has no value to read.
    if submitted_boot_counter.is_some() && cli.new_counter_file.is_none() {
        eprintln!(
            "hippius-guest-release: fail-closed: counter-file-usage: \
             --last-counter-file requires --new-counter-file"
        );
        return Err(AgentError::Kbs("counter-file-usage"));
    }

    // 6. POST /v1/kbs/release.
    let signed = kbs_client::release(
        http.as_ref(),
        &cli.kbs_url,
        ticket.cose_bytes(),
        &nonce,
        &report,
        submitted_boot_counter,
    )?;

    // 7. §6/§7/§19/§20 binding gate + HPKE unwrap. `keys` is consumed
    //    by value — the X25519 secret scalar drops + wipes
    //    immediately after this returns.
    let secrets = verify::verify_and_unwrap(
        &signed,
        keys,
        &nonce,
        &ticket,
        &measurement,
        &PINNED_KBS_RESPONSE_VK,
        PINNED_KBS_RESPONSE_KID,
    )?;

    // 7b. Phase 2A — write the KBS-issued counter to
    // `--new-counter-file` BEFORE we ship the LUKS KEK to
    // cryptsetup, so a crash between unlock and persist still
    // surfaces on the serial (the persistence step ran first;
    // cryptroot retry will see the same on-disk value, and the
    // KBS-side CAS keeps semantics consistent).
    if let Some(path) = cli.new_counter_file.as_deref() {
        write_new_counter(path, secrets.boot_counter).map_err(AgentError::Kbs)?;
    }

    // 7c. `kbs-core::volume_stamp` — write the anti-rollback confirm
    // context BEFORE we ship the LUKS KEK, same fail-closed ordering
    // as 7b. A requested-but-absent token (a KBS that predates this
    // gate) is FATAL rather than a silent skip: the operator asked
    // for the gate, so getting none must surface as an error, not
    // quietly proceed unrolled-back-protected.
    if let Some(path) = cli.volume_stamp_ctx_out.as_deref() {
        let token = secrets.volume_stamp_token.as_ref().ok_or_else(|| {
            eprintln!(
                "hippius-guest-release: fail-closed: volume-stamp-ctx-out: \
                 no-token-in-release (KBS predates the volume-stamp gate)"
            );
            AgentError::Kbs("volume-stamp-no-token")
        })?;
        let target = secrets
            .expected_volume_stamp
            .checked_add(1)
            .ok_or(AgentError::Kbs("volume-stamp-overflow"))?;
        write_volume_stamp_ctx(
            path,
            &ticket.order().vm_id,
            secrets.expected_volume_stamp,
            target,
            token,
        )
        .map_err(AgentError::Kbs)?;
    }

    // 7d. `kbs-core::volume_stamp` — write the PLAIN decimal `expected`
    // value for the POSIX-sh initramfs gate, strictly AFTER 7c's
    // fatal-on-no-token check. `expected_volume_stamp` is always
    // present on the wire (defaults to `0`), so this never fails
    // closed the way 7c can — but ordering it after 7c means a fatal
    // 7c error returns before this file is ever created, so a
    // `--volume-stamp-ctx-out` no-token failure never leaves a stale
    // expectation file for the shell to (wrongly) trust.
    if let Some(path) = cli.volume_stamp_expected_out.as_deref() {
        write_volume_stamp_expected(path, secrets.expected_volume_stamp)
            .map_err(AgentError::Kbs)?;
    }

    Ok(secrets)
}

/// Phase 2A — read the previous KBS-issued counter from `path`.
/// Missing file or empty file ⇒ `0` (first boot; the caller then
/// submits `1`). Bad content (anything but ASCII decimal,
/// optionally followed by a single trailing newline) is a guest
/// bug — return a `&'static str` classifier without echoing the
/// content (§20). Returns `prev + 1` because the SUBMITTED counter
/// is always the value the guest expects KBS to advance TO.
fn read_last_counter(path: &std::path::Path) -> Result<u64, &'static str> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(_) => return Err("counter-read-io"),
    };
    let s = std::str::from_utf8(&bytes).map_err(|_| "counter-read-utf8")?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    if s.is_empty() {
        return Ok(1);
    }
    let prev: u64 = s.parse().map_err(|_| "counter-read-parse")?;
    prev.checked_add(1).ok_or("counter-overflow")
}

/// Phase 2A — write `value` as ASCII decimal + newline to `path`,
/// mode 0600 / parent dir 0755. Mirrors `write_userdata`'s
/// §20-conformant classifier-only diagnostic discipline.
fn write_new_counter(path: &std::path::Path, value: u64) -> Result<(), &'static str> {
    use std::io::ErrorKind::*;

    let class = |e: std::io::Error| -> &'static str {
        match e.kind() {
            NotFound => "not-found",
            PermissionDenied => "permission-denied",
            AlreadyExists => "already-exists",
            InvalidInput => "invalid-input",
            WriteZero => "write-zero",
            Interrupted => "interrupted",
            _ => "other",
        }
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(class)?;
        }
    }

    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(class)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(class)?;

    let line = format!("{value}\n");
    f.write_all(line.as_bytes()).map_err(class)?;
    f.flush().map_err(class)?;
    Ok(())
}

/// `kbs-core::volume_stamp` — write the confirm-context JSON a LATER,
/// separate `--confirm-volume-stamp` invocation reads:
/// `{"vm_id":"…","expected":N,"target":N,"token":"64 hex chars"}`.
/// Mode 0600 / parent dir 0755 — same discipline as
/// [`write_secret_0600`], reused directly. The token never appears
/// anywhere else (no log line, no stdout) — this file is the ONLY
/// place it is written in the clear, and it lives on tmpfs.
///
/// `vm_id` comes from the (unverified-by-us, KBS-bound) ticket, so it
/// is escaped as a JSON string rather than trusted to be quote-safe —
/// defence-in-depth, not a correctness requirement in practice.
fn write_volume_stamp_ctx(
    path: &std::path::Path,
    vm_id: &str,
    expected: u64,
    target: u64,
    token: &[u8; 32],
) -> Result<(), &'static str> {
    let json = format!(
        "{{\"vm_id\":{},\"expected\":{expected},\"target\":{target},\"token\":\"{}\"}}",
        json_escape_string(vm_id),
        encode_hex(token),
    );
    write_secret_0600(path, json.as_bytes())
}

/// `kbs-core::volume_stamp` — write ONLY the decimal `expected` value
/// (`{expected}\n`) for the POSIX-sh initramfs gate. Mode `0644` / parent
/// dir `0755` — NOT `0600`: this is not a secret, unlike every other
/// `*_out` file in this binary.
///
/// Unlike the other writers here, a failure ACTIVELY REMOVES whatever
/// landed on disk before propagating the error (best-effort
/// `remove_file`, errors ignored — there is nothing more to do if the
/// removal itself fails). The shell gate this file feeds treats "file
/// present" as an authoritative expectation, so a half-written or
/// stale file would be WORSE than none: the shell would compare
/// against garbage (or a value from a different, failed attempt)
/// instead of correctly treating "no file" as "nothing to fail on
/// yet" / falling through to whatever its own no-file policy is.
fn write_volume_stamp_expected(path: &std::path::Path, expected: u64) -> Result<(), &'static str> {
    let line = format!("{expected}\n");
    match write_secret_0600_at_mode(path, line.as_bytes(), 0o644) {
        Ok(()) => Ok(()),
        Err(cls) => {
            let _ = std::fs::remove_file(path);
            Err(cls)
        }
    }
}

/// Minimal JSON string-literal encoder: quotes + escapes `"`, `\`, and
/// C0 control characters. Not a general-purpose JSON encoder — just
/// enough to make [`write_volume_stamp_ctx`]'s single string field
/// safe regardless of what a hostile/malformed ticket puts in `vm_id`.
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Lowercase-hex-encode `bytes` without pulling in a crate for it —
/// mirrors the hand-rolled discipline of the rest of this file's I/O
/// helpers (`read_last_counter` / `write_new_counter`).
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The 3 fields [`run_confirm`] needs out of a
/// [`write_volume_stamp_ctx`]-written ctx file. `expected` is written
/// for operator/audit legibility but not read back — the confirm POST
/// only needs `vm_id`, `target`, and `token`.
struct VolumeStampCtx {
    vm_id: String,
    target: u64,
    token: [u8; 32],
}

/// Parse the FIXED-shape JSON [`write_volume_stamp_ctx`] wrote. This
/// is deliberately NOT a general JSON parser: this binary is the only
/// writer of the file, the schema never varies, and a tiny literal
/// scan means no recursive-descent surface to get wrong on a corrupted
/// or hostile ctx file. Any deviation from the exact expected shape
/// fails closed with a classifier; the token is decoded straight into
/// a fixed `[u8; 32]` and never echoed in an error.
fn read_volume_stamp_ctx(path: &std::path::Path) -> Result<VolumeStampCtx, &'static str> {
    let bytes = std::fs::read(path).map_err(|_| "ctx-read")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "ctx-utf8")?;

    let vm_id = extract_json_string(text, "\"vm_id\":\"").ok_or("ctx-vm-id")?;
    let target = extract_json_number(text, "\"target\":").ok_or("ctx-target")?;
    let token_hex = extract_json_string(text, "\"token\":\"").ok_or("ctx-token")?;
    let token = decode_hex_32(&token_hex).ok_or("ctx-token-hex")?;

    Ok(VolumeStampCtx {
        vm_id,
        target,
        token,
    })
}

/// Find `key_prefix` (e.g. `"vm_id":"`) and return the bytes up to the
/// next unescaped `"`. Refuses (returns `None`) if the value contains
/// a backslash — [`write_volume_stamp_ctx`] never emits an escape
/// sequence for a well-formed vm_id (it comes straight from the
/// ticket, no quote/control chars in practice), so a `\` here means
/// either a hand-edited/corrupted file or a real escape sequence that
/// this deliberately-non-general parser will not attempt to decode.
/// Fail closed rather than unescape.
fn extract_json_string(text: &str, key_prefix: &str) -> Option<String> {
    let start = text.find(key_prefix)? + key_prefix.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    let value = &rest[..end];
    if value.contains('\\') {
        return None;
    }
    Some(value.to_string())
}

/// Find `key_prefix` (e.g. `"target":`) and parse the following run of
/// ASCII digits as `u64`.
fn extract_json_number(text: &str, key_prefix: &str) -> Option<u64> {
    let start = text.find(key_prefix)? + key_prefix.len();
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

/// Decode exactly 64 lowercase-or-uppercase hex chars into `[u8; 32]`.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `kbs-core::volume_stamp` CONFIRM MODE — reads the ctx file a prior
/// release-mode invocation wrote and POSTs the confirmation over the
/// SAME transport selection [`run`] uses (`vsock://` → the miner-agent
/// relay, `https://` → direct `reqwest`). Deliberately does NOT touch
/// the ticket, attestation, or any release-mode flag: the confirm
/// endpoint is a bare `{vm_id, value, token}` POST (see
/// `kbs-transport::wire::VolumeStampConfirmBody` / the module docs on
/// `kbs-core::volume_stamp` for why no attestation is needed here —
/// the token itself is the authenticator).
fn run_confirm(kbs_url: &str, ctx_path: &std::path::Path) -> Result<(), AgentError> {
    let ctx = read_volume_stamp_ctx(ctx_path).map_err(AgentError::Kbs)?;

    // Same transport dispatch as `run` step 3 — reusing the exact
    // `HttpClient` abstraction rather than a second client.
    let http: Box<dyn HttpClient> = if is_vsock_url(kbs_url) {
        Box::new(VsockHttpClient::new())
    } else {
        Box::new(ReqwestHttpClient::new().map_err(|e| AgentError::Kbs(e.class()))?)
    };

    let body =
        encode_confirm_request(&ctx.vm_id, ctx.target, &ctx.token).map_err(AgentError::Kbs)?;
    let url = format!(
        "{}/v1/kbs/volume-stamp/confirm",
        kbs_url.trim_end_matches('/')
    );
    let response = http.post_cbor(&url, &body)?;
    if !(200..300).contains(&response.status) {
        return Err(AgentError::Kbs("confirm-http-status"));
    }
    decode_confirm_response(&response.body).map_err(AgentError::Kbs)
}

/// Encode the `POST /v1/kbs/volume-stamp/confirm` request body —
/// same deterministic-CBOR discipline as every other KBS wire body.
/// Mirrors `kbs-transport::wire::VolumeStampConfirmBody { vm_id,
/// value, token }` field-for-field WITHOUT depending on the
/// `kbs-transport` crate itself, which pulls in `axum`/`tokio` — deps
/// this musl-static initramfs binary must never link.
fn encode_confirm_request(
    vm_id: &str,
    target: u64,
    token: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    let value = Value::Map(vec![
        (Value::Text("vm_id".into()), Value::Text(vm_id.to_string())),
        (Value::Text("value".into()), Value::Integer(target.into())),
        (Value::Text("token".into()), Value::Bytes(token.to_vec())),
    ]);
    to_canonical_vec(&value).map_err(|_| "confirm-request-encode")
}

/// Decode a `VolumeStampConfirmResponse { confirmed: u64 }` body. Only
/// the shape is checked — `confirmed` itself is not otherwise
/// consumed, the caller only needs to know the confirm succeeded.
fn decode_confirm_response(body: &[u8]) -> Result<(), &'static str> {
    assert_canonical(body).map_err(|_| "confirm-response-non-canonical")?;
    let value: Value = ciborium::de::from_reader(body).map_err(|_| "confirm-response-decode")?;
    let Value::Map(entries) = value else {
        return Err("confirm-response-decode");
    };
    let has_confirmed = entries.iter().any(|(k, v)| {
        matches!(k, Value::Text(t) if t == "confirmed") && matches!(v, Value::Integer(_))
    });
    if has_confirmed {
        Ok(())
    } else {
        Err("confirm-response-decode")
    }
}

/// Construct the `SnpReportProvider` for this build target. Real
/// `/dev/sev-guest` on Linux/x86_64; a mock on every other target so
/// `cargo check` on a dev box still passes (the mock never produces
/// a valid signed report, so the KBS will deny it — exactly what we
/// want on a non-CVM host).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn snp_provider() -> Box<dyn hippius_agent_initramfs::SnpReportProvider> {
    Box::new(hippius_agent_initramfs::SevGuestProvider::new())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn snp_provider() -> Box<dyn hippius_agent_initramfs::SnpReportProvider> {
    use hippius_agent_initramfs::{MockSnpReportProvider, SNP_REPORT_LEN};
    Box::new(MockSnpReportProvider::new(vec![0u8; SNP_REPORT_LEN]))
}

/// Emit a single static diagnostic to stderr. §20: no secret bytes,
/// no plaintext from the inner classifier — only the closed-vocab
/// `class()` family + `sub_class()` tag, both `&'static str`.
fn log_fatal(err: &AgentError) {
    match err.sub_class() {
        Some(sub) => eprintln!(
            "hippius-guest-release: fail-closed: {}:{}",
            err.class(),
            sub
        ),
        None => eprintln!("hippius-guest-release: fail-closed: {}", err.class()),
    }
}

/// P9/#12 — the tmpfs-only gate on the secret-bearing `*_out` paths.
///
/// The load-bearing pair is `refuses_the_state_disk_path` (the exposure)
/// and `accepts_the_live_production_path` (a guard that breaks the live
/// boot is worse than the hole it closes). The rest pin the exact
/// bypasses a naive `starts_with("/run")` string match would let through.
#[cfg(test)]
mod secret_out_path_tests {
    use super::*;
    use std::path::Path;

    const FLAG: &str = "--lifecycle-key-out";

    /// A fresh, unique directory under the OS temp dir.
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "hippius-guest-release-out-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // ── the live production path MUST boot ───────────────────────────

    #[test]
    fn accepts_the_live_production_path() {
        // Exactly what vali stamps into the measured cmdline today
        // (`_LIFECYCLE_KEY_TMPFS_PATH` in vali/apps/orchestration/
        // services/launch.py) and the keyscript forwards.
        assert_eq!(
            check_secret_out_path(FLAG, Path::new("/run/hippius/lifecycle.key")),
            Ok(())
        );
    }

    #[test]
    fn accepts_the_other_two_live_production_paths() {
        // The hardcoded `--userdata-out` and the golden overlay's
        // default `--volume-stamp-ctx-out`.
        assert_eq!(
            check_secret_out_path(
                "--userdata-out",
                Path::new("/run/cloud-init/seed/user-data")
            ),
            Ok(())
        );
        assert_eq!(
            check_secret_out_path(
                "--volume-stamp-ctx-out",
                Path::new("/run/hippius/volume-stamp.ctx")
            ),
            Ok(())
        );
    }

    #[test]
    fn accepts_a_run_path_whose_parents_do_not_exist_yet() {
        // On a fresh boot the keyscript's `mkdir -p` may not have run
        // (or the caller relies on `write_secret_0600`'s create_dir_all).
        // A deep, entirely absent /run subtree must still be accepted —
        // refusing it would brick the boot.
        assert_eq!(
            check_secret_out_path(
                FLAG,
                Path::new("/run/hippius/does/not/exist/yet/lifecycle.key")
            ),
            Ok(())
        );
    }

    // ── the exposure ─────────────────────────────────────────────────

    #[test]
    fn refuses_the_state_disk_path() {
        // /hippius-state is the miner-provisioned PLAINTEXT ext4 state
        // disk (/dev/vdd), mounted in the initramfs BEFORE the release.
        // A cmdline pointed here would hand the miner the §7 signing key.
        let err = check_secret_out_path(FLAG, Path::new("/hippius-state/lifecycle.key"))
            .expect_err("a persistent path must be refused");
        assert!(err.contains("/hippius-state/lifecycle.key"), "{err}");
        assert!(err.contains("--lifecycle-key-out"), "{err}");
    }

    #[test]
    fn refuses_an_ordinary_persistent_path() {
        assert!(check_secret_out_path(FLAG, Path::new("/var/lib/hippius/lifecycle.key")).is_err());
        assert!(check_secret_out_path(FLAG, Path::new("/etc/lifecycle.key")).is_err());
    }

    #[test]
    fn refusal_names_the_offending_path_not_the_key() {
        // §20: the operator needs the PATH to fix the launch; the bytes
        // that were about to be written must never appear.
        let err = check_secret_out_path(FLAG, Path::new("/hippius-state/k"))
            .expect_err("must be refused");
        assert!(err.contains("/hippius-state/k"), "{err}");
    }

    // ── what a naive prefix string match would miss ──────────────────

    #[test]
    fn refuses_a_parent_dir_traversal_out_of_run() {
        // `"/run/../hippius-state/k".starts_with("/run")` is TRUE as a
        // string. Component-wise it is not, and the `..` is refused
        // outright.
        let err = check_secret_out_path(FLAG, Path::new("/run/../hippius-state/k"))
            .expect_err("`..` traversal must be refused");
        assert!(err.contains(".."), "{err}");
        assert!(err.contains("/run/../hippius-state/k"), "{err}");
    }

    #[test]
    fn refuses_a_parent_dir_component_even_when_it_lands_back_inside_run() {
        // `/run/hippius/../lifecycle.key` resolves inside /run, but the
        // refusal is unconditional: allowing `..` at all would mean the
        // gate depends on resolution order, and no honest caller emits
        // one.
        assert!(check_secret_out_path(FLAG, Path::new("/run/hippius/../lifecycle.key")).is_err());
    }

    #[test]
    fn refuses_a_sibling_directory_sharing_the_run_prefix_string() {
        // `"/runaway/k".starts_with("/run")` is TRUE as a string.
        let err = check_secret_out_path(FLAG, Path::new("/runaway/k"))
            .expect_err("a `/run`-prefixed SIBLING dir must be refused");
        assert!(err.contains("/runaway/k"), "{err}");
    }

    #[test]
    fn refuses_a_relative_path() {
        let err = check_secret_out_path(FLAG, Path::new("run/hippius/lifecycle.key"))
            .expect_err("a relative path must be refused");
        assert!(err.contains("run/hippius/lifecycle.key"), "{err}");
        // The REFUSAL is redundant with the `strip_prefix` leg (a
        // relative path can never strip an absolute prefix); what the
        // explicit `is_absolute` check buys is an accurate diagnostic,
        // so that is what is pinned. Without it the operator is told
        // the path is "outside /run/", which is true but unhelpful when
        // the actual bug is a missing leading slash in the cmdline.
        assert!(
            err.contains("relative path"),
            "a relative path must be diagnosed AS relative; got: {err}"
        );
    }

    #[test]
    fn refuses_the_prefix_directory_itself() {
        assert!(check_secret_out_path(FLAG, Path::new("/run")).is_err());
        assert!(check_secret_out_path(FLAG, Path::new("/run/")).is_err());
    }

    // ── the resolved (symlink) leg, against a real temp prefix ───────

    #[test]
    fn accepts_a_plain_path_under_an_injected_prefix() {
        let prefix = tmp_dir("plain");
        assert_eq!(
            check_secret_out_path_under(FLAG, &prefix.join("sub/key"), &prefix),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_directory_component_pointing_outside() {
        // The exact shape the concern names: `<prefix>/hippius` is a
        // symlink into "persistent storage". Lexically the path is
        // under the prefix; only resolution catches it.
        let prefix = tmp_dir("symlink-dir");
        let persistent = tmp_dir("symlink-dir-target");
        std::os::unix::fs::symlink(&persistent, prefix.join("hippius")).unwrap();

        let path = prefix.join("hippius/lifecycle.key");
        let err = check_secret_out_path_under(FLAG, &path, &prefix)
            .expect_err("a symlinked component escaping the prefix must be refused");
        assert!(err.contains("RESOLVES outside"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn accepts_a_symlinked_directory_component_that_stays_inside() {
        // A symlink is not itself disqualifying — only escaping is.
        let prefix = tmp_dir("symlink-inside");
        std::fs::create_dir_all(prefix.join("real")).unwrap();
        std::os::unix::fs::symlink(prefix.join("real"), prefix.join("alias")).unwrap();
        assert_eq!(
            check_secret_out_path_under(FLAG, &prefix.join("alias/lifecycle.key"), &prefix),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_an_existing_file_that_is_itself_a_symlink_outside() {
        // The FINAL component is the symlink (a pre-planted key file).
        let prefix = tmp_dir("symlink-file");
        let persistent = tmp_dir("symlink-file-target");
        let target = persistent.join("stolen.key");
        std::fs::write(&target, b"x").unwrap();
        let path = prefix.join("lifecycle.key");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(check_secret_out_path_under(FLAG, &path, &prefix).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_a_prefix_that_is_itself_a_symlink() {
        // Some systems ship `/run` as a symlink. The resolved leg is
        // anchored on the CANONICALIZED prefix, so this must still boot.
        let real = tmp_dir("aliased-prefix-real");
        let parent = tmp_dir("aliased-prefix-parent");
        let alias = parent.join("run");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        std::fs::create_dir_all(real.join("hippius")).unwrap();

        assert_eq!(
            check_secret_out_path_under(FLAG, &alias.join("hippius/lifecycle.key"), &alias),
            Ok(())
        );
    }

    #[test]
    fn skips_the_resolved_leg_when_the_prefix_does_not_exist() {
        // Not-too-strict: a lexically-correct path under a prefix that
        // is not mounted yet is ACCEPTED rather than bricking the boot.
        let missing = tmp_dir("absent").join("never-created");
        assert_eq!(
            check_secret_out_path_under(FLAG, &missing.join("lifecycle.key"), &missing),
            Ok(())
        );
    }

    // ── flags deliberately NOT guarded ───────────────────────────────

    #[test]
    fn the_persistent_counter_paths_are_not_run_paths() {
        // Documents the carve-out: `--last/--new-counter-file` point at
        // the state disk BY DESIGN. If someone ever adds them to the
        // guarded list in `main`, this is the reminder that it would
        // refuse every production boot.
        let counter = Path::new("/hippius-state/boot-counter");
        assert!(
            check_secret_out_path("--new-counter-file", counter).is_err(),
            "the counter path is NOT a /run path — it must stay unguarded"
        );
    }
}

#[cfg(test)]
mod volume_stamp_ctx_tests {
    use super::*;

    /// A fresh path under the OS temp dir, unique per test process +
    /// call, so parallel `cargo test` runs never collide.
    fn tmp_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hippius-guest-release-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    #[test]
    fn volume_stamp_ctx_round_trips_through_disk() {
        let path = tmp_path("roundtrip");
        let token = [0xABu8; 32];
        write_volume_stamp_ctx(&path, "vm-abc", 4, 5, &token).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "ctx file must be mode 0600");
        }

        let ctx = read_volume_stamp_ctx(&path).unwrap();
        assert_eq!(ctx.vm_id, "vm-abc");
        assert_eq!(ctx.target, 5);
        assert_eq!(ctx.token, token);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn volume_stamp_expected_writes_plain_decimal_at_0644() {
        let path = tmp_path("expected");
        write_volume_stamp_expected(&path, 37).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "37\n", "no JSON, no token — just the decimal");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "expected file must be mode 0644, not 0600");
        }

        let _ = std::fs::remove_file(&path);
    }

    /// The exact scenario the caller flagged: a STALE `expected` file
    /// (from some earlier, unrelated write) sits at `path`; THIS
    /// write attempt fails (here: the file is made read-only so the
    /// re-open fails with permission-denied). The helper must remove
    /// the stale file rather than leave it for the shell to wrongly
    /// treat as the current, authoritative expectation.
    #[cfg(unix)]
    #[test]
    fn volume_stamp_expected_removes_a_stale_file_on_failure() {
        use std::os::unix::fs::PermissionsExt;

        let path = tmp_path("expected-stale");
        std::fs::write(&path, b"999\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        assert!(write_volume_stamp_expected(&path, 7).is_err());
        assert!(
            !path.exists(),
            "a failed write must not leave the stale file behind"
        );
    }

    #[test]
    fn read_volume_stamp_ctx_rejects_a_missing_file() {
        let path = tmp_path("missing");
        assert!(matches!(read_volume_stamp_ctx(&path), Err("ctx-read")));
    }

    #[test]
    fn read_volume_stamp_ctx_rejects_a_short_token() {
        let path = tmp_path("short-token");
        std::fs::write(
            &path,
            br#"{"vm_id":"vm-abc","expected":4,"target":5,"token":"ab"}"#,
        )
        .unwrap();
        assert!(matches!(read_volume_stamp_ctx(&path), Err("ctx-token-hex")));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_escape_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_escape_string("plain"), "\"plain\"");
        assert_eq!(json_escape_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_escape_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(json_escape_string("a\nb"), "\"a\\u000ab\"");
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x01, 0xAB, 0xFF];
        assert_eq!(encode_hex(&bytes), "0001abff");
    }

    #[test]
    fn decode_hex_32_rejects_wrong_length() {
        assert!(decode_hex_32("ab").is_none());
        assert!(decode_hex_32(&"ab".repeat(31)).is_none());
        assert!(decode_hex_32(&"ab".repeat(33)).is_none());
    }

    #[test]
    fn decode_hex_32_rejects_non_hex_chars() {
        assert!(decode_hex_32(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn decode_hex_32_round_trips_with_encode_hex() {
        let bytes = [0x5Au8; 32];
        let hex = encode_hex(&bytes);
        assert_eq!(decode_hex_32(&hex).unwrap(), bytes);
    }

    #[test]
    fn encode_confirm_request_is_canonical_and_carries_the_three_fields() {
        let token = [0x11u8; 32];
        let body = encode_confirm_request("vm-abc", 5, &token).unwrap();
        assert_canonical(&body).expect("confirm request body must be canonical CBOR");
        let value: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(entries) = value else {
            panic!("confirm request body is not a map");
        };
        assert_eq!(entries.len(), 3);
        let vm_id = entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Text(s)) if t == "vm_id" => Some(s.clone()),
            _ => None,
        });
        assert_eq!(vm_id.as_deref(), Some("vm-abc"));
        let value_field = entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Integer(i)) if t == "value" => {
                let n: u64 = (*i).try_into().ok()?;
                Some(n)
            }
            _ => None,
        });
        assert_eq!(value_field, Some(5));
        let token_field = entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bytes(b)) if t == "token" => Some(b.clone()),
            _ => None,
        });
        assert_eq!(token_field.as_deref(), Some(&token[..]));
    }

    #[test]
    fn decode_confirm_response_accepts_a_well_formed_body() {
        let value = Value::Map(vec![(
            Value::Text("confirmed".into()),
            Value::Integer(5.into()),
        )]);
        let body = to_canonical_vec(&value).unwrap();
        assert_eq!(decode_confirm_response(&body), Ok(()));
    }

    #[test]
    fn decode_confirm_response_rejects_a_missing_confirmed_field() {
        let value = Value::Map(vec![(
            Value::Text("other".into()),
            Value::Integer(5.into()),
        )]);
        let body = to_canonical_vec(&value).unwrap();
        assert_eq!(
            decode_confirm_response(&body),
            Err("confirm-response-decode")
        );
    }
}
