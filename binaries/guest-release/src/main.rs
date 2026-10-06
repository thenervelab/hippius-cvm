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
//!   **Stamp protocol v2** (a timeline-bound volume stamp, M0/M1): the
//!   release attests v2 in its SNP `REPORT_DATA`
//!   (`hippius_types::report_data::tenant_stamp_v2`) and accepts ONLY a
//!   `HIPPIUS_KBS_RELEASE_V2` response carrying a
//!   `volume_stamp_transition {expected, target}`, which
//!   `--volume-stamp-transition-out` hands to the shell gate
//!   (`<expected hex> <target hex>\n`) and the ctx file carries as
//!   `"timeline"` for the confirm. A KBS that predates v2 refuses a v2
//!   report outright (403), and that 403 is FINAL: a v2-capable M0/M1
//!   guest NEVER retries attesting v1. Every KBS refusal is the same
//!   generic 403, so a miner could forge one; a v1 retry would then let
//!   it get a v1 adopt of an old zero-timeline disk after a KBS store
//!   wipe and keep the VM on the zero timeline past its first confirm
//!   (reopening every abandoned zero-timeline disk). A denial is a
//!   denial: the boot fails (a denial of service the miner can always
//!   cause anyway), nothing is written for the gate. The KBS is rolled
//!   to v2 BEFORE any v2 guest is baked and must never go below it. M2
//!   (`customer`) attests v1 only, exactly as before — its stamp is the
//!   guardian's, the KBS has none to bind to a timeline.
//!
//!   **`--integrity-wipe DEVICE`** is a third DISTINCT mode, with no KBS
//!   traffic at all: it zeroes a freshly `luksFormat --integrity-no-wipe`'d
//!   mapping with parallel `O_DIRECT` writers so every sector carries a
//!   valid dm-integrity tag before the filesystem is laid down. It lives
//!   here because this binary is already static and already staged in
//!   both initramfs families. See [`wipe`].
//!
//! **Customer-held disk keys (M1 `split` / M2 `customer`).** The
//! release mode reads the MEASURED cmdline (`/proc/cmdline`) with
//! [`GuardianBinding::from_cmdline`]; a grammar error fails closed.
//! No binding (M0, `hippius`) ⇒ exactly the exchange above, nothing
//! else. With a binding:
//!
//! 1. the ticket's signed `key_mode` must equal the measured mode;
//! 2. the **guardian leg** runs FIRST ([`guardian_leg`]) — before any
//!    KBS contact, waiting indefinitely inside this boot for a verified
//!    `share_C` (never a reboot, never a KBS call while waiting). The
//!    one terminal answer, a signed `erased`, halts the guest in place;
//! 3. the KBS leg runs unchanged, except that M1 requires the KBS KEK
//!    (`share_H`) and M2 refuses one;
//! 4. `combine_kek(mode, share_H, share_C, vm_id)` is what reaches
//!    stdout — 32 bytes, as before. Both shares and the result are
//!    `Zeroizing`;
//! 5. `--share-c-version-out` records the share version the guardian
//!    sealed (the shell stores it in the volume's LUKS2 token), and in
//!    M2 the volume stamp comes from the guardian: the ctx file names
//!    the guardian as the confirm target, so `--confirm-volume-stamp`
//!    confirms there instead of at the KBS;
//! 6. `--instance-id-out` records the VM's stable cloud-init
//!    instance-id (derived from the same `vm_id`); the golden overlay
//!    hands the released user-data to cloud-init on the volume's first
//!    boot only (H5b).
//!
//! In every mode, a `/proc/cmdline` long enough that the kernel or the
//! EFI stub may have cut a key-mode token off, and that carries none,
//! is refused before any contact (see [`cmdline_may_hide_key_mode`]).
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
    guardian_relay_url, is_vsock_url, AgentError, GuardianVsockClient, HttpClient,
    ReqwestHttpClient, SnpReportProvider, VsockHttpClient, PINNED_KBS_RESPONSE_KID,
    PINNED_KBS_RESPONSE_VK,
};
use hippius_guest::{AttestedStampProtocol, GuardianRelease};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::guardian::{
    combine_kek, encode_canonical, GuardianBinding, GuardianStampConfirm, KeyMode,
    GUARDIAN_STAMP_CONFIRM_PATH, GUARDIAN_WIRE_V, KEY_LEN, MAX_CMDLINE_LEN, OVMF_INITRD_PREFIX,
};
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;
use zeroize::Zeroizing;

mod guardian_leg;
#[cfg(test)]
mod keyed_tests;
mod wipe;

/// Exit codes the keyscript caller distinguishes.
const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
/// Generic release-exchange failure (transport, decode, sig, binding).
/// Maps every closed-vocabulary `AgentError::class()` to this exit
/// code; the operator distinguishes on stderr classification tags.
const EXIT_RELEASE_FAILED: u8 = 3;
/// `--integrity-wipe` failed: the device is NOT fully initialised and
/// must not get a filesystem.
const EXIT_WIPE_FAILED: u8 = 4;

#[derive(Parser, Debug)]
#[command(
    name = "hippius-guest-release",
    version,
    about = "Run the SEV-SNP / KBS release exchange and emit the LUKS KEK on stdout."
)]
struct Cli {
    /// HTTPS base URL for the KBS, e.g.
    /// `https://kbs.hippius.network`. The release POST hits
    /// `${KBS_URL}/v1/kbs/release`. Required in every mode except
    /// `--integrity-wipe`, which talks to no KBS.
    #[arg(long, required_unless_present = "integrity_wipe")]
    kbs_url: Option<String>,

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

    /// Phase 2A of audit follow-up Review #2 — anti-rollback for
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

    /// Stamp protocol v2 — companion to `--volume-stamp-expected-out`:
    /// when the release attested v2 and the KBS answered with a
    /// `volume_stamp_transition`, write `<expected hex> <target hex>\n`
    /// (two 64-char lowercase hex timeline ids), mode `0644`, nothing
    /// secret. The shell gate then accepts the volume only on the
    /// `expected` timeline and stamps the `target` one. When the release
    /// carried NO transition (a v1 release — M2 only; M0/M1 never get
    /// one) the file is REMOVED, never left stale: its absence is what
    /// tells the gate to run the v1 comparison (M2) or to refuse (M0/M1). Written BEFORE `--volume-stamp-expected-out`, so the
    /// expectation file (which the gate treats as authoritative) never
    /// exists without its transition. A release that carried a transition
    /// while `--volume-stamp-expected-out` is set but this flag is not is
    /// REFUSED (the gate would read the expectation as a v1 one).
    #[arg(long)]
    volume_stamp_transition_out: Option<std::path::PathBuf>,

    /// Customer-held keys (M1/M2 only) — the `share_C` version recorded
    /// in the overlay upper's LUKS2 `hippius-keymode` token. Absent on
    /// first boot (blank volume). Folded into the guardian report and
    /// request; the guardian must seal exactly this version. Refused on
    /// an M0 (`hippius`) cmdline.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    share_c_version: Option<u32>,

    /// Customer-held keys (M1/M2: REQUIRED there, refused in M0) —
    /// where to write the `share_C` version the guardian sealed, as
    /// ASCII decimal + newline, mode `0644` (not a secret). Written
    /// after every other `*_out` file and BEFORE the KEK ships; the
    /// golden overlay records it in the volume's LUKS2 token on first
    /// boot.
    #[arg(long)]
    share_c_version_out: Option<std::path::PathBuf>,

    /// Customer-held keys (M1/M2: REQUIRED there, refused in M0) —
    /// where to write this VM's STABLE cloud-init instance-id
    /// ([`cloud_init_instance_id`] of the ticket's `vm_id`, the same
    /// `vm_id` the keyslot key is combined under), as `iid-<32 hex>` +
    /// newline, mode `0644` (not a secret). The golden overlay puts it
    /// in the NoCloud `meta-data` on every boot, so cloud-init sees ONE
    /// instance for the volume's lifetime and its per-instance modules
    /// run once — the KBS-released user-data is handed to cloud-init on
    /// the volume's first boot only (M0 keeps a random instance-id per
    /// boot and the user-data every boot).
    #[arg(long)]
    instance_id_out: Option<std::path::PathBuf>,

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
    ///
    /// The ctx file names the confirm target: the KBS (M0/M1, no
    /// target field — byte-identical to before) or, in M2, the
    /// customer's guardian via the guardian relay (`"to":"guardian"`).
    /// The guardian's answer is an unsigned ack and is only logged.
    #[arg(long, conflicts_with_all = [
        "ticket",
        "userdata_out",
        "lifecycle_key_out",
        "last_counter_file",
        "new_counter_file",
        "volume_stamp_ctx_out",
        "volume_stamp_expected_out",
        "volume_stamp_transition_out",
        "share_c_version",
        "share_c_version_out",
        "instance_id_out",
    ])]
    confirm_volume_stamp: Option<std::path::PathBuf>,

    /// INTEGRITY-WIPE MODE. Zero every sector of DEVICE (a block device
    /// directly under `/dev/mapper/`, opened `O_DIRECT|O_EXCL`) with
    /// parallel writers, then `fdatasync`. For a LUKS2 + dm-integrity
    /// volume formatted with `--integrity-no-wipe` and activated with
    /// `--integrity-no-journal`: afterwards every sector carries a valid
    /// tag, exactly as after cryptsetup's own (serial) wipe. Exit
    /// `EXIT_WIPE_FAILED` on any error. No KBS traffic; mutually
    /// exclusive with every other flag.
    #[arg(long, conflicts_with_all = [
        "kbs_url",
        "ticket",
        "userdata_out",
        "lifecycle_key_out",
        "last_counter_file",
        "new_counter_file",
        "volume_stamp_ctx_out",
        "volume_stamp_expected_out",
        "volume_stamp_transition_out",
        "confirm_volume_stamp",
        "share_c_version",
        "share_c_version_out",
        "instance_id_out",
    ])]
    integrity_wipe: Option<std::path::PathBuf>,
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

    // Integrity-wipe mode: no KBS, no secrets — clap has already refused
    // it alongside any other flag.
    if let Some(device) = cli.integrity_wipe.as_deref() {
        return match wipe::run(device) {
            Ok(size) => {
                eprintln!(
                    "hippius-guest-release: integrity-wipe {}: done, {} MiB",
                    device.display(),
                    size >> 20
                );
                ExitCode::from(EXIT_OK)
            }
            Err(e) => {
                eprintln!(
                    "hippius-guest-release: fail-closed: integrity-wipe {}: {e}",
                    device.display()
                );
                ExitCode::from(EXIT_WIPE_FAILED)
            }
        };
    }
    // `required_unless_present` guarantees this outside wipe mode.
    let Some(kbs_url) = cli.kbs_url.as_deref() else {
        eprintln!("hippius-guest-release: fail-closed: usage: --kbs-url is required");
        return ExitCode::from(EXIT_USAGE);
    };

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
        return match run_confirm(kbs_url, ctx_path) {
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

    let kek = match run(&cli, kbs_url) {
        Ok(released) => released,
        // Customer-held keys: the guardian signed `erased`. Terminal —
        // no retry can clear it — but exiting would hand the boot to a
        // failure path that may power the guest off (dracut) or panic
        // it (initramfs-tools), and a relaunch loop would re-ask the
        // guardian forever. Halt in place instead: the disk stays
        // locked, the KBS is never contacted, the console says why.
        Err(AgentError::Guardian(guardian_leg::ERASED)) => halt_erased(),
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
    if let Err(e) = handle.write_all(kek.kek.as_slice()) {
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
    // `kek.kek` + `kek.userdata` drop + `Zeroizing`-wipe here.
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

/// What a successful release hands to `main`: the keyslot key for
/// stdout and the two secrets that must land on tmpfs BEFORE it ships.
struct Released {
    /// M0: the KBS KEK, byte-for-byte as released. M1/M2: the 32-byte
    /// [`combine_kek`] output.
    kek: Zeroizing<Vec<u8>>,
    userdata: Zeroizing<Vec<u8>>,
    lifecycle_key: Option<Zeroizing<Vec<u8>>>,
}

/// Everything [`run_with`] talks to, injectable so the whole exchange —
/// guardian leg, KBS leg, combine — runs in tests against fakes.
struct Deps<'a> {
    kbs: &'a dyn HttpClient,
    guardian: &'a dyn HttpClient,
    guardian_url: &'a str,
    snp: &'a dyn SnpReportProvider,
    kbs_vk: &'a [u8; 32],
    kbs_kid: &'a [u8],
    env: &'a mut dyn guardian_leg::LegEnv,
}

fn run(cli: &Cli, kbs_url: &str) -> Result<Released, AgentError> {
    // Customer-held keys: the MEASURED cmdline selects the key mode.
    // `/proc/cmdline` is what the kernel was launched with — the string
    // SEV measured (plus the one `\n` the kernel appends, which the
    // parser strips). Unreadable ⇒ the mode is unknown ⇒ fail closed.
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|_| AgentError::Guardian("cmdline-read"))?;

    // KBS transport, selected by the `--kbs-url` scheme:
    //    - `vsock://CID:PORT` → relay the two KBS POSTs over AF_VSOCK
    //      to the miner-agent (the guest needs NO network to reach the
    //      KBS — the robust permissionless path, see
    //      `kbs_vsock_client`);
    //    - `https://…` → direct `reqwest`/`rustls` blocking client
    //      (legacy network path), §20 strict 5 s connect / 30 s request.
    // Constructing either client does no I/O.
    let kbs: Box<dyn HttpClient> = if is_vsock_url(kbs_url) {
        Box::new(VsockHttpClient::new())
    } else {
        Box::new(ReqwestHttpClient::new().map_err(|e| AgentError::Kbs(e.class()))?)
    };
    let guardian = GuardianVsockClient::new();
    let guardian_url = guardian_relay_url();
    let provider = snp_provider();
    let mut env = ConsoleEnv;
    run_with(
        cli,
        kbs_url,
        &cmdline,
        Deps {
            kbs: kbs.as_ref(),
            guardian: &guardian,
            guardian_url: &guardian_url,
            snp: provider.as_ref(),
            kbs_vk: &PINNED_KBS_RESPONSE_VK,
            kbs_kid: PINNED_KBS_RESPONSE_KID,
            env: &mut env,
        },
    )
}

fn run_with(
    cli: &Cli,
    kbs_url: &str,
    cmdline: &str,
    deps: Deps<'_>,
) -> Result<Released, AgentError> {
    // 0. Customer-held keys: read the measured binding (`None` = M0).
    //    A cmdline the grammar refuses is refused here — before any
    //    contact with anyone.
    if cmdline_may_hide_key_mode(cmdline) {
        return Err(AgentError::Guardian("cmdline-may-be-truncated"));
    }
    let binding = GuardianBinding::from_cmdline(cmdline)
        .map_err(|_| AgentError::Guardian("cmdline-grammar"))?;
    let mode = binding.as_ref().map_or(KeyMode::Hippius, |b| b.mode);
    check_key_mode_flags(cli, binding.is_some())?;

    // 1. Load the COSE ticket from disk. `ticket::load` accepts either
    //    a `vsock://CID:PORT` URI (production) or an absolute file
    //    path (smoke / dev), exactly as the legacy agent does.
    //    `main` already refused to call `run` with no `--ticket`; the
    //    `ok_or` here is a defensive re-statement of that invariant,
    //    never actually taken. The ticket's signed `key_mode` must be
    //    the measured one (M0: exactly the pre-guardian refusal).
    let ticket_path = cli
        .ticket
        .as_deref()
        .ok_or(AgentError::Ticket("missing"))?
        .to_string_lossy()
        .into_owned();
    let ticket = ticket_stage::load_for_mode(&ticket_path, mode)?;

    // 1b. Customer-held keys: the GUARDIAN LEG, before any KBS contact
    //     (see `guardian_leg`: it waits inside this boot, it never
    //     returns without a verified share except on a signed
    //     `erased`). M0 never gets here.
    let guardian = match binding.as_ref() {
        Some(b) => Some(guardian_leg::run(
            deps.guardian,
            deps.guardian_url,
            deps.snp,
            deps.env,
            b,
            &ticket.order().vm_id,
            cli.share_c_version,
        )?),
        None => None,
    };

    // 5b. Phase 2A of audit follow-up Review #2 — read the previous
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

    // 2-6. The release exchange: a fresh X25519 key, a fresh KBS nonce,
    //    an SNP report binding both, POST /v1/kbs/release. M0/M1 attest
    //    STAMP PROTOCOL v2 in REPORT_DATA and NEVER fall back to v1: a
    //    denial of the v2 report is final (a forged 403 must not buy a v1
    //    release — see the module docs). M2 attests v1 only (its stamp is
    //    the guardian's; the KBS has none to bind to a timeline).
    let attested = if mode == KeyMode::Customer {
        AttestedStampProtocol::V1
    } else {
        AttestedStampProtocol::V2
    };
    let (signed, keys, nonce, measurement) = release_exchange(
        &deps,
        kbs_url,
        ticket.cose_bytes(),
        submitted_boot_counter,
        attested,
    )?;

    // 7. §6/§7/§19/§20 binding gate + HPKE unwrap. `keys` is consumed
    //    by value — the X25519 secret scalar drops + wipes
    //    immediately after this returns. The KEK must be present in
    //    M0/M1 (in M1 it is `share_H`) and absent in M2. The response
    //    shape must be the ATTESTED protocol's (v2: the V2 domain and a
    //    timeline transition; v1: exactly the pre-v2 response).
    let mut secrets = verify::verify_and_unwrap_attested(
        &signed,
        keys,
        &nonce,
        &ticket,
        &measurement,
        deps.kbs_vk,
        deps.kbs_kid,
        mode,
        attested,
    )?;

    // 7a. The keyslot key. M0 is the KBS KEK verbatim; M1/M2 derive it
    //     from both shares (M1) or the guardian's alone (M2).
    let kek = keyslot_key(
        mode,
        secrets.luks.take(),
        guardian.as_ref(),
        &ticket.order().vm_id,
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

    // 7c/7d. The volume stamp: the KBS's in M0/M1 (exactly as before),
    //        the guardian's in M2 (the KBS notes no stamp for an M2
    //        VM, so the one it echoes binds nothing).
    let stamp = match guardian.as_ref().and_then(|g| g.stamp.as_ref()) {
        Some(g) => StampSource::Guardian {
            expected: g.expected,
            token: &g.token,
        },
        None => StampSource::Kbs {
            expected: secrets.expected_volume_stamp,
            token: secrets.volume_stamp_token.as_deref(),
            transition: secrets.volume_stamp_transition,
        },
    };
    write_stamp_outputs(cli, &ticket.order().vm_id, &stamp)?;

    // 7e. Customer-held keys: the share version for the LUKS2 token,
    //     after every other `*_out` file and before the KEK ships.
    if let (Some(path), Some(g)) = (cli.share_c_version_out.as_deref(), guardian.as_ref()) {
        write_share_c_version(path, g.share_c_version).map_err(AgentError::Guardian)?;
    }
    // 7f. Customer-held keys: the stable cloud-init instance-id, from the
    //     `vm_id` the keyslot key was just combined under.
    if let (Some(path), Some(_)) = (cli.instance_id_out.as_deref(), guardian.as_ref()) {
        write_instance_id(path, &cloud_init_instance_id(&ticket.order().vm_id))
            .map_err(AgentError::Guardian)?;
    }

    Ok(Released {
        kek,
        userdata: std::mem::take(&mut secrets.userdata),
        lifecycle_key: secrets.lifecycle_key.take(),
    })
}

/// One exchange: `(signed response, the key it is sealed to, the nonce,
/// the guest's own measurement)`.
type Exchange = (
    hippius_types::release::SignedResponse,
    keygen::Ephemeral,
    kbs_client::KbsNonce,
    [u8; snp_report::MEASUREMENT_LEN],
);

/// Steps 2-6, ONCE, attesting `attested`. There is no second attempt: a
/// KBS denial (403) is returned as is — never retried under another stamp
/// protocol — like every other failure.
fn release_exchange(
    deps: &Deps<'_>,
    kbs_url: &str,
    cose_ticket: &[u8],
    submitted_boot_counter: Option<u64>,
    attested: AttestedStampProtocol,
) -> Result<Exchange, AgentError> {
    // 2. X25519 ephemeral keygen — `Zeroizing<[u8; 32]>` for the
    //    secret scalar, public bytes exposed for the SNP REPORT_DATA.
    let keys = keygen::generate_ephemeral()?;
    // 4. Fresh single-use KBS nonce.
    let nonce = kbs_client::fetch_nonce(deps.kbs, kbs_url)?;
    // 5. SEV-SNP report — `/dev/sev-guest` ioctl. v1: the §20 layout
    //    `nonce ‖ x25519_pub`; v2: `SHA-256(v2 domain ‖ nonce) ‖
    //    x25519_pub` — the guest's only (PSP-signed) v2 claim.
    let report = match attested {
        AttestedStampProtocol::V2 => {
            snp_report::request_stamp_v2(deps.snp, &nonce.0, keys.public_bytes())?
        }
        AttestedStampProtocol::V1 => snp_report::request(deps.snp, &nonce.0, keys.public_bytes())?,
    };
    let measurement = snp_report::measurement(&report)?;
    // 6. POST /v1/kbs/release.
    let signed = kbs_client::release(
        deps.kbs,
        kbs_url,
        cose_ticket,
        &nonce,
        &report,
        submitted_boot_counter,
    )?;
    Ok((signed, keys, nonce, measurement))
}

/// The customer-held-keys flags belong to M1/M2 only, and there
/// `--share-c-version-out` is required: without it a first boot would
/// format a volume whose LUKS2 token cannot record the share version.
fn check_key_mode_flags(cli: &Cli, keyed: bool) -> Result<(), AgentError> {
    if keyed {
        if cli.share_c_version_out.is_none() {
            return Err(AgentError::Guardian("share-c-version-out-required"));
        }
        if cli.instance_id_out.is_none() {
            return Err(AgentError::Guardian("instance-id-out-required"));
        }
    } else if cli.share_c_version.is_some()
        || cli.share_c_version_out.is_some()
        || cli.instance_id_out.is_some()
    {
        return Err(AgentError::Guardian("key-mode-flags-without-binding"));
    }
    Ok(())
}

/// The bytes `main` writes to stdout.
///
/// - M0: the KBS KEK verbatim (the caller checks its length, as before).
/// - M1: `combine_kek(split, share_H, share_C)`; `share_H` must be
///   exactly 32 bytes.
/// - M2: `combine_kek(customer, —, share_C)`.
///
/// The shares are consumed and wipe on drop; any other combination
/// fails closed.
fn keyslot_key(
    mode: KeyMode,
    kbs_kek: Option<Zeroizing<Vec<u8>>>,
    guardian: Option<&GuardianRelease>,
    vm_id: &str,
) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    let combined = match (mode, kbs_kek, guardian) {
        (KeyMode::Hippius, Some(kek), None) => return Ok(kek),
        (KeyMode::Split, Some(kek), Some(g)) => {
            if kek.len() != KEY_LEN {
                return Err(AgentError::Guardian("share-h-length"));
            }
            let mut share_h = Zeroizing::new([0u8; KEY_LEN]);
            share_h.copy_from_slice(&kek);
            combine_kek(mode, Some(&share_h), Some(&g.share_c), vm_id)
        }
        (KeyMode::Customer, None, Some(g)) => combine_kek(mode, None, Some(&g.share_c), vm_id),
        _ => return Err(AgentError::Guardian("shares-do-not-match-mode")),
    }
    .map_err(|_| AgentError::Guardian("combine"))?;
    Ok(Zeroizing::new(combined.to_vec()))
}

/// Where this boot's volume-stamp expectation and confirm token came
/// from — and so where the confirm goes.
enum StampSource<'a> {
    /// M0/M1: the KBS's `kbs-core::volume_stamp`. `transition` is the
    /// stamp-protocol-v2 `(expected, target)` timelines (`None` for a v1
    /// release).
    Kbs {
        expected: u64,
        token: Option<&'a [u8; 32]>,
        transition: Option<([u8; 32], [u8; 32])>,
    },
    /// M2: the customer's guardian (signed response, sealed token).
    Guardian { expected: u64, token: &'a [u8; 32] },
}

/// 7c + 7d. `kbs-core::volume_stamp` — write the anti-rollback confirm
/// context BEFORE we ship the LUKS KEK, same fail-closed ordering as
/// 7b. A requested-but-absent token (a KBS that predates this gate) is
/// FATAL rather than a silent skip: the operator asked for the gate, so
/// getting none must surface as an error, not quietly proceed
/// unrolled-back-protected.
///
/// Then the PLAIN decimal `expected` value for the POSIX-sh initramfs
/// gate, strictly AFTER the fatal-on-no-token check. `expected` is
/// always present on the wire (defaults to `0`), so this never fails
/// closed the way the ctx write can — but ordering it after means a
/// fatal ctx error returns before this file is ever created, so a
/// `--volume-stamp-ctx-out` no-token failure never leaves a stale
/// expectation file for the shell to (wrongly) trust.
fn write_stamp_outputs(cli: &Cli, vm_id: &str, stamp: &StampSource<'_>) -> Result<(), AgentError> {
    let (expected, token, to, transition) = match *stamp {
        StampSource::Kbs {
            expected,
            token,
            transition,
        } => (expected, token, ConfirmTo::Kbs, transition),
        StampSource::Guardian { expected, token } => {
            (expected, Some(token), ConfirmTo::Guardian, None)
        }
    };
    // A v2 expectation only means something WITH its transition: the gate
    // reads a missing transition file as a v1 release and would compare
    // the value alone — against a volume the release bound to a timeline.
    // Refuse before anything is written for the gate.
    if transition.is_some()
        && cli.volume_stamp_expected_out.is_some()
        && cli.volume_stamp_transition_out.is_none()
    {
        eprintln!(
            "hippius-guest-release: fail-closed: the release carried a volume-stamp timeline \
             transition but --volume-stamp-transition-out is not set (--volume-stamp-expected-out \
             is)"
        );
        return Err(AgentError::Kbs("volume-stamp-transition-out-required"));
    }
    if let Some(path) = cli.volume_stamp_ctx_out.as_deref() {
        let token = token.ok_or_else(|| {
            eprintln!(
                "hippius-guest-release: fail-closed: volume-stamp-ctx-out: \
                 no-token-in-release (KBS predates the volume-stamp gate)"
            );
            AgentError::Kbs("volume-stamp-no-token")
        })?;
        let target = expected
            .checked_add(1)
            .ok_or(AgentError::Kbs("volume-stamp-overflow"))?;
        write_volume_stamp_ctx(
            path,
            vm_id,
            expected,
            target,
            token,
            to,
            transition.as_ref().map(|(_, t)| t),
        )
        .map_err(AgentError::Kbs)?;
    }
    // The transition BEFORE the expectation: the gate treats an existing
    // expectation file as authoritative, so it must never see one without
    // the transition that came with it.
    if let Some(path) = cli.volume_stamp_transition_out.as_deref() {
        write_volume_stamp_transition(path, transition.as_ref()).map_err(AgentError::Kbs)?;
    }
    if let Some(path) = cli.volume_stamp_expected_out.as_deref() {
        write_volume_stamp_expected(path, expected).map_err(AgentError::Kbs)?;
    }
    Ok(())
}

/// `--share-c-version-out`: `N\n`, mode `0644` (a version number the
/// guardian also sends in the clear to the relay — not a secret).
fn write_share_c_version(path: &std::path::Path, version: u32) -> Result<(), &'static str> {
    write_secret_0600_at_mode(path, format!("{version}\n").as_bytes(), 0o644)
}

/// Domain separator of [`cloud_init_instance_id`]. Changing it changes
/// the instance-id of every M1/M2 volume, which makes cloud-init treat
/// each one as a NEW instance on its next boot.
const INSTANCE_ID_DOMAIN: &[u8] = b"hippius-iid-v1\0";

/// The stable cloud-init instance-id of an M1/M2 VM:
/// `iid-` + the first 32 lowercase hex characters of
/// `SHA-256("hippius-iid-v1\0" ‖ vm_id)`.
///
/// The same `vm_id` feeds [`combine_kek`], so a boot under another
/// `vm_id` opens no keyslot: the id cannot be moved without also losing
/// the disk. It is not a secret (the `vm_id` is on the measured
/// cmdline already); it only has to be stable per VM and distinct
/// between VMs.
fn cloud_init_instance_id(vm_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(INSTANCE_ID_DOMAIN);
    h.update(vm_id.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(4 + 32);
    out.push_str("iid-");
    for b in &digest[..16] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// `--instance-id-out`: `iid-<32 hex>\n`, mode `0644` (not a secret).
fn write_instance_id(path: &std::path::Path, iid: &str) -> Result<(), &'static str> {
    write_secret_0600_at_mode(path, format!("{iid}\n").as_bytes(), 0o644)
}

/// The longest spelling of the key-mode token.
const LONGEST_KEY_MODE_TOKEN: &str = "hippius.key_mode=customer";

/// The shortest `/proc/cmdline` (without its trailing `\n`) that a
/// truncation could have produced while cutting a key-mode token off.
///
/// SEV measures the whole cmdline; the guest sees at most
/// [`MAX_CMDLINE_LEN`] bytes of it. Both truncations on the boot path
/// cut from the end:
/// - the kernel's own copy is bytewise, so what survives is exactly
///   2047 bytes;
/// - the EFI stub (`efi_convert_cmdline`, the path OVMF direct boot
///   takes) cuts at the last whitespace before byte 2048, so less
///   survives — but when the token it cut was the key-mode token
///   itself, that token started within its own length of the limit, so
///   at least `2047 - 25 = 2022` bytes survive.
///
/// All of this is about `/proc/cmdline` as the guest sees it, which is
/// what both truncations act on: OVMF puts [`OVMF_INITRD_PREFIX`]
/// (`initrd=initrd `, 14 bytes) in front of the measured cmdline, so in
/// MEASURED bytes the floor is [`KEY_MODE_TRUNCATION_FLOOR_MEASURED`]
/// (2008) and the longest cmdline that is never cut is
/// [`MAX_MEASURED_CMDLINE_LEN`](hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN) (2033). Those two are vali's numbers.
///
/// A key-mode token cut off makes an M1/M2 launch look like M0 from
/// inside the guest, which would then skip the guardian and format a
/// first-boot volume under the KBS KEK alone. An honest vali never
/// mints a measured cmdline over [`MAX_MEASURED_CMDLINE_LEN`](hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN), so an
/// honest launch never loses a token this way; a compromised one is
/// refused here.
const KEY_MODE_TRUNCATION_FLOOR: usize = MAX_CMDLINE_LEN - LONGEST_KEY_MODE_TOKEN.len();

/// [`KEY_MODE_TRUNCATION_FLOOR`] in measured bytes (without the OVMF
/// prefix): vali must not mint a token-less cmdline this long or longer.
#[cfg_attr(not(test), allow(dead_code))]
const KEY_MODE_TRUNCATION_FLOOR_MEASURED: usize =
    KEY_MODE_TRUNCATION_FLOOR - OVMF_INITRD_PREFIX.len();

/// `true` when `/proc/cmdline` carries NO key-mode token and is long
/// enough ([`KEY_MODE_TRUNCATION_FLOOR`]) that one may have been cut
/// off. The guest then refuses to boot rather than guess M0. The cost
/// is that an M0 launch whose `/proc/cmdline` is 2022..=2047 bytes
/// (measured 2008..=2033) no longer boots.
///
/// What this cannot see: a truncation that dropped a key-mode token
/// placed AFTER a long token straddling the limit, or anything after a
/// `\n` (the EFI stub stops there). Neither yields a key the customer
/// did not approve: a guest that believes it is M0 never asks the
/// guardian, so the VM never enrolls, which is what the customer's
/// first-boot enrollment check catches (the same as an M0 launch sold
/// as M1).
fn cmdline_may_hide_key_mode(cmdline: &str) -> bool {
    let cmdline = cmdline.strip_suffix('\n').unwrap_or(cmdline);
    if cmdline.len() < KEY_MODE_TRUNCATION_FLOOR {
        return false;
    }
    !cmdline
        .split_ascii_whitespace()
        .any(|t| t.split_once('=').map_or(t, |(k, _)| k) == "hippius.key_mode")
}

/// Production [`guardian_leg::LegEnv`]: really sleep, and put every
/// status line on stderr (the kmsg the shell captures) AND the console,
/// where `quiet` would otherwise hide a guest that is waiting for its
/// guardian. Status lines carry no secrets.
struct ConsoleEnv;

impl guardian_leg::LegEnv for ConsoleEnv {
    fn pause(&mut self, delay: Duration) -> bool {
        std::thread::sleep(delay);
        true
    }

    fn status(&mut self, line: &str) {
        eprintln!("hippius-guest-release: {line}");
        if let Ok(mut console) = std::fs::OpenOptions::new().write(true).open("/dev/console") {
            let _ = writeln!(console, "hippius-guest-release: {line}");
        }
    }
}

/// The guardian signed `erased`: this VM's customer share is gone and
/// no retry can bring it back. Never returns — see the call site.
fn halt_erased() -> ! {
    let mut env = ConsoleEnv;
    loop {
        guardian_leg::LegEnv::status(
            &mut env,
            "fail-closed: the customer key guardian ERASED this VM's key share. \
             The disk cannot be unlocked and its data is unrecoverable. \
             Halting here (no reboot, no KBS contact); stop or delete the VM.",
        );
        std::thread::sleep(Duration::from_secs(3600));
    }
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
///
/// `to` names the confirm target. A KBS ctx (M0/M1) carries no target
/// field — byte-identical to every ctx written before customer-held
/// keys; a guardian ctx (M2) ends in `"to":"guardian"`.
fn write_volume_stamp_ctx(
    path: &std::path::Path,
    vm_id: &str,
    expected: u64,
    target: u64,
    token: &[u8; 32],
    to: ConfirmTo,
    timeline: Option<&[u8; 32]>,
) -> Result<(), &'static str> {
    let to_field = match to {
        ConfirmTo::Kbs => "",
        ConfirmTo::Guardian => ",\"to\":\"guardian\"",
    };
    // Stamp protocol v2: the timeline the guest stamps and confirms on.
    // Absent for a v1 release (byte-identical to before).
    let timeline_field = match timeline {
        Some(t) => format!(",\"timeline\":\"{}\"", encode_hex(t)),
        None => String::new(),
    };
    let json = format!(
        "{{\"vm_id\":{},\"expected\":{expected},\"target\":{target},\"token\":\"{}\"{to_field}{timeline_field}}}",
        json_escape_string(vm_id),
        encode_hex(token),
    );
    write_secret_0600(path, json.as_bytes())
}

/// Stamp protocol v2 — `--volume-stamp-transition-out`: write
/// `<expected hex> <target hex>\n` (mode `0644`, not a secret) for a
/// release that carried a transition; REMOVE the file for one that did
/// not, so the shell gate never runs the v2 comparison on a stale
/// transition. A failed write removes whatever landed, like
/// [`write_volume_stamp_expected`].
fn write_volume_stamp_transition(
    path: &std::path::Path,
    transition: Option<&([u8; 32], [u8; 32])>,
) -> Result<(), &'static str> {
    let Some((expected, target)) = transition else {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("volume-stamp-transition-remove"),
        };
    };
    let line = format!("{} {}\n", encode_hex(expected), encode_hex(target));
    match write_secret_0600_at_mode(path, line.as_bytes(), 0o644) {
        Ok(()) => Ok(()),
        Err(cls) => {
            let _ = std::fs::remove_file(path);
            Err(cls)
        }
    }
}

/// Who a volume-stamp confirm goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmTo {
    /// `POST /v1/kbs/volume-stamp/confirm` (M0/M1).
    Kbs,
    /// `POST /v1/guardian/stamp/confirm` via the guardian relay (M2).
    Guardian,
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
    to: ConfirmTo,
    /// Stamp protocol v2: the timeline the volume was stamped on.
    timeline: Option<[u8; 32]>,
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
    let to = match extract_json_string(text, "\"to\":\"").as_deref() {
        None => ConfirmTo::Kbs,
        Some("guardian") => ConfirmTo::Guardian,
        Some(_) => return Err("ctx-to"),
    };
    let timeline = match extract_json_string(text, "\"timeline\":\"") {
        None => None,
        Some(h) => Some(decode_hex_32(&h).ok_or("ctx-timeline-hex")?),
    };
    // A guardian confirm never carries a KBS timeline.
    if to == ConfirmTo::Guardian && timeline.is_some() {
        return Err("ctx-timeline");
    }

    Ok(VolumeStampCtx {
        vm_id,
        target,
        token,
        to,
        timeline,
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

    // M2: the stamp is the guardian's — confirm there, over the
    // guardian relay. The KBS is not involved. The answer must be signed
    // by the guardian key the MEASURED cmdline pins, read again here
    // (this is a separate process from the release).
    if ctx.to == ConfirmTo::Guardian {
        let cmdline = std::fs::read_to_string("/proc/cmdline")
            .map_err(|_| AgentError::Guardian("cmdline-read"))?;
        let binding = confirm_binding(&cmdline)?;
        return confirm_to_guardian(
            &GuardianVsockClient::new(),
            &guardian_relay_url(),
            &ctx,
            &binding,
        );
    }

    // Same transport dispatch as `run` step 3 — reusing the exact
    // `HttpClient` abstraction rather than a second client.
    let http: Box<dyn HttpClient> = if is_vsock_url(kbs_url) {
        Box::new(VsockHttpClient::new())
    } else {
        Box::new(ReqwestHttpClient::new().map_err(|e| AgentError::Kbs(e.class()))?)
    };

    let body = encode_confirm_request(&ctx.vm_id, ctx.target, &ctx.token, ctx.timeline.as_ref())
        .map_err(AgentError::Kbs)?;
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

/// The measured binding an M2 confirm verifies its ack against: the same
/// `/proc/cmdline` rules as release mode (a possibly-truncated cmdline or
/// a grammar error fails closed), and it must be `customer` — only M2
/// writes a guardian confirm context.
fn confirm_binding(cmdline: &str) -> Result<GuardianBinding, AgentError> {
    if cmdline_may_hide_key_mode(cmdline) {
        return Err(AgentError::Guardian("cmdline-may-be-truncated"));
    }
    match GuardianBinding::from_cmdline(cmdline) {
        Ok(Some(b)) if b.mode == KeyMode::Customer => Ok(b),
        Ok(_) => Err(AgentError::Guardian("confirm-not-customer-mode")),
        Err(_) => Err(AgentError::Guardian("cmdline-grammar")),
    }
}

/// M2 confirm: `POST /v1/guardian/stamp/confirm` with the token the
/// SIGNED guardian response sealed to this boot. The miner relays the
/// answer, so it counts only as a [`SignedGuardianStampAck`] that
/// verifies under the measured `guardian_pk` and echoes THIS confirm
/// (`vm_id`, `target`, `sha256(token)`) — [`hippius_guest::verify_stamp_ack`].
/// Anything else (unsigned, forged, another confirm's ack, a relay error)
/// is an `Err`: the mandatory first-boot confirm retries and then fails
/// closed, a later-boot confirm logs a warning. The stamp value itself is
/// never read from the ack; the next boot's signed `expected_volume_stamp`
/// is the only stamp the guest trusts.
///
/// [`SignedGuardianStampAck`]: hippius_types::guardian::SignedGuardianStampAck
fn confirm_to_guardian(
    relay: &dyn HttpClient,
    relay_url: &str,
    ctx: &VolumeStampCtx,
    binding: &GuardianBinding,
) -> Result<(), AgentError> {
    let confirm = GuardianStampConfirm {
        v: GUARDIAN_WIRE_V,
        vm_id: ctx.vm_id.clone(),
        target: ctx.target,
        token: ctx.token.to_vec(),
    };
    let body =
        encode_canonical(&confirm).map_err(|_| AgentError::Guardian("confirm-request-encode"))?;
    let url = format!(
        "{}{GUARDIAN_STAMP_CONFIRM_PATH}",
        relay_url.trim_end_matches('/')
    );
    let response = relay.post_cbor(&url, &body)?;
    if !(200..300).contains(&response.status) {
        return Err(AgentError::Guardian("confirm-http-status"));
    }
    hippius_guest::verify_stamp_ack(&response.body, binding, &confirm).map_err(|e| {
        AgentError::Guardian(match e {
            hippius_guest::GuestError::Signature(_) => "confirm-ack-bad-signature",
            hippius_guest::GuestError::Schema(_) => "confirm-ack-mismatch",
            _ => "confirm-ack-decode",
        })
    })?;
    eprintln!("hippius-guest-release: volume stamp confirm: guardian-signed ack verified");
    Ok(())
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
    timeline: Option<&[u8; 32]>,
) -> Result<Vec<u8>, &'static str> {
    let mut entries = vec![
        (Value::Text("vm_id".into()), Value::Text(vm_id.to_string())),
        (Value::Text("value".into()), Value::Integer(target.into())),
        (Value::Text("token".into()), Value::Bytes(token.to_vec())),
    ];
    // Stamp protocol v2 only; a v1 confirm body is byte-identical to
    // before (`VolumeStampConfirmBody::timeline_id` is optional).
    if let Some(t) = timeline {
        entries.push((Value::Text("timeline_id".into()), Value::Bytes(t.to_vec())));
    }
    to_canonical_vec(&Value::Map(entries)).map_err(|_| "confirm-request-encode")
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
        // M1/M2 (H5b): the golden overlay's staging path — the user-data
        // reaches the seed only on the volume's first boot.
        assert_eq!(
            check_secret_out_path("--userdata-out", Path::new("/run/hippius/userdata.staged")),
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
        write_volume_stamp_ctx(&path, "vm-abc", 4, 5, &token, ConfirmTo::Kbs, None).unwrap();
        // The KBS ctx is byte-identical to the pre-customer-keys file.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!(
                "{{\"vm_id\":\"vm-abc\",\"expected\":4,\"target\":5,\"token\":\"{}\"}}",
                "ab".repeat(32)
            )
        );

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
        assert_eq!(ctx.to, ConfirmTo::Kbs);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_guardian_ctx_names_its_target_and_round_trips() {
        let path = tmp_path("guardian-ctx");
        let token = [0xCDu8; 32];
        write_volume_stamp_ctx(&path, "vm-abc", 41, 42, &token, ConfirmTo::Guardian, None).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with(",\"to\":\"guardian\"}"), "{text}");
        let ctx = read_volume_stamp_ctx(&path).unwrap();
        assert_eq!(ctx.to, ConfirmTo::Guardian);
        assert_eq!(ctx.target, 42);
        assert_eq!(ctx.token, token);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_ctx_naming_an_unknown_target_is_refused() {
        let path = tmp_path("bad-to");
        std::fs::write(
            &path,
            format!(
                "{{\"vm_id\":\"v\",\"expected\":1,\"target\":2,\"token\":\"{}\",\"to\":\"kbs2\"}}",
                "ab".repeat(32)
            ),
        )
        .unwrap();
        assert!(matches!(read_volume_stamp_ctx(&path), Err("ctx-to")));
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
        let body = encode_confirm_request("vm-abc", 5, &token, None).unwrap();
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

    /// Stamp protocol v2: the confirm names the timeline it stamped
    /// (`timeline_id`, 32 bytes) — and only then; a v1 body keeps its
    /// three fields.
    #[test]
    fn a_v2_confirm_carries_the_timeline_and_a_v1_one_does_not() {
        let token = [0x11u8; 32];
        let body = encode_confirm_request("vm-abc", 5, &token, Some(&[0x7c; 32])).unwrap();
        assert_canonical(&body).unwrap();
        let Value::Map(entries) = ciborium::de::from_reader::<Value, _>(body.as_slice()).unwrap()
        else {
            panic!("not a map");
        };
        assert_eq!(entries.len(), 4);
        let t = entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Bytes(b)) if k == "timeline_id" => Some(b.clone()),
            _ => None,
        });
        assert_eq!(t.as_deref(), Some(&[0x7c; 32][..]));
    }

    /// A v2 ctx round-trips its timeline; a guardian ctx with a timeline,
    /// or a timeline that is not 64 hex chars, is refused.
    #[test]
    fn a_v2_ctx_round_trips_its_timeline() {
        let path = tmp_path("v2ctx");
        let token = [0xABu8; 32];
        write_volume_stamp_ctx(
            &path,
            "vm-abc",
            4,
            5,
            &token,
            ConfirmTo::Kbs,
            Some(&[0x7c; 32]),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.ends_with(&format!(",\"timeline\":\"{}\"}}", "7c".repeat(32))),
            "{text}"
        );
        let ctx = read_volume_stamp_ctx(&path).unwrap();
        assert_eq!(ctx.timeline, Some([0x7c; 32]));
        assert_eq!(ctx.to, ConfirmTo::Kbs);
        std::fs::write(&path, text.replace(&"7c".repeat(32), "7c")).unwrap();
        assert!(matches!(
            read_volume_stamp_ctx(&path),
            Err("ctx-timeline-hex")
        ));
        write_volume_stamp_ctx(&path, "vm-abc", 4, 5, &token, ConfirmTo::Guardian, None).unwrap();
        let g = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            g.replace("}", &format!(",\"timeline\":\"{}\"}}", "7c".repeat(32))),
        )
        .unwrap();
        assert!(matches!(read_volume_stamp_ctx(&path), Err("ctx-timeline")));
        let _ = std::fs::remove_file(&path);
    }

    /// The transition file: `<expected hex> <target hex>\n` at 0644 for a
    /// v2 release; REMOVED (never left stale) for a v1 one.
    #[test]
    fn the_transition_file_is_written_for_v2_and_removed_for_v1() {
        let path = tmp_path("transition");
        write_volume_stamp_transition(&path, Some(&([0xa1; 32], [0xb2; 32]))).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{} {}\n", "a1".repeat(32), "b2".repeat(32))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        write_volume_stamp_transition(&path, None).unwrap();
        assert!(!path.exists(), "a v1 release leaves no transition behind");
        write_volume_stamp_transition(&path, None).unwrap();
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
