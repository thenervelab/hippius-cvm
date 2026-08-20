//! Guest end-of-life path — §24/§25 (PR-E1.5).
//!
//! The dual of the §21 boot pipeline. When the VM is being stopped
//! (tenant cancel, lease expiry, migration drain), the measured guest
//! agent runs this sequence — invoked as the `eol` subcommand of the
//! binary (see [`crate::main`]), wired by the measured image's shutdown
//! integration (a systemd shutdown unit / dracut shutdown hook — §F):
//!
//! 1. **Sign a `StoppedAck`** ([`hippius_guest::sign_stopped_ack`]) with
//!    the guest lifecycle Ed25519 key — proof that THIS generation of
//!    THIS lease will not run again (§24: the orchestrator needs it
//!    before committing `Destroyed{gen}` / activating a §25 migration
//!    destination).
//! 2. **Push the signed ack to vali** through the Edge relay. Best
//!    effort: if vali is unreachable the failure is **swallowed** and
//!    the sequence continues — security (crypto-erase + poweroff) takes
//!    priority over audit-log completeness.
//! 3. **Tear down the dm-crypt mapping** for the per-VM volume
//!    (`luksClose hippius-data`) — the plaintext device-mapper target
//!    is removed from the kernel.
//! 4. **Power the VM off** (`reboot(RB_POWER_OFF)`).
//!
//! ## Fail-closed, never fail-open
//!
//! Every step before the poweroff is **best-effort and non-aborting**:
//! a failed signature, an unreachable vali, a `luksClose` error — none
//! of them stop the sequence. The VM **always** reaches the poweroff.
//! Rationale (§24): a guest that cannot complete the audit handshake
//! must still shut down — leaving a hostile/half-stopped guest running
//! is strictly worse than an incomplete audit record. There is no
//! retry, no shell, no "leave it running and try later".
//!
//! ## Secret discipline (§20)
//!
//! The lifecycle [`SigningKey`] is taken **by value** and dropped at
//! the end of [`run_eol`]; `ed25519-dalek`'s `zeroize` feature makes
//! `SigningKey: ZeroizeOnDrop`, so the key bytes wipe on that drop.
//! Nothing here logs key material — only closed `&'static str` classes.
//!
//! ## Why a trait (mirrors `LuksUnlocker` / `RootfsPivot`)
//!
//! The OS-effecting half — `luksClose` (libcryptsetup) + `reboot(2)` —
//! is untestable and destructive from `cargo test`. So the
//! cross-platform [`EolSink`] trait + [`MockEolSink`] live here and the
//! real [`RealEolSink`] is gated to `target_os = "linux"`. [`run_eol`]
//! itself — the orchestration + fail-closed semantics — is fully
//! unit-tested against the mock.

use crate::pipeline::AgentError;
use crate::stages::kbs_client::HttpClient;
// `MAPPER_NAME` is used only by the Linux-only `RealEolSink`.
#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
use crate::stages::unlock::MAPPER_NAME;
use core::cell::Cell;
use ed25519_dalek::SigningKey;
use hippius_guest::sign_stopped_ack;
use hippius_types::stopped::StoppedAck;

/// vali endpoint (relative to the Edge-relayed base URL) the signed
/// `StoppedAck` is POSTed to.
const STOPPED_ACK_PATH: &str = "/v1/lifecycle/stopped";

/// Stable classifier strings for EOL diagnostics. Emitted to stderr as
/// fixed tags only — never with any field interpolated (§20).
mod cat {
    /// No lifecycle key was available — the ack could not be signed.
    pub(super) const NO_KEY: &str = "eol-no-key";
    /// `sign_stopped_ack` failed (canonical-encode error).
    pub(super) const SIGN: &str = "eol-sign-failed";
    /// Encoding the signed ack for the wire failed.
    pub(super) const ENCODE: &str = "eol-encode-failed";
    /// The vali push failed (transport error or non-2xx) — swallowed.
    pub(super) const PUSH: &str = "eol-push-failed";
    /// `luksClose` failed — swallowed; the sequence still powers off.
    pub(super) const LUKS_CLOSE: &str = "eol-luks-close-failed";
    /// The push + ack succeeded.
    pub(super) const ACK_OK: &str = "eol-ack-pushed";
}

/// The fields that pin a `StoppedAck` to one VM-lifecycle event (§24).
/// Owned (resolved by [`crate::main`]'s `eol` subcommand) — [`run_eol`]
/// borrows them into the short-lived [`StoppedAck`].
#[derive(Debug, Clone)]
pub struct StoppedAckParams {
    /// Which VM.
    pub vm_id: String,
    /// Which lease (anti-replay across re-leasings).
    pub lease_id: String,
    /// Which generation (anti-replay across §24 destroy / §25 migrate).
    pub vm_generation: u64,
    /// Single-use freshness nonce supplied by the orchestrator.
    pub nonce: [u8; 32],
    /// The guest's view of the stop time (Unix seconds).
    pub now_unix: u64,
}

/// The OS-effecting half of the EOL path: dm-crypt teardown + poweroff.
///
/// Production: [`RealEolSink`] (Linux). Tests + non-Linux dev hosts:
/// [`MockEolSink`].
pub trait EolSink {
    /// Tear down the dm-crypt mapping for the per-VM LUKS volume
    /// (`/dev/mapper/`[`MAPPER_NAME`]). An error is **non-fatal** — the
    /// caller swallows it and still powers off.
    fn luks_close(&self) -> Result<(), AgentError>;

    /// Power the VM off. On success this **never returns**; it returns
    /// `Err` only if the syscall itself failed.
    fn poweroff(&self) -> Result<(), AgentError>;
}

/// Run the §24/§25 guest EOL sequence: sign → push → `luksClose` →
/// poweroff. See the module docs for the fail-closed contract.
///
/// `lifecycle_key` is `None` when the key could not be resolved — the
/// sign + push steps are then skipped and the sequence goes straight to
/// teardown + poweroff (still fail-closed).
///
/// Returns `Ok(())` only on the impossible path where `poweroff` does
/// not halt the VM; every realistic terminating condition is the
/// poweroff (which never returns) or an `Err` from a failed poweroff.
pub fn run_eol(
    lifecycle_key: Option<SigningKey>,
    params: &StoppedAckParams,
    vali_base_url: &str,
    http: &dyn HttpClient,
    sink: &dyn EolSink,
) -> Result<(), AgentError> {
    // ── 1 + 2. Sign the StoppedAck and push it to vali. Best-effort:
    //    any failure here is logged as a static class and swallowed.
    match lifecycle_key {
        Some(key) => sign_and_push(&key, params, vali_base_url, http),
        None => log_eol(cat::NO_KEY),
        // `key: SigningKey` drops here → ZeroizeOnDrop wipes the bytes.
    }

    // ── 3 + 4. Tear down the dm-crypt mapping, then power off.
    eol_teardown(sink)
}

/// Sign + push ONLY — the §25 systemd-shutdown-hook half of the EOL
/// path. Runs the sign + best-effort vali push and returns; it does
/// **not** `luksClose` or `poweroff`.
///
/// This is the integration point for a measured tenant image whose
/// running init is the distro's own **systemd** (the BYO-OS / cloud-init
/// path — the custom Rust agent-initramfs is the boot `/init`, not the
/// running guest's PID 1). A systemd shutdown unit
/// (`Before=shutdown.target`) invokes `hippius-agent-initramfs eol
/// --sign-only` as one of its final clean-shutdown steps. systemd itself
/// then unmounts + closes the dm-crypt mapping and powers the machine
/// off — so this path must NOT call `luksClose` / `poweroff` (doing so
/// from a non-PID-1 process mid-systemd-shutdown would race systemd's own
/// teardown). On the legacy initramfs-as-init path, [`run_eol`] (which
/// owns the teardown + poweroff) is used instead.
///
/// ## Fail-closed, non-destructive (§25)
///
/// Identical secret + fail-closed discipline to [`run_eol`]: a missing
/// key, a sign error, or an unreachable vali are all swallowed static-
/// class logs — the function still returns `Ok(())` so systemd's
/// shutdown proceeds. It NEVER crypto-erases (no `luksClose`, no disk
/// unlink): §25 preserves the on-disk ciphertext for the snapshot.
pub fn run_eol_sign_only(
    lifecycle_key: Option<SigningKey>,
    params: &StoppedAckParams,
    vali_base_url: &str,
    http: &dyn HttpClient,
) {
    match lifecycle_key {
        Some(key) => sign_and_push(&key, params, vali_base_url, http),
        None => log_eol(cat::NO_KEY),
        // `key: SigningKey` drops here → ZeroizeOnDrop wipes the bytes.
    }
}

/// dm-crypt teardown (`luksClose`) followed by the poweroff — the
/// terminal half of the EOL sequence.
///
/// Shared by [`run_eol`] and the degraded `eol` subcommand paths in
/// [`crate::main`] (no resolvable identity, or no HTTP transport), so
/// the §24 fail-closed teardown — and the classified log of a swallowed
/// `luksClose` failure — is defined in exactly one place. A
/// `luks_close` error is **non-fatal**: the VM still powers off.
/// Returns `Err` only if the poweroff syscall itself fails.
pub fn eol_teardown(sink: &dyn EolSink) -> Result<(), AgentError> {
    if sink.luks_close().is_err() {
        log_eol(cat::LUKS_CLOSE);
    }
    sink.poweroff()
}

/// Sign the `StoppedAck` and POST it to vali. Every failure is a
/// swallowed static-class log line — this never returns an error,
/// because nothing it does may abort the EOL sequence.
fn sign_and_push(
    key: &SigningKey,
    params: &StoppedAckParams,
    vali_base_url: &str,
    http: &dyn HttpClient,
) {
    let ack = StoppedAck {
        vm_id: &params.vm_id,
        lease_id: &params.lease_id,
        vm_generation: params.vm_generation,
        nonce: &params.nonce,
        now_unix: params.now_unix,
    };
    let signed = match sign_stopped_ack(key, &ack) {
        Ok(s) => s,
        Err(_) => {
            log_eol(cat::SIGN);
            return;
        }
    };
    let body = match encode_signed_ack(&signed) {
        Ok(b) => b,
        Err(_) => {
            log_eol(cat::ENCODE);
            return;
        }
    };
    // vali's `StoppedAckIngestView` keys the stored bytes by the
    // `(vm_id, generation)` it reads from the URL query — it 400s
    // without BOTH. The host vsock proxy forwards the query verbatim
    // (it matches the allow-list on the path component only), so the
    // SAME url works over the `vsock://` transport and the legacy IP
    // one. The body stays the OPAQUE `SignedStoppedAck` — only vali's
    // verifier decodes it (§5.6 opacity; the relay never does).
    let url = stopped_ack_url(vali_base_url, &params.vm_id, params.vm_generation);
    match http.post_cbor(&url, &body) {
        Ok(resp) if (200..300).contains(&resp.status) => log_eol(cat::ACK_OK),
        // Transport error OR a non-2xx status — both swallowed.
        _ => log_eol(cat::PUSH),
    }
}

/// Canonical-CBOR encode a [`SignedStoppedAck`] for the wire — the
/// deterministic encoding vali re-derives + verifies.
fn encode_signed_ack(
    signed: &hippius_types::stopped::SignedStoppedAck,
) -> Result<Vec<u8>, AgentError> {
    let value =
        ciborium::value::Value::serialized(signed).map_err(|_| AgentError::Eol("encode"))?;
    hippius_types::cbor::to_canonical_vec(&value).map_err(|_| AgentError::Eol("encode"))
}

/// Build the stopped-ack POST URL: `<base>/v1/lifecycle/stopped?vm_id=…
/// &generation=…`. vali's ingest REQUIRES both query params (400 without
/// either). The `base` is the measured `hippius.vali_url` token — either
/// a `vsock://CID:PORT` proxy authority (the default, since the
/// confidential guest has no IP route to vali) or a legacy `https://`
/// base. The query is appended after the path so the host vsock proxy,
/// which matches its allow-list on the path component, forwards it
/// verbatim into vali's ingress.
///
/// `vm_id` is percent-encoded (defensive — vm-ids are `[a-z0-9-]` in
/// practice, but a stray reserved byte must not break the query). The
/// generation is a `u64` — always query-safe.
fn stopped_ack_url(base: &str, vm_id: &str, generation: u64) -> String {
    format!(
        "{}{}?vm_id={}&generation={}",
        base.trim_end_matches('/'),
        STOPPED_ACK_PATH,
        encode_query_component(vm_id),
        generation,
    )
}

/// Minimal RFC-3986 percent-encoding for a query-string value: keep the
/// unreserved set (`A–Z a–z 0–9 - _ . ~`) verbatim, escape everything
/// else as `%XX`. Kept local + dependency-free (the initramfs binary
/// avoids pulling a URL crate for one call).
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0x0f));
            }
        }
    }
    out
}

/// Upper-case hex digit for a nibble (`0..=15`).
fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Emit a fixed EOL diagnostic tag to stderr. The argument is
/// `&'static str` by type — no field can ever be interpolated (§20 "no
/// seed logging"; enforced crate-wide by `tests/no_seed_logging.rs`).
fn log_eol(class: &'static str) {
    eprintln!("hippius-agent-eol: {class}");
}

// ── Production implementation (Linux only) ──────────────────────────

/// A libcryptsetup log callback that drops every message — keeps
/// libcryptsetup diagnostics off the serial console (§20), exactly as
/// [`crate::stages::luks_cryptsetup`] does for the unlock side.
///
/// `extern "C"` with raw-pointer parameters is mandated by the
/// callback ABI, but the body dereferences nothing — so no `unsafe` is
/// needed and `unsafe_code = "forbid"` holds.
#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
extern "C" fn drop_libcryptsetup_log(
    _level: std::os::raw::c_int,
    _msg: *const std::os::raw::c_char,
    _usrptr: *mut std::os::raw::c_void,
) {
}

/// Production [`EolSink`] — real `libcryptsetup` deactivate + real
/// `reboot(2)`. Zero-sized + stateless. Linux-only.
#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
#[derive(Debug, Default)]
pub struct RealEolSink;

#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
impl RealEolSink {
    /// Construct a sink. No-op (stateless).
    pub fn new() -> Self {
        Self
    }
}

#[cfg(all(target_os = "linux", feature = "cryptsetup"))]
impl EolSink for RealEolSink {
    fn luks_close(&self) -> Result<(), AgentError> {
        use libcryptsetup_rs::consts::flags::CryptDeactivate;
        use libcryptsetup_rs::{set_log_callback, CryptInit};

        // Silence libcryptsetup before any call (§20 — no serial echo).
        set_log_callback::<()>(Some(drop_libcryptsetup_log), None);

        // Initialise a context from the *active mapping* by name (no
        // backing-device path needed for a deactivate), then drop the
        // dm-crypt target.
        let mut device = CryptInit::init_by_name_and_header(MAPPER_NAME, None)
            .map_err(|_| AgentError::Eol("luks-close-init"))?;
        device
            .activate_handle()
            .deactivate(MAPPER_NAME, CryptDeactivate::empty())
            .map_err(|_| AgentError::Eol("luks-close"))?;
        Ok(())
    }

    fn poweroff(&self) -> Result<(), AgentError> {
        // Single `reboot(2)` wrapper, shared with the fatal-error path.
        crate::stages::hardening::poweroff()
    }
}

// ── Mock implementation (all platforms) ─────────────────────────────

/// Test / non-Linux dev-host stand-in for [`RealEolSink`].
///
/// Records whether `luks_close` and `poweroff` were called and returns
/// configurable outcomes — so [`run_eol`]'s fail-closed sequencing is
/// fully unit-testable without a kernel device-mapper or a real
/// `reboot(2)`.
pub struct MockEolSink {
    /// Outcome `luks_close` returns.
    luks_close_outcome: Result<(), &'static str>,
    /// Outcome `poweroff` returns (`Ok` so the mock does not "diverge"
    /// — a test needs `run_eol` to return so it can assert).
    poweroff_outcome: Result<(), &'static str>,
    /// Set once `luks_close` has been called.
    luks_closed: Cell<bool>,
    /// Set once `poweroff` has been called.
    powered_off: Cell<bool>,
}

impl MockEolSink {
    /// A mock whose `luks_close` + `poweroff` both succeed.
    pub fn new() -> Self {
        Self {
            luks_close_outcome: Ok(()),
            poweroff_outcome: Ok(()),
            luks_closed: Cell::new(false),
            powered_off: Cell::new(false),
        }
    }

    /// A mock whose `luks_close` fails — used to pin that the sequence
    /// still reaches `poweroff` (fail-closed).
    pub fn failing_luks_close() -> Self {
        Self {
            luks_close_outcome: Err("luks-close"),
            ..Self::new()
        }
    }

    /// Whether `luks_close` has been called.
    pub fn luks_closed(&self) -> bool {
        self.luks_closed.get()
    }

    /// Whether `poweroff` has been called.
    pub fn powered_off(&self) -> bool {
        self.powered_off.get()
    }
}

impl Default for MockEolSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EolSink for MockEolSink {
    fn luks_close(&self) -> Result<(), AgentError> {
        self.luks_closed.set(true);
        self.luks_close_outcome.map_err(AgentError::Eol)
    }

    fn poweroff(&self) -> Result<(), AgentError> {
        self.powered_off.set(true);
        self.poweroff_outcome.map_err(AgentError::Eol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::kbs_client::HttpResponse;
    use core::cell::RefCell;

    /// Recording [`HttpClient`] for the EOL push tests.
    struct RecordingHttp {
        status: Option<u16>,
        last_url: RefCell<Option<String>>,
        post_count: Cell<u32>,
    }

    impl RecordingHttp {
        /// Returns `status` on every POST.
        fn responding(status: u16) -> Self {
            Self {
                status: Some(status),
                last_url: RefCell::new(None),
                post_count: Cell::new(0),
            }
        }

        /// Fails every POST with a transport error.
        fn unreachable() -> Self {
            Self {
                status: None,
                last_url: RefCell::new(None),
                post_count: Cell::new(0),
            }
        }
    }

    impl HttpClient for RecordingHttp {
        fn post_cbor(&self, url: &str, _body: &[u8]) -> Result<HttpResponse, AgentError> {
            self.post_count.set(self.post_count.get() + 1);
            *self.last_url.borrow_mut() = Some(url.to_string());
            match self.status {
                Some(status) => Ok(HttpResponse {
                    status,
                    body: Vec::new(),
                }),
                None => Err(AgentError::Kbs("transport")),
            }
        }
    }

    fn params() -> StoppedAckParams {
        StoppedAckParams {
            vm_id: "vm-abc".to_string(),
            lease_id: "lease-1".to_string(),
            vm_generation: 7,
            nonce: [0x22u8; 32],
            now_unix: 1_700_000_000,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn happy_path_signs_pushes_closes_and_powers_off() {
        let http = RecordingHttp::responding(200);
        let sink = MockEolSink::new();
        run_eol(Some(key()), &params(), "https://vali.test", &http, &sink)
            .expect("mock poweroff returns Ok");

        // The signed ack was POSTed to the vali stopped-ack endpoint —
        // WITH the `?vm_id=&generation=` query vali's ingest requires
        // (vm_id="vm-abc", generation=7 from `params()`).
        assert_eq!(http.post_count.get(), 1);
        assert_eq!(
            http.last_url.borrow().as_deref(),
            Some("https://vali.test/v1/lifecycle/stopped?vm_id=vm-abc&generation=7")
        );
        // … and the teardown + poweroff both ran.
        assert!(sink.luks_closed());
        assert!(sink.powered_off());
    }

    #[test]
    fn an_unreachable_vali_is_swallowed_and_the_vm_still_powers_off() {
        // §24: audit-log completeness must never block the shutdown.
        let http = RecordingHttp::unreachable();
        let sink = MockEolSink::new();
        run_eol(Some(key()), &params(), "https://vali.test", &http, &sink)
            .expect("a swallowed push error must not abort run_eol");
        assert_eq!(http.post_count.get(), 1, "the push was attempted");
        assert!(sink.luks_closed(), "teardown still ran");
        assert!(sink.powered_off(), "the VM still powered off");
    }

    #[test]
    fn a_missing_lifecycle_key_skips_the_push_but_still_powers_off() {
        // No key ⇒ no signature, no push — but teardown + poweroff
        // still run (fail-closed).
        let http = RecordingHttp::responding(200);
        let sink = MockEolSink::new();
        run_eol(None, &params(), "https://vali.test", &http, &sink)
            .expect("run_eol returns via the mock poweroff");
        assert_eq!(http.post_count.get(), 0, "no key ⇒ no push attempted");
        assert!(sink.luks_closed());
        assert!(sink.powered_off());
    }

    #[test]
    fn a_failed_luks_close_still_reaches_poweroff() {
        // §24: a dm-crypt teardown error must not strand the VM running.
        let http = RecordingHttp::responding(200);
        let sink = MockEolSink::failing_luks_close();
        run_eol(Some(key()), &params(), "https://vali.test", &http, &sink)
            .expect("a swallowed luks-close error must not abort run_eol");
        assert!(sink.luks_closed(), "luks_close was attempted");
        assert!(sink.powered_off(), "poweroff still reached");
    }

    #[test]
    fn a_non_2xx_vali_response_is_treated_as_a_swallowed_push_failure() {
        let http = RecordingHttp::responding(503);
        let sink = MockEolSink::new();
        run_eol(Some(key()), &params(), "https://vali.test", &http, &sink)
            .expect("a non-2xx push is swallowed");
        assert!(sink.powered_off());
    }

    #[test]
    fn eol_sink_trait_is_object_safe() {
        let sink: Box<dyn EolSink> = Box::new(MockEolSink::new());
        assert!(sink.poweroff().is_ok());
    }

    #[test]
    fn sign_only_pushes_the_ack_and_never_powers_off() {
        // §25 systemd-shutdown-hook variant: it signs + pushes, then
        // RETURNS — systemd owns the luksClose + poweroff. There is no
        // sink to touch, so the only observable effect is the push.
        let http = RecordingHttp::responding(200);
        run_eol_sign_only(Some(key()), &params(), "https://vali.test", &http);
        assert_eq!(http.post_count.get(), 1, "the signed ack was pushed");
        assert_eq!(
            http.last_url.borrow().as_deref(),
            Some("https://vali.test/v1/lifecycle/stopped?vm_id=vm-abc&generation=7")
        );
    }

    #[test]
    fn the_push_url_targets_the_vsock_proxy_with_the_query() {
        // The DEFAULT transport: a `vsock://` vali_url. The same URL
        // builder appends `?vm_id=&generation=` so the host proxy
        // forwards them into vali's ingress. (The vsock authority is
        // carried through verbatim; only main.rs picks the transport.)
        let http = RecordingHttp::responding(202);
        run_eol_sign_only(Some(key()), &params(), "vsock://2:19266", &http);
        assert_eq!(
            http.last_url.borrow().as_deref(),
            Some("vsock://2:19266/v1/lifecycle/stopped?vm_id=vm-abc&generation=7")
        );
    }

    #[test]
    fn the_push_url_percent_encodes_a_reserved_vm_id() {
        let url = stopped_ack_url("https://vali.test", "vm/a b&c", 3);
        assert_eq!(
            url,
            "https://vali.test/v1/lifecycle/stopped?vm_id=vm%2Fa%20b%26c&generation=3"
        );
    }

    #[test]
    fn sign_only_swallows_an_unreachable_vali() {
        // Fail-closed audit: a push miss must NOT abort (systemd's
        // shutdown proceeds regardless). The function returns `()`.
        let http = RecordingHttp::unreachable();
        run_eol_sign_only(Some(key()), &params(), "https://vali.test", &http);
        assert_eq!(http.post_count.get(), 1, "the push was attempted");
    }

    #[test]
    fn sign_only_with_no_key_skips_the_push() {
        let http = RecordingHttp::responding(200);
        run_eol_sign_only(None, &params(), "https://vali.test", &http);
        assert_eq!(http.post_count.get(), 0, "no key ⇒ no push");
    }
}
