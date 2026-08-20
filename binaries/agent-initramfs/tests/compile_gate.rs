//! Compile-gate + structural coverage for the §21 pipeline shape.
//!
//! NOT a functional test — `/dev/sev-guest`, the KBS, and `cryptsetup`
//! are unreachable from `cargo test`. The job is to pin the pipeline
//! shape (types, ordering, error propagation, secret-ownership
//! discipline, REPORT_DATA layout) so the remaining stage PRs can
//! replace each body without churning the orchestration.
//!
//! ## PR-E1.5 update
//!
//! PR-E1.5 implemented the final stages — `NoCloudSeed` (behind a
//! `SeedWriter` trait) and `SwitchRoot` (behind a `RootfsPivot` trait).
//! Every §21 stage is now real: there is no stub left. The shape tests
//! below pin the §21 order and the §20 by-value secret-ownership
//! signatures; the end-to-end behaviour lives in `kbs_integration.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // The `verify_and_unwrap` signature has seven parameters — pinning
    // it via a `fn(...)` cast is exactly the type-complexity the lint
    // flags. The verbosity is load-bearing: it enforces the §20
    // wipe-before-pivot discipline (`keys: Ephemeral` BY VALUE) at
    // compile time.
    clippy::type_complexity
)]

use hippius_agent_initramfs::pipeline::SECTION_21_ORDER;
use hippius_agent_initramfs::stages::kbs_client::KbsNonce;
use hippius_agent_initramfs::stages::{
    keygen, seed,
    snp_report::{self, MockSnpReportProvider, ReportData, SnpReportProvider, SNP_REPORT_LEN},
    switch_root,
    ticket::Ticket,
    unlock::{self, LuksUnlocker, MockLuksUnlocker},
    verify,
    verity::{self, MockRootfsVerity, RootfsVerity},
};
use hippius_agent_initramfs::{run, AgentError, Config, HttpClient, HttpResponse, Stage};

/// A no-op [`HttpClient`] for the `run` shape tests. `run` aborts at
/// the ticket-load stage (the skeleton `Config` has an empty
/// `ticket_path`) long before the KBS transport is touched, so this is
/// never actually called.
struct NoopHttp;

impl HttpClient for NoopHttp {
    fn post_cbor(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse, AgentError> {
        Err(AgentError::Kbs("noop-http-unreached"))
    }
}

#[test]
fn pipeline_aborts_when_the_ticket_is_missing() {
    // §21 ordering: ticket-load (step 0) runs BEFORE the X25519 keygen
    // and the KBS transport. The skeleton `Config` has an empty
    // `ticket_path`, so `run` fails closed at `ticket::load` with an
    // `AgentError::Ticket` — and the SNP provider is NEVER invoked.
    let cfg = Config::from_skeleton_defaults();
    let provider = MockSnpReportProvider::with_zeroed_response();
    let unlocker = MockLuksUnlocker::new();
    let verity_opener = MockRootfsVerity::ok();
    let seed_writer = seed::MockSeedWriter::new();
    let pivot = switch_root::MockRootfsPivot::new();
    match run(
        &cfg,
        &provider,
        &NoopHttp,
        &unlocker,
        &verity_opener,
        &seed_writer,
        &pivot,
    ) {
        Err(AgentError::Ticket(_)) => {}
        Err(other) => panic!("expected Ticket(_) abort at step 0, got {other:?}"),
        Ok(()) => panic!("pipeline returned Ok with a skeleton config"),
    }
    assert!(
        seed_writer.last_call().is_none(),
        "seed writer invoked before ticket-load — §21 ordering broken"
    );
    assert!(
        pivot.last_device().is_none(),
        "rootfs pivot invoked before ticket-load — §21 ordering broken"
    );
    assert!(
        provider.captured_report_data().is_none(),
        "SNP provider invoked before ticket-load — §21 ordering broken"
    );
}

#[test]
fn section_21_order_matches_pinned_const() {
    // The agreed §21 step order. A future PR reordering / adding /
    // removing a stage must touch this assertion AND the array in the
    // same diff.
    assert_eq!(
        SECTION_21_ORDER,
        [
            Stage::LoadTicket,
            Stage::Keygen,
            Stage::NonceFetch,
            Stage::SnpReport,
            Stage::KbsRelease,
            Stage::VerifyRelease,
            Stage::LuksUnlock,
            Stage::OpenRootfsVerity,
            Stage::NoCloudSeed,
            Stage::SwitchRoot,
        ]
    );
}

#[test]
fn stage_signatures_pin_secret_ownership() {
    // §20 wipe-before-pivot. The secret-bearing stages take their
    // secret BY VALUE so the `Zeroizing` Drop fires before
    // `switch_root`'s `execve(2)` (which bypasses destructors). Pinned
    // via `as fn(...)` casts — a future PR that softened any of these
    // to a `&` reference would fail to type-check HERE, not silently
    // leave a secret live in guest RAM across the pivot.
    //
    // `verify_and_unwrap` consumes `Ephemeral` (the X25519 scalar);
    // `open_luks` + `write_nocloud` consume `Zeroizing<Vec<u8>>` (the
    // LUKS key / the cloud-init plaintext).
    let _: fn(
        &hippius_types::release::SignedResponse,
        keygen::Ephemeral,
        &KbsNonce,
        &Ticket,
        &[u8; 48],
        &[u8; 32],
        &[u8],
    ) -> Result<hippius_guest::UnwrappedSecrets, AgentError> = verify::verify_and_unwrap;
    let _: fn(&dyn LuksUnlocker, &str, zeroize::Zeroizing<Vec<u8>>) -> Result<(), AgentError> =
        unlock::open_luks;
    let _: fn(&dyn seed::SeedWriter, &str, zeroize::Zeroizing<Vec<u8>>) -> Result<(), AgentError> =
        seed::write_nocloud;

    // `switch_root::pivot` takes NO secret input — by the time the
    // pipeline reaches it every `Zeroizing` buffer has already been
    // consumed + wiped by an earlier stage, so the `execve(2)` bypass
    // of `Drop` is safe. Pin that it takes only the pivot impl + the
    // PivotConfig.
    let _: fn(&dyn switch_root::RootfsPivot, &switch_root::PivotConfig) -> Result<(), AgentError> =
        switch_root::pivot;

    // `verity::open_rootfs` likewise carries no secret — the dm-verity
    // root hash is an integrity anchor (covered by the launch digest),
    // not a confidentiality key. Pin its shape so a refactor that
    // accidentally threaded a secret here would fail the type-check.
    let _: fn(&dyn RootfsVerity, &str, &str, &[u8]) -> Result<(), AgentError> = verity::open_rootfs;
}

#[test]
fn final_stages_are_real_not_stubs() {
    // PR-E1.5: `NoCloudSeed` + `SwitchRoot` are implemented. Driving
    // them through their mocks must NOT return `AgentError::Todo` — a
    // regression to a stub body would surface here.
    let writer = seed::MockSeedWriter::new();
    seed::write_nocloud(
        &writer,
        "/run/seed/nocloud-net",
        zeroize::Zeroizing::new(Vec::new()),
    )
    .expect("the NoCloud seed stage is implemented");
    let pivot = switch_root::MockRootfsPivot::new();
    let pivot_cfg = switch_root::PivotConfig {
        rootfs_device: "/dev/mapper/hippius-rootfs".to_string(),
        mode: switch_root::PivotMode::ManagedRootfs,
    };
    switch_root::pivot(&pivot, &pivot_cfg).expect("the switch_root stage is implemented");
}

#[test]
fn report_data_pins_section_20_layout() {
    // §20 byte-exact: REPORT_DATA[0..32] = KBS_nonce,
    // REPORT_DATA[32..64] = X25519 pub. Nonuniform patterns so an
    // off-by-one, a swap, or a same-byte fill all surface distinctly.
    let mut nonce = [0u8; 32];
    let mut pk = [0u8; 32];
    for i in 0..32 {
        nonce[i] = i as u8; // 0x00..0x1F
        pk[i] = 0x80 | (i as u8); // 0x80..0x9F (disjoint from nonce)
    }
    let rd = snp_report::report_data(&nonce, &pk);
    let bytes = rd.as_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..32], &nonce[..]);
    assert_eq!(&bytes[32..], &pk[..]);
    assert_eq!(bytes[31], 0x1F);
    assert_eq!(bytes[32], 0x80);
}

#[test]
fn report_data_constructor_is_pubcrate() {
    // §20 layout is the single grep target: `ReportData`'s constructor
    // is `pub(crate)`, so this `tests/` crate can only obtain one via
    // `snp_report::report_data` — the layout helper.
    let rd: ReportData = snp_report::report_data(&[0u8; 32], &[1u8; 32]);
    let _bytes: &[u8; 64] = rd.as_bytes();
}

#[test]
fn snp_provider_receives_section_20_layout_through_request() {
    let provider = MockSnpReportProvider::with_zeroed_response();
    let nonce: [u8; 32] = core::array::from_fn(|i| (i * 3) as u8);
    let pk: [u8; 32] = core::array::from_fn(|i| 0xC0 | (i as u8));
    let report = snp_report::request(&provider, &nonce, &pk).unwrap();
    assert_eq!(report.0.len(), SNP_REPORT_LEN);
    let captured = provider
        .captured_report_data()
        .expect("provider invoked once");
    assert_eq!(&captured[..32], &nonce);
    assert_eq!(&captured[32..], &pk);
}

#[test]
fn keygen_produces_real_x25519_keypair() {
    let k1 = keygen::generate_ephemeral().unwrap();
    let k2 = keygen::generate_ephemeral().unwrap();
    assert_eq!(k1.public_bytes().len(), 32);
    assert_ne!(k1.public_bytes(), k2.public_bytes());
}

#[test]
fn snp_report_provider_trait_is_object_safe() {
    // §21 `run` takes `&dyn SnpReportProvider` — a future non-object-
    // safe method would break this cast here instead of at a call site.
    let provider: Box<dyn SnpReportProvider> =
        Box::new(MockSnpReportProvider::with_zeroed_response());
    let rd = snp_report::report_data(&[0u8; 32], &[0u8; 32]);
    let report = provider.get_report(rd).unwrap();
    assert_eq!(report.0.len(), SNP_REPORT_LEN);
}

#[test]
fn http_client_trait_is_object_safe() {
    // PR-E1.3 `run` takes `&dyn HttpClient` — pin object-safety here.
    let http: Box<dyn HttpClient> = Box::new(NoopHttp);
    assert!(http.post_cbor("https://kbs.invalid", &[]).is_err());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn sev_guest_provider_impl_is_present_on_linux_x86_64() {
    use hippius_agent_initramfs::SevGuestProvider;
    let provider = SevGuestProvider::new();
    let _: &dyn SnpReportProvider = &provider;
    let _ = provider;
}

#[cfg(target_os = "linux")]
#[test]
fn real_luks_unlocker_impl_is_present_on_linux() {
    // The Linux-only `RealLuksUnlocker` MUST implement `LuksUnlocker` —
    // a refactor dropping the `impl` would break this `&dyn` coercion.
    // The macOS dev loop never compiles `RealLuksUnlocker`, so this is
    // the only automated guard that the real impl is present and
    // object-safe. Parallels `sev_guest_provider_impl_is_present_*`.
    use hippius_agent_initramfs::RealLuksUnlocker;
    let unlocker = RealLuksUnlocker::new();
    let _: &dyn LuksUnlocker = &unlocker;
    let _ = unlocker;
}

#[test]
fn agent_error_class_is_static_str() {
    // §20 logging discipline: `main` only ever logs via
    // `AgentError::class()`, which returns `&'static str`. Pin every
    // variant so a future variant carrying plaintext can't slip
    // through without updating both `class()` and this test.
    let cases: &[(AgentError, &'static str)] = &[
        (AgentError::Todo(Stage::Keygen), "stage-not-implemented"),
        (AgentError::SnpDevice("open-failed"), "snp-device-failed"),
        (AgentError::Ticket("read"), "ticket-failed"),
        (AgentError::Kbs("timeout"), "kbs-failed"),
        (AgentError::KbsDenial, "kbs-denial"),
        (AgentError::Verify("pinned-vk-decode"), "verify-failed"),
        (AgentError::Luks("activate"), "luks-failed"),
        (AgentError::Seed("not-tmpfs"), "seed-failed"),
        (AgentError::SwitchRoot("mount-rootfs"), "switch-root-failed"),
        (AgentError::Hardening("debug-shell"), "hardening-failed"),
        (AgentError::Eol("luks-close"), "eol-failed"),
    ];
    for (err, want) in cases {
        let class: &'static str = err.class();
        assert_eq!(class, *want);
    }

    // The closed-classifier variants — those carrying a `&'static str`
    // tag or no payload — have a `Display` that emits ONLY the fixed
    // tag (no `{0}` interpolation), so even an accidental
    // `eprintln!("{err}")` cannot splice plaintext. (`Todo` renders
    // the finite `Stage` enum, `Guest` the audited `GuestError` — both
    // safe but not equal to `class()`, so they are excluded here.)
    assert_eq!(
        AgentError::SnpDevice("open-failed").to_string(),
        "snp-device-failed"
    );
    assert_eq!(AgentError::Ticket("read").to_string(), "ticket-failed");
    assert_eq!(AgentError::Kbs("timeout").to_string(), "kbs-failed");
    assert_eq!(AgentError::KbsDenial.to_string(), "kbs-denial");
    assert_eq!(
        AgentError::Verify("pinned-vk-decode").to_string(),
        "verify-failed"
    );
    assert_eq!(AgentError::Luks("activate").to_string(), "luks-failed");
    assert_eq!(AgentError::Seed("not-tmpfs").to_string(), "seed-failed");
    assert_eq!(
        AgentError::SwitchRoot("mount-rootfs").to_string(),
        "switch-root-failed"
    );
    assert_eq!(
        AgentError::Hardening("debug-shell").to_string(),
        "hardening-failed"
    );
    assert_eq!(AgentError::Eol("luks-close").to_string(), "eol-failed");
}
