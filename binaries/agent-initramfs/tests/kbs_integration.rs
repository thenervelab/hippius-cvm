//! PR-E1.3 — KBS HTTP client + verify-and-unwrap integration tests.
//!
//! Drives the production `kbs_client` + `verify` stages against a
//! `MockKbsService` — a [`HttpClient`] that returns canned,
//! **validly signed + HPKE-wrapped** release responses, minted with
//! the same `kbs-core` primitives a real KBS uses. No network, no
//! `/dev/sev-guest`, no `cryptsetup`.
//!
//! Proven here:
//! 1. A full release loop — `ticket::load` → `kbs_client::fetch_nonce`
//!    → `kbs_client::release` → `verify::verify_and_unwrap` — recovers
//!    the exact LUKS + user-data plaintexts the mock KBS sealed.
//! 2. A KBS denial (HTTP 403) is surfaced as the terminal
//!    [`AgentError::KbsDenial`].
//! 3. A signed-but-mismatched response (wrong `vm_id`) is rejected by
//!    the §6/§7/§19/§20 binding gate — fail-closed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder};
use ed25519_dalek::SigningKey;
use hippius_agent_initramfs::stages::{kbs_client, snp_report, ticket, verify};
use hippius_agent_initramfs::{
    run, AgentError, Config, HandoffMode, HttpClient, HttpResponse, KbsNonce, MockLuksUnlocker,
    MockRootfsPivot, MockRootfsVerity, MockSeedWriter, PivotMode, ReportData, SnpReport,
    SnpReportProvider,
};
use hippius_types::cbor::to_canonical_vec;
use hippius_types::digest::userdata_digest;
use hippius_types::release::{
    KbsResponse, ReleaseContext, SignedResponse, HPKE_SUITE_ID, RELEASE_DOMAIN,
};

// ── Fixed test parameters (the OrderTicket + ExpectedRelease bindings) ──

// #312 — v2 carries `flavor: Flavor` in place of v1's
// `resource_class: String`. Wire-bytes change because
// `Value::Text("flavor") != Value::Text("resource_class")`.
const SCHEMA_V: u32 = 2;
const TICKET_ID: &str = "tk-e1.3-test";
const TENANT_ID: &str = "tenant-a";
const VM_ID: &str = "vm-abc";
const VM_GENERATION: u64 = 7;
const LUKS_PATH: &str = "kbs/vm/vm-abc/luks";
const LUKS_VERSION: u64 = 3;
const USERDATA_PATH: &str = "kbs/vm/vm-abc/userdata";
const USERDATA_VERSION: u64 = 2;
const KBS_KID: &[u8] = b"kbs-test-kid";
const KBS_URL: &str = "https://kbs.test";

fn measurement() -> [u8; 48] {
    [0x33u8; 48]
}
fn kbs_nonce() -> [u8; 32] {
    [0x22u8; 32]
}
fn luks_plaintext() -> Vec<u8> {
    b"luks-key-material-0123456789abcdef".to_vec()
}
fn userdata_plaintext() -> Vec<u8> {
    b"#cloud-config\nhostname: vm-abc\n".to_vec()
}

/// SHA-256 the §6/§19 spec pins over the user-data plaintext. The
/// OrderTicket's `allowed_userdata_digest` AND the KBS response's must
/// both equal this — and `verify_and_unwrap_release` recomputes it
/// over the unwrapped plaintext as the last line of defence.
fn pinned_digest() -> [u8; 32] {
    userdata_digest(
        TENANT_ID,
        VM_ID,
        TICKET_ID,
        "userdata",
        USERDATA_PATH,
        USERDATA_VERSION,
        &userdata_plaintext(),
    )
}

// ── Mint a COSE_Sign1 OrderTicket ──────────────────────────────────

/// Hand-build the `OrderTicket` CBOR map (the type is decode-only, so
/// the minter side builds the CBOR directly — same as L1 does).
fn order_ticket_cbor(digest: &[u8; 32]) -> Vec<u8> {
    let vault_ref = |path: &str, version: u64| {
        Value::Map(vec![
            (Value::Text("path".into()), Value::Text(path.into())),
            (
                Value::Text("version".into()),
                Value::Integer(version.into()),
            ),
        ])
    };
    let ticket = Value::Map(vec![
        (
            Value::Text("v".into()),
            Value::Integer(u64::from(SCHEMA_V).into()),
        ),
        (
            Value::Text("ticket_id".into()),
            Value::Text(TICKET_ID.into()),
        ),
        (
            Value::Text("issue_time".into()),
            Value::Integer(1_700_000_000u64.into()),
        ),
        (
            Value::Text("expiry".into()),
            Value::Integer(1_700_086_400u64.into()),
        ),
        (Value::Text("nonce".into()), Value::Bytes(vec![0x11u8; 16])),
        (
            Value::Text("tenant_id".into()),
            Value::Text(TENANT_ID.into()),
        ),
        (Value::Text("user_id".into()), Value::Text("user-x".into())),
        (Value::Text("vm_id".into()), Value::Text(VM_ID.into())),
        (
            Value::Text("lease_id".into()),
            Value::Text("lease-1".into()),
        ),
        (
            Value::Text("vm_generation".into()),
            Value::Integer(VM_GENERATION.into()),
        ),
        (Value::Text("node_id".into()), Value::Text("node-1".into())),
        (
            Value::Text("platform_id".into()),
            Value::Text("milan".into()),
        ),
        (
            Value::Text("allowed_measurements".into()),
            Value::Array(vec![Value::Bytes(measurement().to_vec())]),
        ),
        (
            Value::Text("userdata_vault_ref".into()),
            vault_ref(USERDATA_PATH, USERDATA_VERSION),
        ),
        (
            Value::Text("luks_vault_ref".into()),
            vault_ref(LUKS_PATH, LUKS_VERSION),
        ),
        (
            Value::Text("allowed_userdata_digest".into()),
            Value::Bytes(digest.to_vec()),
        ),
        (Value::Text("flavor".into()), Value::Text("small".into())),
        (
            Value::Text("lifecycle_perms".into()),
            Value::Array(vec![Value::Text("start".into())]),
        ),
    ]);
    to_canonical_vec(&ticket).unwrap()
}

/// Wrap an OrderTicket payload in a COSE_Sign1 envelope. The agent
/// does NOT verify the L1 signature, so a builder with no real
/// signature is enough to exercise the decode path.
fn cose_ticket(digest: &[u8; 32]) -> Vec<u8> {
    CoseSign1Builder::new()
        .payload(order_ticket_cbor(digest))
        .build()
        .to_vec()
        .unwrap()
}

// ── Mint a signed + HPKE-wrapped KBS release response ──────────────

fn release_ctx<'a>(
    secret_type: &'a str,
    secret_path: &'a str,
    secret_version: u64,
    nonce: &'a [u8; 32],
    meas: &'a [u8; 48],
    digest: &'a [u8; 32],
    vm_id: &'a str,
) -> ReleaseContext<'a> {
    ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id,
        vm_generation: VM_GENERATION,
        kbs_nonce: nonce,
        measurement: meas,
        kbs_kid: KBS_KID,
        secret_type,
        secret_path,
        secret_version,
        allowed_userdata_digest: digest,
    }
}

/// Mint a `SignedResponse` exactly as a real KBS would: HPKE-wrap both
/// secrets to the guest pubkey, build the `KbsResponse`, Ed25519-sign
/// it. `vm_id` is a parameter so a test can mint a *mismatched*
/// response (binding-rejection coverage).
fn mint_signed_response(kbs_sk: &SigningKey, guest_pub: &[u8; 32], vm_id: &str) -> SignedResponse {
    let nonce = kbs_nonce();
    let meas = measurement();
    let digest = pinned_digest();

    let luks_ctx = release_ctx(
        "luks",
        LUKS_PATH,
        LUKS_VERSION,
        &nonce,
        &meas,
        &digest,
        vm_id,
    );
    let ud_ctx = release_ctx(
        "userdata",
        USERDATA_PATH,
        USERDATA_VERSION,
        &nonce,
        &meas,
        &digest,
        vm_id,
    );
    let luks = kbs_core::crypto::hpke_wrap(guest_pub, &luks_plaintext(), &luks_ctx).unwrap();
    let userdata = kbs_core::crypto::hpke_wrap(guest_pub, &userdata_plaintext(), &ud_ctx).unwrap();

    let response = KbsResponse {
        domain: RELEASE_DOMAIN.to_string(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.to_string(),
        tenant_id: TENANT_ID.to_string(),
        vm_id: vm_id.to_string(),
        vm_generation: VM_GENERATION,
        kbs_nonce: nonce.to_vec(),
        measurement: meas.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: digest.to_vec(),
        luks: Some(luks),
        userdata,
        lifecycle_key: None,
        boot_counter: 0,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
        volume_stamp_transition: None,
        cdn_fleet: None,
    };
    kbs_core::crypto::sign_response(kbs_sk, &response).unwrap()
}

/// Canonical-CBOR encode a `SignedResponse` for the HTTP body.
fn signed_response_body(signed: &SignedResponse) -> Vec<u8> {
    to_canonical_vec(&Value::serialized(signed).unwrap()).unwrap()
}

/// Canonical-CBOR `{nonce: bstr}` — the `/v1/kbs/nonce` response body.
fn nonce_body(nonce: &[u8; 32]) -> Vec<u8> {
    to_canonical_vec(&Value::Map(vec![(
        Value::Text("nonce".into()),
        Value::Bytes(nonce.to_vec()),
    )]))
    .unwrap()
}

// ── The MockKbsService ─────────────────────────────────────────────

/// A canned-response KBS. Routes on the request path: `/v1/kbs/nonce`
/// returns the nonce body; `/v1/kbs/release` returns `release_status`
/// + `release_body`.
struct MockKbsService {
    nonce_body: Vec<u8>,
    release_status: u16,
    release_body: Vec<u8>,
}

impl HttpClient for MockKbsService {
    fn post_cbor(&self, url: &str, _body: &[u8]) -> Result<HttpResponse, AgentError> {
        if url.ends_with("/v1/kbs/nonce") {
            Ok(HttpResponse {
                status: 200,
                body: self.nonce_body.clone(),
            })
        } else if url.ends_with("/v1/kbs/release") {
            Ok(HttpResponse {
                status: self.release_status,
                body: self.release_body.clone(),
            })
        } else {
            Err(AgentError::Kbs("mock-unknown-route"))
        }
    }
}

/// Build the 1184-byte mock SNP report with the test measurement
/// planted at the §20 offset (`0x90..0xC0`).
fn snp_report_with_measurement() -> SnpReport {
    let mut bytes = vec![0u8; hippius_agent_initramfs::SNP_REPORT_LEN];
    bytes[0x90..0x90 + 48].copy_from_slice(&measurement());
    SnpReport(bytes)
}

/// Write a COSE ticket to a temp file and `ticket::load` it — exercises
/// the real `LoadTicket` file path.
fn load_ticket(cose: &[u8]) -> hippius_agent_initramfs::Ticket {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.cose");
    std::fs::write(&path, cose).unwrap();
    ticket::load(path.to_str().unwrap()).unwrap()
}

// ── Tests ──────────────────────────────────────────────────────────

#[test]
fn full_release_loop_recovers_the_sealed_secrets() {
    let kbs_sk = SigningKey::from_bytes(&[7u8; 32]);
    let kbs_vk = kbs_sk.verifying_key().to_bytes();

    // Guest keypair — the response is HPKE-wrapped to this pubkey.
    let keys = hippius_agent_initramfs::stages::keygen::generate_ephemeral().unwrap();
    let guest_pub = *keys.public_bytes();

    let digest = pinned_digest();
    let signed = mint_signed_response(&kbs_sk, &guest_pub, VM_ID);
    let mock = MockKbsService {
        nonce_body: nonce_body(&kbs_nonce()),
        release_status: 200,
        release_body: signed_response_body(&signed),
    };

    // Drive the production stages.
    let ticket = load_ticket(&cose_ticket(&digest));
    let nonce = kbs_client::fetch_nonce(&mock, KBS_URL).unwrap();
    assert_eq!(nonce.0, kbs_nonce(), "nonce round-trips through the client");

    let report = snp_report_with_measurement();
    let meas = snp_report::measurement(&report).unwrap();
    assert_eq!(meas, measurement());

    let signed_resp =
        kbs_client::release(&mock, KBS_URL, ticket.cose_bytes(), &nonce, &report, None).unwrap();

    let secrets =
        verify::verify_and_unwrap(&signed_resp, keys, &nonce, &ticket, &meas, &kbs_vk, KBS_KID)
            .expect("a valid signed response must verify + unwrap");

    // The exact plaintexts the mock KBS sealed come back out.
    assert_eq!(&secrets.luks.as_deref().unwrap()[..], &luks_plaintext()[..]);
    assert_eq!(&secrets.userdata[..], &userdata_plaintext()[..]);
}

#[test]
fn a_kbs_denial_is_terminal() {
    // HTTP 403 ⇒ the KBS evaluated the request and said no. The client
    // surfaces the terminal `KbsDenial` — no retry, the agent aborts.
    let mock = MockKbsService {
        nonce_body: nonce_body(&kbs_nonce()),
        release_status: 403,
        release_body: b"a-signed-denial".to_vec(),
    };
    let report = snp_report_with_measurement();
    let err = kbs_client::release(
        &mock,
        KBS_URL,
        b"cose-ticket-bytes",
        &KbsNonce(kbs_nonce()),
        &report,
        None,
    )
    .expect_err("a 403 must not yield Ok");
    assert!(matches!(err, AgentError::KbsDenial));
    assert_eq!(err.class(), "kbs-denial");
}

#[test]
fn a_signed_but_mismatched_response_is_rejected_by_the_binding_gate() {
    // The response is validly SIGNED by the pinned KBS key, but its
    // `vm_id` does not match the ticket. `verify_and_unwrap_release`
    // must fail closed at the binding check — before any HPKE unwrap.
    let kbs_sk = SigningKey::from_bytes(&[7u8; 32]);
    let kbs_vk = kbs_sk.verifying_key().to_bytes();
    let keys = hippius_agent_initramfs::stages::keygen::generate_ephemeral().unwrap();
    let guest_pub = *keys.public_bytes();

    let digest = pinned_digest();
    // Minted with the WRONG vm_id.
    let signed = mint_signed_response(&kbs_sk, &guest_pub, "vm-WRONG");
    let mock = MockKbsService {
        nonce_body: nonce_body(&kbs_nonce()),
        release_status: 200,
        release_body: signed_response_body(&signed),
    };

    let ticket = load_ticket(&cose_ticket(&digest));
    let nonce = kbs_client::fetch_nonce(&mock, KBS_URL).unwrap();
    let report = snp_report_with_measurement();
    let meas = snp_report::measurement(&report).unwrap();
    let signed_resp =
        kbs_client::release(&mock, KBS_URL, ticket.cose_bytes(), &nonce, &report, None).unwrap();

    let err =
        verify::verify_and_unwrap(&signed_resp, keys, &nonce, &ticket, &meas, &kbs_vk, KBS_KID)
            .expect_err("a mismatched vm_id must fail the binding gate");
    // The agent wraps the library's rejection as a release-rejected.
    assert!(matches!(err, AgentError::Guest(_)));
    assert_eq!(err.class(), "release-rejected");
}

// ── PR-E1.5 — the full `run` pipeline reaches `switch_root` ─────────

/// A `SnpReportProvider` that splices the §20 `REPORT_DATA` it is
/// handed into a well-formed 1184-byte report — REPORT_DATA at `0x50`,
/// `measurement()` at `0x90`. Unlike `MockSnpReportProvider` (fixed
/// canned bytes), this lets a downstream mock KBS recover the guest
/// pubkey `run` generates *internally*, so a full-pipeline test is
/// possible without injecting the keygen (§20 keeps keygen in `run`).
struct EchoingSnpProvider;

impl SnpReportProvider for EchoingSnpProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport, AgentError> {
        let mut bytes = vec![0u8; hippius_agent_initramfs::SNP_REPORT_LEN];
        // REPORT_DATA occupies 0x50..0x90; MEASUREMENT the 48 bytes at
        // 0x90 (AMD SEV-SNP ABI — same offsets `snp_report` pins).
        bytes[0x50..0x90].copy_from_slice(report_data.as_bytes());
        bytes[0x90..0x90 + 48].copy_from_slice(&measurement());
        Ok(SnpReport(bytes))
    }
}

/// A mock KBS that — like a real KBS — HPKE-wraps the release response
/// to the *actual* guest pubkey carried in the SNP report, then signs
/// it. Necessary because `run` generates its X25519 keypair internally:
/// the response cannot be pre-canned for an unknown pubkey.
struct WrappingMockKbs {
    kbs_sk: SigningKey,
}

impl HttpClient for WrappingMockKbs {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        if url.ends_with("/v1/kbs/nonce") {
            return Ok(HttpResponse {
                status: 200,
                body: nonce_body(&kbs_nonce()),
            });
        }
        if url.ends_with("/v1/kbs/release") {
            // Pull the guest pubkey out of REPORT_DATA[32..64] — i.e.
            // report bytes 0x70..0x90 — inside the posted SNP report.
            let value: Value = ciborium::de::from_reader(body).expect("release request CBOR");
            let Value::Map(entries) = value else {
                panic!("release request is not a map");
            };
            let snp_report = entries
                .iter()
                .find_map(|(k, v)| match (k, v) {
                    (Value::Text(t), Value::Bytes(b)) if t == "snp_report" => Some(b.clone()),
                    _ => None,
                })
                .expect("release request carries an snp_report field");
            let guest_pub: [u8; 32] = snp_report[0x70..0x90]
                .try_into()
                .expect("32-byte guest pubkey in REPORT_DATA");
            let signed = mint_signed_response(&self.kbs_sk, &guest_pub, VM_ID);
            return Ok(HttpResponse {
                status: 200,
                body: signed_response_body(&signed),
            });
        }
        Err(AgentError::Kbs("mock-unknown-route"))
    }
}

#[test]
fn run_drives_the_full_pipeline_to_switch_root() {
    // End-to-end `pipeline::run`: every §21 stage — ticket → keygen →
    // nonce → SNP report → KBS release → verify+unwrap → LUKS unlock →
    // NoCloud seed → switch_root. With mock backends for the
    // OS-effecting tail (LUKS / seed / pivot) the whole sequence
    // completes and the mock pivot returns (a `RealRootfsPivot` would
    // `execve` the guest init and never return). Proves PR-E1.5 wired
    // the `SeedWriter` + `RootfsPivot` into `run` and that each
    // released secret reaches its stage intact.
    let kbs_sk = SigningKey::from_bytes(&[7u8; 32]);
    let kbs_vk = kbs_sk.verifying_key().to_bytes();

    let dir = tempfile::tempdir().unwrap();
    let ticket_path = dir.path().join("order.cose");
    std::fs::write(&ticket_path, cose_ticket(&pinned_digest())).unwrap();

    let mut cfg = Config::from_skeleton_defaults();
    cfg.ticket_path = ticket_path.to_str().unwrap().to_string();
    cfg.kbs_base_url = KBS_URL.to_string();
    cfg.luks_device = "/dev/test-luks".to_string();
    cfg.nocloud_tmpfs_dir = "/run/test-seed/nocloud-net".to_string();
    cfg.rootfs_device = "/dev/mapper/test-rootfs".to_string();
    cfg.pinned_kbs_vk = kbs_vk;
    cfg.pinned_kbs_kid = KBS_KID.to_vec();

    let snp = EchoingSnpProvider;
    let http = WrappingMockKbs { kbs_sk };
    let unlocker = MockLuksUnlocker::new();
    let verity_opener = MockRootfsVerity::ok();
    let seed_writer = MockSeedWriter::new();
    let pivot = MockRootfsPivot::new();

    run(
        &cfg,
        &snp,
        &http,
        &unlocker,
        &verity_opener,
        &seed_writer,
        &pivot,
    )
    .expect("the full pipeline must complete through switch_root");

    // LUKS unlock received the configured backing device and a key of
    // exactly the released LUKS plaintext's length.
    let call = unlocker
        .last_call()
        .expect("open_luks reached the unlocker");
    assert_eq!(call.device, "/dev/test-luks");
    assert_eq!(call.key_len, luks_plaintext().len());

    // The NoCloud seed stage received the configured tmpfs dir and the
    // released user-data plaintext (length only — the mock never copies
    // the bytes out).
    let (seed_dir, ud_len) = seed_writer
        .last_call()
        .expect("write_seed reached the seed writer");
    assert_eq!(seed_dir, "/run/test-seed/nocloud-net");
    assert_eq!(ud_len, userdata_plaintext().len());

    // The switch_root stage received the configured verity-rootfs
    // device — the §21 pivot is wired into `run`.
    assert_eq!(
        pivot.last_device().as_deref(),
        Some("/dev/mapper/test-rootfs")
    );
    // Default `Config::from_skeleton_defaults()` ⇒ `HandoffMode::
    // ManagedRootfs`, so the pivot mode that flowed through MUST be
    // `ManagedRootfs` (and the verity stage WAS reached — its mock
    // recorded a call below).
    let pivot_call = pivot.last_call().expect("pivot received a call");
    assert!(matches!(pivot_call.mode, PivotMode::ManagedRootfs));
    assert!(
        verity_opener.last_call.borrow().is_some(),
        "verity stage must run in ManagedRootfs mode"
    );
}

#[test]
fn run_in_tenant_luks_mode_skips_verity_and_pivots_into_luks_mapper() {
    // #257 BYO base-OS: when `cfg.handoff == TenantLuks`, the §21
    // pipeline MUST skip the dm-verity open stage (the tenant LUKS
    // volume IS the rootfs) and forward `cfg.kernel_release` into
    // the pivot so the real impl can bind-mount the kernel-modules
    // tree on the way through.
    let kbs_sk = SigningKey::from_bytes(&[7u8; 32]);
    let kbs_vk = kbs_sk.verifying_key().to_bytes();

    let dir = tempfile::tempdir().unwrap();
    let ticket_path = dir.path().join("order.cose");
    std::fs::write(&ticket_path, cose_ticket(&pinned_digest())).unwrap();

    let mut cfg = Config::from_skeleton_defaults();
    cfg.ticket_path = ticket_path.to_str().unwrap().to_string();
    cfg.kbs_base_url = KBS_URL.to_string();
    cfg.luks_device = "/dev/test-luks".to_string();
    cfg.nocloud_tmpfs_dir = "/run/test-seed/nocloud-net".to_string();
    cfg.handoff = HandoffMode::TenantLuks;
    cfg.kernel_release = "6.12.63+deb13-amd64".to_string();
    cfg.rootfs_device = "/dev/mapper/hippius-data".to_string();
    cfg.pinned_kbs_vk = kbs_vk;
    cfg.pinned_kbs_kid = KBS_KID.to_vec();

    let snp = EchoingSnpProvider;
    let http = WrappingMockKbs { kbs_sk };
    let unlocker = MockLuksUnlocker::new();
    // `failing` so a regression that DID call verity in TenantLuks
    // mode would fail-close visibly instead of being a silent waste.
    let verity_opener = MockRootfsVerity::failing("must-not-be-called");
    let seed_writer = MockSeedWriter::new();
    let pivot = MockRootfsPivot::new();

    run(
        &cfg,
        &snp,
        &http,
        &unlocker,
        &verity_opener,
        &seed_writer,
        &pivot,
    )
    .expect("TenantLuks pipeline must complete (verity skipped)");

    // Verity opener MUST NOT have been called — TenantLuks bypasses it.
    assert!(
        verity_opener.last_call.borrow().is_none(),
        "verity stage must be skipped in TenantLuks mode"
    );

    // Pivot received the LUKS mapper as rootfs + the kernel release
    // for the modules bind-mount.
    let pivot_call = pivot.last_call().expect("pivot received a call");
    assert_eq!(pivot_call.rootfs_device, "/dev/mapper/hippius-data");
    match pivot_call.mode {
        PivotMode::TenantLuks { kernel_release } => {
            assert_eq!(kernel_release, "6.12.63+deb13-amd64");
        }
        PivotMode::ManagedRootfs => panic!("expected TenantLuks mode in pivot config"),
    }
}
