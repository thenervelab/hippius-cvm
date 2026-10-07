//! Customer-held keys, end to end inside `run_with`.
//!
//! A fake miner relay and guardian (Ed25519-signed with a test `GK`,
//! HPKE-sealed with the real §20 suite) and a fake KBS (signed with a
//! test KBS key) are driven through the production guardian leg, KBS
//! leg and combine.
//!
//! The load-bearing claims:
//! - M1/M2 emit exactly the `combine_kek` known answers (the shares are
//!   the hippius-types KAT inputs);
//! - the guardian leg runs to completion BEFORE the first KBS request,
//!   and a guardian that is down, forged, replayed or wrong keeps the
//!   guest waiting with ZERO KBS requests;
//! - `erased` (signed, for THIS request) is the only terminal answer;
//! - M0 never talks to the guardian and emits the KBS KEK verbatim.

use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use coset::{CborSerializable, CoseSign1Builder};
use ed25519_dalek::{Signer, SigningKey};
use hippius_agent_initramfs::{HttpResponse, ReportData, SnpReport, SNP_REPORT_LEN};
use hippius_types::digest::userdata_digest;
use hippius_types::guardian::{
    decode_canonical, guest_pub_hash, relay_answer, signing_input, stamp_token_hash,
    GuardianDenial, GuardianDenyReason, GuardianNonceRequest, GuardianNonceResponse,
    GuardianReleaseRequest, GuardianResponse, GuardianStampAck, GuardianWrapped, LaunchRecipe,
    SignedGuardianDenial, SignedGuardianResponse, SignedGuardianStampAck, DENY_SIG_DOMAIN,
    GUARDIAN_NONCE_PATH, GUARDIAN_RECIPE_PATH, GUARDIAN_RELEASE_PATH, RESP_SIG_DOMAIN,
    SHARE_HPKE_INFO, STAMP_ACK_SIG_DOMAIN, STAMP_TOKEN_HPKE_INFO,
};
use hippius_types::release::{
    KbsResponse, ReleaseContext, VolumeStampTransition, HPKE_SUITE_ID, RELEASE_DOMAIN,
    RELEASE_DOMAIN_V2,
};

// ── the hippius-types combine KAT inputs ─────────────────────────────
const VM_ID: &str = "vm-kat-kek-01";
const M1_KAT: &str = "00f85e62c082cbc12fae9469acef40f60643eac3e40a2719c8d004276a70c9bb";
const M2_KAT: &str = "da3400f63de565d42a261b34faf1279b9351cb2e31e11ec3df3476bdf74032b7";
/// `iid-` + sha256("hippius-iid-v1\0" ‖ VM_ID)[..16] as hex — pinned
/// independently of the code (python3 hashlib).
const VM_ID_IID: &str = "iid-3a693f9c2cd7229cb0d0ee2256270777";

fn share_h() -> Vec<u8> {
    (0u8..32).collect()
}
fn share_c() -> [u8; 32] {
    core::array::from_fn(|i| 0xa0 + u8::try_from(i).unwrap())
}

const SCHEMA_V: u32 = 2;
const TICKET_ID: &str = "tk-keyed";
const TENANT_ID: &str = "tenant-k";
const LUKS_PATH: &str = "kbs/vm/vm-kat-kek-01/luks";
const UD_PATH: &str = "kbs/vm/vm-kat-kek-01/userdata";
const KBS_KID: &[u8] = b"kbs-test-kid";
const KBS_URL: &str = "https://kbs.test";
const RELAY_URL: &str = "vsock://2:19271";
const MEAS: [u8; 48] = [0x33; 48];
const KBS_STAMP_E: u64 = 7;
const GUARDIAN_STAMP_E: u64 = 41;
const STAMP_TOKEN: [u8; 32] = [0x7E; 32];

fn userdata() -> Vec<u8> {
    b"#cloud-config\nhostname: keyed\n".to_vec()
}

fn digest() -> [u8; 32] {
    userdata_digest(
        TENANT_ID,
        VM_ID,
        TICKET_ID,
        "userdata",
        UD_PATH,
        1,
        &userdata(),
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn gk() -> SigningKey {
    SigningKey::from_bytes(&[0x61; 32])
}

fn kbs_key() -> SigningKey {
    SigningKey::from_bytes(&[0x62; 32])
}

fn cmdline(mode: Option<KeyMode>, pk: &SigningKey) -> String {
    let mut c = "ro quiet dm-verity.root=00 hippius.disk_gb=10 boot=hippius-golden".to_string();
    if let Some(m) = mode {
        c.push_str(&format!(
            // `100.64.0.9:7443`, hex-encoded (H1b).
            " hippius.key_mode={} hippius.guardian_pk={} \
             hippius.guardian_ep=3130302e36342e302e393a37343433",
            m.as_wire(),
            hex(&pk.verifying_key().to_bytes())
        ));
    }
    c
}

// ── the ticket ───────────────────────────────────────────────────────

fn ticket_file(dir: &std::path::Path, key_mode: Option<&str>) -> std::path::PathBuf {
    let t = |s: &str| Value::Text(s.into());
    let vref = |p: &str| {
        Value::Map(vec![
            (t("path"), t(p)),
            (t("version"), Value::Integer(1u64.into())),
        ])
    };
    let mut entries = vec![
        (t("v"), Value::Integer(u64::from(SCHEMA_V).into())),
        (t("ticket_id"), t(TICKET_ID)),
        (t("issue_time"), Value::Integer(1_700_000_000u64.into())),
        (t("expiry"), Value::Integer(1_700_086_400u64.into())),
        (t("nonce"), Value::Bytes(vec![0x11; 16])),
        (t("tenant_id"), t(TENANT_ID)),
        (t("user_id"), t("user-k")),
        (t("vm_id"), t(VM_ID)),
        (t("lease_id"), t("lease-k")),
        (t("vm_generation"), Value::Integer(1u64.into())),
        (t("node_id"), t("node-k")),
        (t("platform_id"), t("genoa")),
        (
            t("allowed_measurements"),
            Value::Array(vec![Value::Bytes(MEAS.to_vec())]),
        ),
        (t("userdata_vault_ref"), vref(UD_PATH)),
        (t("luks_vault_ref"), vref(LUKS_PATH)),
        (
            t("allowed_userdata_digest"),
            Value::Bytes(digest().to_vec()),
        ),
        (t("flavor"), t("small")),
        (t("lifecycle_perms"), Value::Array(vec![t("start")])),
    ];
    if let Some(m) = key_mode {
        entries.push((t("key_mode"), t(m)));
    }
    let payload = to_canonical_vec(&Value::Map(entries)).unwrap();
    let cose = CoseSign1Builder::new()
        .payload(payload)
        .build()
        .to_vec()
        .unwrap();
    let path = dir.join("ticket.cose");
    std::fs::write(&path, cose).unwrap();
    path
}

// ── the event log every fake appends to ──────────────────────────────

type Log = Rc<RefCell<Vec<String>>>;

// ── SNP ──────────────────────────────────────────────────────────────

/// A report whose `REPORT_DATA` (0x50) and `MEASUREMENT` (0x90) are
/// where the real ABI puts them, so the fakes read the guest key back
/// out of the report exactly like the real verifiers do.
struct FakeSnp;

impl SnpReportProvider for FakeSnp {
    fn get_report(&self, rd: ReportData) -> Result<SnpReport, AgentError> {
        let mut r = vec![0u8; SNP_REPORT_LEN];
        r[0x50..0x90].copy_from_slice(rd.as_bytes());
        r[0x90..0x90 + 48].copy_from_slice(&MEAS);
        Ok(SnpReport(r))
    }
}

// ── KBS ──────────────────────────────────────────────────────────────

/// Which KBS the fake plays, as far as stamp protocol v2 goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KbsKind {
    /// Knows v2: a v2 report gets a V2 response with this transition, a
    /// v1 report the V1 response.
    V2 {
        expected: [u8; 32],
        target: [u8; 32],
    },
    /// Predates v2: a v2 report is not `nonce ‖ pub`, so it is denied
    /// (403) — exactly what the real pre-v2 KBS answers, and what a
    /// miner forging a 403 to the v2 report looks like to the guest.
    Old,
    /// Broken: answers a V1 response even to a v2 report.
    V1Always,
}

struct FakeKbs {
    log: Log,
    calls: Cell<usize>,
    /// The KEK the KBS releases; `None` = a KEK-less (M2) release.
    luks: Option<Vec<u8>>,
    kind: KbsKind,
    /// The stamp protocol each release request's REPORT_DATA attested.
    attested: RefCell<Vec<u8>>,
}

impl FakeKbs {
    fn new(log: &Log, luks: Option<Vec<u8>>) -> Self {
        Self {
            log: log.clone(),
            calls: Cell::new(0),
            luks,
            kind: KbsKind::V2 {
                expected: [0; 32],
                target: [0; 32],
            },
            attested: RefCell::new(Vec::new()),
        }
    }
}

const KBS_NONCE: [u8; 32] = [0x22; 32];

fn ctx<'a>(ty: &'a str, path: &'a str, ver: u64, d: &'a [u8; 32]) -> ReleaseContext<'a> {
    ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: 1,
        kbs_nonce: &KBS_NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        secret_type: ty,
        secret_path: path,
        secret_version: ver,
        allowed_userdata_digest: d,
    }
}

impl HttpClient for FakeKbs {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        self.calls.set(self.calls.get() + 1);
        if url.ends_with("/v1/kbs/nonce") {
            self.log.borrow_mut().push("kbs:nonce".into());
            let b = to_canonical_vec(&Value::Map(vec![(
                Value::Text("nonce".into()),
                Value::Bytes(KBS_NONCE.to_vec()),
            )]))
            .unwrap();
            return Ok(HttpResponse {
                status: 200,
                body: b,
            });
        }
        assert!(url.ends_with("/v1/kbs/release"), "{url}");
        self.log.borrow_mut().push("kbs:release".into());
        let req: Value = ciborium::de::from_reader(body).unwrap();
        let report = req
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("snp_report"))
            .and_then(|(_, v)| v.as_bytes().cloned())
            .unwrap();
        // The KBS layouts: v1 `nonce ‖ guest_pub`, v2
        // `SHA-256(v2 domain ‖ nonce) ‖ guest_pub` — nothing else.
        let bound = &report[0x50..0x70];
        let v2 = if bound == KBS_NONCE {
            false
        } else {
            assert_eq!(
                bound,
                hippius_types::report_data::tenant_stamp_v2_nonce_binding(&KBS_NONCE),
                "KBS report_data layout"
            );
            true
        };
        self.attested.borrow_mut().push(if v2 { 2 } else { 1 });
        if v2 && self.kind == KbsKind::Old {
            return Ok(HttpResponse {
                status: 403,
                body: b"signed-denial".to_vec(),
            });
        }
        let transition = match (v2, self.kind) {
            (true, KbsKind::V2 { expected, target }) => Some((expected, target)),
            _ => None,
        };
        let guest_pub: [u8; 32] = report[0x70..0x90].try_into().unwrap();
        let d = digest();
        let luks = self.luks.as_ref().map(|k| {
            kbs_core::crypto::hpke_wrap(&guest_pub, k, &ctx("luks", LUKS_PATH, 1, &d)).unwrap()
        });
        let ud =
            kbs_core::crypto::hpke_wrap(&guest_pub, &userdata(), &ctx("userdata", UD_PATH, 1, &d))
                .unwrap();
        let token = kbs_core::crypto::hpke_wrap(
            &guest_pub,
            &[0x5A; 32],
            &ctx(
                "volume-stamp-token",
                "kbs/volume-stamp",
                KBS_STAMP_E + 1,
                &d,
            ),
        )
        .unwrap();
        let resp = KbsResponse {
            domain: RELEASE_DOMAIN.into(),
            v: SCHEMA_V,
            ticket_id: TICKET_ID.into(),
            tenant_id: TENANT_ID.into(),
            vm_id: VM_ID.into(),
            vm_generation: 1,
            kbs_nonce: KBS_NONCE.to_vec(),
            measurement: MEAS.to_vec(),
            kbs_kid: KBS_KID.to_vec(),
            hpke_suite_id: HPKE_SUITE_ID,
            allowed_userdata_digest: d.to_vec(),
            luks,
            userdata: ud,
            lifecycle_key: None,
            boot_counter: 3,
            expected_volume_stamp: KBS_STAMP_E,
            volume_stamp_token: Some(token),
            volume_stamp_transition: None,
            cdn_fleet: None,
        };
        let resp = match transition {
            Some((e, t)) => KbsResponse {
                domain: RELEASE_DOMAIN_V2.into(),
                volume_stamp_transition: Some(VolumeStampTransition {
                    expected_timeline_id: e.to_vec(),
                    target_timeline_id: t.to_vec(),
                }),
                ..resp
            },
            None => resp,
        };
        let signed = kbs_core::crypto::sign_response(&kbs_key(), &resp).unwrap();
        Ok(HttpResponse {
            status: 200,
            body: to_canonical_vec(&Value::serialized(&signed).unwrap()).unwrap(),
        })
    }
}

// ── guardian relay + guardian ────────────────────────────────────────

#[derive(Clone)]
enum Answer {
    /// Release `share_C` at `version`.
    Release { version: u32 },
    /// A signed denial for this request.
    Deny(GuardianDenyReason),
    /// The relay could not reach the guardian.
    Down,
}

struct FakeGuardian {
    log: Log,
    calls: Cell<usize>,
    /// One answer per release attempt; the last one repeats.
    answers: RefCell<Vec<Answer>>,
    mode: KeyMode,
    signer: SigningKey,
    /// Tamper the echoed guest key hash (a replayed decision).
    wrong_guest_pub_hash: bool,
    nonce_counter: Cell<u8>,
    last_request: RefCell<Option<GuardianReleaseRequest>>,
    confirms: RefCell<Vec<Vec<u8>>>,
}

impl FakeGuardian {
    fn new(log: &Log, mode: KeyMode, answers: Vec<Answer>) -> Self {
        Self {
            log: log.clone(),
            calls: Cell::new(0),
            answers: RefCell::new(answers),
            mode,
            signer: gk(),
            wrong_guest_pub_hash: false,
            nonce_counter: Cell::new(0),
            last_request: RefCell::new(None),
            confirms: RefCell::new(Vec::new()),
        }
    }

    fn next_answer(&self) -> Answer {
        let mut a = self.answers.borrow_mut();
        if a.len() > 1 {
            a.remove(0)
        } else {
            a[0].clone()
        }
    }
}

fn seal(to: &[u8], pt: &[u8], info: &[u8], aad: &[u8]) -> GuardianWrapped {
    let to: [u8; 32] = to.try_into().unwrap();
    let (enc, ct) = kbs_core::crypto::hpke_seal_raw(&to, pt, info, aad).unwrap();
    GuardianWrapped { enc, ct }
}

fn signed(key: &SigningKey, domain: &[u8], body: Vec<u8>) -> Vec<u8> {
    let sig = key.sign(&signing_input(domain, &body)).to_bytes().to_vec();
    encode_canonical(&SignedGuardianResponse { body, sig }).unwrap()
}

impl HttpClient for FakeGuardian {
    fn post_cbor(&self, url: &str, body: &[u8]) -> Result<HttpResponse, AgentError> {
        self.calls.set(self.calls.get() + 1);
        let path = url.strip_prefix(RELAY_URL).unwrap();
        let ok = |b: Vec<u8>| {
            Ok(HttpResponse {
                status: 200,
                body: b,
            })
        };
        if path == GUARDIAN_RECIPE_PATH {
            self.log.borrow_mut().push("guardian:recipe".into());
            return ok(encode_canonical(&LaunchRecipe {
                ovmf_sha384: vec![1; 48],
                kernel_sha256: vec![2; 32],
                initrd_sha256: vec![3; 32],
                cmdline: cmdline(Some(self.mode), &gk()),
                vcpus: 2,
                vcpu_type: "EpycGenoa".into(),
                guest_features: 1,
            })
            .unwrap());
        }
        if path == GUARDIAN_NONCE_PATH {
            self.log.borrow_mut().push("guardian:nonce".into());
            let req: GuardianNonceRequest = decode_canonical(body).unwrap();
            assert_eq!(req.vm_id, VM_ID);
            self.nonce_counter.set(self.nonce_counter.get() + 1);
            return ok(encode_canonical(&GuardianNonceResponse {
                v: 1,
                nonce: vec![self.nonce_counter.get(); 32],
            })
            .unwrap());
        }
        if path == GUARDIAN_STAMP_CONFIRM_PATH {
            self.log.borrow_mut().push("guardian:confirm".into());
            self.confirms.borrow_mut().push(body.to_vec());
            // An honest guardian: a signed ack echoing this very confirm.
            let c: GuardianStampConfirm = decode_canonical(body).unwrap();
            return ok(signed_ack(
                &self.signer,
                STAMP_ACK_SIG_DOMAIN,
                ack_body(&c.vm_id, c.target, &c.token),
            ));
        }
        assert_eq!(path, GUARDIAN_RELEASE_PATH);
        self.log.borrow_mut().push("guardian:release".into());
        let req: GuardianReleaseRequest = decode_canonical(body).unwrap();
        req.validate().unwrap();
        // The report binds THIS nonce, vm, guest key and share version —
        // the exact preimage a real guardian recomputes.
        let nonce: [u8; 32] = req.nonce.clone().try_into().unwrap();
        let gp: [u8; 32] = req.guest_pub.clone().try_into().unwrap();
        let want =
            hippius_types::report_data::guardian(&nonce, &req.vm_id, &gp, req.share_c_version)
                .unwrap();
        assert_eq!(
            &req.snp_report[0x50..0x90],
            &want[..],
            "guardian report_data"
        );
        *self.last_request.borrow_mut() = Some(req.clone());
        let mut gph = guest_pub_hash(&req.guest_pub).to_vec();
        if self.wrong_guest_pub_hash {
            gph = vec![0xAB; 32];
        }
        match self.next_answer() {
            Answer::Down => {
                let (status, class) = relay_answer::UNREACHABLE;
                Ok(HttpResponse {
                    status,
                    body: class.as_bytes().to_vec(),
                })
            }
            Answer::Deny(reason) => {
                let d = GuardianDenial {
                    v: 1,
                    vm_id: req.vm_id.clone(),
                    nonce: req.nonce.clone(),
                    guest_pub_hash: gph,
                    reason,
                };
                let body = encode_canonical(&d).unwrap();
                let sig = self
                    .signer
                    .sign(&signing_input(DENY_SIG_DOMAIN, &body))
                    .to_bytes()
                    .to_vec();
                Ok(HttpResponse {
                    status: 403,
                    body: encode_canonical(&SignedGuardianDenial { body, sig }).unwrap(),
                })
            }
            Answer::Release { version } => {
                let customer = self.mode == KeyMode::Customer;
                let mut r = GuardianResponse {
                    v: 1,
                    vm_id: req.vm_id.clone(),
                    nonce: req.nonce.clone(),
                    guest_pub_hash: gph,
                    key_mode: self.mode,
                    share_c_version: version,
                    wrapped_share: GuardianWrapped {
                        enc: vec![0; 32],
                        ct: vec![0; 48],
                    },
                    expected_volume_stamp: customer.then_some(GUARDIAN_STAMP_E),
                    stamp_token_wrapped: None,
                };
                if customer {
                    r.stamp_token_wrapped = Some(GuardianWrapped {
                        enc: vec![0; 32],
                        ct: vec![0; 48],
                    });
                }
                let aad = r.wrap_aad().unwrap();
                r.wrapped_share = seal(&req.guest_pub, &share_c(), SHARE_HPKE_INFO, &aad);
                if customer {
                    r.stamp_token_wrapped = Some(seal(
                        &req.guest_pub,
                        &STAMP_TOKEN,
                        STAMP_TOKEN_HPKE_INFO,
                        &aad,
                    ));
                }
                ok(signed(
                    &self.signer,
                    RESP_SIG_DOMAIN,
                    encode_canonical(&r).unwrap(),
                ))
            }
        }
    }
}

// ── the leg's environment ────────────────────────────────────────────

struct TestEnv {
    pauses: Vec<Duration>,
    lines: Vec<String>,
    max_pauses: usize,
}

impl TestEnv {
    fn new(max_pauses: usize) -> Self {
        Self {
            pauses: Vec::new(),
            lines: Vec::new(),
            max_pauses,
        }
    }
}

impl guardian_leg::LegEnv for TestEnv {
    fn pause(&mut self, delay: Duration) -> bool {
        self.pauses.push(delay);
        self.pauses.len() < self.max_pauses
    }
    fn status(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

// ── the harness ──────────────────────────────────────────────────────

struct Case {
    dir: tempfile::TempDir,
    log: Log,
    kbs: FakeKbs,
    guardian: FakeGuardian,
    env: TestEnv,
    ticket_mode: Option<&'static str>,
    cmdline: String,
    extra: Vec<String>,
    /// Leave out `--volume-stamp-transition-out` (N1).
    omit_transition_out: bool,
}

impl Case {
    fn new(mode: KeyMode, answers: Vec<Answer>) -> Self {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let keyed = mode != KeyMode::Hippius;
        let luks = (mode != KeyMode::Customer).then(share_h);
        Self {
            dir: tempfile::tempdir().unwrap(),
            kbs: FakeKbs::new(&log, luks),
            guardian: FakeGuardian::new(&log, mode, answers),
            log,
            env: TestEnv::new(1000),
            ticket_mode: keyed.then(|| mode.as_wire()),
            cmdline: cmdline(keyed.then_some(mode), &gk()),
            extra: Vec::new(),
            omit_transition_out: false,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_string_lossy().into_owned()
    }

    fn cli(&self) -> Cli {
        let ticket = ticket_file(self.dir.path(), self.ticket_mode);
        let mut args = vec![
            "hippius-guest-release".to_string(),
            "--kbs-url".into(),
            KBS_URL.into(),
            "--ticket".into(),
            ticket.to_string_lossy().into_owned(),
            "--volume-stamp-ctx-out".into(),
            self.path("stamp.ctx"),
            "--volume-stamp-expected-out".into(),
            self.path("stamp.expected"),
        ];
        if !self.omit_transition_out {
            args.push("--volume-stamp-transition-out".into());
            args.push(self.path("stamp.transition"));
        }
        if self.cmdline.contains("hippius.key_mode") {
            args.push("--share-c-version-out".into());
            args.push(self.path("share-c-version"));
            args.push("--instance-id-out".into());
            args.push(self.path("instance-id"));
        }
        args.extend(self.extra.iter().cloned());
        Cli::try_parse_from(args).unwrap()
    }

    fn run(&mut self) -> Result<Released, AgentError> {
        let cli = self.cli();
        let kbs_vk = kbs_key().verifying_key().to_bytes();
        run_with(
            &cli,
            KBS_URL,
            &self.cmdline,
            Deps {
                kbs: &self.kbs,
                guardian: &self.guardian,
                guardian_url: RELAY_URL,
                snp: &FakeSnp,
                kbs_vk: &kbs_vk,
                kbs_kid: KBS_KID,
                env: &mut self.env,
            },
        )
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.dir.path().join(name).exists()
    }
}

fn err_of(r: Result<Released, AgentError>) -> AgentError {
    match r {
        Ok(_) => panic!("expected a failure"),
        Err(e) => e,
    }
}

// ── happy paths ──────────────────────────────────────────────────────

#[test]
fn m1_emits_the_split_known_answer_and_asks_the_guardian_first() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    let out = c.run().unwrap();
    assert_eq!(hex(&out.kek), M1_KAT);
    assert_eq!(&out.userdata[..], &userdata()[..]);
    // The whole guardian leg, then the KBS leg.
    assert_eq!(
        *c.log.borrow(),
        [
            "guardian:recipe",
            "guardian:nonce",
            "guardian:release",
            "kbs:nonce",
            "kbs:release"
        ]
    );
    // M1 keeps the KBS stamp exactly as M0 does: no target field.
    assert_eq!(c.read("stamp.expected"), format!("{KBS_STAMP_E}\n"));
    let ctx = c.read("stamp.ctx");
    assert!(!ctx.contains("\"to\""), "{ctx}");
    assert!(
        ctx.contains(&format!("\"target\":{}", KBS_STAMP_E + 1)),
        "{ctx}"
    );
    assert_eq!(c.read("share-c-version"), "1\n");
    assert_eq!(c.read("instance-id"), format!("{VM_ID_IID}\n"));
    // First boot: no version sent.
    assert_eq!(
        c.guardian
            .last_request
            .borrow()
            .as_ref()
            .unwrap()
            .share_c_version,
        None
    );
}

#[test]
fn m2_emits_the_customer_known_answer_and_takes_the_guardian_stamp() {
    let mut c = Case::new(KeyMode::Customer, vec![Answer::Release { version: 3 }]);
    c.extra = vec!["--share-c-version".into(), "3".into()];
    let out = c.run().unwrap();
    assert_eq!(hex(&out.kek), M2_KAT);
    assert_eq!(c.read("stamp.expected"), format!("{GUARDIAN_STAMP_E}\n"));
    let ctx = c.read("stamp.ctx");
    assert!(ctx.ends_with(",\"to\":\"guardian\"}"), "{ctx}");
    assert!(
        ctx.contains(&format!("\"target\":{}", GUARDIAN_STAMP_E + 1)),
        "{ctx}"
    );
    assert!(ctx.contains(&hex(&STAMP_TOKEN)), "{ctx}");
    assert_eq!(c.read("share-c-version"), "3\n");
    assert_eq!(c.read("instance-id"), format!("{VM_ID_IID}\n"));
    assert_eq!(
        c.guardian
            .last_request
            .borrow()
            .as_ref()
            .unwrap()
            .share_c_version,
        Some(3)
    );
    assert_eq!(c.kbs.calls.get(), 2);
}

#[test]
fn a_guardian_that_comes_back_unblocks_the_boot_without_intervention() {
    let mut c = Case::new(
        KeyMode::Split,
        vec![
            Answer::Down,
            Answer::Deny(GuardianDenyReason::AwaitingApproval),
            Answer::Down,
            Answer::Release { version: 1 },
        ],
    );
    let out = c.run().unwrap();
    assert_eq!(hex(&out.kek), M1_KAT);
    assert_eq!(
        c.env.pauses,
        [1, 2, 4].map(Duration::from_secs).to_vec(),
        "backoff doubles from 1 s"
    );
    assert_eq!(
        c.env.lines[..3],
        [
            "awaiting-guardian:unreachable",
            "awaiting-guardian:refused:awaiting-approval",
            "awaiting-guardian:unreachable",
        ]
    );
    // Not one KBS request until the share was in hand.
    let log = c.log.borrow();
    let first_kbs = log.iter().position(|e| e.starts_with("kbs:")).unwrap();
    let last_guardian = log
        .iter()
        .rposition(|e| e.starts_with("guardian:"))
        .unwrap();
    assert!(last_guardian < first_kbs, "{log:?}");
}

// ── the guardian leg never touches the KBS while waiting ─────────────

fn stuck(mut c: Case, pauses: usize) -> Case {
    c.env = TestEnv::new(pauses);
    let e = err_of(c.run());
    assert!(matches!(e, AgentError::Guardian("stopped")), "{e:?}");
    assert_eq!(c.kbs.calls.get(), 0, "no KBS request while waiting");
    assert!(!c.exists("stamp.ctx") && !c.exists("share-c-version"));
    c
}

#[test]
fn a_down_guardian_is_waited_out_with_capped_backoff_and_zero_kbs_calls() {
    let c = stuck(Case::new(KeyMode::Split, vec![Answer::Down]), 10);
    assert_eq!(
        c.env.pauses,
        [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]
            .map(Duration::from_secs)
            .to_vec()
    );
    assert!(c
        .env
        .lines
        .iter()
        .all(|l| l == "awaiting-guardian:unreachable"));
}

#[test]
fn a_non_terminal_denial_is_waited_out() {
    for reason in GuardianDenyReason::ALL {
        if reason.is_terminal() {
            continue;
        }
        let c = stuck(Case::new(KeyMode::Customer, vec![Answer::Deny(reason)]), 3);
        assert_eq!(
            c.env.lines[0],
            format!("awaiting-guardian:refused:{}", reason.as_wire())
        );
    }
}

#[test]
fn erased_is_terminal_and_never_reaches_the_kbs() {
    let mut c = Case::new(
        KeyMode::Split,
        vec![Answer::Deny(GuardianDenyReason::Erased)],
    );
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian(guardian_leg::ERASED)),
        "{e:?}"
    );
    assert_eq!(c.kbs.calls.get(), 0);
    assert!(c.env.pauses.is_empty(), "no retry after erased");
}

#[test]
fn an_answer_signed_by_another_key_is_retried_never_trusted() {
    // The guardian answers, but not with the MEASURED key — a forged
    // release (the relay choosing the share) and a forged `erased`.
    for answer in [
        Answer::Release { version: 1 },
        Answer::Deny(GuardianDenyReason::Erased),
    ] {
        let mut c = Case::new(KeyMode::Customer, vec![answer]);
        c.guardian.signer = SigningKey::from_bytes(&[0x99; 32]);
        let c = stuck(c, 3);
        assert!(c
            .env
            .lines
            .iter()
            .all(|l| l == "awaiting-guardian:bad-signature"));
    }
}

#[test]
fn a_cmdline_pinning_another_guardian_key_trusts_nothing_from_this_one() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.cmdline = cmdline(Some(KeyMode::Split), &SigningKey::from_bytes(&[0x42; 32]));
    let c = stuck(c, 2);
    assert!(c
        .env
        .lines
        .iter()
        .all(|l| l == "awaiting-guardian:bad-signature"));
}

#[test]
fn a_replayed_decision_for_another_guest_key_is_retried() {
    for answer in [
        Answer::Deny(GuardianDenyReason::Erased),
        Answer::Release { version: 1 },
    ] {
        let mut c = Case::new(KeyMode::Split, vec![answer]);
        c.guardian.wrong_guest_pub_hash = true;
        let c = stuck(c, 2);
        assert!(c
            .env
            .lines
            .iter()
            .all(|l| l == "awaiting-guardian:bad-response:unverified"));
    }
}

#[test]
fn a_share_version_other_than_the_volumes_is_retried() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 4 }]);
    c.extra = vec!["--share-c-version".into(), "3".into()];
    let c = stuck(c, 2);
    assert_eq!(
        c.guardian
            .last_request
            .borrow()
            .as_ref()
            .unwrap()
            .share_c_version,
        Some(3)
    );
}

// ── ticket vs cmdline ────────────────────────────────────────────────

#[test]
fn a_ticket_mode_other_than_the_measured_one_fails_before_any_contact() {
    let cases: [(KeyMode, Option<&'static str>, &str); 4] = [
        (KeyMode::Split, None, "key-mode-mismatch"),
        (KeyMode::Split, Some("customer"), "key-mode-mismatch"),
        (KeyMode::Customer, Some("split"), "key-mode-mismatch"),
        (KeyMode::Hippius, Some("split"), "key-mode-unsupported"),
    ];
    for (measured, ticket, class) in cases {
        let mut c = Case::new(measured, vec![Answer::Release { version: 1 }]);
        c.ticket_mode = ticket;
        let e = err_of(c.run());
        assert!(
            matches!(e, AgentError::Ticket(t) if t == class),
            "{measured:?}/{ticket:?}: {e:?}"
        );
        assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
    }
}

// ── the KBS KEK per mode ─────────────────────────────────────────────

#[test]
fn m2_refuses_a_kbs_that_releases_a_kek() {
    let mut c = Case::new(KeyMode::Customer, vec![Answer::Release { version: 1 }]);
    c.kbs.luks = Some(share_h());
    let e = err_of(c.run());
    assert!(matches!(e, AgentError::Guest(_)), "{e:?}");
    assert!(!c.exists("stamp.ctx") && !c.exists("share-c-version"));
}

#[test]
fn m1_refuses_a_kbs_that_releases_no_kek() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.kbs.luks = None;
    let e = err_of(c.run());
    assert!(matches!(e, AgentError::Guest(_)), "{e:?}");
    assert!(!c.exists("stamp.ctx"));
}

#[test]
fn m1_refuses_a_share_h_that_is_not_32_bytes() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.kbs.luks = Some(vec![7; 31]);
    let e = err_of(c.run());
    assert!(matches!(e, AgentError::Guardian("share-h-length")), "{e:?}");
    assert!(!c.exists("stamp.ctx"));
}

// ── M0 is untouched ──────────────────────────────────────────────────

#[test]
fn m0_never_calls_the_guardian_and_emits_the_kbs_kek_verbatim() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.kbs.luks = Some(b"an-m0-kek-of-any-length".to_vec());
    let out = c.run().unwrap();
    assert_eq!(&out.kek[..], b"an-m0-kek-of-any-length");
    assert_eq!(c.guardian.calls.get(), 0);
    assert_eq!(*c.log.borrow(), ["kbs:nonce", "kbs:release"]);
    assert!(c.env.lines.is_empty() && c.env.pauses.is_empty());
    assert!(!c.read("stamp.ctx").contains("\"to\""));
    assert!(!c.exists("share-c-version"));
    assert!(!c.exists("instance-id"));
}

#[test]
fn the_key_mode_flags_are_refused_off_their_mode_before_any_contact() {
    // M0 with a guardian flag.
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.extra = vec!["--share-c-version".into(), "2".into()];
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian("key-mode-flags-without-binding")),
        "{e:?}"
    );
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.extra = vec!["--share-c-version-out".into(), c.path("v")];
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian("key-mode-flags-without-binding")),
        "{e:?}"
    );
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
    // M1 without somewhere to record the share version.
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    let cli = {
        let ticket = ticket_file(c.dir.path(), Some("split"));
        Cli::try_parse_from([
            "hippius-guest-release",
            "--kbs-url",
            KBS_URL,
            "--ticket",
            ticket.to_str().unwrap(),
        ])
        .unwrap()
    };
    let kbs_vk = kbs_key().verifying_key().to_bytes();
    let e = run_with(
        &cli,
        KBS_URL,
        &c.cmdline,
        Deps {
            kbs: &c.kbs,
            guardian: &c.guardian,
            guardian_url: RELAY_URL,
            snp: &FakeSnp,
            kbs_vk: &kbs_vk,
            kbs_kid: KBS_KID,
            env: &mut c.env,
        },
    );
    assert!(matches!(
        err_of(e),
        AgentError::Guardian("share-c-version-out-required")
    ));
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
}

#[test]
fn a_cmdline_the_grammar_refuses_fails_before_any_contact() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.cmdline = format!("{} hippius.key_mode=split", c.cmdline);
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian("cmdline-grammar")),
        "{e:?}"
    );
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
}

#[test]
fn share_c_version_zero_is_refused_by_the_parser() {
    assert!(Cli::try_parse_from([
        "hippius-guest-release",
        "--kbs-url",
        KBS_URL,
        "--ticket",
        "/t",
        "--share-c-version",
        "0",
    ])
    .is_err());
}

#[test]
fn the_production_environment_always_keeps_waiting() {
    // `false` would turn "wait for the guardian" into "give up and fail
    // the boot" — exactly the reboot/relaunch churn the leg exists to
    // avoid.
    let mut env = ConsoleEnv;
    assert!(guardian_leg::LegEnv::pause(&mut env, Duration::ZERO));
}

// ── M2 stamp confirm goes to the guardian, and needs a SIGNED ack ─────

fn m2_ctx(target: u64, token: [u8; 32]) -> VolumeStampCtx {
    VolumeStampCtx {
        vm_id: VM_ID.into(),
        target,
        token,
        to: ConfirmTo::Guardian,
        timeline: None,
    }
}

fn m2_binding() -> GuardianBinding {
    GuardianBinding::from_cmdline(&cmdline(Some(KeyMode::Customer), &gk()))
        .unwrap()
        .unwrap()
}

fn ack_body(vm_id: &str, target: u64, token: &[u8]) -> Vec<u8> {
    encode_canonical(&GuardianStampAck {
        v: GUARDIAN_WIRE_V,
        vm_id: vm_id.into(),
        target,
        token_hash: stamp_token_hash(token).to_vec(),
    })
    .unwrap()
}

fn signed_ack(key: &SigningKey, domain: &[u8], body: Vec<u8>) -> Vec<u8> {
    let sig = key.sign(&signing_input(domain, &body)).to_bytes().to_vec();
    encode_canonical(&SignedGuardianStampAck { body, sig }).unwrap()
}

#[test]
fn an_m2_confirm_goes_to_the_guardian_and_succeeds_on_its_signed_ack() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let g = FakeGuardian::new(&log, KeyMode::Customer, vec![Answer::Down]);
    confirm_to_guardian(&g, RELAY_URL, &m2_ctx(42, STAMP_TOKEN), &m2_binding()).unwrap();
    let sent: GuardianStampConfirm = decode_canonical(&g.confirms.borrow()[0]).unwrap();
    assert_eq!(
        sent,
        GuardianStampConfirm {
            v: 1,
            vm_id: VM_ID.into(),
            target: 42,
            token: STAMP_TOKEN.to_vec(),
        }
    );
    assert_eq!(*log.borrow(), ["guardian:confirm"]);
}

struct Canned(u16, Vec<u8>);

impl HttpClient for Canned {
    fn post_cbor(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse, AgentError> {
        Ok(HttpResponse {
            status: self.0,
            body: self.1.clone(),
        })
    }
}

fn confirm_class(status: u16, body: Vec<u8>) -> &'static str {
    match confirm_to_guardian(
        &Canned(status, body),
        RELAY_URL,
        &m2_ctx(42, STAMP_TOKEN),
        &m2_binding(),
    ) {
        Ok(()) => "ok",
        Err(AgentError::Guardian(c)) => c,
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

#[test]
fn an_m2_confirm_counts_only_on_a_verified_ack_for_this_confirm() {
    let good = || ack_body(VM_ID, 42, &STAMP_TOKEN);
    assert_eq!(
        confirm_class(200, signed_ack(&gk(), STAMP_ACK_SIG_DOMAIN, good())),
        "ok"
    );
    let (status, class) = relay_answer::UNREACHABLE;
    let other_key = SigningKey::from_bytes(&[0x63; 32]);
    let cases: Vec<(u16, Vec<u8>, &str)> = vec![
        // A relay answer, and a signed ack under a non-2xx status.
        (status, class.as_bytes().to_vec(), "confirm-http-status"),
        (
            403,
            signed_ack(&gk(), STAMP_ACK_SIG_DOMAIN, good()),
            "confirm-http-status",
        ),
        // The pre-H1b plain `{v}` ack, and the older `{v, confirmed}`.
        (200, vec![0xa1, 0x61, 0x76, 0x01], "confirm-ack-decode"),
        (
            200,
            vec![
                0xa2, 0x61, 0x76, 0x01, 0x69, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x65, 0x64,
                0x0a,
            ],
            "confirm-ack-decode",
        ),
        (200, b"ok".to_vec(), "confirm-ack-decode"),
        // The right body, unsigned (a zero signature) or forged.
        (
            200,
            encode_canonical(&SignedGuardianStampAck {
                body: good(),
                sig: vec![0; 64],
            })
            .unwrap(),
            "confirm-ack-bad-signature",
        ),
        (
            200,
            signed_ack(&other_key, STAMP_ACK_SIG_DOMAIN, good()),
            "confirm-ack-bad-signature",
        ),
        // Signed by the measured key under the RESPONSE domain.
        (
            200,
            signed_ack(&gk(), RESP_SIG_DOMAIN, good()),
            "confirm-ack-bad-signature",
        ),
        // Genuinely signed, for another confirm.
        (
            200,
            signed_ack(
                &gk(),
                STAMP_ACK_SIG_DOMAIN,
                ack_body(VM_ID, 43, &STAMP_TOKEN),
            ),
            "confirm-ack-mismatch",
        ),
        (
            200,
            signed_ack(
                &gk(),
                STAMP_ACK_SIG_DOMAIN,
                ack_body("vm-other", 42, &STAMP_TOKEN),
            ),
            "confirm-ack-mismatch",
        ),
    ];
    for (s, b, want) in cases {
        assert_eq!(confirm_class(s, b), want);
    }
}

#[test]
fn an_ack_recorded_before_a_guardian_reset_is_not_a_confirm_now() {
    // Same vm, same target — the guardian was re-initialised and sealed a
    // NEW token. The relay answers with the genuine ack it recorded for
    // the OLD token.
    let recorded = signed_ack(
        &gk(),
        STAMP_ACK_SIG_DOMAIN,
        ack_body(VM_ID, 42, &[0x01; 32]),
    );
    assert_eq!(confirm_class(200, recorded), "confirm-ack-mismatch");
}

#[test]
fn the_confirm_binding_is_the_measured_m2_one_or_nothing() {
    let b = confirm_binding(&format!("{}\n", cmdline(Some(KeyMode::Customer), &gk()))).unwrap();
    assert_eq!(b, m2_binding());
    for (c, want) in [
        (
            cmdline(Some(KeyMode::Split), &gk()),
            "confirm-not-customer-mode",
        ),
        (cmdline(None, &gk()), "confirm-not-customer-mode"),
        (
            format!(
                "{} hippius.key_mode=customer",
                cmdline(Some(KeyMode::Customer), &gk())
            ),
            "cmdline-grammar",
        ),
        (padded("ro", MAX_CMDLINE_LEN), "cmdline-may-be-truncated"),
    ] {
        assert!(
            matches!(confirm_binding(&c), Err(AgentError::Guardian(got)) if got == want),
            "{want}"
        );
    }
}

#[test]
fn an_ack_signed_by_another_guardian_than_the_measured_one_is_refused() {
    // The ack is genuine for the key the relay would like the guest to
    // trust, but the cmdline pins `gk()`.
    let other = SigningKey::from_bytes(&[0x64; 32]);
    let reply = signed_ack(
        &other,
        STAMP_ACK_SIG_DOMAIN,
        ack_body(VM_ID, 42, &STAMP_TOKEN),
    );
    let pinned_other = GuardianBinding::from_cmdline(&cmdline(Some(KeyMode::Customer), &other))
        .unwrap()
        .unwrap();
    // Verifies against its own key ...
    confirm_to_guardian(
        &Canned(200, reply.clone()),
        RELAY_URL,
        &m2_ctx(42, STAMP_TOKEN),
        &pinned_other,
    )
    .unwrap();
    // ... never against the measured one.
    assert_eq!(confirm_class(200, reply), "confirm-ack-bad-signature");
}

// ── H5b: the stable cloud-init instance-id ───────────────────────────

#[test]
fn the_instance_id_is_the_pinned_derivation_of_the_vm_id() {
    assert_eq!(cloud_init_instance_id(VM_ID), VM_ID_IID);
    // Distinct VMs, distinct ids; the shape the golden overlay checks.
    let other = cloud_init_instance_id("vm-kat-kek-02");
    assert_ne!(other, VM_ID_IID);
    for iid in [cloud_init_instance_id(VM_ID), other] {
        let hex = iid.strip_prefix("iid-").unwrap();
        assert_eq!(hex.len(), 32);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}

#[test]
fn the_instance_id_flag_is_m1_m2_only_and_required_there() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.extra = vec!["--instance-id-out".into(), c.path("iid")];
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian("key-mode-flags-without-binding")),
        "{e:?}"
    );
    assert!(!c.exists("iid"));
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);

    let mut c = Case::new(KeyMode::Customer, vec![Answer::Release { version: 1 }]);
    let ticket = ticket_file(c.dir.path(), Some("customer"));
    let cli = Cli::try_parse_from([
        "hippius-guest-release",
        "--kbs-url",
        KBS_URL,
        "--ticket",
        ticket.to_str().unwrap(),
        "--share-c-version-out",
        &c.path("share-c-version"),
    ])
    .unwrap();
    let kbs_vk = kbs_key().verifying_key().to_bytes();
    let e = run_with(
        &cli,
        KBS_URL,
        &c.cmdline,
        Deps {
            kbs: &c.kbs,
            guardian: &c.guardian,
            guardian_url: RELAY_URL,
            snp: &FakeSnp,
            kbs_vk: &kbs_vk,
            kbs_kid: KBS_KID,
            env: &mut c.env,
        },
    );
    assert!(matches!(
        err_of(e),
        AgentError::Guardian("instance-id-out-required")
    ));
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
}

#[test]
fn the_instance_id_flag_conflicts_with_the_other_modes() {
    for mode in ["--confirm-volume-stamp", "--integrity-wipe"] {
        assert!(Cli::try_parse_from([
            "hippius-guest-release",
            "--kbs-url",
            KBS_URL,
            mode,
            "/x",
            "--instance-id-out",
            "/run/iid",
        ])
        .is_err());
    }
}

// ── the truncated-cmdline rule ───────────────────────────────────────

/// `base` padded with a filler token to exactly `len` bytes.
fn padded(base: &str, len: usize) -> String {
    let fill = len - base.len() - 3;
    let c = format!("{base} x={}", "a".repeat(fill));
    assert_eq!(c.len(), len);
    c
}

#[test]
fn the_truncation_floor_is_one_key_mode_token_below_the_limit() {
    assert_eq!(MAX_CMDLINE_LEN, 2047);
    assert_eq!(KEY_MODE_TRUNCATION_FLOOR, 2022);
    // The EFI stub keeps [0, S) where S is the last whitespace before
    // byte 2048. The longest token starting at S+1 still reaches byte
    // 2047 only if S + 1 + 25 >= 2048, i.e. S >= 2022.
    assert_eq!(
        2048 - 1 - LONGEST_KEY_MODE_TOKEN.len(),
        KEY_MODE_TRUNCATION_FLOOR
    );
}

#[test]
fn a_long_cmdline_without_a_key_mode_token_may_be_truncated() {
    let base = cmdline(None, &gk());
    for len in [KEY_MODE_TRUNCATION_FLOOR, 2030, MAX_CMDLINE_LEN] {
        let c = padded(&base, len);
        assert!(cmdline_may_hide_key_mode(&c), "len {len}");
        // `/proc/cmdline` carries one trailing newline.
        assert!(
            cmdline_may_hide_key_mode(&format!("{c}\n")),
            "len {len} + newline"
        );
    }
    let c = padded(&base, KEY_MODE_TRUNCATION_FLOOR - 1);
    assert!(!cmdline_may_hide_key_mode(&c));
    // The trailing newline does not count.
    assert!(!cmdline_may_hide_key_mode(&format!("{c}\n")));
    assert!(!cmdline_may_hide_key_mode(&base));
}

#[test]
fn a_long_cmdline_that_carries_its_key_mode_token_is_not_truncation() {
    for mode in [KeyMode::Hippius, KeyMode::Split, KeyMode::Customer] {
        let base = format!(
            "{} hippius.key_mode={}",
            cmdline(None, &gk()),
            mode.as_wire()
        );
        let c = padded(&base, MAX_CMDLINE_LEN);
        assert!(!cmdline_may_hide_key_mode(&c), "{mode:?}");
    }
    // A token merely CONTAINING the key is not the key.
    for tok in ["xhippius.key_mode=split", "hippius.key_mode_x=split"] {
        let c = padded(&format!("{} {tok}", cmdline(None, &gk())), MAX_CMDLINE_LEN);
        assert!(cmdline_may_hide_key_mode(&c), "{tok}");
    }
}

#[test]
fn a_possibly_truncated_cmdline_fails_before_any_contact() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.cmdline = padded(&c.cmdline, MAX_CMDLINE_LEN);
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Guardian("cmdline-may-be-truncated")),
        "{e:?}"
    );
    assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0);
    assert!(!c.exists("stamp.ctx") && !c.exists("stamp.expected"));

    // One byte shorter: an M0 boot as before.
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Release { version: 1 }]);
    c.cmdline = padded(&c.cmdline, KEY_MODE_TRUNCATION_FLOOR - 1);
    c.run().unwrap();
    assert_eq!(*c.log.borrow(), ["kbs:nonce", "kbs:release"]);

    // A keyed cmdline at the very limit still boots: its token is there.
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.cmdline = padded(&c.cmdline, MAX_CMDLINE_LEN);
    let out = c.run().unwrap();
    assert_eq!(hex(&out.kek), M1_KAT);
}

#[test]
fn a_cloud_init_directive_on_a_keyed_cmdline_fails_before_any_contact() {
    for extra in [
        "hippius.vm_id=acc:datasource:end_cc",
        "url=http://x/cfg",
        "ds=nocloud;i=iid-evil",
    ] {
        let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
        c.cmdline = format!("{} {extra}", c.cmdline);
        let e = err_of(c.run());
        assert!(
            matches!(e, AgentError::Guardian("cmdline-grammar")),
            "{extra}: {e:?}"
        );
        assert_eq!(c.kbs.calls.get() + c.guardian.calls.get(), 0, "{extra}");
    }
}

#[test]
fn the_rule_reads_proc_cmdline_with_the_ovmf_initrd_prefix() {
    use hippius_types::guardian::MAX_MEASURED_CMDLINE_LEN;
    // OVMF (edk2 GenericQemuLoadImageLib) puts `initrd=initrd ` in front
    // of the measured cmdline; /proc/cmdline is that plus one `\n`.
    assert_eq!(OVMF_INITRD_PREFIX, "initrd=initrd ");
    assert_eq!(KEY_MODE_TRUNCATION_FLOOR_MEASURED, 2008);
    assert_eq!(MAX_MEASURED_CMDLINE_LEN, 2033);
    let proc = |measured: &str| format!("{OVMF_INITRD_PREFIX}{measured}\n");
    let base = cmdline(None, &gk());
    // Token-less: measured 2008 is /proc 2022 — refused; 2007 boots.
    let m = padded(&base, KEY_MODE_TRUNCATION_FLOOR_MEASURED);
    assert!(cmdline_may_hide_key_mode(&proc(&m)));
    let m = padded(&base, KEY_MODE_TRUNCATION_FLOOR_MEASURED - 1);
    assert!(!cmdline_may_hide_key_mode(&proc(&m)));
    // The longest measured cmdline vali may mint fills /proc/cmdline to
    // exactly the kernel limit — nothing is cut.
    let m = padded(&base, MAX_MEASURED_CMDLINE_LEN);
    assert_eq!(proc(&m).len() - 1, MAX_CMDLINE_LEN);
    // A keyed cmdline at that length still carries its token.
    let keyed = format!("{base} hippius.key_mode=split");
    assert!(!cmdline_may_hide_key_mode(&proc(&padded(
        &keyed,
        MAX_MEASURED_CMDLINE_LEN
    ))));
    // The prefix token is not a grammar key: the binding parses through it.
    let c = Case::new(KeyMode::Split, vec![]);
    let b = GuardianBinding::from_cmdline(&proc(&c.cmdline))
        .unwrap()
        .unwrap();
    assert_eq!(b.mode, KeyMode::Split);
}

// ── stamp protocol v2 ────────────────────────────────────────────────

/// M0 attests stamp protocol v2 in its REPORT_DATA, accepts the V2
/// response, and hands the shell gate the transition and the confirm its
/// timeline.
#[test]
fn m0_attests_v2_and_hands_the_transition_to_the_gate() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Down]);
    c.kbs.kind = KbsKind::V2 {
        expected: [0xa1; 32],
        target: [0xb2; 32],
    };
    let out = c.run().unwrap();
    assert_eq!(out.kek.as_slice(), share_h().as_slice());
    assert_eq!(*c.kbs.attested.borrow(), [2], "one release, attested v2");
    assert_eq!(
        c.read("stamp.transition"),
        format!("{} {}\n", "a1".repeat(32), "b2".repeat(32))
    );
    assert_eq!(c.read("stamp.expected"), format!("{KBS_STAMP_E}\n"));
    let ctx = c.read("stamp.ctx");
    assert!(
        ctx.contains(&format!("\"timeline\":\"{}\"", "b2".repeat(32))),
        "{ctx}"
    );
    assert_eq!(c.guardian.calls.get(), 0, "M0 never talks to the guardian");
}

/// N1 — a v2 response's expectation only means something WITH its
/// transition: without `--volume-stamp-transition-out` the shell gate
/// would see the expectation alone and run the v1 comparison on it. So a
/// release that carried a transition refuses, and writes NOTHING for the
/// gate (no ctx, no expectation) — while a v1 response (no transition)
/// still needs no transition file.
#[test]
fn a_transition_without_transition_out_is_refused() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Down]);
    c.kbs.kind = KbsKind::V2 {
        expected: [0xa1; 32],
        target: [0xb2; 32],
    };
    c.omit_transition_out = true;
    let e = err_of(c.run());
    assert!(
        matches!(e, AgentError::Kbs("volume-stamp-transition-out-required")),
        "{e:?}"
    );
    assert!(!c.exists("stamp.expected") && !c.exists("stamp.ctx"));

    // M2 (the only v1 release left): no transition, so none is needed.
    let mut v1 = Case::new(KeyMode::Customer, vec![Answer::Release { version: 3 }]);
    v1.extra = vec!["--share-c-version".into(), "3".into()];
    v1.omit_transition_out = true;
    v1.run().unwrap();
    assert_eq!(*v1.kbs.attested.borrow(), [1]);
    assert!(v1.exists("stamp.expected") && !v1.exists("stamp.transition"));
}

/// M1 keeps the KBS stamp, so it attests v2 too.
#[test]
fn m1_attests_v2() {
    let mut c = Case::new(KeyMode::Split, vec![Answer::Release { version: 1 }]);
    c.run().unwrap();
    assert_eq!(*c.kbs.attested.borrow(), [2]);
    assert!(c.exists("stamp.transition"));
}

/// M2's stamp is the guardian's: it attests v1 only, the KBS answers the
/// pre-v2 response, and the gate gets NO transition — the M2 path is
/// exactly what it was.
#[test]
fn m2_attests_v1_only_and_gets_no_transition() {
    let mut c = Case::new(KeyMode::Customer, vec![Answer::Release { version: 3 }]);
    c.extra = vec!["--share-c-version".into(), "3".into()];
    std::fs::write(c.dir.path().join("stamp.transition"), "stale").unwrap();
    let out = c.run().unwrap();
    assert_eq!(hex(&out.kek), M2_KAT);
    assert_eq!(*c.kbs.attested.borrow(), [1]);
    assert!(
        !c.exists("stamp.transition"),
        "a stale transition is removed"
    );
    assert!(!c.read("stamp.ctx").contains("timeline"));
}

/// R1 — a denial of the v2 report is FINAL for M0 and M1: the guest never
/// retries attesting v1. Every KBS refusal is the same generic 403, so
/// this is also what a MINER that forges a 403 gets — after a KBS store
/// wipe a v1 retry would have been served a v1 adopt of an old
/// zero-timeline disk, and the VM kept on the zero timeline past its
/// first confirm. Now the boot fails (denial of service only): one
/// release, attested v2, and nothing written for the gate.
#[test]
fn a_denial_of_the_v2_report_is_final_never_a_v1_retry() {
    for mode in [KeyMode::Hippius, KeyMode::Split] {
        let mut c = Case::new(mode, vec![Answer::Release { version: 1 }]);
        c.kbs.kind = KbsKind::Old;
        let e = err_of(c.run());
        assert!(matches!(e, AgentError::KbsDenial), "{mode:?}: {e:?}");
        assert_eq!(
            *c.kbs.attested.borrow(),
            [2],
            "{mode:?}: v2 only, no v1 retry"
        );
        let kbs_calls: Vec<String> = c
            .log
            .borrow()
            .iter()
            .filter(|l| l.starts_with("kbs:"))
            .cloned()
            .collect();
        assert_eq!(kbs_calls, ["kbs:nonce", "kbs:release"], "{mode:?}");
        assert!(
            !c.exists("stamp.expected") && !c.exists("stamp.ctx") && !c.exists("stamp.transition"),
            "{mode:?}: nothing written for the gate"
        );
    }
}

/// A denial is a denial whatever the KBS: one release request, never a
/// second one under another stamp protocol.
#[test]
fn a_denied_release_is_final() {
    struct Deny(Cell<usize>);
    impl HttpClient for Deny {
        fn post_cbor(&self, url: &str, _b: &[u8]) -> Result<HttpResponse, AgentError> {
            if url.ends_with("/v1/kbs/nonce") {
                let b = to_canonical_vec(&Value::Map(vec![(
                    Value::Text("nonce".into()),
                    Value::Bytes(KBS_NONCE.to_vec()),
                )]))
                .unwrap();
                return Ok(HttpResponse {
                    status: 200,
                    body: b,
                });
            }
            self.0.set(self.0.get() + 1);
            Ok(HttpResponse {
                status: 403,
                body: Vec::new(),
            })
        }
    }
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Down]);
    let deny = Deny(Cell::new(0));
    let cli = c.cli();
    let kbs_vk = kbs_key().verifying_key().to_bytes();
    let out = run_with(
        &cli,
        KBS_URL,
        &c.cmdline,
        Deps {
            kbs: &deny,
            guardian: &c.guardian,
            guardian_url: RELAY_URL,
            snp: &FakeSnp,
            kbs_vk: &kbs_vk,
            kbs_kid: KBS_KID,
            env: &mut c.env,
        },
    );
    assert!(matches!(out, Err(AgentError::KbsDenial)));
    assert_eq!(deny.0.get(), 1, "one release, never a retry");
    assert!(!c.exists("stamp.ctx") && !c.exists("stamp.expected"));
}

/// Any other failure of the v2 release (a 5xx, a 400) is returned as is,
/// with no second release — a flaky or hostile relay does not buy a
/// downgrade either.
#[test]
fn a_non_denial_failure_of_the_v2_attempt_is_final() {
    struct Status(u16, Cell<usize>);
    impl HttpClient for Status {
        fn post_cbor(&self, url: &str, _b: &[u8]) -> Result<HttpResponse, AgentError> {
            if url.ends_with("/v1/kbs/nonce") {
                let b = to_canonical_vec(&Value::Map(vec![(
                    Value::Text("nonce".into()),
                    Value::Bytes(KBS_NONCE.to_vec()),
                )]))
                .unwrap();
                return Ok(HttpResponse {
                    status: 200,
                    body: b,
                });
            }
            self.1.set(self.1.get() + 1);
            Ok(HttpResponse {
                status: self.0,
                body: Vec::new(),
            })
        }
    }
    for status in [500, 502, 400] {
        let mut c = Case::new(KeyMode::Hippius, vec![Answer::Down]);
        let kbs = Status(status, Cell::new(0));
        let cli = c.cli();
        let kbs_vk = kbs_key().verifying_key().to_bytes();
        let out = run_with(
            &cli,
            KBS_URL,
            &c.cmdline,
            Deps {
                kbs: &kbs,
                guardian: &c.guardian,
                guardian_url: RELAY_URL,
                snp: &FakeSnp,
                kbs_vk: &kbs_vk,
                kbs_kid: KBS_KID,
                env: &mut c.env,
            },
        );
        assert!(
            matches!(out, Err(AgentError::Kbs("release-http-status"))),
            "{status}"
        );
        assert_eq!(kbs.1.get(), 1, "{status}: no second release");
    }
}

/// A KBS that answers a v2 report with a V1 response is not answering
/// this report: refused, nothing written for the gate.
#[test]
fn a_v1_response_to_a_v2_report_is_refused() {
    let mut c = Case::new(KeyMode::Hippius, vec![Answer::Down]);
    c.kbs.kind = KbsKind::V1Always;
    let e = err_of(c.run());
    assert!(matches!(e, AgentError::Guest(_)), "{e:?}");
    assert_eq!(*c.kbs.attested.borrow(), [2]);
    assert!(!c.exists("stamp.expected") && !c.exists("stamp.transition"));
}
