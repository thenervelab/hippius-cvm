use super::*;

const PK_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn pk_bytes() -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::try_from(i % 16).unwrap() * 0x11;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn split_cmdline() -> String {
    format!(
        "console=ttyS0 boot=hippius-golden hippius.vm_id=vm-1 \
         hippius.key_mode=split hippius.guardian_pk={PK_HEX} \
         hippius.guardian_ep=3130302e36342e332e373a37343433"
    )
}

fn parse(c: &str) -> core::result::Result<Option<GuardianBinding>, CmdlineError> {
    GuardianBinding::from_cmdline(c)
}

// ---------------------------------------------------------------------
// cmdline grammar
// ---------------------------------------------------------------------

#[test]
fn m0_cmdline_has_no_binding() {
    assert_eq!(parse("").unwrap(), None);
    assert_eq!(
        parse("console=ttyS0 boot=hippius-golden hippius.vm_id=vm-1 ro").unwrap(),
        None
    );
    // Explicit hippius without guardian tokens is still M0.
    assert_eq!(parse("hippius.key_mode=hippius quiet").unwrap(), None);
}

#[test]
fn split_and_customer_parse_fully() {
    let b = parse(&split_cmdline()).unwrap().unwrap();
    assert_eq!(b.mode, KeyMode::Split);
    assert_eq!(b.guardian_pk, pk_bytes());
    assert_eq!(
        b.endpoint,
        GuardianEndpoint {
            host: GuardianHost::Ipv4(Ipv4Addr::new(100, 64, 3, 7)),
            port: 7443
        }
    );
    let c = split_cmdline().replace("key_mode=split", "key_mode=customer");
    assert_eq!(parse(&c).unwrap().unwrap().mode, KeyMode::Customer);
    // Token order and extra whitespace do not matter.
    let reordered = format!(
        "  hippius.guardian_ep=672e6578616d706c652e636f6d3a31   hippius.guardian_pk={PK_HEX}   hippius.key_mode=split \n"
    );
    let b = parse(&reordered).unwrap().unwrap();
    assert_eq!(b.endpoint.host, GuardianHost::Dns("g.example.com".into()));
    assert_eq!(b.endpoint.port, 1);
}

#[test]
fn guardian_tokens_without_customer_mode_are_orphans() {
    let pk = format!("hippius.guardian_pk={PK_HEX}");
    let ep = "hippius.guardian_ep=31302e302e302e313a37343433";
    for c in [
        pk.clone(),
        ep.to_string(),
        format!("hippius.key_mode=hippius {pk}"),
        format!("hippius.key_mode=hippius {ep}"),
        format!("{pk} {ep}"),
    ] {
        assert_eq!(parse(&c), Err(CmdlineError::OrphanGuardianToken), "{c}");
    }
}

#[test]
fn customer_modes_require_both_guardian_tokens() {
    let pk = format!("hippius.guardian_pk={PK_HEX}");
    let ep = "hippius.guardian_ep=31302e302e302e313a37343433";
    for mode in ["split", "customer"] {
        assert_eq!(
            parse(&format!("hippius.key_mode={mode} {ep}")),
            Err(CmdlineError::MissingGuardianPk)
        );
        assert_eq!(
            parse(&format!("hippius.key_mode={mode} {pk}")),
            Err(CmdlineError::MissingGuardianEp)
        );
        assert_eq!(
            parse(&format!("hippius.key_mode={mode}")),
            Err(CmdlineError::MissingGuardianPk)
        );
    }
}

#[test]
fn every_duplicate_is_refused() {
    let base = split_cmdline();
    for extra in [
        "hippius.key_mode=split".to_string(),
        "hippius.key_mode=customer".to_string(),
        format!("hippius.guardian_pk={PK_HEX}"),
        "hippius.guardian_ep=3130302e36342e332e373a37343433".to_string(),
    ] {
        assert_eq!(
            parse(&format!("{base} {extra}")),
            Err(CmdlineError::DuplicateToken),
            "{extra}"
        );
    }
    // Also in M0: a repeated mode token is refused, not resolved.
    assert_eq!(
        parse("hippius.key_mode=hippius hippius.key_mode=hippius"),
        Err(CmdlineError::DuplicateToken)
    );
}

#[test]
fn empty_and_bare_tokens_are_refused() {
    for c in [
        "hippius.key_mode",
        "hippius.key_mode=",
        "hippius.guardian_pk",
        "hippius.guardian_ep=",
    ] {
        assert_eq!(parse(c), Err(CmdlineError::EmptyToken), "{c}");
    }
}

#[test]
fn lookalike_keys_are_refused() {
    for c in [
        "hippius.key-mode=split",
        "HIPPIUS.KEY_MODE=split",
        "hippius.Guardian_pk=00",
        "hippius.guardian-ep=a.b:1",
        "hippius.KEY_MODE",
    ] {
        assert_eq!(parse(c), Err(CmdlineError::LookalikeToken), "{c}");
    }
    // Keys that merely contain a grammar key are someone else's.
    assert_eq!(
        parse("rd.hippius.key_mode=split x.hippius.guardian_pk=zz").unwrap(),
        None
    );
}

#[test]
fn quotes_near_grammar_keys_are_refused() {
    assert_eq!(
        parse("foo=\"a hippius.key_mode=split b\""),
        Err(CmdlineError::Quoted)
    );
    assert_eq!(
        parse(&format!("{} x=\"y\"", split_cmdline())),
        Err(CmdlineError::Quoted)
    );
    // Lookalike spelling inside quotes is caught too.
    assert_eq!(
        parse("foo=\"HIPPIUS.GUARDIAN-EP=a.b:1\""),
        Err(CmdlineError::Quoted)
    );
    // A quoted M0 cmdline without any grammar key is untouched.
    assert_eq!(parse("foo=\"a b\" quiet").unwrap(), None);
}

#[test]
fn unknown_mode_is_refused() {
    for m in ["Split", "none", "customer,", "splitx", "m1", "hippius=1"] {
        let c = format!("hippius.key_mode={m}");
        assert_eq!(parse(&c), Err(CmdlineError::UnknownMode), "{m}");
    }
}

#[test]
fn bad_guardian_pk_is_refused() {
    let upper = PK_HEX.to_ascii_uppercase();
    let short = &PK_HEX[..62];
    let long = format!("{PK_HEX}00");
    let nonhex = format!("{}zz", &PK_HEX[..62]);
    let prefixed = format!("0x{}", &PK_HEX[..62]);
    for pk in [
        upper.as_str(),
        short,
        long.as_str(),
        nonhex.as_str(),
        prefixed.as_str(),
    ] {
        let c = format!(
            "hippius.key_mode=split hippius.guardian_pk={pk} hippius.guardian_ep=312e322e332e343a35"
        );
        assert_eq!(parse(&c), Err(CmdlineError::BadGuardianPk), "{pk}");
    }
    // Every hex digit decodes to its value (a–f and 0–9 edges).
    let c = "hippius.key_mode=split \
             hippius.guardian_pk=09af09af09af09af09af09af09af09af09af09af09af09af09af09af09af09af \
             hippius.guardian_ep=312e322e332e343a35";
    let b = parse(c).unwrap().unwrap();
    assert_eq!(b.guardian_pk, [0x09, 0xaf].repeat(16).as_slice());
}

#[test]
fn bad_guardian_ep_is_refused_through_the_cmdline() {
    let c = format!(
        "hippius.key_mode=customer hippius.guardian_pk={PK_HEX} hippius.guardian_ep=https://g:1"
    );
    assert_eq!(parse(&c), Err(CmdlineError::BadGuardianEp));
}

// ---------------------------------------------------------------------
// endpoint grammar
// ---------------------------------------------------------------------

#[test]
fn endpoint_accepts_each_canonical_form_and_round_trips() {
    let cases = [
        (
            "100.64.3.7:7443",
            GuardianHost::Ipv4(Ipv4Addr::new(100, 64, 3, 7)),
            7443,
        ),
        (
            "0.0.0.0:65535",
            GuardianHost::Ipv4(Ipv4Addr::UNSPECIFIED),
            65535,
        ),
        ("[::1]:1", GuardianHost::Ipv6(Ipv6Addr::LOCALHOST), 1),
        (
            "[2001:db8::7]:7443",
            GuardianHost::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)),
            7443,
        ),
        (
            "[::ffff:10.0.0.1]:80",
            GuardianHost::Ipv6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()),
            80,
        ),
        (
            "guardian.example.com:7443",
            GuardianHost::Dns("guardian.example.com".into()),
            7443,
        ),
        ("localhost:9", GuardianHost::Dns("localhost".into()), 9),
        ("a-1.b2.c:10", GuardianHost::Dns("a-1.b2.c".into()), 10),
        ("1.2.3.a:10", GuardianHost::Dns("1.2.3.a".into()), 10),
    ];
    for (s, host, port) in cases {
        let ep = GuardianEndpoint::parse(s).unwrap_or_else(|_| panic!("{s}"));
        assert_eq!(ep.host, host, "{s}");
        assert_eq!(ep.port, port, "{s}");
        assert_eq!(ep.to_wire(), s);
    }
}

#[test]
fn endpoint_label_and_length_limits() {
    let l63 = "a".repeat(63);
    let l64 = "a".repeat(64);
    assert!(GuardianEndpoint::parse(&format!("{l63}.com:1")).is_ok());
    assert!(GuardianEndpoint::parse(&format!("{l64}.com:1")).is_err());
    // 253-byte host is the maximum.
    let host253 = format!("{}.{}.{}.{}", l63, l63, l63, "a".repeat(61));
    assert_eq!(host253.len(), 253);
    let ok = format!("{host253}:65535");
    assert_eq!(ok.len(), MAX_ENDPOINT_LEN);
    assert!(GuardianEndpoint::parse(&ok).is_ok());
    let host254 = format!("{host253}a");
    assert!(GuardianEndpoint::parse(&format!("{host254}:1")).is_err());
    assert!(GuardianEndpoint::parse(&format!("{host254}:65535")).is_err());
}

#[test]
fn endpoint_rejects_everything_else() {
    for s in [
        "",
        "g.example.com",           // no port
        "g.example.com:",          // empty port
        ":7443",                   // empty host
        "g.example.com:0",         // port 0
        "g.example.com:65536",     // port overflow
        "g.example.com:99999",     // port overflow
        "g.example.com:123456",    // too many digits
        "g.example.com:07443",     // leading zero
        "g.example.com:+80",       // sign
        "g.example.com:8a",        // non-digit
        "G.example.com:1",         // uppercase
        "g_x.example.com:1",       // underscore
        "-g.example.com:1",        // label starts with dash
        "g-.example.com:1",        // label ends with dash
        "g..example.com:1",        // empty label
        ".g.example.com:1",        // leading dot
        "g.example.com.:1",        // trailing dot
        "g.1:1",                   // numeric TLD
        "1.2.3:1",                 // short dotted-numeric
        "1.2.3.4.5:1",             // too many octets
        "256.1.1.1:1",             // octet overflow
        "01.2.3.4:1",              // leading zero octet
        "user@g.example.com:1",    // userinfo
        "https://g.example.com:1", // scheme
        "g.example.com:1/path",    // path
        "g.example.com/x:1",       // path in host
        "g .example.com:1",        // space
        "::1:7443",                // unbracketed IPv6
        "[::1]",                   // no port
        "[::1]7443",               // no colon
        "[::1]:",                  // empty port
        "[::1:7443",               // unclosed bracket
        "[0:0::1]:1",              // non-canonical IPv6
        "[::0001]:1",              // non-canonical IPv6
        "[2001:DB8::1]:1",         // uppercase IPv6
        "[fe80::1%eth0]:1",        // zone id
        "[1.2.3.4]:1",             // IPv4 in brackets
        "[g.example.com]:1",       // name in brackets
        "[]:1",                    // empty brackets
        "g.example.com:1:2",       // two ports
    ] {
        assert!(GuardianEndpoint::parse(s).is_err(), "{s:?} must be refused");
    }
    let too_long = format!("{}:1", "a".repeat(MAX_ENDPOINT_LEN));
    assert!(GuardianEndpoint::parse(&too_long).is_err());
}

// ---------------------------------------------------------------------
// key mode / deny reasons / relay constants
// ---------------------------------------------------------------------

#[test]
fn key_mode_wire_strings_match_serde() {
    for (m, w) in [
        (KeyMode::Hippius, "hippius"),
        (KeyMode::Split, "split"),
        (KeyMode::Customer, "customer"),
    ] {
        assert_eq!(m.as_wire(), w);
        assert_eq!(KeyMode::from_wire(w), Some(m));
        assert_eq!(Value::serialized(&m).unwrap(), Value::Text(w.into()));
    }
    assert_eq!(KeyMode::from_wire("Hippius"), None);
    assert_eq!(KeyMode::from_wire(""), None);
}

#[test]
fn deny_reason_vocabulary_is_closed_and_matches_serde() {
    let wires = [
        "awaiting-approval",
        "release-not-pinned",
        "measurement-mismatch",
        "policy",
        "tcb",
        "chip-not-approved",
        "mode-mismatch",
        "unknown-vm",
        "erased",
        "bad-nonce",
        "bad-report",
        "bad-chain",
        "rate",
        "share-version-unavailable",
    ];
    assert_eq!(GuardianDenyReason::ALL.len(), wires.len());
    for (r, w) in GuardianDenyReason::ALL.iter().zip(wires) {
        assert_eq!(r.as_wire(), w);
        assert_eq!(GuardianDenyReason::from_wire(w), Some(*r));
        assert_eq!(Value::serialized(r).unwrap(), Value::Text(w.into()));
        assert_eq!(r.is_terminal(), w == "erased", "{w}");
    }
    assert_eq!(GuardianDenyReason::from_wire("unreachable"), None);
    assert_eq!(GuardianDenyReason::from_wire("Erased"), None);
}

#[test]
fn relay_port_and_paths_are_closed() {
    assert_eq!(GUARDIAN_VSOCK_PORT, 0x4B47);
    assert_ne!(GUARDIAN_VSOCK_PORT, crate::kbs_vsock::PORT);
    assert_ne!(GUARDIAN_VSOCK_PORT, crate::ticket_vsock::PORT);
    assert_ne!(
        GUARDIAN_VSOCK_PORT,
        crate::host_attestor_challenge::CHALLENGE_PORT
    );
    assert_ne!(
        GUARDIAN_VSOCK_PORT,
        crate::host_attestor_challenge::ENROLL_BEACON_PORT
    );
    assert!(is_guardian_allowed_path("/v1/guardian/nonce"));
    assert!(is_guardian_allowed_path("/v1/guardian/release"));
    assert!(is_guardian_allowed_path("/v1/guardian/stamp/confirm"));
    for p in [
        "/v1/guardian/nonce?x=1",
        "/v1/guardian/release/",
        "/v1/guardian",
        "/v1/guardian/admin",
        "/v1/kbs/release",
        "",
        "http://10.0.0.1/v1/guardian/nonce",
    ] {
        assert!(!is_guardian_allowed_path(p), "{p}");
    }
    // A guardian path is never a KBS-relay path, and vice versa.
    for p in GUARDIAN_ALLOWED_PATHS {
        assert!(!crate::kbs_vsock::is_allowed_path(p), "{p}");
    }
    // The relay (H4) enforces these; pin the values it is built against.
    assert_eq!(GUARDIAN_MAX_REQUEST_BYTES, 64 * 1024);
    assert_eq!(GUARDIAN_MAX_RESPONSE_BYTES, 16 * 1024);
}

#[test]
fn recipe_path_is_relay_local_never_forwarded() {
    assert_eq!(GUARDIAN_RECIPE_PATH, "/v1/guardian/recipe");
    assert!(!is_guardian_allowed_path(GUARDIAN_RECIPE_PATH));
    assert!(!crate::kbs_vsock::is_allowed_path(GUARDIAN_RECIPE_PATH));
}

#[test]
fn relay_answer_classes_are_distinct_and_never_200() {
    let all = [
        relay_answer::PATH_FORBIDDEN,
        relay_answer::NO_GUARDIAN,
        relay_answer::UNREACHABLE,
        relay_answer::TIMEOUT,
        relay_answer::BAD_RESPONSE,
        relay_answer::REQUEST_TOO_LARGE,
        relay_answer::NO_RECIPE,
        relay_answer::RATE_LIMITED,
    ];
    for (i, (status, class)) in all.iter().enumerate() {
        assert!(*status >= 400, "{class}");
        assert!(class.starts_with("guardian-"), "{class}");
        for (_, other) in &all[i + 1..] {
            assert_ne!(class, other);
        }
    }
}

#[test]
fn signature_domains_are_distinct_and_start_with_a_cbor_text_head() {
    let domains = [
        RESP_SIG_DOMAIN,
        DENY_SIG_DOMAIN,
        STAMP_ACK_SIG_DOMAIN,
        crate::custody::BIND_SIG_DOMAIN,
        crate::custody::RENEW_SIG_DOMAIN,
        crate::custody::REKEY_SIG_DOMAIN,
        crate::custody::VERDICT_SIG_DOMAIN,
    ];
    for (i, a) in domains.iter().enumerate() {
        assert_eq!(a[0], 0x68, "CBOR text head, never a map head");
        assert_eq!(*a.last().unwrap(), 0, "NUL-terminated");
        for b in &domains[i + 1..] {
            assert!(!a.starts_with(b) && !b.starts_with(a));
        }
    }
    assert_ne!(SHARE_HPKE_INFO, STAMP_TOKEN_HPKE_INFO);
    assert_ne!(SHARE_HPKE_INFO, crate::release::HPKE_INFO);
    assert_ne!(SHARE_HPKE_INFO, crate::custody::REKEY_HPKE_INFO);
}

#[test]
fn signing_inputs_prefix_their_domain() {
    let r = SignedGuardianResponse {
        body: b"body".to_vec(),
        sig: vec![0; SIG_LEN],
    };
    let d = SignedGuardianDenial {
        body: b"body".to_vec(),
        sig: vec![0; SIG_LEN],
    };
    let a = SignedGuardianStampAck {
        body: b"body".to_vec(),
        sig: vec![0; SIG_LEN],
    };
    assert_eq!(r.signing_input(), [RESP_SIG_DOMAIN, b"body"].concat());
    assert_eq!(d.signing_input(), [DENY_SIG_DOMAIN, b"body"].concat());
    assert_eq!(
        a.signing_input(),
        b"hippius-guardian-stamp-ack-v1\0body".to_vec()
    );
    assert_ne!(r.signing_input(), d.signing_input());
    assert_ne!(a.signing_input(), r.signing_input());
    assert_ne!(a.signing_input(), d.signing_input());
    r.validate().unwrap();
    d.validate().unwrap();
    a.validate().unwrap();
    for len in [0, 63, 65] {
        let bad = SignedGuardianStampAck {
            body: vec![],
            sig: vec![0; len],
        };
        assert!(bad.validate().is_err(), "{len}");
    }
    let bad = SignedGuardianResponse {
        body: vec![],
        sig: vec![0; 63],
    };
    assert!(bad.validate().is_err());
    let bad = SignedGuardianDenial {
        body: vec![],
        sig: vec![0; 65],
    };
    assert!(bad.validate().is_err());
}

// ---------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------

fn recipe() -> LaunchRecipe {
    LaunchRecipe {
        ovmf_sha384: vec![1; 48],
        kernel_sha256: vec![2; 32],
        initrd_sha256: vec![3; 32],
        cmdline: split_cmdline(),
        vcpus: 4,
        vcpu_type: "EpycGenoa".into(),
        guest_features: 1,
    }
}

fn release_req() -> GuardianReleaseRequest {
    GuardianReleaseRequest {
        v: 1,
        vm_id: "vm-1".into(),
        key_mode: KeyMode::Split,
        nonce: vec![4; 32],
        snp_report: vec![0; 1184],
        guest_pub: vec![5; 32],
        vcek_chain: vec![0x30; 3000],
        launch_recipe: recipe(),
        share_c_version: Some(1),
    }
}

fn wrapped(b: u8) -> GuardianWrapped {
    GuardianWrapped {
        enc: vec![b; HPKE_ENC_LEN],
        ct: vec![b; WRAPPED_CT_LEN],
    }
}

fn response(mode: KeyMode) -> GuardianResponse {
    let customer = mode == KeyMode::Customer;
    GuardianResponse {
        v: 1,
        vm_id: "vm-1".into(),
        nonce: vec![4; 32],
        guest_pub_hash: guest_pub_hash(&[5; 32]).to_vec(),
        key_mode: mode,
        share_c_version: 1,
        wrapped_share: wrapped(6),
        expected_volume_stamp: customer.then_some(9),
        stamp_token_wrapped: customer.then(|| wrapped(7)),
    }
}

fn denial() -> GuardianDenial {
    GuardianDenial {
        v: 1,
        vm_id: "vm-1".into(),
        nonce: vec![4; 32],
        guest_pub_hash: guest_pub_hash(&[5; 32]).to_vec(),
        reason: GuardianDenyReason::ReleaseNotPinned,
    }
}

fn confirm() -> GuardianStampConfirm {
    GuardianStampConfirm {
        v: 1,
        vm_id: "vm-1".into(),
        target: 10,
        token: vec![8; 32],
    }
}

fn ack() -> GuardianStampAck {
    GuardianStampAck {
        v: 1,
        vm_id: "vm-1".into(),
        target: 10,
        token_hash: stamp_token_hash(&[8; 32]).to_vec(),
    }
}

fn round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let bytes = encode_canonical(value).unwrap();
    assert_canonical(&bytes).unwrap();
    let back: T = decode_canonical(&bytes).unwrap();
    assert_eq!(&back, value);
}

fn with_rogue_field<T: Serialize>(value: &T) -> Vec<u8> {
    let mut v = Value::serialized(value).unwrap();
    if let Value::Map(m) = &mut v {
        m.push((Value::Text("rogue".into()), Value::Integer(1.into())));
    }
    to_canonical_vec(&v).unwrap()
}

#[test]
fn every_wire_type_round_trips_and_refuses_unknown_fields() {
    let nreq = GuardianNonceRequest {
        v: 1,
        vm_id: "vm-1".into(),
    };
    let nresp = GuardianNonceResponse {
        v: 1,
        nonce: vec![4; 32],
    };
    let signed_a = SignedGuardianStampAck {
        body: vec![1, 2],
        sig: vec![3; 64],
    };
    let signed = SignedGuardianResponse {
        body: vec![1, 2],
        sig: vec![3; 64],
    };
    let signed_d = SignedGuardianDenial {
        body: vec![1, 2],
        sig: vec![3; 64],
    };
    round_trip(&nreq);
    round_trip(&nresp);
    round_trip(&recipe());
    round_trip(&release_req());
    round_trip(&response(KeyMode::Split));
    round_trip(&response(KeyMode::Customer));
    round_trip(&wrapped(1));
    round_trip(&denial());
    round_trip(&confirm());
    round_trip(&ack());
    round_trip(&signed_a);
    round_trip(&signed);
    round_trip(&signed_d);

    assert!(decode_canonical::<GuardianNonceRequest>(&with_rogue_field(&nreq)).is_err());
    assert!(decode_canonical::<GuardianNonceResponse>(&with_rogue_field(&nresp)).is_err());
    assert!(decode_canonical::<LaunchRecipe>(&with_rogue_field(&recipe())).is_err());
    assert!(decode_canonical::<GuardianReleaseRequest>(&with_rogue_field(&release_req())).is_err());
    assert!(
        decode_canonical::<GuardianResponse>(&with_rogue_field(&response(KeyMode::Split))).is_err()
    );
    assert!(decode_canonical::<GuardianWrapped>(&with_rogue_field(&wrapped(1))).is_err());
    assert!(decode_canonical::<GuardianDenial>(&with_rogue_field(&denial())).is_err());
    assert!(decode_canonical::<GuardianStampConfirm>(&with_rogue_field(&confirm())).is_err());
    assert!(decode_canonical::<GuardianStampAck>(&with_rogue_field(&ack())).is_err());
    assert!(decode_canonical::<SignedGuardianStampAck>(&with_rogue_field(&signed_a)).is_err());
    assert!(decode_canonical::<SignedGuardianResponse>(&with_rogue_field(&signed)).is_err());
    assert!(decode_canonical::<SignedGuardianDenial>(&with_rogue_field(&signed_d)).is_err());
}

#[test]
fn closed_enums_refuse_unknown_wire_values() {
    let mut v = Value::serialized(&denial()).unwrap();
    if let Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            if k == &Value::Text("reason".into()) {
                *val = Value::Text("unreachable".into());
            }
        }
    }
    assert!(decode_canonical::<GuardianDenial>(&to_canonical_vec(&v).unwrap()).is_err());

    let mut v = Value::serialized(&release_req()).unwrap();
    if let Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            if k == &Value::Text("key_mode".into()) {
                *val = Value::Text("SPLIT".into());
            }
        }
    }
    assert!(decode_canonical::<GuardianReleaseRequest>(&to_canonical_vec(&v).unwrap()).is_err());
}

#[test]
fn decode_refuses_second_wire_images() {
    // Struct order is not canonical order.
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&release_req(), &mut bytes).unwrap();
    assert!(decode_canonical::<GuardianReleaseRequest>(&bytes).is_err());

    // An explicit null for an omitted Option.
    let mut v = Value::serialized(&response(KeyMode::Split)).unwrap();
    if let Value::Map(m) = &mut v {
        m.push((Value::Text("expected_volume_stamp".into()), Value::Null));
    }
    let bytes = to_canonical_vec(&v).unwrap();
    assert!(decode_canonical::<GuardianResponse>(&bytes).is_err());

    // An integer array where a byte string belongs.
    let mut v = Value::serialized(&denial()).unwrap();
    if let Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            if k == &Value::Text("nonce".into()) {
                *val = Value::Array(vec![Value::Integer(4.into()); 32]);
            }
        }
    }
    assert!(decode_canonical::<GuardianDenial>(&to_canonical_vec(&v).unwrap()).is_err());
}

#[test]
fn absent_options_are_omitted_not_null() {
    let mut r = release_req();
    r.share_c_version = None;
    let bytes = encode_canonical(&r).unwrap();
    let Value::Map(m) = ciborium::de::from_reader::<Value, _>(bytes.as_slice()).unwrap() else {
        panic!("map")
    };
    assert!(!m
        .iter()
        .any(|(k, _)| k == &Value::Text("share_c_version".into())));
    round_trip(&r);
    r.validate().unwrap();
}

/// Canonical-encoding fixtures, generated independently with Python
/// `cbor2.dumps(obj, canonical=True)`. Every party (guest, guardian,
/// relay tests) must produce these exact bytes.
#[test]
fn canonical_encoding_fixtures() {
    let nreq = GuardianNonceRequest {
        v: 1,
        vm_id: "vm-1".into(),
    };
    assert_eq!(hex(&encode_canonical(&nreq).unwrap()), FIXTURE_NONCE_REQ);

    let d = GuardianDenial {
        v: 1,
        vm_id: "vm-1".into(),
        nonce: vec![0x11; 32],
        guest_pub_hash: vec![0x33; 32],
        reason: GuardianDenyReason::ChipNotApproved,
    };
    assert_eq!(hex(&encode_canonical(&d).unwrap()), FIXTURE_DENIAL);

    let d = GuardianDenial {
        reason: GuardianDenyReason::ShareVersionUnavailable,
        ..d
    };
    assert_eq!(
        hex(&encode_canonical(&d).unwrap()),
        FIXTURE_DENIAL_SHARE_VERSION
    );
    assert_eq!(
        decode_canonical::<GuardianDenial>(&unhex(FIXTURE_DENIAL_SHARE_VERSION)).unwrap(),
        d
    );

    // The stamp-confirm answer is a SIGNED ack over `{v, vm_id, target,
    // token_hash}`. Neither the old bare `{v}` nor the older unsigned
    // `{v, confirmed}` decodes as its body.
    let ack = GuardianStampAck {
        v: 1,
        vm_id: "vm-1".into(),
        target: 300,
        token_hash: stamp_token_hash(&[0x22; 32]).to_vec(),
    };
    assert_eq!(hex(&ack.token_hash), FIXTURE_TOKEN_HASH);
    assert_eq!(hex(&encode_canonical(&ack).unwrap()), FIXTURE_STAMP_ACK);
    assert_eq!(
        decode_canonical::<GuardianStampAck>(&unhex(FIXTURE_STAMP_ACK)).unwrap(),
        ack
    );
    for old in [FIXTURE_CONFIRM_BARE_ACK, FIXTURE_CONFIRM_OLD_SHAPE] {
        assert!(decode_canonical::<GuardianStampAck>(&unhex(old)).is_err());
        assert!(decode_canonical::<SignedGuardianStampAck>(&unhex(old)).is_err());
    }

    let c = GuardianStampConfirm {
        v: 1,
        vm_id: "vm-1".into(),
        target: 300,
        token: vec![0x22; 32],
    };
    assert_eq!(hex(&encode_canonical(&c).unwrap()), FIXTURE_CONFIRM);

    let r = GuardianResponse {
        v: 1,
        vm_id: "vm-1".into(),
        nonce: vec![0x11; 32],
        guest_pub_hash: vec![0x33; 32],
        key_mode: KeyMode::Customer,
        share_c_version: 2,
        wrapped_share: GuardianWrapped {
            enc: vec![0x44; 32],
            ct: vec![0x55; 48],
        },
        expected_volume_stamp: Some(7),
        stamp_token_wrapped: Some(GuardianWrapped {
            enc: vec![0x66; 32],
            ct: vec![0x77; 48],
        }),
    };
    // A real sealed 32-byte secret is 32 B `enc` + 48 B `ct` (32 + the
    // 16-byte Poly1305 tag): the fixture's shape must validate.
    r.validate().unwrap();
    assert_eq!(hex(&encode_canonical(&r).unwrap()), FIXTURE_RESPONSE);
    assert_eq!(hex(&r.wrap_aad().unwrap()), FIXTURE_RESPONSE_AAD);
}

const FIXTURE_NONCE_REQ: &str = "a261760165766d5f696464766d2d31";
const FIXTURE_DENIAL: &str = "a5617601656e6f6e636558201111111111111111111111111111111111111111\
     11111111111111111111111165766d5f696464766d2d3166726561736f6e7163\
     6869702d6e6f742d617070726f7665646e67756573745f7075625f6861736858\
     2033333333333333333333333333333333333333333333333333333333333333\
     33";
const FIXTURE_DENIAL_SHARE_VERSION: &str =
    "a5617601656e6f6e636558201111111111111111111111111111111111111111\
     11111111111111111111111165766d5f696464766d2d3166726561736f6e7819\
     73686172652d76657273696f6e2d756e617661696c61626c656e67756573745f\
     7075625f68617368582033333333333333333333333333333333333333333333\
     33333333333333333333";
const FIXTURE_CONFIRM_BARE_ACK: &str = "a1617601";
const FIXTURE_TOKEN_HASH: &str = "9f72ea0cf49536e3c66c787f705186df9a4378083753ae9536d65b3ad7fcddc4";
const FIXTURE_STAMP_ACK: &str = "a461760165766d5f696464766d2d316674617267657419012c6a746f6b656e5f\
     6861736858209f72ea0cf49536e3c66c787f705186df9a4378083753ae9536d6\
     5b3ad7fcddc4";
const FIXTURE_CONFIRM_OLD_SHAPE: &str = "a261760169636f6e6669726d65640a";
const FIXTURE_CONFIRM: &str = "a461760165746f6b656e58202222222222222222222222222222222222222222\
     22222222222222222222222265766d5f696464766d2d31667461726765741901\
     2c";
const FIXTURE_RESPONSE: &str = "a9617601656e6f6e636558201111111111111111111111111111111111111111\
     11111111111111111111111165766d5f696464766d2d31686b65795f6d6f6465\
     68637573746f6d65726d777261707065645f7368617265a26263745830555555\
     5555555555555555555555555555555555555555555555555555555555555555\
     5555555555555555555555555563656e63582044444444444444444444444444\
     444444444444444444444444444444444444446e67756573745f7075625f6861\
     7368582033333333333333333333333333333333333333333333333333333333\
     333333336f73686172655f635f76657273696f6e02737374616d705f746f6b65\
     6e5f77726170706564a262637458307777777777777777777777777777777777\
     7777777777777777777777777777777777777777777777777777777777777763\
     656e635820666666666666666666666666666666666666666666666666666666\
     66666666667565787065637465645f766f6c756d655f7374616d7007";
const FIXTURE_RESPONSE_AAD: &str =
    "633d061c6ed20b134c5c79eceba8d3a4324b2e2231ec2ea7103920bd7423ecda";

#[test]
fn release_request_validation_rejects_each_bad_field() {
    release_req().validate().unwrap();
    let mut r = release_req();
    r.vcek_chain.clear();
    r.validate().unwrap(); // no chain supplied is allowed
    r.vcek_chain = vec![0; MAX_VCEK_CHAIN_LEN];
    r.validate().unwrap();

    let bad: [fn(&mut GuardianReleaseRequest); 12] = [
        |r| r.v = 2,
        |r| r.vm_id.clear(),
        |r| r.vm_id = "v".repeat(MAX_VM_ID_LEN + 1),
        |r| r.key_mode = KeyMode::Hippius,
        |r| r.nonce = vec![4; 31],
        |r| r.snp_report.clear(),
        |r| r.snp_report = vec![0; MAX_SNP_REPORT_LEN + 1],
        |r| r.guest_pub = vec![5; 33],
        |r| r.vcek_chain = vec![0; MAX_VCEK_CHAIN_LEN + 1],
        |r| r.share_c_version = Some(0),
        |r| r.launch_recipe.vcpus = 0,
        |r| r.launch_recipe.cmdline.clear(),
    ];
    for (i, f) in bad.iter().enumerate() {
        let mut r = release_req();
        f(&mut r);
        assert!(r.validate().is_err(), "case {i}");
    }
    let mut r = release_req();
    r.vm_id = "v".repeat(MAX_VM_ID_LEN);
    r.snp_report = vec![0; MAX_SNP_REPORT_LEN];
    r.key_mode = KeyMode::Customer;
    r.launch_recipe.cmdline = r.launch_recipe.cmdline.replace("=split", "=customer");
    r.validate().unwrap();
}

#[test]
fn release_request_key_mode_must_match_the_measured_cmdline() {
    // M2 recipe asked as M1 (and the reverse): the relay cannot pick the
    // guardian's policy branch.
    let mut r = release_req();
    r.launch_recipe.cmdline = r.launch_recipe.cmdline.replace("=split", "=customer");
    assert!(r.validate().is_err(), "customer recipe, split request");
    let mut r = release_req();
    r.key_mode = KeyMode::Customer;
    assert!(r.validate().is_err(), "split recipe, customer request");
    // An M0 recipe has no guardian at all.
    let mut r = release_req();
    r.launch_recipe.cmdline = "console=ttyS0 boot=hippius-golden".into();
    assert!(r.validate().is_err(), "M0 recipe");
    let mut r = release_req();
    r.launch_recipe.cmdline = r.launch_recipe.cmdline.replace("=split", "=hippius");
    assert!(r.validate().is_err(), "explicit M0 recipe");
    // A recipe the one grammar refuses is refused here too.
    let mut r = release_req();
    r.launch_recipe.cmdline.push_str(" hippius.key_mode=split");
    assert!(r.validate().is_err(), "duplicate mode token");
}

#[test]
fn recipe_validation_rejects_each_bad_field() {
    let bad: [fn(&mut LaunchRecipe); 13] = [
        |r| r.ovmf_sha384 = vec![1; 32],
        |r| r.kernel_sha256 = vec![2; 48],
        |r| r.initrd_sha256 = vec![3; 31],
        |r| r.cmdline.clear(),
        |r| r.cmdline = "a".repeat(MAX_MEASURED_CMDLINE_LEN + 1),
        |r| r.vcpus = 0,
        |r| r.vcpus = MAX_VCPUS + 1,
        |r| r.vcpu_type.clear(),
        |r| r.vcpu_type = "a".repeat(MAX_VCPU_TYPE_LEN + 1),
        |r| r.vcpu_type = "Epyc Genoa".into(),
        // The measured spelling: no `/proc/cmdline` newline, no controls.
        |r| r.cmdline.push('\n'),
        |r| r.cmdline.push_str("\tquiet"),
        |r| r.cmdline.push('\u{a0}'),
    ];
    for (i, f) in bad.iter().enumerate() {
        let mut r = recipe();
        f(&mut r);
        assert!(r.validate().is_err(), "case {i}");
    }
    let mut r = recipe();
    r.cmdline = "a".repeat(MAX_MEASURED_CMDLINE_LEN);
    r.vcpus = MAX_VCPUS;
    r.vcpu_type = format!("{}-1", "E".repeat(MAX_VCPU_TYPE_LEN - 2));
    r.validate().unwrap();
    let mut r = recipe();
    r.vcpus = 1;
    r.validate().unwrap();
    // The recipe's cmdline goes through the one grammar.
    assert_eq!(recipe().binding().unwrap().unwrap().mode, KeyMode::Split);
}

#[test]
fn response_validation_ties_stamp_fields_to_the_mode() {
    response(KeyMode::Split).validate().unwrap();
    response(KeyMode::Customer).validate().unwrap();

    // Split with stamp fields, customer without, or one of the pair.
    let mut r = response(KeyMode::Split);
    r.expected_volume_stamp = Some(1);
    r.stamp_token_wrapped = Some(wrapped(7));
    assert!(r.validate().is_err());
    let mut r = response(KeyMode::Customer);
    r.expected_volume_stamp = None;
    r.stamp_token_wrapped = None;
    assert!(r.validate().is_err());
    let mut r = response(KeyMode::Customer);
    r.stamp_token_wrapped = None;
    assert!(r.validate().is_err());
    let mut r = response(KeyMode::Customer);
    r.expected_volume_stamp = None;
    assert!(r.validate().is_err());
    let mut r = response(KeyMode::Split);
    r.expected_volume_stamp = Some(1);
    assert!(r.validate().is_err());
    // A malformed stamp token is refused.
    let mut r = response(KeyMode::Customer);
    r.stamp_token_wrapped = Some(GuardianWrapped {
        enc: vec![0; 32],
        ct: vec![0; 47],
    });
    assert!(r.validate().is_err());

    let bad: [fn(&mut GuardianResponse); 9] = [
        |r| r.v = 0,
        |r| r.vm_id.clear(),
        |r| r.nonce = vec![0; 33],
        |r| r.guest_pub_hash = vec![0; 31],
        |r| r.key_mode = KeyMode::Hippius,
        |r| r.share_c_version = 0,
        |r| r.wrapped_share.enc = vec![0; 31],
        |r| r.wrapped_share.ct = vec![0; WRAPPED_CT_LEN + 1],
        |r| r.wrapped_share.ct = vec![0; 32],
    ];
    for (i, f) in bad.iter().enumerate() {
        let mut r = response(KeyMode::Split);
        f(&mut r);
        assert!(r.validate().is_err(), "case {i}");
    }
}

#[test]
fn wrap_aad_binds_everything_but_the_sealed_fields() {
    let base = response(KeyMode::Customer);
    let aad = base.wrap_aad().unwrap();
    // Changing a sealed field leaves the aad alone (it must exist first).
    let mut r = base.clone();
    r.wrapped_share = wrapped(0xee);
    r.stamp_token_wrapped = Some(wrapped(0xef));
    assert_eq!(r.wrap_aad().unwrap(), aad);
    // Changing any other field moves it.
    let edits: [fn(&mut GuardianResponse); 6] = [
        |r| r.vm_id = "vm-2".into(),
        |r| r.nonce = vec![0; 32],
        |r| r.guest_pub_hash = vec![0; 32],
        |r| r.key_mode = KeyMode::Split,
        |r| r.share_c_version = 3,
        |r| r.expected_volume_stamp = Some(10),
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut r = base.clone();
        f(&mut r);
        assert_ne!(r.wrap_aad().unwrap(), aad, "case {i}");
    }
    // …and it is the hash of the body with exactly those two keys gone.
    let mut v = Value::serialized(&base).unwrap();
    if let Value::Map(m) = &mut v {
        m.retain(|(k, _)| {
            k != &Value::Text("wrapped_share".into())
                && k != &Value::Text("stamp_token_wrapped".into())
        });
        assert_eq!(m.len(), 7);
    }
    let want: [u8; 32] = Sha256::digest(to_canonical_vec(&v).unwrap()).into();
    assert_eq!(aad, want);
}

#[test]
fn small_types_validate() {
    GuardianNonceRequest {
        v: 1,
        vm_id: "x".into(),
    }
    .validate()
    .unwrap();
    assert!(GuardianNonceRequest {
        v: 2,
        vm_id: "x".into()
    }
    .validate()
    .is_err());
    assert!(GuardianNonceRequest {
        v: 1,
        vm_id: String::new()
    }
    .validate()
    .is_err());

    GuardianNonceResponse {
        v: 1,
        nonce: vec![0; 32],
    }
    .validate()
    .unwrap();
    assert!(GuardianNonceResponse {
        v: 1,
        nonce: vec![0; 16]
    }
    .validate()
    .is_err());
    assert!(GuardianNonceResponse {
        v: 0,
        nonce: vec![0; 32]
    }
    .validate()
    .is_err());

    denial().validate().unwrap();
    let mut d = denial();
    d.nonce.pop();
    assert!(d.validate().is_err());
    let mut d = denial();
    d.v = 2;
    assert!(d.validate().is_err());
    let mut d = denial();
    d.vm_id.clear();
    assert!(d.validate().is_err());

    confirm().validate().unwrap();
    let mut c = confirm();
    c.target = 0;
    assert!(c.validate().is_err());
    let mut c = confirm();
    c.token = vec![0; 31];
    assert!(c.validate().is_err());
    let mut c = confirm();
    c.v = 9;
    assert!(c.validate().is_err());
    let mut c = confirm();
    c.vm_id.clear();
    assert!(c.validate().is_err());

    ack().validate().unwrap();
    let edits: [fn(&mut GuardianStampAck); 5] = [
        |a| a.v = 2,
        |a| a.vm_id.clear(),
        |a| a.vm_id = "v".repeat(MAX_VM_ID_LEN + 1),
        |a| a.target = 0,
        |a| a.token_hash = vec![0; 31],
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut a = ack();
        f(&mut a);
        assert!(a.validate().is_err(), "case {i}");
    }
    let mut a = ack();
    a.vm_id = "v".repeat(MAX_VM_ID_LEN);
    a.target = 1;
    a.validate().unwrap();
}

#[test]
fn guest_pub_hash_is_sha256() {
    assert_eq!(
        hex(&guest_pub_hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ---------------------------------------------------------------------
// combine_kek
// ---------------------------------------------------------------------

fn share_h() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn share_c() -> [u8; 32] {
    core::array::from_fn(|i| 0xa0 + u8::try_from(i).unwrap())
}

const KAT_VM: &str = "vm-kat-kek-01";

/// KAT computed independently with Python `hmac`/`hashlib` (RFC 5869
/// HKDF written out by hand, itself checked against RFC 5869 test case
/// 1): `share_H = 00..1f`, `share_C = a0..bf`, `vm_id = "vm-kat-kek-01"`.
#[test]
fn combine_kek_known_answers() {
    let m1 = combine_kek(KeyMode::Split, Some(&share_h()), Some(&share_c()), KAT_VM).unwrap();
    assert_eq!(
        hex(&m1[..]),
        "00f85e62c082cbc12fae9469acef40f60643eac3e40a2719c8d004276a70c9bb"
    );
    let m2 = combine_kek(KeyMode::Customer, None, Some(&share_c()), KAT_VM).unwrap();
    assert_eq!(
        hex(&m2[..]),
        "da3400f63de565d42a261b34faf1279b9351cb2e31e11ec3df3476bdf74032b7"
    );
}

#[test]
fn combine_kek_m0_is_share_h_byte_for_byte() {
    let k = combine_kek(KeyMode::Hippius, Some(&share_h()), None, KAT_VM).unwrap();
    assert_eq!(*k, share_h());
    // M0 does not look at vm_id at all (today's path never did).
    let k = combine_kek(KeyMode::Hippius, Some(&share_h()), None, "").unwrap();
    assert_eq!(*k, share_h());
}

#[test]
fn combine_kek_separates_modes_and_binds_the_vm() {
    let c = share_c();
    let m1 = combine_kek(KeyMode::Split, Some(&share_h()), Some(&c), KAT_VM).unwrap();
    let m2 = combine_kek(KeyMode::Customer, None, Some(&c), KAT_VM).unwrap();
    assert_ne!(*m1, *m2, "same share_C, different mode ⇒ different KEK");
    // M1 needs both shares: a different share_H moves the key.
    let other_h = [0x5a; 32];
    let m1b = combine_kek(KeyMode::Split, Some(&other_h), Some(&c), KAT_VM).unwrap();
    assert_ne!(*m1, *m1b);
    // …and neither share alone is the key.
    assert_ne!(*m1, share_h());
    assert_ne!(*m1, c);
    assert_ne!(*m2, c);
    // vm_id is bound.
    for mode_h in [Some(&share_h()), None] {
        let mode = if mode_h.is_some() {
            KeyMode::Split
        } else {
            KeyMode::Customer
        };
        let a = combine_kek(mode, mode_h, Some(&c), "vm-a").unwrap();
        let b = combine_kek(mode, mode_h, Some(&c), "vm-b").unwrap();
        assert_ne!(*a, *b);
    }
}

#[test]
fn combine_kek_refuses_wrong_share_combinations() {
    let h = share_h();
    let c = share_c();
    type Case<'a> = (KeyMode, Option<&'a [u8; 32]>, Option<&'a [u8; 32]>);
    let bad: [Case; 9] = [
        (KeyMode::Hippius, None, None),
        (KeyMode::Hippius, Some(&h), Some(&c)),
        (KeyMode::Hippius, None, Some(&c)),
        (KeyMode::Split, None, None),
        (KeyMode::Split, Some(&h), None),
        (KeyMode::Split, None, Some(&c)),
        (KeyMode::Customer, None, None),
        (KeyMode::Customer, Some(&h), Some(&c)),
        (KeyMode::Customer, Some(&h), None),
    ];
    for (i, (m, sh, sc)) in bad.into_iter().enumerate() {
        assert!(combine_kek(m, sh, sc, KAT_VM).is_err(), "case {i}");
    }
}

#[test]
fn combine_kek_refuses_a_bad_vm_id_in_customer_modes() {
    let h = share_h();
    let c = share_c();
    let long = "v".repeat(MAX_VM_ID_LEN + 1);
    for vm in ["", long.as_str()] {
        assert!(combine_kek(KeyMode::Split, Some(&h), Some(&c), vm).is_err());
        assert!(combine_kek(KeyMode::Customer, None, Some(&c), vm).is_err());
    }
    let max = "v".repeat(MAX_VM_ID_LEN);
    assert!(combine_kek(KeyMode::Customer, None, Some(&c), &max).is_ok());
}

// ---------------------------------------------------------------------
// review follow-ups: byte hygiene, cmdline cap, echo checks
// ---------------------------------------------------------------------

#[test]
fn non_printable_bytes_are_refused_when_a_grammar_key_is_present() {
    let base = split_cmdline();
    for bad in [
        "\t", "\x0b", "\x0c", "\r", "\u{a0}", "\u{7f}", "\x00", "\n ",
    ] {
        let c = format!("{base}{bad}quiet");
        assert_eq!(parse(&c), Err(CmdlineError::NonPrintable), "{bad:?}");
    }
    // `\x0B` is kernel whitespace but not Rust ASCII whitespace: without
    // the byte rule this would hide a second mode token from one reader.
    let c = format!("{base}\x0bhippius.key_mode=customer");
    assert_eq!(parse(&c), Err(CmdlineError::NonPrintable));
    assert_eq!(
        parse("hippius.key_mode=split\thippius.guardian_pk=00"),
        Err(CmdlineError::NonPrintable)
    );
    // An M0 cmdline with tabs is none of our business.
    assert_eq!(parse("console=ttyS0\tquiet\x0bro").unwrap(), None);
    // Printable edges pass: `~` (0x7e) and ` ` (0x20).
    assert!(parse(&format!("{base} x=~")).unwrap().is_some());
}

#[test]
fn one_trailing_newline_is_the_proc_cmdline_spelling() {
    let base = split_cmdline();
    assert_eq!(parse(&format!("{base}\n")).unwrap(), parse(&base).unwrap());
    assert_eq!(
        parse(&format!("{base}\n\n")),
        Err(CmdlineError::NonPrintable)
    );
}

#[test]
fn cmdline_cap_is_the_x86_command_line_size_minus_nul() {
    assert_eq!(MAX_CMDLINE_LEN, 2047);
    // OVMF prefixes `initrd=initrd ` (14 bytes) to the measured cmdline.
    assert_eq!(OVMF_INITRD_PREFIX.len(), 14);
    assert_eq!(MAX_MEASURED_CMDLINE_LEN, 2033);
}

fn binding() -> GuardianBinding {
    parse(&split_cmdline()).unwrap().unwrap()
}

#[test]
fn response_check_against_accepts_the_matching_answer() {
    response(KeyMode::Split)
        .check_against(&binding(), &release_req())
        .unwrap();
    // No version in the request (first boot) ⇒ any version is fine.
    let mut req = release_req();
    req.share_c_version = None;
    let mut r = response(KeyMode::Split);
    r.share_c_version = 5;
    r.check_against(&binding(), &req).unwrap();
    // Customer mode end to end.
    let mut req = release_req();
    req.key_mode = KeyMode::Customer;
    let mut b = binding();
    b.mode = KeyMode::Customer;
    response(KeyMode::Customer).check_against(&b, &req).unwrap();
}

#[test]
fn response_check_against_refuses_every_mismatch() {
    let edits: [fn(&mut GuardianResponse); 6] = [
        |r| r.vm_id = "vm-2".into(),
        |r| r.nonce = vec![0; 32],
        |r| r.guest_pub_hash = guest_pub_hash(&[6; 32]).to_vec(),
        |r| r.share_c_version = 2,
        |r| r.v = 2,
        |r| r.wrapped_share.enc.clear(),
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut r = response(KeyMode::Split);
        f(&mut r);
        assert!(
            r.check_against(&binding(), &release_req()).is_err(),
            "case {i}"
        );
    }
    // Mode: response vs request, and response vs the measured binding.
    let r = response(KeyMode::Customer);
    assert!(r.check_against(&binding(), &release_req()).is_err());
    let mut req = release_req();
    req.key_mode = KeyMode::Customer;
    assert!(
        r.check_against(&binding(), &req).is_err(),
        "binding says split"
    );
    let mut b = binding();
    b.mode = KeyMode::Customer;
    assert!(
        response(KeyMode::Split)
            .check_against(&b, &release_req())
            .is_err(),
        "binding says customer"
    );
    // Response agrees with the measured binding but not with the request.
    assert!(
        response(KeyMode::Customer)
            .check_against(&b, &release_req())
            .is_err(),
        "request says split"
    );
}

#[test]
fn denial_check_against_requires_the_full_echo() {
    denial().check_against(&release_req()).unwrap();
    let edits: [fn(&mut GuardianDenial); 5] = [
        |d| d.vm_id = "vm-2".into(),
        |d| d.nonce = vec![0; 32],
        // The replay the nonce alone cannot stop: same nonce, old key.
        |d| d.guest_pub_hash = guest_pub_hash(&[6; 32]).to_vec(),
        |d| d.guest_pub_hash = vec![0; 31],
        |d| d.v = 0,
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut d = denial();
        f(&mut d);
        assert!(d.check_against(&release_req()).is_err(), "case {i}");
    }
}

// ---------------------------------------------------------------------
// cloud-init cmdline directives (H5b review B2)
// ---------------------------------------------------------------------

#[test]
fn cc_anywhere_is_refused_in_a_keyed_cmdline() {
    // The Debian 12 (cloud-init 22.4.2) repro: `read_cc_from_cmdline`
    // finds `cc:` inside another token and reads up to `end_cc`.
    for extra in [
        "hippius.vm_id=acc:datasource:end_cc",
        "hippius.vm_id=acc:datasource_list:[NoCloud]",
        "x=cc:runcmd:[[id]]",
        "cc:runcmd:%5B%5Bid%5D%5D end_cc",
        "cc: ssh_import_id: [x]",
        "y=end_cc",
        "hippius.lease_id=Xcc:",
    ] {
        let c = format!("{} {extra}", split_cmdline());
        assert_eq!(parse(&c), Err(CmdlineError::CloudInitDirective), "{extra}");
    }
}

#[test]
fn cloud_init_cmdline_keys_are_refused_in_a_keyed_cmdline() {
    for extra in [
        "url=http://x/cfg",
        "url",
        "cloud-config-url=file:///run/x",
        "network-config=e30K",
        "ci.ds=Ec2",
        "ci.datasource=OpenStack",
        "ci.di.policy=search",
        "ci.datasource.ec2.strict_id=false",
        "ds=Ec2",
        "ds=",
        "ds",
        "ds=nocloud;i=iid-evil",
        "ds=nocloud;h=evil",
        "ds=nocloud;public-keys=ssh-ed25519",
        "ds=nocloud;s=http://evil/",
        "ds=nocloud;s=/run/cloud-init/seed/;i=iid-evil",
        "ds=nocloud-net;s=http://evil/",
        "ds=nocloudx",
        "ds=nocloud;",
    ] {
        let c = format!("{} {extra}", split_cmdline());
        assert_eq!(parse(&c), Err(CmdlineError::CloudInitDirective), "{extra}");
        assert!(carries_cloud_init_directive(&c), "{extra}");
    }
}

#[test]
fn the_golden_cmdline_shapes_still_parse() {
    // cloud-init splits on whitespace and keys on the first `=`:
    // `hippius.kbs_url=` / `hippius.vali_url=` are not `url=`, and the
    // canonical NoCloud tokens are allowed.
    for ds in ALLOWED_DS_VALUES {
        let c = format!(
            "{} ds={ds} hippius.kbs_url=vsock://2:19266 hippius.vali_url=vsock://2:19270 \
             systemd.import_credentials=no ip=off root=/dev/mapper/x cloud-init=enabled \
             xurl=1 xds=Ec2 rd.ci.ds=1 surl=cc",
            split_cmdline()
        );
        assert!(parse(&c).unwrap().is_some(), "{ds}");
        assert!(!carries_cloud_init_directive(&c), "{ds}");
    }
}

#[test]
fn an_m0_cmdline_is_not_checked_for_cloud_init_directives() {
    // No grammar key: M0 stays byte-identical, whatever cloud-init
    // tokens it carries.
    assert_eq!(
        parse("console=ttyS0 ds=nocloud;i=x url=http://x cc:a end_cc").unwrap(),
        None
    );
    // An explicit `hippius` mode mentions a grammar key: checked.
    assert_eq!(
        parse("hippius.key_mode=hippius url=http://x"),
        Err(CmdlineError::CloudInitDirective)
    );
}

// ---------------------------------------------------------------------
// H1b: the hex-encoded guardian endpoint token
// ---------------------------------------------------------------------

fn keyed_with_ep_value(v: &str) -> String {
    format!(
        "console=ttyS0 hippius.key_mode=customer hippius.guardian_pk={PK_HEX} \
         hippius.guardian_ep={v}"
    )
}

fn ep_hex(s: &str) -> String {
    hex(s.as_bytes())
}

#[test]
fn the_ep_token_is_the_lowercase_hex_of_the_canonical_endpoint() {
    for s in [
        "100.64.3.7:7443",
        "guardian.example.com:7443",
        "[2001:db8::7]:7443",
        "[::ffff:10.0.0.1]:80",
    ] {
        let ep = GuardianEndpoint::parse(s).unwrap();
        let tok = encode_guardian_ep_token(&ep);
        assert_eq!(tok, ep_hex(s), "{s}");
        // The binding exposes the DECODED endpoint.
        let b = parse(&keyed_with_ep_value(&tok)).unwrap().unwrap();
        assert_eq!(b.endpoint, ep, "{s}");
        assert_eq!(b.endpoint.to_wire(), s);
    }
    // Pinned independently (python3 `"100.64.3.7:7443".encode().hex()`).
    let ep = GuardianEndpoint::parse("100.64.3.7:7443").unwrap();
    assert_eq!(
        encode_guardian_ep_token(&ep),
        "3130302e36342e332e373a37343433"
    );
    // Every nibble maps (0-9 and a-f edges).
    assert_eq!(
        lower_hex(&[0x00, 0x09, 0x0a, 0x0f, 0x90, 0xaf, 0xff]),
        "00090a0f90afff"
    );
}

#[test]
fn endpoints_that_spell_cloud_init_markers_are_accepted_once_hex_encoded() {
    for s in [
        "guardian.example.cc:443",
        "[2001:db8::cc:1]:443",
        "end-cc.example.com:1",
        "cc.example.com:1",
        "[cc::1]:443",
    ] {
        let c = keyed_with_ep_value(&ep_hex(s));
        assert!(!c.contains("cc:") && !c.contains("end_cc"), "{s}");
        let b = parse(&c).unwrap().unwrap();
        assert_eq!(b.endpoint.to_wire(), s);
    }
    // Pinned independently (python3 `.encode().hex()`).
    assert_eq!(
        ep_hex("guardian.example.cc:443"),
        "677561726469616e2e6578616d706c652e63633a343433"
    );
    assert_eq!(
        ep_hex("[2001:db8::cc:1]:443"),
        "5b323030313a6462383a3a63633a315d3a343433"
    );
    // The PLAIN spelling is not the token, and the substring rule still
    // stands in front of it (defence in depth).
    assert_eq!(
        parse(&keyed_with_ep_value("guardian.example.cc:443")),
        Err(CmdlineError::CloudInitDirective)
    );
}

#[test]
fn every_other_ep_token_spelling_is_refused() {
    let good = ep_hex("100.64.3.7:7443");
    let long = ep_hex(&format!("{}:1", "a".repeat(MAX_ENDPOINT_LEN)));
    let bad_values = [
        "100.64.3.7:7443".to_string(), // the plain endpoint
        good.to_ascii_uppercase(),     // uppercase hex
        format!("{}{}", &good[..2], good[2..].to_ascii_uppercase()),
        good[..good.len() - 1].to_string(),   // odd length
        "3".to_string(),                      // one digit
        format!("0x{good}"),                  // `0x` prefix
        format!("{good}g0"),                  // non-hex digit
        "ff".to_string(),                     // not UTF-8
        "c328".to_string(),                   // invalid UTF-8 sequence
        format!("{good}00"),                  // decoded `\0` suffix
        format!("{good}20"),                  // decoded ` ` suffix
        ep_hex("100.64.3.7:07443"),           // non-canonical port
        ep_hex("100.064.3.7:7443"),           // non-canonical octet
        ep_hex("G.example.com:1"),            // uppercase host
        ep_hex("[2001:DB8::1]:1"),            // uppercase IPv6
        ep_hex("[2001:db8:0:0:0:0:0:1]:1"),   // uncompressed IPv6
        ep_hex("https://g.example.com:1"),    // scheme
        ep_hex("g.example.com"),              // no port
        ep_hex("h\u{f6}st.example:1"),        // valid UTF-8, not LDH
        long,                                 // decoded over the cap
        "3".repeat(2 * MAX_ENDPOINT_LEN + 2), // encoded over the cap
    ];
    for bad in bad_values {
        assert_eq!(
            parse(&keyed_with_ep_value(&bad)),
            Err(CmdlineError::BadGuardianEp),
            "{bad:?}"
        );
    }
    // The longest canonical endpoint still fits.
    let l63 = "a".repeat(63);
    let max = format!("{l63}.{l63}.{l63}.{}:65535", "a".repeat(61));
    assert_eq!(max.len(), MAX_ENDPOINT_LEN);
    let b = parse(&keyed_with_ep_value(&ep_hex(&max))).unwrap().unwrap();
    assert_eq!(b.endpoint.to_wire(), max);
}

// ---------------------------------------------------------------------
// H1b: the signed M2 stamp-confirm ack
// ---------------------------------------------------------------------

#[test]
fn stamp_token_hash_is_sha256_of_the_token() {
    // python3: hashlib.sha256(b"\x22" * 32).hexdigest()
    assert_eq!(hex(&stamp_token_hash(&[0x22; 32])), FIXTURE_TOKEN_HASH);
    assert_ne!(stamp_token_hash(&[0x22; 32]), stamp_token_hash(&[0x23; 32]));
}

#[test]
fn stamp_ack_check_against_accepts_its_own_confirm() {
    ack().check_against(&confirm()).unwrap();
}

#[test]
fn stamp_ack_check_against_refuses_every_mismatch() {
    let edits: [fn(&mut GuardianStampAck); 7] = [
        |a| a.vm_id = "vm-2".into(),
        |a| a.target = 11,
        |a| a.target = 9,
        |a| a.token_hash = stamp_token_hash(&[9; 32]).to_vec(),
        // The token itself is not its hash.
        |a| a.token_hash = vec![8; 32],
        |a| a.token_hash = vec![0; 32],
        |a| a.v = 2,
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut a = ack();
        f(&mut a);
        assert!(a.check_against(&confirm()).is_err(), "case {i}");
    }
}

#[test]
fn an_old_ack_for_the_same_vm_and_target_does_not_answer_a_new_confirm() {
    // After a guardian re-init (or an authorised rollback) the same
    // (vm_id, target) comes round again with a FRESH token. An ack the
    // relay recorded the first time must not verify the second time.
    let old_confirm = confirm();
    let old_ack = ack();
    old_ack.check_against(&old_confirm).unwrap();
    let mut new_confirm = confirm();
    new_confirm.token = vec![0x5a; 32];
    assert_eq!(new_confirm.vm_id, old_confirm.vm_id);
    assert_eq!(new_confirm.target, old_confirm.target);
    assert!(old_ack.check_against(&new_confirm).is_err());
}
