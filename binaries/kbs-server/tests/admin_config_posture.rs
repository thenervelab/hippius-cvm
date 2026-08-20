//! `GET /v1/admin/config` — the posture readout's TWO load-bearing
//! claims, tested against the real `Config` parser and the real
//! derivation (`wiring::config_posture`):
//!
//! 1. it reports the EFFECTIVE posture — the resolved values the
//!    process enforces, not the raw operator input;
//! 2. it exposes **posture, never material**. Every path, URL, mount
//!    name and key in the config below is a distinctive canary string,
//!    and none of them may appear anywhere in the serialised response.
//!    The field set is pinned exactly, so a future addition that leaks
//!    has to fight this test rather than slip through review.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_kbs_server::config::Config;
use hippius_kbs_server::wiring::config_posture;
use std::io::Write;

/// Every value here that could POSSIBLY be sensitive is a canary:
/// filesystem paths (they map where secrets live), the Vault address +
/// KV mount (they map where KEKs live), the broker URL, the listen
/// addresses, and the raw public keys.
const CANARIES: &[&str] = &[
    "CANARY-signing-key-path",
    "CANARY-vault-address",
    "CANARY-kv-mount",
    "CANARY-broker",
    "CANARY-broker-ca",
    "CANARY-vault-ca",
    "CANARY-allowlist-path",
    "CANARY-vek-path",
    "CANARY-admin-tls",
    "CANARY-kds",
    // Raw key material / identifiers rendered in the config.
    "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d", // allowlist root
    "4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e", // rotation root
    "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f", // L1 pubkey
    "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a", // KBS auth pubkey
    "0102030405060708",                                                 // kid
];

/// The COMPLETE, pinned set of fields the posture response serialises.
///
/// Adding a field here is a deliberate act: it must be posture (a
/// boolean, a bound, a count, an enum label or a fingerprint) and it
/// must survive the canary assertion below. Removing one is a wire
/// break for `apps.synthetic.checks.check_kbs_config_drift`.
const PINNED_FIELDS: &[&str] = &[
    "v",
    "require_wrapped_kek",
    "max_unconfirmed_releases",
    "volume_stamp_gate_armed",
    "admin_listener_mode",
    "evidence_sink_wired",
    "live_attestation_sink_wired",
    "allowlist_root_pubkey_fpr",
    "allowlist_root_next_pubkey_fpr",
    "allowlist_signed_path_configured",
    "l1_key_count",
    "min_tcb",
    "required_bits",
    "allowed_mask",
    "snp_chain_wired",
    "snp_generation",
    "snp_kds_fetch_enabled",
    "vault_broker_wired",
    "vault_broker_ca_pinned",
    "vault_ca_pinned",
    "vault_dev_environment",
    "vault_dev_allow_any_kbs_measurement",
    "vault_dev_skip_tls_verify",
];

/// A maximally-populated production-shaped config: every optional
/// section present, every path/URL a canary.
const CANARY_CONFIG: &str = r#"
require_wrapped_kek = true

[listen]
addr = "10.11.12.13:8000"

[storage]
state_dir = "/var/lib/CANARY-state"
audit_dir = "/var/lib/CANARY-audit"
nonce_ttl_secs = 300
evidence_dir = "/var/lib/CANARY-evidence"
live_attestation_dir = "/var/lib/CANARY-live-attestation"
max_unconfirmed_releases = 3

[allowlist]
root_pubkey_hex = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d"
root_pubkey_hex_next = "4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e"
signed_path = "/etc/CANARY-allowlist-path/allowlist.cose"

[keys]
signing_key_path = "/etc/CANARY-signing-key-path/signing.key"
kid_hex = "0102030405060708"
auth_pubkey_hex = "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a"

[vault]
address = "https://CANARY-vault-address:8200"
kv_mount = "CANARY-kv-mount"
broker_url = "https://CANARY-broker:8100"
broker_ca_path = "/etc/CANARY-broker-ca/ca.pem"
ca_cert_path = "/etc/CANARY-vault-ca/ca.pem"

[launch_policy]
min_tcb = 25
required_bits = 2
allowed_mask = 6

[live_attestation]
compute_chain_genesis_hex = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"
compute_pallet_instance_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

[[l1_keys]]
kid_hex = "0102030405060708"
pubkey_hex = "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f"

[snp]
generation = "turin"
vek_pem_path = "/etc/CANARY-vek-path/vek.pem"
kds_url = "https://CANARY-kds.example"

[admin]
addr = "10.11.12.13:8001"
require_mtls = true
tls_cert_path = "/etc/CANARY-admin-tls/tls.crt"
tls_key_path = "/etc/CANARY-admin-tls/tls.key"
client_ca_path = "/etc/CANARY-admin-tls/ca.crt"
"#;

fn load(body: &str) -> Config {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(body.as_bytes()).unwrap();
    Config::load(f.path()).expect("test config must load")
}

#[test]
fn posture_exposes_exactly_the_pinned_field_set() {
    let posture = config_posture(&load(CANARY_CONFIG));
    let value = serde_json::to_value(&posture).unwrap();
    let obj = value
        .as_object()
        .expect("posture must serialise to an object");

    let mut got: Vec<&str> = obj.keys().map(String::as_str).collect();
    got.sort_unstable();
    let mut want: Vec<&str> = PINNED_FIELDS.to_vec();
    want.sort_unstable();
    assert_eq!(
        got, want,
        "the posture response's field set changed. This endpoint is served to an \
         authenticated operator, but 'authenticated' is not a licence to publish secrets: \
         a new field must be posture (boolean / bound / count / label / fingerprint) and \
         must not carry a path, a URL, a mount name or key material. Update PINNED_FIELDS \
         only after checking it against the canary test below."
    );
}

#[test]
fn posture_leaks_no_path_no_url_and_no_key_material() {
    let posture = config_posture(&load(CANARY_CONFIG));
    let body = serde_json::to_string(&posture).unwrap();

    for canary in CANARIES {
        assert!(
            !body.contains(canary),
            "the posture response leaked {canary:?} — a path/URL/key from the config must \
             never reach this endpoint. Response was: {body}"
        );
    }
    // Belt-and-braces: nothing that looks like a filesystem path or a
    // URL scheme, whatever it is named.
    assert!(
        !body.contains("/etc/") && !body.contains("/var/"),
        "the posture response contains a filesystem path: {body}"
    );
    assert!(
        !body.contains("http://") && !body.contains("https://"),
        "the posture response contains a URL: {body}"
    );
}

#[test]
fn posture_reports_the_resolved_values_the_process_enforces() {
    let posture = config_posture(&load(CANARY_CONFIG));

    // Resolved, not raw: `3` stays `3`, and the ARMED boolean is derived
    // from the same `Option` gate 5c enforces.
    assert_eq!(posture.max_unconfirmed_releases, Some(3));
    assert!(posture.volume_stamp_gate_armed);
    assert!(posture.require_wrapped_kek);
    // The mode `AdminListenerMode::decide` ACTUALLY picked — material is
    // complete, so mTLS, and it would say so even with require_mtls
    // false (see the next test).
    assert_eq!(posture.admin_listener_mode, "mtls");
    assert!(posture.evidence_sink_wired);
    assert!(posture.live_attestation_sink_wired);
    assert!(posture.allowlist_signed_path_configured);
    assert_eq!(posture.l1_key_count, 1);
    assert_eq!(posture.min_tcb, 25);
    assert_eq!(posture.required_bits, 2);
    assert_eq!(posture.allowed_mask, 6);
    assert!(posture.snp_chain_wired);
    assert_eq!(posture.snp_generation.as_deref(), Some("turin"));
    assert!(posture.snp_kds_fetch_enabled);
    assert!(posture.vault_broker_wired);
    assert!(posture.vault_broker_ca_pinned);
    assert!(posture.vault_ca_pinned);
    assert!(!posture.vault_dev_environment);
    assert!(!posture.vault_dev_allow_any_kbs_measurement);
    assert!(!posture.vault_dev_skip_tls_verify);

    // The fingerprint is SHA-256(decoded pubkey)[..8], lower-case hex —
    // reproducible by an operator, and NOT the key.
    let expected = {
        use sha2::{Digest, Sha256};
        let raw = hex::decode("3d".repeat(32)).unwrap();
        hex::encode(&Sha256::digest(&raw)[..8])
    };
    assert_eq!(posture.allowlist_root_pubkey_fpr, expected);
    assert_eq!(posture.allowlist_root_pubkey_fpr.len(), 16);
    assert_ne!(
        posture.allowlist_root_pubkey_fpr,
        "3d".repeat(32),
        "the fingerprint must not be the key"
    );
    // A rotation in flight is visible, also as a fingerprint.
    assert!(posture.allowlist_root_next_pubkey_fpr.is_some());
    assert_ne!(
        posture.allowlist_root_next_pubkey_fpr,
        Some(posture.allowlist_root_pubkey_fpr.clone())
    );
}

#[test]
fn posture_reports_the_disabled_gate_as_none_not_zero() {
    // `max_unconfirmed_releases = 0` is the operator vocabulary for
    // DISABLED, and the binary resolves it to `None`. Reporting a
    // literal `0` would read as "bound = 0, refuse everything" — the
    // exact opposite of the deployed behaviour.
    let body = CANARY_CONFIG.replace(
        "max_unconfirmed_releases = 3",
        "max_unconfirmed_releases = 0",
    );
    let posture = config_posture(&load(&body));
    assert_eq!(posture.max_unconfirmed_releases, None);
    assert!(!posture.volume_stamp_gate_armed);
    let json = serde_json::to_value(&posture).unwrap();
    assert_eq!(json["max_unconfirmed_releases"], serde_json::Value::Null);
}

#[test]
fn posture_reports_the_listener_mode_decide_picks_not_the_require_mtls_flag() {
    // `require_mtls` is NOT the enforcement switch: complete material
    // enforces mTLS whatever the flag says, and absent material with the
    // flag OFF is a plaintext, UNAUTHENTICATED lifecycle API. A posture
    // readout that echoed the flag would report "false" for a listener
    // that is in fact enforcing, and "false" for one that is in fact
    // wide open — the same word for opposite states.
    let with_material_flag_off =
        CANARY_CONFIG.replace("require_mtls = true", "require_mtls = false");
    assert_eq!(
        config_posture(&load(&with_material_flag_off)).admin_listener_mode,
        "mtls",
        "material present ⇒ mTLS is enforced whatever require_mtls says"
    );

    let no_material_flag_off = CANARY_CONFIG
        .replace("require_mtls = true", "require_mtls = false")
        .replace("tls_cert_path = \"/etc/CANARY-admin-tls/tls.crt\"\n", "")
        .replace("tls_key_path = \"/etc/CANARY-admin-tls/tls.key\"\n", "")
        .replace("client_ca_path = \"/etc/CANARY-admin-tls/ca.crt\"\n", "");
    assert_eq!(
        config_posture(&load(&no_material_flag_off)).admin_listener_mode,
        "plaintext-opt-in",
        "no material + the explicit opt-out ⇒ an UNAUTHENTICATED admin API, and the readout \
         must name that state distinctly"
    );

    let no_material_flag_on = CANARY_CONFIG
        .replace("tls_cert_path = \"/etc/CANARY-admin-tls/tls.crt\"\n", "")
        .replace("tls_key_path = \"/etc/CANARY-admin-tls/tls.key\"\n", "")
        .replace("client_ca_path = \"/etc/CANARY-admin-tls/ca.crt\"\n", "");
    assert_eq!(
        config_posture(&load(&no_material_flag_on)).admin_listener_mode,
        "refuse",
        "no material + require_mtls ⇒ the listener is not bound at all"
    );
}
