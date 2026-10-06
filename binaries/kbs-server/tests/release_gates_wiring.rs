//! The config→release-path seam for the two fail-closed release gates
//! (`require_wrapped_kek`, `require_wrapped_userdata`).
//!
//! Each gate is a `#[serde(default)] = false` config key threaded through
//! `wiring::build_service` into the `DefaultKbsService`, and reported by
//! `wiring::config_posture`. Those are TWO derivations from the same
//! field, and only the posture one was pinned — so deleting a
//! `.with_require_*()` call left the endpoint truthfully reporting
//! `true` while the release path enforced nothing, forever, with the
//! whole suite green. An operator who armed a gate and verified it on
//! `GET /v1/admin/config` would have been reading a number that meant
//! nothing.
//!
//! This asserts against the value the RELEASE PATH holds, and asserts
//! that it agrees with the posture readout — the one thing a monitor can
//! see.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use hippius_kbs_server::config::Config;
use hippius_kbs_server::wiring::{build_service, config_posture};
use std::io::Write;
use zeroize::Zeroizing;

/// A minimal but REAL config: `build_service` reads the signing key off
/// disk and opens the state/audit dirs, so those have to exist.
fn wired_with(gates: &str) -> (Config, hippius_kbs_server::wiring::WiredKbs) {
    wired_with_live(gates, "")
}

/// [`wired_with`] plus extra `[live_attestation]` lines.
fn wired_with_live(gates: &str, live: &str) -> (Config, hippius_kbs_server::wiring::WiredKbs) {
    let (toml, dir) = config_text(gates, live);
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let cfg = Config::load(f.path()).expect("config must load");
    let wired = build_service(&cfg, Zeroizing::new("test-token".to_string()))
        .expect("build_service must wire");
    // `dir` must outlive `build_service` (the stores hold open paths);
    // leak it deliberately so the returned service stays usable.
    std::mem::forget(dir);
    (cfg, wired)
}

fn config_text(gates: &str, live: &str) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let audit = dir.path().join("audit");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&audit).unwrap();
    let key_path = dir.path().join("signing.key");
    std::fs::write(&key_path, [7u8; 32]).unwrap();
    // A REAL Ed25519 pubkey — `build_service` decompresses the allowlist
    // root at boot and refuses a bogus one.
    let root_hex = hex::encode(
        SigningKey::from_bytes(&[3u8; 32])
            .verifying_key()
            .to_bytes(),
    );

    let toml = format!(
        r#"
{gates}

[listen]
addr = "127.0.0.1:8000"

[storage]
state_dir = "{state}"
audit_dir = "{audit}"
nonce_ttl_secs = 300

[allowlist]
root_pubkey_hex = "{root_hex}"

[keys]
signing_key_path = "{key}"
kid_hex = "6b62732d6b6964"
auth_pubkey_hex = "6b62732d617574682d7075626b6579"

[vault]
address = "https://127.0.0.1:8200"
kv_mount = "secret"

[launch_policy]
min_tcb = 0
required_bits = 0
allowed_mask = 0

[live_attestation]
compute_chain_genesis_hex = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"
compute_pallet_instance_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
{live}
"#,
        live = live,
        gates = gates,
        root_hex = root_hex,
        state = state.display(),
        audit = audit.display(),
        key = key_path.display(),
    );
    (toml, dir)
}

#[test]
fn keepalive_binding_reaches_the_keepalive_path() {
    use kbs_core::keepalive_binding::BindingMode;
    let (_, off) = wired_with("");
    assert_eq!(off.service.keepalive_binding_mode, BindingMode::Off);
    let (_, rec) = wired_with_live("", "keepalive_binding = \"record\"");
    assert_eq!(rec.service.keepalive_binding_mode, BindingMode::Record);
    let (_, enf) = wired_with_live("", "keepalive_binding = \"enforce\"");
    assert_eq!(enf.service.keepalive_binding_mode, BindingMode::Enforce);
}

#[test]
fn keepalive_binding_records_live_in_the_state_dir_and_survive_a_rewire() {
    use kbs_core::keepalive_binding::{GuestIdentity, SeedOutcome};
    let (toml, dir) = config_text("", "keepalive_binding = \"record\"");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let cfg = Config::load(f.path()).expect("config must load");
    let file = dir.path().join("state").join("keepalive-bindings.json");
    let guest = GuestIdentity {
        chip_id: [0x11; 64],
        report_id: [0x22; 32],
    };
    {
        let wired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
        // The service and the admin listener share ONE store.
        assert!(std::sync::Arc::ptr_eq(
            &wired.service.keepalive_bindings,
            &wired.keepalive_bindings
        ));
        assert_eq!(
            wired.keepalive_bindings.seed("vm-a", guest).unwrap(),
            SeedOutcome::Seeded
        );
        assert!(
            file.exists(),
            "the record must be written into the state dir"
        );
    } // process restart
    let rewired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
    let rec = rewired.keepalive_bindings.get("vm-a").unwrap().unwrap();
    assert_eq!(rec.guest, guest);
    assert_eq!(
        rewired
            .service
            .keepalive_bindings
            .get("vm-a")
            .unwrap()
            .unwrap()
            .guest,
        guest
    );
}

#[test]
fn an_unknown_keepalive_binding_refuses_to_load() {
    let (toml, _dir) = config_text("", "keepalive_binding = \"on\"");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let err = Config::load(f.path()).expect_err("an unknown mode must not load");
    assert!(err.to_string().contains("keepalive_binding"), "{err}");
}

#[test]
fn every_release_gate_reaches_the_release_path_when_armed() {
    let (cfg, wired) = wired_with(
        "require_wrapped_kek = true\n\
         require_wrapped_userdata = true",
    );
    assert!(
        wired.service.require_wrapped_kek,
        "require_wrapped_kek armed in config but not on the release service"
    );
    assert!(
        wired.service.require_wrapped_userdata,
        "require_wrapped_userdata armed in config but not on the release service — \
         plaintext cloud-init at rest would keep being released"
    );

    // What the release path enforces and what the endpoint reports must
    // be the same fact. A monitor diffs the second against an expected
    // posture; if the two can disagree, that diff certifies nothing.
    let posture = config_posture(&cfg);
    assert_eq!(
        posture.require_wrapped_kek,
        wired.service.require_wrapped_kek
    );
    assert_eq!(
        posture.require_wrapped_userdata,
        wired.service.require_wrapped_userdata
    );
}

#[test]
fn the_gates_are_off_when_the_config_omits_them() {
    // `#[serde(default)]` = false. Stated as a test because "an omitted
    // key silently reads false" is the property the chart's
    // render-it-explicitly discipline exists to work around.
    let (cfg, wired) = wired_with("");
    assert!(!wired.service.require_wrapped_kek);
    assert!(!wired.service.require_wrapped_userdata);
    assert!(!config_posture(&cfg).require_wrapped_userdata);
}

#[test]
fn the_enforce_grace_window_is_counted_from_the_state_epoch() {
    // Strict unless configured; only with enforce; counted from the state
    // dir's epoch so a restart in the same pod (same state dir) keeps it.
    let (_, strict) = wired_with_live("", "keepalive_binding = \"enforce\"");
    assert_eq!(strict.service.keepalive_grace_closes_at_unix, None);

    let (toml, dir) = config_text(
        "",
        "keepalive_binding = \"enforce\"\nkeepalive_binding_grace_secs = 900",
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let cfg = Config::load(f.path()).expect("config must load");
    // A pod that started (its state dir was first used) 1000 s ago: the
    // window has already closed, and a later process must not reopen it.
    let epoch_file = dir
        .path()
        .join("state")
        .join(kbs_core::keepalive_binding::GRACE_EPOCH_FILE);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(&epoch_file, (now - 1000).to_string()).unwrap();
    {
        // Scoped: the wired stores hold file locks on the state dir.
        let wired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
        assert_eq!(
            wired.service.keepalive_grace_closes_at_unix,
            Some(now - 1000 + 900)
        );
    }
    {
        // An epoch in the future (a fast clock at stamping, or one that
        // stepped back since) cannot stretch the window past now + grace.
        std::fs::write(&epoch_file, (now + 5_000).to_string()).unwrap();
        let wired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
        let closes = wired.service.keepalive_grace_closes_at_unix.unwrap();
        assert!(closes <= now + 900 + 60, "window stretched to {closes}");
    }
    // A fresh state dir (pod replacement) opens a new window from now.
    std::fs::remove_file(&epoch_file).unwrap();
    let rewired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
    let closes = rewired.service.keepalive_grace_closes_at_unix.unwrap();
    assert!(closes >= now + 900 && closes <= now + 960);
}

#[test]
fn the_state_epoch_is_stamped_on_every_start_whatever_the_mode() {
    // So a pod that starts dark and is later restarted WITH a grace window
    // gets its original epoch, not a new one.
    let (toml, dir) = config_text("", "keepalive_binding = \"record\"");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let cfg = Config::load(f.path()).expect("config must load");
    {
        let wired = build_service(&cfg, Zeroizing::new("t".to_string())).unwrap();
        assert_eq!(wired.service.keepalive_grace_closes_at_unix, None);
    }
    assert!(dir
        .path()
        .join("state")
        .join(kbs_core::keepalive_binding::GRACE_EPOCH_FILE)
        .exists());
}

#[test]
fn a_grace_window_without_enforce_or_above_the_cap_refuses_to_load() {
    for live in [
        "keepalive_binding = \"record\"\nkeepalive_binding_grace_secs = 60",
        "keepalive_binding = \"enforce\"\nkeepalive_binding_grace_secs = 3601",
    ] {
        let (toml, _dir) = config_text("", live);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        assert!(
            Config::load(f.path()).is_err(),
            "{live} must refuse to load"
        );
    }
}
