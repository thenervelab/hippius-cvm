//! Integration test for the §22 allowlist install-vs-revalidate boot
//! logic (`wiring::build_service`).
//!
//! Without that logic the binary would call `InstalledAllowlist::install`
//! on every start; the durable HWM CAS contract refuses `epoch <=
//! current`, so the second boot would crashloop. This test mints a
//! signed artifact, boots the binary twice against the same state dir,
//! and asserts the second boot reaches `/readyz` (i.e. the wiring took
//! the `revalidate_with` branch).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::cbor::to_canonical_vec;

/// Reserve an ephemeral TCP port, then release it for the child to bind.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

/// Kills the spawned child on drop so a failed assertion never leaks a
/// process.
struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Build a canonical-CBOR `AllowlistBody` + COSE_Sign1 EdDSA wrapper
/// for an artifact with a single placeholder measurement at the given
/// epoch. Matches the shape `kbs_core::allowlist::parse_and_verify`
/// re-derives at boot.
fn mint_artifact(sk: &SigningKey, epoch: u64, measurement: [u8; 48]) -> Vec<u8> {
    let body = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(1.into())),
        (Value::Text("epoch".into()), Value::Integer(epoch.into())),
        (
            Value::Text("entries".into()),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(measurement.to_vec()),
                Value::Map(vec![
                    (
                        Value::Text("accepted_l1_kids".into()),
                        Value::Array(vec![Value::Bytes(b"l1-kid".to_vec())]),
                    ),
                    (
                        Value::Text("accepted_kbs_response_kids".into()),
                        Value::Array(vec![Value::Bytes(b"kbs-kid".to_vec())]),
                    ),
                ]),
            ])]),
        ),
    ]);
    let payload = to_canonical_vec(&body).expect("canonical body");
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
        .build()
        .to_vec()
        .expect("COSE_Sign1 encode")
}

/// Write the kbs-server TOML config for the test layout.
#[allow(clippy::too_many_arguments)]
fn write_config(
    config_path: &Path,
    port: u16,
    state: &Path,
    audit: &Path,
    key_path: &Path,
    allowlist_path: &Path,
    root_hex: &str,
) {
    let toml = format!(
        r#"
[listen]
addr = "127.0.0.1:{port}"

[storage]
state_dir = "{state}"
audit_dir = "{audit}"
nonce_ttl_secs = 300

[allowlist]
root_pubkey_hex = "{root_hex}"
signed_path = "{allowlist}"

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
"#,
        port = port,
        state = state.display(),
        audit = audit.display(),
        root_hex = root_hex,
        key = key_path.display(),
        allowlist = allowlist_path.display(),
    );
    std::fs::write(config_path, toml).expect("write config");
}

/// Spawn the binary, wait for `/healthz` + `/readyz` to return 200.
/// Returns the (running) child so the caller can kill it.
fn boot_and_wait_ready(config_path: &Path, port: u16) -> Killer {
    let child = Command::new(env!("CARGO_BIN_EXE_hippius-kbs-server"))
        .arg("--config")
        .arg(config_path)
        .env("VAULT_TOKEN", "integration-test-placeholder-token")
        .spawn()
        .expect("spawn hippius-kbs-server");
    let killer = Killer(child);
    let base = format!("http://127.0.0.1:{port}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();
    let mut ok = false;
    for _ in 0..100 {
        if let Ok(resp) = agent.get(&format!("{base}/readyz")).call() {
            if resp.status() == 200 {
                ok = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "/readyz never became 200");
    killer
}

#[test]
fn restart_with_same_artifact_revalidates_without_crash() {
    // ── fixture ────────────────────────────────────────────────────
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let audit = dir.path().join("audit");
    std::fs::create_dir_all(&state).expect("state");
    std::fs::create_dir_all(&audit).expect("audit");

    let key_path = dir.path().join("kbs-signing.key");
    std::fs::write(&key_path, [7u8; 32]).expect("write signing key");

    // §22 root signing key — sign the artifact + tell the binary to
    // verify against its matching pubkey.
    let root_sk = SigningKey::from_bytes(&[9u8; 32]);
    let root_hex = hex::encode(root_sk.verifying_key().to_bytes());

    let allowlist_path = dir.path().join("allowlist.cose");
    let artifact = mint_artifact(&root_sk, 1, [0xABu8; 48]);
    std::fs::write(&allowlist_path, &artifact).expect("write allowlist");

    // ── first boot — install (CAS-advance from None → epoch 1) ─────
    let port_a = free_port();
    let config_path_a = dir.path().join("kbs-a.toml");
    write_config(
        &config_path_a,
        port_a,
        &state,
        &audit,
        &key_path,
        &allowlist_path,
        &root_hex,
    );
    let killer_a = boot_and_wait_ready(&config_path_a, port_a);
    drop(killer_a); // stop the first binary; audit-log lock is released

    // ── second boot — same artifact, same state dir; the HWM is now
    //     1, so the wiring MUST take `revalidate_with` (epoch == HWM)
    //     instead of `install` (which would CAS-reject epoch <= HWM
    //     and crashloop). ───────────────────────────────────────────
    let port_b = free_port();
    let config_path_b = dir.path().join("kbs-b.toml");
    write_config(
        &config_path_b,
        port_b,
        &state,
        &audit,
        &key_path,
        &allowlist_path,
        &root_hex,
    );
    let _killer_b = boot_and_wait_ready(&config_path_b, port_b);
}
