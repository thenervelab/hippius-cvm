//! Integration test: the binary boots from a minimal config and serves
//! `/healthz` + `/readyz`.
//!
//! This is the separate-crate integration target, so it carries its own
//! lint allowance (the `#![cfg_attr(test, ...)]` in `lib.rs` does not
//! reach here).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Child, Command};
use std::time::Duration;

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

#[test]
fn boots_and_serves_health_and_readiness() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    let audit = dir.path().join("audit");
    std::fs::create_dir_all(&state).expect("state dir");
    std::fs::create_dir_all(&audit).expect("audit dir");

    // 32-byte KBS response-signing seed.
    let key_path = dir.path().join("kbs-signing.key");
    std::fs::write(&key_path, [7u8; 32]).expect("write signing key");

    // A genuine Ed25519 public key for the §22 allowlist root.
    let root_vk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let root_hex = hex::encode(root_vk.to_bytes());

    let port = free_port();
    let config = format!(
        r#"
[listen]
addr = "127.0.0.1:{port}"

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
"#,
        port = port,
        state = state.display(),
        audit = audit.display(),
        root_hex = root_hex,
        key = key_path.display(),
    );
    let config_path = dir.path().join("kbs.toml");
    std::fs::write(&config_path, config).expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_hippius-kbs-server"))
        .arg("--config")
        .arg(&config_path)
        .env("VAULT_TOKEN", "integration-test-placeholder-token")
        .spawn()
        .expect("spawn hippius-kbs-server");
    let _killer = Killer(child);

    let base = format!("http://127.0.0.1:{port}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();

    // Poll /healthz until the server has bound its listener.
    let mut healthz = None;
    for _ in 0..50 {
        if let Ok(resp) = agent.get(&format!("{base}/healthz")).call() {
            healthz = Some(resp);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let healthz = healthz.expect("/healthz never became reachable");
    assert_eq!(healthz.status(), 200, "/healthz status");
    assert_eq!(
        healthz.into_string().expect("healthz body"),
        "ok",
        "/healthz body",
    );

    let readyz = agent
        .get(&format!("{base}/readyz"))
        .call()
        .expect("/readyz call");
    assert_eq!(readyz.status(), 200, "/readyz status");
}
