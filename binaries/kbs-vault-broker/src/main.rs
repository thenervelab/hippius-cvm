//! `hippius-kbs-vault-broker` binary entrypoint.
//!
//! Loads TOML config, resolves the broker's OWN Vault credential (a
//! short-lived `auth/<mount>/login` token when `BROKER_VAULT_JWT_ROLE`
//! is set — M-k8sauth #94 — else the static `BROKER_VAULT_TOKEN`),
//! builds the AMD-rooted verifier + the Vault token-minter + the
//! challenge store + the measurement allowlist, and serves the
//! canonical-CBOR challenge/redeem endpoints until SIGTERM.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hippius_kbs_vault_broker::allowlist::FixedMeasurementAllowlist;
use hippius_kbs_vault_broker::challenge::InMemoryChallenges;
use hippius_kbs_vault_broker::config::Config;
use hippius_kbs_vault_broker::handlers::{router, BrokerState};
use hippius_kbs_vault_broker::vault_auth::{startup_credentials, JwtLogin, VaultAuth};
use hippius_kbs_vault_broker::vault_client::{
    build_vault_agent, HttpJwtLogin, HttpVaultTokenMinter,
};
use hippius_kbs_vault_broker::verifier;
use kbs_core::snp::LaunchPolicy;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kbs-vault-broker: FATAL: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/kbs-vault-broker/config.toml".to_string());
    let raw = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("read config {config_path}: {e}"))?;
    let cfg: Config = toml::from_str(&raw).map_err(|e| format!("parse config: {e}"))?;
    cfg.validate().map_err(|e| format!("{e}"))?;

    // M-k8sauth (#94): prefer a short-lived `auth/<mount>/login` token
    // over the static `BROKER_VAULT_TOKEN`. With no role configured this
    // is the pre-#94 path, error strings included.
    let creds = startup_credentials(|k| std::env::var(k).ok())?;

    if let Some(p) = &cfg.vault.ca_cert_path {
        eprintln!(
            "kbs-vault-broker: Vault TLS pinned to CA at {}",
            p.display()
        );
    } else if cfg.vault.dev_skip_tls_verify {
        eprintln!(
            "kbs-vault-broker: ⚠️  DEV-MODE: vault.dev_skip_tls_verify=true — Vault server \
             certificate verification disabled. NEVER ENABLE IN PROD."
        );
    }

    let verifier = verifier::build(&cfg.snp).map_err(|e| format!("{e}"))?;
    let verifier: Box<dyn hippius_kbs_vault_broker::redeem::SelfReportVerifier + Send + Sync> =
        Box::new(verifier);
    let allowlist = FixedMeasurementAllowlist::from_hex(&cfg.kbs_measurement_allowlist)
        .map_err(|e| format!("kbs_measurement_allowlist: {e}"))?;
    eprintln!(
        "kbs-vault-broker: {} KBS measurement(s) allowlisted",
        allowlist.len()
    );
    let agent = build_vault_agent(
        cfg.vault.dev_skip_tls_verify,
        cfg.vault.ca_cert_path.as_deref(),
    )?;
    let login: Option<Box<dyn JwtLogin>> = creds.jwt.as_ref().map(|_| {
        Box::new(HttpJwtLogin::new(agent.clone(), &cfg.vault.address)) as Box<dyn JwtLogin>
    });
    let auth = VaultAuth::new(creds, login)?;
    // Log in ONCE here so the pod log states, before any tenant traffic,
    // whether this confidential guest can read its projected
    // ServiceAccount token — and fails closed if it cannot AND no static
    // token is configured.
    auth.prime()?;
    let minter = HttpVaultTokenMinter::new(
        &cfg.vault.address,
        agent,
        auth,
        cfg.vault.child_token_ttl_secs,
        &cfg.vault.token_role,
    );
    let state = Arc::new(BrokerState {
        verifier,
        challenges: Box::new(InMemoryChallenges::new(cfg.challenge.ttl_secs)),
        allowlist: Box::new(allowlist),
        minter: Box::new(minter),
        policy: LaunchPolicy {
            min_tcb: cfg.policy.min_tcb,
            required_bits: cfg.policy.required_bits,
            allowed_mask: cfg.policy.allowed_mask,
        },
        now_unix,
    });

    // RA-KBS-M1 — serve HTTPS when the operator mounted a cert + key
    // (`listen.tls_{cert,key}_path`), else plain HTTP (backward
    // compatible). HTTPS encrypts the minted per-VM Vault token on the
    // broker↔KBS hop; the KBS pins this cert's CA.
    match (&cfg.listen.tls_cert_path, &cfg.listen.tls_key_path) {
        (Some(cert), Some(key)) => {
            // Install the `ring` provider as the process default (matches
            // ureq's rustls; idempotent — ignore an already-installed).
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .map_err(|e| format!("tls cert/key load: {e}"))?;
            let addr: std::net::SocketAddr =
                cfg.listen.addr.parse().map_err(|e| {
                    format!("listen.addr {} not a socket addr: {e}", cfg.listen.addr)
                })?;
            eprintln!("kbs-vault-broker: listening on {addr} (TLS)");
            let handle = axum_server::Handle::new();
            let drain = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                drain.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            axum_server::bind_rustls(addr, tls)
                .handle(handle)
                .serve(router(state).into_make_service())
                .await
                .map_err(|e| format!("serve-tls: {e}"))
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(&cfg.listen.addr)
                .await
                .map_err(|e| format!("bind {}: {e}", cfg.listen.addr))?;
            eprintln!("kbs-vault-broker: listening on {}", cfg.listen.addr);
            axum::serve(listener, router(state).into_make_service())
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(|e| format!("serve: {e}"))
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("kbs-vault-broker: shutdown signal — draining");
}
