//! HTTP server assembly + process lifecycle.
//!
//! The release router is the `kbs-server` transport (`/healthz`,
//! `/v1/kbs/{nonce,release}`) plus a `/readyz` probe. The service is
//! fully wired BEFORE the listener binds, so anything that answers an
//! HTTP request is, by construction, ready.
//!
//! When `[admin]` is configured, a SECOND listener binds on a separate
//! port (default `:8001`) serving `/v1/admin/vm/{vm_id}/register-vm`.
//! The two listeners share the lifecycle + L1 keyring stores via Arc
//! (see `wiring::WiredKbs`). The admin listener has NO public Ingress;
//! it is authenticated by **mTLS against a pinned client CA**
//! (`admin_tls`) and additionally gated by CiliumNetworkPolicy (vali pod
//! only) in K6 — two independent controls, one of them cryptographic.
//! When the mTLS material is missing the listener is REFUSED rather than
//! served in plaintext (`admin.require_mtls`, default true).

use crate::admin_tls::{self, AdminListenerMode};
use crate::config::Config;
use crate::error::Error;
use crate::wiring::{build_admin_state, build_service};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use kbs_transport::build_admin_router;
use std::sync::Arc;
use zeroize::Zeroizing;

/// `GET /readyz` — readiness probe. The process binds its listener only
/// after the service is fully wired, so a reply always means ready.
async fn readyz() -> StatusCode {
    StatusCode::OK
}

/// Compose the router: the `kbs-server` transport plus `/readyz`.
pub fn build_router(svc: Arc<kbs_transport::DefaultKbsService>) -> Router {
    kbs_transport::build_router(svc).route("/readyz", get(readyz))
}

/// Decide, build, bind and spawn the admin listener.
///
/// `Ok(None)` means "no admin listener is running" — either `[admin]` is
/// absent, or it is present but its mTLS material is missing while
/// `require_mtls` is set. **That second case is the fail-closed path**:
/// the admin API is the unauthenticated-lifecycle-mutation surface, so
/// it is left unbound rather than served in plaintext. The refusal is
/// deliberately NOT fatal to the process: the release path keeps
/// answering, so a misconfiguration costs new launches / migrations
/// instead of the KEK unlock of every already-running VM.
///
/// An `Err` is reserved for material that IS configured but does not
/// load — a broken cert must never degrade into plaintext either, and
/// (unlike absent material) it is unambiguously an operator error worth
/// failing the whole start on.
async fn spawn_admin_listener(
    cfg: &Config,
    wired: &mut crate::wiring::WiredKbs,
) -> Result<Option<tokio::task::JoinHandle<std::io::Result<()>>>, Error> {
    let Some(admin_cfg) = cfg.admin.as_ref() else {
        eprintln!(
            "kbs-server: WARNING — [admin] absent; lifecycle pre-registration is disabled and every release will fail closed at the vm-states gate"
        );
        return Ok(None);
    };

    // Decide + build the TLS material BEFORE binding.
    let tls = match AdminListenerMode::decide(admin_cfg) {
        AdminListenerMode::Mtls(paths) => {
            let server_cfg = admin_tls::build_server_config(&paths)
                .map_err(|e| Error::Serve(format!("admin mTLS material rejected: {e}")))?;
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg)))
        }
        AdminListenerMode::PlaintextOptIn => {
            eprintln!(
                "kbs-server: WARNING — admin.dev_allow_plaintext=true and no admin TLS material: \
                 the lifecycle admin API on {} is served UNAUTHENTICATED (network policy is the \
                 only control). DEV ONLY — never in production.",
                admin_cfg.addr
            );
            None
        }
        AdminListenerMode::Refuse(why) => {
            eprintln!(
                "kbs-server: REFUSING to serve the admin listener on {} — {why}; the lifecycle \
                 admin API stays CLOSED (DEV ONLY: admin.require_mtls=false AND \
                 admin.dev_allow_plaintext=true, with no TLS material, serves it in plaintext \
                 behind network policy alone)",
                admin_cfg.addr
            );
            return Ok(None);
        }
    };

    let admin_state = build_admin_state(
        cfg,
        Arc::clone(&wired.l1_keyring),
        Arc::clone(&wired.service.kbs_signing_key),
        Arc::clone(&wired.vm_states),
        Arc::clone(&wired.allowlist),
        Arc::clone(&wired.boot_counter),
        Arc::clone(&wired.volume_stamp),
        wired.custody.clone(),
        Arc::clone(&wired.keepalive_bindings),
        Arc::clone(&wired.release_audit),
    )?;
    // The release path records the authorized-rollback events it owns
    // (consume / refused / cleared) in the SAME admin hash chain as the
    // arm that authorised them.
    wired
        .service
        .set_rollback_audit(Arc::clone(&admin_state.audit));
    // A process restart INSIDE the pod (the state emptyDir survives it)
    // can leave an authorized rollback whose stamp step was applied but
    // never delivered. Revert every such record whose arm is gone before
    // serving, audited in the admin chain. (Every release also reconciles
    // its own VM first, so this is housekeeping, not the only guard.)
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Serve(format!("clock: {e}")))?
        .as_secs();
    for (vm, outcome) in kbs_core::rollback::reconcile_all_pending(
        wired.boot_counter.as_ref(),
        wired.volume_stamp.as_ref(),
        Some(admin_state.audit.as_ref()),
        now_unix,
    )
    .map_err(|e| Error::Serve(format!("rollback reconcile: {e}")))?
    {
        eprintln!("kbs-server: pending rollback of vm_id={vm} at startup: {outcome:?}");
    }
    let admin_app = build_admin_router(admin_state);
    let allowed_identities = Arc::new(admin_cfg.allowed_client_identities.clone());
    if tls.is_some() {
        eprintln!(
            "kbs-server: admin client identities allowed: {}",
            admin_cfg
                .allowed_client_identities
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let admin_listener = tokio::net::TcpListener::bind(admin_cfg.addr)
        .await
        .map_err(|e| Error::Serve(format!("admin bind {}: {e}", admin_cfg.addr)))?;
    eprintln!(
        "kbs-server: admin listening on {} ({}; ClusterIP-only; vali calls it before each launch)",
        admin_cfg.addr,
        match tls {
            Some(_) => "mTLS, pinned client CA",
            None => "PLAINTEXT — unauthenticated",
        }
    );
    Ok(Some(match tls {
        Some(acceptor) => tokio::spawn(async move {
            admin_tls::serve_admin_mtls(
                admin_listener,
                acceptor,
                admin_app,
                allowed_identities,
                shutdown_signal(),
            )
            .await;
            Ok::<(), std::io::Error>(())
        }),
        None => tokio::spawn(async move {
            axum::serve(admin_listener, admin_app)
                .with_graceful_shutdown(shutdown_signal())
                .await
        }),
    }))
}

/// Wire the service, bind the listener(s), and serve until SIGTERM/
/// SIGINT.
pub async fn run(cfg: Config, vault_token: Zeroizing<String>) -> Result<(), Error> {
    // Wiring (stores opened, audit log locked) happens before any bind.
    let mut wired = build_service(&cfg, vault_token)?;

    let listener = tokio::net::TcpListener::bind(cfg.listen.addr)
        .await
        .map_err(|e| Error::Serve(format!("bind {}: {e}", cfg.listen.addr)))?;
    eprintln!("kbs-server: listening on {}", cfg.listen.addr);

    // Optionally bind the admin listener on a SEPARATE port. The
    // admin path mutates lifecycle state; isolating it from the
    // public-Ingress release path is a §13 attack-surface gate.
    let admin_handle = spawn_admin_listener(&cfg, &mut wired).await?;

    // Built last so `wired` is still whole for the admin wiring above
    // (`wired.service` moves here).
    let app = build_router(Arc::new(wired.service));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| Error::Serve(format!("serve: {e}")))?;

    // Wait for the admin listener to drain (it received the same
    // shutdown signal). Errors here are non-fatal — the release
    // path already shut down cleanly.
    if let Some(h) = admin_handle {
        if let Err(e) = h.await {
            eprintln!("kbs-server: admin task join: {e}");
        }
    }

    // `app` (and the `Arc<DefaultKbsService>` inside it) drops here —
    // releasing the audit sink's exclusive lock.
    eprintln!("kbs-server: graceful shutdown complete");
    Ok(())
}

/// Completes on SIGTERM (k8s pod stop) or SIGINT (Ctrl-C).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            // No SIGTERM handler ⇒ rely on Ctrl-C alone rather than abort.
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    eprintln!("kbs-server: shutdown signal received — draining in-flight requests");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readyz_returns_200() {
        assert_eq!(readyz().await, StatusCode::OK);
    }
}
