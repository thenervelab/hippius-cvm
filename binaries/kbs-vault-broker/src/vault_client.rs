//! Vault token-create client — mints the per-VM-scoped child token.
//!
//! KEK-HSM Phase 3 (RA-KBS-M2): the broker makes ONE Vault call under its
//! own token and NEVER writes an ACL policy:
//!
//! POST `auth/token/create/<role>` — a child token attaching the ONE
//! FIXED, operator-created, TEMPLATED policy `kbs-cap-templated`
//! ([`TEMPLATED_CAP_POLICY`], `deploy/terraform/policies/`), scoped to a
//! single VM via `entity_alias=<vm_id>`: Vault binds the token to an
//! entity whose token-mount alias name is the vm_id, and the templated
//! policy's `{{identity.entity.aliases.<accessor>.name}}` resolves to
//! that vm_id — so the cap can read EXACTLY this VM's luks-kek/userdata/
//! lifecycle-key and transit-decrypt EXACTLY its `kek-<vm_id>` key.
//! `no_default_policy`, short TTL, `num_uses` bounded, non-renewable.
//!
//! Why this matters: the broker previously PUT `sys/policies/acl/kbs-cap-*`
//! with arbitrary HCL, so a broker RCE could author `read secret/*` and
//! mint a token on it = read every secret (all KEKs + the L1/allowlist
//! signing seeds = forge everything). The broker now holds NO
//! `sys/policies/acl` write; it can only mint tenant-KEK-scoped caps via
//! the fixed template.
//!
//! The request-shape builder [`token_create_body`] is pure + unit-tested;
//! the HTTP round-trip is thin around it.

use std::time::Duration;

use hippius_types::vault_broker::BrokerScope;
use zeroize::Zeroizing;

use crate::error::BrokerError;
use crate::redeem::VaultTokenMinter;
use crate::vault_auth::{
    with_jwt_retry, CallFailure, JwtLogin, LoginError, LoginOutcome, VaultAuth,
};

/// `num_uses` on the minted token: the KBS does up to 3 reads (luks +
/// userdata + optional §7 lifecycle key) plus, since Phase 2 (KEK-HSM),
/// one `transit/decrypt` to unwrap the KEK — up to 4 ops; a little slack
/// absorbs a retried read without granting an open-ended credential.
const TOKEN_NUM_USES: u64 = 6;

/// The FIXED, operator-created, TEMPLATED per-VM capability policy
/// (KEK-HSM Phase 3 / RA-KBS-M2). The broker attaches THIS one policy to
/// every cap token (never writes a per-VM ACL) and scopes it via
/// `entity_alias=<vm_id>`; the policy's `{{identity.entity.aliases.…name}}`
/// templates resolve to that vm_id. See
/// `deploy/terraform/policies/kbs-cap-templated.hcl`.
const TEMPLATED_CAP_POLICY: &str = "kbs-cap-templated";

/// Build the ureq agent used for EVERY broker→Vault call, with the
/// operator's TLS posture applied. Shared by the token-mint client and
/// the jwt-login transport so both trust exactly the same CA.
pub fn build_vault_agent(
    dev_skip_tls_verify: bool,
    ca_cert_path: Option<&std::path::Path>,
) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(10));
    // CA-pin (prod) takes precedence; dev-skip is the fallback.
    if let Some(path) = ca_cert_path {
        let pem = std::fs::read(path)
            .map_err(|e| format!("vault.ca_cert_path {}: {e}", path.display()))?;
        let cfg = crate::tls::ca_pinned_tls_config(&pem)?;
        builder = builder.tls_config(std::sync::Arc::new(cfg));
    } else if dev_skip_tls_verify {
        builder = builder.tls_config(std::sync::Arc::new(crate::tls::dev_insecure_tls_config()));
    }
    Ok(builder.build())
}

/// The `auth/<mount>/login` round-trip (M-k8sauth, #94).
///
/// §20: the response BODY of a failed login is dropped UNREAD — some
/// Vault versions echo the submitted JWT back in it. Only the status
/// code survives into [`LoginError::Rejected`].
pub struct HttpJwtLogin {
    agent: ureq::Agent,
    address: String,
}

impl HttpJwtLogin {
    pub fn new(agent: ureq::Agent, address: &str) -> Self {
        Self {
            agent,
            address: address.trim_end_matches('/').to_string(),
        }
    }
}

impl JwtLogin for HttpJwtLogin {
    fn login(
        &self,
        auth_path: &str,
        role: &str,
        sa_jwt: &Zeroizing<String>,
    ) -> Result<LoginOutcome, LoginError> {
        let url = format!("{}/v1/auth/{}/login", self.address, auth_path);
        let resp = self
            .agent
            .post(&url)
            .send_json(serde_json::json!({ "role": role, "jwt": sa_jwt.as_str() }))
            .map_err(|e| match e {
                ureq::Error::Status(status, _) => LoginError::Rejected { status },
                ureq::Error::Transport(_) => LoginError::Unreachable,
            })?;
        let body: serde_json::Value = resp.into_json().map_err(|_| LoginError::Malformed)?;
        let auth = body.get("auth");
        let token = auth
            .and_then(|a| a.get("client_token"))
            .and_then(|t| t.as_str())
            .unwrap_or_default();
        if token.is_empty() {
            return Err(LoginError::Malformed);
        }
        let lease_secs = auth
            .and_then(|a| a.get("lease_duration"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        Ok(LoginOutcome {
            token: Zeroizing::new(token.to_string()),
            lease_secs,
        })
    }
}

pub struct HttpVaultTokenMinter {
    agent: ureq::Agent,
    address: String,
    auth: VaultAuth,
    ttl_secs: u64,
    token_role: String,
}

impl HttpVaultTokenMinter {
    pub fn new(
        address: &str,
        agent: ureq::Agent,
        auth: VaultAuth,
        ttl_secs: u64,
        token_role: &str,
    ) -> Self {
        Self {
            agent,
            address: address.trim_end_matches('/').to_string(),
            auth,
            ttl_secs,
            token_role: token_role.to_string(),
        }
    }
}

/// The `auth/token/create/<role>` JSON body for a scoped child token.
///
/// KEK-HSM Phase 3: `entity_alias` binds the token to an entity whose
/// token-mount alias name IS the vm_id, so the FIXED `TEMPLATED_CAP_POLICY`
/// resolves its `{{identity.entity.aliases.…name}}` templates to that vm's
/// release paths — per-VM scope with NO broker-authored ACL. `vm_id` is
/// charset-locked by `BrokerScope::validate` ([a-z0-9-]), so it is a safe
/// alias name.
pub fn token_create_body(policy: &str, entity_alias: &str, ttl_secs: u64) -> serde_json::Value {
    serde_json::json!({
        "policies": [policy],
        "entity_alias": entity_alias,
        "no_default_policy": true,
        "renewable": false,
        "ttl": format!("{ttl_secs}s"),
        "explicit_max_ttl": format!("{ttl_secs}s"),
        "num_uses": TOKEN_NUM_USES,
        "type": "service",
    })
}

impl VaultTokenMinter for HttpVaultTokenMinter {
    fn mint_scoped(
        &self,
        scope: &BrokerScope,
        now_unix: u64,
    ) -> Result<(Zeroizing<Vec<u8>>, u64), BrokerError> {
        // KEK-HSM Phase 3 (RA-KBS-M2): the broker NO LONGER writes a per-VM
        // ACL policy. It mints the cap via the token ROLE, attaching the
        // one FIXED `TEMPLATED_CAP_POLICY` and passing `entity_alias=vm_id`
        // — Vault binds the token to an entity whose token-mount alias name
        // is the vm_id, so the templated policy resolves to EXACTLY this
        // VM's release paths. The broker holds no `sys/policies/acl` write,
        // so a broker RCE can no longer author `read secret/*` (the
        // forge-everything path). `vm_id` is charset-locked by
        // `BrokerScope::validate`, so it is a safe alias name.
        let token_url = format!("{}/v1/auth/token/create/{}", self.address, self.token_role);
        // The broker's OWN credential is resolved per call (#94): a
        // short-lived jwt-login token when a role is configured, else the
        // static `BROKER_VAULT_TOKEN`. `with_jwt_retry` re-logs in EXACTLY
        // once on a 403 held against a cached login token, because Vault
        // answers an expired-mid-flight token with the same 403 as a
        // genuine policy denial. Everything below the header is the
        // unchanged Phase-3 mint.
        let minted = with_jwt_retry(&self.auth, |broker_token| {
            let resp = self
                .agent
                .post(&token_url)
                .set("X-Vault-Token", broker_token)
                .send_json(token_create_body(
                    TEMPLATED_CAP_POLICY,
                    &scope.vm_id,
                    self.ttl_secs,
                ))
                .map_err(|e| CallFailure {
                    status: http_status(&e),
                    error: BrokerError::VaultMint(format!("token create: {}", classify(&e))),
                })?;
            let body: serde_json::Value = resp.into_json().map_err(|_| CallFailure {
                status: None,
                error: BrokerError::VaultMint("token create: non-JSON response".into()),
            })?;
            let token = body
                .get("auth")
                .and_then(|a| a.get("client_token"))
                .and_then(|t| t.as_str())
                .ok_or_else(|| CallFailure {
                    status: None,
                    error: BrokerError::VaultMint("token create: missing auth.client_token".into()),
                })?;
            if token.is_empty() {
                return Err(CallFailure {
                    status: None,
                    error: BrokerError::VaultMint("token create: empty client_token".into()),
                });
            }
            Ok(Zeroizing::new(token.as_bytes().to_vec()))
        })?;
        Ok((minted, now_unix.saturating_add(self.ttl_secs)))
    }
}

/// Classify a `ureq` error to a secret-free string — never echo the
/// URL (carries no secret here, but stays disciplined) or body.
fn classify(e: &ureq::Error) -> &'static str {
    match e {
        ureq::Error::Status(403, _) => "vault-403-forbidden",
        ureq::Error::Status(404, _) => "vault-404-not-found",
        ureq::Error::Status(400, _) => "vault-400-bad-request",
        ureq::Error::Status(_, _) => "vault-http-error",
        ureq::Error::Transport(_) => "vault-transport",
    }
}

/// The HTTP status of a `ureq` error, when there was a response at all.
/// Drives the ONE 403 re-login retry; a transport error yields `None`
/// and is never retried.
fn http_status(e: &ureq::Error) -> Option<u16> {
    match e {
        ureq::Error::Status(code, _) => Some(*code),
        ureq::Error::Transport(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_body_binds_the_fixed_templated_policy_and_entity_alias() {
        // KEK-HSM Phase 3: the cap token attaches the ONE fixed templated
        // policy + `entity_alias=<vm_id>` (the per-VM scope) — never a
        // broker-authored ACL. Short-TTL, num_uses-bounded, no default.
        let b = token_create_body(TEMPLATED_CAP_POLICY, "smoke-001", 60);
        assert_eq!(b["policies"], serde_json::json!(["kbs-cap-templated"]));
        assert_eq!(b["entity_alias"], serde_json::json!("smoke-001"));
        assert_eq!(b["no_default_policy"], serde_json::json!(true));
        assert_eq!(b["renewable"], serde_json::json!(false));
        assert_eq!(b["ttl"], serde_json::json!("60s"));
        assert_eq!(b["num_uses"], serde_json::json!(TOKEN_NUM_USES));
    }
}
