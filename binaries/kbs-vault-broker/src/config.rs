//! Broker operator config (TOML, fail-closed).
//!
//! Every struct is `#[serde(deny_unknown_fields)]` — an unknown key
//! aborts startup rather than silently ignoring a misconfiguration.
//! The privileged Vault token is NOT in this file; it comes from the
//! `BROKER_VAULT_TOKEN` env (a mounted secret), so a `kubectl get -o
//! yaml` of the config never exposes it.

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::BrokerError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: Listen,
    pub vault: Vault,
    pub snp: Snp,
    pub policy: Policy,
    pub challenge: Challenge,
    /// Accepted KBS launch measurements (lower-case 96-hex each). Empty
    /// ⇒ the broker mints nothing (fail-closed).
    #[serde(default)]
    pub kbs_measurement_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// `host:port` the broker serves on (in-cluster, NetworkPolicy-gated
    /// to KBS only).
    pub addr: String,
    /// RA-KBS-M1 — optional server-TLS. When BOTH `tls_cert_path` and
    /// `tls_key_path` are set the broker serves HTTPS (the minted per-VM
    /// Vault token no longer transits the pod network in cleartext); the
    /// KBS pins this cert's CA. Absent ⇒ plain HTTP (backward compatible).
    #[serde(default)]
    pub tls_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub tls_key_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// Vault base URL, e.g. `https://vault.example.invalid:8200`. May
    /// be a bare `IP:port`.
    pub address: String,
    /// KV-v2 mount the per-tenant secrets live under (e.g. `secret`).
    /// The minted child token is scoped to `secret/data/<path>` reads.
    pub kv_mount: String,
    /// DEV-ONLY: skip Vault TLS server-cert verification. Fail-closed:
    /// refused unless `dev_environment=true` AND `address` is a
    /// loopback/private endpoint (see [`Config::validate`]).
    #[serde(default)]
    pub dev_skip_tls_verify: bool,
    /// EXPLICIT non-production opt-in (audit H7). Every DEV-ONLY override
    /// (`dev_skip_tls_verify`) is default-DENY unless this is `true`.
    /// `#[serde(default)]` ⇒ `false`, so a production config (which never
    /// sets it) can never enable a dev override, whatever the address.
    #[serde(default)]
    pub dev_environment: bool,
    /// PROD: path to the Vault CA bundle (PEM). When set, the broker
    /// verifies the Vault server cert against EXACTLY this CA (normal
    /// chain + SAN verification) instead of the dev skip. Takes
    /// precedence over `dev_skip_tls_verify`.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// TTL (seconds) of the minted scoped child token. Short — the KBS
    /// uses it for two reads (luks + userdata) immediately.
    pub child_token_ttl_secs: u64,
    /// Vault token ROLE the child token is created against
    /// (`auth/token/create/<role>`). Required: Vault only lets a
    /// non-root token attach policies OUTSIDE its own set through a
    /// role whose `allowed_policies_glob` covers them (`kbs-cap-*`) —
    /// a bare `auth/token/create` would be rejected with
    /// "child policies must be subset of parent". The role is
    /// operator-provisioned next to the broker policy.
    pub token_role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snp {
    /// AMD generation root (`milan` | `genoa` | `turin`) — the
    /// generation of the host the KBS POD runs on (NOT the tenant
    /// hosts the KBS verifies). The KBS's self-report is signed by
    /// that host's VEK, anchored to this generation's ARK/ASK.
    pub generation: Generation,
    /// OPTIONAL operator-mounted VEK PEM fallback. The broker prefers
    /// the VEK carried in the self-report (the host PSP cert table) so
    /// the chain tracks the report's TCB automatically; this mounted
    /// VEK is used only when a redeem carries none. Omit it in prod
    /// once the host populates its extended-report cert table (§17 /
    /// #394). When set, it is chain-verified to the built-in ARK/ASK
    /// at startup.
    #[serde(default)]
    pub vek_pem_path: Option<PathBuf>,
    /// AMD KDS base URL for fetching the per-chip VCEK when the
    /// self-report carries no cert table (the usual case unless the
    /// host injects certs). Empty disables the KDS fallback. The
    /// broker derives the exact `/{gen}/{chip_id}?…SPL=` URL from the
    /// report's chip_id + reported TCB, fetches once, and caches the
    /// VCEK by (chip_id, TCB) so a release never blocks on KDS.
    #[serde(default)]
    pub kds_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Generation {
    Milan,
    Genoa,
    Turin,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub min_tcb: u64,
    pub required_bits: u64,
    pub allowed_mask: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// Challenge nonce TTL (seconds). Short — the KBS redeems within
    /// one release round-trip.
    pub ttl_secs: u64,
}

impl Config {
    pub fn validate(&self) -> Result<(), BrokerError> {
        if self.listen.addr.is_empty() {
            return Err(BrokerError::Config("listen.addr must be set".into()));
        }
        if self.vault.address.is_empty() {
            return Err(BrokerError::Config("vault.address must be set".into()));
        }
        if self.vault.kv_mount.is_empty() {
            return Err(BrokerError::Config("vault.kv_mount must be set".into()));
        }
        if self.vault.child_token_ttl_secs == 0 {
            return Err(BrokerError::Config(
                "vault.child_token_ttl_secs must be > 0".into(),
            ));
        }
        if self.vault.token_role.is_empty() {
            return Err(BrokerError::Config("vault.token_role must be set".into()));
        }
        if self.challenge.ttl_secs == 0 {
            return Err(BrokerError::Config("challenge.ttl_secs must be > 0".into()));
        }
        // CA-pin and dev-skip are mutually exclusive (CA wins, but
        // flag both so the deploy intent is unambiguous).
        if self.vault.ca_cert_path.is_some() && self.vault.dev_skip_tls_verify {
            return Err(BrokerError::Config(
                "vault.ca_cert_path and vault.dev_skip_tls_verify are mutually exclusive \
                 — drop the dev skip when pinning the Vault CA"
                    .into(),
            ));
        }
        // FAIL-CLOSED guard for the DEV-ONLY TLS skip (audit H7) — same
        // posture as the KBS's `Config::validate`. The old guard refused
        // only when `vault.address` contained a prod-marker SUBSTRING
        // (`tier0`/`prod`/`hippius.network`), which did NOT match the
        // IP-addressed production Vault. Now default-DENY: refused unless
        // the operator EXPLICITLY asserts `dev_environment=true` AND the
        // Vault endpoint is non-public.
        if self.vault.dev_skip_tls_verify {
            if !self.vault.dev_environment {
                return Err(BrokerError::Config(
                    "vault.dev_skip_tls_verify=true requires an EXPLICIT \
                     vault.dev_environment=true opt-in (fail-closed — the TLS skip is \
                     never for production)"
                        .into(),
                ));
            }
            if vault_endpoint_is_public(&self.vault.address) {
                return Err(BrokerError::Config(format!(
                    "vault.dev_skip_tls_verify=true is refused against the public Vault \
                     endpoint ({:?}) even with dev_environment=true — the TLS skip is \
                     only for a loopback/private dev Vault",
                    self.vault.address,
                )));
            }
        }
        if self.kbs_measurement_allowlist.is_empty() {
            // Not an error (a fresh deploy may pin the measurement
            // later), but loud — the broker mints nothing until pinned.
            eprintln!(
                "kbs-vault-broker: ⚠️  kbs_measurement_allowlist is EMPTY — every redeem \
                 will be denied until a KBS measurement is pinned"
            );
        }
        Ok(())
    }
}

/// Classify a `vault.address` as a PUBLIC (globally-routable) endpoint for
/// the fail-closed dev-override guard (audit H7). Returns `true` when the
/// host parses as a public IP OR is a non-local DNS name — i.e. NOT a
/// loopback/private/link-local IP and NOT a `localhost` / `*.localhost`
/// / `*.local` name. `.internal` was DROPPED (RA-KBS-VL4): no standards
/// basis for being local (resolves to an arbitrary address), so it's
/// now public ⇒ a dev override can't skip TLS toward `vault.internal`.
/// Fail-closed on a host we can't confidently classify as local
/// (returns `true`).
fn vault_endpoint_is_public(address: &str) -> bool {
    let no_scheme = address
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(address);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme).trim();
    let host = if let Some(inner) = host.strip_prefix('[') {
        // `[ipv6]:port` → the part before `]`.
        inner.split(']').next().unwrap_or(inner)
    } else {
        // `host:port` — strip a trailing `:port` only when the head has no
        // other colon (so a bare IPv6 without brackets stays intact).
        match host.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        }
    };
    if host.is_empty() {
        return true; // can't classify ⇒ fail-closed (treat as public)
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return !(ip.is_loopback()
            || ip.is_unspecified()
            || match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
                }
            });
    }
    let h = host.to_ascii_lowercase();
    !(h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_vault() -> Vault {
        Vault {
            address: "https://127.0.0.1:8200".into(),
            kv_mount: "secret".into(),
            dev_skip_tls_verify: false,
            dev_environment: false,
            ca_cert_path: None,
            child_token_ttl_secs: 60,
            token_role: "kbs-cap".into(),
        }
    }

    fn config_with(vault: Vault) -> Config {
        Config {
            listen: Listen {
                addr: "0.0.0.0:8100".into(),
                tls_cert_path: None,
                tls_key_path: None,
            },
            vault,
            snp: Snp {
                generation: Generation::Turin,
                vek_pem_path: None,
                kds_url: None,
            },
            policy: Policy {
                min_tcb: 0,
                required_bits: 0,
                allowed_mask: 0,
            },
            challenge: Challenge { ttl_secs: 30 },
            kbs_measurement_allowlist: vec!["ab".repeat(48)],
        }
    }

    #[test]
    fn dev_skip_defaults_off_and_base_validates() {
        let cfg = config_with(base_vault());
        assert!(!cfg.vault.dev_skip_tls_verify);
        cfg.validate().expect("base config must validate");
    }

    #[test]
    fn dev_skip_without_dev_environment_is_refused() {
        let mut v = base_vault();
        v.dev_skip_tls_verify = true;
        let err = config_with(v)
            .validate()
            .expect_err("dev_skip without dev_environment must be refused");
        assert!(
            matches!(err, BrokerError::Config(ref msg)
                if msg.contains("dev_skip_tls_verify") && msg.contains("dev_environment")),
            "rejection must name the flag and the required opt-in: {err:?}"
        );
    }

    #[test]
    fn dev_skip_on_public_endpoint_is_refused_even_with_dev_environment() {
        for public_addr in [
            // RFC 5737 documentation range — stands in for a production
            // Vault addressed by bare IP:port.
            "https://203.0.113.10:8200",
            "https://vault:8200", // bare DNS name (not *.local)
            "https://vault.hippius.network:8200",
        ] {
            let mut v = base_vault();
            v.dev_skip_tls_verify = true;
            v.dev_environment = true;
            v.address = public_addr.into();
            let err = config_with(v).validate().expect_err(&format!(
                "dev_skip on public endpoint {public_addr:?} must be refused"
            ));
            assert!(
                matches!(err, BrokerError::Config(msg) if msg.contains("public Vault endpoint")),
                "rejection should cite the public-endpoint refusal for {public_addr:?}"
            );
        }
    }

    #[test]
    fn dev_skip_with_dev_environment_and_loopback_validates() {
        let mut v = base_vault();
        v.dev_skip_tls_verify = true;
        v.dev_environment = true; // address already 127.0.0.1
        config_with(v)
            .validate()
            .expect("dev_skip + dev_environment + loopback must validate");
    }

    #[test]
    fn endpoint_classifier_matches_expected() {
        for (addr, is_public) in [
            ("https://203.0.113.10:8200", true),
            ("https://vault.hippius.network:8200", true),
            ("https://vault:8200", true),
            ("https://127.0.0.1:8200", false),
            ("http://10.0.0.5:8200", false),
            ("https://192.168.1.9:8200", false),
            ("https://[::1]:8200", false),
            ("https://[fc00::1]:8200", false),
            ("https://localhost:8200", false),
            ("https://vault.local:8200", false),
            // RA-KBS-VL4: `.internal` is now PUBLIC (no standards basis
            // for being local) ⇒ a dev override toward it is refused.
            ("https://vault.internal:8200", true),
        ] {
            assert_eq!(
                vault_endpoint_is_public(addr),
                is_public,
                "classification mismatch for {addr:?}"
            );
        }
    }
}
