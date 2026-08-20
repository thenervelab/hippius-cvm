//! How the broker authenticates ITSELF to Vault (M-k8sauth, #94).
//!
//! Phase 4, after ESO (#886), vali (#887) and the bake Job (#888): the
//! broker was the LAST component still holding a static Vault token. It
//! now exchanges its projected ServiceAccount token for a SHORT-lived
//! Vault token at `auth/<mount>/login` and caches it, re-logging in at
//! 2/3 of the lease so a call starting just before the boundary cannot
//! land after it.
//!
//! This is NOT the release path. The per-VM capability mint
//! ([`crate::vault_client`]) is untouched — this module only decides
//! which token goes in the `X-Vault-Token` header of that one call.
//!
//! ## The static token stays as a transition FALLBACK
//!
//! Unlike vali and the baker, the broker runs as a **kata-snp
//! confidential guest**, and it is NOT established that a SEV-SNP CVM
//! receives the CONTENT of a projected ServiceAccount volume: `kata-snp`
//! runs with `shared_fs="none"`, so a projected volume the kubelet
//! materialises on the HOST is not automatically a readable file inside
//! the guest. The fallback is therefore load-bearing, and so is the
//! logging: on failure we say at ERROR **which** of three very different
//! things happened —
//!
//! - [`LoginError::TokenFile`] — the projected token never reached the
//!   guest (the CVM question above), so this migration needs a different
//!   credential delivery, not a config tweak;
//! - [`LoginError::Rejected`] — the guest CAN read it and Vault saw a
//!   real JWT; only the role/binding is wrong (a config fix);
//! - [`LoginError::Unreachable`] — nothing was learned about either.
//!
//! ## §20 discipline
//!
//! Neither the submitted SA JWT nor the returned Vault token is ever
//! logged or attached to an error. A Vault login error BODY can echo the
//! submitted JWT back, so the HTTP response body of a failed login is
//! dropped unread and only the status code survives.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use zeroize::Zeroizing;

use crate::error::BrokerError;

/// The privileged static Vault token (pre-#94; now the fallback).
pub const ENV_STATIC_TOKEN: &str = "BROKER_VAULT_TOKEN";
/// Vault `jwt` role to log in as. EMPTY/UNSET ⇒ jwt auth disabled and
/// the broker behaves exactly as it did before #94.
pub const ENV_JWT_ROLE: &str = "BROKER_VAULT_JWT_ROLE";
/// Vault auth mount the role lives under.
pub const ENV_JWT_AUTH_PATH: &str = "BROKER_VAULT_JWT_AUTH_PATH";
/// Where the projected ServiceAccount token is mounted.
pub const ENV_JWT_TOKEN_PATH: &str = "BROKER_VAULT_JWT_TOKEN_PATH";

/// Default Vault auth mount (`auth/jwt/login`).
pub const DEFAULT_JWT_AUTH_PATH: &str = "jwt";
/// Default projected-token mount point — matches the `vault`-audience
/// projected volume vali and the baker use (#887/#888).
pub const DEFAULT_JWT_TOKEN_PATH: &str = "/var/run/secrets/vault/token";

/// Re-login at 2/3 of the lease rather than at expiry, so a call that
/// starts just before the boundary cannot land after it.
const REFRESH_NUMERATOR: u64 = 2;
const REFRESH_DENOMINATOR: u64 = 3;

/// Floor for a lease Vault reports as 0/absent (root-ish or a
/// misconfigured role). WITHOUT it `refresh_at` lands on `now`, the
/// cache never hits, and the broker logs in again on EVERY mint — a hot
/// loop against Vault, not a stale token. The floor turns that into one
/// login per 5 min.
const FALLBACK_LEASE_SECS: u64 = 300;

/// Monotonic seconds since first use. Monotonic, not wall-clock, so an
/// NTP step cannot make a live token look expired (or an expired one
/// look live).
fn monotonic_secs() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// Why a jwt login did not produce a Vault token. The three variants are
/// the three ANSWERS this migration needs to tell apart from a pod log
/// alone — see the module docs. None of them carries the JWT.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The projected ServiceAccount token is absent, unreadable or
    /// empty. On a kata-snp guest this is the expected symptom of the
    /// volume never crossing the CVM boundary.
    #[error("projected SA token unreadable at {path} ({reason})")]
    TokenFile { path: String, reason: String },
    /// Vault answered the login with a non-2xx. The body is dropped
    /// unread — it can echo the submitted JWT.
    #[error("login rejected by vault (HTTP {status})")]
    Rejected { status: u16 },
    /// Could not reach Vault at all (DNS/TCP/TLS/timeout).
    #[error("vault unreachable")]
    Unreachable,
    /// 2xx, but not a login response we can use.
    #[error("login response carried no auth.client_token")]
    Malformed,
}

/// A successful `auth/<mount>/login`.
pub struct LoginOutcome {
    pub token: Zeroizing<String>,
    /// `auth.lease_duration` as Vault reported it (0 ⇒ absent).
    pub lease_secs: u64,
}

/// The ONE network call of a login, isolated behind a trait so the
/// caching / refresh / fallback discipline around it is unit-testable
/// without a Vault.
pub trait JwtLogin: Send + Sync {
    fn login(
        &self,
        auth_path: &str,
        role: &str,
        sa_jwt: &Zeroizing<String>,
    ) -> Result<LoginOutcome, LoginError>;
}

/// Where + as whom to log in. `None` anywhere this appears means jwt
/// auth is DISABLED (no role configured) and the pre-#94 static-token
/// path applies unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtSettings {
    pub role: String,
    pub auth_path: String,
    pub token_path: PathBuf,
}

impl JwtSettings {
    /// Read the jwt config from an env getter. Returns `None` when no
    /// role is configured — an unset role is the OFF switch, and every
    /// other var is defaulted so setting just the role is enough.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let role = get(ENV_JWT_ROLE).unwrap_or_default().trim().to_string();
        if role.is_empty() {
            return None;
        }
        let auth_path = get(ENV_JWT_AUTH_PATH)
            .unwrap_or_default()
            .trim()
            .trim_matches('/')
            .to_string();
        let auth_path = if auth_path.is_empty() {
            DEFAULT_JWT_AUTH_PATH.to_string()
        } else {
            auth_path
        };
        let token_path = get(ENV_JWT_TOKEN_PATH)
            .unwrap_or_default()
            .trim()
            .to_string();
        let token_path = if token_path.is_empty() {
            DEFAULT_JWT_TOKEN_PATH.to_string()
        } else {
            token_path
        };
        Some(Self {
            role,
            auth_path,
            token_path: PathBuf::from(token_path),
        })
    }
}

/// What the broker has to authenticate with at startup.
pub struct Credentials {
    pub jwt: Option<JwtSettings>,
    pub static_token: Option<Zeroizing<String>>,
}

/// Resolve the startup credentials from env, fail-closed.
///
/// When NO jwt role is configured this reproduces the pre-#94 startup
/// contract exactly, including both error strings: the static token is
/// then the only credential there is, so a missing or empty one is
/// still a fatal config error.
pub fn startup_credentials(get: impl Fn(&str) -> Option<String>) -> Result<Credentials, String> {
    let jwt = JwtSettings::from_env(&get);
    let raw = get(ENV_STATIC_TOKEN);
    // Deliberately NOT trimmed: the pre-#94 code took the raw env value,
    // and this path must stay byte-identical when no role is set.
    let static_token = match &raw {
        Some(s) if !s.is_empty() => Some(Zeroizing::new(s.clone())),
        _ => None,
    };
    if jwt.is_none() {
        if raw.is_none() {
            return Err("BROKER_VAULT_TOKEN env not set (mounted secret)".to_string());
        }
        if static_token.is_none() {
            return Err("BROKER_VAULT_TOKEN is empty".to_string());
        }
    }
    Ok(Credentials { jwt, static_token })
}

struct Cached {
    token: Zeroizing<String>,
    /// Monotonic second at which the cached token stops being served.
    refresh_at: u64,
}

struct Jwt {
    settings: JwtSettings,
    login: Box<dyn JwtLogin>,
}

/// Resolves the Vault token the broker puts on its own Vault calls.
///
/// Order: a cached/fresh jwt-login token when a role is configured, else
/// the static `BROKER_VAULT_TOKEN`. While both are configured the static
/// token is a FALLBACK ONLY, and taking it is logged at ERROR — a silent
/// fallback would hide a broken jwt setup for as long as the static
/// token happens to live.
pub struct VaultAuth {
    jwt: Option<Jwt>,
    static_token: Option<Zeroizing<String>>,
    cache: Mutex<Option<Cached>>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    log: Box<dyn Fn(&str) + Send + Sync>,
}

impl VaultAuth {
    /// Build from resolved [`Credentials`] plus the login transport.
    /// Fails closed when there is NO credential of either kind.
    pub fn new(creds: Credentials, login: Option<Box<dyn JwtLogin>>) -> Result<Self, String> {
        let jwt = match (creds.jwt, login) {
            (Some(settings), Some(login)) => Some(Jwt { settings, login }),
            (Some(_), None) => {
                return Err("jwt role configured but no login transport built".to_string())
            }
            (None, _) => None,
        };
        if jwt.is_none() && creds.static_token.is_none() {
            return Err("no Vault credential: neither BROKER_VAULT_JWT_ROLE nor \
                        BROKER_VAULT_TOKEN is set"
                .to_string());
        }
        Ok(Self {
            jwt,
            static_token: creds.static_token,
            cache: Mutex::new(None),
            clock: Box::new(monotonic_secs),
            log: Box::new(|line| eprintln!("kbs-vault-broker: {line}")),
        })
    }

    /// Replace the clock (tests drive the 2/3-of-lease refresh).
    #[must_use]
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the log sink (tests assert on what is — and is not —
    /// written).
    #[must_use]
    pub fn with_log(mut self, log: Box<dyn Fn(&str) + Send + Sync>) -> Self {
        self.log = log;
        self
    }

    /// True when jwt auth is configured AND a login token is cached —
    /// the only situation in which a 403 might mean "my token expired
    /// mid-flight" rather than "policy says no".
    pub fn has_cached_jwt(&self) -> bool {
        self.jwt.is_some()
            && self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
    }

    /// The token for one Vault call (cached when still fresh).
    pub fn token(&self) -> Result<Zeroizing<String>, BrokerError> {
        self.resolve(false)
    }

    /// The token for one Vault call, forcing a new login first.
    pub fn refreshed_token(&self) -> Result<Zeroizing<String>, BrokerError> {
        self.resolve(true)
    }

    /// Log in ONCE at startup, so the pod log answers — before any
    /// tenant traffic — the open question of this migration: can this
    /// confidential guest read its projected ServiceAccount token at
    /// all? Fails only when there is no usable credential left.
    pub fn prime(&self) -> Result<(), String> {
        let Some(jwt) = &self.jwt else {
            (self.log)(
                "vault auth: using the static BROKER_VAULT_TOKEN (no BROKER_VAULT_JWT_ROLE set)",
            );
            return Ok(());
        };
        (self.log)(&format!(
            "vault auth: jwt configured — mount=auth/{} role={} token_path={}",
            jwt.settings.auth_path,
            jwt.settings.role,
            jwt.settings.token_path.display()
        ));
        self.resolve(false).map(|_| ()).map_err(|e| format!("{e}"))
    }

    fn resolve(&self, force_refresh: bool) -> Result<Zeroizing<String>, BrokerError> {
        let Some(jwt) = &self.jwt else {
            return self
                .static_token
                .clone()
                .ok_or_else(|| BrokerError::Config(ENV_STATIC_TOKEN.to_string()));
        };
        match self.jwt_token(jwt, force_refresh) {
            Ok(token) => Ok(token),
            Err(e) => {
                // Loud on purpose, and specific: which of the three
                // failures this is decides whether the migration needs a
                // config fix or a different credential delivery.
                (self.log)(&format!(
                    "ERROR: vault auth: jwt login FAILED — {e} [mount=auth/{} role={}]",
                    jwt.settings.auth_path, jwt.settings.role
                ));
                match &self.static_token {
                    Some(static_token) => {
                        (self.log)(
                            "ERROR: vault auth: falling back to the static BROKER_VAULT_TOKEN — \
                             the jwt role / projected-token path needs attention",
                        );
                        Ok(static_token.clone())
                    }
                    None => Err(BrokerError::VaultMint(format!("vault-jwt-login: {e}"))),
                }
            }
        }
    }

    fn jwt_token(&self, jwt: &Jwt, force_refresh: bool) -> Result<Zeroizing<String>, LoginError> {
        let now = (self.clock)();
        // The lock is held ACROSS the login on purpose: without it N
        // concurrent redeems on a cold cache each mint a Vault token and
        // N-1 are leaked (never revoked, just left to expire).
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if !force_refresh {
            if let Some(cached) = cache.as_ref() {
                if now < cached.refresh_at {
                    return Ok(cached.token.clone());
                }
            }
        }
        let sa_jwt = read_sa_jwt(&jwt.settings.token_path)?;
        let outcome = jwt
            .login
            .login(&jwt.settings.auth_path, &jwt.settings.role, &sa_jwt)?;
        let lease = if outcome.lease_secs == 0 {
            FALLBACK_LEASE_SECS
        } else {
            outcome.lease_secs
        };
        let refresh_in = lease.saturating_mul(REFRESH_NUMERATOR) / REFRESH_DENOMINATOR;
        (self.log)(&format!(
            "vault auth: jwt login OK — mount=auth/{} role={} lease={}s (re-login in {refresh_in}s)",
            jwt.settings.auth_path, jwt.settings.role, outcome.lease_secs
        ));
        *cache = Some(Cached {
            token: outcome.token.clone(),
            refresh_at: now.saturating_add(refresh_in),
        });
        Ok(outcome.token)
    }
}

/// Read the projected ServiceAccount token. Absent/unreadable is a
/// FIRST-CLASS outcome, not a panic: off-cluster (and possibly inside a
/// kata-snp guest) there simply is no such file.
fn read_sa_jwt(path: &Path) -> Result<Zeroizing<String>, LoginError> {
    let raw = std::fs::read_to_string(path).map_err(|e| LoginError::TokenFile {
        path: path.display().to_string(),
        reason: format!("{e}"),
    })?;
    let token = Zeroizing::new(raw.trim().to_string());
    if token.is_empty() {
        return Err(LoginError::TokenFile {
            path: path.display().to_string(),
            reason: "file is empty".to_string(),
        });
    }
    Ok(token)
}

/// A failed Vault call, carrying the HTTP status (when there was one)
/// alongside the broker-vocabulary error, so [`with_jwt_retry`] can tell
/// a 403 apart without re-classifying transport errors.
pub struct CallFailure {
    pub status: Option<u16>,
    pub error: BrokerError,
}

/// Run one authenticated Vault call, re-logging in EXACTLY once on a
/// 403 while a cached jwt token is held.
///
/// A cached token can expire (or be revoked) between two calls, and
/// Vault answers that with the SAME 403 as a genuine policy denial. So:
/// re-login once and replay. A real denial 403s again and we stop — one
/// wasted login, no loop. Nothing is retried when the credential is the
/// static token, which cannot be refreshed.
pub fn with_jwt_retry<T>(
    auth: &VaultAuth,
    call: impl Fn(&Zeroizing<String>) -> Result<T, CallFailure>,
) -> Result<T, BrokerError> {
    let token = auth.token()?;
    match call(&token) {
        Ok(value) => Ok(value),
        Err(failure) => {
            if failure.status == Some(403) && auth.has_cached_jwt() {
                let fresh = auth.refreshed_token()?;
                return call(&fresh).map_err(|f| f.error);
            }
            Err(failure.error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// A JWT that must never appear in a log line or an error.
    const SECRET_JWT: &str = "eyJhbGciOiJSUzI1NiJ9.SECRET-SA-JWT-PAYLOAD.sig";

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    /// `unwrap_err` needs `T: Debug`, and neither `Credentials` nor
    /// `VaultAuth` implements it — deliberately, they hold tokens.
    fn err_of<T>(r: Result<T, String>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    struct FakeLogin {
        calls: AtomicU64,
        outcome: Box<dyn Fn(u64) -> Result<LoginOutcome, LoginError> + Send + Sync>,
        seen_jwt: Mutex<Vec<String>>,
    }

    impl FakeLogin {
        fn ok(token: &'static str, lease: u64) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                outcome: Box::new(move |n| {
                    Ok(LoginOutcome {
                        token: Zeroizing::new(format!("{token}-{n}")),
                        lease_secs: lease,
                    })
                }),
                seen_jwt: Mutex::new(Vec::new()),
            })
        }
        fn failing(make: impl Fn() -> LoginError + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                outcome: Box::new(move |_| Err(make())),
                seen_jwt: Mutex::new(Vec::new()),
            })
        }
        fn count(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl JwtLogin for Arc<FakeLogin> {
        fn login(
            &self,
            _auth_path: &str,
            _role: &str,
            sa_jwt: &Zeroizing<String>,
        ) -> Result<LoginOutcome, LoginError> {
            self.seen_jwt
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(sa_jwt.to_string());
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            (self.outcome)(n)
        }
    }

    /// A real on-disk projected-token file, so `read_sa_jwt` is exercised
    /// for what it is (a filesystem read that may simply not be there).
    struct TokenFile(PathBuf);
    impl TokenFile {
        fn with(contents: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "broker-sa-jwt-{}-{}.tok",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
        fn missing() -> PathBuf {
            std::env::temp_dir().join("broker-sa-jwt-does-not-exist-a9f3.tok")
        }
    }
    impl Drop for TokenFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    struct Logs(Arc<Mutex<Vec<String>>>);
    impl Logs {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }
        fn sink(&self) -> Box<dyn Fn(&str) + Send + Sync> {
            let buf = Arc::clone(&self.0);
            Box::new(move |line| {
                buf.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(line.to_string())
            })
        }
        fn all(&self) -> Vec<String> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
        fn errors(&self) -> Vec<String> {
            self.all()
                .into_iter()
                .filter(|l| l.starts_with("ERROR:"))
                .collect()
        }
    }

    fn settings(token_path: PathBuf) -> JwtSettings {
        JwtSettings {
            role: "kbs-vault-broker".to_string(),
            auth_path: "jwt".to_string(),
            token_path,
        }
    }

    fn auth_with(
        jwt: Option<JwtSettings>,
        login: Option<Box<dyn JwtLogin>>,
        static_token: Option<&str>,
        logs: &Logs,
        clock: Arc<AtomicU64>,
    ) -> VaultAuth {
        VaultAuth::new(
            Credentials {
                jwt,
                static_token: static_token.map(|s| Zeroizing::new(s.to_string())),
            },
            login,
        )
        .unwrap()
        .with_log(logs.sink())
        .with_clock(Box::new(move || clock.load(Ordering::SeqCst)))
    }

    // ---- CLAIM: an unset role leaves the pre-#94 path untouched -------

    #[test]
    fn no_role_means_no_jwt_settings_at_all() {
        // The OFF switch is the role being empty/unset — every other var
        // being present must not turn jwt auth on by itself.
        assert_eq!(JwtSettings::from_env(env(&[])), None);
        assert_eq!(JwtSettings::from_env(env(&[(ENV_JWT_ROLE, "")])), None);
        assert_eq!(JwtSettings::from_env(env(&[(ENV_JWT_ROLE, "   ")])), None);
        assert_eq!(
            JwtSettings::from_env(env(&[
                (ENV_JWT_AUTH_PATH, "kubernetes"),
                (ENV_JWT_TOKEN_PATH, "/somewhere/token"),
            ])),
            None
        );
    }

    #[test]
    fn role_unset_keeps_the_exact_pre_94_static_token_contract() {
        // Byte-identical to the old main.rs: unset and empty are two
        // DIFFERENT fatal messages, and any non-empty value is taken raw.
        assert_eq!(
            err_of(startup_credentials(env(&[]))),
            "BROKER_VAULT_TOKEN env not set (mounted secret)"
        );
        assert_eq!(
            err_of(startup_credentials(env(&[(ENV_STATIC_TOKEN, "")]))),
            "BROKER_VAULT_TOKEN is empty"
        );
        let creds = startup_credentials(env(&[(ENV_STATIC_TOKEN, "hvs.static")])).unwrap();
        assert!(creds.jwt.is_none());
        assert_eq!(
            creds.static_token.map(|t| t.to_string()),
            Some("hvs.static".to_string())
        );
    }

    #[test]
    fn role_unset_serves_the_static_token_and_never_logs_an_error() {
        let logs = Logs::new();
        let auth = auth_with(
            None,
            None,
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        auth.prime().unwrap();
        assert_eq!(auth.token().unwrap().as_str(), "hvs.static");
        assert!(!auth.has_cached_jwt());
        assert!(logs.errors().is_empty(), "{:?}", logs.all());
    }

    #[test]
    fn a_role_alone_is_enough_and_the_rest_is_defaulted() {
        let s = JwtSettings::from_env(env(&[(ENV_JWT_ROLE, "kbs-vault-broker")])).unwrap();
        assert_eq!(s.role, "kbs-vault-broker");
        assert_eq!(s.auth_path, DEFAULT_JWT_AUTH_PATH);
        assert_eq!(s.token_path, PathBuf::from(DEFAULT_JWT_TOKEN_PATH));
        // Overrides win, and a mount given as `/kubernetes/` is accepted.
        let s = JwtSettings::from_env(env(&[
            (ENV_JWT_ROLE, "r"),
            (ENV_JWT_AUTH_PATH, "/kubernetes/"),
            (ENV_JWT_TOKEN_PATH, "/var/run/secrets/other/token"),
        ]))
        .unwrap();
        assert_eq!(s.auth_path, "kubernetes");
        assert_eq!(s.token_path, PathBuf::from("/var/run/secrets/other/token"));
    }

    // ---- CLAIM: a successful login is what gets used ------------------

    #[test]
    fn login_success_uses_the_logged_in_token_not_the_static_one() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 3600);
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        assert_eq!(auth.token().unwrap().as_str(), "hvs.jwt-0");
        assert_eq!(login.count(), 1);
        assert!(logs.errors().is_empty(), "{:?}", logs.all());
        // The success line names the mount + role + lease, never a token.
        let ok = logs
            .all()
            .into_iter()
            .find(|l| l.contains("jwt login OK"))
            .unwrap();
        assert!(ok.contains("mount=auth/jwt"), "{ok}");
        assert!(ok.contains("role=kbs-vault-broker"), "{ok}");
        assert!(ok.contains("lease=3600s"), "{ok}");
        assert!(!ok.contains("hvs.jwt-0"), "{ok}");
    }

    // ---- CLAIM: a failed login falls back, loudly ---------------------

    #[test]
    fn login_failure_with_a_static_token_falls_back_and_logs_error() {
        // The token file IS readable here: this pins the "vault said no"
        // leg, not the "guest never got the file" one.
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::failing(|| LoginError::Rejected { status: 400 });
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        assert_eq!(auth.token().unwrap().as_str(), "hvs.static");
        let errs = logs.errors();
        assert_eq!(errs.len(), 2, "{errs:?}");
        assert!(errs[0].contains("HTTP 400"), "{errs:?}");
        assert!(errs[1].contains("falling back"), "{errs:?}");
    }

    #[test]
    fn login_failure_without_a_static_token_fails_closed() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::failing(|| LoginError::Rejected { status: 403 });
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        let err = auth.token().unwrap_err();
        assert!(format!("{err}").contains("vault-jwt-login"), "{err}");
        assert_eq!(err.http_status(), 502);
        // prime() surfaces the same fail-closed at STARTUP.
        assert!(auth.prime().is_err());
    }

    #[test]
    fn the_three_failures_are_distinguishable_in_the_log() {
        // The deliverable: an operator reading only the pod log must be
        // able to tell "the guest never got the file" from "vault said
        // no" from "vault was unreachable".

        // (a) token file absent — the kata-snp CVM question.
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(TokenFile::missing())),
            Some(Box::new(FakeLogin::ok("unused", 60))),
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        auth.token().unwrap();
        assert!(
            logs.errors()[0].contains("projected SA token unreadable"),
            "{:?}",
            logs.errors()
        );

        // (b) login rejected — carries the HTTP status.
        let file_b = TokenFile::with(SECRET_JWT);
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file_b.0.clone())),
            Some(Box::new(FakeLogin::failing(|| LoginError::Rejected {
                status: 400,
            }))),
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        auth.token().unwrap();
        assert!(
            logs.errors()[0].contains("login rejected by vault (HTTP 400)"),
            "{:?}",
            logs.errors()
        );

        // (c) vault unreachable — says nothing about the token file.
        let file_c = TokenFile::with(SECRET_JWT);
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file_c.0.clone())),
            Some(Box::new(FakeLogin::failing(|| LoginError::Unreachable))),
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        auth.token().unwrap();
        assert!(
            logs.errors()[0].contains("vault unreachable"),
            "{:?}",
            logs.errors()
        );
    }

    // ---- CLAIM: no secret ever reaches a log line or an error ---------

    #[test]
    fn a_successful_login_never_writes_the_jwt_or_the_minted_token_to_a_log() {
        // The SUCCESS path is where the plaintext Vault token actually
        // exists, so it is the path most likely to grow a debug line.
        // Every log line of a full lifecycle — first login, cache hits,
        // and a refresh — is checked, not just the one line we wrote.
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 900);
        let logs = Logs::new();
        let clock = Arc::new(AtomicU64::new(0));
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::clone(&clock),
        );
        auth.prime().unwrap();
        auth.token().unwrap();
        clock.store(600, Ordering::SeqCst);
        auth.token().unwrap();
        auth.refreshed_token().unwrap();
        assert!(login.count() >= 2, "the refresh legs did not run");
        let lines = logs.all();
        assert!(lines.iter().any(|l| l.contains("jwt login OK")));
        for line in &lines {
            assert!(!line.contains(SECRET_JWT), "JWT leaked: {line}");
            assert!(!line.contains("hvs.jwt-"), "vault token leaked: {line}");
        }
        // The transport was handed the JWT — so the check above is not
        // passing merely because nothing ever read the file.
        let seen = login.seen_jwt.lock().unwrap_or_else(|e| e.into_inner());
        assert!(seen.iter().all(|j| j == SECRET_JWT), "{seen:?}");
    }

    #[test]
    fn no_log_line_or_error_ever_contains_the_jwt_or_the_vault_token() {
        let file = TokenFile::with(SECRET_JWT);
        // A rejection whose Display would leak if anyone ever put the
        // response body in it.
        let login = FakeLogin::failing(|| LoginError::Rejected { status: 400 });
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            Some("hvs.static-secret"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        auth.prime().unwrap();
        for line in logs.all() {
            assert!(!line.contains(SECRET_JWT), "JWT leaked: {line}");
            assert!(!line.contains("hvs.static-secret"), "token leaked: {line}");
        }
        // …and the error type itself, when it is returned rather than logged.
        let err = LoginError::Rejected { status: 400 };
        assert!(!format!("{err}").contains(SECRET_JWT));
        assert!(!format!("{err:?}").contains(SECRET_JWT));

        // The fail-closed BrokerError is what a caller would attach to a
        // 502 body — it must be clean too.
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(FakeLogin::failing(|| LoginError::Rejected {
                status: 400,
            }))),
            None,
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        let err = auth.token().unwrap_err();
        assert!(!format!("{err}").contains(SECRET_JWT), "{err}");
    }

    // ---- CLAIM: the token is cached, and refreshed at 2/3 of the lease -

    #[test]
    fn a_cached_token_is_reused_so_n_calls_are_not_n_logins() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 3600);
        let logs = Logs::new();
        let clock = Arc::new(AtomicU64::new(0));
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::clone(&clock),
        );
        for _ in 0..25 {
            assert_eq!(auth.token().unwrap().as_str(), "hvs.jwt-0");
        }
        assert_eq!(login.count(), 1, "cache did not hold");
        assert!(auth.has_cached_jwt());
    }

    #[test]
    fn the_token_is_refreshed_at_two_thirds_of_the_lease_not_at_expiry() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 900);
        let logs = Logs::new();
        let clock = Arc::new(AtomicU64::new(0));
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::clone(&clock),
        );
        assert_eq!(auth.token().unwrap().as_str(), "hvs.jwt-0");
        // 2/3 of 900 = 600. One second BEFORE the boundary: still cached.
        clock.store(599, Ordering::SeqCst);
        assert_eq!(auth.token().unwrap().as_str(), "hvs.jwt-0");
        assert_eq!(login.count(), 1);
        // AT the boundary: a new login, well before the 900s expiry.
        clock.store(600, Ordering::SeqCst);
        assert_eq!(auth.token().unwrap().as_str(), "hvs.jwt-1");
        assert_eq!(login.count(), 2);
    }

    #[test]
    fn a_zero_lease_does_not_become_a_login_per_call() {
        // Vault reporting lease_duration 0 must not collapse the cache
        // into a hot loop: the floor gives one login per 200s (2/3 of
        // 300), not one per call.
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 0);
        let logs = Logs::new();
        let clock = Arc::new(AtomicU64::new(0));
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::clone(&clock),
        );
        for _ in 0..10 {
            auth.token().unwrap();
        }
        assert_eq!(login.count(), 1);
        clock.store(199, Ordering::SeqCst);
        auth.token().unwrap();
        assert_eq!(login.count(), 1);
        clock.store(200, Ordering::SeqCst);
        auth.token().unwrap();
        assert_eq!(login.count(), 2);
    }

    // ---- CLAIM: a 403 costs exactly one re-login ----------------------

    fn failure(status: u16) -> CallFailure {
        CallFailure {
            status: Some(status),
            error: BrokerError::VaultMint(format!("token create: vault-{status}")),
        }
    }

    #[test]
    fn a_403_triggers_exactly_one_relogin_and_then_gives_up() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 3600);
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        let calls = AtomicU64::new(0);
        let seen: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let out: Result<(), BrokerError> = with_jwt_retry(&auth, |tok| {
            calls.fetch_add(1, Ordering::SeqCst);
            seen.lock().unwrap().push(tok.to_string());
            Err(failure(403))
        });
        assert!(out.is_err());
        // Two attempts, two logins (the initial one + ONE forced), and the
        // replay carried a DIFFERENT, freshly minted token.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(login.count(), 2);
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen, vec!["hvs.jwt-0".to_string(), "hvs.jwt-1".to_string()]);
    }

    #[test]
    fn a_403_on_a_success_path_and_non_403s_do_not_retry() {
        let file = TokenFile::with(SECRET_JWT);
        let login = FakeLogin::ok("hvs.jwt", 3600);
        let logs = Logs::new();
        let auth = auth_with(
            Some(settings(file.0.clone())),
            Some(Box::new(Arc::clone(&login))),
            None,
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        // A 400 is a request-shape problem; replaying it is pointless.
        let calls = AtomicU64::new(0);
        let out: Result<(), BrokerError> = with_jwt_retry(&auth, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(failure(400))
        });
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(login.count(), 1);
        // A success is passed straight through, one call, no extra login.
        let ok = with_jwt_retry(&auth, |_| Ok(7u8)).unwrap();
        assert_eq!(ok, 7);
        assert_eq!(login.count(), 1);
    }

    #[test]
    fn a_403_on_the_static_token_path_is_never_retried() {
        // There is nothing to refresh, so a retry would just be a second
        // identical rejection.
        let logs = Logs::new();
        let auth = auth_with(
            None,
            None,
            Some("hvs.static"),
            &logs,
            Arc::new(AtomicU64::new(0)),
        );
        let calls = AtomicU64::new(0);
        let out: Result<(), BrokerError> = with_jwt_retry(&auth, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(failure(403))
        });
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_credential_of_either_kind_is_refused_at_construction() {
        let err = err_of(VaultAuth::new(
            Credentials {
                jwt: None,
                static_token: None,
            },
            None,
        ));
        assert!(err.contains("no Vault credential"), "{err}");
    }
}
