//! `idempotency-record` / `idempotency-recall` subcommands — §14
//! retry-dedup for the PR-G5 vali §24/§25 orchestration layer.
//!
//! Thin CLI wrappers over `kbs_core::persist::FileIdempotencyStore`
//! (PR #45). vali's orchestrator drives external side-effects
//! (snapshot trigger, crypto-erase, NetBird revoke, …) from a tick
//! loop; a tick that crashes after the side-effect but before
//! advancing the job state would re-run it. Each side-effectful step
//! is therefore wrapped: `idempotency-recall` before, skip if
//! already done; `idempotency-record` after. vali shells out here
//! rather than bind the store via PyO3 — the durable file format +
//! the cross-process `O_CREAT|O_EXCL` race-safety stay in Rust next
//! to PR #45.
//!
//! ## Wire contract
//!
//! - stdin: ignored.
//! - the store directory is read from `IDEMPOTENCY_DIR` (env, not
//!   argv); the entry TTL from `IDEMPOTENCY_TTL_SECS` (env, default
//!   1 day).
//! - stdout: a single JSON object — `{"tag":"ok",…}` or
//!   `{"tag":"err","error":"…","category":"…"}`.
//! - exit: `0` ok, `2` structured failure, `1` stdout-write failure.
//!
//! A `record` for a key that already exists is NOT an error — it is
//! a normal `{"tag":"ok","recorded":false,"replay":true}` result the
//! caller acts on (a concurrent tick already recorded it).

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use kbs_core::persist::{FileIdempotencyStore, IdempotencyKey, IdempotencyStore};
use kbs_core::KbsError;
use serde::Serialize;

const EXIT_OK: u8 = 0;
const EXIT_STRUCTURED: u8 = 2;
const EXIT_INTERNAL: u8 = 1;

/// Default recall window when `IDEMPOTENCY_TTL_SECS` is unset — one
/// day comfortably exceeds any plausible orchestration retry window.
const DEFAULT_TTL_SECS: u64 = 86_400;

const ENV_DIR: &str = "IDEMPOTENCY_DIR";
const ENV_TTL: &str = "IDEMPOTENCY_TTL_SECS";

/// Stable `category` vocabulary — keep in sync with the Django
/// consumer (`apps.orchestration.idempotency`).
mod category {
    /// Missing / malformed env config (`IDEMPOTENCY_DIR`, TTL).
    pub const CONFIG: &str = "config";
    /// A hex argument failed to decode or had the wrong length.
    pub const DECODE: &str = "decode";
    /// The file-backed store raised an I/O / corruption error.
    pub const STORE: &str = "store";
}

/// Structured failure — surfaced as `{"tag":"err",…}` + exit 2.
#[derive(Debug)]
struct Fail {
    category: &'static str,
    message: String,
}

impl Fail {
    fn new(category: &'static str, message: String) -> Self {
        Self { category, message }
    }
}

#[derive(clap::Args)]
pub struct IdempotencyRecordArgs {
    /// Hex-encoded idempotency key (the producer's opaque bytestring).
    #[arg(long)]
    key_hex: String,
    /// Hex-encoded 32-byte SHA-256 of the canonical response the
    /// caller is recording for this key.
    #[arg(long)]
    response_hash_hex: String,
    /// Unix seconds to stamp the entry with. Defaults to the system
    /// clock; an explicit value keeps tests deterministic.
    #[arg(long)]
    now_unix: Option<u64>,
}

#[derive(clap::Args)]
pub struct IdempotencyRecallArgs {
    /// Hex-encoded idempotency key to look up.
    #[arg(long)]
    key_hex: String,
    /// Unix seconds used for the TTL check. Defaults to the system
    /// clock.
    #[arg(long)]
    now_unix: Option<u64>,
}

#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum RecordOutput {
    Ok {
        /// `true` iff THIS call wrote the entry.
        recorded: bool,
        /// `true` iff the key was already present (a benign race —
        /// the caller proceeds as "already done").
        replay: bool,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

#[derive(Serialize)]
#[serde(tag = "tag", rename_all = "lowercase")]
enum RecallOutput {
    Ok {
        found: bool,
        /// Hex of the recorded 32-byte response hash, or `null`.
        hash: Option<String>,
    },
    Err {
        error: String,
        category: &'static str,
    },
}

/// Entry point for `idempotency-record`.
pub fn run_record(args: IdempotencyRecordArgs) -> ExitCode {
    let output = match record(&args) {
        Ok((recorded, replay)) => RecordOutput::Ok { recorded, replay },
        Err(f) => RecordOutput::Err {
            error: f.message,
            category: f.category,
        },
    };
    let exit = match &output {
        RecordOutput::Ok { .. } => EXIT_OK,
        RecordOutput::Err { .. } => EXIT_STRUCTURED,
    };
    emit(&output, exit)
}

/// Entry point for `idempotency-recall`.
pub fn run_recall(args: IdempotencyRecallArgs) -> ExitCode {
    let output = match recall(&args) {
        Ok(hash) => RecallOutput::Ok {
            found: hash.is_some(),
            hash: hash.map(hex::encode),
        },
        Err(f) => RecallOutput::Err {
            error: f.message,
            category: f.category,
        },
    };
    let exit = match &output {
        RecallOutput::Ok { .. } => EXIT_OK,
        RecallOutput::Err { .. } => EXIT_STRUCTURED,
    };
    emit(&output, exit)
}

fn emit<T: Serialize>(output: &T, exit: u8) -> ExitCode {
    match serde_json::to_writer(io::stdout().lock(), output) {
        Ok(()) => ExitCode::from(exit),
        Err(e) => {
            eprintln!("hippius-ticket-validator: stdout write failed: {e}");
            ExitCode::from(EXIT_INTERNAL)
        }
    }
}

fn record(args: &IdempotencyRecordArgs) -> Result<(bool, bool), Fail> {
    let (dir, ttl) = store_config()?;
    let key = decode_key(&args.key_hex)?;
    let response_hash = decode_hash(&args.response_hash_hex)?;
    do_record(&dir, ttl, &key, &response_hash, now_unix(args.now_unix))
}

fn recall(args: &IdempotencyRecallArgs) -> Result<Option<[u8; 32]>, Fail> {
    let (dir, ttl) = store_config()?;
    let key = decode_key(&args.key_hex)?;
    do_recall(&dir, ttl, &key, now_unix(args.now_unix))
}

/// Record `(key, hash)`. Returns `(recorded, replay)` — `recorded`
/// is `true` when this call wrote the entry; `replay` is `true` when
/// the key was already present (not an error: a concurrent tick won).
fn do_record(
    dir: &Path,
    ttl: u64,
    key: &IdempotencyKey,
    response_hash: &[u8; 32],
    now: u64,
) -> Result<(bool, bool), Fail> {
    let store = open_store(dir, ttl)?;
    match store.record(key, response_hash, now) {
        Ok(()) => Ok((true, false)),
        // `Replay` = the key already exists. Surfaced as a normal
        // result, NOT an error — the caller treats it as "the
        // side-effect was already performed".
        Err(KbsError::Replay) => Ok((false, true)),
        Err(e) => Err(Fail::new(category::STORE, format!("record: {e}"))),
    }
}

/// Recall the hash recorded for `key`, or `None` if absent / expired.
fn do_recall(
    dir: &Path,
    ttl: u64,
    key: &IdempotencyKey,
    now: u64,
) -> Result<Option<[u8; 32]>, Fail> {
    let store = open_store(dir, ttl)?;
    store
        .recall(key, now)
        .map_err(|e| Fail::new(category::STORE, format!("recall: {e}")))
}

fn open_store(dir: &Path, ttl: u64) -> Result<FileIdempotencyStore, Fail> {
    FileIdempotencyStore::open(dir, ttl)
        .map_err(|e| Fail::new(category::STORE, format!("open store: {e}")))
}

/// Resolve the store directory + TTL from the environment.
fn store_config() -> Result<(PathBuf, u64), Fail> {
    let dir = std::env::var(ENV_DIR)
        .map_err(|_| Fail::new(category::CONFIG, format!("{ENV_DIR} is not set")))?;
    if dir.trim().is_empty() {
        return Err(Fail::new(category::CONFIG, format!("{ENV_DIR} is empty")));
    }
    let ttl = match std::env::var(ENV_TTL) {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|e| Fail::new(category::CONFIG, format!("{ENV_TTL} invalid: {e}")))?,
        Err(_) => DEFAULT_TTL_SECS,
    };
    Ok((PathBuf::from(dir), ttl))
}

fn decode_key(key_hex: &str) -> Result<IdempotencyKey, Fail> {
    let bytes = hex::decode(key_hex.trim())
        .map_err(|e| Fail::new(category::DECODE, format!("key_hex: {e}")))?;
    if bytes.is_empty() {
        return Err(Fail::new(
            category::DECODE,
            "key_hex decodes to an empty key".to_string(),
        ));
    }
    Ok(IdempotencyKey(bytes))
}

fn decode_hash(hash_hex: &str) -> Result<[u8; 32], Fail> {
    let bytes = hex::decode(hash_hex.trim())
        .map_err(|e| Fail::new(category::DECODE, format!("response_hash_hex: {e}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        Fail::new(
            category::DECODE,
            format!("response_hash must be 32 bytes (got {})", bytes.len()),
        )
    })
}

fn now_unix(explicit: Option<u64>) -> u64 {
    explicit.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key(s: &str) -> IdempotencyKey {
        IdempotencyKey(s.as_bytes().to_vec())
    }

    #[test]
    fn record_then_recall_returns_the_hash() {
        let td = TempDir::new().unwrap();
        let k = key("migration:job-1:fencing");
        let h = [0xABu8; 32];
        let (recorded, replay) = do_record(td.path(), 600, &k, &h, 1_000).unwrap();
        assert!(recorded);
        assert!(!replay);
        assert_eq!(do_recall(td.path(), 600, &k, 1_010).unwrap(), Some(h));
    }

    #[test]
    fn recall_of_unknown_key_is_none() {
        let td = TempDir::new().unwrap();
        assert_eq!(
            do_recall(td.path(), 600, &key("never-recorded"), 1_000).unwrap(),
            None,
        );
    }

    #[test]
    fn second_record_of_same_key_is_a_replay_not_an_error() {
        let td = TempDir::new().unwrap();
        let k = key("decommission:job-2:cryptoerasing");
        do_record(td.path(), 600, &k, &[1u8; 32], 100).unwrap();
        // A concurrent / retried record — reported as replay, exit 0.
        let (recorded, replay) = do_record(td.path(), 600, &k, &[2u8; 32], 110).unwrap();
        assert!(!recorded);
        assert!(replay);
        // The ORIGINAL hash is preserved (the second write never lands).
        assert_eq!(do_recall(td.path(), 600, &k, 120).unwrap(), Some([1u8; 32]),);
    }

    #[test]
    fn recall_past_ttl_is_none() {
        let td = TempDir::new().unwrap();
        let k = key("migration:job-3:snapshot");
        do_record(td.path(), 30, &k, &[7u8; 32], 100).unwrap();
        assert!(do_recall(td.path(), 30, &k, 120).unwrap().is_some());
        assert!(do_recall(td.path(), 30, &k, 200).unwrap().is_none());
    }

    #[test]
    fn decode_hash_rejects_wrong_length() {
        assert_eq!(decode_hash("abcd").unwrap_err().category, category::DECODE);
        assert_eq!(decode_hash(&"ab".repeat(32)).unwrap(), [0xABu8; 32],);
    }

    #[test]
    fn decode_key_rejects_empty_and_bad_hex() {
        assert_eq!(decode_key("").unwrap_err().category, category::DECODE);
        assert_eq!(decode_key("zz").unwrap_err().category, category::DECODE);
        assert_eq!(decode_key("6162").unwrap().0, b"ab");
    }

    #[test]
    fn now_unix_prefers_the_explicit_value() {
        assert_eq!(now_unix(Some(42)), 42);
        assert!(now_unix(None) > 0);
    }
}
