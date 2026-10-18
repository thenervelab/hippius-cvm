//! The poster's persisted state (`<state_disk_root>/inventory-state.json`,
//! mode 0600, written atomically): the report `sequence`, the digest of
//! each section last ACCEPTED by vali, and the cadence clocks.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The state file's name under the agent's state root.
pub const STATE_FILE: &str = "inventory-state.json";

/// The state file is never read past this (a few hundred bytes in use).
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// vali's sequence column is an `i64`.
pub const MAX_SEQUENCE: u64 = i64::MAX as u64;

/// A sequence is never below `now_unix × SEQUENCE_CLOCK_SCALE` (see
/// [`InventoryState::next_sequence`]).
pub const SEQUENCE_CLOCK_SCALE: u64 = 1000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryState {
    /// The last sequence drawn (consumed before its report is sent).
    pub sequence: u64,
    /// Per section name, the hex SHA-256 of the canonical CBOR of the
    /// section vali last accepted.
    #[serde(default)]
    pub digests: BTreeMap<String, String>,
    #[serde(default)]
    pub last_full_unix: Option<i64>,
    /// When the next `full` is due (the interval plus its jitter, drawn
    /// once per cycle).
    #[serde(default)]
    pub next_full_unix: Option<i64>,
    #[serde(default)]
    pub last_counters_unix: Option<i64>,
    /// The last report that reached vali, accepted or not (vali's
    /// per-hour budget counts both).
    #[serde(default)]
    pub last_sent_unix: Option<i64>,
}

/// Why the state could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    Unreadable,
    TooLarge,
    Corrupt,
}

impl StateError {
    pub fn class(self) -> &'static str {
        match self {
            StateError::Unreadable => "unreadable",
            StateError::TooLarge => "too-large",
            StateError::Corrupt => "corrupt",
        }
    }
}

impl InventoryState {
    /// The state at `path`; missing is a first run.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        use std::io::Read;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(_) => return Err(StateError::Unreadable),
        };
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StateError::Unreadable)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateError::TooLarge);
        }
        let state: Self = serde_json::from_slice(&bytes).map_err(|_| StateError::Corrupt)?;
        // vali stores a sequence as an i64: one past it is no state of ours.
        if state.sequence > MAX_SEQUENCE {
            return Err(StateError::Corrupt);
        }
        Ok(state)
    }

    /// Write it to `path`: a 0600 temp file in the same directory, fsync,
    /// rename, fsync the directory.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("state path has no parent"))?;
        std::fs::create_dir_all(dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        // `NamedTempFile` creates the file 0600.
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// Draw the next sequence: above the last one, and never below the
    /// clock floor `now_unix × 1000`. The floor keeps it above what vali
    /// last accepted even when this file is lost or reset (a reinstall
    /// under the same identity), which would otherwise be refused as a
    /// replay forever. Persist the state before the report is sent: a
    /// lost response never reuses the value.
    pub fn next_sequence(&mut self, now_unix: i64) -> u64 {
        let floor = u64::try_from(now_unix)
            .unwrap_or(0)
            .saturating_mul(SEQUENCE_CLOCK_SCALE);
        self.sequence = self.sequence.saturating_add(1).max(floor).min(MAX_SEQUENCE);
        self.sequence
    }
}
