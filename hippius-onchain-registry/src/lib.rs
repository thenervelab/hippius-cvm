//! Single-source reader for `pallet-compute-scoring` (§23) on-chain
//! state, over a `thenervelab/thebrain` Substrate node's JSON-RPC.
//!
//! This crate is the ONE definition of the §23 storage-key derivation
//! (`twox_128` / `blake2_128`) + SCALE decode + the minimal blocking
//! JSON-RPC client. Two consumers share it so the wire layout can
//! never drift between them:
//!
//! - the `read-miner-status` vali shell-out (`hippius-ticket-validator`),
//!   the scheduler's authoritative on-chain read; and
//! - the **Edge gateway's on-chain miner-auth registry poller** — the
//!   permissionless replacement for the operator-CA mTLS bootstrap
//!   (`docs/design/permissionless-miner-auth.md`): a connecting miner
//!   is admitted iff its node_id is registered + `Active` on-chain.
//!
//! The pallet's storage shapes (the reader's frozen contract):
//!
//! - `CurrentEpoch` — `StorageValue<u64, ValueQuery>`; absent ⇒ 0.
//! - `NodeIdToChild` — `StorageMap<Blake2_128Concat, [u8;32],
//!   AccountId>`. The AUTHORITATIVE registry: the pallet writes a
//!   `MinerStatuses` row ONLY for non-default statuses and removes it
//!   on recovery to Active, so enumerating `MinerStatuses` would miss
//!   every Active miner. `NodeIdToChild` carries every registration.
//! - `MinerStatuses[node_id]` — the §13 `Active | Quarantined |
//!   Decommissioned` state machine; ABSENT ⇒ the implicit `Active`.
//! - `EpochWeights[CurrentEpoch][node_id]` — `StorageDoubleMap` → the
//!   §23 reward weight, reused as the v1 "quality" signal.
//! - `ChildRegistrations[child]` — `StorageMap<Blake2_128Concat,
//!   AccountId, ChildRegistration>`: the child's `family`, `node_id` and
//!   `Active | Unbonding` status. With `NodeIdToChild` it answers "which
//!   family runs this node" ([`fetch_node_family`], the operator-config
//!   write check).
//!
//! Deterministic: no randomness, no wall-clock; the only inputs are
//! the RPC responses.

use std::hash::Hasher;
use std::io::Read;
use std::time::Duration;

use blake2::digest::consts::U16;
use blake2::{Blake2b, Digest};
use codec::Decode;
use twox_hash::XxHash64;

pub mod metadata;

/// Per-RPC-call timeout. Each `state_getStorage` / `state_getKeysPaged`
/// round-trip is bounded independently.
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(8);

/// Hard cap on a single RPC response body. A misbehaving / hostile
/// node cannot OOM the reader by streaming an unbounded body.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// `state_getKeysPaged` page size.
const KEYS_PAGE_SIZE: u32 = 1000;

/// Stable `category` vocabulary — kept in sync with the Django
/// consumer (`apps.scheduler.chain`) and the Edge poller's log lines.
pub mod category {
    /// The JSON-RPC request could not be sent / the connection
    /// failed / the RPC URL was empty.
    pub const RPC_REQUEST: &str = "rpc-request";
    /// The node answered but the response was not a well-formed
    /// JSON-RPC result (non-JSON, `error` member, missing `result`,
    /// bad hex, unexpected storage-key shape).
    pub const RPC_RESPONSE: &str = "rpc-response";
    /// A storage value decoded off the wire did not match the
    /// pallet's expected SCALE layout.
    pub const SCALE_DECODE: &str = "scale-decode";
    /// The signed vali feed failed its Ed25519 signature check — a
    /// missing / malformed / wrong signature over the response bytes when
    /// a verifying pubkey is pinned (audit M-registry-mTLS). Fail-closed:
    /// a tampered / unsigned feed is dropped, never trusted.
    pub const FEED_SIGNATURE: &str = "feed-signature";
    /// `state_getMetadata` returned something this reader cannot make a
    /// claim about: a bad `meta` magic, a metadata version outside the
    /// supported set, or a pallet name too long to SCALE-length-prefix.
    /// Distinct from [`RPC_RESPONSE`] because the response WAS well-formed
    /// JSON — it is the metadata blob itself we refuse to interpret. We
    /// never guess: an unknown metadata layout means "cannot determine".
    pub const METADATA_SHAPE: &str = "metadata-shape";
    /// The runtime metadata no longer names a pallet / storage item the
    /// read depends on: its raw storage may be a fossil. Fail-closed reads
    /// (the operator-config family check) refuse on it.
    pub const PALLET_ABSENT: &str = "pallet-absent";
}

/// Structured read failure. `category` is drawn from [`category`];
/// `message` is operator-facing and NEVER echoes the RPC URL (which
/// may carry a credential) — only the error kind (§20).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{category}: {message}")]
pub struct RegistryError {
    pub category: &'static str,
    pub message: String,
}

impl RegistryError {
    pub fn new(category: &'static str, message: String) -> Self {
        Self { category, message }
    }
}

/// The §13 per-node state-machine value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerStatus {
    Active,
    Quarantined,
    Decommissioned,
}

impl MinerStatus {
    /// Map the `MinerStatus` SCALE discriminant to the enum. An
    /// unknown discriminant fails closed (the read is dropped).
    pub fn from_discriminant(discriminant: u8) -> Result<Self, RegistryError> {
        match discriminant {
            0 => Ok(MinerStatus::Active),
            1 => Ok(MinerStatus::Quarantined),
            2 => Ok(MinerStatus::Decommissioned),
            other => Err(RegistryError::new(
                category::SCALE_DECODE,
                format!("unknown MinerStatus discriminant {other}"),
            )),
        }
    }

    /// The lowercase wire label (`active` | `quarantined` |
    /// `decommissioned`) — the JSON contract the vali scheduler reads.
    pub fn label(self) -> &'static str {
        match self {
            MinerStatus::Active => "active",
            MinerStatus::Quarantined => "quarantined",
            MinerStatus::Decommissioned => "decommissioned",
        }
    }
}

/// One registered miner, as read off the chain.
#[derive(Debug, Clone)]
pub struct MinerRecord {
    /// The 32-byte Ed25519 node identity (the registry key).
    pub node_id: [u8; 32],
    pub status: MinerStatus,
    /// Epoch of the last on-chain `MinerStatus` transition.
    pub last_transition_epoch: u64,
    /// Epoch the miner's score genuinely reflects: `current_epoch` if
    /// the validator scored it this epoch (`EpochWeights` present),
    /// else `last_transition_epoch`.
    pub data_epoch: u64,
    /// §23 reward weight (the v1 "quality" signal), `u128`.
    pub quality: u128,
    /// The miner's announced effective price (`MinerPrice[node_id]`, USD
    /// per resource-unit ×1e6). `None` ⇒ the miner has not set a price —
    /// the scheduler's price term is then inert for it (treated as free /
    /// price-neutral), and the tenant ceiling never trips.
    pub price: Option<u128>,
}

/// A full read of the registry at one chain head.
#[derive(Debug, Clone)]
pub struct RegistrySnapshot {
    pub current_epoch: u64,
    pub miners: Vec<MinerRecord>,
    /// Whether the pallet this snapshot was read from is STILL WIRED into
    /// the runtime (present in `state_getMetadata`), as opposed to a
    /// removed pallet whose storage prefix survived the runtime upgrade.
    ///
    /// A runtime upgrade that drops a pallet does NOT delete its storage.
    /// Every read in this crate derives its keys from the pallet NAME
    /// STRING (twox-128) and reads raw storage — so a removed pallet keeps
    /// answering with the last bytes it ever wrote, forever. Without this
    /// flag the reader cannot tell "live chain state" from "a fossil", and
    /// a consumer polling every 30 s sees a perfectly healthy read of data
    /// that can never change again.
    ///
    /// `true` also means "could not determine" — see [`fetch_registry`].
    pub pallet_live: bool,
}

impl RegistrySnapshot {
    /// The set of node_ids admitted to participate: registered AND
    /// `Active`. This is the permissionless Edge admission gate — a
    /// quarantined / decommissioned node is excluded for free on the
    /// next refresh (revocation = on-chain state transition).
    pub fn active_node_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.miners
            .iter()
            .filter(|m| m.status == MinerStatus::Active)
            .map(|m| m.node_id)
            .collect()
    }
}

/// Read the full §23 registry from `rpc_url` for the pallet named
/// `pallet` (as wired into thebrain's `construct_runtime!` — drives
/// the twox-128 prefix; a wrong name reads zero miners and the caller
/// fails closed). Blocking; run it off the async runtime.
///
/// The docstring above describes the WRONG-NAME failure. There is a
/// second one it does not cover, and it fails OPEN: if the pallet was
/// REMOVED from the runtime, the name is right, the storage prefix
/// survives the upgrade, and every read below returns the last bytes the
/// pallet ever wrote — indefinitely, with no error anywhere. The
/// [`RegistrySnapshot::pallet_live`] flag (probed from the runtime
/// metadata, which is the only thing that knows) is what distinguishes
/// the two.
///
/// **This function does NOT fail on `pallet_live == false`.** That is
/// deliberate and is an operator decision, not this crate's: vali is
/// running production placement off this read right now, and turning the
/// fossil into an `Err` here would instantly stop every placement and
/// empty the Edge's admission feed. The crate's job is to stop LYING
/// about the data; the consumer decides what to do about the truth (in
/// vali: `VALI_CHAIN_REQUIRE_PALLET_LIVE`).
pub fn fetch_registry(rpc_url: &str, pallet: &str) -> Result<RegistrySnapshot, RegistryError> {
    let url = rpc_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "RPC URL is empty".to_string(),
        ));
    }

    // Probe FIRST — the answer describes every storage read below it.
    //
    // A probe that itself FAILS (RPC blip, unknown metadata version) must
    // not take the registry read down, and must not raise the alarm
    // either: "cannot determine" defaults to `true`, i.e. the same claim
    // this crate made before the probe existed. An RPC hiccup flipping
    // `pallet_live` to false would teach operators to ignore the flag,
    // which is exactly the failure this whole change is fixing.
    let pallet_live = probe_to_flag(pallet_present_in_metadata(url, pallet));

    // CurrentEpoch — `StorageValue<u64, ValueQuery>`; absent ⇒ 0.
    let current_epoch_key = storage_value_key(pallet, "CurrentEpoch");
    let current_epoch = match get_storage(url, &current_epoch_key)? {
        Some(bytes) => scale_u64(&bytes)?,
        None => 0,
    };

    // Discover the registered set from `NodeIdToChild`.
    let registry_prefix = storage_map_prefix(pallet, "NodeIdToChild");
    let registry_keys = get_keys_paged(url, &registry_prefix, None)?;

    let epoch_scale = current_epoch.to_le_bytes();

    let mut miners = Vec::with_capacity(registry_keys.len());
    for key in &registry_keys {
        // Blake2_128Concat layout: prefix(32) ++ blake2_128(16) ++
        // raw [u8; 32] node_id — the node_id is the trailing 32 B.
        if key.len() != registry_prefix.len() + 16 + 32 {
            return Err(RegistryError::new(
                category::RPC_RESPONSE,
                format!("unexpected NodeIdToChild key length {}", key.len()),
            ));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&key[key.len() - 32..]);

        // MinerStatuses[node_id] — present ⇒ a non-default status;
        // ABSENT ⇒ the implicit `Active`.
        let status_key = storage_map_key(pallet, "MinerStatuses", &node_id);
        let (status, last_transition_epoch) = match get_storage(url, &status_key)? {
            Some(bytes) => {
                let (disc, epoch) = decode_miner_status_entry(&bytes)?;
                (MinerStatus::from_discriminant(disc)?, epoch)
            }
            None => (MinerStatus::Active, 0u64),
        };

        // EpochWeights[current_epoch][node_id] → `u128`. `None` ⇒ not
        // scored this epoch ⇒ quality 0, data_epoch = last transition.
        let weight_key = storage_double_map_key(pallet, "EpochWeights", &epoch_scale, &node_id);
        let (quality, data_epoch) = match get_storage(url, &weight_key)? {
            Some(bytes) => (scale_u128(&bytes)?, current_epoch),
            None => (0u128, last_transition_epoch),
        };

        // MinerPrice[node_id] → `u128` (OptionQuery). `None` ⇒ the miner
        // never announced a price — price-neutral for placement.
        let price_key = storage_map_key(pallet, "MinerPrice", &node_id);
        let price = match get_storage(url, &price_key)? {
            Some(bytes) => Some(scale_u128(&bytes)?),
            None => None,
        };

        miners.push(MinerRecord {
            node_id,
            status,
            last_transition_epoch,
            data_epoch,
            quality,
            price,
        });
    }

    // Deterministic order — stable logs / golden diffs.
    miners.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Ok(RegistrySnapshot {
        current_epoch,
        miners,
        pallet_live,
    })
}

/// Is `pallet` still wired into the runtime at `rpc_url`?
///
/// Reads `state_getMetadata` — the ONLY authority on what the runtime
/// actually contains. Raw storage cannot answer this: a removed pallet's
/// prefix survives the upgrade and keeps serving its last-written bytes,
/// so `state_getStorage` is happy either way.
///
/// The test is a byte search for the pallet's name as SCALE encodes a
/// `String`: `Compact(len) ++ utf8`. A live pallet's name appears several
/// times in the metadata (the pallet entry itself plus its Call / Event /
/// Error type paths); a removed one appears zero times. The LENGTH PREFIX
/// is load-bearing — without it a bare ASCII match would hit any type
/// path, doc string or longer name that merely CONTAINS the needle.
///
/// Supports metadata v14 and v15. An unknown version is an error, not a
/// guess: we would rather say "cannot determine" than make a false claim
/// about a layout we have not read.
pub fn pallet_present_in_metadata(rpc_url: &str, pallet: &str) -> Result<bool, RegistryError> {
    let url = rpc_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "RPC URL is empty".to_string(),
        ));
    }
    let result = rpc_call(url, "state_getMetadata", serde_json::json!([]))?;
    let hex_str = result.as_str().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "state_getMetadata result is not a string".to_string(),
        )
    })?;
    metadata_contains_pallet(&decode_hex(hex_str)?, pallet)
}

/// Collapse a metadata-probe outcome into the `pallet_live` flag.
///
/// A FAILED probe (RPC blip, unknown metadata version) is "cannot
/// determine", and cannot-determine reports `true` — the same claim this
/// crate made before the probe existed. Deliberately NOT fail-closed: an
/// RPC hiccup that flipped the flag to `false` would teach operators to
/// ignore the one signal that distinguishes a live chain from a fossil,
/// and (with vali's gate armed) would turn a transient network error
/// into a placement outage.
///
/// A one-line seam, but it is the only place that decision is made, so
/// it is the only place it can be pinned by a test without a network.
fn probe_to_flag(probe: Result<bool, RegistryError>) -> bool {
    probe.unwrap_or(true)
}

/// Metadata magic — the first 4 bytes of every `state_getMetadata` blob.
const METADATA_MAGIC: &[u8; 4] = b"meta";

/// Metadata versions whose byte layout this probe is willing to claim
/// anything about. v14 (current on thebrain) and v15.
const SUPPORTED_METADATA_VERSIONS: [u8; 2] = [14, 15];

/// The pure half of [`pallet_present_in_metadata`] — no network, so the
/// discrimination itself is unit-testable over synthetic bytes.
fn metadata_contains_pallet(metadata: &[u8], pallet: &str) -> Result<bool, RegistryError> {
    if metadata.len() < METADATA_MAGIC.len() + 1 {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            format!(
                "metadata is {} bytes — too short to be metadata",
                metadata.len()
            ),
        ));
    }
    if &metadata[..METADATA_MAGIC.len()] != METADATA_MAGIC {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            "metadata does not start with the 'meta' magic".to_string(),
        ));
    }
    let version = metadata[METADATA_MAGIC.len()];
    if !SUPPORTED_METADATA_VERSIONS.contains(&version) {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            format!("unsupported metadata version {version}"),
        ));
    }
    let needle = scale_string_bytes(pallet)?;
    Ok(metadata
        .windows(needle.len())
        .any(|window| window == needle.as_slice()))
}

/// `Compact(len) ++ utf8` — how SCALE encodes a `String`, and therefore
/// how every pallet name appears inside the metadata blob.
fn scale_string_bytes(s: &str) -> Result<Vec<u8>, RegistryError> {
    let mut out = compact_len_prefix(s.len())?;
    out.extend_from_slice(s.as_bytes());
    Ok(out)
}

/// SCALE compact encoding of a length. Single-byte mode (`len < 64`,
/// `len << 2`) and two-byte mode (`len < 2^14`, `(len << 2) | 0b01`,
/// little-endian) — the only two a pallet name can plausibly need.
///
/// A name at or beyond 2^14 bytes is refused rather than silently
/// mis-encoded: a wrong prefix would search for a needle that cannot
/// exist and report the pallet as REMOVED, i.e. a false alarm.
/// A zero-length name is refused for the mirror-image reason — its
/// encoding is the single byte `0x00`, which occurs all over the blob
/// and would report every runtime as containing it.
fn compact_len_prefix(len: usize) -> Result<Vec<u8>, RegistryError> {
    if len == 0 {
        return Err(RegistryError::new(
            category::METADATA_SHAPE,
            "pallet name is empty".to_string(),
        ));
    }
    if len < 64 {
        // Single-byte mode: the two low bits are the 0b00 mode tag.
        Ok(vec![(len as u8) << 2])
    } else if len < 1 << 14 {
        // Two-byte mode: 0b01 mode tag, value in the upper 14 bits, LE.
        Ok((((len as u16) << 2) | 0b01).to_le_bytes().to_vec())
    } else {
        Err(RegistryError::new(
            category::METADATA_SHAPE,
            format!("pallet name is {len} bytes — too long to length-prefix"),
        ))
    }
}

/// One announced-but-not-yet-effective miner price change, read off the
/// pallet's `PendingPriceChange` map.
#[derive(Debug, Clone)]
pub struct PendingPriceChangeRecord {
    /// The 32-byte node identity the change is for (the map key).
    pub node_id: [u8; 32],
    /// The price (u128, USD per resource-unit ×1e6) that becomes
    /// effective at `effective_block`.
    pub new_price: u128,
    /// The block at which `new_price` bites.
    pub effective_block: u64,
}

/// A point-in-time read of the pallet's `PendingPriceChange` map plus
/// the chain head block. The price-migration watcher needs the block
/// (not just the epoch) to size the migration notice window.
#[derive(Debug, Clone)]
pub struct PendingPriceSnapshot {
    pub current_block: u64,
    pub changes: Vec<PendingPriceChangeRecord>,
}

/// Read the pallet's `PendingPriceChange` map (announced-but-not-yet-
/// effective miner price changes) plus the chain head block, from
/// `rpc_url` for the pallet named `pallet`. Mirrors [`fetch_registry`]:
/// blocking, fail-closed on every error, and never echoes the RPC URL.
pub fn fetch_pending_prices(
    rpc_url: &str,
    pallet: &str,
) -> Result<PendingPriceSnapshot, RegistryError> {
    let url = rpc_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "RPC URL is empty".to_string(),
        ));
    }

    // The migration window is measured in blocks — read the chain head.
    let current_block = get_block_number(url)?;

    // Enumerate `PendingPriceChange` — sparse (a row exists only while a
    // change is announced-and-pending; `apply_price_change` removes it).
    let prefix = storage_map_prefix(pallet, "PendingPriceChange");
    let keys = get_keys_paged(url, &prefix, None)?;

    let mut changes = Vec::with_capacity(keys.len());
    for key in &keys {
        // Blake2_128Concat: prefix(32) ++ blake2_128(16) ++ [u8;32].
        if key.len() != prefix.len() + 16 + 32 {
            return Err(RegistryError::new(
                category::RPC_RESPONSE,
                format!("unexpected PendingPriceChange key length {}", key.len()),
            ));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&key[key.len() - 32..]);

        let value = match get_storage(url, key)? {
            Some(bytes) => bytes,
            // Listed but gone between the paged-keys read and this fetch
            // (a concurrent `apply_price_change`) — just skip it.
            None => continue,
        };
        let (new_price, effective_block) = decode_price_change(&value)?;
        changes.push(PendingPriceChangeRecord {
            node_id,
            new_price,
            effective_block,
        });
    }

    // Deterministic order — stable logs / golden diffs.
    changes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Ok(PendingPriceSnapshot {
        current_block,
        changes,
    })
}

// ─── node → family (operator config auth) ───────────────────────────

/// A child registration's `ChildStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStatus {
    Active,
    /// Deregistered, deposit still bonded.
    Unbonding,
}

impl ChildStatus {
    /// Map the `ChildStatus` SCALE discriminant. An unknown discriminant
    /// fails closed.
    pub fn from_discriminant(discriminant: u8) -> Result<Self, RegistryError> {
        match discriminant {
            0 => Ok(ChildStatus::Active),
            1 => Ok(ChildStatus::Unbonding),
            other => Err(RegistryError::new(
                category::SCALE_DECODE,
                format!("unknown ChildStatus discriminant {other}"),
            )),
        }
    }

    /// The lowercase wire label (`active` | `unbonding`).
    pub fn label(self) -> &'static str {
        match self {
            ChildStatus::Active => "active",
            ChildStatus::Unbonding => "unbonding",
        }
    }
}

/// The head of a `ChildRegistration<AccountId32, BlockNumber, Balance>`:
/// `family`, the `node_id` it registered, and its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRegistrationHead {
    pub family: [u8; 32],
    pub node_id: [u8; 32],
    pub status: ChildStatus,
}

/// Why a node has no family binding at the read block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnboundReason {
    /// `NodeIdToChild[node_id]` is absent: the node is not registered.
    NoChild,
    /// The child named by `NodeIdToChild` has no `ChildRegistrations` row.
    NoRegistration,
    /// The registration names another node: the forward and the reverse
    /// index disagree, so neither is trusted.
    NodeMismatch,
}

impl UnboundReason {
    pub fn label(self) -> &'static str {
        match self {
            UnboundReason::NoChild => "no-child",
            UnboundReason::NoRegistration => "no-registration",
            UnboundReason::NodeMismatch => "node-mismatch",
        }
    }
}

/// One node's family binding, every read pinned to one finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFamilyRead {
    /// The finalized block the reads were made at (`0x` + 64 hex).
    pub block_hash: String,
    pub node_id: [u8; 32],
    /// `Ok((child, registration))` when `NodeIdToChild[node_id]` names a
    /// child whose registration names this very node.
    pub binding: Result<([u8; 32], ChildRegistrationHead), UnboundReason>,
}

/// Read `NodeIdToChild[node_id]` and the child's `ChildRegistrations` row
/// at the finalized head, for the pallet named `pallet`. Blocking,
/// fail-closed on every transport / decode error, and never echoes the
/// RPC URL.
pub fn fetch_node_family(
    rpc_url: &str,
    pallet: &str,
    node_id: &[u8; 32],
) -> Result<NodeFamilyRead, RegistryError> {
    let url = rpc_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "RPC URL is empty".to_string(),
        ));
    }
    let block_hash = get_finalized_head(url)?;
    // An authorization read must not trust a fossil: a removed pallet (or
    // map) keeps answering raw storage reads with its last-written bytes.
    // The runtime metadata AT THE SAME BLOCK must still name the pallet
    // and both maps; anything else — absent, or undeterminable — fails.
    let metadata = get_metadata_at(url, &block_hash)?;
    require_family_maps(&metadata, pallet)?;
    let binding = (|| {
        let Some(raw_child) =
            get_storage_at(url, &node_id_to_child_key(pallet, node_id), &block_hash)?
        else {
            return Ok(Err(UnboundReason::NoChild));
        };
        let child = decode_account_id(&raw_child)?;
        let Some(raw_reg) =
            get_storage_at(url, &child_registration_key(pallet, &child), &block_hash)?
        else {
            return Ok(Err(UnboundReason::NoRegistration));
        };
        let reg = decode_child_registration_head(&raw_reg)?;
        if reg.node_id != *node_id {
            return Ok(Err(UnboundReason::NodeMismatch));
        }
        Ok::<_, RegistryError>(Ok((child, reg)))
    })()?;
    Ok(NodeFamilyRead {
        block_hash,
        node_id: *node_id,
        binding,
    })
}

/// The runtime metadata (decoded structurally, [`metadata`]) must list
/// `NodeIdToChild` and `ChildRegistrations` as `Blake2_128Concat` maps of
/// `pallet`, under the storage prefix the keys are derived from.
fn require_family_maps(metadata_blob: &[u8], pallet: &str) -> Result<(), RegistryError> {
    require_maps(
        metadata_blob,
        pallet,
        &["NodeIdToChild", "ChildRegistrations"],
        &[],
    )
}

/// `NodeIdToChild` key: `StorageMap<Blake2_128Concat, [u8; 32], AccountId>`.
fn node_id_to_child_key(pallet: &str, node_id: &[u8; 32]) -> Vec<u8> {
    storage_map_key(pallet, "NodeIdToChild", node_id)
}

/// `ChildRegistrations` key: `StorageMap<Blake2_128Concat, AccountId, …>`.
/// An `AccountId32` encodes as its 32 raw bytes.
fn child_registration_key(pallet: &str, child: &[u8; 32]) -> Vec<u8> {
    storage_map_key(pallet, "ChildRegistrations", child)
}

/// An `AccountId32` value: exactly 32 bytes.
fn decode_account_id(bytes: &[u8]) -> Result<[u8; 32], RegistryError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        RegistryError::new(
            category::SCALE_DECODE,
            format!("AccountId is {} bytes, want 32", bytes.len()),
        )
    })
}

/// Decode a `ChildRegistration<AccountId32, BlockNumber, Balance>`:
/// `family (32) ++ node_id (32) ++ status (1) ++ deposit (u128, 16) ++
/// unbonding_end (BlockNumber)`. The runtime binds `BlockNumber = u32`;
/// a `u64` block number is accepted too (the head fields this returns sit
/// before it either way). Any other length is a layout this reader does
/// not know and fails closed.
fn decode_child_registration_head(bytes: &[u8]) -> Result<ChildRegistrationHead, RegistryError> {
    const HEAD: usize = 32 + 32 + 1 + 16;
    if bytes.len() != HEAD + 4 && bytes.len() != HEAD + 8 {
        return Err(RegistryError::new(
            category::SCALE_DECODE,
            format!("ChildRegistration is {} bytes", bytes.len()),
        ));
    }
    let mut family = [0u8; 32];
    family.copy_from_slice(&bytes[0..32]);
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&bytes[32..64]);
    let status = ChildStatus::from_discriminant(bytes[64])?;
    Ok(ChildRegistrationHead {
        family,
        node_id,
        status,
    })
}

// ─── compute families and their storage (the storage requirement) ───

/// A validator-reported `NodeQuality` of an Arion child
/// (`NodeQualityByChild`): `shard_data_bytes: u128 ++ bandwidth_bytes: u128
/// ++ uptime_permille: u16 ++ strikes: u32 ++ integrity_fails: u32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeQualityRead {
    pub shard_data_bytes: u128,
    pub bandwidth_bytes: u128,
    pub uptime_permille: u16,
    pub strikes: u32,
    pub integrity_fails: u32,
}

/// One child of a family's Arion `FamilyChildren` list and what the chain
/// says about it — the inputs of the pallet's own payout eligibility
/// (`compute_family_weight_from_nodes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageChildRead {
    pub child: [u8; 32],
    /// `Arion.ChildRegistrations[child]`; `None` when absent.
    pub registration: Option<ChildRegistrationHead>,
    /// `Arion.NodeWeightByChild[child]` (`0` when absent).
    pub node_weight: u16,
    /// `Arion.NodeWeightLastBucket[child]` (`0` when absent).
    pub last_bucket: u32,
    /// `Arion.NodeQualityByChild[child]`.
    pub quality: Option<NodeQualityRead>,
}

/// A compute node of a family: its node id and its compute child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeNodeRead {
    pub node_id: [u8; 32],
    pub child: [u8; 32],
}

/// One compute family: its Active compute nodes and every child its Arion
/// `FamilyChildren` lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyStorageRead {
    pub family: [u8; 32],
    pub compute: Vec<ComputeNodeRead>,
    pub storage: Vec<StorageChildRead>,
}

/// Every compute family and its Arion storage children, all read at one
/// finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageFamiliesRead {
    pub block_hash: String,
    /// `Arion.CurrentWeightBucket`.
    pub current_weight_bucket: u32,
    /// The Arion pallet constant `StaleChildBuckets`: a child whose weight
    /// is older than this many buckets is not paid by the pallet.
    pub stale_child_buckets: u32,
    pub families: Vec<FamilyStorageRead>,
}

/// Read every Active compute node (`compute_pallet.NodeIdToChild` →
/// `ChildRegistrations`), grouped by family, and for each family the Arion
/// children it lists (`arion_pallet.FamilyChildren` → `ChildRegistrations`,
/// `NodeWeightByChild`, `NodeWeightLastBucket`, `NodeQualityByChild`), plus
/// `CurrentWeightBucket` and the `StaleChildBuckets` constant — every read
/// pinned to the finalized head. The runtime metadata at that block must
/// name every map read (a fossil is refused) and the constant.
///
/// Facts only: what counts as a healthy storage node is the caller's to
/// decide. Blocking, fail-closed on every transport / decode error, never
/// echoes the RPC URL.
pub fn fetch_storage_families(
    rpc_url: &str,
    compute_pallet: &str,
    arion_pallet: &str,
) -> Result<StorageFamiliesRead, RegistryError> {
    let url = rpc_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "RPC URL is empty".to_string(),
        ));
    }
    let at = get_finalized_head(url)?;
    let metadata = get_metadata_at(url, &at)?;
    require_maps(
        &metadata,
        compute_pallet,
        &["NodeIdToChild", "ChildRegistrations"],
        &[],
    )?;
    require_maps(
        &metadata,
        arion_pallet,
        &[
            "FamilyChildren",
            "ChildRegistrations",
            "NodeWeightByChild",
            "NodeWeightLastBucket",
            "NodeQualityByChild",
        ],
        &["CurrentWeightBucket"],
    )?;
    let stale_child_buckets =
        match metadata::pallet_constant(&metadata, arion_pallet, "StaleChildBuckets")? {
            Some(bytes) => scale_u32(&bytes)?,
            None => {
                return Err(RegistryError::new(
                    category::PALLET_ABSENT,
                    format!("`{arion_pallet}` has no StaleChildBuckets constant in the runtime"),
                ))
            }
        };
    let current_weight_bucket = match get_storage_at(
        url,
        &storage_value_key(arion_pallet, "CurrentWeightBucket"),
        &at,
    )? {
        Some(bytes) => scale_u32(&bytes)?,
        None => 0,
    };

    // Active compute nodes, grouped by family.
    let prefix = storage_map_prefix(compute_pallet, "NodeIdToChild");
    let mut by_family: std::collections::BTreeMap<[u8; 32], Vec<ComputeNodeRead>> =
        std::collections::BTreeMap::new();
    for key in get_keys_paged(url, &prefix, Some(&at))? {
        if key.len() != prefix.len() + 16 + 32 {
            return Err(RegistryError::new(
                category::RPC_RESPONSE,
                format!("unexpected NodeIdToChild key length {}", key.len()),
            ));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&key[key.len() - 32..]);
        let Some(raw_child) = get_storage_at(url, &key, &at)? else {
            continue;
        };
        let child = decode_account_id(&raw_child)?;
        let Some(raw_reg) = get_storage_at(
            url,
            &storage_map_key(compute_pallet, "ChildRegistrations", &child),
            &at,
        )?
        else {
            continue;
        };
        let reg = decode_child_registration_head(&raw_reg)?;
        // The two indexes must agree, and only an Active compute node is
        // one the gate acts on.
        if reg.node_id != node_id || reg.status != ChildStatus::Active {
            continue;
        }
        by_family
            .entry(reg.family)
            .or_default()
            .push(ComputeNodeRead { node_id, child });
    }

    let mut families = Vec::with_capacity(by_family.len());
    for (family, mut compute) in by_family {
        compute.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let children = match get_storage_at(
            url,
            &storage_map_key(arion_pallet, "FamilyChildren", &family),
            &at,
        )? {
            Some(bytes) => decode_account_list(&bytes)?,
            None => Vec::new(),
        };
        let mut storage = Vec::with_capacity(children.len());
        for child in children {
            let registration = match get_storage_at(
                url,
                &storage_map_key(arion_pallet, "ChildRegistrations", &child),
                &at,
            )? {
                Some(bytes) => Some(decode_child_registration_head(&bytes)?),
                None => None,
            };
            let node_weight = match get_storage_at(
                url,
                &storage_map_key(arion_pallet, "NodeWeightByChild", &child),
                &at,
            )? {
                Some(bytes) => scale_u16(&bytes)?,
                None => 0,
            };
            let last_bucket = match get_storage_at(
                url,
                &storage_map_key(arion_pallet, "NodeWeightLastBucket", &child),
                &at,
            )? {
                Some(bytes) => scale_u32(&bytes)?,
                None => 0,
            };
            let quality = match get_storage_at(
                url,
                &storage_map_key(arion_pallet, "NodeQualityByChild", &child),
                &at,
            )? {
                Some(bytes) => Some(decode_node_quality(&bytes)?),
                None => None,
            };
            storage.push(StorageChildRead {
                child,
                registration,
                node_weight,
                last_bucket,
                quality,
            });
        }
        families.push(FamilyStorageRead {
            family,
            compute,
            storage,
        });
    }
    Ok(StorageFamiliesRead {
        block_hash: at,
        current_weight_bucket,
        stale_child_buckets,
        families,
    })
}

/// The runtime metadata must list each of `maps` as a `Blake2_128Concat`
/// map and each of `values` as a plain value of `pallet`, under the
/// storage prefix the keys are derived from.
fn require_maps(
    metadata_blob: &[u8],
    pallet: &str,
    maps: &[&str],
    values: &[&str],
) -> Result<(), RegistryError> {
    let absent = |what: String| RegistryError::new(category::PALLET_ABSENT, what);
    let storage = metadata::pallet_storage(metadata_blob, pallet)?
        .ok_or_else(|| absent(format!("pallet `{pallet}` has no storage in the runtime")))?;
    if storage.prefix != pallet {
        return Err(absent(format!(
            "pallet `{pallet}` stores under prefix `{}`",
            storage.prefix
        )));
    }
    for name in maps {
        let entry = storage.entries.iter().find(|e| e.name == *name);
        if entry.and_then(|e| e.map_hashers.as_deref()) != Some(&[metadata::BLAKE2_128_CONCAT]) {
            return Err(absent(format!(
                "`{pallet}.{name}` is not a Blake2_128Concat map in the runtime"
            )));
        }
    }
    for name in values {
        let entry = storage.entries.iter().find(|e| e.name == *name);
        if !matches!(entry, Some(e) if e.map_hashers.is_none()) {
            return Err(absent(format!(
                "`{pallet}.{name}` is not a plain value in the runtime"
            )));
        }
    }
    Ok(())
}

/// A `BoundedVec<AccountId32, _>`: `Compact(len) ++ len × 32 bytes`, and
/// nothing after it.
fn decode_account_list(bytes: &[u8]) -> Result<Vec<[u8; 32]>, RegistryError> {
    let mut input = bytes;
    let list = <Vec<[u8; 32]> as codec::Decode>::decode(&mut input)
        .map_err(|e| RegistryError::new(category::SCALE_DECODE, format!("account list: {e}")))?;
    if !input.is_empty() {
        return Err(RegistryError::new(
            category::SCALE_DECODE,
            format!("account list has {} trailing bytes", input.len()),
        ));
    }
    Ok(list)
}

/// A `NodeQuality`: exactly `16 + 16 + 2 + 4 + 4` bytes.
fn decode_node_quality(bytes: &[u8]) -> Result<NodeQualityRead, RegistryError> {
    if bytes.len() != 42 {
        return Err(RegistryError::new(
            category::SCALE_DECODE,
            format!("NodeQuality is {} bytes, want 42", bytes.len()),
        ));
    }
    let u128_at = |i: usize| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes[i..i + 16]);
        u128::from_le_bytes(b)
    };
    let u32_at = |i: usize| {
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[i..i + 4]);
        u32::from_le_bytes(b)
    };
    Ok(NodeQualityRead {
        shard_data_bytes: u128_at(0),
        bandwidth_bytes: u128_at(16),
        uptime_permille: u16::from_le_bytes([bytes[32], bytes[33]]),
        strikes: u32_at(34),
        integrity_fails: u32_at(38),
    })
}

/// Fetch the registry from a **vali feed** (the in-cluster
/// `GET /v1/edge/registry` endpoint) instead of directly from the
/// chain. The Edge uses this: its egress is locked to vali (it cannot
/// reach the external RPC), and vali — which has internet egress —
/// reads the chain via [`fetch_registry`] and re-serves the result.
///
/// The feed body is the same shape `read-miner-status` emits
/// (`{"current_epoch": N, "miners": [{node_id_hex, status,
/// last_transition_epoch, data_epoch, quality_dec}, …]}`), so the JSON
/// contract has one definition shared by producer and consumer. Plain
/// HTTP (the vali Service is in-cluster `http`); no TLS feature needed.
pub fn fetch_feed(feed_url: &str) -> Result<RegistrySnapshot, RegistryError> {
    fetch_feed_verified(feed_url, None)
}

/// HTTP header carrying the hex Ed25519 signature over the exact response
/// body bytes (audit M-registry-mTLS). MUST match vali's
/// `EdgeRegistryFeedView.SIG_HEADER`.
pub const FEED_SIG_HEADER: &str = "X-Hippius-Registry-Sig";

/// Fetch + parse the vali registry feed, verifying its Ed25519 signature
/// when `expected_pubkey` is `Some` (audit M-registry-mTLS).
///
/// The feed is PUBLIC data but is the Edge's admission allow-set, so an
/// in-cluster MITM of the plain-HTTP hop could inject a rogue node_id or
/// strip legit ones. With a pinned pubkey, the signature over the EXACT
/// response bytes is required + verified; a missing / malformed / wrong
/// signature is a fail-closed [`category::FEED_SIGNATURE`] error (the
/// caller keeps its last good set + flips unhealthy). `None` ⇒ the
/// pre-pin window: the feed is parsed unverified (backward-compatible so
/// vali can deploy the signer BEFORE the Edge pins its pubkey).
pub fn fetch_feed_verified(
    feed_url: &str,
    expected_pubkey: Option<[u8; 32]>,
) -> Result<RegistrySnapshot, RegistryError> {
    let url = feed_url.trim();
    if url.is_empty() {
        return Err(RegistryError::new(
            category::RPC_REQUEST,
            "feed URL is empty".to_string(),
        ));
    }
    let response = ureq::get(url)
        .timeout(RPC_CALL_TIMEOUT)
        .call()
        .map_err(|e| {
            RegistryError::new(
                category::RPC_REQUEST,
                format!("feed request failed ({:?})", e.kind()),
            )
        })?;
    // Read the signature header BEFORE consuming the body (`into_reader`).
    let sig_hex = response.header(FEED_SIG_HEADER).map(|s| s.to_string());
    let mut buf = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| {
            RegistryError::new(category::RPC_RESPONSE, format!("feed read failed: {e}"))
        })?;
    if let Some(pubkey) = expected_pubkey {
        verify_feed_signature(&buf, sig_hex.as_deref(), &pubkey)?;
    }
    parse_feed_body(&buf)
}

/// Verify the hex Ed25519 signature over `body` against `pubkey`.
/// Fail-closed on a missing / malformed / wrong signature.
fn verify_feed_signature(
    body: &[u8],
    sig_hex: Option<&str>,
    pubkey: &[u8; 32],
) -> Result<(), RegistryError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig_hex = sig_hex.ok_or_else(|| {
        RegistryError::new(
            category::FEED_SIGNATURE,
            "feed signature header absent but a verifying key is pinned".to_string(),
        )
    })?;
    let sig_bytes = decode_hex(sig_hex.trim())?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        RegistryError::new(
            category::FEED_SIGNATURE,
            format!("feed signature is {} bytes, want 64", sig_bytes.len()),
        )
    })?;
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|e| {
        RegistryError::new(category::FEED_SIGNATURE, format!("bad feed pubkey: {e}"))
    })?;
    vk.verify(body, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            RegistryError::new(
                category::FEED_SIGNATURE,
                "feed signature does not verify against the pinned key".to_string(),
            )
        })
}

/// Parse the vali feed JSON body into a [`RegistrySnapshot`]. Separated
/// from the HTTP fetch so it is unit-testable without a server.
fn parse_feed_body(body: &[u8]) -> Result<RegistrySnapshot, RegistryError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| RegistryError::new(category::RPC_RESPONSE, format!("feed non-JSON: {e}")))?;
    let current_epoch = v
        .get("current_epoch")
        .and_then(|e| e.as_u64())
        .ok_or_else(|| {
            RegistryError::new(
                category::RPC_RESPONSE,
                "feed missing current_epoch".to_string(),
            )
        })?;
    // OPTIONAL — an older vali serves a feed without this key. Absent ⇒
    // `true`, i.e. exactly the claim the feed made before the key
    // existed, so a new Edge against an old vali behaves as it does
    // today instead of fabricating an alarm out of a version skew. A
    // non-bool value is likewise ignored rather than treated as false.
    let pallet_live = v
        .get("pallet_live")
        .and_then(|p| p.as_bool())
        .unwrap_or(true);
    let miners_raw = v.get("miners").and_then(|m| m.as_array()).ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "feed 'miners' not an array".to_string(),
        )
    })?;
    let mut miners = Vec::with_capacity(miners_raw.len());
    for entry in miners_raw {
        let node_id_hex = entry
            .get("node_id_hex")
            .and_then(|n| n.as_str())
            .ok_or_else(|| {
                RegistryError::new(
                    category::RPC_RESPONSE,
                    "feed miner missing node_id_hex".into(),
                )
            })?;
        let bytes = decode_hex(node_id_hex)?;
        if bytes.len() != 32 {
            return Err(RegistryError::new(
                category::RPC_RESPONSE,
                format!("feed node_id_hex is {} bytes, want 32", bytes.len()),
            ));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&bytes);
        let status = match entry.get("status").and_then(|s| s.as_str()).unwrap_or("") {
            "active" => MinerStatus::Active,
            "quarantined" => MinerStatus::Quarantined,
            "decommissioned" => MinerStatus::Decommissioned,
            other => {
                return Err(RegistryError::new(
                    category::SCALE_DECODE,
                    format!("feed unknown status {other:?}"),
                ))
            }
        };
        let last_transition_epoch = entry
            .get("last_transition_epoch")
            .and_then(|e| e.as_u64())
            .unwrap_or(0);
        let data_epoch = entry
            .get("data_epoch")
            .and_then(|e| e.as_u64())
            .unwrap_or(0);
        // quality is a decimal STRING (u128 out of JSON-number range).
        let quality = entry
            .get("quality_dec")
            .and_then(|q| q.as_str())
            .unwrap_or("0")
            .parse::<u128>()
            .map_err(|e| {
                RegistryError::new(category::SCALE_DECODE, format!("feed quality_dec: {e}"))
            })?;
        // price is an OPTIONAL decimal STRING — absent/null ⇒ no price set.
        let price = match entry.get("price_dec").and_then(|p| p.as_str()) {
            Some(s) => Some(s.parse::<u128>().map_err(|e| {
                RegistryError::new(category::SCALE_DECODE, format!("feed price_dec: {e}"))
            })?),
            None => None,
        };
        miners.push(MinerRecord {
            node_id,
            status,
            last_transition_epoch,
            data_epoch,
            quality,
            price,
        });
    }
    miners.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Ok(RegistrySnapshot {
        current_epoch,
        miners,
        pallet_live,
    })
}

// ─── Substrate storage-key derivation ────────────────────────────────

/// `twox_128` — Substrate's storage-prefix hash: two seeded
/// xxHash-64 digests, each written little-endian, concatenated.
fn twox_128(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut h0 = XxHash64::with_seed(0);
    h0.write(data);
    out[0..8].copy_from_slice(&h0.finish().to_le_bytes());
    let mut h1 = XxHash64::with_seed(1);
    h1.write(data);
    out[8..16].copy_from_slice(&h1.finish().to_le_bytes());
    out
}

/// `blake2_128` — BLAKE2b with the parameter-block output length set
/// to 16 bytes (NOT a truncated 64-byte digest), exactly as
/// Substrate's `blake2_128`.
fn blake2_128(data: &[u8]) -> [u8; 16] {
    let digest = Blake2b::<U16>::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Storage key for a `StorageValue`: `twox_128(pallet) ++
/// twox_128(item)`.
fn storage_value_key(pallet: &str, item: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&twox_128(pallet.as_bytes()));
    key.extend_from_slice(&twox_128(item.as_bytes()));
    key
}

/// Storage prefix shared by every entry of a `StorageMap` /
/// `StorageDoubleMap` — same shape as a `StorageValue` key.
fn storage_map_prefix(pallet: &str, item: &str) -> Vec<u8> {
    storage_value_key(pallet, item)
}

/// Full storage key for a `StorageMap` entry hashed
/// `Blake2_128Concat`: `prefix ++ blake2_128(k) ++ k`.
fn storage_map_key(pallet: &str, item: &str, k: &[u8]) -> Vec<u8> {
    let mut key = storage_map_prefix(pallet, item);
    key.extend_from_slice(&blake2_128(k));
    key.extend_from_slice(k);
    key
}

/// Full storage key for a `StorageDoubleMap` entry, both keys hashed
/// `Blake2_128Concat`: `prefix ++ blake2_128(k1) ++ k1 ++
/// blake2_128(k2) ++ k2`.
fn storage_double_map_key(pallet: &str, item: &str, k1: &[u8], k2: &[u8]) -> Vec<u8> {
    let mut key = storage_map_prefix(pallet, item);
    key.extend_from_slice(&blake2_128(k1));
    key.extend_from_slice(k1);
    key.extend_from_slice(&blake2_128(k2));
    key.extend_from_slice(k2);
    key
}

// ─── SCALE decoding ──────────────────────────────────────────────────

/// Decode a `MinerStatusEntry<BlockNumber>` — SCALE layout
/// `{ status: MinerStatus (1-byte enum), last_transition_block:
/// BlockNumber, last_transition_epoch: u64 }`. Returns
/// `(status_discriminant, last_transition_epoch)`.
///
/// `status` is the FIRST field (head byte) and `last_transition_epoch`
/// is the LAST field (trailing 8 bytes), so both are extracted without
/// depending on whether `BlockNumberFor<T>` is `u32` or `u64` — a
/// wrong width assumption cannot shift the epoch offset.
fn decode_miner_status_entry(bytes: &[u8]) -> Result<(u8, u64), RegistryError> {
    // status(1) + smallest BlockNumber (u32 = 4) + epoch(u64 = 8).
    const MIN_LEN: usize = 1 + 4 + 8;
    if bytes.len() < MIN_LEN {
        return Err(RegistryError::new(
            category::SCALE_DECODE,
            format!("MinerStatusEntry too short: {} bytes", bytes.len()),
        ));
    }
    let status = bytes[0];
    let last_transition_epoch = scale_u64(&bytes[bytes.len() - 8..])?;
    Ok((status, last_transition_epoch))
}

/// Decode a `PriceChange<BlockNumber>` — SCALE layout `{ new_price:
/// u128, effective_block: BlockNumber }`. `new_price` is the leading 16
/// bytes; `effective_block` is decoded from the remainder as `u32` (the
/// runtime's `BlockNumberFor<T>`) and widened to `u64`. Returns
/// `(new_price, effective_block)`.
fn decode_price_change(bytes: &[u8]) -> Result<(u128, u64), RegistryError> {
    // u128(16) + smallest BlockNumber (u32 = 4).
    const MIN_LEN: usize = 16 + 4;
    if bytes.len() < MIN_LEN {
        return Err(RegistryError::new(
            category::SCALE_DECODE,
            format!("PriceChange too short: {} bytes", bytes.len()),
        ));
    }
    let new_price = scale_u128(&bytes[..16])?;
    let effective_block = u32::decode(&mut &bytes[16..])
        .map_err(|e| RegistryError::new(category::SCALE_DECODE, format!("u32: {e}")))?;
    Ok((new_price, u64::from(effective_block)))
}

fn scale_u64(bytes: &[u8]) -> Result<u64, RegistryError> {
    u64::decode(&mut &bytes[..])
        .map_err(|e| RegistryError::new(category::SCALE_DECODE, format!("u64: {e}")))
}

fn scale_u128(bytes: &[u8]) -> Result<u128, RegistryError> {
    u128::decode(&mut &bytes[..])
        .map_err(|e| RegistryError::new(category::SCALE_DECODE, format!("u128: {e}")))
}

/// A `u32` value: exactly 4 bytes (an encoded value never carries more).
fn scale_u32(bytes: &[u8]) -> Result<u32, RegistryError> {
    <[u8; 4]>::try_from(bytes)
        .map(u32::from_le_bytes)
        .map_err(|_| {
            RegistryError::new(
                category::SCALE_DECODE,
                format!("u32 is {} bytes", bytes.len()),
            )
        })
}

/// A `u16` value: exactly 2 bytes.
fn scale_u16(bytes: &[u8]) -> Result<u16, RegistryError> {
    <[u8; 2]>::try_from(bytes)
        .map(u16::from_le_bytes)
        .map_err(|_| {
            RegistryError::new(
                category::SCALE_DECODE,
                format!("u16 is {} bytes", bytes.len()),
            )
        })
}

// ─── JSON-RPC client ─────────────────────────────────────────────────

/// `0x`-prefixed hex → bytes. A bare (un-prefixed) string is also
/// accepted defensively.
fn decode_hex(s: &str) -> Result<Vec<u8>, RegistryError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|e| {
        RegistryError::new(
            category::RPC_RESPONSE,
            format!("invalid hex in response: {e}"),
        )
    })
}

/// One JSON-RPC 2.0 call. Returns the `result` member, or a
/// structured failure on transport / protocol error.
fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, RegistryError> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = ureq::post(url)
        .timeout(RPC_CALL_TIMEOUT)
        .set("Content-Type", "application/json")
        .send_json(request)
        // Surface only the error KIND, never the `Display` form: a
        // `ureq` transport error embeds the request URL, and the RPC
        // URL may carry a credential. The kind (a bare enum variant)
        // is diagnostic without leaking the URL (§20).
        .map_err(|e| {
            RegistryError::new(
                category::RPC_REQUEST,
                format!("{method}: RPC request failed ({:?})", e.kind()),
            )
        })?;

    // Bound the body before parsing so a hostile node can't OOM us.
    let mut buf = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| {
            RegistryError::new(
                category::RPC_RESPONSE,
                format!("{method}: response read failed: {e}"),
            )
        })?;
    let body: serde_json::Value = serde_json::from_slice(&buf).map_err(|e| {
        RegistryError::new(
            category::RPC_RESPONSE,
            format!("{method}: non-JSON response: {e}"),
        )
    })?;
    if let Some(err) = body.get("error") {
        return Err(RegistryError::new(
            category::RPC_RESPONSE,
            format!("{method}: node returned error: {err}"),
        ));
    }
    body.get("result").cloned().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            format!("{method}: response missing 'result'"),
        )
    })
}

/// `chain_getHeader()` → the head block number. The header's `number`
/// member is a hex-encoded (`0x…`) integer; parse it to `u64`. Used to
/// size the price-change notice window (blocks, not epochs).
fn get_block_number(url: &str) -> Result<u64, RegistryError> {
    let result = rpc_call(url, "chain_getHeader", serde_json::json!([]))?;
    let number = result
        .get("number")
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            RegistryError::new(
                category::RPC_RESPONSE,
                "chain_getHeader result missing 'number'".to_string(),
            )
        })?;
    let trimmed = number.strip_prefix("0x").unwrap_or(number);
    u64::from_str_radix(trimmed, 16).map_err(|e| {
        RegistryError::new(
            category::RPC_RESPONSE,
            format!("chain_getHeader 'number' not hex: {e}"),
        )
    })
}

/// `state_getStorage(key)` — `None` if the key is absent.
fn get_storage(url: &str, key: &[u8]) -> Result<Option<Vec<u8>>, RegistryError> {
    let key_hex = format!("0x{}", hex::encode(key));
    let result = rpc_call(url, "state_getStorage", serde_json::json!([key_hex]))?;
    if result.is_null() {
        return Ok(None);
    }
    let hex_str = result.as_str().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "state_getStorage result is not a string".to_string(),
        )
    })?;
    Ok(Some(decode_hex(hex_str)?))
}

/// `chain_getFinalizedHead()` → the finalized block hash (`0x` + 64 hex).
fn get_finalized_head(url: &str) -> Result<String, RegistryError> {
    let result = rpc_call(url, "chain_getFinalizedHead", serde_json::json!([]))?;
    let hash = result.as_str().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "chain_getFinalizedHead result is not a string".to_string(),
        )
    })?;
    if decode_hex(hash)?.len() != 32 || !hash.starts_with("0x") {
        return Err(RegistryError::new(
            category::RPC_RESPONSE,
            "chain_getFinalizedHead result is not a 32-byte hash".to_string(),
        ));
    }
    Ok(hash.to_ascii_lowercase())
}

/// `state_getMetadata(at)` — the runtime metadata blob at block `at`.
fn get_metadata_at(url: &str, at: &str) -> Result<Vec<u8>, RegistryError> {
    let result = rpc_call(url, "state_getMetadata", serde_json::json!([at]))?;
    let hex_str = result.as_str().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "state_getMetadata result is not a string".to_string(),
        )
    })?;
    decode_hex(hex_str)
}

/// `state_getStorage(key, at)` — `None` if the key is absent at `at`.
fn get_storage_at(url: &str, key: &[u8], at: &str) -> Result<Option<Vec<u8>>, RegistryError> {
    let key_hex = format!("0x{}", hex::encode(key));
    let result = rpc_call(url, "state_getStorage", serde_json::json!([key_hex, at]))?;
    if result.is_null() {
        return Ok(None);
    }
    let hex_str = result.as_str().ok_or_else(|| {
        RegistryError::new(
            category::RPC_RESPONSE,
            "state_getStorage result is not a string".to_string(),
        )
    })?;
    Ok(Some(decode_hex(hex_str)?))
}

/// `state_getKeysPaged(prefix, …[, at])` — every storage key under
/// `prefix`, fetched page by page, at block `at` when given (else the
/// best block).
fn get_keys_paged(
    url: &str,
    prefix: &[u8],
    at: Option<&str>,
) -> Result<Vec<Vec<u8>>, RegistryError> {
    let prefix_hex = format!("0x{}", hex::encode(prefix));
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut start_key: Option<String> = None;

    loop {
        let params = match at {
            Some(at) => serde_json::json!([prefix_hex, KEYS_PAGE_SIZE, start_key, at]),
            None => serde_json::json!([prefix_hex, KEYS_PAGE_SIZE, start_key]),
        };
        let result = rpc_call(url, "state_getKeysPaged", params)?;
        let page = result.as_array().ok_or_else(|| {
            RegistryError::new(
                category::RPC_RESPONSE,
                "state_getKeysPaged result is not an array".to_string(),
            )
        })?;
        if page.is_empty() {
            break;
        }
        let mut last_hex: Option<String> = None;
        for entry in page {
            let key_hex = entry.as_str().ok_or_else(|| {
                RegistryError::new(
                    category::RPC_RESPONSE,
                    "state_getKeysPaged entry is not a string".to_string(),
                )
            })?;
            out.push(decode_hex(key_hex)?);
            last_hex = Some(key_hex.to_string());
        }
        // Short page ⇒ end of the map.
        if page.len() < KEYS_PAGE_SIZE as usize {
            break;
        }
        start_key = last_hex;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use codec::Encode;

    // ── Storage-key derivation conformance (the frozen contract the
    //    reader + the pallet must byte-match) ──────────────────────────

    #[test]
    fn twox_128_matches_known_system_prefix() {
        // `twox_128("System")` is a fixed, widely published vector —
        // anchors the (seed-0 ++ seed-1, LE) construction.
        assert_eq!(
            hex::encode(twox_128(b"System")),
            "26aa394eea5630e07c48ae0c9558cef7",
        );
    }

    #[test]
    fn blake2_128_is_16_bytes_and_deterministic() {
        let a = blake2_128(b"hippius-compute-node");
        let b = blake2_128(b"hippius-compute-node");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert_ne!(blake2_128(b"a"), blake2_128(b"b"));
    }

    #[test]
    fn storage_value_key_is_32_bytes() {
        let key = storage_value_key("ComputeScoring", "CurrentEpoch");
        assert_eq!(key.len(), 32);
        assert_eq!(&key[0..16], &twox_128(b"ComputeScoring"));
        assert_eq!(&key[16..32], &twox_128(b"CurrentEpoch"));
    }

    #[test]
    fn double_map_key_layout_places_node_id_in_the_trailing_32_bytes() {
        let epoch: u64 = 42;
        let node_id = [7u8; 32];
        let key = storage_double_map_key(
            "ComputeScoring",
            "EpochWeights",
            &epoch.to_le_bytes(),
            &node_id,
        );
        assert_eq!(key.len(), 32 + 16 + 8 + 16 + 32);
        assert_eq!(&key[key.len() - 32..], &node_id);
    }

    #[test]
    fn storage_map_key_node_id_is_trailing_32_bytes() {
        let node_id = [9u8; 32];
        let key = storage_map_key("ComputeScoring", "NodeIdToChild", &node_id);
        assert_eq!(key.len(), 32 + 16 + 32);
        assert_eq!(&key[key.len() - 32..], &node_id);
    }

    // ── SCALE decode ─────────────────────────────────────────────────

    #[test]
    fn decode_miner_status_entry_roundtrips_with_u32_block() {
        let mut bytes = vec![1u8]; // Quarantined
        bytes.extend_from_slice(&123u32.to_le_bytes());
        bytes.extend_from_slice(&777u64.to_le_bytes());
        let (status, epoch) = decode_miner_status_entry(&bytes).unwrap();
        assert_eq!(status, 1);
        assert_eq!(epoch, 777);
    }

    #[test]
    fn decode_miner_status_entry_is_robust_to_a_u64_block_number() {
        let mut bytes = vec![2u8]; // Decommissioned
        bytes.extend_from_slice(&123u64.to_le_bytes());
        bytes.extend_from_slice(&999u64.to_le_bytes());
        let (status, epoch) = decode_miner_status_entry(&bytes).unwrap();
        assert_eq!(status, 2);
        assert_eq!(epoch, 999);
    }

    #[test]
    fn decode_miner_status_entry_rejects_truncated_input() {
        let err = decode_miner_status_entry(&[0u8; 12]).unwrap_err();
        assert_eq!(err.category, category::SCALE_DECODE);
    }

    #[test]
    fn decode_price_change_roundtrips_with_u32_block() {
        // SCALE `PriceChange { new_price: u128, effective_block: u32 }` —
        // the pallet's field order (new_price first) is load-bearing.
        let mut bytes = 1_500_000u128.to_le_bytes().to_vec();
        bytes.extend_from_slice(&5_657_344u32.to_le_bytes());
        let (new_price, effective_block) = decode_price_change(&bytes).unwrap();
        assert_eq!(new_price, 1_500_000);
        assert_eq!(effective_block, 5_657_344);
    }

    #[test]
    fn decode_price_change_reads_only_the_low_word_of_a_u64_block() {
        // If a runtime widened BlockNumber to u64, the trailing high word
        // is ignored — block numbers fit u32, so the low word is correct.
        let mut bytes = 42u128.to_le_bytes().to_vec();
        bytes.extend_from_slice(&7u64.to_le_bytes());
        let (new_price, effective_block) = decode_price_change(&bytes).unwrap();
        assert_eq!(new_price, 42);
        assert_eq!(effective_block, 7);
    }

    #[test]
    fn decode_price_change_rejects_truncated_input() {
        let err = decode_price_change(&[0u8; 16]).unwrap_err();
        assert_eq!(err.category, category::SCALE_DECODE);
    }

    #[test]
    fn miner_status_from_discriminant_covers_every_variant_and_fails_closed() {
        assert_eq!(
            MinerStatus::from_discriminant(0).unwrap(),
            MinerStatus::Active
        );
        assert_eq!(
            MinerStatus::from_discriminant(1).unwrap(),
            MinerStatus::Quarantined
        );
        assert_eq!(
            MinerStatus::from_discriminant(2).unwrap(),
            MinerStatus::Decommissioned
        );
        assert_eq!(
            MinerStatus::from_discriminant(9).unwrap_err().category,
            category::SCALE_DECODE,
        );
    }

    #[test]
    fn miner_status_labels_match_the_json_contract() {
        assert_eq!(MinerStatus::Active.label(), "active");
        assert_eq!(MinerStatus::Quarantined.label(), "quarantined");
        assert_eq!(MinerStatus::Decommissioned.label(), "decommissioned");
    }

    #[test]
    fn scale_int_decoders_roundtrip() {
        assert_eq!(scale_u64(&999u64.to_le_bytes()).unwrap(), 999);
        let big: u128 = 340_282_366_920_938_463_463_374_607_431_768_211_455;
        assert_eq!(scale_u128(&big.to_le_bytes()).unwrap(), big);
        assert_eq!(scale_u64(&[]).unwrap_err().category, category::SCALE_DECODE);
    }

    #[test]
    fn decode_hex_strips_0x_prefix() {
        assert_eq!(
            decode_hex("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("0xnothex").unwrap_err().category,
            category::RPC_RESPONSE,
        );
    }

    // ── active_node_ids admission gate ───────────────────────────────

    #[test]
    fn parse_feed_body_round_trips_the_vali_shape() {
        // The exact shape vali's /v1/edge/registry serves (== the
        // read-miner-status ok payload, minus the tag).
        let body = br#"{
            "current_epoch": 4,
            "miners": [
              {"node_id_hex":"aa11220000000000000000000000000000000000000000000000000000000000",
               "status":"active","last_transition_epoch":0,"data_epoch":4,"quality_dec":"7"},
              {"node_id_hex":"bb33440000000000000000000000000000000000000000000000000000000000",
               "status":"quarantined","last_transition_epoch":3,"data_epoch":3,"quality_dec":"0"}
            ]
        }"#;
        let snap = parse_feed_body(body).unwrap();
        assert_eq!(snap.current_epoch, 4);
        assert_eq!(snap.miners.len(), 2);
        let active = snap.active_node_ids();
        assert_eq!(active.len(), 1);
        let mut want = [0u8; 32];
        want[0] = 0xaa;
        want[1] = 0x11;
        want[2] = 0x22;
        assert!(active.contains(&want));
    }

    #[test]
    fn parse_feed_body_rejects_bad_node_id_and_status() {
        assert_eq!(
            parse_feed_body(
                br#"{"current_epoch":1,"miners":[{"node_id_hex":"zz","status":"active"}]}"#
            )
            .unwrap_err()
            .category,
            category::RPC_RESPONSE
        );
        assert_eq!(
            parse_feed_body(br#"{"current_epoch":1,"miners":[{"node_id_hex":"aa11220000000000000000000000000000000000000000000000000000000000","status":"bogus"}]}"#)
                .unwrap_err()
                .category,
            category::SCALE_DECODE
        );
    }

    #[test]
    fn active_node_ids_includes_only_active_miners() {
        let snap = RegistrySnapshot {
            current_epoch: 5,
            pallet_live: true,
            miners: vec![
                MinerRecord {
                    node_id: [1u8; 32],
                    status: MinerStatus::Active,
                    last_transition_epoch: 0,
                    data_epoch: 5,
                    quality: 10,
                    price: None,
                },
                MinerRecord {
                    node_id: [2u8; 32],
                    status: MinerStatus::Quarantined,
                    last_transition_epoch: 4,
                    data_epoch: 4,
                    quality: 0,
                    price: None,
                },
                MinerRecord {
                    node_id: [3u8; 32],
                    status: MinerStatus::Decommissioned,
                    last_transition_epoch: 3,
                    data_epoch: 3,
                    quality: 0,
                    price: None,
                },
            ],
        };
        let active = snap.active_node_ids();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&[1u8; 32]));
        assert!(!active.contains(&[2u8; 32]));
        assert!(!active.contains(&[3u8; 32]));
    }

    // ── Removed-pallet (orphaned storage prefix) detection ───────────
    //
    // The failure this defends against: a runtime upgrade drops a pallet
    // but NOT its storage, so every twox-128-derived read keeps returning
    // the pallet's last-written bytes forever. The metadata is the only
    // place the removal is visible.

    /// Synthesize a metadata blob: `"meta" ++ version ++ body`.
    fn fake_metadata(version: u8, body: &[u8]) -> Vec<u8> {
        let mut out = b"meta".to_vec();
        out.push(version);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn metadata_probe_finds_a_scale_prefixed_pallet_name() {
        // A live pallet: its name appears SCALE-`String`-encoded.
        let mut body = vec![0x00, 0xff, 0x42];
        body.extend_from_slice(&scale_string_bytes("Registration").unwrap());
        body.extend_from_slice(b"\x00\x00trailing");
        let metadata = fake_metadata(14, &body);
        assert!(metadata_contains_pallet(&metadata, "Registration").unwrap());
    }

    #[test]
    fn metadata_probe_reports_a_removed_pallet_as_absent() {
        // The runtime kept `Registration` and dropped `ComputeScoring` —
        // whose storage prefix nonetheless still answers reads.
        let mut body = Vec::new();
        body.extend_from_slice(&scale_string_bytes("Registration").unwrap());
        body.extend_from_slice(&scale_string_bytes("RankingCompute").unwrap());
        let metadata = fake_metadata(14, &body);
        assert!(metadata_contains_pallet(&metadata, "Registration").unwrap());
        assert!(!metadata_contains_pallet(&metadata, "ComputeScoring").unwrap());
    }

    #[test]
    fn metadata_probe_ignores_a_bare_unprefixed_name_occurrence() {
        // THE point of the length prefix. The ASCII "ComputeScoring" is
        // present — as a doc string, a type path, or a substring of a
        // longer name — but never as a SCALE `String` of that exact
        // length. Matching on ASCII alone would call a removed pallet
        // live, i.e. reinstate the silent fail-open this change fixes.
        let mut body = b"ComputeScoring".to_vec(); // bare, no prefix
        body.extend_from_slice(b"pallet_compute_scoring::pallet::Call");
        // …and as a strict substring of a LONGER SCALE-encoded name,
        // whose prefix byte encodes 21, not 14.
        body.extend_from_slice(&scale_string_bytes("ComputeScoringLegacy").unwrap());
        let metadata = fake_metadata(14, &body);
        assert!(!metadata_contains_pallet(&metadata, "ComputeScoring").unwrap());
    }

    #[test]
    fn metadata_probe_rejects_a_bad_magic() {
        let mut blob = b"NOTM".to_vec();
        blob.push(14);
        blob.extend_from_slice(&scale_string_bytes("ComputeScoring").unwrap());
        let err = metadata_contains_pallet(&blob, "ComputeScoring").unwrap_err();
        assert_eq!(err.category, category::METADATA_SHAPE);
        // Too short to even hold magic + version — same category.
        assert_eq!(
            metadata_contains_pallet(b"met", "ComputeScoring")
                .unwrap_err()
                .category,
            category::METADATA_SHAPE,
        );
    }

    #[test]
    fn metadata_probe_rejects_an_unsupported_version() {
        // v13 and v16 are layouts we have not read — refuse to make a
        // claim rather than guess (a wrong guess = a false "removed").
        for version in [13u8, 16u8, 0u8] {
            let metadata = fake_metadata(version, &scale_string_bytes("Registration").unwrap());
            let err = metadata_contains_pallet(&metadata, "Registration").unwrap_err();
            assert_eq!(err.category, category::METADATA_SHAPE);
        }
        // …and both supported versions are accepted.
        for version in [14u8, 15u8] {
            let metadata = fake_metadata(version, &scale_string_bytes("Registration").unwrap());
            assert!(metadata_contains_pallet(&metadata, "Registration").unwrap());
        }
    }

    #[test]
    fn compact_len_prefix_matches_hand_computed_vectors() {
        // Single-byte mode: `len << 2`, mode tag 0b00.
        assert_eq!(compact_len_prefix(1).unwrap(), vec![0x04]);
        assert_eq!(compact_len_prefix(14).unwrap(), vec![0x38]); // "ComputeScoring"
        assert_eq!(compact_len_prefix(63).unwrap(), vec![0xfc]);
        // Two-byte mode at the boundary: len 64 ⇒ (64<<2)|1 = 0x0101, LE.
        assert_eq!(compact_len_prefix(64).unwrap(), vec![0x01, 0x01]);
        // len 65 ⇒ (65<<2)|1 = 261 = 0x0105, LE ⇒ [0x05, 0x01].
        assert_eq!(compact_len_prefix(65).unwrap(), vec![0x05, 0x01]);
        // len 16383 (2^14-1) ⇒ (16383<<2)|1 = 65533 = 0xfffd, LE.
        assert_eq!(compact_len_prefix(16383).unwrap(), vec![0xfd, 0xff]);
        // Beyond the two-byte mode: refuse, never mis-encode.
        assert_eq!(
            compact_len_prefix(16384).unwrap_err().category,
            category::METADATA_SHAPE,
        );
        // Empty name: `0x00` would match everywhere — refuse.
        assert_eq!(
            compact_len_prefix(0).unwrap_err().category,
            category::METADATA_SHAPE,
        );
    }

    #[test]
    fn a_64_char_name_is_found_via_the_two_byte_prefix() {
        // End-to-end proof the two-byte branch is wired into the search,
        // not just unit-tested in isolation.
        let name = "A".repeat(64);
        let encoded = scale_string_bytes(&name).unwrap();
        assert_eq!(&encoded[..2], &[0x01, 0x01]);
        let metadata = fake_metadata(14, &encoded);
        assert!(metadata_contains_pallet(&metadata, &name).unwrap());
        // A 65-char name (different prefix) must NOT match the 64-char
        // encoding — the prefix discriminates length, not just content.
        assert!(!metadata_contains_pallet(&metadata, &"A".repeat(65)).unwrap());
    }

    /// A one-shot-per-connection JSON-RPC stub on 127.0.0.1 (loopback
    /// only — no external network). Answers `state_getMetadata` with
    /// `metadata`, every storage read with `null` and every paged-keys
    /// read with `[]`, so `fetch_registry` completes with zero miners
    /// and the ONLY interesting output is `pallet_live`.
    ///
    /// This exists because the probe's WIRING — does `fetch_registry`
    /// actually store what the probe returned? — is invisible to the
    /// pure-function tests above; a mutant that computed the flag and
    /// then dropped it on the floor survived them all.
    fn spawn_rpc_stub(metadata: Vec<u8>) -> String {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let metadata_hex = format!("\"0x{}\"", hex::encode(metadata));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                // Headers → Content-Length → body.
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = std::io::Read::read_exact(&mut reader, &mut body);
                let body = String::from_utf8_lossy(&body);

                let result = if body.contains("state_getMetadata") {
                    metadata_hex.clone()
                } else if body.contains("state_getKeysPaged") {
                    "[]".to_string()
                } else {
                    "null".to_string()
                };
                let payload = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{result}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn fetch_registry_reports_a_removed_pallet_without_failing_the_read() {
        // THE defect, end to end. The metadata does NOT contain the
        // pallet, yet every storage read still answers — exactly what a
        // runtime upgrade that dropped the pallet leaves behind.
        let metadata = fake_metadata(14, &scale_string_bytes("Registration").unwrap());
        let url = spawn_rpc_stub(metadata);

        let snapshot = fetch_registry(&url, "ComputeScoring").unwrap();
        // It does NOT fail closed — production placement is running off
        // this read; turning it into an Err here would be an outage.
        assert!(!snapshot.pallet_live);
        assert_eq!(snapshot.miners.len(), 0);
    }

    #[test]
    fn fetch_registry_reports_a_live_pallet_as_live() {
        let metadata = fake_metadata(14, &scale_string_bytes("ComputeScoring").unwrap());
        let url = spawn_rpc_stub(metadata);
        assert!(fetch_registry(&url, "ComputeScoring").unwrap().pallet_live);
    }

    #[test]
    fn fetch_registry_assumes_live_when_the_metadata_is_unreadable() {
        // A garbage metadata blob ⇒ the probe errors ⇒ "cannot
        // determine" ⇒ `true`, and the registry read still succeeds. An
        // RPC/metadata problem must never masquerade as a dead pallet.
        let url = spawn_rpc_stub(b"not-metadata-at-all".to_vec());
        assert!(fetch_registry(&url, "ComputeScoring").unwrap().pallet_live);
    }

    #[test]
    fn a_failed_probe_does_not_raise_the_alarm() {
        // "Cannot determine" ⇒ `true`. An RPC blip or an unknown metadata
        // version must NOT be reported as a removed pallet: a false alarm
        // here is (with vali's gate armed) a placement outage, and it
        // trains operators to ignore the flag.
        assert!(probe_to_flag(Err(RegistryError::new(
            category::RPC_REQUEST,
            "node unreachable".to_string(),
        ))));
        assert!(probe_to_flag(Err(RegistryError::new(
            category::METADATA_SHAPE,
            "unsupported metadata version 16".to_string(),
        ))));
        // …and a SUCCESSFUL probe is passed through unchanged, both ways.
        assert!(probe_to_flag(Ok(true)));
        assert!(!probe_to_flag(Ok(false)));
    }

    #[test]
    fn parse_feed_body_defaults_pallet_live_true_when_the_key_is_absent() {
        // Version skew: an OLD vali serves a feed with no `pallet_live`.
        // A new Edge must read it exactly as it does today — never
        // fabricate an alarm out of a missing key.
        let snap = parse_feed_body(br#"{"current_epoch":4,"miners":[]}"#).unwrap();
        assert!(snap.pallet_live);
        // …and an explicit `false` is carried through.
        let dead =
            parse_feed_body(br#"{"current_epoch":4,"miners":[],"pallet_live":false}"#).unwrap();
        assert!(!dead.pallet_live);
        let live =
            parse_feed_body(br#"{"current_epoch":4,"miners":[],"pallet_live":true}"#).unwrap();
        assert!(live.pallet_live);
        // A non-bool value is ignored (⇒ true), not read as false.
        let junk =
            parse_feed_body(br#"{"current_epoch":4,"miners":[],"pallet_live":"no"}"#).unwrap();
        assert!(junk.pallet_live);
    }

    // ── Feed signature verification (audit M-registry-mTLS) ──────────

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn verify_feed_signature_accepts_a_valid_signature() {
        use ed25519_dalek::Signer;
        let sk = signing_key();
        let pk = sk.verifying_key().to_bytes();
        let body = br#"{"current_epoch":1,"miners":[]}"#;
        let sig = hex::encode(sk.sign(body).to_bytes());
        verify_feed_signature(body, Some(&sig), &pk).unwrap();
    }

    #[test]
    fn verify_feed_signature_rejects_a_missing_header() {
        let pk = signing_key().verifying_key().to_bytes();
        let err = verify_feed_signature(b"body", None, &pk).unwrap_err();
        assert_eq!(err.category, category::FEED_SIGNATURE);
    }

    #[test]
    fn verify_feed_signature_rejects_a_tampered_body() {
        use ed25519_dalek::Signer;
        let sk = signing_key();
        let pk = sk.verifying_key().to_bytes();
        let sig = hex::encode(sk.sign(b"original body").to_bytes());
        // Same signature, DIFFERENT body → reject (MITM tamper).
        let err = verify_feed_signature(b"tampered body", Some(&sig), &pk).unwrap_err();
        assert_eq!(err.category, category::FEED_SIGNATURE);
    }

    #[test]
    fn verify_feed_signature_rejects_a_wrong_key() {
        use ed25519_dalek::Signer;
        let sk = signing_key();
        let other_pk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let body = b"body";
        let sig = hex::encode(sk.sign(body).to_bytes());
        let err = verify_feed_signature(body, Some(&sig), &other_pk).unwrap_err();
        assert_eq!(err.category, category::FEED_SIGNATURE);
    }

    #[test]
    fn verify_feed_signature_rejects_malformed_hex_and_length() {
        let pk = signing_key().verifying_key().to_bytes();
        assert_eq!(
            verify_feed_signature(b"b", Some("zz"), &pk)
                .unwrap_err()
                .category,
            category::RPC_RESPONSE, // decode_hex failure category
        );
        assert_eq!(
            verify_feed_signature(b"b", Some("aabb"), &pk)
                .unwrap_err()
                .category,
            category::FEED_SIGNATURE, // 2 bytes, want 64
        );
    }

    // ── node → family ────────────────────────────────────────────────

    #[test]
    fn blake2_128_concat_matches_the_published_system_account_key() {
        // `System.Account[Alice]`, the key every Substrate tutorial prints.
        let alice = hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
            .unwrap();
        assert_eq!(
            hex::encode(storage_map_key("System", "Account", &alice)),
            "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9\
             de1e86a9a8c739864cf3cc5ec2bea59f\
             d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
    }

    #[test]
    fn node_family_keys_are_blake2_128_concat_maps_of_the_pallet() {
        let node_id = [0x11u8; 32];
        let key = node_id_to_child_key("ComputeScoring", &node_id);
        assert_eq!(&key[0..16], &twox_128(b"ComputeScoring"));
        assert_eq!(&key[16..32], &twox_128(b"NodeIdToChild"));
        assert_eq!(&key[32..48], &blake2_128(&node_id));
        assert_eq!(&key[48..], &node_id);

        let child = [0x22u8; 32];
        let key = child_registration_key("ComputeScoring", &child);
        assert_eq!(&key[16..32], &twox_128(b"ChildRegistrations"));
        assert_eq!(&key[32..48], &blake2_128(&child));
        assert_eq!(&key[48..], &child);
    }

    fn registration_bytes(status: u8, block_width: usize) -> Vec<u8> {
        let mut bytes = vec![0xaau8; 32]; // family
        bytes.extend_from_slice(&[0xbbu8; 32]); // node_id
        bytes.push(status);
        bytes.extend_from_slice(&5_000_000_000_000u128.to_le_bytes()); // deposit
        bytes.extend_from_slice(&vec![0x07u8; block_width]); // unbonding_end
        bytes
    }

    #[test]
    fn decode_child_registration_reads_family_node_and_status() {
        let reg = decode_child_registration_head(&registration_bytes(0, 4)).unwrap();
        assert_eq!(reg.family, [0xaau8; 32]);
        assert_eq!(reg.node_id, [0xbbu8; 32]);
        assert_eq!(reg.status, ChildStatus::Active);
        let reg = decode_child_registration_head(&registration_bytes(1, 8)).unwrap();
        assert_eq!(reg.status, ChildStatus::Unbonding);
        assert_eq!(reg.status.label(), "unbonding");
    }

    #[test]
    fn decode_child_registration_fails_closed_on_unknown_layouts() {
        for bad in [
            registration_bytes(2, 4),  // unknown status
            registration_bytes(0, 2),  // too short
            registration_bytes(0, 16), // too long
            vec![0u8; 64],
        ] {
            let err = decode_child_registration_head(&bad).unwrap_err();
            assert_eq!(err.category, category::SCALE_DECODE);
        }
    }

    #[test]
    fn decode_account_id_wants_exactly_32_bytes() {
        assert_eq!(decode_account_id(&[3u8; 32]).unwrap(), [3u8; 32]);
        assert_eq!(
            decode_account_id(&[3u8; 33]).unwrap_err().category,
            category::SCALE_DECODE
        );
    }

    /// A loopback JSON-RPC stub (127.0.0.1, no outside network): answers
    /// each call with `answer(method, params)`, one connection per call.
    fn rpc_stub(
        answer: impl Fn(&str, &serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let result = answer(request["method"].as_str().unwrap(), &request["params"]);
                let reply =
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        url
    }

    const HEAD: &str = "0xabababababababababababababababababababababababababababababababab";

    /// A chain where `node` is registered by child `[0x22; 32]` of family
    /// `[0x33; 32]`, serving `meta` as its runtime metadata.
    fn chain_stub(node: [u8; 32], meta: Vec<u8>) -> String {
        rpc_stub(move |method, params| match method {
            "chain_getFinalizedHead" => serde_json::json!(HEAD),
            "state_getMetadata" => {
                assert_eq!(params[0], HEAD, "metadata is read at the finalized head");
                serde_json::json!(format!("0x{}", hex::encode(&meta)))
            }
            "state_getStorage" => {
                assert_eq!(params[1], HEAD, "storage is read at the finalized head");
                let key = decode_hex(params[0].as_str().unwrap()).unwrap();
                if key == node_id_to_child_key("ComputeScoring", &node) {
                    serde_json::json!(format!("0x{}", hex::encode([0x22u8; 32])))
                } else if key == child_registration_key("ComputeScoring", &[0x22u8; 32]) {
                    let mut reg = vec![0x33u8; 32];
                    reg.extend_from_slice(&node);
                    reg.push(0);
                    reg.extend_from_slice(&[0u8; 16 + 4]);
                    serde_json::json!(format!("0x{}", hex::encode(reg)))
                } else {
                    serde_json::Value::Null
                }
            }
            other => panic!("unexpected RPC {other}"),
        })
    }

    #[test]
    fn fetch_node_family_reads_the_binding_at_the_finalized_head() {
        let node = [0x11u8; 32];
        let read = fetch_node_family(
            &chain_stub(node, metadata::tests::live(14)),
            "ComputeScoring",
            &node,
        )
        .unwrap();
        assert_eq!(read.block_hash, HEAD);
        let (child, reg) = read.binding.unwrap();
        assert_eq!(child, [0x22u8; 32]);
        assert_eq!(reg.family, [0x33u8; 32]);
        assert_eq!(reg.status, ChildStatus::Active);
        // Another node is not registered.
        let other = [0x44u8; 32];
        let read = fetch_node_family(
            &chain_stub(node, metadata::tests::live(15)),
            "ComputeScoring",
            &other,
        )
        .unwrap();
        assert_eq!(read.binding.unwrap_err(), UnboundReason::NoChild);
    }

    #[test]
    fn fetch_node_family_refuses_a_fossil_pallet_or_map() {
        let node = [0x11u8; 32];
        for (label, meta) in metadata::tests::fossils() {
            let err =
                fetch_node_family(&chain_stub(node, meta), "ComputeScoring", &node).unwrap_err();
            assert_eq!(err.category, category::PALLET_ABSENT, "{label}");
        }
    }

    #[test]
    fn fetch_node_family_refuses_an_empty_url() {
        let err = fetch_node_family("  ", "ComputeScoring", &[0u8; 32]).unwrap_err();
        assert_eq!(err.category, category::RPC_REQUEST);
    }

    // ── compute families and their Arion storage ──────────────────────

    fn hexed(bytes: &[u8]) -> serde_json::Value {
        serde_json::json!(format!("0x{}", hex::encode(bytes)))
    }

    /// A `ChildRegistration` as mainnet stores it (`BlockNumber = u64`).
    fn reg(family: [u8; 32], node: [u8; 32], status: u8) -> Vec<u8> {
        let mut out = family.to_vec();
        out.extend_from_slice(&node);
        out.push(status);
        out.extend_from_slice(&[0u8; 16 + 8]);
        out
    }

    fn quality(bytes: u128, uptime: u16) -> Vec<u8> {
        let mut out = bytes.to_le_bytes().to_vec();
        out.extend_from_slice(&7u128.to_le_bytes());
        out.extend_from_slice(&uptime.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out
    }

    /// Family A `[0xa1]`: compute nodes `[0x01]` (child `[0xc1]`, Active)
    /// and `[0x02]` (child `[0xc2]`, Unbonding — not a compute node of the
    /// gate); Arion children `[0xd1]` (fully reported) and `[0xd2]` (no
    /// registration, nothing reported). Family B `[0xb1]`: compute node
    /// `[0x03]` (child `[0xc3]`), no Arion children. A node whose forward
    /// and reverse index disagree (`[0x04]`) is skipped.
    fn storage_chain(meta: Vec<u8>) -> String {
        use std::collections::HashMap;
        let (fa, fb) = ([0xa1u8; 32], [0xb1u8; 32]);
        let mut kv: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let compute = |node: u8, child: u8, family: [u8; 32], status: u8, reg_node: u8| {
            vec![
                (
                    storage_map_key("ComputeScoring", "NodeIdToChild", &[node; 32]),
                    vec![child; 32],
                ),
                (
                    storage_map_key("ComputeScoring", "ChildRegistrations", &[child; 32]),
                    reg(family, [reg_node; 32], status),
                ),
            ]
        };
        kv.extend(compute(0x01, 0xc1, fa, 0, 0x01));
        kv.extend(compute(0x02, 0xc2, fa, 1, 0x02));
        kv.extend(compute(0x03, 0xc3, fb, 0, 0x03));
        kv.extend(compute(0x04, 0xc4, fb, 0, 0x99));
        let mut children = codec::Compact(2u32).encode();
        children.extend_from_slice(&[0xd1u8; 32]);
        children.extend_from_slice(&[0xd2u8; 32]);
        kv.insert(storage_map_key("Arion", "FamilyChildren", &fa), children);
        kv.insert(
            storage_map_key("Arion", "ChildRegistrations", &[0xd1u8; 32]),
            reg(fa, [0xe1u8; 32], 0),
        );
        kv.insert(
            storage_map_key("Arion", "NodeWeightByChild", &[0xd1u8; 32]),
            900u16.to_le_bytes().to_vec(),
        );
        kv.insert(
            storage_map_key("Arion", "NodeWeightLastBucket", &[0xd1u8; 32]),
            40u32.to_le_bytes().to_vec(),
        );
        kv.insert(
            storage_map_key("Arion", "NodeQualityByChild", &[0xd1u8; 32]),
            quality(1 << 40, 990),
        );
        kv.insert(
            storage_value_key("Arion", "CurrentWeightBucket"),
            42u32.to_le_bytes().to_vec(),
        );
        let prefix = storage_map_prefix("ComputeScoring", "NodeIdToChild");
        rpc_stub(move |method, params| match method {
            "chain_getFinalizedHead" => serde_json::json!(HEAD),
            "state_getMetadata" => {
                assert_eq!(params[0], HEAD);
                hexed(&meta)
            }
            "state_getKeysPaged" => {
                assert_eq!(params[3], HEAD, "keys are listed at the finalized head");
                assert_eq!(params[0], hexed(&prefix));
                let mut keys: Vec<_> = kv
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .map(|k| hexed(k))
                    .collect();
                if !params[2].is_null() {
                    keys.clear(); // one page
                }
                serde_json::json!(keys)
            }
            "state_getStorage" => {
                assert_eq!(params[1], HEAD, "storage is read at the finalized head");
                let key = decode_hex(params[0].as_str().unwrap()).unwrap();
                kv.get(&key).map_or(serde_json::Value::Null, |v| hexed(v))
            }
            other => panic!("unexpected RPC {other}"),
        })
    }

    #[test]
    fn fetch_storage_families_reads_every_compute_family_and_its_arion_children() {
        let read = fetch_storage_families(
            &storage_chain(metadata::tests::with_arion(14, 4, None)),
            "ComputeScoring",
            "Arion",
        )
        .unwrap();
        assert_eq!(read.block_hash, HEAD);
        assert_eq!(read.stale_child_buckets, 4);
        assert_eq!(read.current_weight_bucket, 42);
        let families: Vec<_> = read.families.iter().map(|f| f.family).collect();
        assert_eq!(families, [[0xa1u8; 32], [0xb1u8; 32]]);
        let a = &read.families[0];
        // The Unbonding compute child is not a compute node of the gate.
        assert_eq!(
            a.compute,
            [ComputeNodeRead {
                node_id: [0x01; 32],
                child: [0xc1; 32]
            }]
        );
        assert_eq!(a.storage.len(), 2);
        let d1 = &a.storage[0];
        assert_eq!(d1.child, [0xd1u8; 32]);
        let r = d1.registration.as_ref().unwrap();
        assert_eq!(
            (r.family, r.node_id, r.status),
            ([0xa1; 32], [0xe1; 32], ChildStatus::Active)
        );
        assert_eq!((d1.node_weight, d1.last_bucket), (900, 40));
        let q = d1.quality.as_ref().unwrap();
        assert_eq!((q.shard_data_bytes, q.bandwidth_bytes), (1 << 40, 7));
        assert_eq!(
            (q.uptime_permille, q.strikes, q.integrity_fails),
            (990, 1, 2)
        );
        let d2 = &a.storage[1];
        assert_eq!(
            (
                d2.registration.is_none(),
                d2.node_weight,
                d2.last_bucket,
                d2.quality.is_none()
            ),
            (true, 0, 0, true)
        );
        // Family B: one compute node (the mismatched index is skipped), no storage.
        let b = &read.families[1];
        assert_eq!(b.compute.len(), 1);
        assert_eq!(b.compute[0].node_id, [0x03; 32]);
        assert!(b.storage.is_empty());
    }

    #[test]
    fn fetch_storage_families_refuses_a_fossil_or_a_missing_constant() {
        for drop in [
            "FamilyChildren",
            "ChildRegistrations",
            "NodeWeightByChild",
            "NodeWeightLastBucket",
            "NodeQualityByChild",
            "CurrentWeightBucket",
            "StaleChildBuckets",
        ] {
            let err = fetch_storage_families(
                &storage_chain(metadata::tests::with_arion(14, 4, Some(drop))),
                "ComputeScoring",
                "Arion",
            )
            .unwrap_err();
            assert_eq!(err.category, category::PALLET_ABSENT, "{drop}");
        }
        // The compute pallet's maps are required too.
        let err = fetch_storage_families(
            &storage_chain(metadata::tests::with_arion(14, 4, None)),
            "Gone",
            "Arion",
        )
        .unwrap_err();
        assert_eq!(err.category, category::PALLET_ABSENT);
    }

    #[test]
    fn storage_family_decoders_fail_closed() {
        assert_eq!(
            decode_account_list(&[0x08, 1, 2]).unwrap_err().category,
            category::SCALE_DECODE
        );
        let mut trailing = codec::Compact(1u32).encode();
        trailing.extend_from_slice(&[9u8; 33]);
        assert_eq!(
            decode_account_list(&trailing).unwrap_err().category,
            category::SCALE_DECODE
        );
        assert!(decode_account_list(&codec::Compact(0u32).encode())
            .unwrap()
            .is_empty());
        assert_eq!(
            decode_node_quality(&[0u8; 41]).unwrap_err().category,
            category::SCALE_DECODE
        );
        assert_eq!(
            scale_u32(&[0u8; 5]).unwrap_err().category,
            category::SCALE_DECODE
        );
        assert_eq!(
            scale_u16(&[0u8; 1]).unwrap_err().category,
            category::SCALE_DECODE
        );
        assert_eq!(scale_u32(&7u32.to_le_bytes()).unwrap(), 7);
    }
}
