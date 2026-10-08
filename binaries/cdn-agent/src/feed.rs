//! Feed state: snapshot/delta application, purge generations, and the
//! last-known-good (LKG) snapshot.
//!
//! The state holds only what the backend sent: public config and
//! **sealed** blobs. Nothing unsealed is ever stored here, so the LKG
//! file on the data volume carries ciphertext only.
//!
//! Purge is versioned keys (spec §10.2). The agent keeps every
//! generation it has seen at its maximum: a snapshot or delta that
//! carries a lower value never makes purged objects reachable again.
//! A removed zone leaves a tombstone one generation above anything it
//! had, so a re-added zone with the same id cannot resurrect old keys.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{is_valid_id, is_valid_region};
use crate::error::{CdnError, Result};
use crate::hostname::is_valid_hostname;
use crate::persist;
use crate::wire::{
    AcmeHttp01, Block, FeedMode, FeedResponse, FleetKeyState, FleetKeyVersion, Hostname, Peer,
    PurgeGenerations, SealedCert, SelfState, Zone,
};

const MAX_ZONES: usize = 100_000;
const MAX_HOSTNAMES: usize = 200_000;
const MAX_CERTS: usize = 200_000;
const MAX_BLOCKS: usize = 100_000;
const MAX_ACME: usize = 10_000;
const MAX_PEERS: usize = 1_024;
const MAX_FLEET_VERSIONS: usize = 16;
const MAX_PREFIXES_PER_ZONE: usize = 10_000;
const MAX_SECRETS_PER_ZONE: usize = 16;
const MAX_SETTINGS_BYTES: usize = 64 * 1024;
const MAX_PATH_LEN: usize = 1_024;
const MAX_PEM_LEN: usize = 32 * 1024;

/// LKG file format version.
const LKG_FORMAT: u32 = 1;
/// The LKG file can reach the size of a large snapshot.
const MAX_LKG_LEN: u64 = 512 * 1024 * 1024;

/// The node's applied view of the feed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedState {
    pub revision: u64,
    pub zones: BTreeMap<String, Zone>,
    /// By `hostname_id`.
    pub hostnames: BTreeMap<String, Hostname>,
    /// By `zone_id`, including tombstones of removed zones.
    pub purges: BTreeMap<String, PurgeGenerations>,
    pub blocks: BTreeMap<String, Block>,
    /// By `hostname_id`.
    pub certs: BTreeMap<String, SealedCert>,
    pub acme_http01: Vec<AcmeHttp01>,
    pub fleet_key_versions: Vec<FleetKeyVersion>,
    pub self_state: SelfState,
    pub peers: Vec<Peer>,
    /// A snapshot has been applied (or an LKG loaded). Revision 0 is a
    /// valid snapshot revision, so the revision cannot tell. Not stored
    /// in the LKG: loading one sets it.
    #[serde(skip)]
    pub snapshot_applied: bool,
}

/// What [`FeedState::apply`] did.
#[derive(Debug)]
pub enum Applied {
    /// A new state at `state.revision`.
    New(Box<FeedState>),
    /// A delta at or below the current revision: nothing to do.
    Stale,
}

impl FeedState {
    /// Whether no snapshot has been applied yet.
    pub fn is_empty(&self) -> bool {
        !self.snapshot_applied
    }

    /// Apply a feed response, returning the new state. `self` is left
    /// untouched on error, so a bad revision never half-applies.
    pub fn apply(&self, resp: FeedResponse) -> Result<Applied> {
        let mut next = match resp.mode {
            FeedMode::Delta if self.is_empty() => {
                return Err(CdnError::Feed("delta-without-base"));
            }
            FeedMode::Delta if resp.revision <= self.revision => return Ok(Applied::Stale),
            FeedMode::Delta => {
                let mut next = self.clone();
                next.remove(&resp.removed);
                next
            }
            FeedMode::Snapshot => {
                if resp.revision < self.revision {
                    eprintln!(
                        "hippius-cdn-agent: feed snapshot went back from revision {} to {}",
                        self.revision, resp.revision
                    );
                }
                // Start from nothing but the purge history, then tombstone
                // every zone the snapshot no longer carries.
                let mut next = FeedState {
                    purges: self.purges.clone(),
                    ..FeedState::default()
                };
                let kept: BTreeSet<&str> = resp.zones.iter().map(|z| z.zone_id.as_str()).collect();
                for zone_id in self.zones.keys() {
                    if !kept.contains(zone_id.as_str()) {
                        next.tombstone(zone_id);
                    }
                }
                next
            }
        };

        next.revision = resp.revision;
        next.snapshot_applied = true;
        for z in resp.zones {
            next.zones.insert(z.zone_id.clone(), z);
        }
        for h in resp.hostnames {
            next.hostnames.insert(h.hostname_id.clone(), h);
        }
        for b in resp.blocks {
            next.blocks.insert(b.block_id.clone(), b);
        }
        for c in resp.certs {
            next.certs.insert(c.hostname_id.clone(), c);
        }
        for p in resp.purges {
            next.merge_purge(p);
        }
        next.acme_http01 = resp.acme_http01;
        next.fleet_key_versions = resp.fleet_key_versions;
        next.self_state = resp.self_state;
        next.peers = resp.peers;

        next.drop_unusable_paths();
        next.validate()?;
        // The backend serves a full snapshot on every 200 (no deltas yet):
        // an unchanged one must not re-push secrets or rewrite the LKG.
        if next == *self {
            return Ok(Applied::Stale);
        }
        Ok(Applied::New(Box::new(next)))
    }

    fn remove(&mut self, removed: &crate::wire::Removed) {
        for id in &removed.zones {
            if self.zones.remove(id).is_some() {
                self.tombstone(id);
            }
        }
        for id in &removed.hostnames {
            self.hostnames.remove(id);
        }
        for id in &removed.blocks {
            self.blocks.remove(id);
        }
        for id in &removed.certs {
            self.certs.remove(id);
        }
    }

    /// Replace a removed zone's purge state with a tombstone above every
    /// generation it had.
    fn tombstone(&mut self, zone_id: &str) {
        let top = self
            .purges
            .get(zone_id)
            .map(|p| {
                p.prefixes
                    .values()
                    .chain(p.paths.values())
                    .copied()
                    .fold(p.zone_generation, u64::max)
            })
            .unwrap_or(0);
        self.purges.insert(
            zone_id.to_string(),
            PurgeGenerations {
                zone_id: zone_id.to_string(),
                zone_generation: top.saturating_add(1),
                prefixes: BTreeMap::new(),
                paths: BTreeMap::new(),
            },
        );
    }

    /// Drop purge keys and blocks whose path is unusable instead of
    /// refusing the revision: they come from customer purges and staff
    /// blocks, can never match a request, and one of them must not stall
    /// every later revision (merged purge keys are kept forever).
    fn drop_unusable_paths(&mut self) {
        let mut dropped = 0usize;
        for p in self.purges.values_mut() {
            let before = p.prefixes.len() + p.paths.len();
            p.prefixes
                .retain(|k, _| is_request_path(k) && k.ends_with('/'));
            p.paths.retain(|k, _| is_request_path(k));
            dropped += before - p.prefixes.len() - p.paths.len();
        }
        let before = self.blocks.len();
        self.blocks.retain(|_, b| match b.kind.as_str() {
            "hostname" => is_valid_hostname(&b.value),
            "prefix" => is_request_path(&b.value) && b.value.ends_with('/'),
            "path" => is_request_path(&b.value),
            _ => false,
        });
        dropped += before - self.blocks.len();
        if dropped > 0 {
            eprintln!("hippius-cdn-agent: {dropped} unusable purge keys or blocks dropped");
        }
    }

    /// Keep the maximum of every generation.
    fn merge_purge(&mut self, incoming: PurgeGenerations) {
        let entry = self
            .purges
            .entry(incoming.zone_id.clone())
            .or_insert_with(|| PurgeGenerations {
                zone_id: incoming.zone_id.clone(),
                zone_generation: 0,
                prefixes: BTreeMap::new(),
                paths: BTreeMap::new(),
            });
        entry.zone_generation = entry.zone_generation.max(incoming.zone_generation);
        for (path, generation) in incoming.paths {
            let slot = entry.paths.entry(path).or_insert(0);
            *slot = (*slot).max(generation);
        }
        // A `prefixes` key without the trailing "/" is an exact path: the
        // backend sends exact purges there until it fills `paths`.
        for (prefix, generation) in incoming.prefixes {
            let map = if prefix.ends_with('/') {
                &mut entry.prefixes
            } else {
                &mut entry.paths
            };
            let slot = map.entry(prefix).or_insert(0);
            *slot = (*slot).max(generation);
        }
    }

    /// The zone ids the node serves (metering attributes only these).
    pub fn zone_ids(&self) -> BTreeSet<String> {
        self.zones.keys().cloned().collect()
    }

    /// The fleet key version the backend currently seals to.
    pub fn active_fleet_version(&self) -> Option<u32> {
        self.fleet_key_versions
            .iter()
            .find(|v| v.state == FleetKeyState::Active)
            .map(|v| v.version)
    }

    /// Check every field the data plane will consume. Run on each new
    /// state and on an LKG load.
    pub fn validate(&self) -> Result<()> {
        if self.zones.len() > MAX_ZONES
            || self.hostnames.len() > MAX_HOSTNAMES
            || self.certs.len() > MAX_CERTS
            || self.blocks.len() > MAX_BLOCKS
            || self.acme_http01.len() > MAX_ACME
            || self.peers.len() > MAX_PEERS
            || self.fleet_key_versions.len() > MAX_FLEET_VERSIONS
            || self.purges.len() > MAX_ZONES * 2
        {
            return Err(CdnError::Feed("too-many-entries"));
        }
        for (id, z) in &self.zones {
            validate_zone(id, z)?;
        }
        for (id, h) in &self.hostnames {
            if id != &h.hostname_id || !is_valid_id(id) || !is_valid_hostname(&h.hostname) {
                return Err(CdnError::Feed("hostname-invalid"));
            }
            if !self.zones.contains_key(&h.zone_id) {
                return Err(CdnError::Feed("hostname-zone-unknown"));
            }
        }
        let mut names = BTreeSet::new();
        for h in self.hostnames.values() {
            if !names.insert(h.hostname.as_str()) {
                return Err(CdnError::Feed("hostname-duplicate"));
            }
        }
        for (id, p) in &self.purges {
            if id != &p.zone_id
                || !is_valid_id(id)
                || p.prefixes.len() + p.paths.len() > MAX_PREFIXES_PER_ZONE
            {
                return Err(CdnError::Feed("purge-invalid"));
            }
            if !p
                .prefixes
                .keys()
                .all(|k| is_valid_path(k) && k.ends_with('/'))
                || !p.paths.keys().all(|k| is_valid_path(k))
            {
                return Err(CdnError::Feed("purge-prefix-invalid"));
            }
        }
        for (id, b) in &self.blocks {
            let kind_ok = matches!(b.kind.as_str(), "hostname" | "path" | "prefix");
            let zone_ok = b.zone_id.as_deref().is_none_or(is_valid_id);
            let value_ok = match b.kind.as_str() {
                "hostname" => is_valid_hostname(&b.value),
                // A prefix block is directory-aligned, like a purge prefix.
                "prefix" => is_valid_path(&b.value) && b.value.ends_with('/'),
                _ => is_valid_path(&b.value),
            };
            if id != &b.block_id || !is_valid_id(id) || !kind_ok || !zone_ok || !value_ok {
                return Err(CdnError::Feed("block-invalid"));
            }
        }
        for (id, c) in &self.certs {
            let ok = id == &c.hostname_id
                && is_valid_id(id)
                && is_valid_hostname(&c.hostname)
                && c.cert_chain_pem.len() <= MAX_PEM_LEN
                && c.fleet_key_version >= 1;
            if !ok {
                return Err(CdnError::Feed("cert-invalid"));
            }
        }
        for a in &self.acme_http01 {
            if !is_valid_acme(a) {
                return Err(CdnError::Feed("acme-invalid"));
            }
        }
        let mut versions = BTreeSet::new();
        for v in &self.fleet_key_versions {
            if v.version == 0 || !versions.insert(v.version) {
                return Err(CdnError::Feed("fleet-version-invalid"));
            }
        }
        let active = self
            .fleet_key_versions
            .iter()
            .filter(|v| v.state == FleetKeyState::Active)
            .count();
        if active > 1 {
            return Err(CdnError::Feed("fleet-version-multiple-active"));
        }
        for p in &self.peers {
            let fp_ok = p.cert_fingerprint.len() == 64
                && p.cert_fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !is_valid_id(&p.node_id)
                || !is_valid_region(&p.region)
                || !fp_ok
                || !is_public_ip(&p.public_ip)
            {
                return Err(CdnError::Feed("peer-invalid"));
            }
        }
        if self
            .self_state
            .cert_pem
            .as_ref()
            .is_some_and(|c| c.len() > MAX_PEM_LEN)
        {
            return Err(CdnError::Feed("self-cert-too-large"));
        }
        Ok(())
    }
}

fn validate_zone(id: &str, z: &Zone) -> Result<()> {
    if id != z.zone_id || !is_valid_id(id) {
        return Err(CdnError::Feed("zone-id-invalid"));
    }
    if z.shield_region
        .as_deref()
        .is_some_and(|r| !is_valid_region(r))
    {
        return Err(CdnError::Feed("zone-shield-invalid"));
    }
    if z.secrets.len() > MAX_SECRETS_PER_ZONE {
        return Err(CdnError::Feed("zone-secrets-too-many"));
    }
    let mut names = BTreeSet::new();
    for s in &z.secrets {
        let name_ok = !s.name.is_empty()
            && s.name.len() <= 64
            && s.name.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'_' | b':' | b'-' | b'.')
            });
        if !name_ok || s.fleet_key_version == 0 || !names.insert(s.name.as_str()) {
            return Err(CdnError::Feed("zone-secret-invalid"));
        }
    }
    if z.origin.kind.is_empty()
        || z.origin.kind.len() > 16
        || !z
            .origin
            .kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(CdnError::Feed("zone-origin-invalid"));
    }
    let settings_len = serde_json::to_vec(&z.settings)
        .map_err(|_| CdnError::Feed("zone-settings-invalid"))?
        .len();
    let origin_len = serde_json::to_vec(&z.origin.params)
        .map_err(|_| CdnError::Feed("zone-origin-invalid"))?
        .len();
    if settings_len > MAX_SETTINGS_BYTES || origin_len > MAX_SETTINGS_BYTES {
        return Err(CdnError::Feed("zone-settings-too-large"));
    }
    Ok(())
}

/// A peer address must be publicly routable: shield fetches go there, so
/// a feed entry must not point a node at its own loopback, the host's
/// network, the overlay or a metadata service.
///
/// IPv6 is an allowlist of global unicast (`2000::/3`) minus the
/// prefixes that embed an IPv4 address (6to4 `2002::/16`, Teredo
/// `2001::/32`, and the documentation prefix `2001:db8::/32`);
/// IPv4-mapped addresses are checked as IPv4.
fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(&v4);
            }
            let [s0, s1, ..] = v6.segments();
            (s0 & 0xe000) == 0x2000 && s0 != 0x2002 && !(s0 == 0x2001 && (s1 == 0 || s1 == 0x0db8))
        }
    }
}

fn is_public_v4(v4: &Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    !(v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || a == 0
        || a >= 240 // 240.0.0.0/4 reserved
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10
        || (a == 192 && b == 0 && v4.octets()[2] == 0) // 192.0.0.0/24
        || (a == 198 && (b & 0xfe) == 18) // 198.18.0.0/15
        || (a == 192 && b == 0 && v4.octets()[2] == 2) // 192.0.2.0/24 documentation
        || (a == 198 && b == 51 && v4.octets()[2] == 100) // 198.51.100.0/24 documentation
        || (a == 203 && b == 0 && v4.octets()[2] == 113)) // 203.0.113.0/24 documentation
}

/// A URL path or prefix: starts with `/`, bounded, printable ASCII
/// without spaces (paths arrive percent-encoded).
fn is_valid_path(p: &str) -> bool {
    p.starts_with('/') && p.len() <= MAX_PATH_LEN && p.bytes().all(|b| b.is_ascii_graphic())
}

/// Whether a percent-encoded feed path (purge key, block value) can match
/// a request at all, by the data plane's rule: printable ASCII as sent,
/// and once decoded no control byte, no backslash and no "." / ".."
/// segment (nginx's `$uri` never contains one). The data plane applies
/// the same rule and skips what fails it.
fn is_request_path(p: &str) -> bool {
    if !is_valid_path(p) {
        return false;
    }
    let raw = p.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut decoded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (hex(raw[i + 1]), hex(raw[i + 2])) {
                decoded.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        decoded.push(raw[i]);
        i += 1;
    }
    if decoded.iter().any(|&b| b < 0x20 || b == 0x7f || b == b'\\') {
        return false;
    }
    !decoded
        .split(|&b| b == b'/')
        .any(|seg| seg == b"." || seg == b"..")
}

/// RFC 8555 §8.3: `token` is base64url; the key authorisation is
/// `token "." base64url(thumbprint)`.
fn is_valid_acme(a: &AcmeHttp01) -> bool {
    let b64url = |s: &str| {
        !s.is_empty()
            && s.len() <= 256
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    match a.key_authorization.split_once('.') {
        Some((tok, thumb)) => tok == a.token && b64url(&a.token) && b64url(thumb),
        None => false,
    }
}

#[derive(Serialize, Deserialize)]
struct Lkg {
    format: u32,
    saved_at: u64,
    state: FeedState,
}

/// Persist `state` as the LKG snapshot (atomic).
pub fn save_lkg(path: &Path, state: &FeedState, now: u64) -> Result<()> {
    #[derive(Serialize)]
    struct LkgRef<'a> {
        format: u32,
        saved_at: u64,
        state: &'a FeedState,
    }
    let bytes = serde_json::to_vec(&LkgRef {
        format: LKG_FORMAT,
        saved_at: now,
        state,
    })
    .map_err(|_| CdnError::Feed("lkg-encode"))?;
    persist::atomic_write(path, &bytes)
}

/// Load the LKG snapshot if it exists, is readable, validates, and is
/// younger than `max_age_s`. Returns the state and when it was saved.
/// An unusable file is ignored (the node then waits for the backend).
pub fn load_lkg(path: &Path, now: u64, max_age_s: u64) -> Result<Option<(FeedState, u64)>> {
    let Some(bytes) = persist::read_optional(path, MAX_LKG_LEN)? else {
        return Ok(None);
    };
    let Ok(lkg) = serde_json::from_slice::<Lkg>(&bytes) else {
        return Err(CdnError::Feed("lkg-corrupt"));
    };
    if lkg.format != LKG_FORMAT {
        return Err(CdnError::Feed("lkg-format"));
    }
    if lkg.saved_at > now || now - lkg.saved_at > max_age_s {
        return Err(CdnError::Feed("lkg-too-old"));
    }
    lkg.state.validate()?;
    let mut state = lkg.state;
    state.snapshot_applied = true;
    Ok(Some((state, lkg.saved_at)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn snapshot(rev: u64) -> serde_json::Value {
        json!({
            "revision": rev,
            "mode": "snapshot",
            "zones": [
                {"zone_id": "z1", "state": "active",
                 "origin": {"type": "s3", "bucket": "media"},
                 "shield_region": "FR",
                 "settings": {"rules": []}},
                {"zone_id": "z2", "state": "paused",
                 "origin": {"type": "s3", "bucket": "docs", "prefix": "site/"}}
            ],
            "hostnames": [
                {"hostname_id": "h1", "hostname": "z1.cdn.hippius.com", "zone_id": "z1"},
                {"hostname_id": "h2", "hostname": "img.example.com", "zone_id": "z1"}
            ],
            "purges": [
                {"zone_id": "z1", "zone_generation": 4, "prefixes": {"/img/": 2}}
            ],
            "blocks": [
                {"block_id": "b1", "zone_id": "z1", "kind": "path", "value": "/bad.bin"}
            ],
            "acme_http01": [
                {"token": "tok_1", "key_authorization": "tok_1.thumb-print"}
            ],
            "fleet_key_versions": [{"version": 1, "state": "active"}],
            "self": {"state": "ready", "draining": false},
            "peers": [{"node_id": "cdn-fr-2", "region": "FR",
                       "public_ip": "11.1.2.3", "cert_fingerprint": "ab".repeat(32)}]
        })
    }

    pub(crate) fn resp(v: serde_json::Value) -> FeedResponse {
        serde_json::from_value(v).unwrap()
    }

    fn applied(state: &FeedState, v: serde_json::Value) -> FeedState {
        match state.apply(resp(v)).unwrap() {
            Applied::New(s) => *s,
            Applied::Stale => panic!("unexpected stale"),
        }
    }

    #[test]
    fn an_empty_snapshot_at_revision_0_is_a_base() {
        assert!(FeedState::default().is_empty());
        let s = applied(
            &FeedState::default(),
            json!({"revision": 0, "mode": "snapshot", "self": {"state": "ready", "draining": false}}),
        );
        assert_eq!(s.revision, 0);
        assert!(!s.is_empty(), "a snapshot was applied");
        // The same snapshot again changes nothing.
        let again = s
            .apply(resp(json!({"revision": 0, "mode": "snapshot", "self": {"state": "ready", "draining": false}})))
            .unwrap();
        assert!(matches!(again, Applied::Stale));
        // A delta on top of it applies.
        let d = applied(
            &s,
            json!({"revision": 1, "mode": "delta",
                   "hostnames": [{"hostname_id": "h1", "hostname": "img.example.com", "zone_id": "z1"}],
                   "zones": [{"zone_id": "z1", "state": "active", "origin": {"type": "s3", "bucket": "media"}}],
                   "self": {"state": "ready", "draining": false}}),
        );
        assert_eq!(d.revision, 1);
        assert!(!d.is_empty());
    }

    #[test]
    fn snapshot_then_delta() {
        let s = applied(&FeedState::default(), snapshot(10));
        assert_eq!(s.revision, 10);
        assert_eq!(s.zones.len(), 2);
        assert_eq!(s.active_fleet_version(), Some(1));

        let s2 = applied(
            &s,
            json!({
                "revision": 11, "mode": "delta",
                "hostnames": [{"hostname_id": "h3", "hostname": "v.example.com", "zone_id": "z2"}],
                "removed": {"hostnames": ["h2"], "blocks": ["b1"]},
                "self": {"state": "ready", "draining": true}
            }),
        );
        assert_eq!(s2.revision, 11);
        assert!(s2.hostnames.contains_key("h3"));
        assert!(!s2.hostnames.contains_key("h2"));
        assert!(s2.blocks.is_empty());
        assert!(s2.self_state.draining);
        // Untouched sections survive a delta.
        assert_eq!(s2.zones.len(), 2);
        // Full-value sections are replaced by every response.
        assert!(s2.acme_http01.is_empty());
        assert!(s2.peers.is_empty());
    }

    #[test]
    fn stale_and_baseless_deltas() {
        let delta = |rev: u64| json!({"revision": rev, "mode": "delta", "self": {}});
        assert_eq!(
            FeedState::default()
                .apply(resp(delta(3)))
                .unwrap_err()
                .class(),
            "delta-without-base"
        );
        let s = applied(&FeedState::default(), snapshot(10));
        assert!(matches!(s.apply(resp(delta(10))).unwrap(), Applied::Stale));
        assert!(matches!(s.apply(resp(delta(9))).unwrap(), Applied::Stale));
    }

    #[test]
    fn purge_generations_never_go_down() {
        let s = applied(&FeedState::default(), snapshot(10));
        let s2 = applied(
            &s,
            json!({"revision": 11, "mode": "delta", "self": {},
                   "purges": [{"zone_id": "z1", "zone_generation": 2,
                               "prefixes": {"/img/": 1, "/css/": 7}}]}),
        );
        let p = &s2.purges["z1"];
        assert_eq!(p.zone_generation, 4);
        assert_eq!(p.prefixes["/img/"], 2);
        assert_eq!(p.prefixes["/css/"], 7);

        // A snapshot with lower generations (backend restore) keeps ours.
        let mut snap = snapshot(5);
        snap["purges"] = json!([{"zone_id": "z1", "zone_generation": 1}]);
        let s3 = applied(&s2, snap);
        assert_eq!(s3.purges["z1"].zone_generation, 4);
        assert_eq!(s3.purges["z1"].prefixes["/css/"], 7);
        assert_eq!(s3.revision, 5);
    }

    #[test]
    fn removed_zone_leaves_a_tombstone_above_its_generations() {
        let s = applied(&FeedState::default(), snapshot(10));
        let s2 = applied(
            &s,
            json!({"revision": 11, "mode": "delta", "self": {},
                   "removed": {"zones": ["z2"]}}),
        );
        assert!(!s2.zones.contains_key("z2"));
        assert_eq!(s2.purges["z2"].zone_generation, 1);

        // A snapshot that drops z1 tombstones it above max(4, 2).
        let mut snap = snapshot(12);
        snap["zones"] = json!([snap["zones"][1]]);
        snap["hostnames"] = json!([]);
        snap["blocks"] = json!([]);
        snap["purges"] = json!([]);
        let s3 = applied(&s2, snap);
        assert_eq!(s3.purges["z1"].zone_generation, 5);
        assert!(s3.purges["z1"].prefixes.is_empty());
    }

    #[test]
    fn invalid_revisions_are_refused_whole() {
        let base = applied(&FeedState::default(), snapshot(10));
        let cases = [
            (
                json!({"hostnames": [{"hostname_id": "h9", "hostname": "x.example.com", "zone_id": "nope"}]}),
                "hostname-zone-unknown",
            ),
            (
                json!({"hostnames": [{"hostname_id": "h9", "hostname": "Bad Host", "zone_id": "z1"}]}),
                "hostname-invalid",
            ),
            (
                json!({"hostnames": [{"hostname_id": "h9", "hostname": "img.example.com", "zone_id": "z1"}]}),
                "hostname-duplicate",
            ),
            (
                json!({"acme_http01": [{"token": "a", "key_authorization": "b.c"}]}),
                "acme-invalid",
            ),
            (
                json!({"fleet_key_versions": [{"version": 1, "state": "active"}, {"version": 2, "state": "active"}]}),
                "fleet-version-multiple-active",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "192.0.2.1", "cert_fingerprint": "zz"}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "192.0.2.10", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "198.51.100.7", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "203.0.113.9", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "2001:db8::1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "64:ff9b::a00:1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "2002:a00:1::1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "::a00:1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "198.18.0.1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "240.0.0.1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "192.0.0.8", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "fec0::1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "2001:0:a00:1::1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "169.254.169.254", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "100.64.3.9", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "::ffff:127.0.0.1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "fd00::1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"peers": [{"node_id": "p", "region": "FR", "public_ip": "10.0.0.1", "cert_fingerprint": "ab".repeat(32)}]}),
                "peer-invalid",
            ),
            (
                json!({"zones": [{"zone_id": "z3", "state": "active", "origin": {"type": "s3"}, "shield_region": "fra"}]}),
                "zone-shield-invalid",
            ),
        ];
        for (patch, want) in cases {
            let mut v = json!({"revision": 11, "mode": "delta", "self": {}});
            for (k, val) in patch.as_object().unwrap() {
                v[k] = val.clone();
            }
            assert_eq!(base.apply(resp(v)).unwrap_err().class(), want);
        }
        // The base state is unchanged after every refusal.
        assert_eq!(base.revision, 10);
    }

    #[test]
    fn unusable_purge_keys_and_blocks_are_dropped_not_fatal() {
        let base = applied(&FeedState::default(), snapshot(10));
        let next = applied(
            &base,
            json!({"revision": 11, "mode": "delta", "self": {},
                   "purges": [{"zone_id": "z1", "zone_generation": 1,
                               "prefixes": {"no-slash": 1, "/ok/": 2, "/ctl\u{1}": 3}}],
                   "blocks": [{"block_id": "b2", "kind": "prefix", "value": "/no-slash"},
                              {"block_id": "b4", "kind": "regex", "value": "/x"},
                              {"block_id": "b5", "kind": "path", "value": "/%2e%2e/x"},
                              {"block_id": "b3", "kind": "path", "value": "/fine"}]}),
        );
        assert_eq!(next.revision, 11);
        let p = &next.purges["z1"].prefixes;
        assert_eq!(p.get("/ok/"), Some(&2));
        assert!(!p.contains_key("no-slash") && !p.contains_key("/ctl\u{1}"));
        assert!(!next.blocks.contains_key("b2"));
        assert!(
            !next.blocks.contains_key("b4"),
            "an unknown kind is dropped, not fatal"
        );
        assert!(!next.blocks.contains_key("b5"));
        assert!(next.blocks.contains_key("b3"));
    }

    #[test]
    fn exact_path_purges_and_directory_prefixes() {
        let base = applied(&FeedState::default(), snapshot(10));
        // An absent `paths` map is empty (older backends).
        assert!(base.purges["z1"].paths.is_empty());
        let next = applied(
            &base,
            json!({"revision": 11, "mode": "snapshot", "self": {},
                   "zones": snapshot(10)["zones"], "hostnames": snapshot(10)["hostnames"],
                   "purges": [{"zone_id": "z1", "zone_generation": 4,
                               "prefixes": {"/img/": 3, "/no-slash": 9},
                               "paths": {"/img/a%20b.png": 2, "/a/../b": 9}}]}),
        );
        let p = &next.purges["z1"];
        assert_eq!(p.prefixes.get("/img/"), Some(&3));
        assert!(!p.prefixes.contains_key("/no-slash"));
        assert_eq!(
            p.paths.get("/no-slash"),
            Some(&9),
            "a prefixes key without its / is an exact path (the backend's form until `paths`)"
        );
        assert_eq!(p.paths.get("/img/a%20b.png"), Some(&2));
        assert!(
            !p.paths.contains_key("/a/../b"),
            "a dot segment never matches a request"
        );
        // Exact-path generations never go down either.
        let lower = applied(
            &next,
            json!({"revision": 12, "mode": "delta", "self": {},
                   "purges": [{"zone_id": "z1", "zone_generation": 4,
                               "paths": {"/img/a%20b.png": 1}}]}),
        );
        assert_eq!(lower.purges["z1"].paths.get("/img/a%20b.png"), Some(&2));
    }

    #[test]
    fn request_path_rule_matches_the_data_plane() {
        for ok in [
            "/",
            "/a/b.txt",
            "/a%20b.txt",
            "/a+b",
            "/%C3%BC/",
            "/a/..x",
            "/a%2",
        ] {
            assert!(is_request_path(ok), "{ok}");
        }
        for bad in [
            "/%2e%2e/x",
            "/a/%2E/b",
            "/a%5cb",
            "/a%00",
            "/a/../b",
            "/a%7f",
            "rel",
            "/a b",
        ] {
            assert!(!is_request_path(bad), "{bad}");
        }
    }

    #[test]
    fn snapshot_only_feed() {
        // The backend serves a snapshot on every 200: an identical one is
        // stale (no re-push), a changed zone state applies, and a deleted
        // zone is simply absent (tombstoned).
        let base = applied(&FeedState::default(), snapshot(10));
        assert!(matches!(
            base.apply(resp(snapshot(10))).unwrap(),
            Applied::Stale
        ));
        let mut changed = snapshot(11);
        changed["zones"][0]["state"] = json!("suspended");
        changed["zones"] = json!([changed["zones"][0]]);
        changed["hostnames"] = json!([changed["hostnames"][0]]);
        changed["blocks"] = json!([]);
        let next = applied(&base, changed);
        assert_eq!(next.zones["z1"].state, crate::wire::ZoneState::Suspended);
        assert!(!next.zones.contains_key("z2"));
        assert_eq!(next.purges["z2"].zone_generation, 1);
    }

    #[test]
    fn lkg_round_trip_and_age() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feed.json");
        let s = applied(&FeedState::default(), snapshot(10));
        save_lkg(&p, &s, 1_000).unwrap();
        let (back, saved) = load_lkg(&p, 1_500, 86_400).unwrap().unwrap();
        assert_eq!(back, s);
        assert_eq!(saved, 1_000);
        assert_eq!(
            load_lkg(&p, 100_000, 86_400).unwrap_err().class(),
            "lkg-too-old"
        );
        assert_eq!(
            load_lkg(&p, 999, 86_400).unwrap_err().class(),
            "lkg-too-old"
        );
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(
            load_lkg(&p, 1_500, 86_400).unwrap_err().class(),
            "lkg-corrupt"
        );
        assert!(load_lkg(&dir.path().join("absent"), 0, 1)
            .unwrap()
            .is_none());
    }
}
