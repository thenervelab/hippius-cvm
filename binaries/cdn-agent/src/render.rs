//! Render the applied feed into the OpenResty control documents.
//!
//! - `config` (public): every zone with its `serving` verdict, the
//!   hostname → zone map, purge generations, blocks, ACME HTTP-01 key
//!   authorisations, shield peers, compression and draining.
//! - `secrets` (cleartext, wiped on drop): each serving zone's unsealed
//!   secrets by name.
//!
//! A zone is `serving = false` (with a refusal class) when the origin
//! policy refuses its origin or one of its secrets cannot be opened.
//! OpenResty then answers that zone without contacting any origin.

use std::collections::BTreeMap;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::config::{Compression, DataPlaneConfig};
use crate::error::{CdnError, Result};
use crate::feed::FeedState;
use crate::hooks::OriginPolicy;
use crate::unseal::FleetKeyring;
use crate::wire::{Block, Peer, PurgeGenerations, Zone, ZoneState};

/// The rendered documents.
pub struct Rendered {
    pub config: Vec<u8>,
    pub secrets: Zeroizing<Vec<u8>>,
    /// `(zone_id, class)` of every zone that is not serving.
    pub refused: Vec<(String, &'static str)>,
}

#[derive(Serialize)]
struct ZoneDoc<'a> {
    state: ZoneState,
    serving: bool,
    refusal: Option<&'static str>,
    origin: &'a crate::wire::Origin,
    shield_region: Option<&'a str>,
    settings: &'a serde_json::Value,
    secrets: Vec<&'a str>,
}

#[derive(Serialize)]
struct ConfigDoc<'a> {
    revision: u64,
    compression: &'a [Compression],
    fleet_wildcard: &'a str,
    draining: bool,
    zones: BTreeMap<&'a str, ZoneDoc<'a>>,
    hostnames: BTreeMap<&'a str, &'a str>,
    purges: &'a BTreeMap<String, PurgeGenerations>,
    blocks: Vec<&'a Block>,
    acme_http01: BTreeMap<&'a str, &'a str>,
    peers: &'a [Peer],
}

#[derive(Serialize)]
struct SecretsDoc<'a> {
    zones: BTreeMap<&'a str, BTreeMap<&'a str, &'a str>>,
}

/// Render `state` (see module docs).
pub fn render(
    state: &FeedState,
    keyring: &FleetKeyring,
    policy: &dyn OriginPolicy,
    data_plane: &DataPlaneConfig,
    fleet_wildcard: &str,
) -> Result<Rendered> {
    let mut refused = Vec::new();
    let mut zones = BTreeMap::new();
    // Opened secrets, held until the secrets document is serialised.
    let mut opened: BTreeMap<&str, Vec<(&str, Zeroizing<String>)>> = BTreeMap::new();

    for (zone_id, zone) in &state.zones {
        let verdict = policy
            .admit(&zone.origin)
            .and_then(|()| open_secrets(zone, keyring));
        let refusal = match verdict {
            Ok(secrets) => {
                opened.insert(zone_id.as_str(), secrets);
                None
            }
            Err(class) => {
                refused.push((zone_id.clone(), class));
                Some(class)
            }
        };
        zones.insert(
            zone_id.as_str(),
            ZoneDoc {
                state: zone.state,
                serving: refusal.is_none(),
                refusal,
                origin: &zone.origin,
                shield_region: zone.shield_region.as_deref(),
                settings: &zone.settings,
                secrets: zone.secrets.iter().map(|s| s.name.as_str()).collect(),
            },
        );
    }

    let config = ConfigDoc {
        revision: state.revision,
        compression: &data_plane.compression,
        fleet_wildcard,
        draining: state.self_state.draining,
        zones,
        // A hostname still waiting for its first certificate is the
        // issuer's business only: OpenResty never routes it.
        hostnames: state
            .hostnames
            .values()
            .filter(|h| !h.needs_cert)
            .map(|h| (h.hostname.as_str(), h.zone_id.as_str()))
            .collect(),
        purges: &state.purges,
        blocks: state.blocks.values().collect(),
        acme_http01: state
            .acme_http01
            .iter()
            .map(|a| (a.token.as_str(), a.key_authorization.as_str()))
            .collect(),
        peers: &state.peers,
    };
    let config = serde_json::to_vec(&config).map_err(|_| CdnError::Feed("render-config"))?;

    let capacity: usize = opened
        .values()
        .flatten()
        .map(|(n, v)| n.len() + v.len() + 16)
        .sum::<usize>()
        + 64;
    let doc = SecretsDoc {
        zones: opened
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(z, s)| (*z, s.iter().map(|(n, v)| (*n, v.as_str())).collect()))
            .collect(),
    };
    // x6: any byte may be escaped as \u00XX, and a reallocation would
    // leave an unwiped copy behind.
    let mut secrets: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(capacity * 6));
    serde_json::to_writer(&mut *secrets, &doc).map_err(|_| CdnError::Feed("render-secrets"))?;

    Ok(Rendered {
        config,
        secrets,
        refused,
    })
}

fn open_secrets<'a>(
    zone: &'a Zone,
    keyring: &FleetKeyring,
) -> std::result::Result<Vec<(&'a str, Zeroizing<String>)>, &'static str> {
    zone.secrets
        .iter()
        .map(|s| {
            let plain = keyring
                .open_b64(s.fleet_key_version, &s.sealed_b64)
                .map_err(|e| e.class())?;
            let text = std::str::from_utf8(&plain).map_err(|_| "secret-not-utf8")?;
            Ok((s.name.as_str(), Zeroizing::new(text.to_owned())))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::feed::tests::{resp, snapshot};
    use crate::feed::Applied;
    use crate::hooks::S3OnlyPolicy;
    use crate::unseal::seal_to;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use serde_json::json;

    fn dp() -> DataPlaneConfig {
        DataPlaneConfig {
            compression: vec![Compression::Gzip],
            cache_fill_percent: 75,
            attestation: false,
        }
    }

    #[test]
    fn renders_config_and_secrets_and_refuses_unservable_zones() {
        let ring = FleetKeyring::from_secrets([(1, [9u8; 32])]);
        let pk = ring.public_key(1).unwrap();
        let sealed = |p: &[u8]| B64.encode(seal_to(&pk, p).unwrap());
        let mut snap = snapshot(10);
        snap["zones"][0]["secrets"] = json!([
            {"name": "s3_credentials", "fleet_key_version": 1, "sealed_b64": sealed(b"{\"k\":\"v\"}")}
        ]);
        snap["zones"][1]["secrets"] = json!([
            {"name": "signed_url_key:k1", "fleet_key_version": 1, "sealed_b64": sealed(&[0xff, 0xfe])}
        ]);
        snap["zones"].as_array_mut().unwrap().push(json!(
            {"zone_id": "z3", "state": "active", "origin": {"type": "http", "host": "example.com"}}
        ));
        snap["hostnames"].as_array_mut().unwrap().push(json!(
            {"hostname_id": "h99", "hostname": "pending.example.com", "zone_id": "z1", "needs_cert": true}
        ));
        let Applied::New(state) = crate::feed::FeedState::default().apply(resp(snap)).unwrap()
        else {
            panic!()
        };

        let r = render(&state, &ring, &S3OnlyPolicy, &dp(), "*.cdn.hippius.com").unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&r.config).unwrap();
        assert_eq!(cfg["revision"], 10);
        assert_eq!(cfg["compression"], json!(["gzip"]));
        assert_eq!(cfg["hostnames"]["img.example.com"], "z1");
        // Claimed but not certified yet: never routed.
        assert!(cfg["hostnames"].get("pending.example.com").is_none());
        assert!(!String::from_utf8_lossy(&r.config).contains("pending.example.com"));
        assert_eq!(cfg["purges"]["z1"]["zone_generation"], 4);
        assert_eq!(cfg["acme_http01"]["tok_1"], "tok_1.thumb-print");
        assert_eq!(cfg["zones"]["z1"]["serving"], true);
        assert_eq!(cfg["zones"]["z1"]["secrets"], json!(["s3_credentials"]));
        assert_eq!(cfg["zones"]["z2"]["serving"], false);
        assert_eq!(cfg["zones"]["z2"]["refusal"], "secret-not-utf8");
        assert_eq!(cfg["zones"]["z3"]["refusal"], "origin-kind-not-supported");
        // The public document never carries a secret value.
        assert!(!String::from_utf8_lossy(&r.config).contains("\\\"k\\\""));

        let sec: serde_json::Value = serde_json::from_slice(&r.secrets).unwrap();
        assert_eq!(sec["zones"]["z1"]["s3_credentials"], "{\"k\":\"v\"}");
        assert!(sec["zones"].get("z2").is_none());
        assert_eq!(r.refused.len(), 2);
    }
}
