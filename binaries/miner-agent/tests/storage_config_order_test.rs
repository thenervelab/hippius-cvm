//! `storage-config` wire shape: every ticket-validator encoded body in
//! `test_vectors/orders/storage_config_v1.json` decodes into the agent's
//! `StorageConfigOrder` exactly as the payload says, and an unknown key
//! anywhere in the document is refused at decode. The route itself is
//! covered by `storage_config_route_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ciborium::value::Value;
use hippius_miner_agent::orders::types::{
    DedicatedDiskSpec, StorageDesiredState, StoragePoolClass, StoragePoolSpec,
};
use hippius_miner_agent::orders::{OrderBody, StorageConfigOrder, ORDER_DOMAIN};

fn vector() -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/storage_config_v1.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

fn class(s: &str) -> StoragePoolClass {
    match s {
        "nvme" => StoragePoolClass::Nvme,
        "ssd" => StoragePoolClass::Ssd,
        "hdd" => StoragePoolClass::Hdd,
        other => panic!("class {other}"),
    }
}

fn state(s: &str) -> StorageDesiredState {
    match s {
        "active" => StorageDesiredState::Active,
        "draining" => StorageDesiredState::Draining,
        other => panic!("state {other}"),
    }
}

/// The payload JSON, read as the agent type field by field.
fn expected(payload: &serde_json::Value) -> StorageConfigOrder {
    StorageConfigOrder {
        revision: payload["revision"].as_u64().unwrap(),
        not_after_unix: payload["not_after_unix"].as_u64().unwrap(),
        dry_run: payload["dry_run"].as_bool().unwrap(),
        pools: payload["pools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| StoragePoolSpec {
                id: p["id"].as_str().unwrap().into(),
                path: p["path"].as_str().unwrap().into(),
                class: class(p["class"].as_str().unwrap()),
                budget_gb: u32::try_from(p["budget_gb"].as_u64().unwrap()).unwrap(),
                os_disks: p["os_disks"].as_bool().unwrap(),
                state: state(p["state"].as_str().unwrap()),
            })
            .collect(),
        dedicated_disks: payload["dedicated_disks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| DedicatedDiskSpec {
                id: d["id"].as_str().unwrap().into(),
                state: state(d["state"].as_str().unwrap()),
            })
            .collect(),
    }
}

#[test]
fn every_vector_decodes_into_the_agent_type() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
        let order: OrderBody<StorageConfigOrder> =
            ciborium::de::from_reader(body.as_slice()).unwrap();
        assert_eq!(order.domain, ORDER_DOMAIN, "{name}");
        assert_eq!(order.order_id, v["order_id"].as_str().unwrap(), "{name}");
        assert_eq!(
            order.target_miner_id,
            v["target_miner_id"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(order.payload, expected(&case["payload"]), "{name}");
    }
}

/// Add `key` to the map found by `path` inside the decoded body.
fn with_extra_key(body: &[u8], path: &[&str]) -> Vec<u8> {
    let mut v: Value = ciborium::de::from_reader(body).unwrap();
    let mut cursor = &mut v;
    for step in path {
        cursor = match cursor {
            Value::Map(entries) => {
                &mut entries
                    .iter_mut()
                    .find(|(k, _)| k.as_text() == Some(step))
                    .unwrap()
                    .1
            }
            Value::Array(items) => &mut items[step.parse::<usize>().unwrap()],
            _ => panic!("not a container at {step}"),
        };
    }
    let Value::Map(entries) = cursor else {
        panic!("not a map")
    };
    entries.push((Value::Text("unexpected".into()), Value::Bool(true)));
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).unwrap();
    out
}

#[test]
fn an_unknown_key_is_refused_at_every_level() {
    let v = vector();
    let body = hex::decode(v["cases"][0]["body_hex"].as_str().unwrap()).unwrap();
    for path in [
        &["payload"][..],
        &["payload", "pools", "0"][..],
        &["payload", "dedicated_disks", "0"][..],
    ] {
        let tampered = with_extra_key(&body, path);
        assert!(
            ciborium::de::from_reader::<OrderBody<StorageConfigOrder>, _>(tampered.as_slice())
                .is_err(),
            "{path:?}"
        );
    }
}
