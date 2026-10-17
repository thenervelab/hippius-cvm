//! `move-vm-storage` wire shape: every ticket-validator encoded body in
//! `test_vectors/orders/move_vm_storage_v1.json` decodes into the agent's
//! `MoveVmStorageOrder` exactly as the payload says, and an unknown key is
//! refused at decode.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ciborium::value::Value;
use hippius_miner_agent::orders::{MoveAction, MoveVmStorageOrder, OrderBody, ORDER_DOMAIN};
use hippius_miner_agent::VmId;

fn vector() -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/move_vm_storage_v1.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

fn expected(p: &serde_json::Value) -> MoveVmStorageOrder {
    MoveVmStorageOrder {
        vm_id: VmId::new(p["vm_id"].as_str().unwrap()).unwrap(),
        move_id: p["move_id"].as_str().unwrap().into(),
        action: match p["action"].as_str().unwrap() {
            "start" => MoveAction::Start,
            "cancel" => MoveAction::Cancel,
            "release" => MoveAction::Release,
            "status" => MoveAction::Status,
            other => panic!("action {other}"),
        },
        target_pool: p["target_pool"].as_str().map(String::from),
        expected_source_pool: p["expected_source_pool"].as_str().map(String::from),
        bandwidth_mib_s: p["bandwidth_mib_s"]
            .as_u64()
            .map(|b| u32::try_from(b).unwrap()),
        not_after_unix: p["not_after_unix"].as_u64().unwrap(),
    }
}

#[test]
fn every_vector_body_decodes_into_the_agent_type() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
        let order: OrderBody<MoveVmStorageOrder> =
            ciborium::de::from_reader(body.as_slice()).unwrap();
        assert_eq!(order.domain, ORDER_DOMAIN);
        assert_eq!(order.order_id, v["order_id"].as_str().unwrap());
        assert_eq!(
            order.payload,
            expected(&case["payload"]),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn an_unknown_key_is_refused_at_decode() {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![
            (Value::Text("vm_id".into()), Value::Text("tenant-1".into())),
            (Value::Text("move_id".into()), Value::Text("0".repeat(32))),
            (Value::Text("action".into()), Value::Text("status".into())),
            (
                Value::Text("not_after_unix".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("priority".into()), Value::Integer(1.into())),
        ]),
        &mut payload,
    )
    .unwrap();
    assert!(ciborium::de::from_reader::<MoveVmStorageOrder, _>(payload.as_slice()).is_err());
}

fn decode(fields: &[(&str, Value)]) -> Result<MoveVmStorageOrder, String> {
    let mut map = vec![
        (Value::Text("vm_id".into()), Value::Text("tenant-1".into())),
        (Value::Text("move_id".into()), Value::Text("ab".repeat(16))),
        (
            Value::Text("not_after_unix".into()),
            Value::Integer(0.into()),
        ),
    ];
    for (k, v) in fields {
        map.retain(|(key, _)| key.as_text() != Some(k));
        map.push((Value::Text((*k).into()), v.clone()));
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
    ciborium::de::from_reader::<MoveVmStorageOrder, _>(buf.as_slice()).map_err(|e| e.to_string())
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

#[test]
fn what_the_encoder_refuses_is_refused_at_decode() {
    let start = |pool: &str, src: &str, bw: u64| {
        vec![
            ("action", text("start")),
            ("target_pool", text(pool)),
            ("expected_source_pool", text(src)),
            ("bandwidth_mib_s", Value::Integer(bw.into())),
        ]
    };
    assert!(decode(&start("nvme0", "default", 200)).is_ok());
    for (fields, why) in [
        (start("nvme0", "default", 0), "bad-move-bandwidth"),
        (start("nvme0", "default", 1001), "bad-move-bandwidth"),
        (start("NVMe", "default", 200), "bad-move-pool"),
        (start("default", "default", 200), "move-same-pool"),
        (vec![("action", text("start"))], "move-start-field-missing"),
        (
            start("nvme0", "default", 200)[..3].to_vec(),
            "move-start-field-missing",
        ),
        (
            vec![("action", text("status")), ("target_pool", text("nvme0"))],
            "move-start-field-on-other-action",
        ),
        (
            vec![
                ("action", text("release")),
                ("bandwidth_mib_s", Value::Integer(200.into())),
            ],
            "move-start-field-on-other-action",
        ),
        (
            vec![
                ("action", text("status")),
                ("move_id", text(&"AB".repeat(16))),
            ],
            "bad-move-id",
        ),
        (
            vec![
                ("action", text("status")),
                ("move_id", text(&"a".repeat(31))),
            ],
            "bad-move-id",
        ),
        (
            vec![
                ("action", text("status")),
                ("move_id", text(&format!("{}g", "a".repeat(31)))),
            ],
            "bad-move-id",
        ),
    ] {
        let err = decode(&fields).unwrap_err();
        assert!(err.contains(why), "{why}: {err}");
    }
}
