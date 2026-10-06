//! Integration tests for the public AF_VSOCK relay API (MA-4) — CID
//! allocation and the guest-frame relay loop.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use hippius_miner_agent::vsock::{
    handle_guest_conn, relay_guest_frames, write_frame, CidAllocator, GuestFrame, GuestPeer,
    RelayOutcome, MAX_VSOCK_FRAME, MIN_GUEST_CID,
};
use hippius_miner_agent::{EdgeClient, EnvelopeKind, VmId};

fn edge() -> EdgeClient {
    EdgeClient::insecure_for_tests("http://127.0.0.1:1".to_string())
}

#[test]
fn cid_allocation_is_collision_free_and_deterministic() {
    let alloc = CidAllocator::new();
    let a = alloc.allocate(&VmId::new("tenant-a").unwrap()).unwrap();
    let b = alloc.allocate(&VmId::new("tenant-b").unwrap()).unwrap();
    // Distinct tenants never share a CID...
    assert_ne!(a, b);
    // ...and re-requesting a tenant returns its same CID.
    assert_eq!(alloc.allocate(&VmId::new("tenant-a").unwrap()).unwrap(), a);
    // The first guest CID respects the ABI-reserved 0/1/2.
    assert_eq!(a, MIN_GUEST_CID);
}

#[test]
fn a_released_cid_is_reused_and_resolves_correctly() {
    let alloc = CidAllocator::new();
    let vm = VmId::new("tenant-x").unwrap();
    let cid = alloc.allocate(&vm).unwrap();
    // An identity once the launch's `create_domain` marks it verified.
    assert!(alloc.mark_verified(&vm, cid).unwrap());
    assert_eq!(alloc.vm_id_for_cid(cid).unwrap(), Some(vm.clone()));

    alloc.release(&vm).unwrap();
    assert_eq!(alloc.vm_id_for_cid(cid).unwrap(), None);
    // The freed slot is handed to the next tenant.
    assert_eq!(
        alloc.allocate(&VmId::new("tenant-y").unwrap()).unwrap(),
        cid
    );
}

#[tokio::test]
async fn the_relay_loop_drains_every_frame_to_clean_eof() {
    let (mut writer, mut reader) = tokio::io::duplex(16384);
    for _ in 0..5 {
        write_frame(
            &mut writer,
            &GuestFrame::new(EnvelopeKind::KbsRequest, vec![1u8; 64]),
        )
        .await
        .unwrap();
    }
    drop(writer);

    let peer = GuestPeer {
        cid: MIN_GUEST_CID,
        vm_id: VmId::new("tenant-relay").unwrap(),
    };
    let report = relay_guest_frames(
        &mut reader,
        &peer,
        &edge(),
        MAX_VSOCK_FRAME,
        Duration::from_secs(5),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(report.frames_read, 5);
    assert_eq!(report.outcome, RelayOutcome::Closed);
}

#[tokio::test]
async fn handle_guest_conn_rejects_a_cid_the_allocator_never_assigned() {
    // An inbound connection on a CID with no tracked CVM must be
    // dropped without relaying — a guest cannot speak under an
    // identity the miner-agent did not hand it.
    let allocator = Arc::new(CidAllocator::new());
    let (mut writer, reader) = tokio::io::duplex(4096);
    write_frame(
        &mut writer,
        &GuestFrame::new(EnvelopeKind::ServedReceipt, vec![9u8; 8]),
    )
    .await
    .unwrap();

    // Completes promptly (rejected at the CID check, no relay loop).
    tokio::time::timeout(
        Duration::from_secs(5),
        handle_guest_conn(reader, 4242, &allocator, &edge(), CancellationToken::new()),
    )
    .await
    .expect("unknown-CID rejection must not hang");
}

#[tokio::test]
async fn handle_guest_conn_relays_a_known_cid_session() {
    let allocator = Arc::new(CidAllocator::new());
    let vm = VmId::new("tenant-known").unwrap();
    let cid = allocator.allocate(&vm).unwrap();
    // Known = created: a fresh allocation is not an identity until then.
    assert!(allocator.mark_verified(&vm, cid).unwrap());

    let (mut writer, reader) = tokio::io::duplex(8192);
    write_frame(
        &mut writer,
        &GuestFrame::new(EnvelopeKind::StoppedAck, vec![2u8; 32]),
    )
    .await
    .unwrap();
    drop(writer);

    tokio::time::timeout(
        Duration::from_secs(5),
        handle_guest_conn(reader, cid, &allocator, &edge(), CancellationToken::new()),
    )
    .await
    .expect("a known-CID relay session must terminate at EOF");
}
