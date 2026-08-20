//! `MockLibvirtDriver` behaviour tests.
//!
//! The production `VirshDriver` needs a real libvirt host, so it is
//! out of scope here (live libvirt testing is deliberately not part
//! of PR-MA-3). The mock is what the lifecycle state-machine tests
//! run against, so its transitions are pinned.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_miner_agent::lifecycle::{DomainId, DomainState, LibvirtDriver, MockLibvirtDriver};

const DOMAIN_XML: &str = "<domain><name>hippius-tenant-mock-1</name></domain>";

#[tokio::test]
async fn define_create_query_destroy_cycle() {
    let driver = MockLibvirtDriver::new();

    let id = driver.define_domain(DOMAIN_XML).await.unwrap();
    assert_eq!(id.as_str(), "hippius-tenant-mock-1");
    // Defined but not started.
    assert_eq!(
        driver.query_domain_state(&id).await.unwrap(),
        DomainState::ShutOff
    );

    driver.create_domain(&id).await.unwrap();
    assert_eq!(
        driver.query_domain_state(&id).await.unwrap(),
        DomainState::Running
    );

    driver.destroy_domain(&id, false).await.unwrap();
    assert_eq!(
        driver.query_domain_state(&id).await.unwrap(),
        DomainState::ShutOff
    );
}

#[tokio::test]
async fn post_create_state_is_configurable() {
    // `Paused` / `Crashed` drive the lifecycle's timeout + failed
    // paths; the mock must surface exactly what it was told.
    let driver = MockLibvirtDriver::with_post_create_state(DomainState::Paused);
    let id = driver.define_domain(DOMAIN_XML).await.unwrap();
    driver.create_domain(&id).await.unwrap();
    assert_eq!(
        driver.query_domain_state(&id).await.unwrap(),
        DomainState::Paused
    );
}

#[tokio::test]
async fn list_domains_reports_every_defined_domain() {
    let driver = MockLibvirtDriver::new();
    driver
        .define_domain("<domain><name>hippius-tenant-a</name></domain>")
        .await
        .unwrap();
    driver
        .define_domain("<domain><name>hippius-tenant-b</name></domain>")
        .await
        .unwrap();

    let mut names: Vec<String> = driver
        .list_domains()
        .await
        .unwrap()
        .into_iter()
        .map(|(id, _)| id.as_str().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["hippius-tenant-a", "hippius-tenant-b"]);
    assert_eq!(driver.defined_count().unwrap(), 2);
}

#[tokio::test]
async fn operations_on_an_unknown_domain_fail_closed() {
    let driver = MockLibvirtDriver::new();
    let ghost = DomainId::new("hippius-tenant-ghost").unwrap();
    assert!(driver.create_domain(&ghost).await.is_err());
    assert!(driver.destroy_domain(&ghost, false).await.is_err());
    assert!(driver.query_domain_state(&ghost).await.is_err());
}

#[tokio::test]
async fn define_rejects_xml_without_a_name() {
    let driver = MockLibvirtDriver::new();
    assert!(driver.define_domain("<domain></domain>").await.is_err());
    assert_eq!(driver.defined_count().unwrap(), 0);
}
