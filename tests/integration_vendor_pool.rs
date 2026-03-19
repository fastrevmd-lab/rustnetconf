//! Integration tests for vendor profiles and connection pool against live vSRX.
//!
//! Run with: `cargo test --test integration_vendor_pool`

use rustnetconf::{Client, Datastore};
use rustnetconf::pool::{DeviceConfig, DevicePool};
use rustnetconf::transport::ssh::SshAuth;
use std::time::Duration;

fn should_skip() -> bool {
    std::env::var("SKIP_INTEGRATION").is_ok()
}

fn resolve_key_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/mharman".to_string());
    format!("{home}/.ssh/rustnetconf_test")
}

async fn connect_vsrx() -> Client {
    Client::connect("192.168.1.226:830")
        .username("rustnetconf")
        .key_file(&resolve_key_path())
        .connect()
        .await
        .expect("failed to connect to vSRX")
}

fn vsrx_device_config() -> DeviceConfig {
    DeviceConfig {
        host: "192.168.1.226:830".to_string(),
        username: "rustnetconf".to_string(),
        auth: SshAuth::KeyFile {
            path: resolve_key_path(),
            passphrase: None,
        },
        vendor: None,
    }
}

// ── Vendor Auto-Detection Tests ─────────────────────────────────

/// vSRX is auto-detected as Junos vendor.
#[tokio::test]
async fn test_vsrx_auto_detected_as_junos() {
    if should_skip() { return; }

    let client = connect_vsrx().await;
    assert_eq!(client.vendor_name(), "junos");
}

/// edit-config with Junos auto-wrapping — bare config gets <configuration> added.
#[tokio::test]
async fn test_edit_config_with_junos_auto_wrap() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;
    assert_eq!(client.vendor_name(), "junos");

    client.lock(Datastore::Candidate).await.expect("lock failed");

    // Send bare config WITHOUT <configuration> — Junos vendor adds it
    client.edit_config(Datastore::Candidate)
        .config("<system><location><building>vendor-wrap-test</building></location></system>")
        .default_operation(rustnetconf::DefaultOperation::Merge)
        .send()
        .await
        .expect("edit-config with auto-wrap should succeed");

    let config = client
        .get_config_filtered(
            Datastore::Candidate,
            "<configuration><system><location/></system></configuration>",
        )
        .await
        .expect("get-config failed");

    assert!(config.contains("vendor-wrap-test"), "should contain our building, got: {config}");

    client.unlock(Datastore::Candidate).await.expect("unlock failed");
    client.close_session().await.expect("close failed");
}

/// get-config with Junos unwrapping strips <configuration> wrapper.
#[tokio::test]
async fn test_get_config_junos_unwrap() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let config = client
        .get_config_filtered(
            Datastore::Running,
            "<configuration><system><host-name/></system></configuration>",
        )
        .await
        .expect("get-config failed");

    assert!(config.contains("host-name"), "should contain host-name, got: {config}");
    assert!(
        !config.trim().starts_with("<configuration"),
        "Junos vendor should strip <configuration> wrapper, got: {config}"
    );
}

// ── Connection Pool Tests ───────────────────────────────────────

/// Pool checkout + use + auto-checkin.
#[tokio::test]
async fn test_pool_checkout_and_use() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(5)
        .add_device("vsrx", vsrx_device_config())
        .build();

    {
        let mut conn = pool.checkout("vsrx").await.expect("checkout failed");
        let config = conn.get_config(Datastore::Running).await.expect("get-config failed");
        assert!(!config.is_empty());
    } // conn returned to pool here

    assert_eq!(pool.available_connections(), 5, "permit should be released after drop");
}

/// Pool reuses connections on second checkout.
#[tokio::test]
async fn test_pool_connection_reuse() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(5)
        .add_device("vsrx", vsrx_device_config())
        .build();

    // First checkout + use + checkin
    {
        let mut conn = pool.checkout("vsrx").await.expect("first checkout failed");
        conn.get_config(Datastore::Running).await.expect("first get-config failed");
    }

    // Small delay to let the drop task complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second checkout should reuse the connection (no new SSH handshake)
    {
        let mut conn = pool.checkout("vsrx").await.expect("second checkout failed");
        conn.get_config(Datastore::Running).await.expect("second get-config failed (reused)");
    }
}

/// Pool returns error for unknown device.
#[tokio::test]
async fn test_pool_unknown_device() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(5)
        .add_device("vsrx", vsrx_device_config())
        .build();

    let result = pool.checkout("nonexistent").await;
    assert!(result.is_err(), "unknown device should fail");
}

/// Pool checkout times out when all connections in use.
#[tokio::test]
async fn test_pool_checkout_timeout() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(1)
        .checkout_timeout(Duration::from_secs(2))
        .add_device("vsrx", vsrx_device_config())
        .build();

    // Hold a connection
    let _guard = pool.checkout("vsrx").await.expect("first checkout failed");

    // Second checkout should timeout
    let result = pool.checkout("vsrx").await;
    assert!(result.is_err(), "should timeout with max_connections=1");
}

/// Concurrent pool checkouts to same device.
#[tokio::test]
async fn test_pool_concurrent_checkouts() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(3)
        .add_device("vsrx", vsrx_device_config())
        .build();

    // Checkout 2 connections concurrently
    let (r1, r2) = tokio::join!(
        pool.checkout("vsrx"),
        pool.checkout("vsrx"),
    );

    let mut conn1 = r1.expect("conn1 checkout failed");
    let mut conn2 = r2.expect("conn2 checkout failed");

    // Both should work independently
    let (c1, c2) = tokio::join!(
        conn1.get_config(Datastore::Running),
        conn2.get_config(Datastore::Running),
    );

    assert!(!c1.expect("conn1 get-config failed").is_empty());
    assert!(!c2.expect("conn2 get-config failed").is_empty());

    assert_eq!(pool.available_connections(), 1, "2 of 3 permits in use");
}

/// Pool auto-detects Junos vendor on connections.
#[tokio::test]
async fn test_pool_auto_detects_vendor() {
    if should_skip() { return; }

    let pool = DevicePool::builder()
        .max_connections(5)
        .add_device("vsrx", vsrx_device_config())
        .build();

    let conn = pool.checkout("vsrx").await.expect("checkout failed");
    assert_eq!(conn.vendor_name(), "junos", "pool connection should auto-detect Junos");
}
