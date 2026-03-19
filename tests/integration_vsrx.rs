//! Integration tests against a real Juniper vSRX.
//!
//! These tests require a running vSRX at 192.168.1.226 with NETCONF enabled
//! and SSH key auth configured for user "rustnetconf".
//!
//! Run with: `cargo test --test integration_vsrx`
//!
//! Skip with: set env `SKIP_INTEGRATION=1` to skip these tests when no device
//! is available.

use rustnetconf::{Client, Datastore, DefaultOperation};

/// Check if integration tests should be skipped.
fn should_skip() -> bool {
    std::env::var("SKIP_INTEGRATION").is_ok()
}

/// Resolve ~ in key path.
fn resolve_key_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/mharman".to_string());
    format!("{home}/.ssh/rustnetconf_test")
}

/// Create a connected client to the vSRX.
async fn connect_vsrx() -> Client {
    Client::connect("192.168.1.226:830")
        .username("rustnetconf")
        .key_file(&resolve_key_path())
        .connect()
        .await
        .expect("failed to connect to vSRX — is the device reachable?")
}

/// T34/T35: SSH connect + key auth, session establishment.
#[tokio::test]
async fn test_connect_and_hello() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Verify capabilities were negotiated
    let caps = client.capabilities().expect("no capabilities after connect");
    assert!(caps.has_candidate(), "vSRX should support :candidate");
    assert!(caps.has_validate(), "vSRX should support :validate");
    assert!(caps.has_confirmed_commit(), "vSRX should support :confirmed-commit");
    assert!(caps.session_id().is_some(), "session-id should be present");

    client.close_session().await.expect("close_session failed");
}

/// T42: get-config round trip — fetch running config.
#[tokio::test]
async fn test_get_config_running() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let config = client.get_config(Datastore::Running).await
        .expect("get-config failed");

    // vSRX running config should contain basic system config
    assert!(!config.is_empty(), "running config should not be empty");
    // Junos always has a version string in the config
    assert!(
        config.contains("host-name") || config.contains("version") || config.contains("configuration"),
        "running config should contain recognizable Junos elements, got: {}",
        &config[..std::cmp::min(500, config.len())]
    );

    client.close_session().await.expect("close_session failed");
}

/// T42: get-config with subtree filter.
#[tokio::test]
async fn test_get_config_filtered() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let config = client
        .get_config_filtered(
            Datastore::Running,
            "<configuration><system><host-name/></system></configuration>",
        )
        .await
        .expect("filtered get-config failed");

    assert!(
        config.contains("host-name") || config.contains("vSRX"),
        "filtered config should contain host-name, got: {config}"
    );

    client.close_session().await.expect("close_session failed");
}

/// T41: Full edit-config round trip — lock → edit → validate → commit → unlock.
#[tokio::test]
async fn test_edit_config_round_trip() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Lock candidate
    client.lock(Datastore::Candidate).await
        .expect("lock failed");

    // Edit config — set system location building (safe, reversible change).
    client.edit_config(Datastore::Candidate)
        .config("<configuration><system><location><building>rustnetconf-test-building</building></location></system></configuration>")
        .default_operation(DefaultOperation::Merge)
        .send()
        .await
        .expect("edit-config failed");

    // Validate
    client.validate(Datastore::Candidate).await
        .expect("validate failed");

    // Commit
    client.commit().await
        .expect("commit failed");

    // Verify the change is in running config
    let config = client
        .get_config_filtered(
            Datastore::Running,
            "<configuration><system><location/></system></configuration>",
        )
        .await
        .expect("get-config after commit failed");

    assert!(
        config.contains("rustnetconf-test-building"),
        "committed config should contain our building name, got: {config}"
    );

    // Clean up: remove the location building.
    // The candidate is still locked from our first lock — no need to re-lock.
    client.edit_config(Datastore::Candidate)
        .config(r#"<configuration><system><location><building operation="delete"/></location></system></configuration>"#)
        .default_operation(DefaultOperation::None)
        .send()
        .await
        .expect("cleanup edit-config failed");

    client.commit().await
        .expect("cleanup commit failed");

    client.unlock(Datastore::Candidate).await
        .expect("unlock failed");

    client.close_session().await.expect("close_session failed");
}

/// T32: Capability-gated operations — commit requires :candidate.
#[tokio::test]
async fn test_capability_check() {
    if should_skip() { return; }

    let client = connect_vsrx().await;

    // vSRX supports :candidate, so this should be true
    assert!(client.supports("urn:ietf:params:netconf:capability:candidate:1.0"));
    // It does NOT support base:1.1
    assert!(!client.supports("urn:ietf:params:netconf:base:1.1"));
}

/// T33: Operation after session closed should fail gracefully.
#[tokio::test]
async fn test_operation_after_close() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;
    client.close_session().await.expect("close_session failed");

    // Attempting get-config on a closed session should error
    let result = client.get_config(Datastore::Running).await;
    assert!(result.is_err(), "get-config on closed session should fail");
}

/// T37: NETCONF subsystem channel — verify we get proper XML responses.
#[tokio::test]
async fn test_get_operational() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Junos uses subtree filters on <get> with the Junos operational namespace.
    // Fetch system uptime info which is universally available.
    let data = client
        .get(Some(r#"<system-information xmlns="http://xml.juniper.net/junos/*/junos"/>"#))
        .await;

    // Some Junos versions may not support <get> with operational filters
    // the same way; if it fails, verify we at least get a structured error.
    match data {
        Ok(d) => assert!(!d.is_empty(), "operational data should not be empty"),
        Err(e) => {
            // A structured RPC error is acceptable — it proves the round trip works
            let err_str = format!("{e:?}");
            assert!(
                err_str.contains("ServerError") || err_str.contains("OperationFailed"),
                "expected structured error, got: {e}"
            );
        }
    }

    client.close_session().await.expect("close_session failed");
}
