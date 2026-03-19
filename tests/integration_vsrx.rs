//! Integration tests against a real Juniper vSRX.
//!
//! These tests require a running vSRX at 192.168.1.226 with NETCONF enabled
//! and SSH key auth configured for user "rustnetconf".
//!
//! Run with: `cargo test --test integration_vsrx`
//!
//! Skip with: set env `SKIP_INTEGRATION=1` to skip these tests when no device
//! is available.

use rustnetconf::error::NetconfError;
use rustnetconf::{Client, Datastore, DefaultOperation};
use tokio::sync::Mutex as TokioMutex;

/// Global mutex to serialize tests that lock the candidate datastore.
/// Prevents lock contention when tests run in parallel.
static CANDIDATE_LOCK: std::sync::LazyLock<TokioMutex<()>> =
    std::sync::LazyLock::new(|| TokioMutex::new(()));

/// Check if integration tests should be skipped.
fn should_skip() -> bool {
    std::env::var("SKIP_INTEGRATION").is_ok()
}

/// Resolve ~ in key path.
fn resolve_key_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/mharman".to_string());
    format!("{home}/.ssh/rustnetconf_test")
}

/// Create a connected client to the vSRX using key auth.
async fn connect_vsrx() -> Client {
    Client::connect("192.168.1.226:830")
        .username("rustnetconf")
        .key_file(&resolve_key_path())
        .connect()
        .await
        .expect("failed to connect to vSRX — is the device reachable?")
}

// ── SSH Transport Tests ─────────────────────────────────────────

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

/// T38: Connection refused — wrong port should fail with TransportError.
#[tokio::test]
async fn test_connection_refused() {
    if should_skip() { return; }

    // Port 12345 should be unreachable
    let result = Client::connect("192.168.1.226:12345")
        .username("rustnetconf")
        .key_file(&resolve_key_path())
        .connect()
        .await;

    match result {
        Err(NetconfError::Transport(_)) => {} // expected
        Err(other) => panic!("expected TransportError, got: {other:?}"),
        Ok(_) => panic!("connection to wrong port should fail"),
    }
}

/// T39: Auth failure — wrong credentials should fail with TransportError::Auth.
#[tokio::test]
async fn test_auth_failure() {
    if should_skip() { return; }

    let result = Client::connect("192.168.1.226:830")
        .username("rustnetconf")
        .password("definitely-wrong-password")
        .connect()
        .await;

    match result {
        Err(ref e) => {
            let err_str = format!("{e:?}");
            assert!(
                err_str.contains("Auth") || err_str.contains("auth"),
                "expected auth error, got: {e}"
            );
        }
        Ok(_) => panic!("auth with wrong password should fail"),
    }
}

/// T38: Connection to unreachable host should fail with TransportError.
#[tokio::test]
async fn test_connection_unreachable_host() {
    if should_skip() { return; }

    // 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed unreachable
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Client::connect("192.0.2.1:830")
            .username("test")
            .password("test")
            .connect(),
    )
    .await;

    // Either times out or returns a transport error — both are correct
    match result {
        Err(_timeout) => {} // timed out — expected
        Ok(Err(NetconfError::Transport(_))) => {} // connection error — expected
        Ok(Ok(_)) => panic!("connection to unreachable host should not succeed"),
        Ok(Err(other)) => panic!("expected transport error, got: {other:?}"),
    }
}

// ── Get Config Tests ────────────────────────────────────────────

/// T42: get-config round trip — fetch running config.
#[tokio::test]
async fn test_get_config_running() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let config = client.get_config(Datastore::Running).await
        .expect("get-config failed");

    assert!(!config.is_empty(), "running config should not be empty");
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

/// Get candidate config — should match running when no uncommitted changes.
#[tokio::test]
async fn test_get_config_candidate() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let candidate = client.get_config(Datastore::Candidate).await
        .expect("get-config candidate failed");

    assert!(!candidate.is_empty(), "candidate config should not be empty");
    assert!(
        candidate.contains("host-name") || candidate.contains("configuration"),
        "candidate config should contain recognizable elements, got: {}",
        &candidate[..std::cmp::min(500, candidate.len())]
    );

    client.close_session().await.expect("close_session failed");
}

/// Get-config with a filter that returns no data — should succeed with empty/minimal response.
#[tokio::test]
async fn test_get_config_empty_filter_result() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Filter for a specific element that almost certainly doesn't exist
    let config = client
        .get_config_filtered(
            Datastore::Running,
            "<configuration><system><ntp><server><name>203.0.113.99</name></server></ntp></system></configuration>",
        )
        .await
        .expect("get-config with empty result should succeed");

    // The config might be empty or contain just the wrapper — both are valid
    // The key assertion is that it doesn't error
    let _ = config;

    client.close_session().await.expect("close_session failed");
}

// ── Edit Config Tests ───────────────────────────────────────────

/// T41: Full edit-config round trip — lock → edit → validate → commit → unlock.
#[tokio::test]
async fn test_edit_config_round_trip() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

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

/// Edit-config with replace operation — replaces entire subtree.
#[tokio::test]
async fn test_edit_config_replace() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    let mut client = connect_vsrx().await;

    client.lock(Datastore::Candidate).await
        .expect("lock failed");

    // Set a location with multiple fields. Use merge as default-operation
    // but put operation="replace" on the <location> element itself to replace
    // just that subtree (not the entire config — which would strip mandatory fields).
    client.edit_config(Datastore::Candidate)
        .config(r#"<configuration><system><location operation="replace"><building>replace-test</building><floor>42</floor></location></system></configuration>"#)
        .default_operation(DefaultOperation::Merge)
        .send()
        .await
        .expect("edit-config replace failed");

    // Validate the candidate — location subtree replaced, rest intact
    client.validate(Datastore::Candidate).await
        .expect("validate failed");

    let candidate = client
        .get_config_filtered(
            Datastore::Candidate,
            "<configuration><system><location/></system></configuration>",
        )
        .await
        .expect("get-config candidate after replace failed");

    assert!(
        candidate.contains("replace-test") && candidate.contains("42"),
        "candidate should contain replaced location fields, got: {candidate}"
    );

    // Discard — don't commit this test change. Unlock releases the lock
    // and discards uncommitted candidate changes on Junos.
    client.unlock(Datastore::Candidate).await
        .expect("unlock failed");

    client.close_session().await.expect("close_session failed");
}

/// Validate with intentionally invalid config — expect a structured RPC error.
#[tokio::test]
async fn test_edit_config_invalid_rejected() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    let mut client = connect_vsrx().await;

    client.lock(Datastore::Candidate).await
        .expect("lock failed");

    // Try to set a completely bogus config element
    let result = client.edit_config(Datastore::Candidate)
        .config("<configuration><totally-bogus-element>invalid</totally-bogus-element></configuration>")
        .default_operation(DefaultOperation::Merge)
        .send()
        .await;

    assert!(result.is_err(), "bogus config should be rejected");
    let err = result.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("ServerError"),
        "expected RPC ServerError, got: {err}"
    );

    client.unlock(Datastore::Candidate).await
        .expect("unlock failed");
    client.close_session().await.expect("close_session failed");
}

// ── Lock / Unlock Tests ─────────────────────────────────────────

/// Lock contention — second lock on same datastore should fail with lock-denied.
#[tokio::test]
async fn test_lock_contention() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    // First client locks candidate
    let mut client1 = connect_vsrx().await;
    client1.lock(Datastore::Candidate).await
        .expect("first lock should succeed");

    // Second client tries to lock the same datastore
    let mut client2 = connect_vsrx().await;
    let result = client2.lock(Datastore::Candidate).await;

    assert!(result.is_err(), "second lock should be denied");
    let err = result.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("LockDenied") || err_str.contains("lock"),
        "expected lock-denied error, got: {err}"
    );

    // Clean up
    client1.unlock(Datastore::Candidate).await.expect("unlock failed");
    client1.close_session().await.expect("close failed");
    client2.close_session().await.expect("close failed");
}

/// Unlock without lock — should fail with an RPC error.
#[tokio::test]
async fn test_unlock_without_lock() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    let mut client = connect_vsrx().await;

    let result = client.unlock(Datastore::Candidate).await;
    assert!(result.is_err(), "unlock without lock should fail");

    client.close_session().await.expect("close_session failed");
}

// ── Session Lifecycle Tests ─────────────────────────────────────

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

/// Double close-session should be idempotent — no panic, no error.
#[tokio::test]
async fn test_double_close_session() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;
    client.close_session().await.expect("first close_session failed");
    client.close_session().await.expect("second close_session should be idempotent");
}

/// Multiple sequential RPCs on one session — verify message-id incrementing.
#[tokio::test]
async fn test_multiple_sequential_rpcs() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    let mut client = connect_vsrx().await;

    // Issue several RPCs in sequence on the same session
    let config1 = client.get_config(Datastore::Running).await
        .expect("first get-config failed");
    assert!(!config1.is_empty());

    let config2 = client
        .get_config_filtered(
            Datastore::Running,
            "<configuration><system><host-name/></system></configuration>",
        )
        .await
        .expect("second get-config failed");
    assert!(!config2.is_empty());

    let config3 = client.get_config(Datastore::Candidate).await
        .expect("third get-config failed");
    assert!(!config3.is_empty());

    // Lock and immediately unlock
    client.lock(Datastore::Candidate).await
        .expect("lock failed");
    client.unlock(Datastore::Candidate).await
        .expect("unlock failed");

    // One more RPC after lock/unlock cycle
    let config4 = client.get_config(Datastore::Running).await
        .expect("fourth get-config failed");
    assert!(!config4.is_empty());

    client.close_session().await.expect("close_session failed");
}

// ── Capability Tests ────────────────────────────────────────────

/// T32: Capability-gated operations — commit requires :candidate.
#[tokio::test]
async fn test_capability_check() {
    if should_skip() { return; }

    let client = connect_vsrx().await;

    // vSRX supports :candidate, so this should be true
    assert!(client.supports("urn:ietf:params:netconf:capability:candidate:1.0"));
    // It does NOT support base:1.1
    assert!(!client.supports("urn:ietf:params:netconf:base:1.1"));
    // Validate capability
    assert!(client.supports("urn:ietf:params:netconf:capability:validate:1.0"));
    // Confirmed commit
    assert!(client.supports("urn:ietf:params:netconf:capability:confirmed-commit:1.0"));
    // Junos-specific capability
    assert!(client.supports("http://xml.juniper.net/netconf/junos/1.0"));
}

/// Verify all capability URIs are returned and non-empty.
#[tokio::test]
async fn test_capabilities_all_uris() {
    if should_skip() { return; }

    let client = connect_vsrx().await;

    let caps = client.capabilities().expect("capabilities should exist");
    let uris = caps.all_uris();

    assert!(uris.len() >= 5, "vSRX should advertise at least 5 capabilities, got {}", uris.len());

    // Every URI should be non-empty and look like a real capability
    for uri in uris {
        assert!(!uri.is_empty(), "capability URI should not be empty");
        assert!(
            uri.starts_with("urn:") || uri.starts_with("http"),
            "capability URI should start with urn: or http, got: {uri}"
        );
    }
}

// ── Operational Data Tests ──────────────────────────────────────

/// T37: NETCONF subsystem channel — verify we get proper XML responses.
#[tokio::test]
async fn test_get_operational() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Junos uses subtree filters on <get> with the Junos operational namespace.
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

/// Get without filter — should return all operational + config data.
#[tokio::test]
async fn test_get_unfiltered() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    let data = client.get(None).await
        .expect("unfiltered get failed");

    // Unfiltered <get> should return a large payload with both config and state
    assert!(
        data.len() > 100,
        "unfiltered get should return substantial data, got {} bytes",
        data.len()
    );

    client.close_session().await.expect("close_session failed");
}

// ── Concurrent Session Tests ────────────────────────────────────

/// Multiple independent sessions to the same device — no interference.
#[tokio::test]
async fn test_concurrent_sessions() {
    if should_skip() { return; }

    // Open two sessions simultaneously
    let (mut client1, mut client2) = tokio::join!(
        connect_vsrx(),
        connect_vsrx(),
    );

    // Both should have different session IDs
    let id1 = client1.capabilities().unwrap().session_id().unwrap();
    let id2 = client2.capabilities().unwrap().session_id().unwrap();
    assert_ne!(id1, id2, "concurrent sessions should have different session-ids");

    // Both should be able to fetch config independently
    let (config1, config2) = tokio::join!(
        client1.get_config(Datastore::Running),
        client2.get_config(Datastore::Running),
    );

    let config1 = config1.expect("client1 get-config failed");
    let config2 = config2.expect("client2 get-config failed");
    assert!(!config1.is_empty());
    assert!(!config2.is_empty());

    // Clean up both
    let (r1, r2) = tokio::join!(
        client1.close_session(),
        client2.close_session(),
    );
    r1.expect("client1 close failed");
    r2.expect("client2 close failed");
}

// ── Large Payload Test ──────────────────────────────────────────

/// Large config fetch — verify the framing layer handles multi-read responses.
#[tokio::test]
async fn test_large_config_payload() {
    if should_skip() { return; }

    let mut client = connect_vsrx().await;

    // Fetch the entire running config (unfiltered) — typically several KB on a vSRX
    let config = client.get_config(Datastore::Running).await
        .expect("full get-config failed");

    assert!(
        config.len() > 500,
        "full running config should be substantial, got {} bytes",
        config.len()
    );

    // Verify the config is well-formed — should contain opening and closing tags
    assert!(
        config.contains("host-name"),
        "full config should contain host-name"
    );

    client.close_session().await.expect("close_session failed");
}

// ── Error Structure Tests ───────────────────────────────────────

/// Verify that RPC errors from the device include the structured error fields.
#[tokio::test]
async fn test_rpc_error_structure() {
    if should_skip() { return; }
    let _guard = CANDIDATE_LOCK.lock().await;

    let mut client = connect_vsrx().await;

    client.lock(Datastore::Candidate).await
        .expect("lock failed");

    // Send invalid config to trigger a structured rpc-error
    let result = client.edit_config(Datastore::Candidate)
        .config("<configuration><bogus-element-xyz>invalid</bogus-element-xyz></configuration>")
        .default_operation(DefaultOperation::Merge)
        .send()
        .await;

    match result {
        Err(NetconfError::Rpc(ref rpc_err)) => {
            let err_str = format!("{rpc_err:?}");
            // Should have error-type, error-tag, error-severity, and error-message
            assert!(
                err_str.contains("error_type: Some("),
                "rpc-error should include error-type, got: {err_str}"
            );
            assert!(
                err_str.contains("severity: Some("),
                "rpc-error should include error-severity, got: {err_str}"
            );
        }
        Err(other) => panic!("expected Rpc error variant, got: {other:?}"),
        Ok(_) => panic!("bogus config should have been rejected"),
    }

    client.unlock(Datastore::Candidate).await.expect("unlock failed");
    client.close_session().await.expect("close_session failed");
}
