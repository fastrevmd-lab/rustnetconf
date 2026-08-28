#![no_main]
//! `parse_rpc_reply` must terminate with a `Result` on any input at all.
//!
//! This is the one function in the crate that consumes fully device-controlled
//! bytes, and a panic there is reachable by any device on the management
//! network — a malformed reply should be an `Err`, never an abort. The
//! partial-lock work found a long tail of silent misparses in this layer
//! (foreign namespaces, unstitched entity refs, mixed content, undeclarations);
//! this target covers the coarser property that none of them become a crash.

use libfuzzer_sys::fuzz_target;
use rustnetconf::rpc::parse_rpc_reply;

fuzz_target!(|data: &str| {
    // Both an arbitrary message-id and the common one: the id is compared
    // against the reply's attribute, so it steers a different path.
    let _ = parse_rpc_reply(data, "1");
    let _ = parse_rpc_reply(data, "");
});
