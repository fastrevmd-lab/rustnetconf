#![no_main]
//! `validate_xml_fragment` accepting a fragment must mean the fragment can be
//! embedded in an RPC without breaking the document.
//!
//! The validator is a *validate-then-trust* guard: callers pass its output
//! straight into a `format!`-built envelope, so anything it accepts is spliced
//! in verbatim. If it can accept a string that then makes the surrounding
//! document unparseable, every caller inherits that.
//!
//! This is the property that matters, and the direction that is dangerous.
//! The reverse — the validator rejecting something a parser would accept — is a
//! usability question, not a safety one, and it is deliberately true today: the
//! validator refuses `<?xml ...?>` and `<!DOCTYPE ...>` precisely because they
//! parse fine alone and break things when embedded.

use libfuzzer_sys::fuzz_target;
use quick_xml::events::Event;
use quick_xml::Reader;
use rustnetconf::rpc::validate_xml_fragment;

/// Parse a whole document, returning whether it is well-formed.
fn parses(doc: &str) -> bool {
    let mut reader = Reader::from_str(doc);
    reader.config_mut().check_end_names = true;
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            _ => {}
        }
    }
}

fuzz_target!(|data: &str| {
    if validate_xml_fragment(data).is_err() {
        return;
    }

    // The shape callers actually build: the fragment spliced inside an RPC that
    // already has its own declaration and namespace.
    let embedded = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <nc:edit-config>
    <nc:config>{data}</nc:config>
  </nc:edit-config>
</nc:rpc>"#
    );

    assert!(
        parses(&embedded),
        "validate_xml_fragment accepted a fragment that does not embed cleanly:\n\
         fragment: {data:?}"
    );
});
