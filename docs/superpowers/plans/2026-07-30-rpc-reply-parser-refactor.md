# RPC Reply Parser Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the correctness-critical RPC reply parser with an explicit streaming state machine that preserves public APIs, retains supported NETCONF and Junos behavior, and rejects unsafe or ambiguous malformed replies.

**Architecture:** Move reply parsing into a private `rpc::reply` module with separate XML capture, parser, and Junos repair responsibilities. Keep `quick_xml` streaming, parse each reply once, validate explicit state transitions, and run a narrowly scoped repair only for the captured chassis-cluster commit-check defect.

**Tech Stack:** Rust 2021, `quick-xml` 0.41, existing `thiserror`-based `RpcError`, built-in Rust tests and Cargo tooling.

## Global Constraints

- Keep `rustnetconf::rpc::{parse_rpc_reply, RpcErrorInfo, RpcReply}` source-compatible.
- Keep the root-level `rustnetconf::RpcErrorInfo` re-export source-compatible.
- Add no public error variants and no new dependencies.
- Keep `quick-xml` at version `0.41`.
- Preserve qualified names, namespace declarations, attributes, entities, CDATA semantics, nested `<error-info>`, warnings, and direct Junos payloads.
- Require exactly one matching `message-id`.
- Continue accepting a valid empty `<rpc-reply message-id="..."/>` as `RpcReply::Ok`.
- Repair only an unclosed `<routing-engine>` in a supported chassis-cluster commit-check context with a real closing `<rpc-reply>`.
- Never include the complete device reply in parse-error messages.
- Follow red-green-refactor for every behavior change.

## File Map

- Create `tests/rpc_reply_contract.rs`: public API and behavior characterization tests.
- Modify `src/rpc/mod.rs`: retain XML-fragment validation and re-export the private reply module.
- Create `src/rpc/reply/mod.rs`: public reply types, parser orchestration, and private submodule declarations.
- Create `src/rpc/reply/capture.rs`: one XML-fragment reconstruction implementation.
- Create `src/rpc/reply/parser.rs`: explicit reply state machine and RPC-error builder.
- Create `src/rpc/reply/repair.rs`: narrow chassis-cluster commit-check repair.
- Keep `src/error.rs`, `src/types.rs`, `src/session.rs`, and `src/client.rs` unchanged.

---

### Task 1: Lock Down the Public Reply Contract

**Files:**
- Create: `tests/rpc_reply_contract.rs`

**Interfaces:**
- Consumes: `rustnetconf::rpc::parse_rpc_reply(&str, &str) -> Result<RpcReply, RpcError>`.
- Produces: an external contract suite that remains unchanged while internals move.

- [ ] **Step 1: Add the public contract tests**

Create `tests/rpc_reply_contract.rs`:

```rust
use rustnetconf::error::RpcError;
use rustnetconf::rpc::{parse_rpc_reply, RpcReply};
use rustnetconf::types::ErrorTag;

#[test]
fn public_ok_reply_contract() {
    let xml = r#"<nc:rpc-reply
        xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="41"><nc:ok/></nc:rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "41").expect("valid ok reply");
    assert!(matches!(reply, RpcReply::Ok));
}

#[test]
fn public_data_reply_preserves_xml_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="42">
        <data>
          <if:interfaces xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">
            <if:interface note='uplink &amp; "core"'>
              <if:name>ge-0/0/0</if:name>
            </if:interface>
          </if:interfaces>
        </data>
      </rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "42").expect("valid data reply");
    let RpcReply::Data(data) = reply else {
        panic!("expected Data");
    };

    assert!(data.contains("<if:interfaces"));
    assert!(data.contains("xmlns:if="));
    assert!(data.contains("<if:name>ge-0/0/0</if:name>"));
    rustnetconf::rpc::validate_xml_fragment(&data).expect("captured XML is well formed");
}

#[test]
fn public_direct_payload_aggregates_siblings_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="43">
        <output>first</output>
        <warnings><warning>second</warning></warnings>
      </rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "43").expect("valid direct payload");
    let RpcReply::Data(data) = reply else {
        panic!("expected Data");
    };

    assert!(data.contains("<output>first</output>"));
    assert!(data.contains("<warnings><warning>second</warning></warnings>"));
}

#[test]
fn public_hard_error_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="44">
        <rpc-error>
          <error-type>application</error-type>
          <error-tag>invalid-value</error-tag>
          <error-severity>error</error-severity>
          <error-message>invalid interface</error-message>
        </rpc-error>
      </rpc-reply>"#;

    let error = parse_rpc_reply(xml, "44").expect_err("hard error must fail");
    match error {
        RpcError::ServerError { tag, message, .. } => {
            assert_eq!(tag, ErrorTag::InvalidValue);
            assert_eq!(message, "invalid interface");
        }
        other => panic!("expected ServerError, got {other:?}"),
    }
}

#[test]
fn public_empty_reply_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="45"></rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "45").expect("valid empty reply");
    assert!(matches!(reply, RpcReply::Ok));
}
```

- [ ] **Step 2: Run the contract suite**

Run:

```bash
cargo test -p rustnetconf --test rpc_reply_contract
```

Expected: 5 tests pass. If any test fails against the existing parser, correct
only the test fixture so it represents behavior already supported by `main`.

- [ ] **Step 3: Run the existing RPC parser tests**

Run:

```bash
cargo test -p rustnetconf rpc::tests
```

Expected: all existing `rpc::tests` and `rpc::xml_validate_tests` pass.

- [ ] **Step 4: Commit**

```bash
git add tests/rpc_reply_contract.rs
git commit -m "test(rpc): lock down reply parser contract"
```

---

### Task 2: Extract the Private Reply Module Without Behavior Changes

**Files:**
- Create: `src/rpc/reply/mod.rs`
- Modify: `src/rpc/mod.rs`

**Interfaces:**
- Consumes: the current `RpcReply`, `RpcErrorInfo`, and
  `parse_rpc_reply()` implementations in `src/rpc/mod.rs`.
- Produces: private module `rpc::reply` and unchanged public re-exports from
  `rpc`.

- [ ] **Step 1: Add a compile-time public-path assertion**

Append this test to `tests/rpc_reply_contract.rs`:

```rust
#[test]
fn public_reply_type_paths_remain_available() {
    fn accepts_reply(_: rustnetconf::rpc::RpcReply) {}
    fn accepts_info(_: rustnetconf::rpc::RpcErrorInfo) {}
    fn accepts_root_info(_: rustnetconf::RpcErrorInfo) {}

    let _ = accepts_reply as fn(rustnetconf::rpc::RpcReply);
    let _ = accepts_info as fn(rustnetconf::rpc::RpcErrorInfo);
    let _ = accepts_root_info as fn(rustnetconf::RpcErrorInfo);
}
```

- [ ] **Step 2: Run the path assertion before moving code**

Run:

```bash
cargo test -p rustnetconf --test rpc_reply_contract public_reply_type_paths_remain_available
```

Expected: PASS, proving the paths that the refactor must preserve.

- [ ] **Step 3: Move reply-specific definitions**

In `src/rpc/mod.rs`, leave `filter`, `operations`,
`validate_xml_fragment()`, and `xml_validate_tests` in place. Move the
following definitions, helpers, and reply tests into
`src/rpc/reply/mod.rs` without changing their bodies:

```text
RpcReply
RpcErrorInfo
reescape_attr_value
local_name_of
repair_unclosed_routing_engine
parse_rpc_reply_strict
parse_rpc_reply
ErrorField
RpcErrorBuilder
extract_rpc_reply_inner_content
tests
```

At the top of `src/rpc/reply/mod.rs`, use these imports:

```rust
use crate::error::RpcError;
use crate::rpc::operations::escape_xml_text;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};
```

Where moved tests call XML validation, import its stable parent path:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::validate_xml_fragment;
}
```

Add the module and re-exports to `src/rpc/mod.rs` immediately after
`pub mod operations;`:

```rust
mod reply;

pub use reply::{parse_rpc_reply, RpcErrorInfo, RpcReply};
```

Remove imports from `src/rpc/mod.rs` that are now used only by
`src/rpc/reply/mod.rs`.

- [ ] **Step 4: Verify module extraction**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rustnetconf --test rpc_reply_contract
cargo test -p rustnetconf rpc::reply::tests
```

Expected: formatting passes; 6 public contract tests and all moved reply tests
pass without behavior changes.

- [ ] **Step 5: Commit**

```bash
git add src/rpc/mod.rs src/rpc/reply/mod.rs tests/rpc_reply_contract.rs
git commit -m "refactor(rpc): isolate reply parsing module"
```

---

### Task 3: Introduce One XML Fragment Capture Implementation

**Files:**
- Create: `src/rpc/reply/capture.rs`
- Modify: `src/rpc/reply/mod.rs`

**Interfaces:**
- Consumes: `quick_xml` event types and
  `rpc::operations::{escape_xml_attr, escape_xml_text}`.
- Produces:
  `FragmentCapture::{start, empty, end, text, cdata, entity, finish}` and
  `decode_attribute(&[u8]) -> Result<String, RpcError>`.

- [ ] **Step 1: Write capture tests**

Create `src/rpc/reply/capture.rs` with the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    fn capture_children(xml: &str) -> Result<String, RpcError> {
        let mut reader = Reader::from_str(xml);
        let mut capture = FragmentCapture::default();
        let mut depth = 0usize;

        loop {
            match reader.read_event() {
                Ok(Event::Start(tag)) if depth == 0 => depth = 1,
                Ok(Event::Start(tag)) => {
                    depth += 1;
                    capture.start(&tag)?;
                }
                Ok(Event::Empty(tag)) if depth > 0 => capture.empty(&tag)?,
                Ok(Event::Text(text)) if depth > 0 => capture.text(&text)?,
                Ok(Event::CData(cdata)) if depth > 0 => capture.cdata(&cdata)?,
                Ok(Event::GeneralRef(entity)) if depth > 0 => capture.entity(&entity)?,
                Ok(Event::End(_)) if depth == 1 => break,
                Ok(Event::End(tag)) if depth > 1 => {
                    capture.end(&tag)?;
                    depth -= 1;
                }
                Ok(Event::Eof) => {
                    return Err(RpcError::ParseError(
                        "test fragment ended before its root closed".to_string(),
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(RpcError::ParseError(format!(
                        "test XML parse error: {error}"
                    )));
                }
            }
        }

        capture.finish()
    }

    #[test]
    fn preserves_namespaces_attributes_entities_and_cdata() {
        let xml = r#"<root>
          <if:item xmlns:if="urn:example:if" note='core &amp; "edge"'>
            A &amp; B <![CDATA[<raw>]]>
          </if:item>
        </root>"#;

        let captured = capture_children(xml).expect("capture succeeds");
        assert!(captured.contains("<if:item"));
        assert!(captured.contains("xmlns:if=\"urn:example:if\""));
        assert!(captured.contains("note=\"core &amp; &quot;edge&quot;\""));
        assert!(captured.contains("A &amp; B"));
        assert!(captured.contains("&lt;raw&gt;"));
        crate::rpc::validate_xml_fragment(&captured).expect("captured XML is valid");
    }

    #[test]
    fn malformed_attribute_entity_is_an_error() {
        let xml = r#"<root><item note="bad &unknown; value"/></root>"#;
        let error = capture_children(xml).expect_err("unknown entity must fail");
        assert!(matches!(error, RpcError::ParseError(_)));
        assert!(error.to_string().contains("attribute"));
    }
}
```

- [ ] **Step 2: Run tests to verify the capture type is missing**

Run:

```bash
cargo test -p rustnetconf rpc::reply::capture::tests
```

Expected: compilation fails because `FragmentCapture` is not defined.

- [ ] **Step 3: Implement `FragmentCapture`**

Add this production code above the tests in `capture.rs`:

```rust
use crate::error::RpcError;
use crate::rpc::operations::{escape_xml_attr, escape_xml_text};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText};
use std::str;

#[derive(Debug, Default)]
pub(super) struct FragmentCapture {
    xml: String,
}

impl FragmentCapture {
    pub(super) fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, false)
    }

    pub(super) fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.write_start_like(tag, true)
    }

    pub(super) fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        let name = str::from_utf8(tag.name().as_ref())
            .map_err(|error| parse_error(format!("invalid end-tag name: {error}")))?;
        self.xml.push_str("</");
        self.xml.push_str(name);
        self.xml.push('>');
        Ok(())
    }

    pub(super) fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        let decoded = text
            .decode()
            .map_err(|error| parse_error(format!("invalid text encoding: {error}")))?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn cdata(&mut self, cdata: &BytesCData<'_>) -> Result<(), RpcError> {
        let decoded = cdata
            .decode()
            .map_err(|error| parse_error(format!("invalid CDATA encoding: {error}")))?;
        self.xml.push_str(&escape_xml_text(&decoded));
        Ok(())
    }

    pub(super) fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        let decoded = entity
            .decode()
            .map_err(|error| parse_error(format!("invalid entity encoding: {error}")))?;
        self.xml.push('&');
        self.xml.push_str(&decoded);
        self.xml.push(';');
        Ok(())
    }

    pub(super) fn finish(self) -> Result<String, RpcError> {
        Ok(self.xml)
    }

    fn write_start_like(
        &mut self,
        tag: &BytesStart<'_>,
        empty: bool,
    ) -> Result<(), RpcError> {
        let binding = tag.name();
        let name = str::from_utf8(binding.as_ref())
            .map_err(|error| parse_error(format!("invalid start-tag name: {error}")))?;
        self.xml.push('<');
        self.xml.push_str(name);

        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            let key = str::from_utf8(attribute.key.as_ref())
                .map_err(|error| parse_error(format!("invalid attribute name: {error}")))?;
            let value = decode_attribute(attribute.value.as_ref())?;

            self.xml.push(' ');
            self.xml.push_str(key);
            self.xml.push_str("=\"");
            self.xml.push_str(&escape_xml_attr(&value));
            self.xml.push('"');
        }

        if empty {
            self.xml.push_str("/>");
        } else {
            self.xml.push('>');
        }
        Ok(())
    }
}

pub(super) fn decode_attribute(raw: &[u8]) -> Result<String, RpcError> {
    let raw = str::from_utf8(raw)
        .map_err(|error| parse_error(format!("invalid attribute encoding: {error}")))?;
    quick_xml::escape::unescape(raw)
        .map(|value| value.into_owned())
        .map_err(|error| parse_error(format!("invalid attribute value: {error}")))
}

fn parse_error(message: String) -> RpcError {
    RpcError::ParseError(message)
}
```

Declare the module near the top of `src/rpc/reply/mod.rs`:

```rust
mod capture;
```

- [ ] **Step 4: Run capture tests**

Run:

```bash
cargo test -p rustnetconf rpc::reply::capture::tests
```

Expected: 2 tests pass.

- [ ] **Step 5: Verify the isolated capture component**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rustnetconf rpc::reply::capture::tests
cargo test -p rustnetconf --test rpc_reply_contract
cargo test -p rustnetconf rpc::reply
```

Expected: the 2 capture tests, public contract tests, and all existing legacy
reply tests pass. `FragmentCapture` is wired into the production parser in
Task 4; keeping that switch atomic avoids running two reconstruction
implementations inside the legacy state machine.

- [ ] **Step 6: Commit**

```bash
git add src/rpc/reply/capture.rs src/rpc/reply/mod.rs
git commit -m "refactor(rpc): centralize XML fragment capture"
```

---

### Task 4: Replace the Legacy Parser With Explicit State

**Files:**
- Create: `src/rpc/reply/parser.rs`
- Modify: `src/rpc/reply/mod.rs`

**Interfaces:**
- Consumes:
  `capture::{decode_attribute, FragmentCapture}`, `RpcReply`, and
  `RpcErrorInfo`.
- Produces:
  `parser::parse_strict(&str, &str) -> Result<RpcReply, RpcError>`.

- [ ] **Step 1: Add state-machine parity tests**

Add the following tests at the bottom of `src/rpc/reply/parser.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_state_parses_standard_outcomes() {
        let ok = r#"<rpc-reply message-id="1"><ok/></rpc-reply>"#;
        assert!(matches!(parse_strict(ok, "1"), Ok(RpcReply::Ok)));

        let data = r#"<rpc-reply message-id="2"><data><x/></data></rpc-reply>"#;
        assert!(matches!(parse_strict(data, "2"), Ok(RpcReply::Data(_))));

        let empty_data = r#"<rpc-reply message-id="2b"><data/></rpc-reply>"#;
        assert!(matches!(
            parse_strict(empty_data, "2b"),
            Ok(RpcReply::Data(data)) if data.is_empty()
        ));

        let direct = r#"<rpc-reply message-id="3"><output>done</output></rpc-reply>"#;
        assert!(matches!(parse_strict(direct, "3"), Ok(RpcReply::Data(_))));

        let empty = r#"<rpc-reply message-id="4"></rpc-reply>"#;
        assert!(matches!(parse_strict(empty, "4"), Ok(RpcReply::Ok)));
    }

    #[test]
    fn explicit_state_parses_errors_and_warnings() {
        let warning = r#"<rpc-reply message-id="5">
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>operation-failed</error-tag>
            <error-severity>warning</error-severity>
            <error-message>warning text</error-message>
          </rpc-error>
          <ok/>
        </rpc-reply>"#;
        assert!(matches!(
            parse_strict(warning, "5"),
            Ok(RpcReply::OkWithWarnings(_))
        ));

        let error = r#"<rpc-reply message-id="6">
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>invalid-value</error-tag>
            <error-severity>error</error-severity>
            <error-message>bad value</error-message>
          </rpc-error>
        </rpc-reply>"#;
        assert!(matches!(
            parse_strict(error, "6"),
            Err(RpcError::ServerError { .. })
        ));
    }
}
```

- [ ] **Step 2: Run tests to verify the new parser is missing**

Run:

```bash
cargo test -p rustnetconf rpc::reply::parser::tests
```

Expected: compilation fails because `parse_strict` is not defined.

- [ ] **Step 3: Define explicit parser state**

Add these types above the tests in `parser.rs`:

```rust
use super::capture::{decode_attribute, FragmentCapture};
use super::{RpcErrorInfo, RpcReply};
use crate::error::RpcError;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    BeforeReply,
    InsideReply,
    AfterReply,
}

#[derive(Debug)]
enum PayloadState {
    None,
    Ok,
    Data {
        capture: FragmentCapture,
        depth: usize,
        closed: bool,
    },
    Direct {
        capture: FragmentCapture,
        depth: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorField {
    Type,
    Tag,
    Severity,
    AppTag,
    Path,
    Message,
}

impl ErrorField {
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"error-type" => Some(Self::Type),
            b"error-tag" => Some(Self::Tag),
            b"error-severity" => Some(Self::Severity),
            b"error-app-tag" => Some(Self::AppTag),
            b"error-path" => Some(Self::Path),
            b"error-message" => Some(Self::Message),
            _ => None,
        }
    }

    fn xml_name(self) -> &'static [u8] {
        match self {
            Self::Type => b"error-type",
            Self::Tag => b"error-tag",
            Self::Severity => b"error-severity",
            Self::AppTag => b"error-app-tag",
            Self::Path => b"error-path",
            Self::Message => b"error-message",
        }
    }
}

#[derive(Debug, Default)]
struct RpcErrorBuilder {
    error_type: Option<RpcErrorType>,
    tag: Option<ErrorTag>,
    severity: Option<ErrorSeverity>,
    app_tag: Option<String>,
    path: Option<String>,
    message: Option<String>,
    info: Option<String>,
}

#[derive(Debug)]
struct ErrorState {
    builder: RpcErrorBuilder,
    field: Option<ErrorField>,
    field_text: String,
    info_capture: Option<FragmentCapture>,
    info_depth: usize,
}

impl Default for ErrorState {
    fn default() -> Self {
        Self {
            builder: RpcErrorBuilder::default(),
            field: None,
            field_text: String::new(),
            info_capture: None,
            info_depth: 0,
        }
    }
}

struct ReplyParser<'a> {
    expected_message_id: &'a str,
    envelope: EnvelopeState,
    message_id: Option<String>,
    payload: PayloadState,
    current_error: Option<ErrorState>,
    errors: Vec<RpcErrorInfo>,
}

impl<'a> ReplyParser<'a> {
    fn new(expected_message_id: &'a str) -> Self {
        Self {
            expected_message_id,
            envelope: EnvelopeState::BeforeReply,
            message_id: None,
            payload: PayloadState::None,
            current_error: None,
            errors: Vec::new(),
        }
    }
}
```

- [ ] **Step 4: Add the streaming dispatch loop**

Add `parse_strict()` and dispatch methods:

```rust
pub(super) fn parse_strict(
    xml: &str,
    expected_message_id: &str,
) -> Result<RpcReply, RpcError> {
    let mut parser = ReplyParser::new(expected_message_id);
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => parser.start(&tag)?,
            Ok(Event::Empty(tag)) => parser.empty(&tag)?,
            Ok(Event::Text(text)) => parser.text(&text)?,
            Ok(Event::CData(cdata)) => parser.cdata(&cdata)?,
            Ok(Event::GeneralRef(entity)) => parser.entity(&entity)?,
            Ok(Event::End(tag)) => parser.end(&tag)?,
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_)) => {}
            Ok(Event::DocType(_)) => {
                return Err(parse_error("DOCTYPE is not allowed in an RPC reply"));
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(parse_error(format!("XML parse error: {error}")));
            }
        }
    }

    parser.finish()
}

fn parse_error(message: impl Into<String>) -> RpcError {
    RpcError::ParseError(message.into())
}

fn local_name(tag: &[u8]) -> &[u8] {
    tag.rsplit(|byte| *byte == b':').next().unwrap_or(tag)
}
```

Implement `ReplyParser::{start, empty, text, cdata, entity, end}` using this
dispatch order:

```rust
impl ReplyParser<'_> {
    fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.capture_start(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_start(tag);
        }

        match (self.envelope, local_name(tag.name().as_ref())) {
            (EnvelopeState::BeforeReply, b"rpc-reply") => self.open_reply(tag),
            (EnvelopeState::InsideReply, b"rpc-reply") => {
                Err(parse_error("nested <rpc-reply> is not allowed"))
            }
            (EnvelopeState::InsideReply, b"data") => self.open_data(),
            (EnvelopeState::InsideReply, b"rpc-error") => {
                self.current_error = Some(ErrorState::default());
                Ok(())
            }
            (EnvelopeState::InsideReply, b"ok") => {
                Err(parse_error("<ok> must be an empty element"))
            }
            (EnvelopeState::InsideReply, _) => self.open_direct(tag),
            (EnvelopeState::AfterReply, _) => {
                Err(parse_error("element found after </rpc-reply>"))
            }
            (EnvelopeState::BeforeReply, _) => {
                Err(parse_error("root element is not <rpc-reply>"))
            }
        }
    }

    fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.capture_empty(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_empty(tag);
        }

        match (self.envelope, local_name(tag.name().as_ref())) {
            (EnvelopeState::BeforeReply, b"rpc-reply") => {
                self.open_reply(tag)?;
                self.envelope = EnvelopeState::AfterReply;
                Ok(())
            }
            (EnvelopeState::InsideReply, b"ok") => self.set_ok(),
            (EnvelopeState::InsideReply, b"data") => self.set_empty_data(),
            (EnvelopeState::InsideReply, b"rpc-error" | b"rpc-reply") => {
                Err(parse_error("invalid empty NETCONF reply element"))
            }
            (EnvelopeState::InsideReply, _) => self.capture_direct_empty(tag),
            (EnvelopeState::AfterReply, _) => {
                Err(parse_error("element found after </rpc-reply>"))
            }
            (EnvelopeState::BeforeReply, _) => {
                Err(parse_error("root element is not <rpc-reply>"))
            }
        }
    }

    fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        if self.capture_text(text)? {
            return Ok(());
        }
        let decoded = text
            .decode()
            .map_err(|error| parse_error(format!("invalid text encoding: {error}")))?;
        if decoded.trim().is_empty() {
            Ok(())
        } else {
            Err(parse_error("significant text outside a reply payload"))
        }
    }

    fn cdata(&mut self, cdata: &BytesCData<'_>) -> Result<(), RpcError> {
        if self.capture_cdata(cdata)? {
            Ok(())
        } else {
            Err(parse_error("CDATA outside a reply payload"))
        }
    }

    fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        if self.capture_entity(entity)? {
            Ok(())
        } else {
            Err(parse_error("entity reference outside a reply payload"))
        }
    }
}
```

The six `capture_*` helpers must route events to an active `<data>`, direct
payload, `<error-info>`, or textual error field. Their exact transition rules
are:

```text
Data, closed=false:
  Start -> capture start and increment depth.
  Empty/Text/CDATA/Entity -> capture without changing depth.
  End with depth>0 -> capture end and decrement depth.
  End </data> with depth=0 -> set closed=true without capturing wrapper.

Direct, depth>0:
  Start -> capture start and increment depth.
  Empty/Text/CDATA/Entity -> capture.
  End -> capture end and decrement depth.

Direct, depth=0:
  A vendor Start/Empty begins or appends another top-level direct element.
  rpc-error remains available as a sibling.
  ok/data/rpc-reply are handled as top-level elements and rejected as conflicts.

ErrorState field:
  Text/CDATA/resolved GeneralRef append to field_text.
  A nested Start is a ParseError.
  The matching End flushes field_text through RpcErrorBuilder::set_field.

ErrorState error-info:
  Events inside the wrapper go to info_capture with balanced info_depth.
  Closing </error-info> at depth=0 finishes capture into builder.info.
```

Implement those transitions with these helpers:

```rust
impl ReplyParser<'_> {
    fn capture_start(&mut self, tag: &BytesStart<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.start(tag)?;
                error.info_depth += 1;
                return Ok(true);
            }
            if error.field.is_some() {
                return Err(parse_error("nested element inside an rpc-error text field"));
            }
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                depth,
                closed: false,
            } => {
                capture.start(tag)?;
                *depth += 1;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.start(tag)?;
                *depth += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_empty(&mut self, tag: &BytesStart<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.empty(tag)?;
                return Ok(true);
            }
            if let Some(field) = error.field {
                if local_name(tag.name().as_ref()) == field.xml_name() {
                    error.builder.set_field(field, "")?;
                    error.field = None;
                    error.field_text.clear();
                    return Ok(true);
                }
                return Err(parse_error("nested element inside an rpc-error text field"));
            }
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.empty(tag)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.empty(tag)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_text(&mut self, text: &BytesText<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.text(text)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let decoded = text
                    .decode()
                    .map_err(|cause| parse_error(format!("invalid text encoding: {cause}")))?;
                error.field_text.push_str(&decoded);
                return Ok(true);
            }
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.text(text)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.text(text)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_cdata(&mut self, cdata: &BytesCData<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.cdata(cdata)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let decoded = cdata
                    .decode()
                    .map_err(|cause| parse_error(format!("invalid CDATA encoding: {cause}")))?;
                error.field_text.push_str(&decoded);
                return Ok(true);
            }
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.cdata(cdata)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.cdata(cdata)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_entity(&mut self, entity: &BytesRef<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.entity(entity)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let resolved = crate::xml_entity::resolve_entity_ref(entity)
                    .ok_or_else(|| parse_error("invalid entity in rpc-error text field"))?;
                error.field_text.push_str(&resolved);
                return Ok(true);
            }
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.entity(entity)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.entity(entity)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn open_direct(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::default();
                capture.start(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 1 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => {
                capture.start(tag)?;
                *depth = 1;
                Ok(())
            }
            _ => Err(parse_error("direct payload conflicts with an existing payload")),
        }
    }

    fn capture_direct_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::default();
                capture.empty(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 0 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => capture.empty(tag),
            _ => Err(parse_error("direct payload conflicts with an existing payload")),
        }
    }

    fn error_start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let error = self
            .current_error
            .as_mut()
            .expect("error_start requires current_error");
        let name = local_name(tag.name().as_ref());

        if name == b"error-info" {
            if error.info_capture.is_some() {
                return Err(parse_error("duplicate error-info"));
            }
            error.info_capture = Some(FragmentCapture::default());
            error.info_depth = 0;
            return Ok(());
        }

        let field = ErrorField::from_name(name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        if error.field.is_some() {
            return Err(parse_error("nested rpc-error text fields"));
        }
        error.field = Some(field);
        error.field_text.clear();
        Ok(())
    }

    fn error_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let error = self
            .current_error
            .as_mut()
            .expect("error_empty requires current_error");
        let name = local_name(tag.name().as_ref());

        if name == b"error-info" {
            if error.info_capture.is_some() || error.builder.info.is_some() {
                return Err(parse_error("duplicate error-info"));
            }
            return Ok(());
        }

        let field = ErrorField::from_name(name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        error.builder.set_field(field, "")
    }
}
```

- [ ] **Step 5: Implement envelope, payload, and error finalization**

Add these method contracts and outcomes:

```rust
impl ReplyParser<'_> {
    fn open_reply(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.envelope != EnvelopeState::BeforeReply {
            return Err(parse_error("multiple <rpc-reply> envelopes"));
        }

        let mut message_id = None;
        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            if local_name(attribute.key.as_ref()) == b"message-id" {
                if message_id.is_some() {
                    return Err(parse_error("duplicate message-id attribute"));
                }
                message_id = Some(decode_attribute(attribute.value.as_ref())?);
            }
        }

        self.message_id = message_id;
        self.envelope = EnvelopeState::InsideReply;
        Ok(())
    }

    fn set_ok(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Ok;
                Ok(())
            }
            _ => Err(parse_error("<ok/> conflicts with an existing payload")),
        }
    }

    fn open_data(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Data {
                    capture: FragmentCapture::default(),
                    depth: 0,
                    closed: false,
                };
                Ok(())
            }
            _ => Err(parse_error("<data> conflicts with an existing payload")),
        }
    }

    fn set_empty_data(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Data {
                    capture: FragmentCapture::default(),
                    depth: 0,
                    closed: true,
                };
                Ok(())
            }
            _ => Err(parse_error("<data/> conflicts with an existing payload")),
        }
    }

    fn finish(self) -> Result<RpcReply, RpcError> {
        if self.envelope != EnvelopeState::AfterReply {
            return Err(parse_error("RPC reply envelope did not close"));
        }
        if self.current_error.is_some() {
            return Err(parse_error("<rpc-error> did not close"));
        }

        let message_id = self
            .message_id
            .ok_or_else(|| parse_error("rpc-reply is missing message-id"))?;
        if message_id != self.expected_message_id {
            return Err(RpcError::MessageIdMismatch {
                expected: self.expected_message_id.to_string(),
                actual: message_id,
            });
        }

        let (hard_errors, warnings): (Vec<_>, Vec<_>) = self
            .errors
            .into_iter()
            .partition(|error| error.severity != Some(ErrorSeverity::Warning));

        if let Some(error) = hard_errors.into_iter().next() {
            return Err(RpcError::ServerError {
                error_type: error.error_type,
                tag: error.tag,
                severity: error.severity,
                app_tag: error.app_tag,
                path: error.path,
                message: error.message,
                info: error.info,
            });
        }

        for warning in &warnings {
            tracing::warn!(
                tag = ?warning.tag,
                message = %warning.message,
                "device returned RPC warning"
            );
        }

        match self.payload {
            PayloadState::Data {
                capture,
                closed: true,
                ..
            }
            | PayloadState::Direct {
                capture,
                depth: 0,
            } => {
                let data = capture.finish()?;
                if warnings.is_empty() {
                    Ok(RpcReply::Data(data))
                } else {
                    Ok(RpcReply::DataWithWarnings(data, warnings))
                }
            }
            PayloadState::Ok | PayloadState::None if warnings.is_empty() => Ok(RpcReply::Ok),
            PayloadState::Ok | PayloadState::None => Ok(RpcReply::OkWithWarnings(warnings)),
            PayloadState::Data { .. } | PayloadState::Direct { .. } => {
                Err(parse_error("reply payload did not close"))
            }
        }
    }
}
```

Implement end-event handling:

```rust
impl ReplyParser<'_> {
    fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        let name = local_name(tag.name().as_ref());

        if self.current_error.is_some() {
            {
                let error = self
                    .current_error
                    .as_mut()
                    .expect("current_error was checked");

                if let Some(capture) = error.info_capture.as_mut() {
                    if error.info_depth > 0 {
                        capture.end(tag)?;
                        error.info_depth -= 1;
                        return Ok(());
                    }
                    if name != b"error-info" {
                        return Err(parse_error("unexpected end inside error-info"));
                    }
                    let info = error
                        .info_capture
                        .take()
                        .expect("error-info capture exists")
                        .finish()?;
                    if !info.trim().is_empty() {
                        error.builder.info = Some(info.trim().to_string());
                    }
                    return Ok(());
                }

                if let Some(field) = error.field {
                    if name != field.xml_name() {
                        return Err(parse_error("rpc-error field closed by wrong element"));
                    }
                    error.builder.set_field(field, &error.field_text)?;
                    error.field = None;
                    error.field_text.clear();
                    return Ok(());
                }
            }

            if name == b"rpc-error" {
                let error = self
                    .current_error
                    .take()
                    .expect("current_error was checked");
                self.errors.push(error.builder.finish()?);
                return Ok(());
            }
            return Err(parse_error("unexpected end directly inside rpc-error"));
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                depth,
                closed,
            } if !*closed => {
                if *depth > 0 {
                    capture.end(tag)?;
                    *depth -= 1;
                    return Ok(());
                }
                if name == b"data" {
                    *closed = true;
                    return Ok(());
                }
                return Err(parse_error("unexpected end inside data payload"));
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.end(tag)?;
                *depth -= 1;
                return Ok(());
            }
            _ => {}
        }

        if name != b"rpc-reply" {
            return Err(parse_error("unexpected end directly inside rpc-reply"));
        }
        if self.envelope != EnvelopeState::InsideReply {
            return Err(parse_error("rpc-reply closed outside its envelope"));
        }
        self.envelope = EnvelopeState::AfterReply;
        Ok(())
    }
}
```

Use this parity builder for the state-machine replacement; Task 6 replaces
its fallback behavior with mandatory-field validation:

```rust
impl RpcErrorBuilder {
    fn set_field(&mut self, field: ErrorField, value: &str) -> Result<(), RpcError> {
        match field {
            ErrorField::Type => {
                self.error_type = Some(match value.trim() {
                    "transport" => RpcErrorType::Transport,
                    "rpc" => RpcErrorType::Rpc,
                    "protocol" => RpcErrorType::Protocol,
                    "application" => RpcErrorType::Application,
                    _ => RpcErrorType::Application,
                });
            }
            ErrorField::Tag => {
                self.tag = Some(
                    value
                        .trim()
                        .parse()
                        .expect("ErrorTag::from_str is infallible"),
                );
            }
            ErrorField::Severity => {
                self.severity = Some(if value.trim() == "warning" {
                    ErrorSeverity::Warning
                } else {
                    ErrorSeverity::Error
                });
            }
            ErrorField::AppTag => self.app_tag = Some(value.to_string()),
            ErrorField::Path => self.path = Some(value.to_string()),
            ErrorField::Message => self.message = Some(value.to_string()),
        }
        Ok(())
    }

    fn finish(self) -> Result<RpcErrorInfo, RpcError> {
        Ok(RpcErrorInfo {
            error_type: self.error_type,
            tag: self.tag.unwrap_or(ErrorTag::OperationFailed),
            severity: self.severity,
            app_tag: self.app_tag,
            path: self.path,
            message: self.message.unwrap_or_else(|| "unknown error".to_string()),
            info: self.info,
        })
    }
}
```

- [ ] **Step 6: Declare the new parser without switching public behavior**

Declare the parser module in `src/rpc/reply/mod.rs`:

```rust
mod parser;
```

Keep the legacy `parse_rpc_reply_strict()`, repair wrapper, `ErrorField`,
`RpcErrorBuilder`, and `extract_rpc_reply_inner_content()` active for now.
Task 5 first demonstrates the intended public behavior changes as failing
tests, then performs the atomic switch to `parser::parse_strict`.

- [ ] **Step 7: Run the parser suites**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rustnetconf rpc::reply::parser::tests
cargo test -p rustnetconf rpc::reply::tests
cargo test -p rustnetconf --test rpc_reply_contract
```

Expected: internal state-machine tests, legacy reply tests, and 6 public
contract tests pass. The public parser still uses the legacy implementation at
this checkpoint.

- [ ] **Step 8: Commit**

```bash
git add src/rpc/reply/mod.rs src/rpc/reply/parser.rs
git commit -m "refactor(rpc): parse replies with explicit state"
```

---

### Task 5: Enforce Envelope, Payload, and Message-ID Invariants

**Files:**
- Modify: `src/rpc/reply/mod.rs`
- Modify: `src/rpc/reply/parser.rs`

**Interfaces:**
- Consumes: the legacy public `parse_rpc_reply` and the completed
  `parser::parse_strict`.
- Produces: deterministic `ParseError` or `MessageIdMismatch` for ambiguous
  envelopes, payloads, and identifiers.

- [ ] **Step 1: Add failing table-driven invariant tests**

Append to the existing tests in `src/rpc/reply/mod.rs` so these assertions
exercise the still-active legacy public parser:

```rust
#[test]
fn rejects_ambiguous_envelopes_and_payloads() {
    let cases = [
        (
            "missing message-id",
            r#"<rpc-reply><ok/></rpc-reply>"#,
        ),
        (
            "duplicate data",
            r#"<rpc-reply message-id="1"><data/><data/></rpc-reply>"#,
        ),
        (
            "ok and data",
            r#"<rpc-reply message-id="1"><ok/><data/></rpc-reply>"#,
        ),
        (
            "nested reply",
            r#"<rpc-reply message-id="1"><rpc-reply message-id="1"/></rpc-reply>"#,
        ),
        (
            "second reply",
            r#"<rpc-reply message-id="1"/><rpc-reply message-id="1"/>"#,
        ),
        (
            "significant trailing text",
            r#"<rpc-reply message-id="1"/>trailing"#,
        ),
        (
            "wrong root",
            r#"<notification message-id="1"/>"#,
        ),
    ];

    for (name, xml) in cases {
        let result = parse_rpc_reply(xml, "1");
        assert!(
            matches!(result, Err(RpcError::ParseError(_))),
            "{name} must be ParseError, got {result:?}"
        );
    }
}

#[test]
fn wrong_message_id_keeps_typed_error() {
    let xml = r#"<rpc-reply message-id="actual"><ok/></rpc-reply>"#;
    let result = parse_rpc_reply(xml, "expected");
    assert!(matches!(
        result,
        Err(RpcError::MessageIdMismatch {
            expected,
            actual
        }) if expected == "expected" && actual == "actual"
    ));
}
```

- [ ] **Step 2: Run tests and observe the intended failures**

Run:

```bash
cargo test -p rustnetconf rpc::reply::tests::rejects_ambiguous_envelopes_and_payloads
cargo test -p rustnetconf rpc::reply::tests::wrong_message_id_keeps_typed_error
```

Expected: the first command fails for any invariant still accepted; the second
passes or identifies a regression in typed mismatch handling.

- [ ] **Step 3: Switch the public strict path**

In the existing public `parse_rpc_reply()` repair wrapper, replace both calls
to `parse_rpc_reply_strict()` with:

```rust
parser::parse_strict(xml, expected_message_id)
parser::parse_strict(&repaired, expected_message_id)
```

Keep the legacy repair wrapper until Task 7. Delete the old strict parser,
`parse_rpc_reply_strict`, legacy `ErrorField`, legacy `RpcErrorBuilder`, and
`extract_rpc_reply_inner_content()` now that the new one-pass parser owns
those responsibilities.

Confirm `open_reply`, `set_ok`, `open_data`, direct-payload opening, root-empty
handling, text handling, and `finish()` make every case in the table return
the stated error. Attribute iteration must use `.with_checks(true)` and never
`.flatten()`.

An empty `<rpc-reply/>` must route through `open_reply()` before moving to
`AfterReply`, ensuring the same message-ID rules apply to both empty and
start/end envelopes.

- [ ] **Step 4: Run invariant and regression tests**

Run:

```bash
cargo test -p rustnetconf rpc::reply::parser::tests
cargo test -p rustnetconf rpc::reply::tests::rejects_ambiguous_envelopes_and_payloads
cargo test -p rustnetconf --test rpc_reply_contract
```

Expected: all parser tests and public contract tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/rpc/reply/mod.rs src/rpc/reply/parser.rs
git commit -m "fix(rpc): reject ambiguous reply structure"
```

---

### Task 6: Enforce RPC-Error Fields and Warning-Only Semantics

**Files:**
- Modify: `src/rpc/reply/parser.rs`

**Interfaces:**
- Consumes: `RpcErrorBuilder` and `ReplyParser::finish`.
- Produces: validated `RpcErrorInfo`, typed `ServerError`, and
  `OkWithWarnings` for warning-only replies.

- [ ] **Step 1: Add failing malformed-error tests**

Append to `parser.rs` tests:

```rust
#[test]
fn rejects_missing_mandatory_rpc_error_fields() {
    let cases = [
        (
            "error-type",
            r#"<error-tag>operation-failed</error-tag>
               <error-severity>error</error-severity>"#,
        ),
        (
            "error-tag",
            r#"<error-type>application</error-type>
               <error-severity>error</error-severity>"#,
        ),
        (
            "error-severity",
            r#"<error-type>application</error-type>
               <error-tag>operation-failed</error-tag>"#,
        ),
    ];

    for (missing, fields) in cases {
        let xml = format!(
            r#"<rpc-reply message-id="1"><rpc-error>{fields}</rpc-error></rpc-reply>"#
        );
        let error = parse_strict(&xml, "1").expect_err("missing field must fail");
        assert!(matches!(error, RpcError::ParseError(_)));
        assert!(
            error.to_string().contains(missing),
            "error must name {missing}: {error}"
        );
    }
}

#[test]
fn rejects_invalid_rpc_error_type_and_severity() {
    let invalid_type = r#"<rpc-reply message-id="1"><rpc-error>
      <error-type>vendor-layer</error-type>
      <error-tag>operation-failed</error-tag>
      <error-severity>error</error-severity>
    </rpc-error></rpc-reply>"#;
    assert!(matches!(
        parse_strict(invalid_type, "1"),
        Err(RpcError::ParseError(_))
    ));

    let invalid_severity = r#"<rpc-reply message-id="1"><rpc-error>
      <error-type>application</error-type>
      <error-tag>operation-failed</error-tag>
      <error-severity>notice</error-severity>
    </rpc-error></rpc-reply>"#;
    assert!(matches!(
        parse_strict(invalid_severity, "1"),
        Err(RpcError::ParseError(_))
    ));
}

#[test]
fn warning_only_reply_preserves_warning() {
    let xml = r#"<rpc-reply message-id="1"><rpc-error>
      <error-type>application</error-type>
      <error-tag>operation-failed</error-tag>
      <error-severity>warning</error-severity>
      <error-message>device warning</error-message>
    </rpc-error></rpc-reply>"#;

    let reply = parse_strict(xml, "1").expect("warning-only reply succeeds");
    let RpcReply::OkWithWarnings(warnings) = reply else {
        panic!("expected OkWithWarnings");
    };
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].message, "device warning");
}

#[test]
fn error_info_preserves_nested_attributes() {
    let xml = r#"<rpc-reply message-id="1"><rpc-error>
      <error-type>application</error-type>
      <error-tag>operation-failed</error-tag>
      <error-severity>error</error-severity>
      <error-info>
        <bad-element xmlns:v="urn:vendor" v:source="candidate">x &amp; y</bad-element>
      </error-info>
    </rpc-error></rpc-reply>"#;

    let error = parse_strict(xml, "1").expect_err("hard error");
    let RpcError::ServerError {
        info: Some(info), ..
    } = error
    else {
        panic!("expected ServerError with error-info");
    };
    assert!(info.contains("xmlns:v=\"urn:vendor\""));
    assert!(info.contains("v:source=\"candidate\""));
    assert!(info.contains("x &amp; y"));
}
```

- [ ] **Step 2: Run tests to verify strict cases fail**

Run:

```bash
cargo test -p rustnetconf rpc::reply::parser::tests::rejects_missing_mandatory_rpc_error_fields
cargo test -p rustnetconf rpc::reply::parser::tests::rejects_invalid_rpc_error_type_and_severity
cargo test -p rustnetconf rpc::reply::parser::tests::warning_only_reply_preserves_warning
```

Expected: at least the mandatory-field and invalid-value tests fail before the
builder is tightened.

- [ ] **Step 3: Make builder parsing fallible**

Implement these exact mappings:

```rust
impl RpcErrorBuilder {
    fn set_field(&mut self, field: ErrorField, value: &str) -> Result<(), RpcError> {
        match field {
            ErrorField::Type => {
                self.error_type = Some(match value.trim() {
                    "transport" => RpcErrorType::Transport,
                    "rpc" => RpcErrorType::Rpc,
                    "protocol" => RpcErrorType::Protocol,
                    "application" => RpcErrorType::Application,
                    other => {
                        return Err(parse_error(format!(
                            "invalid rpc-error error-type: {other}"
                        )));
                    }
                });
            }
            ErrorField::Tag => {
                self.tag = Some(
                    value
                        .trim()
                        .parse()
                        .expect("ErrorTag::from_str is infallible"),
                );
            }
            ErrorField::Severity => {
                self.severity = Some(match value.trim() {
                    "error" => ErrorSeverity::Error,
                    "warning" => ErrorSeverity::Warning,
                    other => {
                        return Err(parse_error(format!(
                            "invalid rpc-error error-severity: {other}"
                        )));
                    }
                });
            }
            ErrorField::AppTag => self.app_tag = Some(value.to_string()),
            ErrorField::Path => self.path = Some(value.to_string()),
            ErrorField::Message => self.message = Some(value.to_string()),
        }
        Ok(())
    }

    fn finish(self) -> Result<RpcErrorInfo, RpcError> {
        Ok(RpcErrorInfo {
            error_type: Some(
                self.error_type
                    .ok_or_else(|| parse_error("rpc-error is missing error-type"))?,
            ),
            tag: self
                .tag
                .ok_or_else(|| parse_error("rpc-error is missing error-tag"))?,
            severity: Some(
                self.severity
                    .ok_or_else(|| parse_error("rpc-error is missing error-severity"))?,
            ),
            app_tag: self.app_tag,
            path: self.path,
            message: self.message.unwrap_or_default(),
            info: self.info,
        })
    }
}
```

When `</rpc-error>` closes, call `ErrorState.builder.finish()?` and append the
result. Do not create fallback types, tags, severities, or messages.

- [ ] **Step 4: Verify warning and error behavior**

Run:

```bash
cargo test -p rustnetconf rpc::reply::parser::tests
cargo test -p rustnetconf rpc::reply::tests
cargo test -p rustnetconf --test rpc_reply_contract
```

Expected: all suites pass, including warning-only preservation and nested
`error-info` attributes.

- [ ] **Step 5: Commit**

```bash
git add src/rpc/reply/parser.rs
git commit -m "fix(rpc): validate rpc-error structure"
```

---

### Task 7: Narrow the Junos Chassis-Cluster Repair

**Files:**
- Create: `src/rpc/reply/repair.rs`
- Modify: `src/rpc/reply/mod.rs`

**Interfaces:**
- Consumes: malformed reply XML and local-name-aware `quick_xml` events.
- Produces:
  `repair::repair_cluster_commit_check(&str) -> Option<String>`.

- [ ] **Step 1: Add repair-boundary tests**

Move the existing repair tests beside the public orchestration in
`src/rpc/reply/mod.rs`, retain the captured fixture test, and add:

```rust
#[test]
fn does_not_repair_unrelated_direct_routing_engine() {
    let xml = r#"<rpc-reply message-id="1">
      <routing-engine><name>node0</name><ok/>
    </rpc-reply>"#;
    assert!(matches!(
        parse_rpc_reply(xml, "1"),
        Err(RpcError::ParseError(_))
    ));
}

#[test]
fn does_not_repair_marker_in_unsupported_placement() {
    let xml = r#"<rpc-reply message-id="1">
      <outer><routing-engine><commit-check-success/>
    </outer></rpc-reply>"#;
    assert!(matches!(
        parse_rpc_reply(xml, "1"),
        Err(RpcError::ParseError(_))
    ));
}

#[test]
fn does_not_repair_non_routing_engine_mismatch() {
    let xml = r#"<rpc-reply message-id="1">
      <routing-engine><commit-check-success/></wrong>
    </rpc-reply>"#;
    assert!(matches!(
        parse_rpc_reply(xml, "1"),
        Err(RpcError::ParseError(_))
    ));
}

#[test]
fn does_not_repair_truncated_commit_check() {
    let xml = r#"<rpc-reply message-id="1">
      <routing-engine><commit-check-success/>"#;
    assert!(matches!(
        parse_rpc_reply(xml, "1"),
        Err(RpcError::ParseError(_))
    ));
}
```

- [ ] **Step 2: Run boundary tests against the broad repair**

Run:

```bash
cargo test -p rustnetconf rpc::reply::tests::does_not_repair
```

Expected: at least the unrelated direct `routing-engine` case fails if the
legacy broad repair accepts it.

- [ ] **Step 3: Implement contextual repair state**

Create `src/rpc/reply/repair.rs` with:

```rust
use quick_xml::events::{BytesEnd, Event};
use quick_xml::{Reader, Writer};

#[derive(Debug)]
struct OpenElement {
    qname: Vec<u8>,
    local: Vec<u8>,
    routing_engine_supported: bool,
    routing_engine_has_marker: bool,
}

impl OpenElement {
    fn ordinary(qname: &[u8]) -> Self {
        Self {
            qname: qname.to_vec(),
            local: local_name(qname).to_vec(),
            routing_engine_supported: false,
            routing_engine_has_marker: false,
        }
    }

    fn routing_engine(qname: &[u8], supported: bool) -> Self {
        Self {
            qname: qname.to_vec(),
            local: b"routing-engine".to_vec(),
            routing_engine_supported: supported,
            routing_engine_has_marker: false,
        }
    }

    fn repairable(&self) -> bool {
        self.local == b"routing-engine"
            && self.routing_engine_supported
            && self.routing_engine_has_marker
    }
}

fn local_name(qname: &[u8]) -> &[u8] {
    qname.rsplit(|byte| *byte == b':').next().unwrap_or(qname)
}

fn supported_routing_engine_parent(stack: &[OpenElement]) -> bool {
    stack
        .last()
        .is_some_and(|element| element.local == b"rpc-reply")
        || stack
            .iter()
            .any(|element| element.local == b"multi-routing-engine-results")
}

fn mark_commit_check_result(stack: &mut [OpenElement]) {
    if let Some(routing_engine) = stack
        .iter_mut()
        .rev()
        .find(|element| element.local == b"routing-engine")
    {
        routing_engine.routing_engine_has_marker = true;
    }
}

fn close_repairable(
    writer: &mut Writer<Vec<u8>>,
    stack: &mut Vec<OpenElement>,
) -> Option<()> {
    let top = stack.last()?;
    if !top.repairable() {
        return None;
    }
    let qname = std::str::from_utf8(&top.qname).ok()?;
    writer.write_event(Event::End(BytesEnd::new(qname))).ok()?;
    stack.pop();
    Some(())
}
```

Implement `repair_cluster_commit_check()` as a tolerant reader/writer loop
with this implementation:

```rust
pub(super) fn repair_cluster_commit_check(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false;

    let mut writer = Writer::new(Vec::new());
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut repaired_any = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let qname = tag.name();
                let local = local_name(qname.as_ref());

                if matches!(local, b"commit-check-success" | b"rpc-error") {
                    mark_commit_check_result(&mut stack);
                }

                if local == b"routing-engine" {
                    if stack
                        .last()
                        .is_some_and(|element| element.local == b"routing-engine")
                    {
                        close_repairable(&mut writer, &mut stack)?;
                        repaired_any = true;
                    }
                    let supported = supported_routing_engine_parent(&stack);
                    stack.push(OpenElement::routing_engine(qname.as_ref(), supported));
                } else {
                    stack.push(OpenElement::ordinary(qname.as_ref()));
                }

                writer.write_event(Event::Start(tag.into_owned())).ok()?;
            }
            Ok(Event::Empty(tag)) => {
                if matches!(
                    local_name(tag.name().as_ref()),
                    b"commit-check-success" | b"rpc-error"
                ) {
                    mark_commit_check_result(&mut stack);
                }
                writer.write_event(Event::Empty(tag.into_owned())).ok()?;
            }
            Ok(Event::End(tag)) => {
                let end_local = local_name(tag.name().as_ref());

                while stack
                    .last()
                    .is_some_and(|element| element.local.as_slice() != end_local)
                {
                    let parent_matches = stack.len() >= 2
                        && stack[stack.len() - 2].local.as_slice() == end_local;
                    if !parent_matches {
                        return None;
                    }
                    close_repairable(&mut writer, &mut stack)?;
                    repaired_any = true;
                }

                let open = stack.pop()?;
                if open.local.as_slice() != end_local {
                    return None;
                }
                writer.write_event(Event::End(tag.into_owned())).ok()?;
            }
            Ok(Event::Text(text)) => {
                writer.write_event(Event::Text(text.into_owned())).ok()?;
            }
            Ok(Event::CData(cdata)) => {
                writer.write_event(Event::CData(cdata.into_owned())).ok()?;
            }
            Ok(Event::GeneralRef(entity)) => {
                writer
                    .write_event(Event::GeneralRef(entity.into_owned()))
                    .ok()?;
            }
            Ok(Event::Comment(comment)) => {
                writer
                    .write_event(Event::Comment(comment.into_owned()))
                    .ok()?;
            }
            Ok(Event::Decl(declaration)) => {
                writer
                    .write_event(Event::Decl(declaration.into_owned()))
                    .ok()?;
            }
            Ok(Event::PI(instruction)) => {
                writer
                    .write_event(Event::PI(instruction.into_owned()))
                    .ok()?;
            }
            Ok(Event::DocType(doctype)) => {
                writer
                    .write_event(Event::DocType(doctype.into_owned()))
                    .ok()?;
            }
            Ok(Event::Eof) => {
                if !stack.is_empty() || !repaired_any {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    String::from_utf8(writer.into_inner()).ok()
}
```

- [ ] **Step 4: Wire strict-first orchestration**

Declare the module in `src/rpc/reply/mod.rs`:

```rust
mod repair;
```

Replace the repair wrapper with:

```rust
pub fn parse_rpc_reply(
    xml: &str,
    expected_message_id: &str,
) -> Result<RpcReply, RpcError> {
    match parser::parse_strict(xml, expected_message_id) {
        Ok(reply) => Ok(reply),
        Err(original @ RpcError::ParseError(_)) => {
            let Some(repaired) = repair::repair_cluster_commit_check(xml) else {
                return Err(original);
            };
            parser::parse_strict(&repaired, expected_message_id)
        }
        Err(other) => Err(other),
    }
}
```

Delete the legacy `local_name_of()` and
`repair_unclosed_routing_engine()` implementations.

- [ ] **Step 5: Run repair and parser suites**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rustnetconf rpc::reply::tests
cargo test -p rustnetconf rpc::reply::repair
cargo test -p rustnetconf --test rpc_reply_contract
```

Expected: the captured single-node fixture and two-node synthetic repair pass;
all unrelated, mismatched, and truncated cases return `ParseError`; public
contracts pass.

- [ ] **Step 6: Commit**

```bash
git add src/rpc/reply/mod.rs src/rpc/reply/repair.rs
git commit -m "fix(rpc): narrow cluster reply repair"
```

---

### Task 8: Remove Legacy Code and Run Full Verification

**Files:**
- Modify: `src/rpc/reply/mod.rs`
- Modify: `src/rpc/reply/capture.rs`
- Modify: `src/rpc/reply/parser.rs`
- Modify: `src/rpc/reply/repair.rs`
- Modify: `src/rpc/mod.rs`

**Interfaces:**
- Consumes: all completed parser modules and tests.
- Produces: final focused module layout with no duplicate parser or repair
  implementation.

- [ ] **Step 1: Remove obsolete symbols and imports**

Confirm none of these remain:

```text
parse_rpc_reply_strict
extract_rpc_reply_inner_content
repair_unclosed_routing_engine
reescape_attr_value
in_rpc_reply
in_rpc_error
in_error_info
data_depth
error_info_depth
```

Run:

```bash
rg -n 'parse_rpc_reply_strict|extract_rpc_reply_inner_content|repair_unclosed_routing_engine|reescape_attr_value|in_rpc_reply|in_rpc_error|in_error_info|data_depth|error_info_depth' src/rpc
```

Expected: no matches. Keep `parser::parse_strict`; the search intentionally
targets only the old wrapper name.

- [ ] **Step 2: Check focused module sizes and parser complexity**

Run:

```bash
wc -l src/rpc/reply/*.rs
cargo clippy -p rustnetconf --lib -- \
  -W clippy::too_many_lines \
  -W clippy::cognitive_complexity
```

Expected: no `too_many_lines` or `cognitive_complexity` warning names a
function in `src/rpc/reply/`. A pre-existing warning for
`src/transport/ssh.rs::connect` may remain and must be reported rather than
suppressed.

- [ ] **Step 3: Run formatting**

Run:

```bash
cargo fmt --all -- --check
```

Expected: exit 0 with no output.

- [ ] **Step 4: Run the complete rustnetconf test suite**

Run:

```bash
cargo test -p rustnetconf
```

Expected: all unit, integration, and documentation tests pass with zero
failures.

- [ ] **Step 5: Run standard Clippy**

Run:

```bash
cargo clippy -p rustnetconf --all-targets --all-features -- -D warnings
```

Expected: exit 0 with no warnings.

- [ ] **Step 6: Inspect the final diff**

Run:

```bash
git diff --check
git status --short
git diff --stat origin/main...HEAD
git diff origin/main...HEAD -- src/rpc tests/rpc_reply_contract.rs
```

Expected: no whitespace errors; only the approved parser refactor, tests, spec,
and plan are present.

- [ ] **Step 7: Commit final cleanup if needed**

If Step 1 or formatting changed files:

```bash
git add src/rpc tests/rpc_reply_contract.rs
git commit -m "refactor(rpc): finish reply parser cleanup"
```

If the worktree is already clean, do not create an empty commit.
