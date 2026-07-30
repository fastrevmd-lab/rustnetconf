# RPC Reply Parser Refactor Design

**Date:** 2026-07-30  
**Status:** Approved for implementation planning

## Context

`src/rpc/mod.rs` currently combines RPC reply types, XML validation, reply
parsing, malformed-reply repair, XML fragment reconstruction, and tests. Its
strict reply parser is a 249-line streaming state machine with cognitive
complexity 40, represented by several independent booleans and depth counters.
The malformed Junos chassis-cluster repair path adds another 114-line stateful
function.

This code is correctness-critical. It has recently required fixes for XML
entity handling, namespace and attribute preservation, custom Junos payloads,
and unclosed `<routing-engine>` elements in cluster commit-check replies. The
current shape makes valid and invalid state combinations difficult to see,
which increases the risk that a parser fix changes an unrelated reply form.

## Goals

- Replace the boolean-heavy reply parser with an explicit streaming state
  machine.
- Make structural invariants visible and enforce them deterministically.
- Preserve the existing public `RpcReply`, `RpcErrorInfo`, `RpcError`, and
  `parse_rpc_reply()` APIs.
- Preserve supported standard NETCONF and Junos reply behavior.
- Narrow malformed Junos recovery to the known chassis-cluster defect.
- Preserve qualified names, namespaces, attributes, entities, and CDATA in
  returned XML fragments.
- Reject unsafe or ambiguous malformed replies rather than silently assigning
  them a plausible meaning.
- Make individual state transitions and outcome rules directly unit-testable.

## Non-goals

- Changing the transport, framing, session, or client APIs.
- Replacing `quick_xml` or building a general-purpose XML DOM.
- Adding new public error variants.
- Supporting arbitrary malformed vendor XML.
- Refactoring request serialization in `rpc::operations`.
- Changing notification or `<hello>` parsing.

## Module Structure

Reply parsing will move into a private `rpc::reply` module:

```text
src/rpc/
├── mod.rs
├── filter.rs
├── operations.rs
└── reply/
    ├── mod.rs
    ├── capture.rs
    ├── parser.rs
    └── repair.rs
```

- `reply/mod.rs` owns the existing public reply types and the
  `parse_rpc_reply()` orchestration function.
- `reply/parser.rs` owns `ReplyParser`, its explicit state, event handlers, and
  semantic finalization.
- `reply/capture.rs` owns XML-fragment reconstruction shared by standard
  `<data>`, direct vendor payloads, and `<error-info>`.
- `reply/repair.rs` owns the narrow Junos chassis-cluster commit-check
  normalization.
- `rpc/mod.rs` privately declares `reply` and publicly re-exports
  `parse_rpc_reply`, `RpcErrorInfo`, and `RpcReply`, preserving their current
  source paths.

## Parser Model

The parser remains streaming and consumes `quick_xml::events::Event` values.
Its state is represented explicitly rather than as unrelated flags.

### Envelope state

```rust
enum EnvelopeState {
    BeforeReply,
    InsideReply,
    AfterReply,
}
```

This state permits exactly one `<rpc-reply>` envelope. XML declarations,
comments, processing instructions, and whitespace may surround it. A second
reply, nested reply, significant text, or element outside the envelope is a
parse error.

### Payload state

```rust
enum PayloadState {
    None,
    Ok,
    Data(FragmentCapture),
    Direct(FragmentCapture),
}
```

`<data>` captures its inner XML without the `<data>` wrapper. One or more
vendor-specific elements directly beneath `<rpc-reply>` are captured together
as a direct payload, matching existing Junos custom-RPC behavior. The parser
rejects duplicate `<data>` elements and mixtures of `<ok/>`, `<data>`, and
direct payloads.

### RPC error state

The parser holds either no current error or one `RpcErrorBuilder`. The builder
tracks the RFC 6241 fields and uses a dedicated `FragmentCapture` while inside
`<error-info>`. Multiple sibling `<rpc-error>` elements remain supported.

The following RFC-mandated fields must be present and valid:

- `error-type`
- `error-tag`
- `error-severity`

`error-message`, `error-app-tag`, `error-path`, and `error-info` remain
optional. A missing optional `error-message` produces an empty string because
the public structure requires a `String`; the parser will no longer fabricate
an `"unknown error"` message. Unknown `error-type` or `error-severity` values
are parse errors. Existing `ErrorTag::Other` behavior remains available for
unrecognized vendor tags.

### Event handlers

`ReplyParser` dispatches events to small methods:

- `start`
- `empty`
- `text`
- `cdata`
- `entity`
- `end`
- `finish`

Handlers validate transitions before modifying state. XML attribute iterator
errors and text decoding errors are propagated as `RpcError::ParseError`
instead of being dropped through `.flatten()` or replaced with empty text.

`finish()` verifies the completed envelope, matching message ID, closed
captures, complete errors, and a single unambiguous outcome before constructing
the existing public result types.

## XML Fragment Capture

`FragmentCapture` is the only code responsible for reconstructing returned XML.
It accepts start, empty, end, text, CDATA, and entity events and preserves:

- Qualified element and attribute names.
- Namespace declarations and ordinary attributes.
- Correct attribute escaping regardless of the source quote style.
- Text content with XML-sensitive characters re-escaped.
- Entity references without losing or double-decoding them.
- CDATA content as equivalent escaped text.
- Nested structure and balanced depth.

Using one capture implementation removes the current duplicate reconstruction
logic in the strict parser and `extract_rpc_reply_inner_content()`. Direct
vendor payloads will be collected in the first parsing pass, so the second pass
and its independent state rules can be deleted.

## Message ID Policy

A parsed reply must contain exactly one `message-id` attribute on its
`<rpc-reply>` envelope.

- A matching value proceeds normally.
- A different value returns the existing `RpcError::MessageIdMismatch`.
- A missing, duplicated, or malformed attribute returns
  `RpcError::ParseError`.

This intentionally tightens current behavior, which can accept some replies
without a message ID. NETCONF replies are required to echo the request message
ID, and accepting an unidentified reply risks associating it with the wrong
request.

## Outcome Policy

After structural validation, the parser resolves the result in this order:

1. Any hard `<rpc-error>` returns the first hard error as the existing
   `RpcError::ServerError`.
2. A `<data>` or direct payload returns `Data` or `DataWithWarnings`.
3. `<ok/>` returns `Ok` or `OkWithWarnings`.
4. A warning-only reply returns `OkWithWarnings`.
5. A structurally valid empty `<rpc-reply message-id="..."/>` returns `Ok`, as
   permitted by RFC 6241.
6. Any conflicting or incomplete outcome returns `RpcError::ParseError`.

Warnings continue to be logged. A hard error still takes precedence over any
simultaneous payload, preserving the current externally observable error
behavior while treating warning-only replies more accurately.

## Narrow Junos Repair

`parse_rpc_reply()` remains strict-first. Recovery is attempted only after the
strict parser reports malformed XML.

The repair scanner may synthesize an end tag only when all of these conditions
hold:

- The document has one recognizable `<rpc-reply>` envelope with a real closing
  tag.
- The unmatched open element is exactly `<routing-engine>` (with any namespace
  prefix).
- The `<routing-engine>` is either directly beneath `<rpc-reply>`, as in the
  captured Junos cluster commit-check reply, or within a recognized
  `<multi-routing-engine-results>` container.
- The routing-engine subtree contains a commit-check result marker
  (`<commit-check-success/>`) or an `<rpc-error>`.
- The next sibling `<routing-engine>` or a legitimate ancestor close proves
  where that element should have ended.
- No non-`routing-engine` mismatch, truncation, or unclosed element remains.

The scanner will not use a broad `xml.contains("routing-engine")` heuristic.
It will never synthesize closures for unrelated elements or close arbitrary
open elements at end-of-file. A repaired document must pass the same strict
parser and semantic validation as an originally well-formed document.

If the repair is uncertain or the repaired result remains invalid, the caller
receives the original strict parse error.

## Error Handling

The refactor introduces no public error variants:

- XML syntax, decoding, attribute, state-transition, missing-field, and
  ambiguous-outcome failures use `RpcError::ParseError`.
- A valid reply with the wrong message ID uses
  `RpcError::MessageIdMismatch`.
- A valid hard `<rpc-error>` uses `RpcError::ServerError`.

Internal helpers may use private structured error types to preserve context
while parsing, but they are converted at the `parse_rpc_reply()` boundary.
Parse-error messages should identify the violated invariant and relevant
element without including the full device reply, which may contain sensitive
configuration data.

## Test Strategy

### Characterization tests

Before replacing the parser, tests will lock down every currently supported
reply form:

- `<ok/>`
- `<data>` with nested namespaces and attributes
- Empty replies
- Multiple warnings
- Hard errors mixed with warnings
- Direct Junos custom-RPC payloads
- Well-formed multi-routing-engine replies
- Known malformed cluster commit-check success and error replies
- Entities and CDATA in data, error messages, and `<error-info>`

### Stricter behavior tests

Focused negative tests will cover:

- Missing, duplicate, malformed, and mismatched message IDs.
- Multiple or nested `<rpc-reply>` envelopes.
- Duplicate `<data>` elements.
- Mixed `<ok/>`, `<data>`, and direct payloads.
- Missing or invalid mandatory `<rpc-error>` fields.
- Malformed attributes and entity references.
- Invalid decoding.
- Significant content outside the reply envelope.
- Truncated XML.
- Unrelated malformed XML that merely mentions `routing-engine`.

### Repair tests

Table-driven fixtures will distinguish:

- One-node and two-node repairable cluster replies.
- Repairable cluster replies containing success, warnings, or hard errors.
- Well-formed cluster replies that bypass repair.
- Truncated cluster replies.
- Mismatched non-`routing-engine` elements.
- `routing-engine` elements without a commit-check marker or supported cluster
  placement.
- Inputs that would require more than the permitted narrow repair.

### Verification

Implementation verification will include:

```bash
cargo fmt --all -- --check
cargo test -p rustnetconf
cargo clippy -p rustnetconf --all-targets --all-features -- -D warnings
```

Clippy will also be run with `clippy::too_many_lines` and
`clippy::cognitive_complexity` enabled to confirm that the reply parser no
longer triggers either lint. Any unrelated pre-existing warnings will be
reported separately rather than hidden.

## Implementation Sequence

1. Add characterization tests against the current API and confirm they pass.
2. Move public reply types behind `rpc::reply` re-exports without behavior
   changes.
3. Implement and test `FragmentCapture`.
4. Implement `ReplyParser` and switch the strict path to it.
5. Remove `extract_rpc_reply_inner_content()` and the second parsing pass.
6. Add focused failing tests for the malformed-reply boundary, then implement
   the narrowed Junos repair scanner.
7. Add each stricter structural or mandatory-field test immediately before its
   corresponding validation rule.
8. Run formatting, tests, standard Clippy, and complexity checks.

Except for the intentional failing-test phase of each red-green cycle, every
step should keep the crate compiling and all completed tests passing.

## Success Criteria

- Current public reply and error APIs remain source-compatible.
- Supported standard and Junos fixtures produce the intended existing result
  variants.
- Qualified names, namespaces, attributes, entities, CDATA, and nested
  `<error-info>` survive capture correctly.
- Only the documented Junos chassis-cluster defect is repairable.
- Ambiguous or structurally invalid replies fail deterministically.
- The parser has explicit, testable states and small event handlers.
- The reply parser no longer triggers Clippy's `too_many_lines` or
  `cognitive_complexity` warnings.
- Format, test, and standard lint verification pass.
