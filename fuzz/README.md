# Fuzz targets

Two properties that unit tests cover only at points, and which the code under
test gets wrong in ways that are silent rather than loud.

Requires nightly and a sanitizer, so this crate is deliberately **not** part of
the workspace — `cargo test --workspace` and CI do not build it.

```bash
cargo +nightly fuzz run fragment_embeds_cleanly -- -max_total_time=120
cargo +nightly fuzz run reply_parser_is_total   -- -max_total_time=120
```

Start from the curated corpus rather than cold:

```bash
cargo +nightly fuzz run fragment_embeds_cleanly fuzz/seeds/fragment_embeds_cleanly
```

## `fragment_embeds_cleanly`

If `validate_xml_fragment` accepts a fragment, embedding that fragment in an RPC
must produce a well-formed document.

This is the *validate-then-trust* contract the crate relies on: callers splice
the validated string straight into a `format!`-built envelope, so anything the
validator accepts is trusted verbatim by every caller.

Only that direction is asserted. The reverse — the validator refusing something
a parser would accept — is a usability question, and is deliberately true: it
rejects `<?xml ...?>` and `<!DOCTYPE ...>` exactly because they parse fine alone
and break the document once embedded.

Two real bugs, both found within a minute of the target first running, both now
in the seed corpus:

- **`bare-lt`** — a fragment ending in `<`. quick-xml reads `<</b>` as the start
  of an element named `</b`, so the fragment eats the closing tag of whatever
  encloses it. Under the validator's synthetic `<_>` wrapper that merely leaves
  something unclosed at EOF and looked fine.
- **`root-escape`** — `</_>x<_>`. The fragment closes the validator's own
  synthetic root and reopens it, so the whole thing balances and a net-depth
  check accepts it — while the closing tag it supplied is unmatched anywhere
  real. The synthetic root had leaked into the language being validated.

## `reply_parser_is_total`

`parse_rpc_reply` must return a `Result` on any input, never panic. It is the
one function in the crate that consumes fully device-controlled bytes, so a
panic there is reachable by anything on the management network.

This covers the coarse property. The finer ones — foreign namespaces, unstitched
entity references, mixed content, namespace undeclarations — are pinned by unit
tests, because a *wrong answer* is not a crash and a fuzzer cannot tell one
parse from another without an oracle.
