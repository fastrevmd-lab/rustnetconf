# Fuzz targets

Two properties that unit tests cover only at points, and which the code under
test gets wrong in ways that are silent rather than loud.

Requires nightly and a sanitizer, so this crate is deliberately **not** part of
the workspace — `cargo test --workspace` and CI do not build it.

```bash
cargo +nightly fuzz run fragment_embeds_cleanly -- -max_total_time=120
cargo +nightly fuzz run reply_parser_is_total   -- -max_total_time=120
```

Start from the curated corpus rather than cold. The **writable** corpus goes
first — libFuzzer adds every coverage-increasing input to the first directory it
is given, and `fuzz/seeds/` is tracked, so naming it first would fill the repo
with generated hash files:

```bash
cargo +nightly fuzz run fragment_embeds_cleanly \
  fuzz/corpus/fragment_embeds_cleanly fuzz/seeds/fragment_embeds_cleanly
```

## Oracle

`fragment_embeds_cleanly` checks the embedded document with **roxmltree**, not
quick-xml. An oracle built on the same parser as the code under test shares its
blind spots — quick-xml reports EOF without error on unclosed elements, which is
how the trailing-`<` escape survived, and it is permissive about illegal
character references and undefined entities. Differential fuzzing needs an
independent implementation to differ from.

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

## Known residual — read before trusting a green run

`fragment_embeds_cleanly` **still finds divergences** given enough time. A short
clean run means "no new class within that budget", not "the validator conforms".

Known cases, all reachable in minutes:

```
<a xmlns:p="urn:x" xmlns:q="urn:x"    # duplicate *expanded* attribute names.
   p:x="1" q:x="2"/>                  # `with_checks(true)` compares lexical keys
                                      # only, so tracking declarations is needed
```

Two classes previously listed here — unchecked attribute references, and `xmlns`
as an element prefix — are now rules 16 and 17 below. They were closed after the
fuzzer surfaced them again during the quick-xml 0.42 migration. That is the third
time this table has shrunk by enumeration and not reached zero.

This is structural, not a backlog item. `validate_xml_fragment` is a
hand-written conformance layer over quick-xml, which is *deliberately*
permissive — a pull parser built for speed, not a validating one. Every rule
below had to be added by hand after the fuzzer pointed at it:

| # | rule | what slipped through |
|---|---|---|
| 1 | balanced elements | a trailing `<` ate the enclosing closing tag |
| 2 | must not close the synthetic root | `</_>x<_>` balanced against the wrapper |
| 3 | `Char` production in text | C0 controls |
| 4 | `Char` in CDATA | same |
| 5 | defined entities only | `&cmp;` |
| 6 | character refs in range | `&#x4;` |
| 7 | `Name` production | `<\0ing/>`, `<]nterfaces/>` |
| 8 | `QName`, not bare `Name` | `<:/>` — NETCONF is namespace-based |
| 9 | attributes have values | `<a b/>`, `<inte\rrfacE/>` |
| 10 | whitespace between attributes | `<a b="1"c="2"/>` |
| 11 | no literal `]]>` in text | premature CDATA close |
| 12 | comment syntax | `<!-->`, `<---->` |
| 13 | PI target is a `Name` | `<?<a?>`. Colons **are** legal here — two revisions wrongly rejected `<?a:b?>` and then `<?a:b:c?>` by reusing the element-name (QName) check |
| 14 | `Char` in PI bodies | control characters |
| 15 | no literal `<` in attribute values | `<a b="x<y"/>` |
| 16 | reserved `xmlns` prefix on elements | `<xmlns:a/>` — a well-formed QName of two valid NCNames, which no conforming parser accepts. Attributes are the opposite case: `xmlns:p="…"` **is** the declaration syntax, so the rule cannot live in the shared name check |
| 17 | references in attribute values | `<i n='&'/>`, `<a b="&cmp;"/>`, `<a b="&#4;"/>` — quick-xml keeps attribute values raw and emits no `GeneralRef` event, so a bare `&`, an undefined entity and an out-of-range char ref all passed. Resolution now goes through the same helper the text path uses, so the two cannot disagree |

Enumerating rules terminates only when the list is complete, and nothing here
proves it is. #10 and #13 were found *after* the first twelve were fixed and the
residual was first written down; the three cases above were found after *that*.
Each round of review has produced more, and each fix is individually correct —
which is the point. The process does not converge.

The structural alternative — validate by attempting a *conforming* parse of the
embedded document, which is what this oracle does — is tracked in #89. It trades
a runtime dependency for a property that holds by construction rather than by
enumeration.

## Oracle

`fragment_embeds_cleanly` checks with **roxmltree**, not quick-xml. An oracle
built on the parser under test shares its blind spots: quick-xml reports EOF
without error on unclosed elements, which is how the trailing-`<` escape
survived the first version of this target.

Namespace *binding* is excluded, because whether a prefix resolves depends on
declarations the envelope supplies and the validator cannot see. Getting that
exclusion right took three attempts:

1. treating `UnknownNamespace` as success — wrong: roxmltree reports only the
   *first* error, so an unbound prefix hid every structural problem after it.
   `<p:a/><i n="1"x="2"/>` passed without its missing attribute separator ever
   being examined, and two of the rules above were found only once this was fixed
2. binding one prefix per iteration up to a cap — still wrong: with more distinct
   prefixes than the budget, the loop ends on `UnknownNamespace` and reports
   success *without ever parsing*. 70 prefixes followed by `<i n="&"/>` sailed
   through
3. scanning the fragment and binding every prefix in one pass, each to a
   **distinct** URI — sharing one URI makes `<a p:x="1" q:x="2"/>` a duplicate
   expanded attribute and a false positive
4. excluding prefixes the envelope already binds, and scanning the *full*
   NCName character set. Redeclaring `nc` puts two identical `xmlns:` attributes
   on one element, so `<nc:get/>` — the most ordinary fragment there is — failed
   outright; and an ASCII-only scan left a legal prefix like `é` unbound, which
   put the blind spot from (1) back for `<é:a/><i n="&"/>`

5. renaming the `xml` prefix before the oracle parse. roxmltree 0.20 does not
   know the implicitly-bound `xml` prefix and reports `UnknownNamespace("xml")`
   *even when `xmlns:xml` is declared to its one legal URI*, so binding it
   cannot help — a leading `<xml:a/>` stopped the parse before anything after it
   was examined. Prefix identity does not affect structural well-formedness, so
   the oracle's copy renames it and the property under test is unchanged

Everything the oracle synthesises — the alias for the `xml` prefix and the
namespace URIs it binds — is derived from the input so it cannot collide with
what the fragment declares itself. Both collisions were real false positives:
a fixed alias rewrote `xml:lang` and an existing `alias:lang` to one name, and a
fixed URI stem let `<a xmlns:q="urn:fuzz:synthetic:3" p:x="1" q:x="2"/>` bind
`p` to the URI `q` already had.

### Gaps the oracle keeps, on purpose

Two involve XML that spells things through character references, where the
oracle's plain string handling cannot see what a parser would:

- the `xml:` rewrite is a whole-string replacement, so a namespace URI that
  literally contains `xml:` is rewritten too. Against a second URI spelling the
  same value with a character reference (`urn:&#x78;ml:x`), only one side
  changes and a real duplicate-expanded-attribute error disappears
- `fresh_token` compares raw text, so a fragment declaring the generated URI via
  references (`urn&#x3A;fuzz&#x3A;synthetic&#x3A;0`) is not detected as a
  collision, and the oracle can false-fail

Both are fixable only by decoding entities and tracking QName positions — that
is, by parsing. See below for why that is the wrong trade.



roxmltree 0.20 accepts `<?M<x?>` although XML 1.0 §2.6 requires whitespace
between a PI target and its data, so this class is invisible to the oracle.

A hand-written check for it was tried and **reverted**. It scanned for `<?`
without tracking context, so `<!---</<?l ...` — a `<?` inside a *comment* — read
as an unterminated PI and failed a fragment that embeds fine. The fuzzer found
that within four minutes.

That is the argument against patching the oracle: its value is being an
independent implementation, and every rule reimplemented inside it is a rule
that can be wrong in its own way. The same reasoning applies to the two
entity-reference gaps above — closing them means decoding entities and tracking
QName positions inside the oracle, which is building the parser the oracle
exists to be independent of. `validate_xml_fragment` already rejects
`<?M<x?>`, so the gap masks nothing today; it is recorded here so a future
regression in that class is known to be invisible rather than assumed covered.

The NCName rules are reimplemented in the target rather than borrowed from the
crate. Sharing the code under test's notion of a name would couple the oracle to
it — the same mistake as using quick-xml as the oracle's parser.

Over-binding is harmless; unused `xmlns:` declarations are legal.

## `reply_parser_is_total`

`parse_rpc_reply` must return a `Result` on any input, never panic. It is the
one function in the crate that consumes fully device-controlled bytes, so a
panic there is reachable by anything on the management network.

This covers the coarse property. The finer ones — foreign namespaces, unstitched
entity references, mixed content, namespace undeclarations — are pinned by unit
tests, because a *wrong answer* is not a crash and a fuzzer cannot tell one
parse from another without an oracle.
