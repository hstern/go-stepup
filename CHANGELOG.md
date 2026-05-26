# Changelog

All notable changes to `go-stepup` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

The library SemVer is independent of the RFC version it implements.
See [`README.md`](README.md) §Stability for the versioning policy.

## [Unreleased]

## [0.1.0] - 2026-05-26

First tagged release. `go-stepup` is a stdlib-only, library-vendor-neutral
Go implementation of
[RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html)
— the `WWW-Authenticate: Bearer` challenge a resource server emits
when an access token is technically valid but does not meet the
authentication strength or recency the resource requires. The release
ships the full typed `Challenge` surface plus a lenient parser, a
canonical-form formatter, and an opt-in semantic validator. The
load-bearing property: `Parse → String → Parse` is typed-field
equivalent on every example from RFC 9470 §3, pinned by the
`internal/specfixtures/` conformance corpus.

### Added

- `Challenge` struct — typed representation of a single WWW-Authenticate
  Bearer challenge, with one field per RFC 9470 §3 / RFC 6750 / RFC 7235
  auth-param (`Realm`, `Scope`, `ErrorCode`, `ErrorDescription`,
  `ErrorURI`, `ACRValues`, `MaxAge`) plus an `Extra map[string]string`
  forward-compatibility hatch carrying any auth-param the parser does
  not recognize. `MaxAge` is `*uint64` so a deliberate zero is
  distinguishable from absent; `ACRValues` is `[]string` so callers
  don't re-split on every read.
- `SpecVersion = "RFC 9470"` — the spec revision this library targets.
- Auth-param name constants (`ParamRealm`, `ParamScope`, `ParamError`,
  `ParamErrorDescription`, `ParamErrorURI`, `ParamACRValues`,
  `ParamMaxAge`) covering the RFC 7235 / RFC 6750 / RFC 9470 §3
  vocabulary.
- Error-code wire-string constants (`ErrorInvalidRequest`,
  `ErrorInvalidToken`, `ErrorInsufficientScope`,
  `ErrorInsufficientUserAuthentication`) for direct comparison
  against the `Challenge.ErrorCode` field.
- `ErrInsufficientUserAuthentication` sentinel for `errors.Is`-style
  dispatch when converting a parsed challenge into an error chain.
- Typed error structs — `*ParseError` (grammar / `max_age` violations
  surfaced with a `Position` inside the offending challenge),
  `*ValidationError` (semantic-rule failures from `Validate`, with a
  stable `Rule` identifier and the wire `Field` name), and
  `*FormatError` (unrepresentable byte detected by `MarshalString`,
  with the wire `Field` name and the offending byte's offset).
- `Parse(headerValue string) (*Challenge, error)` — single-header-value
  parser. Walks comma-separated challenges, returns the first Bearer
  challenge with auth-params mapped onto the typed `Challenge` fields
  (and unknown params preserved in `Extra`). Bearer scheme matching is
  case-insensitive per RFC 7235 §2.1; non-Bearer challenges are skipped
  silently and a value containing no Bearer challenge yields `(nil, nil)`.
  Grammar violations and `max_age` validation failures return a
  `*ParseError` whose `Position` points inside the offending challenge.
- `ParseHeader(h http.Header) ([]*Challenge, error)` — HTTP-level
  dispatch entry point. Scans every `WWW-Authenticate` header value
  (case-insensitive header-name lookup via `http.Header.Values`), and
  returns the Bearer challenges that carry
  `error="insufficient_user_authentication"` — i.e. the RFC 9470 step-up
  challenges — in header-then-source order. Non-Bearer schemes and
  Bearer challenges with any other (or absent) error code are silently
  filtered out, so a response advertising Basic and Bearer challenges in
  parallel, or a Bearer challenge signalling `invalid_token`, surfaces as
  `(nil, nil)`. On the first grammar violation in any header value the
  call aborts and returns `(nil, *ParseError)` rather than yielding a
  partial result.
- `(*Challenge).String() string` — canonical-form `WWW-Authenticate`
  formatter satisfying [`fmt.Stringer`]. Emits the literal `Bearer`
  scheme, the seven RFC 9470 / RFC 6750 / RFC 7235 auth-params in spec
  order (`realm`, `scope`, `error`, `error_description`, `error_uri`,
  `acr_values`, `max_age`) for fields that carry a non-zero value, then
  every `Extra` entry in lexicographic key order — so the output is
  byte-stable across runs even though Go map iteration is randomized.
  Text parameters are always quoted-string per RFC 7230 §3.2.6; `max_age`
  is always token form. Per the [`fmt.Stringer`] no-error contract,
  bytes the quoted-string production cannot represent (raw control
  characters, CR, LF) are best-effort replaced with `SP`; the
  replacement incidentally neutralizes CRLF header-injection vectors by
  collapsing them to in-quote whitespace.
- `(*Challenge).MarshalString() (string, error)` — fail-fast sibling of
  `String`. Returns the same canonical bytes when every value is
  representable by RFC 7230 §3.2.6 quoted-string + quoted-pair; returns
  a `*FormatError` naming the field and the offending byte's offset when
  a value contains a byte that grammar cannot encode (any control byte
  other than HTAB, plus DEL — including CR and LF, the header-framing
  injection vectors). Use when the lossy SP-substitution `String` does
  is the wrong behavior — fixture serialization, interop regression
  tests, security-sensitive callers that need to surface malformed input
  rather than mask it. On multiple offending fields the first failure
  in spec emit order wins (so a Realm CR plus a Scope LF reports the
  realm); a pure-empty `Challenge` marshals to `"Bearer"` with no
  error, matching the canonical-form rule `String` pins.
- `(*Challenge).WriteHeader(h http.Header)` — convenience sugar that
  appends a canonical-form `WWW-Authenticate` value (the result of
  `c.String`) to `h`. Multiple calls append additional header values, so
  a response advertising a Bearer step-up challenge alongside a Basic
  fallback is two `WriteHeader` calls (or one `WriteHeader` plus one
  direct `h.Add`). Inherits `String`'s lossy SP-substitution fallback
  for unrepresentable bytes; callers who need fail-fast behavior should
  call `MarshalString` and add the result themselves. Emission is
  policy-free — `WriteHeader` faithfully writes any Bearer `Challenge`,
  even one whose `ErrorCode` would be filtered out on the receive side
  by `ParseHeader`. Passing a nil `http.Header` panics, matching the
  behavior of `http.Header.Add` on a nil receiver.
- `(*Challenge).Validate() error` — opt-in semantic validator over the
  grammar-correct types `Parse` produces. Rejects an unrecognized `error`
  code, an empty `acr_values` token, or a `max_age` above the package-level
  `MaxAgeUpperBound` (default one year of seconds; overridable before
  calling `Validate`). Returns the first `*ValidationError` it finds in
  field declaration order; the stable rule identifiers
  `RuleErrorCodeRecognized`, `RuleACRValuesNonEmpty`, and
  `RuleMaxAgeInBounds` are exported so `errors.As` consumers can branch
  without hardcoding strings. Does not inspect `Realm`, `Scope`,
  `ErrorDescription`, `ErrorURI`, or `Extra` — the latter is the
  forward-compatibility hatch and remains untouched by design.
- Spec-fixture corpus: every WWW-Authenticate example from RFC 9470 §3
  is embedded under `internal/specfixtures/` as one `.txt` file per
  figure, and a root-package `conformance_test.go` iterates the corpus
  asserting the `Parse → String → Parse` round-trip yields
  typed-field-equivalent `*Challenge` values (not byte-equivalent — the
  canonical formatter may reorder, lowercase, or re-quote). A companion
  `MarshalString`-vs-`String` agreement test pins the fail-fast
  formatter's output to match `String` byte-for-byte on every spec
  example, since none of them contain bytes the quoted-string grammar
  cannot represent. Adding a new fixture is "drop a `.txt` file"; the
  `//go:embed` directive picks it up on the next build with no Go
  change required. The corpus is intentionally `internal/` — it is a
  library-private testing aid, not part of the public API.
- Forward-compatibility regression tests (`forward_compat_test.go`)
  pinning the contract that auth-params the parser does not recognize
  as one of the seven RFC 9470 / RFC 6750 / RFC 7235 spec-defined names
  land verbatim on `Challenge.Extra`, that the canonical-form formatter
  emits them back, and that `Parse → String → Parse` and the HTTP-level
  `WriteHeader → ParseHeader` round-trips preserve them. This is the
  invariant that lets existing consumers survive a future RFC 9470
  amendment that adds a new auth-param, or a vendor extension a
  particular resource server chooses to advertise, without a library
  upgrade.
- README quickstart written against the landed `ParseHeader` /
  `WriteHeader` surface: a compilable end-to-end parse example, a
  resource-server emission example, and documentation of the
  `ErrInsufficientUserAuthentication` sentinel's intended
  `errors.Is` wrap-and-dispatch role. Stability section covers
  `Validate`'s rule-identifier contract.
- Doc-comment coverage across the public API. Cross-references use Go
  1.19+ `[Symbol]` bracket links so they render as hyperlinks on
  pkg.go.dev; the package overview lists every entry point and pins the
  `Parse → String → Parse` typed-field-equivalence round-trip contract;
  `FormatError.Field` and `ValidationError.Field` document that they
  carry the wire auth-param name (matching the `Param*` constants), not
  the Go struct field name on `Challenge`.
- Godoc Example functions (`example_test.go`) for every public entry
  point — `ExampleParse`, `ExampleParseHeader`, `ExampleChallenge_String`,
  `ExampleChallenge_WriteHeader`, `ExampleChallenge_MarshalString`,
  `ExampleChallenge_Validate`. These are executable documentation:
  `go test` runs them and compares stdout against the `// Output:` block,
  so the snippets pkg.go.dev renders cannot drift from the actual API
  behavior. `ExampleParseHeader` doubles as documentation for the
  Bearer-plus-`insufficient_user_authentication` filter — the most
  surprising behavior on the parse side.
