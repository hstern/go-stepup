# Changelog

All notable changes to `go-stepup` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

The library SemVer is independent of the RFC version it implements.
See [`README.md`](README.md) §Stability for the versioning policy.

## [Unreleased]

### Added

- Auth-param name constants (`ParamRealm`, `ParamScope`, `ParamError`,
  `ParamErrorDescription`, `ParamErrorURI`, `ParamACRValues`,
  `ParamMaxAge`) covering the RFC 7235 / RFC 6750 / RFC 9470 §3
  vocabulary.
- Error-code wire-string constants (`ErrorInvalidRequest`,
  `ErrorInvalidToken`, `ErrorInsufficientScope`,
  `ErrorInsufficientUserAuthentication`) for direct comparison
  against the `Challenge.ErrorCode` field.
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
