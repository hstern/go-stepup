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
