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
