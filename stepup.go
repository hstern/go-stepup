// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

// Package stepup is a Go implementation of RFC 9470 — OAuth 2.0 Step-Up
// Authentication Challenge Protocol.
//
// The library parses and emits the WWW-Authenticate: Bearer challenge a
// resource server returns when an access token is technically valid but does
// not meet the authentication strength (or recency) the resource requires.
// Consumers dispatch on the typed [Challenge] value or on the
// [ErrInsufficientUserAuthentication] sentinel that subsequent commits
// introduce.
//
// Subsequent commits add the Challenge type, the parser, the canonical-form
// formatter, the optional Validate, and the spec-fixture round-trip test
// corpus.
//
// See https://www.rfc-editor.org/rfc/rfc9470.html.
package stepup

// SpecVersion is the RFC version this library targets. Pinned to the
// Proposed Standard published in 2023-09; future RFC revisions bump this
// constant alongside the library SemVer (independently).
const SpecVersion = "RFC 9470"
