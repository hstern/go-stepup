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

// Auth-param names defined by RFC 9470 §3 for the Bearer challenge, together
// with the auth-params it inherits from RFC 7235 §2.2 (realm) and RFC 6750
// §3 (scope, error, error_description, error_uri).
//
// RFC 7235 makes auth-param names case-insensitive on the wire; the library
// normalizes them to lowercase on parse and emits the lowercase spellings
// below on output. Consumers writing parameter names by hand should use
// these constants rather than string literals to keep call sites diff-clean
// against any future spec amendment that renames a parameter.
//
// See https://www.rfc-editor.org/rfc/rfc9470.html#section-3 for the
// RFC 9470 additions (acr_values, max_age) and
// https://www.rfc-editor.org/rfc/rfc6750.html#section-3 for the underlying
// RFC 6750 set.
const (
	// ParamRealm is the "realm" auth-param defined by RFC 7235 §2.2 and
	// reused by RFC 6750 and RFC 9470 to identify the protection space of
	// the resource.
	ParamRealm = "realm"

	// ParamScope is the "scope" auth-param defined by RFC 6750 §3, carrying
	// the space-separated list of OAuth scopes the resource requires.
	ParamScope = "scope"

	// ParamError is the "error" auth-param defined by RFC 6750 §3, carrying
	// the machine-readable error code. See the Error* constants for the
	// recognized values.
	ParamError = "error"

	// ParamErrorDescription is the "error_description" auth-param defined
	// by RFC 6750 §3, carrying a human-readable explanation of the error.
	ParamErrorDescription = "error_description"

	// ParamErrorURI is the "error_uri" auth-param defined by RFC 6750 §3,
	// carrying a URI to a page documenting the error. The constant name
	// uses URI per Go naming conventions for initialisms; the wire spelling
	// is "error_uri".
	ParamErrorURI = "error_uri"

	// ParamACRValues is the "acr_values" auth-param defined by RFC 9470 §3,
	// carrying the space-separated list of Authentication Context Class
	// Reference values the resource accepts. Mirrors the OIDC request
	// parameter of the same name.
	ParamACRValues = "acr_values"

	// ParamMaxAge is the "max_age" auth-param defined by RFC 9470 §3,
	// carrying the maximum allowable elapsed time in seconds since the end
	// user last actively authenticated. Mirrors the OIDC request parameter
	// of the same name.
	ParamMaxAge = "max_age"
)

// Error-code vocabulary for the "error" auth-param, defined by RFC 6750
// §3.1 and extended by RFC 9470 §3 with insufficient_user_authentication.
// These are the wire-string constants suitable for direct comparison
// against the Challenge.ErrorCode field — itself a plain string so
// consumers can write
//
//	if challenge.ErrorCode == stepup.ErrorInsufficientUserAuthentication { ... }
//
// without an intermediate type assertion.
//
// Naming note: the Error* constants below are the wire strings, distinct
// from the Err* sentinel error values exposed elsewhere in this package.
// ErrInsufficientUserAuthentication is the Go error value returned by
// parse and validation helpers; ErrorInsufficientUserAuthentication is
// the underlying RFC-defined string that error carries. The two
// intentionally share a literal payload but live in different namespaces
// because Go code reaches for them in different ways — errors.Is for the
// sentinel, string equality for the wire constant.
//
// See https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1 and
// https://www.rfc-editor.org/rfc/rfc9470.html#section-3.
const (
	// ErrorInvalidRequest is the "invalid_request" error code defined by
	// RFC 6750 §3.1.
	ErrorInvalidRequest = "invalid_request"

	// ErrorInvalidToken is the "invalid_token" error code defined by
	// RFC 6750 §3.1.
	ErrorInvalidToken = "invalid_token"

	// ErrorInsufficientScope is the "insufficient_scope" error code
	// defined by RFC 6750 §3.1.
	ErrorInsufficientScope = "insufficient_scope"

	// ErrorInsufficientUserAuthentication is the
	// "insufficient_user_authentication" error code defined by RFC 9470
	// §3, signalling that the access token is valid but the
	// authentication event behind it does not meet the resource's
	// strength or recency requirement.
	ErrorInsufficientUserAuthentication = "insufficient_user_authentication"
)
