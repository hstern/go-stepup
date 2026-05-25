// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"errors"
	"fmt"
)

// ErrInsufficientUserAuthentication is the sentinel value clients dispatch on
// when bridging a parsed [Challenge] into Go's error-chain idiom. The string
// matches the RFC 9470 §3 error code "insufficient_user_authentication"
// verbatim so a Challenge whose ErrorCode equals this value can be wrapped
// and surfaced through errors.Is without an intermediate translation step.
//
// This is not returned by the parser itself — Parse returns a *ParseError on
// grammar failure, never this sentinel. Consumers that treat an
// "insufficient_user_authentication" challenge as an actionable error wrap or
// compare against this value themselves:
//
//	ch, err := stepup.Parse(headerValue)
//	if err != nil {
//	    return err
//	}
//	if ch != nil && ch.ErrorCode == stepup.ErrInsufficientUserAuthentication.Error() {
//	    return fmt.Errorf("step-up required: %w", stepup.ErrInsufficientUserAuthentication)
//	}
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3.
var ErrInsufficientUserAuthentication = errors.New("insufficient_user_authentication")

// ParseError reports a grammar-level failure while decoding a
// WWW-Authenticate header value. Returned by Parse and ParseHeader when the
// input violates the RFC 7235 auth-param grammar — unterminated quoted
// string, bad quoted-pair, malformed token, and so on. Semantic problems
// (unknown error code, out-of-range max_age) are not ParseErrors; those
// surface from Validate as a *ValidationError.
type ParseError struct {
	// Position is the byte offset into the header value where parsing
	// failed. Zero-based; points at the offending byte, not past it. For
	// errors that span a region (e.g. unterminated quoted string), Position
	// is the start of the region.
	Position int

	// Reason is a short human-readable description of what went wrong.
	// Stable enough to log but not part of the API surface for matching —
	// callers that need to discriminate should compare error types, not
	// strings.
	Reason string
}

// Error returns the formatted parse-error message including the byte offset.
func (e *ParseError) Error() string {
	return fmt.Sprintf("stepup: parse error at byte %d: %s", e.Position, e.Reason)
}

// ValidationError reports a semantic problem found by [Challenge.Validate].
// The Challenge parsed cleanly per the RFC 7235 grammar but violates a
// higher-level rule — an unrecognized error code, an empty acr_values token,
// a max_age outside the configured bounds, and so on. The three fields
// together identify which rule fired against which field of the Challenge.
type ValidationError struct {
	// Rule names the validation rule that fired (e.g.
	// "recognized-error-code", "non-empty-acr-token",
	// "max-age-within-bounds"). Stable string suitable for log filtering.
	Rule string

	// Field is the Challenge field name the rule applies to ("ErrorCode",
	// "ACRValues", "MaxAge", ...). Matches the Go field name, not the
	// auth-param wire name, so the reader can find the offending code path.
	Field string

	// Reason is a short human-readable description of why the rule failed.
	Reason string
}

// Error returns the formatted validation-error message including the rule,
// field, and reason.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("stepup: validation error: rule %s on field %s: %s", e.Rule, e.Field, e.Reason)
}

// FormatError reports that a Challenge holds a value the WWW-Authenticate
// wire format cannot represent — typically a parameter value containing a
// raw control character, CR, or LF that would break header framing.
// Returned by the strict marshal variant; the fmt.Stringer formatter is
// best-effort and does not surface FormatError.
type FormatError struct {
	// Field is the Challenge field name carrying the unrepresentable value
	// ("Realm", "ErrorDescription", a key from Extra, ...). Matches the Go
	// field name where applicable.
	Field string

	// Reason is a short human-readable description of why the value cannot
	// be formatted.
	Reason string
}

// Error returns the formatted format-error message including the field and
// reason.
func (e *FormatError) Error() string {
	return fmt.Sprintf("stepup: format error on field %s: %s", e.Field, e.Reason)
}
