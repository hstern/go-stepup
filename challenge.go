// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

// Challenge is the typed representation of a single WWW-Authenticate Bearer
// challenge as defined by RFC 9470 §3 (and the underlying Bearer scheme of
// RFC 6750). One Challenge corresponds to one auth-scheme entry in a
// WWW-Authenticate header — a response may carry several. The auth-scheme is
// always "Bearer"; the auth-params live in the fields below.
//
// Fields are in spec-canonical emit order: realm, scope, error,
// error_description, error_uri, acr_values, max_age. Unknown auth-params are
// preserved in Extra to keep the round-trip lossless across future RFC 9470
// amendments and vendor extensions.
//
// The zero value is a valid empty challenge: nil ACRValues, nil MaxAge, and
// nil Extra are all legal and equivalent to the parameter being absent on
// the wire. All fields are independently optional from the type's
// perspective; spec-level rules about which combinations are meaningful live
// in Validate (added in a later commit), not in the type. Per RFC 7235 §2.2,
// all auth-param names are case-insensitive on the wire; the parser
// normalizes to lowercase, the formatter emits lowercase.
//
// See RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge Protocol,
// §3 "Authentication Challenge" — https://www.rfc-editor.org/rfc/rfc9470.html#section-3.
type Challenge struct {
	// Realm is the RFC 7235 protection-space identifier (auth-param "realm").
	// Optional in RFC 9470 challenges; when absent the resource server is
	// signaling that no realm differentiation is in play.
	Realm string

	// Scope is the OAuth 2.0 scope value (auth-param "scope") the client
	// needs to satisfy. Space-separated tokens per RFC 6749 §3.3 — this
	// library does not split them; consumers that need the token set can
	// strings.Fields the value. Optional.
	Scope string

	// ErrorCode is the OAuth 2.0 error code (auth-param "error"). For
	// RFC 9470 challenges this is "insufficient_user_authentication"; for
	// the inherited RFC 6750 codes see the Error* constants. Dispatch on
	// the [ErrInsufficientUserAuthentication] sentinel via errors.Is when
	// converting a parsed Challenge to an error chain.
	ErrorCode string

	// ErrorDescription is the human-readable error description (auth-param
	// "error_description") per RFC 6749 §5.2. Free-form ASCII; not intended
	// for end-user display.
	ErrorDescription string

	// ErrorURI is the URI of a page describing the error (auth-param
	// "error_uri") per RFC 6749 §5.2. Optional.
	ErrorURI string

	// ACRValues is the list of Authentication Context Class Reference values
	// the resource requires (auth-param "acr_values"). On the wire this is
	// one quoted-string of space-separated tokens — mirroring the OIDC
	// acr_values request parameter; in the typed surface the library exposes
	// it as a []string so consumers don't re-split on every read. The parser
	// splits, the formatter joins.
	ACRValues []string

	// MaxAge is the maximum acceptable authentication age in seconds
	// (auth-param "max_age") per RFC 9470 §3. Pointer-to-uint64, not bare
	// uint64, so the type can distinguish "not set" (nil) from "set to 0"
	// (non-nil pointer to 0) — zero is a valid value per spec and forces
	// the client to re-authenticate even if the existing session is fresh.
	// Callers reading the field must nil-check before dereferencing.
	MaxAge *uint64

	// Extra carries any auth-params the parser did not recognize as one of
	// the seven spec-defined params above. Keys are the lowercased
	// auth-param names; values are the unescaped quoted-string contents (or
	// the raw token for token-form params). Forward-compatibility hatch for
	// future RFC 9470 amendments and for vendor extensions that ride on the
	// same header value. The formatter emits Extra entries in lexicographic
	// key order after the spec-ordered fields, so round-trip output is
	// stable.
	Extra map[string]string
}
