// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup_test

import (
	"maps"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/hstern/go-stepup"
)

// The tests in this file pin the library's forward-compatibility
// guarantee: any auth-param the parser does not recognize as one of the
// seven RFC 9470 / RFC 6750 / RFC 7235 spec-defined parameters is
// preserved verbatim on Challenge.Extra, the canonical-form formatter
// emits it back, and a Parse → String → Parse round-trip yields a
// typed-field-equivalent Challenge.
//
// That contract is what lets existing go-stepup consumers survive two
// kinds of future change without a library upgrade:
//
//  1. An IETF amendment to RFC 9470 that adds a new auth-param. Today's
//     library does not know the name; the param lands in Extra, gets
//     re-emitted by String, and existing typed-field readers ignore it.
//     When a future library version promotes the param to a typed field,
//     the test cases here that reference that name move to a typed-field
//     assertion — that is the migration signal.
//
//  2. A vendor-specific extension some resource server chooses to
//     advertise on its WWW-Authenticate value (the spec is silent on
//     vendor extensions but the auth-param grammar admits them). The
//     library passes them through opaquely.
//
// The tests live in the external _test package on purpose: they exercise
// only the public API surface (Parse, ParseHeader, Challenge.String,
// Challenge.WriteHeader, Challenge.Extra) and so double as a
// black-box reproduction of the contract a downstream consumer can
// depend on. A future PR that "tightens" the parser to reject unknown
// auth-params would fail these tests; the file name is the explanation
// for why the tightening is wrong.

// TestForwardCompatVendorExtension exercises the most common
// forward-compat shape: a resource server advertises one or more
// vendor-specific auth-params alongside the RFC 9470 spec-defined ones,
// and the parser preserves them in Extra without affecting the typed
// fields. The test also exercises a full Parse → String → Parse
// round-trip to prove the extras survive re-emission.
func TestForwardCompatVendorExtension(t *testing.T) {
	t.Parallel()

	const in = `Bearer realm="example", error="insufficient_user_authentication", x_vendor_token="opaque", x_vendor_kind="totp"`

	c, err := stepup.Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c == nil {
		t.Fatal("Parse returned nil Challenge for a Bearer header value")
	}

	// Unknown auth-params landed in Extra. Per RFC 7235 §2.2 the parser
	// normalizes names to lowercase; Extra keys are therefore the
	// lowercased spellings regardless of the source casing.
	if got, want := c.Extra["x_vendor_token"], "opaque"; got != want {
		t.Errorf("Extra[%q] = %q, want %q", "x_vendor_token", got, want)
	}
	if got, want := c.Extra["x_vendor_kind"], "totp"; got != want {
		t.Errorf("Extra[%q] = %q, want %q", "x_vendor_kind", got, want)
	}

	// The typed fields populated correctly — Extra did not swallow
	// realm or error.
	if got, want := c.Realm, "example"; got != want {
		t.Errorf("Realm = %q, want %q", got, want)
	}
	if got, want := c.ErrorCode, stepup.ErrorInsufficientUserAuthentication; got != want {
		t.Errorf("ErrorCode = %q, want %q", got, want)
	}

	// Round-trip: emit the canonical form, parse it again, expect a
	// Challenge whose typed fields and Extra map equal the first parse.
	// Per implementer pin #8 in the design notes, round-trip equality
	// is typed-field-level, not byte-level — but reflect.DeepEqual on
	// two *Challenge values produced by the same parser is the
	// strongest practical assertion, since the formatter is
	// deterministic (extras sort lex on emit).
	canonical := c.String()
	again, err := stepup.Parse(canonical)
	if err != nil {
		t.Fatalf("Parse(canonical %q): %v", canonical, err)
	}
	if !reflect.DeepEqual(c, again) {
		t.Errorf("round-trip drift\n  first  = %+v\n  second = %+v\n  canon  = %q", c, again, canonical)
	}
}

// TestForwardCompatHypotheticalFutureParam simulates a future RFC
// amendment that adds a new auth-param the current library does not
// know. The chosen name "auth_time" mirrors the OIDC ID-Token claim of
// the same name and is the kind of param a near-term RFC 9470bis might
// plausibly add to let a resource server demand a freshness assertion
// directly. The point of the test is not to predict which param the
// spec will add — it is to lock in that an unknown name is not a parse
// failure and that round-trip preserves the value.
//
// When the library later promotes "auth_time" (or any chosen name) to
// a typed field, the test that exercises that name moves to a
// typed-field assertion — the migration is straightforward and the
// failing test is the prompt to do it.
func TestForwardCompatHypotheticalFutureParam(t *testing.T) {
	t.Parallel()

	const in = `Bearer error="insufficient_user_authentication", auth_time="1700000000"`

	c, err := stepup.Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c == nil {
		t.Fatal("Parse returned nil Challenge for a Bearer header value")
	}
	if got, want := c.Extra["auth_time"], "1700000000"; got != want {
		t.Errorf("Extra[%q] = %q, want %q", "auth_time", got, want)
	}

	// Round-trip preserves the unknown param.
	canonical := c.String()
	again, err := stepup.Parse(canonical)
	if err != nil {
		t.Fatalf("Parse(canonical %q): %v", canonical, err)
	}
	if !reflect.DeepEqual(c, again) {
		t.Errorf("round-trip drift\n  first  = %+v\n  second = %+v\n  canon  = %q", c, again, canonical)
	}
}

// TestForwardCompatExtraNameCaseInsensitive pins the case-folding
// behavior the RFC 7235 §2.2 grammar requires for auth-param names:
// names are case-insensitive on the wire, the parser normalizes to
// lowercase on input, and Extra is therefore keyed by the lowercased
// spelling regardless of how the value arrived. The test guards
// against a future "preserve source casing" regression that would
// surface as duplicate-key Extra entries for the same logical
// parameter.
func TestForwardCompatExtraNameCaseInsensitive(t *testing.T) {
	t.Parallel()

	const in = `Bearer X_VENDOR_TOKEN="opaque", error="insufficient_user_authentication"`

	c, err := stepup.Parse(in)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c == nil {
		t.Fatal("Parse returned nil Challenge for a Bearer header value")
	}

	if got, ok := c.Extra["x_vendor_token"]; !ok {
		// slices.Sorted + maps.Keys gives a deterministic key list for
		// the failure message even though map iteration is randomized.
		t.Errorf("Extra lowercase lookup failed; keys = %v", slices.Sorted(maps.Keys(c.Extra)))
	} else if got != "opaque" {
		t.Errorf("Extra[%q] = %q, want %q", "x_vendor_token", got, "opaque")
	}
	if _, ok := c.Extra["X_VENDOR_TOKEN"]; ok {
		t.Error("Extra retained source casing for an auth-param name; want lowercased")
	}
}

// TestForwardCompatRoundTripViaHTTPHeader closes the loop on the
// HTTP-level entry points: a Challenge built in Go code with arbitrary
// Extra entries emits via WriteHeader and round-trips back through
// ParseHeader with the extras preserved end-to-end. This is the path
// a resource server takes when it wants to advertise a vendor
// extension on a real http.Header, so the test mirrors that shape
// directly rather than going through the string-level Parse / String
// pair.
func TestForwardCompatRoundTripViaHTTPHeader(t *testing.T) {
	t.Parallel()

	orig := &stepup.Challenge{
		ErrorCode: stepup.ErrorInsufficientUserAuthentication,
		Extra: map[string]string{
			"x_vendor_token": "opaque",
			"x_vendor_kind":  "totp",
		},
	}

	h := http.Header{}
	orig.WriteHeader(h)

	got, err := stepup.ParseHeader(h)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ParseHeader returned %d challenges, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0], orig) {
		t.Errorf("round-trip drift\n  orig = %+v\n  got  = %+v\n  hdr  = %q",
			orig, got[0], h.Get("WWW-Authenticate"))
	}
}
