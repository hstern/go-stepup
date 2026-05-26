// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestParseAuthParams covers the happy paths the RFC 7235 §2.2
// grammar admits, plus the spec-asymmetries every implementer hits
// once. Each table case names the grammar feature it exercises so
// failures pinpoint the broken production. The function is shared by
// the public Parse entry point introduced in a later commit; this
// table is therefore also the regression net for that wrapper.
func TestParseAuthParams(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		in           string
		wantParams   []authParam
		wantConsumed int
	}{
		{
			name:         "empty input",
			in:           "",
			wantParams:   nil,
			wantConsumed: 0,
		},
		{
			name: "single token-form param",
			in:   "max_age=5",
			wantParams: []authParam{
				{name: "max_age", value: "5", isQuoted: false},
			},
			wantConsumed: 9,
		},
		{
			name: "single quoted-form param",
			in:   `realm="example"`,
			wantParams: []authParam{
				{name: "realm", value: "example", isQuoted: true},
			},
			wantConsumed: 15,
		},
		{
			name: "RFC 9470 §3 first example",
			in:   `realm="example", error="insufficient_user_authentication", error_description="Multi-factor authentication required", acr_values="myACR"`,
			wantParams: []authParam{
				{name: "realm", value: "example", isQuoted: true},
				{name: "error", value: "insufficient_user_authentication", isQuoted: true},
				{name: "error_description", value: "Multi-factor authentication required", isQuoted: true},
				{name: "acr_values", value: "myACR", isQuoted: true},
			},
			wantConsumed: 135,
		},
		{
			name: "RFC 9470 §3 max_age example with quoted form",
			in:   `error="insufficient_user_authentication", error_description="More recent authentication required", max_age="5"`,
			wantParams: []authParam{
				{name: "error", value: "insufficient_user_authentication", isQuoted: true},
				{name: "error_description", value: "More recent authentication required", isQuoted: true},
				{name: "max_age", value: "5", isQuoted: true},
			},
			wantConsumed: 110,
		},
		{
			name: "name case-folded to lowercase",
			in:   `Realm="x", REALM="y", reAlm="z"`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
				{name: "realm", value: "y", isQuoted: true},
				{name: "realm", value: "z", isQuoted: true},
			},
			wantConsumed: 31,
		},
		{
			name: "BWS around '='",
			in:   `realm  =  "x"`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
			},
			wantConsumed: 13,
		},
		{
			name: "OWS around list comma",
			in:   "a=1 ,  b=2\t,\tc=3",
			wantParams: []authParam{
				{name: "a", value: "1", isQuoted: false},
				{name: "b", value: "2", isQuoted: false},
				{name: "c", value: "3", isQuoted: false},
			},
			wantConsumed: 16,
		},
		{
			name: "RFC 7230 §7 empty list elements collapsed",
			in:   `,, realm="x", , , scope="read"  , ,`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
				{name: "scope", value: "read", isQuoted: true},
			},
			wantConsumed: 35,
		},
		{
			name: "quoted-pair: embedded DQUOTE",
			in:   `realm="foo \"bar\" baz"`,
			wantParams: []authParam{
				{name: "realm", value: `foo "bar" baz`, isQuoted: true},
			},
			wantConsumed: 23,
		},
		{
			name: "quoted-pair: embedded backslash",
			in:   `error_description="a\\b"`,
			wantParams: []authParam{
				{name: "error_description", value: `a\b`, isQuoted: true},
			},
			wantConsumed: 24,
		},
		{
			name: "quoted-pair: VCHAR decodes to literal byte (not control char)",
			in:   `error_description="line\none"`,
			wantParams: []authParam{
				// "\n" inside the source is the two bytes
				// '\' and 'n'; the quoted-pair rule
				// collapses them to the literal byte 'n',
				// NOT a newline. See RFC 7230 §3.2.6.
				{name: "error_description", value: "linenone", isQuoted: true},
			},
			wantConsumed: 29,
		},
		{
			name: "quoted-string with space-separated tokens (acr_values shape)",
			in:   `acr_values="mfa hwk"`,
			wantParams: []authParam{
				{name: "acr_values", value: "mfa hwk", isQuoted: true},
			},
			wantConsumed: 20,
		},
		{
			name: "value tokens with all tchar specials",
			in:   "x=!#$%&'*+-.^_`|~",
			wantParams: []authParam{
				{name: "x", value: "!#$%&'*+-.^_`|~", isQuoted: false},
			},
			wantConsumed: 17,
		},
		{
			name: "obs-text byte inside quoted-string accepted",
			in:   "realm=\"caf\xe9\"",
			wantParams: []authParam{
				{name: "realm", value: "caf\xe9", isQuoted: true},
			},
			wantConsumed: 12,
		},
		{
			name: "leading OWS before first param",
			in:   `   realm="x"`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
			},
			wantConsumed: 12,
		},
		{
			name: "single empty quoted-string",
			in:   `realm=""`,
			wantParams: []authParam{
				{name: "realm", value: "", isQuoted: true},
			},
			wantConsumed: 8,
		},
		{
			name: "multi-scheme: stop at next auth-scheme boundary",
			// `realm="x"` belongs to this scheme; `Bearer` is
			// the next scheme's token (no '=' follows, even
			// after BWS), so the tokenizer returns consumed
			// pointing at the 'B' of Bearer.
			in: `realm="x", Bearer realm="y"`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
			},
			wantConsumed: 11,
		},
		{
			name: "multi-scheme: no params before next scheme",
			// Input starts with what would be an auth-scheme
			// followed (after at least one space, but the BWS
			// pass also accepts none) by another token without
			// an '='. The whole input belongs to the caller's
			// outer scheme dispatcher; this function reports
			// zero params consumed.
			in:           "Basic",
			wantParams:   nil,
			wantConsumed: 0,
		},
		{
			name: "multi-scheme boundary after trailing comma",
			// Trailing comma after the last param of scheme A,
			// then scheme B's bare token. The list-rule allows
			// the trailing comma; the auth-scheme boundary is
			// detected when B's token has no '=' after it.
			in: `realm="x", , Bearer error="invalid_token"`,
			wantParams: []authParam{
				{name: "realm", value: "x", isQuoted: true},
			},
			wantConsumed: 13,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotParams, gotConsumed, gotErr := parseAuthParams(tc.in)
			if gotErr != nil {
				t.Fatalf("parseAuthParams(%q) returned error: %v", tc.in, gotErr)
			}
			if !reflect.DeepEqual(gotParams, tc.wantParams) {
				t.Errorf("params mismatch for %q\n got:  %#v\n want: %#v", tc.in, gotParams, tc.wantParams)
			}
			if gotConsumed != tc.wantConsumed {
				t.Errorf("consumed mismatch for %q: got %d, want %d", tc.in, gotConsumed, tc.wantConsumed)
			}
		})
	}
}

// TestParseAuthParamsErrors covers grammar violations. Each case
// asserts both that an error is returned and that the *ParseError
// Position points at the offending byte, since callers (and human
// debuggers) rely on the offset to locate the problem in the original
// header value.
func TestParseAuthParamsErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		in           string
		wantPosition int
		wantReason   string
	}{
		{
			name:         "name starts with non-tchar",
			in:           `,@bad="x"`,
			wantPosition: 1,
			wantReason:   "expected auth-param name token",
		},
		{
			name: "missing value after '='",
			in:   `realm=`,
			// Position is at end-of-string; we've consumed
			// the '=' and the (empty) BWS that follows.
			wantPosition: 6,
			wantReason:   "expected auth-param value after '='",
		},
		{
			name:         "value starts with non-tchar non-DQUOTE byte",
			in:           `realm=@`,
			wantPosition: 6,
			wantReason:   "expected token or quoted-string for auth-param value",
		},
		{
			name:         "unterminated quoted-string",
			in:           `realm="unfinished`,
			wantPosition: 6,
			wantReason:   "unterminated quoted-string",
		},
		{
			name:         "dangling backslash inside quoted-string",
			in:           `realm="a\`,
			wantPosition: 8,
			wantReason:   "dangling '\\' in quoted-string",
		},
		{
			name: "control byte inside quoted-string",
			// CR inside a quoted-string is rejected — it would
			// break header framing.
			in:           "realm=\"a\rb\"",
			wantPosition: 8,
			wantReason:   "invalid byte in quoted-string",
		},
		{
			name:         "missing comma between params",
			in:           `realm="x" scope="read"`,
			wantPosition: 10,
			wantReason:   "expected ',' or end of input after auth-param value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, gotErr := parseAuthParams(tc.in)
			if gotErr == nil {
				t.Fatalf("parseAuthParams(%q) succeeded; want *ParseError at position %d", tc.in, tc.wantPosition)
			}
			// The narrowed return type is *ParseError; the
			// errors.As check guards against future refactors
			// that widen it without updating callers.
			var pe *ParseError
			if !errors.As(error(gotErr), &pe) {
				t.Fatalf("parseAuthParams(%q) returned %T; want *ParseError", tc.in, gotErr)
			}
			if pe.Position != tc.wantPosition {
				t.Errorf("Position for %q: got %d, want %d", tc.in, pe.Position, tc.wantPosition)
			}
			if pe.Reason != tc.wantReason {
				t.Errorf("Reason for %q: got %q, want %q", tc.in, pe.Reason, tc.wantReason)
			}
		})
	}
}

// TestIsTcharBoundary checks every byte at the boundaries of the
// tchar production. The byte set is small enough (256 values) that
// exhaustive coverage is cheap and protects against off-by-one drift
// in the hand-rolled membership table.
func TestIsTcharBoundary(t *testing.T) {
	t.Parallel()

	want := map[byte]bool{}
	for c := byte('a'); c <= 'z'; c++ {
		want[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		want[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		want[c] = true
	}
	for _, c := range []byte{'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'} {
		want[c] = true
	}

	for c := 0; c < 256; c++ {
		b := byte(c)
		got := isTchar(b)
		expected := want[b]
		if got != expected {
			t.Errorf("isTchar(%q / 0x%02x): got %v, want %v", b, b, got, expected)
		}
	}
}

// TestIsQdtextBoundary similarly exercises every byte against the
// RFC 7230 §3.2.6 qdtext production. The interesting boundaries are
// HTAB (allowed), CR/LF (rejected — would break header framing),
// DQUOTE / backslash (delimited out, not qdtext), and the obs-text
// range (%x80-FF, all allowed under lenient unmarshal).
func TestIsQdtextBoundary(t *testing.T) {
	t.Parallel()

	for c := 0; c < 256; c++ {
		b := byte(c)
		got := isQdtext(b)
		want := false
		switch {
		case b == '\t' || b == ' ':
			want = true
		case b == 0x21:
			want = true
		case b >= 0x23 && b <= 0x5B:
			want = true
		case b >= 0x5D && b <= 0x7E:
			want = true
		case b >= 0x80:
			want = true
		}
		if got != want {
			t.Errorf("isQdtext(0x%02x): got %v, want %v", b, got, want)
		}
	}
}

// FuzzParseAuthParams exercises the tokenizer with random inputs to
// flush out crashes (panics, out-of-bounds slice indexing, infinite
// loops the unit tests' deterministic shapes miss) and to check the
// structural invariants every successful parse must satisfy.
//
// Seed corpus covers the spec examples and the malformed shapes from
// the unit tests. The fuzz target's invariants:
//
//   - consumed is always in [0, len(in)];
//   - on a successful parse every returned param name is non-empty
//     and lowercased (the tokenizer's normalization contract);
//   - the function returns without panicking for any input.
//
// Coverage of the value contents themselves is left to the unit
// tests — a fuzz-generated quoted-string can legitimately decode to
// anything, so there's no useful round-trip invariant at the
// parseAuthParams layer alone. (Round-trip is the formatter's
// concern, exercised by TestQuotedPairRoundTrip.)
func FuzzParseAuthParams(f *testing.F) {
	seeds := []string{
		"",
		`realm="example"`,
		`max_age=5`,
		`realm="x", scope="read write"`,
		`error="insufficient_user_authentication", max_age="5"`,
		`Realm = "x" , Bearer error="invalid_token"`,
		`,, realm="x", , ,`,
		`realm="foo \"bar\" baz"`,
		`realm="unfinished`,
		`realm=@`,
		"realm=\"a\rb\"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		params, consumed, _ := parseAuthParams(in)
		if consumed < 0 || consumed > len(in) {
			t.Fatalf("consumed out of range: got %d for input of length %d", consumed, len(in))
		}
		for i, p := range params {
			if p.name == "" {
				t.Fatalf("param %d has empty name (input %q)", i, in)
			}
			if p.name != strings.ToLower(p.name) {
				t.Fatalf("param %d name %q not lowercase (input %q)", i, p.name, in)
			}
		}
	})
}

// TestQuotedPairRoundTrip exercises the property the canonical
// formatter (later commit) will rely on: every byte that
// isQuotedPairChar accepts, when emitted as a quoted-pair, parses
// back to itself. The check is asymmetric — only the bytes the
// production admits are covered, since the formatter will never
// emit a quoted-pair for a byte that the grammar rejects.
func TestQuotedPairRoundTrip(t *testing.T) {
	t.Parallel()

	for c := 0; c < 256; c++ {
		b := byte(c)
		if !isQuotedPairChar(b) {
			continue
		}
		// Build `x="\<b>"` and assert the decoded value is the
		// single byte <b>. This is the formatter's only legal
		// quoted-pair shape — leading backslash followed by the
		// escaped byte, no further qdtext between.
		in := "x=\"\\" + string(b) + "\""
		params, _, err := parseAuthParams(in)
		if err != nil {
			t.Fatalf("parseAuthParams(%q): unexpected error %v", in, err)
		}
		if len(params) != 1 {
			t.Fatalf("parseAuthParams(%q): got %d params, want 1", in, len(params))
		}
		if params[0].value != string(b) {
			t.Errorf("quoted-pair round-trip for 0x%02x: got %q, want %q", b, params[0].value, string(b))
		}
	}
}

// uint64p returns a pointer to v. Convenience for table-driven Parse
// tests that need to assert on the *uint64 MaxAge field's contents
// while distinguishing nil from a pointer to zero.
func uint64p(v uint64) *uint64 { return &v }

// TestParse exercises the public single-header-value parser. The
// tokenizer's coverage lives in TestParseAuthParams; this table focuses
// on the field-mapping layer Parse adds on top — scheme dispatch,
// multi-challenge skipping, typed-field population, and the auth-params
// that need special handling (acr_values split, max_age numeric parse).
func TestParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want *Challenge
	}{
		{
			// RFC 9470 §3 example using acr_values to demand a
			// stronger authentication context.
			name: "RFC 9470 §3 example — acr_values",
			in:   `Bearer realm="example", error="insufficient_user_authentication", error_description="Multi-factor authentication required", acr_values="myACR"`,
			want: &Challenge{
				Realm:            "example",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Multi-factor authentication required",
				ACRValues:        []string{"myACR"},
			},
		},
		{
			// RFC 9470 §3 example using max_age to demand a
			// recent authentication event.
			name: "RFC 9470 §3 example — max_age",
			in:   `Bearer error="insufficient_user_authentication", error_description="More recent authentication required", max_age="5"`,
			want: &Challenge{
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "More recent authentication required",
				MaxAge:           uint64p(5),
			},
		},
		{
			// RFC 9470 §3 example combining both signals — a
			// resource asserting both a context-class and a
			// freshness requirement.
			name: "RFC 9470 §3 example — acr_values and max_age combined",
			in:   `Bearer realm="example", error="insufficient_user_authentication", error_description="Strong, recent authentication required", acr_values="myACR", max_age="5"`,
			want: &Challenge{
				Realm:            "example",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Strong, recent authentication required",
				ACRValues:        []string{"myACR"},
				MaxAge:           uint64p(5),
			},
		},
		{
			name: "case-insensitive scheme — lowercase",
			in:   `bearer realm="x"`,
			want: &Challenge{Realm: "x"},
		},
		{
			name: "case-insensitive scheme — uppercase",
			in:   `BEARER realm="x"`,
			want: &Challenge{Realm: "x"},
		},
		{
			name: "case-insensitive scheme — mixed",
			in:   `BeArEr realm="x"`,
			want: &Challenge{Realm: "x"},
		},
		{
			name: "case-insensitive scheme — canonical",
			in:   `Bearer realm="x"`,
			want: &Challenge{Realm: "x"},
		},
		{
			name: "non-Bearer alone returns nil challenge",
			in:   `Basic realm="x"`,
			want: nil,
		},
		{
			name: "Bearer with no params yields zero-value challenge",
			in:   `Bearer`,
			want: &Challenge{},
		},
		{
			// A response may legitimately advertise Basic and
			// Bearer challenges side by side (RFC 7235 §4.1).
			// Parse skips Basic and returns the Bearer one.
			name: "multi-scheme: Bearer second wins over earlier Basic",
			in:   `Basic realm="x", Bearer realm="y", error="insufficient_user_authentication"`,
			want: &Challenge{
				Realm:     "y",
				ErrorCode: ErrorInsufficientUserAuthentication,
			},
		},
		{
			// Two Bearer challenges in one header value: the
			// first one wins. ParseHeader's broader contract
			// (return all relevant challenges in order) is the
			// surface for callers that need to see both.
			name: "multi-Bearer: first wins",
			in:   `Bearer realm="first", Bearer realm="second"`,
			want: &Challenge{Realm: "first"},
		},
		{
			// Forward-compat for future RFC 9470 amendments
			// and vendor extensions: unknown auth-params must
			// round-trip through Extra without erroring.
			name: "unknown auth-param lands in Extra",
			in:   `Bearer realm="x", foo="bar"`,
			want: &Challenge{
				Realm: "x",
				Extra: map[string]string{"foo": "bar"},
			},
		},
		{
			// All seven typed fields populated at once — locks
			// in the full auth-param-name → Challenge-field
			// mapping table. scope and error_uri only get
			// individual coverage here; the other five are
			// exercised by the RFC 9470 §3 example cases above.
			name: "all typed fields populated",
			in: `Bearer realm="r", scope="read write", error="invalid_token", ` +
				`error_description="d", error_uri="https://example.test/err", ` +
				`acr_values="a b", max_age=10`,
			want: &Challenge{
				Realm:            "r",
				Scope:            "read write",
				ErrorCode:        ErrorInvalidToken,
				ErrorDescription: "d",
				ErrorURI:         "https://example.test/err",
				ACRValues:        []string{"a", "b"},
				MaxAge:           uint64p(10),
			},
		},
		{
			// acr_values sent as an explicitly empty string:
			// the parser yields a non-nil zero-length slice so
			// callers can distinguish "param sent with empty
			// value" from "param absent" (nil ACRValues). The
			// godoc commits to this semantics.
			name: "acr_values explicitly empty yields non-nil empty slice",
			in:   `Bearer acr_values=""`,
			want: &Challenge{ACRValues: []string{}},
		},
		{
			// max_age accepts the bare-token form (RFC 7235
			// "token" production). The tokenizer strips the
			// quoting distinction by the time challengeFromParams
			// sees the value, so both forms collapse here.
			name: "max_age token form",
			in:   `Bearer max_age=300`,
			want: &Challenge{MaxAge: uint64p(300)},
		},
		{
			name: "max_age quoted form",
			in:   `Bearer max_age="300"`,
			want: &Challenge{MaxAge: uint64p(300)},
		},
		{
			// Zero is a valid max_age per RFC 9470 §3: it forces
			// the client to re-authenticate even on a fresh
			// session. The non-nil pointer carries the
			// "param sent, value 0" signal that bare uint64
			// could not distinguish from "param absent".
			name: "max_age zero — non-nil pointer to 0",
			in:   `Bearer max_age=0`,
			want: &Challenge{MaxAge: uint64p(0)},
		},
		{
			// acr_values on the wire is one space-separated
			// quoted-string; the parser splits to []string so
			// callers don't re-tokenize on every read. Multiple
			// inter-token spaces collapse per OIDC §3.1.2.1's
			// tokenization.
			name: "acr_values split on space",
			in:   `Bearer acr_values="urn:foo:bar urn:baz:qux"`,
			want: &Challenge{
				ACRValues: []string{"urn:foo:bar", "urn:baz:qux"},
			},
		},
		{
			name: "acr_values single token",
			in:   `Bearer acr_values="urn:foo:bar"`,
			want: &Challenge{
				ACRValues: []string{"urn:foo:bar"},
			},
		},
		{
			// Duplicate auth-params within one challenge
			// resolve last-write-wins. RFC 7235 is silent on
			// duplicates; this is the lenient-unmarshal posture
			// documented in Parse's godoc.
			name: "duplicate realm — last write wins",
			in:   `Bearer realm="first", realm="second"`,
			want: &Challenge{Realm: "second"},
		},
		{
			// Same last-write-wins rule applies to Extra
			// entries — duplicate unknown params keep the last
			// value rather than producing an error.
			name: "duplicate unknown param — last write wins in Extra",
			in:   `Bearer foo="first", foo="second"`,
			want: &Challenge{
				Extra: map[string]string{"foo": "second"},
			},
		},
		{
			// Empty header value: no scheme to dispatch on,
			// nothing to return. Treat as "no Bearer challenge
			// present" — same shape as a non-Bearer-only
			// response.
			name: "empty header value",
			in:   ``,
			want: nil,
		},
		{
			// Whitespace-only and stray-comma input: the
			// list-element skipping in the outer loop walks
			// past it and returns no challenge.
			name: "whitespace and stray commas only",
			in:   `  , , ,  `,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Parse(%q)\n got:  %#v\n want: %#v", tc.in, got, tc.want)
				if got != nil && got.MaxAge != nil {
					t.Logf("got.MaxAge = %d", *got.MaxAge)
				}
				if tc.want != nil && tc.want.MaxAge != nil {
					t.Logf("want.MaxAge = %d", *tc.want.MaxAge)
				}
			}
		})
	}
}

// TestParseErrors covers the failure modes Parse surfaces: scheme
// position, max_age numeric validation, and grammar errors that bubble
// through from the tokenizer. The tokenizer's own error coverage lives
// in TestParseAuthParamsErrors; this table focuses on the additional
// error paths Parse adds on top.
func TestParseErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
	}{
		{
			name: "max_age negative",
			in:   `Bearer max_age=-1`,
		},
		{
			name: "max_age non-numeric",
			in:   `Bearer max_age="abc"`,
		},
		{
			name: "max_age empty",
			in:   `Bearer max_age=""`,
		},
		{
			// Grammar violation in a Bearer challenge's
			// params: the tokenizer's *ParseError should
			// reach the caller verbatim (with the position
			// translated to an absolute offset).
			name: "unterminated quoted-string in Bearer",
			in:   `Bearer realm="unterminated`,
		},
		{
			// Grammar violation in a non-Bearer challenge's
			// params still surfaces — the parser does not
			// short-circuit error reporting on schemes it
			// would otherwise skip, since a malformed value
			// makes the subsequent challenge boundary
			// undecidable.
			name: "unterminated quoted-string in non-Bearer",
			in:   `Basic realm="unterminated`,
		},
		{
			// Bare bytes that are not a tchar at the scheme
			// position: the outer loop expects an auth-scheme
			// token first.
			name: "non-token scheme byte",
			in:   `@bad realm="x"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.in)
			if err == nil {
				t.Fatalf("Parse(%q) = (%#v, nil), want *ParseError", tc.in, got)
			}
			var perr *ParseError
			if !errors.As(err, &perr) {
				t.Fatalf("Parse(%q) returned %T, want *ParseError: %v", tc.in, err, err)
			}
			if got != nil {
				t.Errorf("Parse(%q) returned non-nil challenge alongside error: %#v", tc.in, got)
			}
		})
	}
}

// TestParseMaxAgeErrorPosition asserts that a max_age numeric
// validation error carries a Position inside the failing challenge —
// not at byte 0 of the header value, which would be misleading when the
// failing challenge is not the first one. The exact byte is the start
// of the failing challenge's params block; that is precise enough to
// localize the problem without forcing the implementation to thread a
// per-param offset through the tokenizer.
func TestParseMaxAgeErrorPosition(t *testing.T) {
	t.Parallel()

	// First challenge is Basic and is skipped; Bearer is the second
	// challenge and contains the bad max_age. The error position
	// should fall inside the Bearer challenge's params region (after
	// the "Basic realm=\"x\", Bearer " prefix), not at byte 0.
	in := `Basic realm="x", Bearer max_age="not a number"`
	_, err := Parse(in)
	if err == nil {
		t.Fatalf("Parse(%q) returned nil error, want *ParseError", in)
	}
	var perr *ParseError
	if !errors.As(err, &perr) {
		t.Fatalf("Parse(%q) returned %T, want *ParseError: %v", in, err, err)
	}
	bearerAt := strings.Index(in, "max_age")
	if perr.Position < bearerAt {
		t.Errorf("Parse(%q) reported position %d, want >= %d (inside the Bearer challenge)",
			in, perr.Position, bearerAt)
	}
}
