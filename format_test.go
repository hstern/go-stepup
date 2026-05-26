// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// uintPtr is a tiny helper to build *uint64 inline for table-driven cases —
// MaxAge being *uint64 (to distinguish "not set" from "set to 0") would
// otherwise force a named temporary on every fixture row.
func uintPtr(v uint64) *uint64 { return &v }

func TestChallengeString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Challenge
		want string
	}{
		{
			// Zero-value Challenge: the canonical-form rule says the
			// scheme is always emitted, but no params means no
			// trailing space, comma, or "=" — the bare scheme token
			// alone. Pin this explicitly; it's the easy edge case to
			// regress into " Bearer", "Bearer ", or "Bearer ,".
			name: "empty challenge emits scheme only",
			in:   Challenge{},
			want: "Bearer",
		},
		{
			name: "realm only",
			in:   Challenge{Realm: "example"},
			want: `Bearer realm="example"`,
		},
		{
			// Every typed field set, in spec order, with the
			// per-param quoting rules. max_age is the lone
			// token-form parameter.
			name: "all known fields in spec order",
			in: Challenge{
				Realm:            "example",
				Scope:            "openid profile",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Strong authentication required",
				ErrorURI:         "https://example.com/err",
				ACRValues:        []string{"urn:mace:incommon:iap:silver"},
				MaxAge:           uintPtr(300),
			},
			want: `Bearer realm="example", scope="openid profile", error="insufficient_user_authentication", error_description="Strong authentication required", error_uri="https://example.com/err", acr_values="urn:mace:incommon:iap:silver", max_age=300`,
		},
		{
			// Pointer-to-zero vs nil: the typed surface uses
			// *uint64 precisely to make the distinction
			// observable on the wire. 0 is a valid spec value
			// (forces immediate re-auth).
			name: "max_age zero emits max_age=0",
			in:   Challenge{MaxAge: uintPtr(0)},
			want: "Bearer max_age=0",
		},
		{
			name: "max_age nil emits nothing",
			in:   Challenge{},
			want: "Bearer",
		},
		{
			// Empty slice and nil slice both round-trip as
			// "no acr_values parameter on the wire," matching the
			// "empty vs absent" semantics documented on String.
			name: "empty ACRValues slice emits nothing",
			in:   Challenge{ACRValues: []string{}},
			want: "Bearer",
		},
		{
			// Space-separated inside one quoted-string — the
			// OIDC-mirrored shape.
			name: "multi ACR values join with single SP",
			in:   Challenge{ACRValues: []string{"urn:a", "urn:b", "urn:c"}},
			want: `Bearer acr_values="urn:a urn:b urn:c"`,
		},
		{
			// quoted-pair escaping per RFC 7230 §3.2.6. Easy to
			// get the escape direction backwards — pin the exact
			// bytes.
			name: "quote and backslash in value are escaped",
			in:   Challenge{Realm: `foo "bar" baz \quux`},
			want: `Bearer realm="foo \"bar\" baz \\quux"`,
		},
		{
			// Extra alone, multiple keys: lex order.
			name: "extra entries emit in lex order",
			in: Challenge{
				Extra: map[string]string{
					"zebra": "z",
					"alpha": "a",
					"mango": "m",
				},
			},
			want: `Bearer alpha="a", mango="m", zebra="z"`,
		},
		{
			// Extra adjacent to known params: spec order first,
			// Extra (alphabetized) after.
			name: "extra follows spec-ordered known params",
			in: Challenge{
				Realm: "r",
				Extra: map[string]string{
					"zeta":  "z",
					"alpha": "a",
				},
			},
			want: `Bearer realm="r", alpha="a", zeta="z"`,
		},
		{
			// Lossy control-byte fallback. SOH (0x01) is not a
			// qdtext byte and quoted-pair cannot represent it
			// either, so the no-error contract collapses it to SP.
			name: "control byte falls back to SP",
			in:   Challenge{Realm: "a\x01b"},
			want: `Bearer realm="a b"`,
		},
		{
			// CR and LF collapse to SP — the header-injection
			// neutralization argument. After the fallback the
			// output is well-formed quoted-string the parser
			// will accept.
			name: "CR and LF fall back to SP",
			in:   Challenge{Realm: "a\rb\nc"},
			want: `Bearer realm="a b c"`,
		},
		{
			// HTAB and SP are qdtext-valid; pass through verbatim.
			name: "tab and space pass through",
			in:   Challenge{Realm: "a\tb c"},
			want: "Bearer realm=\"a\tb c\"",
		},
		{
			// obs-text (0x80+) admitted by RFC 7230 §3.2.6 in both
			// qdtext and quoted-pair — pass through verbatim under
			// the lenient-marshal-mirrors-lenient-unmarshal posture.
			name: "obs-text passes through",
			in:   Challenge{Realm: "a\xc3\xa9b"}, // "aéb" as UTF-8
			want: "Bearer realm=\"a\xc3\xa9b\"",
		},
		{
			// 0x7F (DEL) is excluded from qdtext — it falls into
			// the control-byte fallback.
			name: "DEL byte falls back to SP",
			in:   Challenge{Realm: "a\x7fb"},
			want: `Bearer realm="a b"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.in.String()
			if got != tc.want {
				t.Fatalf("String() mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestChallengeStringExtraOrderingStable repeatedly formats the same
// Extra-only Challenge to defend against map-iteration randomness leaking
// into the output. The sort step inside String exists for exactly this
// reason; a regression that drops it would manifest as an intermittent test
// failure here even though the table-driven case above might pass on a
// favorable iteration.
func TestChallengeStringExtraOrderingStable(t *testing.T) {
	t.Parallel()
	c := Challenge{
		Extra: map[string]string{
			"foxtrot": "f",
			"alpha":   "a",
			"echo":    "e",
			"bravo":   "b",
			"delta":   "d",
			"charlie": "c",
		},
	}
	const want = `Bearer alpha="a", bravo="b", charlie="c", delta="d", echo="e", foxtrot="f"`
	for i := range 32 {
		if got := c.String(); got != want {
			t.Fatalf("iteration %d: ordering drifted\n got: %q\nwant: %q", i, got, want)
		}
	}
}

// TestChallengeStringRoundTrip is the load-bearing round-trip check: take
// each RFC 9470 §3 example header value, parse it, format the parsed
// Challenge, parse the formatted output, and assert typed-field
// equivalence with the original parse. Byte equivalence is explicitly NOT
// the contract — the canonical formatter normalizes quoting style (e.g.
// max_age="5" on the wire becomes max_age=5 on output), so the two
// representations differ. What MUST hold is that the typed Challenge after
// the second parse equals the one after the first.
func TestChallengeStringRoundTrip(t *testing.T) {
	t.Parallel()
	// Source: RFC 9470 §3 "Authentication Challenge" examples.
	// https://www.rfc-editor.org/rfc/rfc9470.html#section-3
	inputs := []string{
		`Bearer realm="example", error="insufficient_user_authentication", error_description="Multi-factor authentication required", acr_values="myACR"`,
		`Bearer error="insufficient_user_authentication", error_description="More recent authentication required", max_age="5"`,
		`Bearer realm="example", error="insufficient_user_authentication", error_description="Strong, recent authentication required", acr_values="myACR", max_age="5"`,
	}
	for i, in := range inputs {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			t.Parallel()
			first, err := Parse(in)
			if err != nil {
				t.Fatalf("Parse(input) failed: %v", err)
			}
			if first == nil {
				t.Fatal("Parse(input) returned nil challenge")
			}
			formatted := first.String()
			second, err := Parse(formatted)
			if err != nil {
				t.Fatalf("Parse(formatted) failed: %v\nformatted: %q", err, formatted)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("round-trip lost data\n first:  %+v\n second: %+v\n formatted: %q",
					first, second, formatted)
			}
		})
	}
}

// TestChallengeMarshalString exercises the fail-fast sibling of String. The
// happy-path cases mirror the TestChallengeString table so the two methods
// agree byte-for-byte on every input writeQuotedString can represent; the
// error-path cases cover each *FormatError-producing input (one per
// excluded byte class plus the spec-defined fields). See the
// TestChallengeMarshalStringAgreesWithString sub-test below for the
// systematic agreement check across every valid case in TestChallengeString.
func TestChallengeMarshalString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Challenge
		// want and wantErr are mutually exclusive: a case either
		// asserts a successful marshal byte string OR an error
		// shape, never both.
		want string
		// wantErrField, when non-empty, asserts the test must
		// return a *FormatError whose Field equals this value
		// and whose Reason mentions wantErrByte (hex, uppercase).
		wantErrField string
		wantErrByte  string
	}{
		// --- happy path: every RFC 9470 §3 example marshals
		// successfully and the bytes match String. ---
		{
			name: "rfc9470 example A",
			in: Challenge{
				Realm:            "example",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Multi-factor authentication required",
				ACRValues:        []string{"myACR"},
			},
			want: `Bearer realm="example", error="insufficient_user_authentication", error_description="Multi-factor authentication required", acr_values="myACR"`,
		},
		{
			name: "rfc9470 example B",
			in: Challenge{
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "More recent authentication required",
				MaxAge:           uintPtr(5),
			},
			want: `Bearer error="insufficient_user_authentication", error_description="More recent authentication required", max_age=5`,
		},
		{
			name: "rfc9470 example C",
			in: Challenge{
				Realm:            "example",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Strong, recent authentication required",
				ACRValues:        []string{"myACR"},
				MaxAge:           uintPtr(5),
			},
			want: `Bearer realm="example", error="insufficient_user_authentication", error_description="Strong, recent authentication required", acr_values="myACR", max_age=5`,
		},
		{
			// Empty Challenge marshals to the bare scheme,
			// matching String's canonical-form rule.
			name: "empty challenge",
			in:   Challenge{},
			want: "Bearer",
		},
		{
			// HTAB is qdtext-valid — no error. Output is
			// byte-identical to String's; the round-trip check
			// below will assert that.
			name: "HTAB in Realm is representable",
			in:   Challenge{Realm: "a\tb"},
			want: "Bearer realm=\"a\tb\"",
		},
		{
			// obs-text (high-bit bytes; here the two-byte UTF-8
			// encoding of "é") is admitted by RFC 7230 §3.2.6.
			// Output is byte-stable.
			name: "obs-text in Realm is representable",
			in:   Challenge{Realm: "a\xc3\xa9b"},
			want: "Bearer realm=\"a\xc3\xa9b\"",
		},

		// --- error path: one case per excluded byte class
		// against a representative field. ---
		{
			// CR (0x0D) — the header-injection vector.
			name:         "CR in Realm errors",
			in:           Challenge{Realm: "a\rb"},
			wantErrField: ParamRealm,
			wantErrByte:  "0x0D",
		},
		{
			// LF (0x0A) — the other header-injection vector.
			name:         "LF in Scope errors",
			in:           Challenge{Scope: "openid\nprofile"},
			wantErrField: ParamScope,
			wantErrByte:  "0x0A",
		},
		{
			// NUL (0x00) — the canonical "control character"
			// most callers think of.
			name:         "NUL in ErrorDescription errors",
			in:           Challenge{ErrorDescription: "bad\x00stuff"},
			wantErrField: ParamErrorDescription,
			wantErrByte:  "0x00",
		},
		{
			// DEL (0x7F) — qdtext explicitly excludes it.
			name:         "DEL in ErrorURI errors",
			in:           Challenge{ErrorURI: "https://e/\x7f"},
			wantErrField: ParamErrorURI,
			wantErrByte:  "0x7F",
		},
		{
			// Control byte inside an Extra value — the
			// per-key error path. Field naming is the
			// literal Extra key, NOT a wrapping/prefix.
			name: "control byte in Extra value errors",
			in: Challenge{
				Extra: map[string]string{"vendor": "x\x01y"},
			},
			wantErrField: "vendor",
			wantErrByte:  "0x01",
		},
		{
			// Control byte inside one ACRValues element —
			// the Field is the wire-name "acr_values" (the
			// whole list is one wire parameter); the Reason
			// names the element index so the caller can
			// pinpoint which token was bad.
			name: "control byte in ACRValues element errors",
			in: Challenge{
				ACRValues: []string{"good", "bad\x02value"},
			},
			wantErrField: ParamACRValues,
			wantErrByte:  "0x02",
		},
		{
			// First-failure-wins pins the iteration to spec
			// emit order. Realm comes before Scope in the
			// canonical sequence, so a Realm CR + a Scope LF
			// must report the Realm failure even though both
			// are bad.
			name: "first failure wins in spec order",
			in: Challenge{
				Realm: "a\rb",
				Scope: "x\ny",
			},
			wantErrField: ParamRealm,
			wantErrByte:  "0x0D",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.in.MarshalString()
			if tc.wantErrField != "" {
				// Error path.
				if err == nil {
					t.Fatalf("MarshalString() = %q, nil; want *FormatError(%s)",
						got, tc.wantErrField)
				}
				var fe *FormatError
				if !errors.As(err, &fe) {
					t.Fatalf("MarshalString() err type = %T; want *FormatError", err)
				}
				if fe.Field != tc.wantErrField {
					t.Errorf("FormatError.Field = %q; want %q", fe.Field, tc.wantErrField)
				}
				if !strings.Contains(fe.Reason, tc.wantErrByte) {
					t.Errorf("FormatError.Reason = %q; want it to mention %q",
						fe.Reason, tc.wantErrByte)
				}
				if got != "" {
					t.Errorf("MarshalString() returned non-empty string %q alongside error",
						got)
				}
				return
			}
			// Happy path.
			if err != nil {
				t.Fatalf("MarshalString() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("MarshalString() mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestChallengeMarshalStringAgreesWithString runs every TestChallengeString
// fixture through MarshalString and asserts the two methods produce the
// same bytes on inputs that String can encode losslessly — i.e. on every
// row except the explicit lossy-fallback rows. Pins the contract that
// MarshalString is a strict superset of String's success path, not a
// separate formatter that might drift in its canonical form.
//
// The list of lossy fixtures here MUST be kept in sync with the
// fallback-asserting cases in TestChallengeString; the comment on each
// excluded name points at the byte class that triggers the divergence.
func TestChallengeMarshalStringAgreesWithString(t *testing.T) {
	t.Parallel()
	// Fixture names from TestChallengeString that intentionally
	// exercise the lossy fallback — these are the cases where
	// String and MarshalString diverge by design.
	lossy := map[string]bool{
		"control byte falls back to SP": true, // 0x01 in Realm
		"CR and LF fall back to SP":     true, // 0x0D, 0x0A in Realm
		"DEL byte falls back to SP":     true, // 0x7F in Realm
	}
	// Re-list TestChallengeString's table inline so this test is
	// self-contained and a future refactor of one table can't
	// silently desync from the other. The cases are small.
	cases := []struct {
		name string
		in   Challenge
	}{
		{"empty challenge emits scheme only", Challenge{}},
		{"realm only", Challenge{Realm: "example"}},
		{
			"all known fields in spec order",
			Challenge{
				Realm:            "example",
				Scope:            "openid profile",
				ErrorCode:        ErrorInsufficientUserAuthentication,
				ErrorDescription: "Strong authentication required",
				ErrorURI:         "https://example.com/err",
				ACRValues:        []string{"urn:mace:incommon:iap:silver"},
				MaxAge:           uintPtr(300),
			},
		},
		{"max_age zero emits max_age=0", Challenge{MaxAge: uintPtr(0)}},
		{"empty ACRValues slice emits nothing", Challenge{ACRValues: []string{}}},
		{"multi ACR values join with single SP", Challenge{ACRValues: []string{"urn:a", "urn:b", "urn:c"}}},
		{"quote and backslash in value are escaped", Challenge{Realm: `foo "bar" baz \quux`}},
		{
			"extra entries emit in lex order",
			Challenge{Extra: map[string]string{"zebra": "z", "alpha": "a", "mango": "m"}},
		},
		{
			"extra follows spec-ordered known params",
			Challenge{Realm: "r", Extra: map[string]string{"zeta": "z", "alpha": "a"}},
		},
		{"tab and space pass through", Challenge{Realm: "a\tb c"}},
		{"obs-text passes through", Challenge{Realm: "a\xc3\xa9b"}},
	}
	for _, tc := range cases {
		if lossy[tc.name] {
			t.Errorf("test bug: %q is in the agreement table but is a lossy case", tc.name)
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.in.String()
			m, err := tc.in.MarshalString()
			if err != nil {
				t.Fatalf("MarshalString() unexpected error: %v", err)
			}
			if s != m {
				t.Fatalf("String / MarshalString disagree\n  String:        %q\n  MarshalString: %q", s, m)
			}
		})
	}
}

// TestChallengeStringRoundTripExtra exercises the Extra-preserving path of
// the round-trip: an unknown auth-param parsed into Extra must survive
// String → Parse with the same key and value. Locks in the
// forward-compatibility guarantee at the formatter level so a future
// regression that, say, drops Extra entries from the emit loop fails here
// loudly rather than waiting for STEPUP-17's dedicated test.
func TestChallengeStringRoundTripExtra(t *testing.T) {
	t.Parallel()
	first := &Challenge{
		Realm:     "r",
		ErrorCode: ErrorInsufficientUserAuthentication,
		Extra: map[string]string{
			"vendor_token": "abc",
			"trace_id":     "xyz",
		},
	}
	formatted := first.String()
	second, err := Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(formatted) failed: %v\nformatted: %q", err, formatted)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Extra round-trip lost data\n first:  %+v\n second: %+v\n formatted: %q",
			first, second, formatted)
	}
}
