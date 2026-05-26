// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup_test

import (
	"reflect"
	"testing"

	"github.com/hstern/go-stepup"
	"github.com/hstern/go-stepup/internal/specfixtures"
)

// TestConformance is the RFC 9470 §3 round-trip guarantee, applied to
// every example header value the section defines. For each fixture, the
// test:
//
//  1. parses the value into a *Challenge (failing on any parse error),
//  2. formats the parsed challenge with String to obtain the
//     library's canonical-form serialization,
//  3. parses that canonical-form string again,
//  4. asserts the two *Challenge values are reflect.DeepEqual.
//
// The asserted property is typed-field equivalence, not byte equivalence.
// The canonical output may differ from the input in parameter order, in
// auth-param-name casing (the formatter pins lowercase), and in
// quoting style (the formatter emits max_age in token form even though
// the RFC examples quote it). Re-parsing collapses those representational
// differences back to the same field values — that is the round-trip
// contract every external caller relies on, and the contract this test
// enforces against the authoritative spec corpus.
//
// The test lives in package stepup_test (external) deliberately, so it
// exercises only the public API surface — Parse and (*Challenge).String
// — exactly as a third-party consumer would. Same-package access would
// let the test cheat by inspecting unexported state and would not catch
// API-shape regressions.
func TestConformance(t *testing.T) {
	t.Parallel()

	fixtures := specfixtures.All()
	if len(fixtures) == 0 {
		t.Fatal("specfixtures.All() returned no fixtures; the embedded corpus is empty")
	}

	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			t.Parallel()

			first, err := stepup.Parse(fx.Value)
			if err != nil {
				t.Fatalf("Parse(%q) initial: %v", fx.Value, err)
			}
			if first == nil {
				t.Fatalf("Parse(%q) returned (nil, nil); every RFC §3 example is a Bearer step-up challenge and must yield a non-nil *Challenge", fx.Value)
			}

			canonical := first.String()

			second, err := stepup.Parse(canonical)
			if err != nil {
				t.Fatalf("Parse(canonical %q) after first round-trip: %v", canonical, err)
			}
			if second == nil {
				t.Fatalf("Parse(canonical %q) returned (nil, nil); canonical-form output of a step-up challenge must round-trip to a non-nil *Challenge", canonical)
			}

			if !reflect.DeepEqual(first, second) {
				t.Errorf("round-trip typed-field drift\n  input     = %q\n  canonical = %q\n  first     = %+v\n  second    = %+v",
					fx.Value, canonical, first, second)
			}
		})
	}
}

// TestConformanceMarshalString exercises the fail-fast formatter against
// the same corpus. MarshalString and String agree byte-for-byte whenever
// every field value is representable in the RFC 7230 quoted-string +
// quoted-pair grammar — which is the case for every published RFC 9470
// example, since the spec never embeds control characters in its sample
// values. An error from MarshalString on any of these inputs would
// signal one of two regressions: either the formatter has started
// rejecting valid bytes, or a fixture has acquired an invalid byte
// (e.g. through accidental editor-introduced CR/LF). Both are bugs the
// test surfaces immediately.
func TestConformanceMarshalString(t *testing.T) {
	t.Parallel()

	for _, fx := range specfixtures.All() {
		t.Run(fx.Name, func(t *testing.T) {
			t.Parallel()

			parsed, err := stepup.Parse(fx.Value)
			if err != nil {
				t.Fatalf("Parse(%q): %v", fx.Value, err)
			}
			if parsed == nil {
				t.Fatalf("Parse(%q) returned (nil, nil)", fx.Value)
			}

			strict, err := parsed.MarshalString()
			if err != nil {
				t.Fatalf("MarshalString on RFC §3 example must not error, got %v (input %q)", err, fx.Value)
			}
			if got, want := strict, parsed.String(); got != want {
				t.Errorf("MarshalString and String disagree on safe input\n  MarshalString = %q\n  String        = %q", got, want)
			}
		})
	}
}
