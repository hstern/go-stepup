// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package specfixtures

import (
	"strings"
	"testing"
)

// TestAllEmbedsKnownFixtures asserts that the .txt files this package is
// known to ship are actually picked up by the //go:embed directive. The
// directive is silent on missing files (an empty match set just yields an
// empty FS), so without this smoke test a future rename of a fixture
// would silently empty the corpus and the conformance suite at the repo
// root would pass trivially with zero subtests.
//
// The list below is the floor — every name listed must appear in All().
// Adding a new fixture file does not require updating this test; the
// floor only grows when the existing fixtures are intentionally
// retired (which would also need a CHANGELOG entry and a discussion).
func TestAllEmbedsKnownFixtures(t *testing.T) {
	t.Parallel()

	required := []string{
		"rfc9470_section3_fig2",
		"rfc9470_section3_fig3",
	}

	got := All()
	if len(got) == 0 {
		t.Fatal("All() returned no fixtures; the //go:embed directive matched nothing")
	}

	names := make(map[string]bool, len(got))
	for _, f := range got {
		names[f.Name] = true
	}

	for _, want := range required {
		if !names[want] {
			t.Errorf("required fixture %q missing from All(); have %d fixtures: %v", want, len(got), fixtureNames(got))
		}
	}
}

// TestAllValuesAreNonEmptyBearerChallenges asserts each fixture's Value
// is a non-empty string that begins with the Bearer auth-scheme token
// (case-insensitive). A fixture that fails this check is structurally
// wrong — a header value missing the scheme cannot be a WWW-Authenticate
// challenge — and would cause the root-package conformance test to fail
// with a less informative "Parse returned nil" message.
func TestAllValuesAreNonEmptyBearerChallenges(t *testing.T) {
	t.Parallel()

	for _, f := range All() {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			if f.Value == "" {
				t.Fatalf("fixture %q has empty Value; check the .txt file is not blank", f.Name)
			}
			if !strings.HasPrefix(strings.ToLower(f.Value), "bearer") {
				t.Errorf("fixture %q does not begin with a Bearer scheme token: %q", f.Name, f.Value)
			}
		})
	}
}

// TestAllIsDeterministic asserts that two consecutive All() calls return
// the same Name sequence — the contract that lets test runners pin a
// failing subtest path across runs.
func TestAllIsDeterministic(t *testing.T) {
	t.Parallel()

	first := All()
	second := All()
	if len(first) != len(second) {
		t.Fatalf("All() returned %d fixtures then %d on a second call; length must be stable", len(first), len(second))
	}
	for i := range first {
		if first[i].Name != second[i].Name {
			t.Fatalf("All() ordering not stable at index %d: %q vs %q", i, first[i].Name, second[i].Name)
		}
	}
}

func fixtureNames(fs []Fixture) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Name
	}
	return out
}
