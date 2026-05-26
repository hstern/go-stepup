// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hstern/go-stepup"
)

func u64ptr(v uint64) *uint64 { return &v }

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		challenge stepup.Challenge
		wantRule  string // "" means expect nil error
		wantField string
		// substrings the Reason must contain (each must appear); empty list
		// means do not assert on Reason content.
		wantReasonContains []string
	}{
		{
			name:      "empty challenge is valid",
			challenge: stepup.Challenge{},
		},
		{
			name:      "recognized error: invalid_request",
			challenge: stepup.Challenge{ErrorCode: stepup.ErrorInvalidRequest},
		},
		{
			name:      "recognized error: invalid_token",
			challenge: stepup.Challenge{ErrorCode: stepup.ErrorInvalidToken},
		},
		{
			name:      "recognized error: insufficient_scope",
			challenge: stepup.Challenge{ErrorCode: stepup.ErrorInsufficientScope},
		},
		{
			name:      "recognized error: insufficient_user_authentication",
			challenge: stepup.Challenge{ErrorCode: stepup.ErrorInsufficientUserAuthentication},
		},
		{
			name:               "unrecognized error code is rejected",
			challenge:          stepup.Challenge{ErrorCode: "invalid_user_authentication"},
			wantRule:           stepup.RuleErrorCodeRecognized,
			wantField:          stepup.ParamError,
			wantReasonContains: []string{"invalid_user_authentication"},
		},
		{
			name:      "empty error code is legal (parameter omitted)",
			challenge: stepup.Challenge{ErrorCode: ""},
		},
		{
			name:      "nil acr_values",
			challenge: stepup.Challenge{ACRValues: nil},
		},
		{
			name:      "single non-empty acr token",
			challenge: stepup.Challenge{ACRValues: []string{"urn:foo"}},
		},
		{
			name:               "empty acr token at index 1 is rejected",
			challenge:          stepup.Challenge{ACRValues: []string{"urn:foo", "", "urn:bar"}},
			wantRule:           stepup.RuleACRValuesNonEmpty,
			wantField:          stepup.ParamACRValues,
			wantReasonContains: []string{"index 1"},
		},
		{
			name:      "nil MaxAge",
			challenge: stepup.Challenge{MaxAge: nil},
		},
		{
			name:      "MaxAge zero is legal per spec",
			challenge: stepup.Challenge{MaxAge: u64ptr(0)},
		},
		{
			name:      "MaxAge 300 is within bounds",
			challenge: stepup.Challenge{MaxAge: u64ptr(300)},
		},
		{
			name:      "MaxAge at the inclusive upper bound",
			challenge: stepup.Challenge{MaxAge: u64ptr(stepup.MaxAgeUpperBound)},
		},
		{
			name:               "MaxAge above the upper bound is rejected",
			challenge:          stepup.Challenge{MaxAge: u64ptr(stepup.MaxAgeUpperBound + 1)},
			wantRule:           stepup.RuleMaxAgeInBounds,
			wantField:          stepup.ParamMaxAge,
			wantReasonContains: []string{"max_age", "exceeds"},
		},
		{
			name: "extra is not validated even with garbage values",
			challenge: stepup.Challenge{
				Extra: map[string]string{"junk_param": "totally bogus value with \x00 control bytes"},
			},
		},
		{
			name: "first failure wins: error code reported before acr or max_age",
			challenge: stepup.Challenge{
				ErrorCode: "nope_not_a_code",
				ACRValues: []string{""},
				MaxAge:    u64ptr(stepup.MaxAgeUpperBound + 1),
			},
			wantRule:  stepup.RuleErrorCodeRecognized,
			wantField: stepup.ParamError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.challenge.Validate()

			if tc.wantRule == "" {
				if err != nil {
					t.Fatalf("Validate: want nil, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Validate: want *ValidationError rule=%s, got nil", tc.wantRule)
			}

			var ve *stepup.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("Validate: want *ValidationError, got %T: %v", err, err)
			}
			if ve.Rule != tc.wantRule {
				t.Errorf("Rule: want %q, got %q", tc.wantRule, ve.Rule)
			}
			if ve.Field != tc.wantField {
				t.Errorf("Field: want %q, got %q", tc.wantField, ve.Field)
			}
			for _, sub := range tc.wantReasonContains {
				if !strings.Contains(ve.Reason, sub) {
					t.Errorf("Reason: want substring %q, got %q", sub, ve.Reason)
				}
			}
		})
	}
}

// TestValidateMaxAgeUpperBoundOverride exercises the package-level
// MaxAgeUpperBound knob. The test serializes against itself (the variable is
// not safe to mutate concurrently with Validate) by avoiding t.Parallel and
// restoring the default with t.Cleanup.
func TestValidateMaxAgeUpperBoundOverride(t *testing.T) {
	original := stepup.MaxAgeUpperBound
	t.Cleanup(func() { stepup.MaxAgeUpperBound = original })

	stepup.MaxAgeUpperBound = 600

	if err := (&stepup.Challenge{MaxAge: u64ptr(600)}).Validate(); err != nil {
		t.Errorf("MaxAge=600 at bound: want nil, got %v", err)
	}

	err := (&stepup.Challenge{MaxAge: u64ptr(1200)}).Validate()
	if err == nil {
		t.Fatalf("MaxAge=1200 over bound: want *ValidationError, got nil")
	}
	var ve *stepup.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if ve.Rule != stepup.RuleMaxAgeInBounds {
		t.Errorf("Rule: want %q, got %q", stepup.RuleMaxAgeInBounds, ve.Rule)
	}
	if !strings.Contains(ve.Reason, "600") {
		t.Errorf("Reason: want substring %q naming the overridden bound, got %q", "600", ve.Reason)
	}
}
