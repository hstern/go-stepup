// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"fmt"
	"slices"
)

// Stable identifiers for the validation rules Validate enforces. Exported so
// that callers using errors.As to unwrap a *ValidationError can branch on
// the rule that fired without hardcoding the string literal:
//
//	var ve *stepup.ValidationError
//	if errors.As(err, &ve) && ve.Rule == stepup.RuleMaxAgeInBounds {
//	    // ...
//	}
//
// These identifiers are part of the library's public API surface; once
// shipped they will not be renamed within the v0.x line.
const (
	// RuleErrorCodeRecognized fires when Challenge.ErrorCode is non-empty
	// but does not match one of the recognized RFC 6750 / RFC 9470 error
	// codes (the Error* constants in this package).
	RuleErrorCodeRecognized = "error_code_recognized"

	// RuleACRValuesNonEmpty fires when Challenge.ACRValues contains an
	// element that is the empty string. The wire format is a
	// space-separated quoted-string, so empty tokens cannot occur in a
	// parser-produced Challenge — this rule guards against callers
	// constructing Challenge values directly and inserting empty elements
	// by accident.
	RuleACRValuesNonEmpty = "acr_values_non_empty"

	// RuleMaxAgeInBounds fires when Challenge.MaxAge is non-nil and the
	// dereferenced value exceeds MaxAgeUpperBound. Zero is always legal —
	// the spec uses it to require fresh authentication on every request.
	RuleMaxAgeInBounds = "max_age_in_bounds"
)

// MaxAgeUpperBound is the inclusive maximum *Challenge.MaxAge value Validate
// accepts. Defaults to one year of seconds (60 * 60 * 24 * 365). RFC 9470 is
// silent on a maximum; this library treats one year as the threshold above
// which max_age stops being a meaningful authentication-recency signal and
// is more likely to be a data-entry mistake.
//
// Override before calling Validate if your deployment's max_age semantics
// demand a different ceiling. This is a package-level variable rather than
// a per-call option to keep the optional check zero-ceremony at the call
// site; it is therefore not safe to mutate concurrently with Validate. The
// recommended pattern is to set it once during program initialization (an
// init function, or early in main) and leave it alone thereafter.
var MaxAgeUpperBound uint64 = 60 * 60 * 24 * 365

// recognizedErrorCodes is the set of error codes Validate considers
// acceptable for the "error" auth-param: the three RFC 6750 §3.1 codes
// plus the RFC 9470 §3 addition. Kept as a map for O(1) membership
// regardless of how many codes future spec revisions add.
var recognizedErrorCodes = map[string]struct{}{
	ErrorInvalidRequest:                 {},
	ErrorInvalidToken:                   {},
	ErrorInsufficientScope:              {},
	ErrorInsufficientUserAuthentication: {},
}

// Validate reports whether c carries values consistent with the recognized
// RFC 9470 / RFC 6750 vocabulary and grammar constraints beyond what Parse
// already enforces. It is opt-in — Parse and ParseHeader return Challenges
// that round-trip but may carry out-of-vocabulary error codes, empty
// acr_values tokens, or out-of-bounds max_age values; Validate is the
// caller's signal that they want to reject these rather than tolerate them.
//
// Rules enforced:
//
//   - ErrorCode, if non-empty, must be one of the recognized values:
//     [ErrorInvalidRequest], [ErrorInvalidToken], [ErrorInsufficientScope],
//     [ErrorInsufficientUserAuthentication]. An empty ErrorCode is legal
//     (a challenge may omit the error parameter entirely).
//   - Every element of ACRValues, if any, must be a non-empty string. The
//     wire form is a space-separated quoted-string; the parser uses
//     strings.Fields so empty tokens are already discarded — this check
//     guards against callers constructing Challenge values directly and
//     inserting empty elements by accident.
//   - MaxAge, if non-nil, must satisfy 0 ≤ *MaxAge ≤ [MaxAgeUpperBound].
//     Zero is legal (the spec uses it to require fresh authentication on
//     every request); the upper bound is a sanity ceiling overridable by
//     reassigning the package variable.
//
// Validate returns the first *[ValidationError] it finds, walking fields in
// declaration order (Realm → Scope → ErrorCode → ErrorDescription →
// ErrorURI → ACRValues → MaxAge → Extra). It is not a multi-error reporter;
// the typical consumer pattern is "validate, fail fast, surface to user."
// Callers wanting every problem in one pass should walk the rules
// themselves.
//
// Validate does NOT check Realm, Scope, ErrorDescription, or ErrorURI
// content beyond what RFC 7235 grammar requires (which Parse already
// enforced). URIs in ErrorURI are not parsed; the spec leaves their shape
// to RFC 6750 §3.1 with no further structural constraint. Callers wanting
// URL parsing should net/url.Parse it themselves.
//
// Validate does NOT check Extra. Forward-compatibility for future
// auth-param additions and vendor extensions is the explicit reason Extra
// exists; rejecting unknown keys would defeat that.
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3
// and RFC 6750 §3.1 — https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1.
func (c *Challenge) Validate() error {
	if c.ErrorCode != "" {
		if _, ok := recognizedErrorCodes[c.ErrorCode]; !ok {
			return &ValidationError{
				Rule:   RuleErrorCodeRecognized,
				Field:  ParamError,
				Reason: fmt.Sprintf("unrecognized error code: %q", c.ErrorCode),
			}
		}
	}

	if i := slices.Index(c.ACRValues, ""); i >= 0 {
		return &ValidationError{
			Rule:   RuleACRValuesNonEmpty,
			Field:  ParamACRValues,
			Reason: fmt.Sprintf("element at index %d is empty", i),
		}
	}

	if c.MaxAge != nil && *c.MaxAge > MaxAgeUpperBound {
		return &ValidationError{
			Rule:   RuleMaxAgeInBounds,
			Field:  ParamMaxAge,
			Reason: fmt.Sprintf("max_age %d exceeds upper bound %d", *c.MaxAge, MaxAgeUpperBound),
		}
	}

	return nil
}
