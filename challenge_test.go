// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"errors"
	"testing"
)

// Smoke check that the three structured error types satisfy the error
// interface via pointer receivers. The interface assertion happens at
// compile time; the test exists to make the contract observable in
// `go test -v` output and to fail loudly if a later edit accidentally
// moves the receiver off the pointer.
func TestErrorTypesImplementError(t *testing.T) {
	var (
		_ error = (*ParseError)(nil)
		_ error = (*ValidationError)(nil)
		_ error = (*FormatError)(nil)
	)
}

// Smoke check that the sentinel matches itself under errors.Is. Guards
// against a future refactor accidentally redeclaring the variable inside a
// function (which would mint a fresh error value per call and silently break
// every consumer dispatching on it).
func TestSentinelMatchesItself(t *testing.T) {
	wrapped := errors.Join(ErrInsufficientUserAuthentication, errors.New("context"))
	if !errors.Is(wrapped, ErrInsufficientUserAuthentication) {
		t.Fatalf("errors.Is(wrapped, ErrInsufficientUserAuthentication) = false, want true")
	}
	if ErrInsufficientUserAuthentication.Error() != "insufficient_user_authentication" {
		t.Fatalf("sentinel string drifted: %q", ErrInsufficientUserAuthentication.Error())
	}
}
