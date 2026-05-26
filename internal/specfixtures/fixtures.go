// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

// Package specfixtures embeds the WWW-Authenticate header values shown as
// examples in RFC 9470 §3 ("Authentication Requirements Challenge") so the
// library's parser and formatter can be round-trip-tested against the
// authoritative wire forms. The corpus is intentionally library-private —
// it exists to exercise the public API as a black-box consumer would, not
// to ship as a public API itself; that is why it lives under internal/.
//
// # Adding a fixture
//
// Drop a new .txt file in this directory containing one WWW-Authenticate
// header value verbatim — no leading "WWW-Authenticate:" prefix, no
// trailing newline (a stray one is tolerated and stripped). The //go:embed
// directive below picks it up on the next build; no Go code change is
// required. Name the file after its source (e.g. rfc9470_section3_fig2.txt,
// errata_<id>.txt). The basename without extension becomes the subtest
// name when the root-package conformance test iterates the corpus.
//
// # What "fixture" means here
//
// A fixture is one full auth-scheme entry as it would appear on the wire,
// suitable for direct argument to [github.com/hstern/go-stepup.Parse]. The
// RFC §3 figures show each example as the value following
// "WWW-Authenticate:" on a 401 response; the corpus stores only that
// value, since the parser consumes header values, not whole header lines.
//
// # Scope discipline
//
// Only spec-literal examples and published errata land here. Synthesized
// forward-compatibility cases (unknown auth-params, vendor extensions)
// belong with the forward-compat test file, not in this corpus — mixing
// the two would blur the "what does the RFC actually say?" line this
// package draws.
package specfixtures

import (
	"embed"
	"io/fs"
	"slices"
	"strings"
)

// raw holds every .txt file in this directory at build time. The
// //go:embed directive resolves at compile time, so a fixture added under
// this package is picked up on the next `go build` with no registration
// step. embed.FS is the supported stdlib mechanism; no third-party
// dependency is involved.
//
//go:embed *.txt
var raw embed.FS

// Fixture is one named WWW-Authenticate header value from the corpus.
//
// The library's round-trip property is that Parse(Value).String() parsed
// again equals the first Parse — typed-field equivalence, not byte
// equivalence (canonical-form output may reorder, lowercase, or re-quote
// the input). Consumers of this package iterate [All] and assert that
// property over Value.
type Fixture struct {
	// Name identifies the fixture in test output. It is the .txt
	// basename with the extension trimmed — "rfc9470_section3_fig2"
	// for "rfc9470_section3_fig2.txt". The naming convention makes
	// the source obvious in test failure messages and is a stable
	// handle a regression test can pin against.
	Name string

	// Value is the WWW-Authenticate header value, exactly as it
	// would appear on the wire. A single trailing newline (which
	// many text editors append) is stripped on load so the value
	// matches what an HTTP client would actually see in the
	// h.Get("WWW-Authenticate") return.
	Value string
}

// All returns every embedded fixture, sorted lexicographically by Name
// for deterministic iteration. The returned slice is freshly allocated on
// each call — callers may sort, filter, or otherwise mutate it without
// affecting the embedded corpus or each other.
//
// Iteration order is deterministic so test failures pin to a stable
// subtest path: a future regression in fixture N reports the same path
// across machines and runs, which matters when bisecting a flake or
// reproducing a CI failure locally.
func All() []Fixture {
	entries, err := fs.ReadDir(raw, ".")
	if err != nil {
		// embed.FS.ReadDir on the root of a //go:embed-backed FS
		// cannot fail at runtime: the directory listing is baked in
		// at compile time. A non-nil error here would indicate a
		// stdlib bug, not a runtime condition the caller can
		// recover from, so a panic is the honest signal.
		panic("specfixtures: embedded FS read failed: " + err.Error())
	}

	out := make([]Fixture, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".txt") {
			// Defensive: //go:embed *.txt is the gate, so this
			// branch should not fire. Skip rather than panic in
			// case a future change widens the embed pattern.
			continue
		}
		data, err := raw.ReadFile(name)
		if err != nil {
			panic("specfixtures: reading embedded " + name + ": " + err.Error())
		}
		// Strip a single trailing newline if the editor inserted
		// one; HTTP header values never carry one on the wire.
		// strings.TrimRight handles both LF and CRLF — and the
		// rare editor that appends multiple trailing newlines —
		// without affecting in-value whitespace.
		value := strings.TrimRight(string(data), "\r\n")

		out = append(out, Fixture{
			Name:  strings.TrimSuffix(name, ".txt"),
			Value: value,
		})
	}

	slices.SortFunc(out, func(a, b Fixture) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}
