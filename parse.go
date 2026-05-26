// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"strings"
)

// authParam is one parsed name=value pair from an RFC 7235 §2.1
// auth-param list. The name is lowercased per RFC 7235 §2.2's
// case-insensitivity rule, so callers can compare against the Param*
// wire constants by direct string equality. The value is fully decoded:
// surrounding DQUOTEs stripped and quoted-pairs collapsed.
//
// The isQuoted bit records whether the source used quoted-string
// form (true) or bare token form (false). RFC 9470 §3 shows
// max_age=5 and max_age="5" as both valid; preserving the
// distinction lets a future non-canonical formatter round-trip
// byte-for-byte if needed. The canonical formatter introduced in a
// later commit normalizes to one chosen form per parameter and
// ignores this bit.
type authParam struct {
	name     string
	value    string
	isQuoted bool
}

// parseAuthParams parses a single auth-scheme's auth-param list out of
// s starting at offset 0. It returns the params in source order
// (lowercased names, decoded values), the byte count it consumed up to
// the start of the next challenge (or len(s) on full consumption), and
// a non-nil *ParseError positioned at the offending byte on grammar
// failure.
//
// The function stops at:
//   - end of string;
//   - the boundary between this challenge and the next, recognized
//     when a bare token at a list position is followed (after BWS)
//     by something other than "=". The returned consumed offset
//     points at the start of that next auth-scheme's token so the
//     caller can resume.
//
// RFC 7230 §7's list-rule permits empty list elements; ", ," between
// params is silently skipped. RFC 7235 §2.2's BWS around "=" and OWS
// around list "," are accepted. Auth-param names use the RFC 7230
// §3.2.6 tchar set; bytes outside it in name position produce a
// ParseError.
//
// ASCII-only by construction: RFC 7235's grammar admits no UTF-8 in
// tokens, and quoted-string content is the RFC 7230 qdtext / quoted-
// pair set (also ASCII / obs-text bytes). All position arithmetic
// runs on bytes, not runes.
func parseAuthParams(s string) (params []authParam, consumed int, err *ParseError) {
	i := 0
	for i < len(s) {
		// Skip OWS and stray commas at list position. RFC 7230 §7
		// list-rule: "( *( "," OWS ) element *( OWS "," [ OWS
		// element ] ) )"; consecutive commas (with or without OWS
		// between them) collapse to one separator with no element
		// in between.
		i = skipOWS(s, i)
		if i >= len(s) {
			break
		}
		if s[i] == ',' {
			i++
			continue
		}

		// Read the name token. RFC 7235 §2.2:
		// auth-param = token BWS "=" BWS ( token / quoted-string ).
		nameStart := i
		j := scanToken(s, i)
		if j == i {
			return nil, i, &ParseError{Position: i, Reason: "expected auth-param name token"}
		}
		name := s[nameStart:j]
		afterName := j

		// BWS between the name and "=".
		k := skipOWS(s, afterName)

		if k >= len(s) || s[k] != '=' {
			// No "=" follows. This is the auth-scheme boundary:
			// per RFC 7235 §2.1 a challenge starts with
			// "auth-scheme [ 1*SP ... ]", so a bare token at a
			// list position with no "=" after BWS belongs to the
			// next challenge. The token we just consumed is that
			// next scheme name — surrender it by reporting
			// consumed = nameStart so the caller can resume.
			//
			// Two sub-cases collapse here:
			//   1. nameStart is at the start of input (e.g. an
			//      input like "Basic" alone) — no preceding
			//      auth-param, the whole input is just a bare
			//      scheme with no params. We return an empty
			//      param list and consumed = 0.
			//   2. nameStart is mid-string after a comma — the
			//      prior params belonged to the previous scheme,
			//      and this is the start of the next.
			return params, nameStart, nil
		}

		// Consume the "=" and the BWS that follows.
		k++
		k = skipOWS(s, k)
		if k >= len(s) {
			return nil, k, &ParseError{Position: k, Reason: "expected auth-param value after '='"}
		}

		// Value is either a quoted-string or a token.
		var (
			value    string
			isQuoted bool
		)
		if s[k] == '"' {
			v, end, perr := scanQuotedString(s, k)
			if perr != nil {
				return nil, perr.Position, perr
			}
			value = v
			isQuoted = true
			k = end
		} else {
			vStart := k
			vEnd := scanToken(s, k)
			if vEnd == vStart {
				return nil, k, &ParseError{Position: k, Reason: "expected token or quoted-string for auth-param value"}
			}
			value = s[vStart:vEnd]
			k = vEnd
		}

		params = append(params, authParam{
			name:     strings.ToLower(name),
			value:    value,
			isQuoted: isQuoted,
		})
		i = k

		// After a value, expect OWS then either "," or end of
		// string. Anything else is a grammar violation — including
		// another bare token, which would be ambiguous between a
		// malformed param and a missing comma. We require the
		// comma so input like `realm="x" scope="y"` (no separator)
		// errors cleanly rather than silently coalescing.
		i = skipOWS(s, i)
		if i >= len(s) {
			break
		}
		if s[i] != ',' {
			return nil, i, &ParseError{Position: i, Reason: "expected ',' or end of input after auth-param value"}
		}
		// Consume the comma and continue; the loop head will skip
		// any OWS and additional commas before the next element.
		i++
	}

	return params, i, nil
}

// skipOWS advances past any RFC 7230 §3.2.3 OWS (SP / HTAB) bytes
// starting at i and returns the new index. BWS shares the OWS
// production; this function serves both.
func skipOWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// scanToken returns the index of the first byte at or after i that is
// not a tchar per RFC 7230 §3.2.6. If s[i] itself is not a tchar the
// function returns i (zero-length match), which callers treat as
// "expected token here".
func scanToken(s string, i int) int {
	for i < len(s) && isTchar(s[i]) {
		i++
	}
	return i
}

// isTchar reports whether c is a tchar per RFC 7230 §3.2.6:
//
//	tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" /
//	        "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//
// The membership check is hand-rolled rather than using a map or
// regexp to keep the tokenizer allocation-free on the hot path.
func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// scanQuotedString decodes one RFC 7230 §3.2.6 quoted-string starting
// at s[i] (which must be the opening DQUOTE). It returns the decoded
// content (without the surrounding DQUOTEs, with quoted-pairs
// collapsed), the index immediately past the closing DQUOTE, and a
// *ParseError on grammar violation.
//
// Grammar:
//
//	quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//	qdtext        = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//	quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
//
// obs-text covers %x80-FF; the function accepts those bytes for
// lenient-unmarshal posture but does not interpret them as UTF-8.
// Quoted-pair decodes to the literal escaped byte: "\\" -> "\",
// "\"" -> `"`, "\n" -> "n" (any VCHAR, NOT a newline).
func scanQuotedString(s string, i int) (value string, end int, err *ParseError) {
	if i >= len(s) || s[i] != '"' {
		return "", i, &ParseError{Position: i, Reason: "expected '\"' to begin quoted-string"}
	}
	start := i
	i++ // past opening DQUOTE

	// Fast path: if no quoted-pair is present, the decoded value is
	// the byte range between the quotes verbatim. Scan for either a
	// closing DQUOTE or a backslash to decide.
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '"':
			return s[i:j], j + 1, nil
		case '\\':
			// Fall through to the decoding path. Allocate a
			// builder sized for the worst case (the remaining
			// quoted-string content) so the per-byte append is
			// amortized.
			var b strings.Builder
			b.Grow(len(s) - i)
			b.WriteString(s[i:j])
			return decodeQuotedTail(s, start, j, &b)
		default:
			if !isQdtext(s[j]) {
				return "", j, &ParseError{Position: j, Reason: "invalid byte in quoted-string"}
			}
		}
	}
	return "", start, &ParseError{Position: start, Reason: "unterminated quoted-string"}
}

// decodeQuotedTail completes a scanQuotedString in the slow path,
// starting at the first backslash inside the quoted-string. start is
// the index of the opening DQUOTE (for error positions on
// unterminated input); j is the index of the backslash; b already
// holds the verbatim bytes from immediately after the opening DQUOTE
// up to but not including s[j].
func decodeQuotedTail(s string, start, j int, b *strings.Builder) (value string, end int, err *ParseError) {
	for j < len(s) {
		c := s[j]
		switch c {
		case '"':
			return b.String(), j + 1, nil
		case '\\':
			// quoted-pair: backslash + ( HTAB / SP / VCHAR /
			// obs-text ). VCHAR is %x21-7E.
			if j+1 >= len(s) {
				return "", j, &ParseError{Position: j, Reason: "dangling '\\' in quoted-string"}
			}
			esc := s[j+1]
			if !isQuotedPairChar(esc) {
				return "", j + 1, &ParseError{Position: j + 1, Reason: "invalid quoted-pair escape"}
			}
			b.WriteByte(esc)
			j += 2
		default:
			if !isQdtext(c) {
				return "", j, &ParseError{Position: j, Reason: "invalid byte in quoted-string"}
			}
			b.WriteByte(c)
			j++
		}
	}
	return "", start, &ParseError{Position: start, Reason: "unterminated quoted-string"}
}

// isQdtext reports whether c is a qdtext byte per RFC 7230 §3.2.6:
//
//	qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//
// obs-text = %x80-FF. The byte %x22 (DQUOTE) and %x5C (backslash) are
// not qdtext — they're the framing delimiter and the quoted-pair
// escape, respectively. CR and LF are NOT permitted: they would break
// header framing and only appear in obs-fold (itself deprecated by
// RFC 7230 §3.2.4). Rejecting them here lets header consumers trust
// that a decoded value never contains an embedded line break.
func isQdtext(c byte) bool {
	switch {
	case c == '\t', c == ' ':
		return true
	case c == 0x21:
		return true
	case c >= 0x23 && c <= 0x5B:
		return true
	case c >= 0x5D && c <= 0x7E:
		return true
	case c >= 0x80: // obs-text
		return true
	}
	return false
}

// isQuotedPairChar reports whether c is a legal byte after the
// backslash in an RFC 7230 §3.2.6 quoted-pair:
//
//	quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
//
// VCHAR is %x21-7E. CR and LF are not VCHAR and are excluded; same
// header-framing rationale as isQdtext.
func isQuotedPairChar(c byte) bool {
	switch {
	case c == '\t', c == ' ':
		return true
	case c >= 0x21 && c <= 0x7E: // VCHAR
		return true
	case c >= 0x80: // obs-text
		return true
	}
	return false
}
