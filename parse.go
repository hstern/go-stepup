// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Parse parses a single WWW-Authenticate header value into a Challenge.
//
// The header value MAY contain multiple challenges separated by commas
// (RFC 7235 §4.1). Parse walks them in order and returns the first one
// whose auth-scheme is "Bearer" (case-insensitive per RFC 7235 §2.1).
// Non-Bearer challenges are skipped silently. If the value contains no
// Bearer challenge — for example, `Basic realm="x"` alone — Parse returns
// (nil, nil), not an error: absence of a Bearer challenge is a legitimate
// response shape from a server that does not speak RFC 9470, not a parse
// failure.
//
// Parse does NOT filter on the [ErrorInsufficientUserAuthentication]
// error code; the first Bearer challenge is returned regardless of its
// ErrorCode (or absence thereof). This is the right entry point for a
// client that already knows the response is a step-up challenge and
// wants the parsed view of it. For HTTP dispatch — "is this an RFC 9470
// step-up response at all, and if so what does it ask for?" — use
// [ParseHeader], which scans every WWW-Authenticate header line and
// filters to Bearer challenges that carry
// error="insufficient_user_authentication".
//
// Unknown auth-params are preserved verbatim in Challenge.Extra to retain
// forward compatibility with future RFC 9470 amendments and vendor
// extensions; their presence never produces an error. Within a single
// challenge, duplicate auth-params resolve last-write-wins for both typed
// fields and Extra entries — RFC 7235 is silent on duplicates and this
// library takes the lenient-unmarshal posture.
//
// Grammar violations — malformed quoted-string, illegal characters in a
// token, dangling escape, non-numeric or negative max_age — return a
// *ParseError whose Position points at the byte offset where parsing
// first went wrong.
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3.
func Parse(headerValue string) (*Challenge, error) {
	chs, err := scanBearerChallenges(headerValue)
	if err != nil {
		return nil, err
	}
	if len(chs) == 0 {
		return nil, nil
	}
	return chs[0], nil
}

// ParseHeader scans every WWW-Authenticate header in h and returns the
// Bearer challenges that carry error="insufficient_user_authentication"
// — i.e. RFC 9470 step-up challenges — in header-then-source order.
//
// The filter is the entire point of this entry: a response may
// legitimately advertise Basic and Bearer challenges in parallel (RFC
// 7235 §4.1), and a Bearer challenge may itself signal any RFC 6750
// error (invalid_request / invalid_token / insufficient_scope) or no
// error at all. ParseHeader is concerned only with RFC 9470 challenges,
// so non-Bearer schemes are silently skipped and Bearer challenges
// whose ErrorCode is anything other than
// [ErrorInsufficientUserAuthentication] are dropped from the result.
// Callers who want the broader "first Bearer challenge regardless of
// error code" view on a single header value should use [Parse].
//
// Header name matching follows http.Header.Values, which canonicalizes
// "www-authenticate", "WWW-Authenticate", etc. to the single MIME
// canonical form. Multiple header lines are walked in their stored
// order, and challenges within one header value are walked in source
// order; the two iterations compose to "header-then-source" ordering
// in the returned slice.
//
// When no WWW-Authenticate header is present, or none of the present
// challenges pass the filter, ParseHeader returns (nil, nil). An empty
// http.Header and an http.Header with no matching challenges are
// indistinguishable in the return: both signal "no RFC 9470 step-up
// challenge here," which is what the caller cares about.
//
// On the first grammar violation in any header value, ParseHeader
// returns (nil, err) without processing subsequent headers. The
// alternative — "collect errors and return what parsed" — would lose
// data the caller might need to see; a malformed header-set is a
// malformed header-set, and the consumer should know.
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3.
func ParseHeader(h http.Header) ([]*Challenge, error) {
	var out []*Challenge
	for _, v := range h.Values("WWW-Authenticate") {
		chs, err := scanBearerChallenges(v)
		if err != nil {
			return nil, err
		}
		for _, c := range chs {
			if c.ErrorCode == ErrorInsufficientUserAuthentication {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// scanBearerChallenges walks one WWW-Authenticate header value and
// returns every Bearer challenge in source order. Non-Bearer schemes
// (Basic, Digest, and any future scheme) are silently skipped. The
// returned challenges have not been filtered on ErrorCode — that is the
// caller's responsibility; ParseHeader applies the RFC 9470
// "insufficient_user_authentication" filter, while Parse does not.
//
// The function is the shared backbone of Parse (which takes the first
// returned challenge) and ParseHeader (which fans out across header
// lines and applies the error-code filter). Both surfaces share the
// scheme-skipping and grammar-error-propagation behavior; only the
// per-value selection differs.
//
// Grammar violations bubble up unchanged: the returned *ParseError
// carries an absolute byte offset within the value the caller passed
// in. The first error short-circuits the scan.
func scanBearerChallenges(headerValue string) ([]*Challenge, error) {
	var out []*Challenge
	i := 0
	for i < len(headerValue) {
		// Skip leading OWS and any stray empty list elements between
		// challenges. RFC 7230 §7 list-rule allows ",, " between
		// elements; treat the same way at the challenge level.
		i = skipOWS(headerValue, i)
		if i < len(headerValue) && headerValue[i] == ',' {
			i++
			continue
		}
		if i >= len(headerValue) {
			break
		}

		// Read the auth-scheme token (RFC 7235 §2.1
		// auth-scheme = token).
		schemeStart := i
		schemeEnd := scanToken(headerValue, i)
		if schemeEnd == schemeStart {
			return nil, &ParseError{
				Position: i,
				Reason:   "expected auth-scheme token",
			}
		}
		scheme := headerValue[schemeStart:schemeEnd]
		isBearer := strings.EqualFold(scheme, "Bearer")

		// RFC 7235 §2.1: between the scheme and its first auth-param
		// the grammar requires 1*SP; in practice this library is
		// liberal and accepts any OWS. The tokenizer expects to be
		// pointed at the first auth-param byte, so advance past the
		// whitespace before delegating.
		i = skipOWS(headerValue, schemeEnd)

		// parseAuthParams consumes this scheme's auth-params and
		// stops at the boundary of the next auth-scheme (a bare
		// token with no '=' after BWS). The returned offset is
		// relative to the slice we hand it.
		params, consumed, perr := parseAuthParams(headerValue[i:])
		if perr != nil {
			// Translate the local Position back to an absolute
			// byte offset in the original header value so the
			// caller's diagnostic points at the right column.
			return nil, &ParseError{
				Position: i + perr.Position,
				Reason:   perr.Reason,
			}
		}

		if isBearer {
			ch, ferr := challengeFromParams(params, i)
			if ferr != nil {
				return nil, ferr
			}
			out = append(out, ch)
		}

		// Advance past this challenge's params and continue scanning
		// for the next auth-scheme. parseAuthParams' returned consumed
		// is 0 when it surrendered a bare token (the next scheme) at
		// the very start of its input — in that case the outer loop
		// re-reads the same byte as a fresh scheme on the next
		// iteration, which is what we want.
		i += consumed
	}
	return out, nil
}

// challengeFromParams maps a slice of decoded auth-params onto the typed
// Challenge fields. Unknown param names land in Extra. The base offset is
// the absolute byte position in the original header value where the
// params block began; it is used to translate per-param value-position
// errors (currently only max_age numeric failures) back to absolute
// offsets the caller can locate.
//
// Within the params slice, the parser preserves source order; duplicate
// names resolve last-write-wins for both typed fields and Extra entries.
// This is the lenient-unmarshal posture — RFC 7235 is silent on
// duplicates within a single challenge, so the library accepts them and
// keeps the last value rather than erroring.
func challengeFromParams(params []authParam, base int) (*Challenge, *ParseError) {
	ch := &Challenge{}

	// valuePos walks alongside params so we can position max_age
	// errors at the value byte, not the start of the header. The
	// tokenizer does not expose per-param offsets — recomputing here
	// from name+value+separators would be brittle — so the position
	// falls back to the params-block base when we cannot pinpoint
	// further. The trade-off is acceptable: max_age parse failures
	// are the only post-tokenizer error path, and pointing at the
	// first byte of the params block still localizes the problem to
	// the right challenge.
	for _, p := range params {
		switch p.name {
		case ParamRealm:
			ch.Realm = p.value
		case ParamScope:
			ch.Scope = p.value
		case ParamError:
			ch.ErrorCode = p.value
		case ParamErrorDescription:
			ch.ErrorDescription = p.value
		case ParamErrorURI:
			ch.ErrorURI = p.value
		case ParamACRValues:
			// RFC 9470 §3 mirrors OIDC §3.1.2.1's acr_values:
			// one quoted-string of space-separated tokens.
			// strings.Fields collapses runs of SP/HTAB and
			// trims leading/trailing whitespace — matching the
			// OIDC tokenization. An explicitly empty value
			// (acr_values="") yields a non-nil zero-length
			// slice, distinguishing "param sent, empty" from
			// "param absent" (nil).
			ch.ACRValues = splitACRValues(p.value)
		case ParamMaxAge:
			n, err := strconv.ParseUint(p.value, 10, 64)
			if err != nil {
				// strconv.ParseUint wraps every failure in a
				// *strconv.NumError whose Error() string
				// duplicates the function-and-value prefix
				// the caller can already see in the source.
				// Extract just the inner cause so the Reason
				// reads cleanly when concatenated with the
				// ParseError formatter ("invalid max_age:
				// invalid syntax" rather than "invalid
				// max_age: strconv.ParseUint: parsing
				// \"abc\": invalid syntax"). The structured
				// Position still localizes the failure to
				// the right challenge.
				inner := err
				var numErr *strconv.NumError
				if errors.As(err, &numErr) {
					inner = numErr.Err
				}
				return nil, &ParseError{
					Position: base,
					Reason:   "invalid max_age: " + inner.Error(),
				}
			}
			ch.MaxAge = &n
		default:
			if ch.Extra == nil {
				ch.Extra = make(map[string]string)
			}
			ch.Extra[p.name] = p.value
		}
	}
	return ch, nil
}

// splitACRValues tokenizes an acr_values wire value into the typed
// []string surface. Uses strings.Fields so multiple inter-token spaces
// (and stray tabs) collapse cleanly. Returns a non-nil zero-length slice
// for an explicitly empty input, so the caller can distinguish the
// "param sent with empty value" case from the "param absent" case
// (nil ACRValues).
func splitACRValues(s string) []string {
	parts := strings.Fields(s)
	if parts == nil {
		return []string{}
	}
	return parts
}

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
