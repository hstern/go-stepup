// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"slices"
	"strconv"
	"strings"
)

// String returns the canonical RFC 9470 §3 WWW-Authenticate value for c, as
// the [fmt.Stringer] no-error contract. The output is suitable for direct use
// as the value of a WWW-Authenticate header on a resource-server response.
//
// # Canonical form
//
// The emitted byte sequence is
//
//	Bearer <p1>=<v1>, <p2>=<v2>, ..., <pn>=<vn>
//
// with a single SP between the scheme and the first auth-param and ", "
// (comma + single SP) between successive auth-params. The scheme is always
// the exact literal "Bearer" — RFC 7235 §2.1 makes auth-scheme matching
// case-insensitive on the wire, but on output the library pins one canonical
// casing for byte-stable round-trips. Auth-param names are emitted lowercase
// per the same section's case-insensitivity rule and the lowercased spellings
// pinned by the Param* constants.
//
// # Parameter order
//
// Auth-params present on c are emitted in two groups:
//
//  1. The seven RFC 9470 / RFC 6750 / RFC 7235 auth-params in spec order:
//     realm, scope, error, error_description, error_uri, acr_values, max_age.
//     Each is emitted only when the corresponding field carries a non-zero
//     value (non-empty string, non-empty slice, or non-nil pointer).
//  2. Entries from Extra in lexicographic key order, so the output is
//     byte-stable across runs even though Go map iteration is randomized.
//
// A Challenge whose every field is the zero value produces the bare token
// "Bearer" with no trailing whitespace, comma, or auth-param — the
// canonical-form rule trumps any "challenge with no params should be empty"
// interpretation.
//
// # Value quoting
//
// Text-valued parameters (realm, scope, error, error_description, error_uri,
// acr_values, and every entry from Extra) are always wrapped in DQUOTE per
// RFC 7230 §3.2.6 quoted-string. Always-quoting is a deliberate choice:
// quoted-string admits any printable byte plus SP and HTAB, while bare token
// form would force per-value tchar inspection and would still need quoting
// for the common case of values carrying spaces or punctuation. Deterministic
// output is worth the few extra bytes.
//
// The max_age parameter is the lone exception: it is always emitted in bare
// token form (max_age=300, not max_age="300"). RFC 9470 §3 admits both forms
// on the wire; the unquoted form is shorter, contains only digits, and is
// the canonical emission this library pins. The parser accepts either form
// per implementer expectation.
//
// The acr_values parameter is a single quoted-string holding the
// space-separated join of c.ACRValues, mirroring the OIDC acr_values shape
// the spec inherits.
//
// Inside the quoted-string, the formatter escapes the two characters
// quoted-pair requires — backslash (\\) and double-quote (\") — and replaces
// every byte that quoted-string cannot represent (HTAB and SP excepted, all
// of 0x00–0x1F plus 0x7F) with a single SP. The replacement is the lossy
// fallback the [fmt.Stringer] no-error contract forces; it incidentally
// neutralizes CR/LF header-injection attempts by collapsing them to
// in-quote whitespace. For a fail-fast variant that surfaces these as a
// *FormatError instead, see the MarshalString method (added in a later
// commit).
//
// # Empty vs absent
//
// The typed surface collapses "field set to the empty string" and "field
// not set" for the string-typed fields (Realm, Scope, ErrorCode,
// ErrorDescription, ErrorURI): both round-trip as "absent on the wire."
// This is the documented cost of mapping wire-empty to Go's zero string.
// Similarly, a nil ACRValues and an empty []string ACRValues both emit no
// acr_values parameter. The MaxAge field uses *uint64 specifically to avoid
// this collapse: a non-nil pointer to 0 emits max_age=0; nil emits no
// max_age parameter.
//
// # Round-trip
//
// Parse → String → Parse yields a Challenge with field values identical to
// the original parse, even though the byte representation may differ in
// parameter order, name case, and quoting style (RFC 9470 §3 examples use
// quoted max_age; canonical form uses token).
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3,
// RFC 7235 §2.1 (auth-scheme casing), and RFC 7230 §3.2.6 (quoted-string
// grammar).
func (c *Challenge) String() string {
	var b strings.Builder
	// Most challenges are < 256 bytes. Pre-size to skip the first few
	// realloc cycles strings.Builder would otherwise perform.
	b.Grow(64)
	b.WriteString("Bearer")

	first := true
	emit := func(name, value string, quoted bool) {
		if first {
			b.WriteByte(' ')
			first = false
		} else {
			b.WriteString(", ")
		}
		b.WriteString(name)
		b.WriteByte('=')
		if quoted {
			writeQuotedString(&b, value)
		} else {
			b.WriteString(value)
		}
	}

	if c.Realm != "" {
		emit(ParamRealm, c.Realm, true)
	}
	if c.Scope != "" {
		emit(ParamScope, c.Scope, true)
	}
	if c.ErrorCode != "" {
		emit(ParamError, c.ErrorCode, true)
	}
	if c.ErrorDescription != "" {
		emit(ParamErrorDescription, c.ErrorDescription, true)
	}
	if c.ErrorURI != "" {
		emit(ParamErrorURI, c.ErrorURI, true)
	}
	if len(c.ACRValues) > 0 {
		emit(ParamACRValues, strings.Join(c.ACRValues, " "), true)
	}
	if c.MaxAge != nil {
		// Token form per the canonical-emission rule documented on
		// String. strconv.FormatUint allocates a single small string;
		// no heap pressure to worry about on the hot path.
		emit(ParamMaxAge, strconv.FormatUint(*c.MaxAge, 10), false)
	}

	if len(c.Extra) > 0 {
		// Map iteration order is randomized; sort the keys so the
		// output is byte-stable. Re-allocating the slice on every
		// String call is cheaper than threading a cached sort through
		// the Challenge type (and would force String to take a
		// pointer receiver for mutation, which it already does — but
		// caching would still be a maintenance hazard against
		// concurrent reads). The slices.Sort path is allocation-light
		// for the common < 8-key case.
		keys := make([]string, 0, len(c.Extra))
		for k := range c.Extra {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			emit(k, c.Extra[k], true)
		}
	}

	return b.String()
}

// writeQuotedString writes s into b wrapped in DQUOTE, escaping the two
// characters RFC 7230 §3.2.6 quoted-pair requires (\\ and \") and replacing
// any byte the quoted-string production cannot represent with a single SP.
// This is the lossy fallback the [fmt.Stringer] no-error contract demands;
// a fail-fast variant lives in MarshalString (added in a later commit) and
// surfaces these bytes as a *FormatError instead.
//
// The replacement set is the control-character range qdtext excludes —
// 0x00–0x08, 0x0A–0x1F, and 0x7F — plus the explicit CR (0x0D) and LF
// (0x0A) bytes that header framing would otherwise split on. HTAB (0x09)
// and SP (0x20) are permitted by qdtext and pass through verbatim. Bytes
// in the obs-text range (0x80–0xFF) pass through too: RFC 7230 §3.2.6
// admits them in both qdtext and quoted-pair, even though their use is
// deprecated. The lenient-unmarshal posture extends symmetrically to the
// marshal side here.
//
// Replacing with SP rather than dropping the byte preserves length-sensitive
// layout (e.g. for human readability when a challenge is hex-dumped in
// logs) and incidentally neutralizes CR/LF header-injection vectors by
// collapsing them to in-quote whitespace the parser will accept.
func writeQuotedString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t' || c == ' ':
			b.WriteByte(c)
		case c >= 0x21 && c <= 0x7E:
			// Printable ASCII other than the two escaped above.
			b.WriteByte(c)
		case c >= 0x80:
			// obs-text — admitted by RFC 7230 §3.2.6.
			b.WriteByte(c)
		default:
			// Control bytes (0x00–0x08, 0x0A–0x1F, 0x7F): the
			// lossy fallback. Replace with SP rather than error;
			// MarshalString is the strict path.
			b.WriteByte(' ')
		}
	}
	b.WriteByte('"')
}
