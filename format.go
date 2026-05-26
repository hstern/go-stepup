// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup

import (
	"fmt"
	"net/http"
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
// *FormatError instead, see [Challenge.MarshalString].
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

// MarshalString returns the canonical-form representation of c, identical
// to c.String when every parameter value contains only bytes the
// quoted-string + quoted-pair grammar (RFC 7230 §3.2.6) can represent.
//
// When any field value contains a byte that grammar cannot represent —
// any control byte other than HTAB, plus DEL; in particular CR and LF,
// the two header-framing bytes — MarshalString returns a *FormatError
// identifying the field and the offending byte's offset. The String
// method handles the same input by replacing the offending byte with SP
// (a lossy but error-free fallback the [fmt.Stringer] contract requires);
// use MarshalString when silent loss is the wrong behavior — fixture
// serialization, interop regression tests, security-sensitive callers
// that need to surface malformed input rather than mask it.
//
// Field naming in the *FormatError matches the wire auth-param name for
// the seven spec-defined parameters (realm, scope, error,
// error_description, error_uri, acr_values), the literal Extra key for
// Extra entries. The max_age parameter is always-valid (its value comes
// from a uint64 and contains only digits) and is not checked.
//
// On multiple offending fields, the first failure in spec emit order
// wins: a Challenge with both a CR in Realm and an LF in Scope reports
// the realm failure. This pins behavior to the spec-order traversal so
// callers can rely on a deterministic failure mode.
//
// A pure-empty Challenge (no fields, no Extra) marshals to "Bearer"
// with no error — the same canonical-form rule String pins.
//
// See RFC 9470 §3 — https://www.rfc-editor.org/rfc/rfc9470.html#section-3
// and RFC 7230 §3.2.6 (quoted-string + quoted-pair grammar).
func (c *Challenge) MarshalString() (string, error) {
	// Pre-scan in spec emit order so the first-failure-wins contract is
	// observable: a *FormatError must name the field the canonical
	// emit loop would have reached first. Doing the scan up front (vs.
	// interleaving with emission) keeps the writer body identical to
	// String — only the validation precondition differs.
	if err := c.validateForWire(); err != nil {
		return "", err
	}
	// Validation passed: every byte in every emitted value is
	// representable, so writeQuotedString's substitution branch is
	// dead and the output is byte-identical to String.
	return c.String(), nil
}

// WriteHeader appends a canonical WWW-Authenticate value for c to h. It
// is a thin convenience over c.String and [http.Header.Add] — the
// equivalent of:
//
//	h.Add("WWW-Authenticate", c.String())
//
// Multiple calls append additional challenges as additional header
// values: a 401 response advertising both a Bearer step-up challenge
// and a fallback Basic challenge is two WriteHeader calls (or one
// WriteHeader plus one direct h.Add). Servers wanting multiple Bearer
// challenges packed into ONE header value should format them manually —
// this helper writes one value per call, which is the
// stdlib-idiomatic shape and the form parsers must handle anyway per
// RFC 7235 §4.1.
//
// WriteHeader inherits String's lossy fallback for bytes the wire
// cannot represent (raw control characters, CR, LF — each replaced
// with SP). Callers who need fail-fast on malformed input should use
// [Challenge.MarshalString] and call h.Add on the returned string
// themselves, branching on the returned *FormatError. The two
// together cover both ergonomic shapes: "I trust my Challenge"
// (WriteHeader) versus "I'm serializing untrusted input"
// (MarshalString + h.Add + error check).
//
// WriteHeader is faithful to whatever Challenge it receives — it does
// not gate on the error code. A Bearer challenge advertising
// error="invalid_token" round-trips through WriteHeader exactly like
// a step-up challenge does, even though [ParseHeader] would filter
// the non-step-up form back out on the receive side. The library
// treats emission as policy-free; deciding whether a given Challenge
// is appropriate to emit is the caller's job.
//
// h must not be nil. Passing a nil [http.Header] panics, matching the
// behavior of [http.Header.Add] on a nil receiver — no extra
// defensive check here, because masking the stdlib panic would only
// hide a programming error one stack frame deeper.
func (c *Challenge) WriteHeader(h http.Header) {
	h.Add("WWW-Authenticate", c.String())
}

// validateForWire walks c in canonical emit order and returns the first
// *FormatError found, or nil if every value is representable. The traversal
// MUST mirror String's emit order — that is the load-bearing property
// MarshalString's "first failure wins" contract relies on.
//
// max_age is intentionally not checked: its value is rendered from a
// uint64 via strconv.FormatUint and so contains only ASCII digits, every
// one of which is representableInQuotedString. Skipping the check keeps
// the hot path one branch shorter and documents the invariant.
func (c *Challenge) validateForWire() *FormatError {
	if c.Realm != "" {
		if err := checkValue(ParamRealm, c.Realm); err != nil {
			return err
		}
	}
	if c.Scope != "" {
		if err := checkValue(ParamScope, c.Scope); err != nil {
			return err
		}
	}
	if c.ErrorCode != "" {
		if err := checkValue(ParamError, c.ErrorCode); err != nil {
			return err
		}
	}
	if c.ErrorDescription != "" {
		if err := checkValue(ParamErrorDescription, c.ErrorDescription); err != nil {
			return err
		}
	}
	if c.ErrorURI != "" {
		if err := checkValue(ParamErrorURI, c.ErrorURI); err != nil {
			return err
		}
	}
	if len(c.ACRValues) > 0 {
		// Check each element individually rather than the joined
		// string so the error can name which element index broke.
		// The joined value is what reaches the wire, but the
		// per-element position is the actionable diagnostic for a
		// caller that needs to fix a misformed input list.
		for i, v := range c.ACRValues {
			if idx, ok := firstUnrepresentableByte(v); !ok {
				return &FormatError{
					Field:  ParamACRValues,
					Reason: fmt.Sprintf("element %d: %s", i, describeByte(v[idx], idx)),
				}
			}
		}
	}
	// MaxAge skipped — digits only by construction.
	if len(c.Extra) > 0 {
		// Spec order says Extra entries emit in lex-sorted key
		// order; walk in the same order so first-failure-wins
		// matches the emit sequence.
		keys := make([]string, 0, len(c.Extra))
		for k := range c.Extra {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if err := checkValue(k, c.Extra[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkValue is the per-field wrapper that turns a firstUnrepresentableByte
// hit into a *FormatError naming the field and the offending byte.
func checkValue(field, value string) *FormatError {
	idx, ok := firstUnrepresentableByte(value)
	if ok {
		return nil
	}
	return &FormatError{
		Field:  field,
		Reason: describeByte(value[idx], idx),
	}
}

// describeByte renders the human-readable Reason fragment for a single
// offending byte: hex form for the byte plus its zero-based offset. Kept
// as one function so every *FormatError this file produces phrases the
// reason consistently.
func describeByte(b byte, offset int) string {
	return fmt.Sprintf("control byte 0x%02X at position %d", b, offset)
}

// writeQuotedString writes s into b wrapped in DQUOTE, escaping the two
// characters RFC 7230 §3.2.6 quoted-pair requires (\\ and \") and replacing
// any byte the quoted-string production cannot represent with a single SP.
// This is the lossy fallback the [fmt.Stringer] no-error contract demands;
// a fail-fast variant lives in MarshalString and surfaces these bytes as a
// *FormatError instead.
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
//
// The "is this byte representable?" decision is delegated to
// representableInQuotedString so the lossy path here and the fail-fast
// path in MarshalString agree byte-for-byte on what counts as
// representable.
func writeQuotedString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case representableInQuotedString(c):
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

// representableInQuotedString reports whether byte c can appear inside a
// quoted-string + quoted-pair envelope per RFC 7230 §3.2.6 — i.e. whether
// the formatter can emit it verbatim (after the usual \" / \\ escaping for
// DQUOTE and backslash, which callers handle separately) rather than
// having to substitute or reject it.
//
// True for:
//
//   - HTAB (0x09) and SP (0x20) — explicitly admitted by qdtext.
//   - %x21–%x7E printable ASCII — qdtext + quoted-pair between them cover
//     every visible byte (DQUOTE and backslash live in here too; the caller
//     wraps those in quoted-pair before reaching this predicate).
//   - %x80–%xFF obs-text — admitted by qdtext (and quoted-pair) even
//     though the production is marked obsolete. Mirrors the
//     lenient-unmarshal posture on the marshal side.
//
// False for:
//
//   - Control bytes 0x00–0x08, 0x0A–0x1F (excluding HTAB which is
//     allowed at 0x09).
//   - CR (0x0D) and LF (0x0A) specifically — falls into the
//     control-byte range above; called out here because these two are
//     the header-injection vectors a hostile input would use to break
//     out of the header.
//   - DEL (0x7F) — qdtext excludes it.
//
// The two emit paths agree on this predicate: String replaces a "false"
// byte with SP (the [fmt.Stringer] no-error fallback); MarshalString
// surfaces it as a *FormatError naming the field and the byte's offset.
// Keeping the classifier in one place is what makes that agreement
// regression-proof.
func representableInQuotedString(c byte) bool {
	switch {
	case c == '\t' || c == ' ':
		return true
	case c >= 0x21 && c <= 0x7E:
		return true
	case c >= 0x80:
		return true
	default:
		// 0x00–0x08, 0x0A–0x1F, 0x7F.
		return false
	}
}

// firstUnrepresentableByte returns the zero-based index of the first byte
// in s that representableInQuotedString rejects, or (0, true) if every
// byte in s is representable. The boolean (rather than a sentinel index
// like -1) makes the common "is this whole string clean?" check a single
// comparison at the call site.
//
// Used by MarshalString to locate the offending byte for the
// *FormatError.Reason message. The lossy String path doesn't need to
// pre-scan and so doesn't call this — it acts byte-by-byte inside the
// emit loop, replacing as it goes.
func firstUnrepresentableByte(s string) (idx int, ok bool) {
	for i := range len(s) {
		if !representableInQuotedString(s[i]) {
			return i, false
		}
	}
	return 0, true
}
