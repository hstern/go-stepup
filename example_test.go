// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0

package stepup_test

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hstern/go-stepup"
)

// ExampleParse demonstrates parsing one WWW-Authenticate header value into a
// typed [stepup.Challenge]. This is the typical "got a 401 response, what did
// it ask for" flow: the caller already has the single header value in hand
// and wants the spec-defined fields surfaced as Go types.
func ExampleParse() {
	const header = `Bearer realm="example", error="insufficient_user_authentication", error_description="Multi-factor authentication required", acr_values="myACR"`

	c, err := stepup.Parse(header)
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	fmt.Println("realm:", c.Realm)
	fmt.Println("error:", c.ErrorCode)
	fmt.Println("acr_values:", c.ACRValues)
	// Output:
	// realm: example
	// error: insufficient_user_authentication
	// acr_values: [myACR]
}

// ExampleParseHeader demonstrates HTTP-level dispatch: iterating every
// WWW-Authenticate header line on a response and surfacing only the RFC 9470
// step-up challenges. Non-Bearer schemes (Basic, Digest, …) and Bearer
// challenges whose error code is anything other than
// "insufficient_user_authentication" are filtered out, so the result is
// exactly the set of step-up demands the server is making.
func ExampleParseHeader() {
	h := http.Header{}
	h.Add("WWW-Authenticate", `Basic realm="x"`)
	h.Add("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
	h.Add("WWW-Authenticate", `Bearer realm="api", error="insufficient_user_authentication", acr_values="myACR"`)

	chs, err := stepup.ParseHeader(h)
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	fmt.Println("count:", len(chs))
	fmt.Println("acr:", chs[0].ACRValues)
	// Output:
	// count: 1
	// acr: [myACR]
}

// ExampleChallenge_String demonstrates serializing a Challenge to its
// canonical WWW-Authenticate value. Text parameters are always
// quoted-string per RFC 7230 §3.2.6; max_age is always token form. The
// emit order is the spec order: realm, scope, error, error_description,
// error_uri, acr_values, max_age, then any Extra entries in
// lexicographic key order.
func ExampleChallenge_String() {
	c := &stepup.Challenge{
		Realm:     "example",
		ErrorCode: stepup.ErrorInsufficientUserAuthentication,
		ACRValues: []string{"myACR"},
	}
	fmt.Println(c.String())
	// Output:
	// Bearer realm="example", error="insufficient_user_authentication", acr_values="myACR"
}

// ExampleChallenge_WriteHeader demonstrates the http.Header integration:
// appending a canonical WWW-Authenticate value to an outgoing response.
// This is the resource-server-side counterpart to [stepup.ParseHeader].
func ExampleChallenge_WriteHeader() {
	h := http.Header{}
	c := &stepup.Challenge{
		ErrorCode:        stepup.ErrorInsufficientUserAuthentication,
		ErrorDescription: "MFA required",
	}
	c.WriteHeader(h)
	fmt.Println(h.Values("WWW-Authenticate"))
	// Output:
	// [Bearer error="insufficient_user_authentication", error_description="MFA required"]
}

// ExampleChallenge_MarshalString demonstrates the fail-fast formatter
// sibling to [stepup.Challenge.String]. MarshalString returns a
// *FormatError naming the field and the offending byte when a value
// contains a byte that the RFC 7230 §3.2.6 quoted-string grammar cannot
// represent — most notably CR and LF, the two header-framing injection
// vectors. Use this variant when silent SP-substitution is the wrong
// behavior.
func ExampleChallenge_MarshalString() {
	c := &stepup.Challenge{
		Realm:     "example",
		ErrorCode: stepup.ErrorInsufficientUserAuthentication,
	}
	s, err := c.MarshalString()
	if err != nil {
		fmt.Println("format error:", err)
		return
	}
	fmt.Println(s)

	bad := &stepup.Challenge{Realm: "evil\r\nInjected: header"}
	if _, err := bad.MarshalString(); err != nil {
		var fe *stepup.FormatError
		if errors.As(err, &fe) {
			fmt.Println("field:", fe.Field)
		}
	}
	// Output:
	// Bearer realm="example", error="insufficient_user_authentication"
	// field: realm
}

// ExampleChallenge_Validate demonstrates the opt-in semantic check on a
// parsed Challenge. Validate returns the first *[stepup.ValidationError]
// it finds — here, an unrecognized error code that Parse accepted (per
// the library's lenient-unmarshal posture) but Validate rejects.
func ExampleChallenge_Validate() {
	c, err := stepup.Parse(`Bearer error="not_a_real_code"`)
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	if err := c.Validate(); err != nil {
		var ve *stepup.ValidationError
		if errors.As(err, &ve) {
			fmt.Println("rule:", ve.Rule)
			fmt.Println("field:", ve.Field)
		}
	}
	// Output:
	// rule: error_code_recognized
	// field: error
}
