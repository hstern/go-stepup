# go-stepup

A Go implementation of
[RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html)
— the `WWW-Authenticate: Bearer` challenge a resource server emits
when an access token is technically valid but does not meet the
authentication strength (or recency) the resource requires, and the
typed parse / format helpers a client needs to interpret it.

`go-stepup` provides:

- A typed `Challenge` value covering every parameter defined by
  RFC 9470 §3 (`realm`, `scope`, `error`, `error_description`,
  `error_uri`, `acr_values`, `max_age`) plus an `Extra` map for
  forward compatibility with future amendments and vendor
  extensions.
- A lenient parser — `Parse(headerValue string) (*Challenge, error)`
  and `ParseHeader(http.Header) ([]*Challenge, error)` — that accepts
  any RFC 7235-conformant `WWW-Authenticate` value and filters to the
  Bearer challenges carrying the RFC 9470 `insufficient_user_authentication`
  error code.
- A strict canonical-form formatter — `(*Challenge).String()` and
  `(*Challenge).WriteHeader(http.Header)` — that emits a single,
  byte-stable representation suitable for interop testing, plus a
  fail-fast `(*Challenge).MarshalString() (string, error)` variant
  for callers that want to surface unrepresentable bytes instead of
  having them substituted.
- An optional `(*Challenge).Validate() error` for callers that want
  semantic checking on top of the spec's grammar requirements.
- A sentinel `ErrInsufficientUserAuthentication` for the dispatch
  pattern most consumers reach for first.

The library is **stdlib-only** in v0.1: no non-test runtime
dependencies. It works with `net/http` directly and with any router
that surfaces `http.Header` (chi, gorilla/mux, fiber, …).

## Status

Pre-release. `v0.1.0` will be the first tagged release. The library
tracks RFC 9470 (Proposed Standard, 2023-09), exposed as
`stepup.SpecVersion`.

## Quickstart

### Client — parse a step-up challenge from a 401 response

`ParseHeader` walks every `WWW-Authenticate` value on the response,
filters to Bearer challenges carrying
`error="insufficient_user_authentication"`, and returns them in header
order. Non-Bearer schemes (Basic, Digest) and Bearer challenges with
any other error code are silently skipped — so every `*Challenge` in
the returned slice is, by construction, a step-up challenge the
client must act on.

```go
package main

import (
	"log"
	"net/http"

	"github.com/hstern/go-stepup"
)

func handle(resp *http.Response) {
	challenges, err := stepup.ParseHeader(resp.Header)
	if err != nil {
		log.Fatal(err) // malformed WWW-Authenticate header
	}
	for _, c := range challenges {
		log.Printf("step-up required: acr_values=%v max_age=%v",
			c.ACRValues, c.MaxAge)
		// Trigger re-authentication at the requested ACR / max_age.
	}
}
```

The `ErrInsufficientUserAuthentication` sentinel is exported for
consumers that wrap a parsed step-up challenge into Go's error-chain
idiom (`fmt.Errorf("step-up required: %w", stepup.ErrInsufficientUserAuthentication)`)
so upstream callers can dispatch via `errors.Is`. The library itself
never returns it — `ParseHeader` returns `(nil, *ParseError)` on
grammar violations and `(challenges, nil)` otherwise.

### Resource server — emit a step-up challenge

`WriteHeader` appends a canonical-form value to an `http.Header`.
Multiple calls append additional challenges, so a response advertising
a Bearer step-up challenge alongside a Basic fallback is two calls (or
one `WriteHeader` plus one direct `Header.Add`).

```go
package main

import (
	"net/http"

	"github.com/hstern/go-stepup"
)

func stepUpRequired(w http.ResponseWriter, _ *http.Request) {
	ch := &stepup.Challenge{
		Realm:            "api.example.com",
		ErrorCode:        stepup.ErrorInsufficientUserAuthentication,
		ErrorDescription: "MFA required for this resource",
		ACRValues:        []string{"urn:mace:incommon:iap:silver"},
	}
	ch.WriteHeader(w.Header())
	w.WriteHeader(http.StatusUnauthorized)
}
```

## How this fits with OAuth 2.0 / OIDC

RFC 9470 is a thin layer on top of RFC 6750 (Bearer token usage) and
borrows the `acr_values` / `max_age` request parameters from
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
`go-stepup` handles only the challenge — the `WWW-Authenticate` header
on the 401 response and the typed value clients dispatch on. Token
introspection, JWT `acr` / `auth_time` claim verification, and
authorization-server request building are explicitly out of scope —
they belong in a JWT library, an OIDC client, or your AS SDK.

## Stability

Pre-v1.0 the library follows SemVer with the caveat that the exported
surface may evolve until the first major. Once `v1.0.0` ships:

- Exported type and function signatures are frozen for the life of
  the major version.
- The wire-level canonical-form output of `(*Challenge).String()` is
  byte-stable; round-tripping `Parse → String → Parse` is
  guaranteed to produce typed-field-equivalent `Challenge` values.
- New optional `Challenge` fields may be added as future RFC 9470
  amendments emerge; existing fields are not removed or renamed.
- The optional `(*Challenge).Validate()` semantic check follows the
  same contract: new rules may be added between minor versions and
  may newly reject input that previously passed, but the reverse
  (relaxing a rule so previously-rejected input passes) is a major
  bump. Existing rule identifiers (`RuleErrorCodeRecognized`,
  `RuleACRValuesNonEmpty`, `RuleMaxAgeInBounds`) are stable; new
  rules add new `Rule*` constants.

The library SemVer is independent of the RFC version it implements.

## License

[Apache-2.0](LICENSE). See [`AGENTS.md`](AGENTS.md) for contributor
conventions.
