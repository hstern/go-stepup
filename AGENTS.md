# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Aider, Copilot
Workspace, etc.) working on `go-stepup`. Human contributors will get
more out of `CONTRIBUTING.md` once it exists; this file captures the
things that are easy for an agent to get wrong if it doesn't know them
up front.

## What this project is

`go-stepup` is a Go implementation of
[RFC 9470 — OAuth 2.0 Step-Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470.html)
— the `WWW-Authenticate: Bearer` challenge a resource server emits
when an access token is technically valid but does not meet the
authentication strength (or recency) the resource requires.

The library is **library-vendor-neutral**: it implements the RFC,
nothing more. It provides a typed `Challenge`, a lenient parser, a
strict canonical-form formatter, and an optional `Validate()`. It
does NOT provide a policy engine, an OIDC client, JWT `acr` claim
verification, or framework-specific middleware. Those belong in
downstream consumers.

Spec version: **RFC 9470** (Proposed Standard, 2023-09). Tracked in
source as `const SpecVersion = "RFC 9470"`.

## Repository scope rules

These rules are absolute. They are not preferences; they're correctness
constraints for what lands in the repo.

1. **The library is the subject.** Code, comments, docs, commit
   messages, and CI artifacts describe what the library does for an
   anonymous Go developer who found it via a search engine. They do
   not describe what the maintainer is using it for, where it is being
   developed, who is tracking which task, or how it relates to anything
   outside this repository.
2. **No private infrastructure references.** No internal hostnames,
   internal Git hosts, internal issue trackers, internal documentation
   sites, or any URL pointing at non-public infrastructure.
3. **No private-tracker identifiers.** Ticket short-codes, project
   IDs, page UUIDs, board names from any private tracker — none of it
   in source, README, CHANGELOG, or commit messages. When public issue
   tracking exists (GitHub Issues), reference its public URL only.
4. **No interim hosting paths.** `go.mod` declares the publication
   module path from day one. Any interim location of the repo during
   private development MUST NOT appear in `go.mod`, README, comments,
   or CI configuration.
5. **No references to sibling private libraries.** Public libraries
   (`go-jose`, `golang.org/x/oauth2`) may be cited by name when
   genuinely relevant.

If you are unsure whether something is safe to write, default to
omitting it and ask. The cost of asking is low; the cost of leaking
context that can't be deleted from git history is high.

## Go conventions for this codebase

### Dependencies

**Zero non-test runtime dependencies.** Standard library only. This is
load-bearing for adoption: a standards-implementing library that pulls
in a logger, a metrics SDK, or an alternate JSON encoder forces those
choices on every consumer. The library is small enough that the stdlib
covers everything it needs (`net/http`, `strings`, `strconv`).

Test-only dependencies (if any are eventually warranted) are fine
under `_test.go` files. None are needed for v0.1.

### Style

- `gofmt`, `go vet`, `staticcheck`, `golangci-lint` all run in CI and
  must pass. `gofumpt` (strict superset of `gofmt`) is the formatter.
- Receivers: short, lowercase, consistent within a type.
- Errors: lowercase sentence, no trailing punctuation, wrap with
  `%w` when adding context.
- Exported symbols have godoc comments. Short, link-rich. Reference
  RFC 9470 section numbers (§3.1, etc.) where they anchor the
  behavior.
- Examples live in `_test.go` as `Example*` functions and render in
  godoc.

### Copyright header

Every `.go` file (including tests) begins with exactly:

```go
// Copyright 2026 The go-stepup Authors
// SPDX-License-Identifier: Apache-2.0
```

before the `package` line. The `LICENSE` file at the repo root carries
the full Apache-2.0 text; the per-file SPDX tag is the binding
reference for tools.

### Validation posture

Lenient on parse, strict on format. The parser accepts any
RFC 7235-conformant `WWW-Authenticate` value — unknown auth-params
land in `Extra` rather than failing — because the wire is the
adversary and forward compatibility matters. The formatter emits a
single canonical form. Callers that want semantic checking on top of
grammar correctness call `(*Challenge).Validate()` explicitly.

### Wire / type fidelity

- Auth-scheme is case-insensitive on input, canonical `Bearer` on
  output (RFC 7235 §2.1).
- Auth-param names are case-insensitive on input, lowercase on output.
- `max_age` accepts both token (`max_age=5`) and quoted-string
  (`max_age="5"`) forms on parse; emits token form.
- `MaxAge` is `*uint64`, not `uint64` — distinguishes "not set" from
  "set to 0"; zero is a valid value per spec.
- `ACRValues` is `[]string` on the typed surface, but a single
  space-separated quoted-string on the wire (mirroring OIDC).
- `ParseHeader` filters to Bearer challenges carrying
  `error="insufficient_user_authentication"`. A response may
  legitimately advertise Basic + Bearer challenges in parallel; the
  library is concerned only with RFC 9470 challenges.
- Round-trip is **typed-field equivalence**, not byte equivalence.
  `Parse → String → Parse` produces a `Challenge` with field values
  identical to the original parse; the intermediate string is the
  canonical form, which may differ from the input in parameter order,
  name case, or quoting style.

## Testing

- Table-driven tests for parser and formatter, against every example
  header value from RFC 9470 §3 (embedded under
  `internal/specfixtures/`).
- Round-trip conformance: parse → format → parse → typed-field
  equivalence.
- Forward-compat test: a synthesized header carrying an unknown
  auth-param round-trips with the param in `Extra`.
- `go test -race -shuffle=on ./...` is the CI test invocation.
- No network calls in unit tests. There is no published RFC 9470
  interop endpoint to point at.

## Commit messages

- Imperative present tense ("add Challenge type", not "added").
- Reference public artifacts only — RFC numbers, spec section numbers,
  public PRs / commits. Do not reference private trackers (see rule 3
  above).
- One logical change per commit. The phased build plan in `.claude/`
  is structured so each phase fits in one PR (or a small series).

## CI

GitHub Actions, two workflows:

- `.github/workflows/ci.yml` — fan-out: `static` (gofmt + vet + tidy),
  `test` (`go test -race -shuffle=on`), `lint` (`golangci-lint`). One
  CI run surfaces every failure at once.
- `.github/workflows/vuln.yml` — separate, non-blocking, runs on
  `main` + daily cron. `govulncheck` against the import graph.

Required checks on every pull request: `static`, `test`, `lint`.

## Where to find more detail

`.claude/` contains the deeper design notes — same content, more
exposition — but is gitignored locally and never published. The
public-facing surface is this `AGENTS.md`, the per-symbol godoc, the
`README.md`, and the `CHANGELOG.md`.

## When to ask vs when to proceed

- Bug fix, refactor, doc tweak, test addition for an existing feature:
  proceed. Reference the RFC section that motivates the change in the
  commit message.
- New exported API surface, change to an interface signature, anything
  that affects backwards compatibility: ask first. These are
  forever-decisions once the library is published.
- Anything that might cross the scope rules (1–5) above: ask. The
  cost of a quick check is far less than the cost of force-pushing
  history after a leak.
