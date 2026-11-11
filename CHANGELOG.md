# Changelog

This file lists the changes that matter to a client developer or an operator. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Heimdall has no release yet, so all entries are under "Unreleased", by phase and date. Each decision change also has a [decision record](docs/decisions/README.md).

## Unreleased

### Phase 3: Breadth

#### 2026-11-12

- Changed: one browser can hold up to five signed-in accounts of a tenant. The session cookie holds a list of session IDs (D12, D50, DR-013). The account picker and `prompt=select_account` follow (#41).
- Changed: a second sign-in of the same user in the same browser keeps the session and its `sid`. The ID token of the next sign-in has the same `sid` and a new `auth_time`. Before, the second sign-in started a new session, and a later sign-out did not revoke the token families of the first one (D13, DR-013).
- Added: the audit event `session.reauthenticated`, and the login API error `session_limit` (HTTP 409).
- Changed: dependency updates: Angular 22.2.4, vitest 5.1.0, OpenTelemetry instrumentation 1.20.2, Scalar 2.19.0, CsCheck 5.0.1, base images, and CI actions.

### Phase 2: Hardening

#### 2026-10-28

- Added: pushed authorization requests at `POST /oauth/v1/par` (RFC 9126, D40 to D43). A client can require them.
- Added: `prompt=consent`. It shows the consent page, also for a client that does not require consent. `prompt` values combine, except `none` with another value.
- Added: `scopes_supported` and `claims_supported` in discovery.
- Changed: `/userinfo` refuses an access token at once when its family is revoked: after a sign-out, a code or refresh token reuse, or `/revoke` (D44, DR-010).
- Added: the OpenID conformance results (`docs/conformance.md`) and the local suite tooling (`tools/conformance/`).
- Added: interop tests with the ASP.NET Core OpenID Connect handler and with `oidc-client-ts`.
- Added: the OpenAPI 3.1 document of the session API and its Scalar page, in Development only.
- Added: the operations runbook (`docs/operations.md`) and the decision records (`docs/decisions/`).
- Added: a Bruno collection for manual tests of each endpoint (`tools/bruno/`). It needs no browser.
- Added: `private_key_jwt` client authentication (RFC 7523, D45 to D49) at `/token`, `/revoke`, `/introspect`, and `/par`. The operator registers the client's public keys inline. `aud` must be the issuer. Each assertion works once (DR-011).
- Changed: CI runs each workflow only when its files change. A new workflow builds the server and migration images.

#### 2026-10-26

- Added: RP-initiated logout at `/oauth/v1/logout`, with a confirm page when the request has no ID token of the current session (D29 to D33).
- Added: back-channel logout. Heimdall sends a signed `logout_token` with `sid` to each client of the ended session (D34, D35).
- Added: the `sid` claim in ID tokens and the `fid` claim in user access tokens (D29).
- Changed: a sign-out revokes every token family of the session, also with `offline_access` (D33).
- Added: token introspection at `POST /oauth/v1/introspect` for confidential clients (RFC 7662, D36 to D39).

#### 2026-10-22 to 2026-10-25

- Added: DPoP (RFC 9449, D24 to D28): bound access tokens, bound refresh tokens for public clients, `dpop_jkt` at `/authorize`, and the DPoP scheme at `/userinfo`.
- Added: a group-commit audit writer.
- Added: mutation tests (Stryker.NET) and property tests (CsCheck). The property tests found two crashes on bad input, now fixed.
- Changed: the account pages took the U15 look on 2026-10-23, then the U16 Ledger card on 2026-10-25 (DR-007).

#### 2026-10-19

- Added: the client configuration cache.
- Added: OpenTelemetry traces and metrics, health endpoints, and forwarded headers from trusted proxies.
- Added: rate limits on sign-in, `/authorize`, `/token`, and `/revoke`, and a sign-in throttle for each account and source. Heimdall never locks an account.
- Added: CORS for the registered origins of browser clients (D23).
- Added: the Angular account pages (login, consent, error) and the demo SPA.

### Phase 1: Core engine

#### 2026-10-18 to 2026-10-19

- Added: the authorization code flow with PKCE `S256` for every client, and the `client_credentials` grant with an audience for each client (D22).
- Added: RS256 signing keys for each tenant, with rotation, a publish wait, and emergency removal (`remove-key`).
- Added: refresh token rotation. A reused refresh token or code revokes its family at once, with no grace window (DR-003).
- Added: Argon2id password hashing, sessions, and the login and consent API.
- Added: `/userinfo`, `/revoke`, discovery, and JWKS.
- Added: PostgreSQL row-level security on every tenant-owned table, as the second tenant layer (D20, DR-006).
- Added: the purge job.

### Phase 0: Threat model and design

#### 2026-10-18

- Added: the threat model (STRIDE for each endpoint, D1 to D22), the schema design, the domain model, and the diagrams.
