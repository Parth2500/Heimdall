# Heimdall Domain Model

This document lists the rules that the Domain layer (`src/Heimdall.Domain`) enforces. Each rule refers to a decision in `docs/threat-model.md` (D1 to D49) or a table in `docs/schema-design.md`.

The Domain layer has no dependencies. It has no EF Core types. Each entity is created by a factory method that checks its rules. A broken rule throws `DomainException`.

The database enforces the most important rules a second time (unique indexes, check constraints, atomic statements). The Domain rules do not replace them. The Domain rules give clear errors and make the rules testable without a database.

## Shared types

| Type | Rule | Reference |
|---|---|---|
| `TokenHash` | Holds a SHA-256 hash of a code, refresh token, session ID, or client secret. Compares only in fixed time. `ToString()` never shows the value. | D3, D4, D7 |
| `ScopeRules` | A scope is not blank and has no white space. Duplicates are removed. | RFC 6749, section 3.3 |
| `Guard` | Checks for empty IDs, blank text, and lifetimes that are not positive. | |

## Tenants and users

| Entity | Rules | Reference |
|---|---|---|
| `Tenant` | The host is a lowercase DNS name. No wildcard, port, or path. | D21 |
| `TenantSettings` | All lifetimes are positive. An idle timeout is not longer than its absolute lifetime. `Default` holds the platform defaults. | D15, "Limits and lifetimes" |
| `LoginThrottle` | The first failures of an account from one source cost nothing (5 by default). After that, the wait doubles with each failure, from 1 second up to a maximum (15 minutes by default). It never locks. | Login, Spoofing and Denial of service |
| `User` | The email is normalized to lowercase for the unique lookup. The domain holds only an Argon2id hash. A password change sets `PasswordChangedAt`, which ends older sessions. A hash upgrade (same password, stronger Argon2id parameters) does not change `PasswordChangedAt`. | D3, D14 |

## Clients

| Rule | Reference |
|---|---|
| The authentication method comes from the client type: `public` uses `none`, `confidential` uses `client_secret_basic`. An invalid combination cannot exist. | D10 |
| Only a confidential client can switch to `private_key_jwt`. The switch stores its public keys. A new key set replaces the old one. A client has one method at a time. | D45, D47 |
| A key set has 1 to 5 keys and at most 16384 characters. Each key has a unique `kid` of 1 to 128 characters, `kty` `RSA` or `EC`, `use` `sig` when present, and no private member. A refused key set changes nothing. | D46 |
| Only a confidential client can use `client_credentials`. | `/token`, Spoofing |
| The `refresh_token` grant needs the `authorization_code` grant. A client can refresh only if it has the `refresh_token` grant. | Refresh flow |
| A client with the `authorization_code` grant needs at least one redirect URI. | |
| A redirect URI is absolute, uses `https` (plain `http` only for loopback), and has no wildcard, fragment, or user information. | RFC 9700 |
| A redirect URI matches by exact ordinal string. No normalization, no prefix match. | `/authorize`, Spoofing |
| The browser origins of a client are the origins of its `https` redirect URIs, in the browser's format. Only an active public client has them. | D23 |
| A new client is `pending` until an admin approves it. Approval does not enable a disabled client. | `/authorize`, Spoofing |
| Token lifetimes: the client value wins, and the tenant value applies if the client has none. The result must have idle not longer than absolute. | D15 |
| An audience is an absolute URI with `https` (plain `http` only for loopback), and no query, fragment, or user information. | D22, RFC 8707 |
| A client with the `client_credentials` grant needs at least one audience. | D22 |
| A requested resource must match an allowed audience by exact string. With no request, the only audience is the default. With two or more audiences, the client must name one. | D22 |
| A user's grant (`ResolveUserAudience`) can also name the tenant's userinfo endpoint. A client with no audience gets the userinfo endpoint as its default. | D22 |
| A post-logout redirect URI and a back-channel logout URI meet the redirect URI rules. A refused update changes nothing. | D32, D35 |
| A post-logout redirect URI matches by exact ordinal string, as a redirect URI does. | D32 |
| Only a confidential client can serve resource audiences. Each one meets the audience rules. A client may introspect an access token whose audience it serves, or that was issued to it, by exact string. | D36, D37 |

## Codes and tokens

| Entity | Rules | Reference |
|---|---|---|
| `Pkce` | Only S256. A verifier has 43 to 128 unreserved characters. A challenge has 43 BASE64URL characters. The check is in fixed time. | D2, RFC 7636 |
| `AuthorizationRequest` | A checked `/authorize` request, stored while the user signs in. Lifetime of 10 minutes. Needs a valid S256 challenge. `state` and `nonce` have at most 512 characters. With `prompt=login`, only a sign-in strictly after the request counts. `max_age` compares with the last sign-in. A `dpop_jkt` must be a 43-character thumbprint (D27). A pushed request (D41) lives 60 seconds and keeps the hash of its `request_uri`. With `prompt=consent`, the user decides on the consent page, also for a client that does not require consent. `prompt=none` with `prompt=login`, `prompt=consent`, or `prompt=select_account` is refused. A `login_hint` must look like an email address of at most 254 characters. `Select` records the `sid` of the chosen session and the time (D52). | `/authorize`, `/par`, login (open redirect) |
| `AuthorizationCode` | Lifetime of 5 minutes. Needs a valid S256 challenge. `Redeem` reports reuse before expiry, because reuse is an attack signal. It records the family that the code started. It keeps the request's DPoP key thumbprint, which must be a 43-character thumbprint (D27). It keeps the `sid` of the session that issued it, which must be 22 base64url characters (D29). | `/token`, Elevation of privilege |
| `TokenFamily` | The absolute limit is fixed at creation. Rotation moves the idle limit, never past the absolute limit. A second revocation keeps the first reason. Refresh can keep or reduce scope, never add to it. It keeps the `sid` of the code, when the code has one (D29). | Refresh flow, D33 |
| `RefreshToken` | Single-use. A second use returns `Reused`, and the caller must revoke the family. | Refresh flow |

## Sessions and consent

| Entity | Rules | Reference |
|---|---|---|
| `Session` | Stores only the hash of the session ID. It is valid only when: not revoked, the tenant matches the request, the user matches and is active, it was created after the last password change, and neither the idle nor the absolute limit has passed. Activity never passes the absolute limit. `max_age` compares with the last sign-in, not the last activity. It has a public `sid` of 22 base64url characters (`SessionSid`), which is not the cookie secret. `Reauthenticate` gives the same session a new ID hash, a new sign-in time, and a new absolute limit. It keeps the `sid` and the creation time. It refuses a revoked session and an unchanged ID. | D11 to D13, D18, D29 |
| `AuthorizationRequest` (consent) | Records one consent decision and the user who made it. A decision counts only for that user. A later decision replaces it. | Consent page, Spoofing |
| `Consent` | Covers a request only if active and every requested scope is in it. A new approval adds scopes to an active consent. After a revocation, a new approval starts with only the new scopes, so old scopes do not come back. | `/authorize`, Repudiation |

## Signing keys

| Rule | Reference |
|---|---|
| The algorithm is `RS256`. | D8 |
| A new key is published at creation. It can sign only after one JWKS cache lifetime. | JWKS, Elevation of privilege |
| Rotation activates the next key first. If the next key is not ready, the current key stays active. A tenant never has no signing key because of a failed rotation. | JWKS |
| A retired key stays in the JWKS until the last token it signed has expired, plus clock skew. | JWKS |
| Emergency removal takes the key out of the JWKS at once. | JWKS, Elevation of privilege |
| The private key reference must not contain key material (text with `PRIVATE KEY` is rejected). | D3, "Local development signing keys" |
| Both keys in a rotation belong to the same tenant. | D19 |

## Audit events

| Rule | Reference |
|---|---|
| An event cannot change after creation. The data is copied at creation. | `/token`, Repudiation |
| The event type uses a constant from `AuditEventTypes`, in the form `area.action`. | |
| A data key that suggests a secret is rejected: `password`, `secret`, `token`, `verifier`, `assertion`, `cookie`, or exactly `code`. This guard catches mistakes. It does not inspect values, so code review still applies. | D7 |

## What the Domain layer does not do

- It does not check the platform limits (minimum and maximum for each setting). The Application layer does this (D16).
- It does not prevent races. Two requests can hold two copies of one entity. The atomic SQL statements in `docs/schema-design.md` close the race.
- It does not hash passwords or sign tokens. The Infrastructure layer does this behind interfaces in the Application layer.
