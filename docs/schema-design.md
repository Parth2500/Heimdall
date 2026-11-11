# Heimdall Schema Design (Phase 0)

This document defines the PostgreSQL schema. It uses the terms in the glossary of `docs/threat-model.md`. Decision IDs (D1 to D50) refer to that document.

The document has no C# code. The entities and the migrations are written by hand, from this design.

## Conventions

| Rule | Reason |
|---|---|
| Primary keys are UUIDv7 (`Guid.CreateVersion7()` in .NET). | Time-ordered keys keep index inserts local. They do not reveal counts. |
| Every tenant-owned table has `tenant_id` (not null, foreign key to `tenants`). | D20. |
| Every unique index and foreign key of a tenant-owned table includes `tenant_id`. | The database refuses a link between two tenants. Use composite foreign keys `(tenant_id, x_id)`. |
| Time columns are `timestamptz`. The atomic statements check expiry with the database clock (`now()`). Other reads pass the time from `TimeProvider`, so tests can control it. | The atomic statements must not depend on the clock of one application server. |
| Secrets, codes, and tokens are stored as `bytea` SHA-256 hashes. | D3. |
| Enums are `text` with a `CHECK` constraint. | Easier to change than a native enum type. |
| The Domain project has no EF Core types. All mapping is in `Infrastructure` with `IEntityTypeConfiguration`. | Dependencies point inward only. |

## Tables

### `tenants`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `host` | text, unique | The subdomain (D21). Lowercase. |
| `name` | text | |
| `status` | text | `active`, `suspended`. |
| `session_idle_seconds` | int | D18. Check: inside the hard bounds. |
| `session_absolute_seconds` | int | |
| `access_token_seconds` | int | Tenant default for clients. |
| `refresh_idle_seconds` | int | |
| `refresh_absolute_seconds` | int | |
| `created_at` | timestamptz | |

### `users`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | This value is the `sub` claim. It never changes and is never reused. |
| `tenant_id` | uuid | |
| `email` | text | As the user typed it. |
| `email_normalized` | text | Lowercase. **Unique with `tenant_id`.** |
| `password_hash` | text | Argon2id with parameters in the string. Check: starts with `$argon2id$`, so a plain password or another algorithm cannot be stored. |
| `status` | text | `active`, `disabled`. |
| `created_at`, `password_changed_at` | timestamptz | `password_changed_at` ends older sessions. |

### `login_throttles`
Failed sign-ins of one account from one source. The throttle keeps no state for an unknown email.

| Column | Type | Note |
|---|---|---|
| `tenant_id`, `user_id`, `source_key` | uuid, uuid, text | **Primary key.** `source_key` is an IPv4 address or an IPv6 /64 network. |
| `failures` | integer | Failures in a row. Check: at least 1. |
| `last_failure_at` | timestamptz | A source with no failure for 24 hours starts again at zero. |
| `throttled_until` | timestamptz, null | No sign-in check for this account and source before this time. |

One `INSERT ... ON CONFLICT DO UPDATE` statement records a failure, so concurrent failures on two servers both count. A successful sign-in deletes the row. Row-level security applies, as for the other tenant-owned tables.

### `dpop_proofs`
DPoP proofs that the tenant has seen (D26). A row lives only while its proof could still pass the `iat` check.

| Column | Type | Note |
|---|---|---|
| `tenant_id`, `proof_hash` | uuid, bytea | **Primary key.** `proof_hash` is SHA-256 of the key thumbprint, a colon, and the `jti`. Check: 32 bytes. |
| `expires_at` | timestamptz | The proof's `iat` plus 61 seconds: the 60-second window, plus one second because `iat` is rounded down. |

One `INSERT ... ON CONFLICT DO NOTHING` statement records a proof. One affected row means a new proof. No affected row means a replay. Two servers that see one proof at the same time get one of each, without a read first. The hash includes the key thumbprint, so a client cannot use up another client's `jti`. Row-level security applies, as for the other tenant-owned tables.

### `client_assertions`
`private_key_jwt` assertions that a client has used (D49). A row lives only while its assertion could still pass the `exp` check.

| Column | Type | Note |
|---|---|---|
| `tenant_id`, `assertion_hash` | uuid, bytea | **Primary key.** `assertion_hash` is SHA-256 of the client's primary key, a colon, and the `jti`. Check: 32 bytes. |
| `expires_at` | timestamptz | The assertion's `exp` plus the 60-second clock difference. |

One `INSERT ... ON CONFLICT DO NOTHING` statement records an assertion, as for `dpop_proofs`. The hash includes the client's primary key, so one client cannot use up another client's `jti`. Row-level security applies, as for the other tenant-owned tables.

### `clients`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid | |
| `client_id` | text | The public identifier. **Unique with `tenant_id`.** |
| `name` | text | |
| `type` | text | `public`, `confidential`. |
| `token_endpoint_auth_method` | text | `none`, `client_secret_basic`, or `private_key_jwt` (D45, D47). Check: `none` for `public`, and `client_secret_basic` or `private_key_jwt` for `confidential`. |
| `jwks` | text, null | D46. The public keys of a `private_key_jwt` client, as a JWK Set of at most 16384 characters. Check: set exactly when the method is `private_key_jwt`. The Domain refuses a private key member. |
| `allowed_grant_types` | text[] | Check: not empty, only known values, and `client_credentials` only for `confidential`. A client can refresh when this list has `refresh_token`. There is no separate flag. |
| `allowed_scopes` | text[] | |
| `redirect_uris` | text[] | Stored exactly. Matching is by exact string, in the application, after the client is loaded. The Domain removes duplicates. |
| `allowed_audiences` | text[] | D22. Absolute URIs, https except loopback, no query or fragment. Check: not empty when `allowed_grant_types` has `client_credentials`. |
| `post_logout_redirect_uris` | text[] | D32. The redirect URI rules apply. Matching is by exact string. Empty means that Heimdall never redirects after a sign-out of this client. |
| `backchannel_logout_uri` | text, null | D34, D35. The redirect URI rules apply. Null means that the client gets no back-channel logout. |
| `require_pushed_authorization_requests` | boolean | D43. `/authorize` refuses a request of this client without `request_uri`. |
| `resource_audiences` | text[] | D37. The audiences that the client serves as a resource server, for introspection. The audience rules of D22 apply. Check: empty unless the client is `confidential`. |
| `require_consent` | bool | |
| `status` | text | `pending`, `active`, `disabled`. A client is `pending` until an admin approves it. |
| `access_token_seconds`, `refresh_idle_seconds`, `refresh_absolute_seconds` | int, null | Null means: use the tenant value (D15). Check constraints give the hard bounds. |
| `created_at` | timestamptz | |
| `approved_by`, `approved_at` | | Not in the first migration. They come with the admin approval use case. |

Redirect URIs are a `text[]` column on `clients`, not a separate table. The first design had a `client_redirect_uris` table. A client has few redirect URIs, the application always loads them with the client, and the lookup is an exact string match in memory. A separate table added a join and gave no extra protection.

### `client_secrets`
Two rows can be valid at the same time. This gives rotation without downtime.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | |
| `secret_hash` | bytea | |
| `created_at` | timestamptz | |
| `expires_at` | timestamptz, null | The old secret gets an expiry when the admin adds a new one. |
| `revoked_at` | timestamptz, null | |

A secret is valid when `revoked_at IS NULL` and (`expires_at IS NULL` or `expires_at > now()`). Heimdall compares the presented hash with all valid rows in fixed time (D4). The application limits a client to two valid secrets.

### `authorization_requests`
Heimdall stores the pending `/authorize` request here while the user signs in and gives consent. The consent form references this row and nothing else (see "User login, session, and consent pages").

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | |
| `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge` | text | The checked request. `code_challenge_method` is always `S256`, so there is no column. `state` and `nonce` have at most 512 characters. |
| `force_login` | boolean | `prompt=login`: only a sign-in after `created_at` counts. |
| `max_age_seconds` | integer, null | The OpenID Connect `max_age`. Check: not negative. |
| `created_at`, `expires_at` | timestamptz | `expires_at` is `created_at` plus 10 minutes. |
| `consent_user_id`, `consent_approved` | uuid null, boolean null | The consent decision for this request and the user who made it. Check: both null or both set. |
| `dpop_key_thumbprint` | text, null | The request's `dpop_jkt` (D27), or the key of the DPoP proof at `/par` (D40). Check: null or 43 characters. Heimdall copies it to the code. |
| `prompt_none` | boolean | `prompt=none`. A pushed request needs it, because `/authorize` does not see the parameters again. |
| `force_consent` | boolean | `prompt=consent`: the user decides on the consent page, also for a client that does not require consent. |
| `request_uri_hash` | bytea, null | The SHA-256 of the `request_uri` of a pushed request (D41). **Unique with `tenant_id`** where not null. `/authorize` clears it when it takes the request (D42). |

Heimdall deletes the row in the same transaction that inserts the code. If two requests resume the same row, the second `DELETE` matches no row, and that transaction rolls back. One stored request gives one code.

### `authorization_codes`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk`, `user_id` | uuid | |
| `code_hash` | bytea | **Unique with `tenant_id`.** |
| `redirect_uri` | text | For the exact-match check at `/token`. |
| `scope` | text | The approved scope. |
| `code_challenge` | text | |
| `nonce`, `auth_time` | | For the ID token. |
| `family_id` | uuid, null | Set at redemption. This is the link from a code to its family. Foreign key with `ON DELETE SET NULL`, added with the `token_families` table. |
| `created_at`, `expires_at` | timestamptz | `expires_at` is `created_at` plus 5 minutes. |
| `redeemed_at` | timestamptz, null | |
| `dpop_key_thumbprint` | text, null | From the request's `dpop_jkt` (D27). When set, only a DPoP proof from this key redeems the code. Check: null or 43 characters. |
| `sid` | char(22), null | The `sid` of the session that issued the code (D29). The family copies it at redemption. It has no foreign key, because a code can outlive its session row. Null only for a code from before the column existed. |

### `token_families`
The family is its own table. Reasons:
1. A family revocation is one update on one row.
2. The idle and absolute lifetimes belong to the family, not to one token.
3. The audit log and alerts can refer to one ID.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | This value is `TokenFamilyId`. |
| `tenant_id`, `client_pk`, `user_id` | uuid | |
| `source_code_id` | uuid | The code that started the family. Audit reference only. It has no foreign key (see "Purge job"). |
| `scope` | text | The scope at the start. Refresh can only reduce it. |
| `created_at` | timestamptz | |
| `absolute_expires_at` | timestamptz | Fixed at creation. Rotation does not change it. |
| `idle_expires_at` | timestamptz | Moves forward at each rotation. It never passes `absolute_expires_at`. |
| `revoked_at` | timestamptz, null | |
| `revoked_reason` | text, null | `reuse_detected`, `user_logout`, `admin`, `user_disabled`, `consent_removed`. |
| `dpop_key_thumbprint` | text, null | The DPoP key of a public client's family (D24). When set, each rotation needs a proof from this key. Check: null or 43 characters. |
| `sid` | char(22), null | The `sid` of the session that signed the user in (D29). A sign-out revokes every family with this value (D33). Index `(tenant_id, sid)` where not null. No foreign key, because the purge job deletes the session first. |

Each access token from a user grant carries the family ID in the `fid` claim (D29). The value is opaque and authenticates nothing.

### `refresh_tokens`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `family_id` | uuid | Composite foreign key to `token_families`. |
| `token_hash` | bytea | **Unique with `tenant_id`.** |
| `created_at` | timestamptz | |
| `used_at` | timestamptz, null | Set when the client rotates the token. |
| `replaced_by_id` | uuid, null | Foreign key to the next token. This replaces the `ReplacedByTokenHash` column of the first draft. A foreign key gives referential integrity, and the hash is not stored twice. |

A token is valid when `used_at IS NULL` and its family is not revoked or expired. Only the newest token of a family can have `used_at IS NULL`.

### `sessions`
| Column | Type | Note |
|---|---|---|
| `id_hash` | bytea PK | The hash of the session ID in the cookie (D12). |
| `sid` | char(22) | The public session ID (D29): 128 random bits, separate from the cookie secret. **Unique with `tenant_id`.** The ID token carries it as the `sid` claim. |
| `tenant_id`, `user_id` | uuid | |
| `created_at`, `last_seen_at` | timestamptz | |
| `auth_time` | timestamptz | For `max_age`. |
| `absolute_expires_at` | timestamptz | |
| `revoked_at` | timestamptz, null | |

The idle limit is `last_seen_at` plus the tenant's `session_idle_seconds`. Heimdall updates `last_seen_at` at most once a minute, so a session check is not a write on each request. The idle limit can therefore be up to one minute late.

### `backchannel_logouts`
The outbox of back-channel logouts (D34, D35). The sign-out transaction inserts one row for each client that gets a `logout_token`. The delivery job deletes the row after a success, or after the last retry.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `client_pk` | uuid | Composite foreign key to `clients`, with `ON DELETE CASCADE`. |
| `user_id` | uuid | The `sub` of the logout token. No foreign key: the row only names the user. |
| `sid` | char(22) | The `sid` of the logout token (D29). Check: 22 characters. |
| `created_at` | timestamptz | The purge job removes a row that is older than one day. |
| `attempts` | integer | The deliveries that a job started. Check: not negative. |
| `next_attempt_at` | timestamptz | When the next delivery may start. A job that takes a row moves it forward, as a lease. |

### `consents`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id`, `user_id`, `client_pk` | uuid | **Unique together.** |
| `scope` | text | |
| `granted_at` | timestamptz | |
| `revoked_at` | timestamptz, null | A revoked consent is kept as evidence (repudiation). |

### `signing_keys`
D19: each tenant has its own keys.

| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid | |
| `kid` | text | **Unique with `tenant_id`.** |
| `algorithm` | text | Check: `RS256`. |
| `public_jwk` | jsonb | |
| `private_key_ref` | text | A Key Vault or KMS reference. For local development, a `devfile:` reference to an entry in the development key file. Never a plain key. |
| `status` | text | `pending`, `active`, `retired`. |
| `published_at` | timestamptz | When the key enters the JWKS. |
| `signing_from` | timestamptz | At least one JWKS cache lifetime after `published_at`. |
| `retired_at`, `remove_after` | timestamptz, null | `remove_after` is the last signed token's expiry plus clock skew. |

Rules: a tenant has at most one `active` key and at most one `pending` key. A key is in the JWKS when it is `pending` and published, `active`, or `retired` and before `remove_after`.

Each status change is one conditional statement: `UPDATE signing_keys SET status = @new WHERE id = @id AND status = @old`. EF Core writes it, because `status` is a concurrency token. When two servers change the same key, the second update matches no row. That server changes nothing and writes no audit event. The unique index covers the other case, where two servers activate two different keys.

### `audit_events`
| Column | Type | Note |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid, null | Null for platform events. |
| `occurred_at` | timestamptz | |
| `type` | text | For example `code.redeemed`, `code.reuse_detected`, `family.revoked`. |
| `actor_user_id`, `subject_user_id`, `client_pk`, `family_id` | uuid, null | |
| `source_ip` | inet | |
| `correlation_id` | text | |
| `data` | jsonb | Old and new values for configuration changes. Never secrets (D7). |

The application database role has `INSERT` and `SELECT` on this table. It has no `UPDATE` or `DELETE`. A separate role purges old rows.

This table has no row-level security, because platform events have no tenant. A query that reads it must filter by `tenant_id` itself. Today no application path reads it. The audit viewer of the admin portal (Phase 3) must filter by tenant, or the table must get a policy first.

How the application writes it (group commit): `BatchingAuditLog` keeps one queue for each server. A request adds its event and waits until a committed transaction holds it. So a response never leaves before its audit row is durable. One writer drains the queue. All events that wait go into one transaction, with up to 256 events in each. With no load, each transaction holds one event, and no timer adds a delay. Under load, events collect during each commit, so the transactions grow. When a transaction fails, the writer writes each event alone, so one bad event fails only its own request. The metric `heimdall.audit.batch_size` shows the size of each transaction.

## The atomic statements

These statements are the core of the security design. Each one is a single SQL command. A check in application code, followed by an update, is not allowed.

**Redeem a code** (`/token`, `authorization_code`). The application creates `@family_id` and inserts the family in the same transaction.
```sql
UPDATE authorization_codes
SET    redeemed_at = @now, family_id = @family_id
WHERE  tenant_id = @tenant AND code_hash = @hash
  AND  client_pk = @client AND redirect_uri = @redirect_uri
  AND  code_challenge = @challenge          -- BASE64URL(SHA256(code_verifier))
  AND  (dpop_key_thumbprint IS NULL OR dpop_key_thumbprint = @dpop_key)   -- D27
  AND  redeemed_at IS NULL AND expires_at > @now
RETURNING *;
```
Every binding is in the `WHERE` clause. A code is consumed only by the right client, with the right redirect URI, PKCE verifier, and DPoP key. A request with a stolen code and no verifier, or without the key that `dpop_jkt` named, matches no row, so it cannot burn the code for the real client. `@dpop_key` is the key of the request's proof, or null. `@now` comes from the application clock, so every time rule uses one clock. The foreign key from `family_id` to `token_families` is `DEFERRABLE INITIALLY DEFERRED`, because this statement sets `family_id` before the family row exists. PostgreSQL checks it at commit.

The transaction also signs the tokens. If no key can sign, the transaction rolls back and the code stays usable.

One row means success. Zero rows means: unknown, expired, reused, or a binding that does not match. Then the application reads the row by hash, outside the transaction. If `redeemed_at` is set, it is a reuse. Heimdall revokes `family_id` of that row, writes an audit event, and raises an alert. A second request waits on the row lock of the first. It sees the committed `family_id`, so the revocation reaches the right family.

**Rotate a refresh token** (`/token`, `refresh_token`).
```sql
UPDATE refresh_tokens AS t
SET    used_at = @now
FROM   token_families AS f
WHERE  t.tenant_id = @tenant AND t.token_hash = @hash AND t.used_at IS NULL
  AND  f.tenant_id = t.tenant_id AND f.id = t.family_id
  AND  f.client_pk = @client AND f.revoked_at IS NULL
  AND  f.idle_expires_at > @now AND f.absolute_expires_at > @now
  AND  (f.dpop_key_thumbprint IS NULL OR f.dpop_key_thumbprint = @dpop_key)   -- D24
RETURNING t.*;
```
The family conditions are in the statement, like the bindings of the code redemption. A token sent by another client, or without the DPoP key of a bound family, matches no row and cannot burn the real client's token. A refused request (wider scope, disabled user) rolls back, so the token stays unused.
Zero rows and a row that exists with `used_at` set is a reuse. Heimdall then runs:
```sql
UPDATE token_families
SET    revoked_at = now(), revoked_reason = 'reuse_detected'
WHERE  id = @family_id AND revoked_at IS NULL;
```
After a successful rotation, the application checks that the user is active and that the scope is not wider. It inserts the new token, sets `replaced_by_id`, and moves `idle_expires_at` to `LEAST(@now + idle, absolute_expires_at)`. All of this runs in one transaction. A disabled user gets `invalid_grant`, and Heimdall revokes the family with the reason `user_disabled`.

**Revoke a family** (`/revoke`, logout, admin) is the second statement above with another `revoked_reason`. The statement is idempotent. `/revoke` uses the reason `user_logout`.

**Take a pushed request** (`/authorize` with `request_uri`, D42).
```sql
UPDATE authorization_requests
SET    request_uri_hash = NULL, expires_at = @now + interval '10 minutes'
WHERE  tenant_id = @tenant AND request_uri_hash = @hash
  AND  client_pk = @client AND expires_at > @now
RETURNING *;
```
The client condition is in the statement, so a `request_uri` sent with another `client_id` does not use up the request. A concurrent second use waits on the row lock, then finds the hash cleared and matches no row.

**Sign in again** (`/session/v1/login`, D13). The user already has a live session in the browser's session list. One statement replaces the key of the row:
```sql
UPDATE sessions
SET    id_hash = @new_hash, auth_time = @now, last_seen_at = @now, absolute_expires_at = @now + @absolute
WHERE  tenant_id = @tenant AND id_hash = @old_hash AND revoked_at IS NULL;
```
One row means success. The old session ID stops working at once, and the `sid` stays. Zero rows means that a sign-out ended the session first. Then the sign-in starts a new session with a new `sid`.

**End a session** (`/oauth/v1/logout`, `/session/v1/logout`, D33). Three statements in one transaction:
```sql
UPDATE sessions SET revoked_at = @now
WHERE  tenant_id = @tenant AND id_hash = @hash AND revoked_at IS NULL;

UPDATE token_families SET revoked_at = @now, revoked_reason = 'user_logout'
WHERE  tenant_id = @tenant AND sid = @sid AND revoked_at IS NULL
RETURNING id, client_pk, user_id;

INSERT INTO backchannel_logouts (id, tenant_id, client_pk, user_id, sid, created_at, attempts, next_attempt_at)
SELECT gen_random_uuid(), f.tenant_id, f.client_pk, f.user_id, f.sid, @now, 0, @now
FROM   (SELECT DISTINCT tenant_id, client_pk, user_id, sid
        FROM token_families WHERE tenant_id = @tenant AND sid = @sid) AS f
JOIN   clients AS c ON c.tenant_id = f.tenant_id AND c.id = f.client_pk
WHERE  c.backchannel_logout_uri IS NOT NULL
RETURNING client_pk;
```
**Deliver a back-channel logout** (`BackchannelLogoutDelivery`, D35). A pass takes the due rows in one statement:
```sql
UPDATE backchannel_logouts
SET    attempts = attempts + 1, next_attempt_at = @now + @lease
WHERE  id IN (
    SELECT id FROM backchannel_logouts
    WHERE  next_attempt_at <= @now
    ORDER  BY next_attempt_at
    LIMIT  @batch
    FOR UPDATE SKIP LOCKED)
RETURNING *;
```
The attempt counts before the call. The lease (4 call time limits) keeps the row away from other servers during the call. After a success, the pass deletes the row. After a failure, it sets `next_attempt_at` to `@now + 30 s × 2^(attempts − 1)`. After the fifth retry fails, it deletes the row and writes the audit event `backchannel_logout.dropped`. A server that stops during a call leaves the row, and the lease brings it back. So a client can get two logout tokens for one sign-out. Each has its own `jti` and names the same session.

The first statement of "End a session" is the lock. When two sign-outs of one session run together, the second waits on the row, then matches no row. Then it stops, so it revokes nothing and queues nothing twice. The insert also includes families that a reuse revoked earlier, because their client can still hold a session of its own. A redeemed code always has a family, so the insert needs no read of `authorization_codes`.

## Indexes

| Table | Index | Reason |
|---|---|---|
| `authorization_codes` | unique `(tenant_id, code_hash)` | The redemption lookup and the single-use guarantee. |
| `authorization_codes` | `(expires_at)` | The purge job. |
| `refresh_tokens` | unique `(tenant_id, token_hash)` | The rotation lookup. |
| `refresh_tokens` | `(family_id)` | Revocation and the purge job. |
| `token_families` | `(user_id)`, `(client_pk)` | Revoke all families for a user or a client. |
| `sessions` | `(user_id)` | End all sessions of a user. |
| `users` | unique `(tenant_id, email_normalized)` | Sign-in lookup. |
| `clients` | unique `(tenant_id, client_id)` | Client lookup. |
| `audit_events` | `(tenant_id, occurred_at)`, `(family_id)` | Investigation. |

## What the database enforces and what the application enforces

| Rule | Database | Application |
|---|---|---|
| A code redeems only once | Unique hash and the conditional `UPDATE` | Handles the zero-row result. |
| Tenant isolation | Composite foreign keys. Row-level security is planned (see below). | EF Core global query filter. With no tenant set, no rows match. |
| Public clients cannot use `client_credentials` | `CHECK` | Domain rule in `Client.Create` |
| A `client_credentials` client has an audience | `CHECK` | Domain rule in `Client.Create` (D22) |
| A secret belongs to a client of the same tenant | Composite foreign key `(tenant_id, client_pk)` | |
| A private key reference holds no key material | `CHECK` | Domain rule in `SigningKey.Create` |
| Setting values inside the hard bounds | `CHECK` | Platform limits from configuration (D16) |
| At most two valid secrets for a client | | Admin use case |
| One `active` signing key for each tenant | Partial unique index on `(tenant_id) WHERE status = 'active'` | Key rotation use case |
| One `pending` signing key for each tenant | Partial unique index `ux_signing_keys_one_pending` on `(tenant_id) WHERE status = 'pending'` | Two servers cannot both create the next key |
| Audit events cannot change | Role rights (planned) | No update or delete code path |
| PKCE `S256`, `RS256` only (D17) | No column for the method. `algorithm` is `NOT NULL` with `CHECK (algorithm = 'RS256')`. `NOT NULL` matters, because a `CHECK` passes on `NULL`. | |

The platform limits (minimum and maximum for each setting) live in configuration and are checked by the application. The database `CHECK` constraints hold only the outer bounds. They are the last defense if the application has a bug. They are wide on purpose, so a change in the limits does not need a migration.

## Implementation status

The first migration (`InitialCreate`) creates `tenants`, `clients`, `client_secrets`, `signing_keys`, and `audit_events`, with the constraints and indexes above. Integration tests in `tests/Heimdall.IntegrationTests` check the constraints against PostgreSQL with raw SQL.

Later migrations add `users`, `sessions`, `authorization_requests`, `authorization_codes`, `token_families`, and `refresh_tokens`. Later migrations also add the consent decision columns and the purge indexes. Not built yet: `consents`, row-level security, and the role rights on `audit_events`.

## Row-level security (D20)

The migration `EnableRowLevelSecurity` turns on row-level security for the nine tenant-owned tables: `users`, `sessions`, `authorization_requests`, `authorization_codes`, `token_families`, `refresh_tokens`, `clients`, `client_secrets`, and `signing_keys`.

- Each table has the policy `tenant_isolation`. A row is visible and writable only when `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`. Without a value, no row matches (fail closed).
- Each table has `FORCE ROW LEVEL SECURITY`, so the table owner is bound too. A superuser still bypasses every policy.
- The policy `platform_access` lets members of the role `heimdall_platform` see every row. Only the platform jobs use it: the key job's tenant list and the purge job (`PlatformDbContextFactory`).
- The migration creates two group roles that cannot log in: `heimdall_app` and `heimdall_platform`. An operator creates the login roles of each environment and grants one group role to each.
- `heimdall_app` has `SELECT`, `INSERT`, `UPDATE`, and `DELETE` on `tenants` and the tenant-owned tables. On `audit_events`, it has `SELECT` and `INSERT` only, so the application cannot change or delete the audit log.
- A new tenant-owned table needs the same grants and policies in its migration.

How the application sets the tenant: `TenantConnectionInterceptor` runs `set_config('app.tenant_id', @tenant, false)` each time EF Core opens a connection. The value comes from the `TenantScope` of the database context. A context with no tenant sets an empty value.

This replaces the first plan, `SET LOCAL` in each transaction. EF Core runs most commands outside an explicit transaction, so `SET LOCAL` would need a transaction around every command. The risk that `SET LOCAL` avoids is a value that stays on a pooled connection and leaks to the next request. Heimdall prevents that leak in two ways. Each open sets the value again, and Npgsql resets the session state when a connection returns to the pool. A test turns the Npgsql reset off and checks that the interceptor alone prevents the leak. The cost is one extra round trip for each connection open.

Measured on 2026-10-22 (#15), as connection opens on the request path, after the audit writer took audit inserts off that path (#16): `/token` 0 or 1, `/userinfo` 1, `/authorize` with a session 2, `/revoke` 3, sign-in 5. `DatabaseRoundTripTests` holds these numbers as a budget. One connection for each request was considered and not chosen. The high-volume endpoints already open at most one connection, so they would gain nothing. A held connection would also stay idle during slow work that is not database work: the Argon2id hash at sign-in, and a key store call when Key Vault signs (Phase 4). Instead, `/authorize` stores the request only when it must show a page, and session validation reads the session and its user in one query.

Configuration: `ConnectionStrings:Heimdall` is the application login (a member of `heimdall_app`). `ConnectionStrings:HeimdallPlatform` is the platform login (a member of `heimdall_platform`). Without `HeimdallPlatform`, the platform jobs use `Heimdall`. That works only when the login is a superuser, as in local development. The migrations run as the owner, not as either login.

## Purge job

A background service (`PurgeJob`, `DataPurger`) deletes old rows in batches. It runs every hour. It deletes at most 1000 rows in each statement and repeats until no rows remain. Batches keep transactions short, so the job does not block `/token`. The values are in configuration (`Heimdall:Purge`).

```sql
DELETE FROM token_families
WHERE id IN (
    SELECT id FROM token_families
    WHERE  idle_expires_at < @now - @family_retention
       OR  revoked_at < @now - @family_retention
    LIMIT  @batch
    FOR UPDATE SKIP LOCKED);
```

The check constraint `idle_expires_at <= absolute_expires_at` makes `idle_expires_at` the end of an unrevoked family. So the statement needs no `LEAST`, and an index on each column serves it. The application sends `@now` from its clock, so tests can control the time.

`SKIP LOCKED` lets two instances of the job run together without waiting for each other.

Indexes for the job: `token_families (idle_expires_at)`, `token_families (revoked_at) WHERE revoked_at IS NOT NULL`, `authorization_codes (expires_at) WHERE family_id IS NULL`, `sessions (absolute_expires_at)`, `sessions (revoked_at) WHERE revoked_at IS NOT NULL`, and `authorization_requests (expires_at)`.

| Table | Delete when | Reason for the delay |
|---|---|---|
| `token_families` (and its `refresh_tokens`, by `ON DELETE CASCADE`) | The family ended more than 7 days ago | A reused token from a recent family must still cause a revocation and an alert. The delay also helps an investigation. |
| `authorization_codes` | `expires_at` is more than 24 hours ago, and the code has no family | A replayed code must still show as `redeemed` for a short time after expiry. |
| `authorization_requests` | `expires_at` has passed | |
| `login_throttles` | No failure for 24 hours, and no wait is running | The row would start again at zero anyway. |
| `dpop_proofs` | `expires_at` has passed | None. After that time the proof fails the `iat` check anyway. |
| `client_assertions` | `expires_at` has passed | None. After that time the assertion fails the `exp` check anyway. |
| `backchannel_logouts` | `created_at` is more than one day ago | The delivery job deletes each row within an hour. This rule removes the rows of a server where the job did not run. |
| `sessions` | `absolute_expires_at` or `revoked_at` is more than 7 days ago | A session that ended by its idle timeout stays until this time. The idle timeout is a tenant setting, so this rule keeps the statement on one table. |

Order: delete families first, then codes. `authorization_codes.family_id` has `ON DELETE SET NULL`, so a code survives its family for the 24-hour delay. `token_families.source_code_id` is a plain column with no foreign key. It is an audit reference only. This avoids a circular foreign key between the two tables.

`audit_events` is not part of this job. A separate role purges it, under a retention policy that is not set yet.

## Decisions on the first open questions

| Question | Decision | Note |
|---|---|---|
| Format of `sub` | UUIDv7 | A UUIDv7 holds its creation time, so `sub` shows when the account was created. This risk is low. If it matters later, the pairwise subject identifiers of Phase 3 remove it. |
| Local signing keys | A JSON file in `.local/`, ignored by git | Development only. See below. |
| Retention of expired data | Batch purge | See "Purge job". |

### Local development signing keys

The file `.local/signing-keys.json` holds the development keys. Rules:
- `.gitignore` excludes `.local/`.
- Heimdall reads this file only when the environment is `Development`. In any other environment, the server does not start, because no other key store exists yet.
- The file store rejects a reference without the `devfile:` prefix. A Key Vault or KMS reference never falls back to a file key.
- `seed-dev` creates the first key of the development tenant. The store creates the file when it writes the first key.
- The file holds plain PKCS#8 keys. On Unix, Heimdall creates the folder with mode 0700 and the file with mode 0600. A FAT or NTFS drive ignores these modes.
- A real key never goes into the repository, a chat, or a log. The development keys are not trusted outside the local machine.
- `IKeyMaterialStore` in `Application` hides the source. It creates a key and signs data. The private key never leaves the store. Key Vault or KMS replaces the file on deployment, with no change to the signing code.
