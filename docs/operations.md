# Operations runbook

This runbook is for the operator of a Heimdall deployment. It covers the database roles, migrations, signing keys, the background jobs, and every configuration section. The security reasons are in the [threat model](threat-model.md). The tables and statements are in the [schema design](schema-design.md).

## Parts of a deployment

| Part | Purpose |
|---|---|
| Server image (`docker build -t heimdall .`) | The API and the account pages. It listens on port 8080 over plain HTTP. |
| Migration image (`docker build -t heimdall-migrate --target migrate .`) | The EF Core migration bundle. It runs once for each release. |
| PostgreSQL | All state. The servers keep only caches. |
| Reverse proxy | It ends TLS and passes the original `Host` header. Heimdall refuses plain HTTP from a client (D1). |

The image is chiseled. It has no shell and no package manager. The server runs as uid 1654. Configuration comes from environment variables, for example `ConnectionStrings__Heimdall`.

## Known limits before production

- **No production key store.** Outside Development, the server does not start until a Key Vault or KMS key store exists (#34). The development key file holds plain private keys.
- **The Data Protection key ring is local to each server.** The antiforgery tokens of the session API and the sealed `logout_request` (U17) use ASP.NET Core Data Protection. With more than one server, a token from one server fails at another server. A restart can also make the outstanding tokens fail. The user then sees a refused sign-in or a sign-out without its redirect, and must try again. Share the key ring before you run more than one server (#68).
- **Rate limits are counted for each server.** With N servers, a caller gets up to N times each limit. The sign-in throttle for each account is in the database, so it is exact.

## Database roles and logins

The migrations create two group roles. Neither role can log in.

| Role | Rights | Used by |
|---|---|---|
| `heimdall_app` | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `tenants` and the tenant-owned tables. `SELECT` and `INSERT` only on `audit_events`. Row-level security limits each request to its tenant. | Every request (`ConnectionStrings:Heimdall`). |
| `heimdall_platform` | Sees the rows of every tenant (policy `platform_access`). | The key job's tenant list and the purge job (`ConnectionStrings:HeimdallPlatform`). |

Create one login for each group role in each environment:

```sql
CREATE ROLE heimdall_app_login LOGIN PASSWORD '<password>' IN ROLE heimdall_app;
CREATE ROLE heimdall_platform_login LOGIN PASSWORD '<password>' IN ROLE heimdall_platform;
```

Rules:

- The migrations run as the database owner. Never give the owner login to a server.
- Never use a superuser login for a server. A superuser bypasses row-level security.
- Without `ConnectionStrings:HeimdallPlatform`, the platform jobs use `ConnectionStrings:Heimdall`. This works only for a superuser, as in local development.
- Keep the passwords in the platform's secret store. Never put them in an appsettings file.

## Migrations

The server never applies migrations. For each release:

1. Back up the database.
2. Run the bundle with the owner connection string:
   ```
   docker run --rm heimdall-migrate --connection "<owner connection string>"
   ```
3. Start the new servers.

During a rolling update, the old servers run against the new schema for a short time. Write each migration so that the previous server version still works with it. Add a column or a table in one release. Remove the old one in a later release.

A new tenant-owned table needs the grants and the row-level security policies in its migration. A test (`RowLevelSecurityTests`) fails the build when a tenant-owned table has no policy.

## Signing keys

Each tenant has its own keys. The key job (`SigningKeyJob`) runs on every server and does the rotation without an operator:

1. It creates the next key one publish wait before the active key reaches its rotation interval (90 days by default).
2. The new key is in the JWKS for one publish wait before it signs. The publish wait is the JWKS cache lifetime plus the server cache lifetime (10 plus 1 minutes by default).
3. The new key then signs. The old key stays in the JWKS until its last token has expired, plus the clock skew.

A tenant has at most one pending key, so two servers cannot create two next keys.

### Emergency key removal

Use this procedure only when a private key is stolen or exposed.

1. Find the `kid` of the key. It is in the JWT header and in the JWKS.
2. Run the command with the application connection string:
   ```
   docker run --rm -e ConnectionStrings__Heimdall="<connection string>" heimdall remove-key <tenant host> <kid>
   ```
   Locally: `dotnet run --project src/Heimdall.Api -- remove-key <tenant host> <kid>`.
3. The key leaves the JWKS at once. Tokens that the key signed stop working at Heimdall. Resource servers refuse them when their JWKS cache expires (10 minutes by default).
4. Heimdall activates a ready next key, or it creates a new key. Token issuance stops until the new key is active, at most one publish wait.
5. Another server can sign with the removed key for one server cache lifetime (1 minute by default). Restart all servers if you cannot accept this gap.
6. Find out how the key was exposed before you close the incident.

## Background jobs

Every server runs the three jobs. They are safe to run on many servers at the same time.

| Job | What it does | How servers share the work |
|---|---|---|
| `SigningKeyJob` | Creates, activates, and retires signing keys. | One pending key for each tenant, and `status` is a concurrency token. |
| `PurgeJob` | Deletes expired and ended rows in batches: codes, token families with their refresh tokens, sessions, stored requests, DPoP proofs, client assertions, throttle rows, back-channel logout rows. | `FOR UPDATE SKIP LOCKED`: two servers never wait for the same rows. |
| `BackchannelLogoutJob` | Sends the signed `logout_token` to each client after a sign-out (D35). | A server takes rows with a lease. A crashed server's rows come back after the lease. |

`Heimdall:Jobs:Enabled = false` stops all three loops. Use it only for a test host or for a server that must not change keys.

## Health, telemetry, and proxies

- `/health/live` answers when the process runs. `/health/ready` answers when the database answers. The body is one word, `Healthy` or `Unhealthy`.
- Set `Heimdall:Health:Port` to a management port. The probes then answer only on that port. Do not publish that port to the internet.
- Set `OTEL_EXPORTER_OTLP_ENDPOINT` to send OpenTelemetry traces and metrics to a collector. Without it, Heimdall sends nothing. Heimdall's meter is `Heimdall`. Watch `heimdall.security.alerts`: each alert is a code reuse or a refresh token reuse. A person must look at each one.
- Behind a proxy, list it in `Heimdall:ForwardedHeaders`. Without that, every request seems to come from the proxy, and the rate limits for each IP block everyone together. Heimdall never reads `X-Forwarded-Host`.

## Configuration reference

All durations use the .NET format `d.hh:mm:ss`, for example `00:10:00` for 10 minutes. A value that is not valid stops the server at startup.

### Connection strings

| Key | Default | Meaning |
|---|---|---|
| `ConnectionStrings:Heimdall` | None. Required. | The application login, a member of `heimdall_app`. |
| `ConnectionStrings:HeimdallPlatform` | `ConnectionStrings:Heimdall` | The platform login, a member of `heimdall_platform`. |

### `Heimdall:Issuer`

| Key | Default | Meaning |
|---|---|---|
| `Port` | None (443) | The public port, when it is not 443. The scheme is always `https`, and the host is the tenant's host (D21). |

### `Heimdall:SigningKeys`

| Key | Default | Meaning |
|---|---|---|
| `JwksCacheLifetime` | 10 minutes | The `max-age` of the JWKS. |
| `ServerCacheLifetime` | 1 minute | How long one server keeps a tenant's keys in memory. |
| `ActivationCheckInterval` | 30 seconds | How often the key job runs. |
| `RotationInterval` | 90 days | How long a key signs before the next key replaces it. |
| `ClockSkew` | 5 minutes | The extra time that a retired key stays in the JWKS after its last token. |
| `DevelopmentKeyFile` | `.local/signing-keys.json` | Development only. The file of plain private keys, relative to the server folder. |

### `Heimdall:PlatformLimits`

The smallest and largest value that a tenant or a client may set (D16). Each entry has `Min` and `Max`.

| Key | Default |
|---|---|
| `SessionIdle` | 5 minutes to 24 hours |
| `SessionAbsolute` | 1 hour to 30 days |
| `AccessToken` | 1 minute to 60 minutes |
| `RefreshIdle` | 1 hour to 30 days |
| `RefreshAbsolute` | 1 day to 90 days |

### `Heimdall:PasswordHashing`

| Key | Default | Meaning |
|---|---|---|
| `MemoryKiB` | 65536 (64 MiB) | Argon2id memory for one hash. |
| `Iterations` | 3 | Argon2id passes over the memory. |
| `MaxConcurrentHashes` | The number of processors | Hashes that run at the same time. Each one holds `MemoryKiB`. |
| `MaxQueueWait` | 5 seconds | The wait for a free slot. After it, the sign-in gets `503` with `Retry-After`. |

Size the server memory for `MemoryKiB` times `MaxConcurrentHashes`, plus the rest of the server.

### `Heimdall:LoginThrottle`

| Key | Default | Meaning |
|---|---|---|
| `FreeFailures` | 5 | Failures in a row for one account and source that cost no wait. |
| `MaxDelay` | 15 minutes | The longest wait. The wait doubles with each failure after the free ones. |
| `ResetAfter` | 24 hours | A source with no failure for this long starts again from zero. |

### `Heimdall:RateLimits`

Each entry has `PermitLimit` and `Window` (1 minute by default). The counters are for each server.

| Key | Default `PermitLimit` | Counts |
|---|---|---|
| `Login` | 5 | Sign-in attempts for each IP. |
| `Authorize` | 120 | `/authorize` requests for each IP. |
| `ClientFailures` | 60 | Failed `/token` and `/revoke` requests for each IP. |
| `ClientIssuance` | 300 | Successful token issuances for each client. |

### `Heimdall:Purge`

| Key | Default | Meaning |
|---|---|---|
| `Interval` | 1 hour | How often the purge job runs. |
| `BatchSize` | 1000 | The most rows that one statement deletes. |
| `FamilyRetention` | 7 days | How long an ended token family stays. A reused token of a recent family must still revoke and alert. |
| `CodeRetention` | 24 hours | How long an expired code with no family stays. |
| `SessionRetention` | 7 days | How long an ended session stays, for an investigation. |
| `BackchannelLogoutRetention` | 1 day | The longest time that a back-channel logout row may stay. |

### `Heimdall:BackchannelLogout`

| Key | Default | Meaning |
|---|---|---|
| `Interval` | 5 seconds | How often the job looks for due rows. |
| `Timeout` | 5 seconds | The time limit of one call (D35). |
| `MaxRetries` | 5 | Retries after the first call. After the last failure, the row is dropped. |
| `FirstRetryDelay` | 30 seconds | The wait before the first retry. Each later wait is twice as long. |
| `BatchSize` | 16 | The most rows that one pass sends at the same time. |
| `BlockPrivateAddresses` | `true` | Refuse loopback, private, and link-local addresses (D35). Development sets it to `false`. |

### `Heimdall:ForwardedHeaders`

| Key | Default | Meaning |
|---|---|---|
| `KnownProxies` | Empty | Proxy addresses, for example `10.0.0.5`. |
| `KnownNetworks` | Empty | Proxy networks in CIDR form, for example `10.0.0.0/24`. |

With both empty, Heimdall reads no forwarded header. Heimdall trusts one hop only.

### `Heimdall:Health`

| Key | Default | Meaning |
|---|---|---|
| `Port` | None (every port) | The management port for the probes. |

### `Heimdall:Jobs`

| Key | Default | Meaning |
|---|---|---|
| `Enabled` | `true` | Runs the loops of the three background jobs. |

### `Heimdall:Ui`

The paths of the account pages. Keep the defaults unless the pages move.

| Key | Default |
|---|---|
| `LoginPath` | `/account/login` |
| `ConsentPath` | `/account/consent` |
| `SelectAccountPath` | `/account/select-account` |
| `ErrorPath` | `/account/error` |
| `LogoutPath` | `/account/logout` |
| `SignedOutPath` | `/account/signed-out` |
| `AccountDirectory` | `wwwroot/account`, relative to the server folder. The image puts the built account pages there. |

### Other settings

| Key | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The OpenTelemetry collector. Without it, Heimdall sends no telemetry. |
| `ASPNETCORE_ENVIRONMENT` | `Development` allows the development key file, `seed-dev`, and the OpenAPI document. Never set it in production. |
| `Logging:LogLevel` | The standard .NET log levels. Logs are JSON outside Development. Heimdall never logs a secret, a code, or a token (D7). |
