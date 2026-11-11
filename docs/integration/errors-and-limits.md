# Errors and rate limits

[Documentation home](../documentation.md)

## Error format

Heimdall uses the error codes of the RFCs. An error body has the `error` member only:

```json
{ "error": "invalid_grant" }
```

Heimdall never sends `error_description`. A detailed reason would help an attacker, for example to learn if a code exists. Heimdall writes the reason to its audit log. If you need the reason, give the operator the time of the request and your `client_id`.

Each response has an `X-Correlation-ID` header. Give it to the operator too. It points to the exact log entries.

## Authorization errors

These errors come back to your `redirect_uri` as query parameters, with `state` and `iss`.

| `error` | Cause | Action |
|---|---|---|
| `invalid_request` | A parameter is missing or wrong: `code_challenge`, `code_challenge_method` is not `S256`, a `response_mode` other than `query`, an unsupported or repeated `prompt` value, `prompt=none` with another value, a bad `max_age`, a `state` or `nonce` over 512 characters, or a malformed `dpop_jkt`. | Fix the request. |
| `unsupported_response_type` | `response_type` is not `code`. | Use `code`. |
| `invalid_scope` | `scope` is missing, malformed, or has a scope that your client does not have. Or it has `offline_access` without the `refresh_token` grant. | Ask only for registered scopes. |
| `unauthorized_client` | Your client does not have the `authorization_code` grant. | Ask the operator. |
| `request_not_supported` | You sent `request`. | Remove it. |
| `invalid_request` (error page) | The `request_uri` is unknown, used, expired, or was pushed by another client. | Push the request again, then use the new `request_uri` within 60 seconds, once. See [Pushed authorization requests](par.md). |
| `access_denied` | The user refused consent. | Show a message. Do not retry at once. |
| `login_required` | `prompt=none` and the user has no valid Heimdall session. With `login_hint` or `id_token_hint`: that user has no valid session in this browser. | Send the user to `/authorize` without `prompt=none`. |
| `account_selection_required` | `prompt=none`, the browser holds several accounts, and your request has no hint. | Send `id_token_hint` or `login_hint` with `prompt=none`. Or send the user to `/authorize` without `prompt=none`. |
| `consent_required` | `prompt=none` and your client needs consent. | Send the user to `/authorize` without `prompt=none`. |

### Errors on a Heimdall page

If `client_id` or `redirect_uri` is wrong, Heimdall shows its own error page and does not redirect. This also happens for a repeated parameter and for a suspended tenant. See [Sign in users](sign-in-users.md#when-heimdall-does-not-redirect-back).

## Token and revocation errors

| Status | `error` | Cause | Action |
|---|---|---|---|
| `400` | `invalid_request` | A malformed request: a query string, a body that is not `application/x-www-form-urlencoded`, a `charset` other than `utf-8`, a body over 16 KiB, a NUL character, a repeated parameter, `client_secret` in the body, a `client_id` that differs from the Basic header, or a missing parameter. | Fix the request. |
| `401` | `invalid_client` | Client authentication failed. The client is unknown, disabled, or the secret is wrong. | Check the client ID and secret, and the Basic encoding. |
| `400` | `invalid_grant` | The code or refresh token is unknown, expired, used, or revoked. Or the `code_verifier` or `redirect_uri` does not match. Or the user is disabled. | Sign the user in again. Do not retry with the same code or token. |
| `400` | `unauthorized_client` | Your client does not have this grant. | Ask the operator. |
| `400` | `unsupported_grant_type` | `grant_type` is not one of the three supported values. | Fix `grant_type`. |
| `400` | `invalid_scope` | A scope is not registered for your client, or it is wider than the original grant, or it is a user scope in `client_credentials`. | Fix `scope`. |
| `400` | `invalid_dpop_proof` | The DPoP proof is missing where it is required, malformed, too old, for another URL, or already used. Or the request has two `DPoP` headers. | Make a new proof and retry once. See [DPoP](dpop.md#errors). |
| `400` | `invalid_target` | The `resource` is not registered for your client. Or you left it out and your client has more than one audience. | Send a registered `resource`. |
| `429` | `temporarily_unavailable` | Rate limit. | Wait for `Retry-After` seconds. |

## Userinfo errors

| Status | `error` | Cause |
|---|---|---|
| `400` | `invalid_request` | The access token is in the query string. Send it in the `Authorization` header. |
| `401` | None | No token. The response has `WWW-Authenticate: Bearer, DPoP algs="ES256 RS256"`. |
| `401` | `invalid_token` | The token is malformed, expired, for another audience, or for a disabled user. Or a bound token came with the `Bearer` scheme, or an unbound token with the `DPoP` scheme. |
| `401` | `invalid_dpop_proof` | A bound token came without a valid, unused proof from its key, for this request and this token. See [DPoP](dpop.md#errors). |
| `403` | `insufficient_scope` | The token has no `openid` scope. |

## Rate limits

Heimdall limits requests to protect itself. A refused request gets `429`, a `Retry-After` header in seconds, and the error `temporarily_unavailable`.

| Limit | Default | Counts |
|---|---|---|
| `/authorize` | 120 each minute for each IP address | Every request. |
| Login | 5 each minute for each IP address | Every sign-in attempt. |
| `/token` and `/revoke` failures | 60 each minute for each IP address | Failed requests only. Normal traffic does not count. |
| `/token` issuance | 300 each minute for each client | Successful token responses only. |

The operator can change these values. The counters are on each Heimdall server, so the real limit can be higher. Do not depend on the exact numbers.

Heimdall also slows down repeated failed sign-ins for one account. It never locks the account. The login page handles this case. Your app sees nothing.

### How to stay under the limits

- Cache `client_credentials` tokens until they are close to expiry.
- Do not refresh a token that is still valid for a long time.
- Respect `Retry-After`. Do not retry in a tight loop.
- Fix `invalid_client` errors at once. Failed requests from one IP address use up a shared budget. When the budget is gone, every request from that IP gets `429`, even with the right secret.
