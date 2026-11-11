# Sign in users

[Documentation home](../documentation.md)

Heimdall signs users in with the authorization code flow and PKCE (RFC 6749, RFC 7636, OAuth 2.1). This is the only user flow. A good OpenID Connect library does most of these steps for you. This page tells you what the library must do, so you can check its settings.

## Overview

```mermaid
sequenceDiagram
    participant U as User's browser
    participant C as Your client
    participant H as Heimdall
    C->>C: Make code_verifier, state, nonce
    C->>U: Redirect to /oauth/v1/authorize
    U->>H: GET /oauth/v1/authorize?...code_challenge...
    H->>U: Login page (and consent page, if on)
    U->>H: Credentials
    H->>U: Redirect to redirect_uri?code=...&state=...&iss=...
    U->>C: GET redirect_uri?code=...&state=...&iss=...
    C->>C: Check state and iss
    C->>H: POST /oauth/v1/token (code, code_verifier)
    H->>C: access_token, id_token, refresh_token
    C->>C: Check the ID token and nonce
```

## Step 1: Read discovery

Get the discovery document from `<issuer>/.well-known/openid-configuration`. Take every endpoint URL from it. Do not build endpoint URLs by hand.

Cache the document. Heimdall sends `Cache-Control: max-age` (10 minutes by default) and an `ETag`.

## Step 2: Make the request values

For each sign-in, make three new random values. Keep them on your side until the callback.

| Value | How to make it | Purpose |
|---|---|---|
| `code_verifier` | 32 random bytes, base64url-encoded (43 characters). RFC 7636 allows 43 to 128 characters. | Proves at `/token` that you started this sign-in. |
| `state` | At least 128 random bits. | Binds the callback to the browser that started it. It stops cross-site request forgery. |
| `nonce` | At least 128 random bits. | Binds the ID token to this sign-in. It stops ID token replay. |

Calculate the challenge: `code_challenge = BASE64URL(SHA256(code_verifier))`.

Store the values where the callback can read them. A server app stores them in its session or in a short-lived, encrypted cookie. A browser app stores them in `sessionStorage`, because the page reloads at the callback.

## Step 3: Send the user to `/authorize`

Redirect the browser to the `authorization_endpoint` with these query parameters:

| Parameter | Required | Value |
|---|---|---|
| `response_type` | Yes | `code` |
| `client_id` | Yes | Your client ID. |
| `redirect_uri` | Yes, if you registered more than one | One of your registered URIs, exactly. Always send it. |
| `scope` | Yes | Space-separated. Include `openid` for an ID token. Each scope must be registered for your client. |
| `code_challenge` | Yes | From step 2. |
| `code_challenge_method` | Yes | `S256`. Heimdall refuses `plain` and a missing value. |
| `state` | Recommended | From step 2. At most 512 characters. |
| `nonce` | Recommended with `openid` | From step 2. At most 512 characters. |
| `prompt` | No | Space-separated. `login` makes the user sign in again. `consent` shows the consent page, also when your client does not require consent. `none` never shows a page and cannot be combined with another value. `select_account` shows the account picker, also when one account is signed in. |
| `login_hint` | No | The email address of the user that you expect. Heimdall uses that account when it is signed in. If not, the sign-in page shows the address. Heimdall never tells you whether the account exists. |
| `id_token_hint` | No | The last ID token that you got for the user. Send it with `prompt=none` to renew a sign-in. You then get that user or an error, never another account. |
| `max_age` | No | Seconds. If the user signed in longer ago, Heimdall asks again. |

One browser can hold several accounts of a tenant. With several accounts and no hint from you, Heimdall shows the account picker. With `prompt=none`, you get `account_selection_required` instead.

Heimdall refuses a request that repeats a parameter. Heimdall ignores parameters that it does not know.

Example:

```
GET /oauth/v1/authorize
  ?response_type=code
  &client_id=orders-web
  &redirect_uri=https%3A%2F%2Forders.example.com%2Fcallback
  &scope=openid%20email%20offline_access
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &state=af0ifjsldkj
  &nonce=n-0S6_WzA2Mj
Host: acme.example.com
```

### What the user sees

Heimdall shows its own login page. If your client has consent turned on, Heimdall then shows a consent page. Your app never sees the user's password.

If the user already has a valid Heimdall session, Heimdall skips the login page. The user goes straight back to your app.

### When Heimdall does not redirect back

Heimdall checks `client_id` and `redirect_uri` first. If either one is wrong, Heimdall shows its own error page. It never redirects to a URI that it has not matched, because that would be an open redirect.

You see this case during development as "the user is stuck on a Heimdall error page". Check that `client_id` and `redirect_uri` match the registration exactly.

## Step 4: Handle the callback

Heimdall redirects the browser to your `redirect_uri`. A success has these query parameters:

| Parameter | Value |
|---|---|
| `code` | The authorization code. It is valid for 5 minutes and for one use. |
| `state` | Your `state`, unchanged. |
| `iss` | The issuer (RFC 9207). |

An error has `error`, `state`, and `iss` instead of `code`. See [Errors and rate limits](errors-and-limits.md#authorization-errors).

Do these checks before you redeem the code:

1. **Check `state`.** It must equal the value that you stored for this browser. If it does not, stop.
2. **Check `iss`.** It must equal your issuer exactly. If it does not, stop. This check stops a mix-up attack when your app trusts more than one identity provider.
3. **Use the stored values once.** Delete `code_verifier`, `state`, and `nonce` from storage after the callback.

## Step 5: Redeem the code at `/token`

Send a `POST` to the `token_endpoint`. The body must be `application/x-www-form-urlencoded`.

A public client sends its `client_id` in the body:

```http
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Forders.example.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_id=orders-web
```

A confidential client authenticates with HTTP Basic and does not need `client_id` in the body:

```http
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Authorization: Basic b3JkZXJzLXdlYjpzM2NyM3Q=
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Forders.example.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Rules for the request:

- Send the same `redirect_uri` that you sent to `/authorize`. You can leave it out only if your client has one registered URI.
- Do not put parameters in the query string. Heimdall refuses it, because proxies and logs keep query strings.
- Do not send `client_secret` in the body. Heimdall supports `client_secret_basic` and `private_key_jwt`, not `client_secret_post`. See [Authenticate with a private key](private-key-jwt.md).
- For HTTP Basic, form-urlencode the client ID and secret first, then join them with `:`, then base64-encode the result (RFC 6749, section 2.3.1).

### Choose the audience

Add `resource=<audience>` to choose the audience of the access token (RFC 8707). If you leave it out, Heimdall picks:

| Your client's registered audiences | `resource` left out | `resource` sent |
|---|---|---|
| None | The userinfo endpoint. | Only the userinfo endpoint URL is allowed. |
| One | That audience. | That audience, or the userinfo endpoint URL. |
| More than one | `invalid_target`. You must send `resource`. | One of them, or the userinfo endpoint URL. |

One access token has one audience. If your app calls an API and also calls `/userinfo`, get the second access token with a refresh. Send a different `resource` each time. See [Refresh tokens](refresh-tokens.md).

### The response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6ImF0K2p3dCJ9...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid email offline_access",
  "refresh_token": "8xLOxBtZp8...",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6IkpXVCJ9..."
}
```

- `id_token` is present only when the scope has `openid`.
- `refresh_token` is present only when the scope has `offline_access` and your client has the `refresh_token` grant.
- Heimdall sends `Cache-Control: no-store`. Do not cache the response.

### If the code is used twice

A code works once. If anyone presents a used code again, Heimdall treats it as theft:

- The second caller gets `invalid_grant`.
- Heimdall revokes the family of refresh tokens that the first redemption issued. The refresh token of the first caller stops working.
- Heimdall raises a security alert.

Heimdall's `/userinfo` and introspection refuse the access token from the first redemption at once. A resource server that checks that token offline accepts it until it expires, because Heimdall cannot recall a JWT.

Do not retry a code redemption that may have succeeded. Start a new sign-in instead.

## Step 6: Check the ID token

Your library must check these items. Do not skip any of them.

| Check | Rule |
|---|---|
| Signature | RS256, with the key from the JWKS that `kid` names. Refuse every other `alg`, including `none`. |
| `typ` | `JWT`. An access token (`at+jwt`) is not an ID token. |
| `iss` | Equals your issuer exactly. |
| `aud` | Equals your `client_id`. |
| `exp` | Is in the future. |
| `nonce` | Equals the `nonce` that you stored for this sign-in. |
| `auth_time` | If you sent `max_age`, it is recent enough. |

The ID token has these claims: `iss`, `sub`, `aud`, `iat`, `exp`, `auth_time`, and `nonce` (if you sent one). It has no `email` claim. Get the email address from [`/userinfo`](endpoint-reference.md#get-or-post-oauthv1userinfo).

## Step 7: Start your own session

The ID token tells you who the user is. It is not a session. Create your app's own session and key it by (`iss`, `sub`).

A server app usually keeps no Heimdall token after this step. It needs Heimdall only to learn who the user is. The Huginn chat app works this way.

## Next steps

- Keep the user signed in: [Refresh tokens](refresh-tokens.md).
- Call your API: [Validate access tokens](validate-access-tokens.md).
- Sign the user out: [Sign out](sign-out.md).
