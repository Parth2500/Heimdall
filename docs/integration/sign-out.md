# Sign out

[Documentation home](../documentation.md)

Sign-out has three parts. Heimdall supports all three.

| Part | What ends | How |
|---|---|---|
| Your app's session | The user's session in your app. | Your app ends it. |
| The Heimdall session | The session of one account at Heimdall, for every app on this browser. A browser can hold several accounts. Your sign-out ends only the account of your ID token. | Send the browser to the `end_session_endpoint` (RP-Initiated Logout 1.0). |
| The tokens of that sign-in | Every refresh token family of the Heimdall session, for every app. | Heimdall revokes them when the session ends. |

A sign-out at Heimdall also tells the servers of the other apps in the session, if they registered a `backchannel_logout_uri` (Back-Channel Logout 1.0).

## Step 1: End your app's session

Delete your app's session and the tokens that it holds. In a browser app, clear the tokens from memory. Keep the ID token for step 2.

## Step 2: Send the browser to Heimdall

Read `end_session_endpoint` from discovery. Then send the browser there:

```http
GET /oauth/v1/logout?id_token_hint=eyJhbGciOiJSUzI1NiIs...
    &post_logout_redirect_uri=https%3A%2F%2Forders.example.com%2Fsigned-out
    &state=af0ifjsldkj HTTP/1.1
Host: acme.example.com
```

| Parameter | Required | Notes |
|---|---|---|
| `id_token_hint` | Recommended | The ID token of this sign-in. An expired ID token is valid here. Heimdall checks its signature, `iss`, and `aud`. |
| `client_id` | No | Your `client_id`. Use it when you have no ID token. When you send both, it must equal the `aud` of the ID token. |
| `post_logout_redirect_uri` | No | Where Heimdall sends the browser after the sign-out. It must be in your registered list, by exact match. |
| `state` | No | Heimdall returns it unchanged. At most 512 characters. |

`POST` with a form body works too. Each parameter can appear only once.

### What Heimdall does

| Request | Result |
|---|---|
| An ID token of this browser's current session | Heimdall ends the session at once. Then it sends the browser to your URI with `state`. |
| No ID token, or an ID token of an older session | Heimdall asks the user: "Sign out of Heimdall?". The session ends only when the user clicks "Sign out". Then the browser goes to your URI. |
| No Heimdall session in the browser | Nothing to end. The browser goes to your URI at once. |
| A URI that is not registered for your client, or no client | Heimdall shows its own "You are signed out" page and redirects nowhere. |
| A `client_id` that differs from the ID token's `aud`, a `state` over 512 characters, or a repeated parameter | Heimdall shows its error page, ends nothing, and redirects nowhere. |

Why the confirmation: another site can send a browser to this endpoint. Without the ID token of the current session, Heimdall cannot know that the request comes from an app of that session. A click on a Heimdall page proves that the user wants to sign out (logout CSRF).

### What ends

- The Heimdall session of that account. The next sign-in asks for the password. Heimdall's account picker still shows the account as "Signed out", until the user removes it.
- Every refresh token family of that session, for every app, also with `offline_access`. A refresh then gets `invalid_grant`. This is stricter than Back-Channel Logout 1.0, section 2.7, which keeps `offline_access` tokens.
- Access tokens stay valid until `exp` (5 minutes by default) for a resource server that checks them offline. Heimdall cannot recall a JWT. Heimdall's `/userinfo` refuses them at once. A resource server that uses introspection sees the sign-out at once (see [Validate access tokens](validate-access-tokens.md#revocation-and-logout)).

## Step 3 (optional): Revoke the refresh token first

If your app has a refresh token, you can revoke it at `/revoke` before step 2. This ends your family even when the user does not confirm the sign-out at Heimdall.

```http
POST /oauth/v1/revoke HTTP/1.1
Host: acme.example.com
Content-Type: application/x-www-form-urlencoded

token=8xLOxBtZp8...
&client_id=orders-web
```

A confidential client sends HTTP Basic instead of `client_id`. Revocation ends the whole family. Heimdall returns `200` for every well-formed request from an authenticated client, and it does not tell you if the token existed (RFC 7009).

## Receive a back-channel logout

Register a `backchannel_logout_uri` on your server. When the user signs out of Heimdall from any app, Heimdall sends:

```http
POST /backchannel-logout HTTP/1.1
Host: orders.example.com
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiIsInR5cCI6ImxvZ291dCtqd3QifQ...
```

The `logout_token` is a JWT:

```json
{
  "iss": "https://acme.example.com",
  "sub": "0190f1e2-3a4b-7c5d-8e9f-a0b1c2d3e4f5",
  "aud": "orders-web",
  "iat": 1792603478,
  "exp": 1792603598,
  "jti": "5a1c0b5e8f3a4d7e9b2c6f1a0d3e8b47",
  "sid": "Qm9vazEyMzQ1Njc4OTAxMg",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
}
```

Check it before you act on it:

1. The header has `alg` `RS256`, `typ` `logout+jwt`, and a `kid` from the JWKS. Check the signature.
2. `iss` is the issuer, and `aud` is your `client_id`.
3. `iat` is recent, and `exp` has not passed. The token lives 2 minutes.
4. `events` has the back-channel logout event, and the token has no `nonce`. So no ID token can pass as a logout token.
5. You have not seen this `jti` before. Keep each `jti` until its `exp`.

Then end every session of your app with this `sid`. The ID token of each sign-in has the same `sid` claim, so store it with your session. Answer `200`. Heimdall reads no response body.

Delivery rules:

- Heimdall sends the call from a background job, a few seconds after the sign-out. The user's sign-out never waits for your server.
- One call has a 5-second limit. Heimdall follows no redirect.
- After a failure, Heimdall tries again after 30 seconds, then 1, 2, 4, and 8 minutes. After the fifth retry fails, it stops and writes an audit event.
- You can get the same sign-out twice, with two `jti` values. Ending a session that already ended must do nothing.
- Your endpoint must use `https` on a public address. Heimdall refuses loopback, private, and link-local addresses, except in Development.

## Register the URIs

The operator registers these values for your client, with the rules of a redirect URI (absolute, `https`, plain `http` only for a loopback address, no fragment, no wildcard):

- `post_logout_redirect_uris`: a list. Matching is by exact string.
- `backchannel_logout_uri`: one URI, or none.

## Library support

- `oidc-client-ts` and `angular-auth-oidc-client`: `signoutRedirect()` and `logoff()` read `end_session_endpoint` and send `id_token_hint`.
- ASP.NET Core: `SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme)` sends the browser to `end_session_endpoint` with `id_token_hint`, when `SaveTokens` is on. See [the ASP.NET Core recipe](recipes/aspnet-core.md).
- `openid-client` (Node.js): `buildEndSessionUrl(config, { id_token_hint, post_logout_redirect_uri, state })`. See [the Node.js recipe](recipes/node-server.md).
