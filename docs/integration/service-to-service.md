# Service-to-service tokens

[Documentation home](../documentation.md)

Use the `client_credentials` grant when a service calls an API for itself, with no user. Examples are a nightly job or one backend that calls another.

## Requirements

- A confidential client with the `client_credentials` grant. It authenticates with a client secret (the Basic header below) or with a private key ([Authenticate with a private key](private-key-jwt.md)).
- At least one registered audience: the API that the service calls.
- The API scopes that the service needs, for example `orders.read`.

## Request a token

```http
POST /oauth/v1/token HTTP/1.1
Host: acme.example.com
Authorization: Basic b3JkZXJzLWpvYjpzM2NyM3Q=
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=orders.read
&resource=https%3A%2F%2Fapi.orders.example.com
```

| Parameter | Required | Value |
|---|---|---|
| `grant_type` | Yes | `client_credentials` |
| `scope` | No | API scopes. If you leave it out, Heimdall issues every scope that is registered for your client. |
| `resource` | If your client has more than one audience | The audience of the token. |

Rules:

- Authenticate with HTTP Basic or with a private key. A public client cannot use this grant.
- Do not ask for user scopes: `openid`, `profile`, `email`, `address`, `phone`, or `offline_access`. There is no user, so Heimdall refuses them with `invalid_scope`.
- Each scope must be registered for your client. Heimdall refuses the whole request if one scope is not. It does not reduce the scope.

## The response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "orders.read"
}
```

There is no refresh token and no ID token. When the access token expires, request a new one with the same call.

## Cache the token

Reuse the access token until it is close to `expires_in`. Do not request a new token for each API call. Heimdall limits each client to 300 issued tokens each minute on each server by default. A service that requests a token for each call reaches this limit.

A simple rule: request a new token when less than 30 seconds of its lifetime remain.

## The token

The access token has `sub` equal to your `client_id`. It has no `auth_time`, because no user signed in. A resource server can use this to tell a service token from a user token. See [Validate access tokens](validate-access-tokens.md#user-tokens-and-service-tokens).
