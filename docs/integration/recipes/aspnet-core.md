# Recipe: ASP.NET Core

[Documentation home](../../documentation.md)

> **Status: the OpenID Connect part is tested.** Heimdall's integration tests run the Microsoft OpenID Connect handler against Heimdall: sign-in with and without PAR, the saved refresh token, and RP-initiated logout (`AspNetCoreOidcInteropTests`). The JWT bearer part is not tested yet. Test it before you depend on it, and report any change that it needs.

This recipe connects an ASP.NET Core server app to Heimdall as a confidential client. It uses `Microsoft.AspNetCore.Authentication.OpenIdConnect`.

To protect an API with Heimdall access tokens, see the `JwtBearer` example in [Validate access tokens](../validate-access-tokens.md#aspnet-core-with-jwtbearer).

## Registration

| Setting | Value |
|---|---|
| Client type | Confidential |
| Grants | `authorization_code` |
| Redirect URI | `https://app.example.com/signin-oidc` (the handler's default `CallbackPath`) |
| Scopes | `openid email` |

## Four defaults to check

Three of the handler's defaults do not match Heimdall. Each one makes the sign-in fail. The fourth default works with Heimdall.

| Default | Problem | Fix |
|---|---|---|
| `ResponseMode = "form_post"` | Heimdall supports `query` only. It refuses `form_post` with `invalid_request`. | Set `ResponseMode = "query"`. |
| `PushedAuthorizationBehavior` (.NET 9 and later) | The default, `UseIfAvailable`, pushes the request to `/oauth/v1/par`, because discovery lists it. This works, and the interop tests cover it. | Keep the default. Use `Require` when the operator sets `require_pushed_authorization_requests`. |
| The client secret goes in the form body (`client_secret_post`) | Heimdall supports `client_secret_basic` and `private_key_jwt`, not `client_secret_post`. It refuses a secret in the body with `invalid_request`. | Remove the secret from the body, and send it in the `Authorization` header from a backchannel handler. |
| `MapInboundClaims = true` | The handler renames `sub` and other claims. | Set `MapInboundClaims = false`. |

## Configuration

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var clientId = builder.Configuration["Heimdall:ClientId"]!;
var clientSecret = builder.Configuration["Heimdall:ClientSecret"]!;

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
    })
    .AddOpenIdConnect(options =>
    {
        options.Authority = "https://acme.example.com";
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;

        options.ResponseType = "code";
        options.ResponseMode = "query";
        options.UsePkce = true;

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("email");

        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "sub";
        options.TokenValidationParameters.ValidAlgorithms = ["RS256"];

        // The ID token has no email. The handler reads it from /userinfo.
        options.GetClaimsFromUserInfoEndpoint = true;
        options.ClaimActions.MapUniqueJsonKey("email", "email");

        // Take the secret out of the form body. The handler below sends it as HTTP Basic.
        options.Events.OnAuthorizationCodeReceived = context =>
        {
            context.TokenEndpointRequest!.ClientSecret = null;
            return Task.CompletedTask;
        };

        options.BackchannelHttpHandler = new HeimdallBasicAuthHandler(clientId, clientSecret)
        {
            InnerHandler = new HttpClientHandler(),
        };
    });
```

The handler that adds the `Authorization` header:

```csharp
using System.Net.Http.Headers;
using System.Text;

/// <summary>Sends the client secret to the token endpoint as HTTP Basic (client_secret_basic), never in the body.</summary>
sealed class HeimdallBasicAuthHandler(string clientId, string clientSecret) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath == "/oauth/v1/token")
        {
            // RFC 6749, section 2.3.1: form-urlencode the ID and the secret, join them with a colon, then base64-encode.
            var credentials = $"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(clientSecret)}";
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }

        return base.SendAsync(request, cancellationToken);
    }
}
```

The handler sends its own request headers. It does not change the shared `HttpClient`, so concurrent sign-ins are safe.

This part is the least certain. Test that the token request has an `Authorization: Basic` header and no `client_secret` in the body.

## What the handler checks for you

With this configuration, the handler checks `state`, the PKCE redemption, the ID token signature, `iss`, `aud`, `exp`, and `nonce`. We have not confirmed that it checks the `iss` parameter in the authorization response (RFC 9207). If your app trusts more than one identity provider, check it yourself in `OnMessageReceived`.

## Sign out

Sign out of both schemes. The OpenID Connect handler reads `end_session_endpoint` from discovery and sends the browser there with `id_token_hint`, because `SaveTokens` keeps the ID token. Register `SignedOutCallbackPath` (`/signout-callback-oidc` by default) as a post-logout redirect URI.

```csharp
app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
}).RequireAuthorization();
```

Use `POST` with antiforgery for your own `/logout`, so another site cannot sign your users out of your app. See [Sign out](../sign-out.md) for what Heimdall ends.
