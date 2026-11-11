using System.Text.Json;
using System.Text.Json.Serialization;
using Heimdall.Api.Hosting;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Application.Logout;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Sessions;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Features;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// The login API for the Angular login page, on the tenant origin (D21). It sets the session cookie (D11 to D13).
/// </summary>
/// <remarks>
/// CSRF defense has three layers. (1) An antiforgery double-submit token: the page reads <see cref="XsrfCookie"/>
/// and sends it in <see cref="XsrfHeader"/>, as Angular's HttpClient does. (2) JSON bodies only: a cross-site HTML form
/// cannot send JSON, and a cross-site script that sends JSON needs a CORS preflight, which Heimdall never allows.
/// (3) The Origin header, when the browser sends one, must be the tenant's own origin.
/// </remarks>
internal static partial class SessionEndpoints
{
    public const string Prefix = "/session/v1";

    /// <summary>D11: <c>__Host-</c> means Secure, Path=/, and no Domain, so no subdomain can set or read it.</summary>
    public const string SessionCookie = "__Host-Heimdall.Session";

    /// <summary>The antiforgery request token. Readable by the page script, by design of the double-submit pattern.</summary>
    public const string XsrfCookie = "__Host-XSRF-TOKEN";

    public const string XsrfHeader = "X-XSRF-TOKEN";

    /// <summary>The antiforgery cookie token. HttpOnly. The framework compares it with the request token.</summary>
    public const string AntiforgeryCookie = "__Host-Heimdall.Antiforgery";

    private const long MaxBodyBytes = 4 * 1024;

    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static void Map(WebApplication app)
    {
        // The metadata describes the handlers for the OpenAPI document (#22). The handlers read their bodies themselves,
        // so the framework cannot infer the shapes.
        var group = app.MapGroup(Prefix).WithTags("Session");
        group.MapGet("/csrf", Csrf)
            .WithSummary("Sets the antiforgery cookies. Call it before any POST.")
            .Produces(StatusCodes.Status204NoContent);
        group.MapPost("/login", LoginAsync).RequireRateLimiting(RateLimits.LoginPolicy)
            .WithSummary("Signs the user in and sets the session cookie.")
            .Accepts<LoginBody>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorBody>(StatusCodes.Status403Forbidden)
            .Produces<ErrorBody>(StatusCodes.Status409Conflict)
            .Produces<ErrorBody>(StatusCodes.Status415UnsupportedMediaType)
            .Produces(StatusCodes.Status429TooManyRequests)
            .Produces<ErrorBody>(StatusCodes.Status503ServiceUnavailable);
        group.MapPost("/logout", LogoutAsync)
            .WithSummary("Ends one account of this browser, or every account (D33). The answer names where the page sends the browser.")
            .Accepts<LogoutBody>("application/json")
            .Produces<LogoutResultBody>()
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status403Forbidden);
        group.MapGet("/me", MeAsync)
            .WithSummary("Returns the signed-in user.")
            .Produces<MeBody>()
            .Produces<ErrorBody>(StatusCodes.Status401Unauthorized);
        group.MapGet("/accounts", AccountsAsync)
            .WithSummary("Returns the accounts of this browser, for the account picker. With request_id, also what the stored request names.")
            .Produces<AccountsBody>();
        group.MapPost("/select", SelectAsync)
            .WithSummary("Records the account that the user chose for a stored request. The page then calls /oauth/v1/authorize/resume.")
            .Accepts<SelectBody>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status403Forbidden)
            .Produces<ErrorBody>(StatusCodes.Status415UnsupportedMediaType);
        group.MapPost("/forget", ForgetAsync)
            .WithSummary("Removes one signed-out account from this browser.")
            .Accepts<ForgetBody>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status403Forbidden)
            .Produces<ErrorBody>(StatusCodes.Status415UnsupportedMediaType);
        group.MapGet("/consent", ConsentPromptAsync)
            .WithSummary("Returns what the consent page shows for a stored request.")
            .Produces<ConsentPromptBody>()
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status401Unauthorized);
        group.MapPost("/consent", ConsentDecisionAsync)
            .WithSummary("Records the user's decision for a stored request. The page then calls /oauth/v1/authorize/resume.")
            .Accepts<ConsentBody>("application/json")
            .Produces(StatusCodes.Status204NoContent)
            .Produces<ErrorBody>(StatusCodes.Status400BadRequest)
            .Produces<ErrorBody>(StatusCodes.Status401Unauthorized)
            .Produces<ErrorBody>(StatusCodes.Status403Forbidden)
            .Produces<ErrorBody>(StatusCodes.Status415UnsupportedMediaType);
    }

    /// <summary>Issues the antiforgery tokens. The page calls it before the login form.</summary>
    private static IResult Csrf(HttpContext context, IAntiforgery antiforgery)
    {
        OAuthResponses.NoStore(context.Response);
        var tokens = antiforgery.GetAndStoreTokens(context);
        context.Response.Cookies.Append(XsrfCookie, tokens.RequestToken!, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
        });
        return Results.NoContent();
    }

    private static async Task<IResult> LoginAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        SessionService sessions,
        HeimdallMetrics metrics,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        if (await RefuseBrowserRequestAsync(context, antiforgery, logger).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        LoginBody? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<LoginBody>(Json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
        {
            LogRefused(logger, "malformed or oversized body");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        SignInResult result;
        try
        {
            result = await sessions.SignInAsync(
                TenantResolutionMiddleware.GetRequestContext(context),
                body?.Email,
                body?.Password,
                context.Request.Cookies[SessionCookie],
                context.RequestAborted).ConfigureAwait(false);
        }
        catch (PasswordHasherBusyException)
        {
            metrics.LoginAttempt("busy");
            context.Response.Headers.RetryAfter = "5";
            return Error(StatusCodes.Status503ServiceUnavailable, "temporarily_unavailable");
        }

        metrics.LoginAttempt(result.Succeeded ? "success" : result.ListFull ? "limit" : "failure");
        if (result.ListFull)
        {
            // The credentials were right, so this answer shows nothing that the caller did not prove.
            return Error(StatusCodes.Status409Conflict, "session_limit");
        }

        if (!result.Succeeded)
        {
            // One answer for an unknown email, a wrong password, and a disabled account.
            return Error(StatusCodes.Status401Unauthorized, "invalid_credentials");
        }

        context.Response.Cookies.Append(SessionCookie, result.Cookie!, SessionCookieOptions());
        return Results.NoContent();
    }

    /// <summary>
    /// The confirm button of the sign-out page (D31). It ends the session as <c>/oauth/v1/logout</c> does (D33). The body
    /// may carry the sealed <c>logout_request</c> of the page (U17). The answer names where the page sends the browser:
    /// a registered post-logout redirect URI, or Heimdall's signed-out page.
    /// </summary>
    private static async Task<IResult> LogoutAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        LogoutService logout,
        LogoutRequestProtector protector,
        Microsoft.Extensions.Options.IOptions<UiOptions> ui,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        // Logout needs the same CSRF checks: a cross-site page must not be able to sign the user out.
        if (await RefuseBrowserRequestAsync(context, antiforgery, logger, requireJson: false).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        LogoutBody? body = null;
        if (context.Request.HasJsonContentType())
        {
            try
            {
                body = await context.Request.ReadFromJsonAsync<LogoutBody>(Json, context.RequestAborted).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
            {
                LogRefused(logger, "malformed or oversized body");
                return Error(StatusCodes.Status400BadRequest, "invalid_request");
            }
        }

        var requestContext = TenantResolutionMiddleware.GetRequestContext(context);

        // A sealed value that does not open (changed, expired, or from another tenant) only loses the redirect.
        var target = protector.Unprotect(requestContext.Tenant.Id, body?.LogoutRequest);
        // A sid of the wrong form names no session. It must not turn into "every account".
        if (body?.Sid is { } sid && !SessionSid.IsValid(sid))
        {
            LogRefused(logger, "sid malformed");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        var outcome = await logout.ConfirmAsync(requestContext, context.Request.Cookies[SessionCookie], target, body?.Sid, context.RequestAborted)
            .ConfigureAwait(false);

        // The cookie stays: an ended session ID authenticates nothing, and the picker shows the account as "Signed out"
        // until the user forgets it (D55).
        var location = outcome is LogoutRedirect redirect ? LogoutEndpoint.RedirectLocation(redirect) : LogoutEndpoint.SignedOutLocation(ui.Value);
        return Results.Json(new LogoutResultBody(location), Json);
    }

    /// <summary>Who is signed in, for the page. Same origin only: Heimdall sends no CORS headers.</summary>
    private static async Task<IResult> MeAsync(HttpContext context, SessionService sessions)
    {
        OAuthResponses.NoStore(context.Response);
        var valid = await sessions.ValidateAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Cookies[SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        return valid is null
            ? Error(StatusCodes.Status401Unauthorized, "no_session")
            : Results.Json(
                new MeBody(valid.User.Id.ToString(), valid.User.Email, valid.Session.AuthTime.ToUnixTimeSeconds()),
                Json);
    }

    /// <summary>
    /// The accounts of this browser, for the account picker and the sign-in page (D55). Same origin only: Heimdall sends
    /// no CORS headers, so no other site can read the list.
    /// </summary>
    private static async Task<IResult> AccountsAsync(HttpContext context, AuthorizationService authorization)
    {
        OAuthResponses.NoStore(context.Response);
        var requestId = context.Request.Query["request_id"];
        var list = await authorization.ListAccountsAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            requestId.Count == 1 ? requestId.ToString() : null,
            context.Request.Cookies[SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        return Results.Json(
            new AccountsBody(
                [.. list.Accounts.Select(a => new AccountBody(a.Sid, a.Email, a.SignedIn ? "signed_in" : "signed_out"))],
                list.Accounts.Count(a => a.SignedIn) < SessionList.MaxSessions,
                list.ClientName,
                list.LoginHint,
                list.SignInSid),
            Json);
    }

    /// <summary>
    /// Records the account that the user chose on the account picker (D52). The same CSRF checks as login apply: a
    /// cross-site page must not choose the account.
    /// </summary>
    private static async Task<IResult> SelectAsync(HttpContext context, IAntiforgery antiforgery, AuthorizationService authorization, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        if (await RefuseBrowserRequestAsync(context, antiforgery, logger).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        SelectBody? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<SelectBody>(Json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
        {
            LogRefused(logger, "malformed or oversized body");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        var result = await authorization.SelectAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            body?.RequestId,
            context.Request.Cookies[SessionCookie],
            body?.Sid,
            context.RequestAborted).ConfigureAwait(false);
        if (!result.IsSuccess)
        {
            // The reason goes to the log only (D5).
            LogRefused(logger, result.Error.AuditDetail);
            return Error(StatusCodes.Status400BadRequest, result.Error.Code);
        }

        return Results.NoContent();
    }

    /// <summary>Removes one signed-out account from the browser's session list ("Forget", D55).</summary>
    private static async Task<IResult> ForgetAsync(HttpContext context, IAntiforgery antiforgery, SessionService sessions, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        if (await RefuseBrowserRequestAsync(context, antiforgery, logger).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        ForgetBody? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<ForgetBody>(Json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
        {
            LogRefused(logger, "malformed or oversized body");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        var cookie = await sessions.ForgetAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Cookies[SessionCookie],
            body?.Sid,
            context.RequestAborted).ConfigureAwait(false);
        if (cookie is null)
        {
            LogRefused(logger, "no signed-out account with this sid");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        if (cookie.Length == 0)
        {
            context.Response.Cookies.Delete(SessionCookie, SessionCookieOptions());
        }
        else
        {
            context.Response.Cookies.Append(SessionCookie, cookie, SessionCookieOptions());
        }

        return Results.NoContent();
    }

    /// <summary>What the consent page shows for a stored request. Same origin only: Heimdall sends no CORS headers.</summary>
    private static async Task<IResult> ConsentPromptAsync(HttpContext context, ConsentService consent, ILoggerFactory loggers)
    {
        OAuthResponses.NoStore(context.Response);
        var requestId = context.Request.Query["request_id"];
        var result = await consent.GetPromptAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            requestId.Count == 1 ? requestId.ToString() : null,
            context.Request.Cookies[SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        if (!result.IsSuccess)
        {
            return ConsentError(result.Error, loggers.CreateLogger(typeof(SessionEndpoints)));
        }

        var prompt = result.Value;
        return Results.Json(new ConsentPromptBody(prompt.ClientId, prompt.ClientName, prompt.Scopes, prompt.RedirectHost), Json);
    }

    /// <summary>
    /// Records the user's decision. The page then sends the browser to <c>/oauth/v1/authorize/resume</c>, which issues the
    /// code or the <c>access_denied</c> error. The same CSRF checks as login apply: a cross-site page must not approve.
    /// </summary>
    private static async Task<IResult> ConsentDecisionAsync(HttpContext context, IAntiforgery antiforgery, ConsentService consent, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(SessionEndpoints));
        OAuthResponses.NoStore(context.Response);

        if (await RefuseBrowserRequestAsync(context, antiforgery, logger).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        ConsentBody? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<ConsentBody>(Json, context.RequestAborted).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException)
        {
            LogRefused(logger, "malformed or oversized body");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        if (body?.Approve is not { } approve)
        {
            LogRefused(logger, "consent decision missing");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        var result = await consent.DecideAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            body.RequestId,
            context.Request.Cookies[SessionCookie],
            approve,
            context.RequestAborted).ConfigureAwait(false);

        return result.IsSuccess ? Results.NoContent() : ConsentError(result.Error, logger);
    }

    // The reason goes to the log only (D5).
    private static IResult ConsentError(OAuthError error, ILogger logger)
    {
        LogRefused(logger, error.AuditDetail);
        return error.Code == ConsentService.LoginRequiredCode
            ? Error(StatusCodes.Status401Unauthorized, error.Code)
            : Error(StatusCodes.Status400BadRequest, error.Code);
    }

    internal static CookieOptions SessionCookieOptions() => new()
    {
        HttpOnly = true,
        Secure = true,

        // Lax, not Strict: a client sends the user to /authorize by a cross-site top-level navigation (D11).
        SameSite = SameSiteMode.Lax,
        Path = "/",

        // No Expires: the cookie ends with the browser. The server enforces the idle and absolute limits.
    };

    /// <summary>The CSRF checks for a state-changing browser request. Returns the refusal, or null to continue.</summary>
    private static async Task<IResult?> RefuseBrowserRequestAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        ILogger logger,
        bool requireJson = true)
    {
        var request = context.Request;
        var expectedOrigin = TenantResolutionMiddleware.GetRequestContext(context).Issuer;
        var origin = request.Headers.Origin.ToString();
        if (origin.Length > 0 && !string.Equals(origin, expectedOrigin, StringComparison.Ordinal))
        {
            LogRefused(logger, "foreign Origin");
            return Error(StatusCodes.Status403Forbidden, "invalid_request");
        }

        if (requireJson && !request.HasJsonContentType())
        {
            LogRefused(logger, "not JSON");
            return Error(StatusCodes.Status415UnsupportedMediaType, "invalid_request");
        }

        if (request.ContentLength is > MaxBodyBytes)
        {
            LogRefused(logger, "body too large");
            return Error(StatusCodes.Status400BadRequest, "invalid_request");
        }

        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } sizeFeature)
        {
            sizeFeature.MaxRequestBodySize = MaxBodyBytes;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            LogRefused(logger, "antiforgery token missing or wrong");
            return Error(StatusCodes.Status403Forbidden, "invalid_request");
        }

        return null;
    }

    private static IResult Error(int status, string code) => Results.Json(new ErrorBody(code), Json, statusCode: status);

    [LoggerMessage(Level = LogLevel.Information, Message = "Session request refused: {Reason}.")]
    private static partial void LogRefused(ILogger logger, string reason);

    private sealed record LoginBody(
        [property: JsonPropertyName("email")] string? Email,
        [property: JsonPropertyName("password")] string? Password);

    private sealed record MeBody(
        [property: JsonPropertyName("sub")] string Sub,
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("auth_time")] long AuthTime);

    private sealed record ConsentBody(
        [property: JsonPropertyName("request_id")] string? RequestId,
        [property: JsonPropertyName("approve")] bool? Approve);

    private sealed record ConsentPromptBody(
        [property: JsonPropertyName("client_id")] string ClientId,
        [property: JsonPropertyName("client_name")] string ClientName,
        [property: JsonPropertyName("scopes")] IReadOnlyList<string> Scopes,
        [property: JsonPropertyName("redirect_host")] string RedirectHost);

    private sealed record LogoutBody(
        [property: JsonPropertyName("logout_request")] string? LogoutRequest,
        [property: JsonPropertyName("sid")] string? Sid);

    private sealed record SelectBody(
        [property: JsonPropertyName("request_id")] string? RequestId,
        [property: JsonPropertyName("sid")] string? Sid);

    private sealed record ForgetBody([property: JsonPropertyName("sid")] string? Sid);

    private sealed record AccountBody(
        [property: JsonPropertyName("sid")] string Sid,
        [property: JsonPropertyName("email")] string Email,
        [property: JsonPropertyName("state")] string State);

    private sealed record AccountsBody(
        [property: JsonPropertyName("accounts")] IReadOnlyList<AccountBody> Accounts,
        [property: JsonPropertyName("can_add")] bool CanAdd,
        [property: JsonPropertyName("client_name")] string? ClientName,
        [property: JsonPropertyName("login_hint")] string? LoginHint,
        [property: JsonPropertyName("sign_in_sid")] string? SignInSid);

    private sealed record LogoutResultBody([property: JsonPropertyName("redirect_to")] string RedirectTo);

    private sealed record ErrorBody([property: JsonPropertyName("error")] string Error);
}
