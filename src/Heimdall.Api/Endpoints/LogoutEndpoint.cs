using Heimdall.Api.Hosting;
using Heimdall.Application.Common;
using Heimdall.Application.Logout;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Endpoints;

/// <summary>
/// <c>GET</c> and <c>POST /oauth/v1/logout</c>, the <c>end_session_endpoint</c> (RP-Initiated Logout 1.0, D30 to D32).
/// The logic is in <see cref="LogoutService"/>. This class turns its outcome into a browser response.
/// </summary>
internal static partial class LogoutEndpoint
{
    public const string Path = "/oauth/v1/logout";

    /// <summary>The fixed value that tells the signed-out page that a sign-out just ran.</summary>
    public const string SignedOutMarker = "done";

    // A logout request has at most these parameters (RP-Initiated Logout 1.0, section 2), plus a few that Heimdall ignores.
    private const int MaxFormValues = 16;

    public static void Map(WebApplication app)
    {
        // The per-IP limit of /authorize: a flood of sign-outs costs a session lookup each.
        app.MapGet(Path, HandleAsync).RequireRateLimiting(RateLimits.AuthorizePolicy);
        app.MapPost(Path, HandleAsync).RequireRateLimiting(RateLimits.AuthorizePolicy).DisableAntiforgery();
    }

    private static async Task HandleAsync(
        HttpContext context,
        LogoutService logout,
        LogoutRequestProtector protector,
        IOptions<UiOptions> ui,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(LogoutEndpoint));
        var parameters = await ReadParametersAsync(context.Request).ConfigureAwait(false);
        var requestContext = TenantResolutionMiddleware.GetRequestContext(context);

        var outcome = parameters is null
            ? new LogoutErrorPage(OAuthError.InvalidRequestCode, "repeated or malformed parameter")
            : await logout.EndSessionAsync(requestContext, parameters, context.Request.Cookies[SessionEndpoints.SessionCookie], context.RequestAborted)
                .ConfigureAwait(false);

        Write(context, requestContext, outcome, protector, ui.Value, logger);
    }

    /// <summary>
    /// The query of a <c>GET</c>, or the form of a <c>POST</c>. Null when a parameter repeats or the form is malformed.
    /// </summary>
    private static async Task<Dictionary<string, string>?> ReadParametersAsync(HttpRequest request)
    {
        IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> values;
        if (HttpMethods.IsPost(request.Method))
        {
            if (!request.HasFormContentType || request.QueryString.HasValue)
            {
                return null;
            }

            try
            {
                values = await request.ReadFormAsync(request.HttpContext.RequestAborted).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is InvalidDataException or BadHttpRequestException or IOException)
            {
                return null;
            }
        }
        else
        {
            values = request.Query;
        }

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in values)
        {
            if (value.Count != 1 || parameters.Count == MaxFormValues)
            {
                return null;
            }

            parameters[name] = value.ToString();
        }

        return parameters;
    }

    private static void Write(
        HttpContext context,
        RequestContext requestContext,
        LogoutOutcome outcome,
        LogoutRequestProtector protector,
        UiOptions ui,
        ILogger logger)
    {
        var response = context.Response;
        OAuthResponses.NoStore(response);

        // The cookie stays in every case. After a sign-out it holds the ID of an ended session, which authenticates
        // nothing. The account picker shows that account as "Signed out" until the user forgets it (D55).
        response.StatusCode = StatusCodes.Status302Found;
        response.Headers.Location = outcome switch
        {
            LogoutRedirect redirect => RedirectLocation(redirect),
            LogoutConfirm { Target: { } target } => AuthorizeEndpoint.AppendQuery(ui.LogoutPath, [new("logout_request", protector.Protect(requestContext.Tenant.Id, target))]),
            LogoutConfirm => ui.LogoutPath,
            LogoutSignedOut => SignedOutLocation(ui),
            LogoutErrorPage page => ErrorLocation(page, ui, logger),
            _ => throw new InvalidOperationException($"Unknown outcome {outcome.GetType().Name}."),
        };
    }

    /// <summary>The registered URI, with <c>state</c> unchanged when the client sent one (D32).</summary>
    internal static string RedirectLocation(LogoutRedirect redirect) =>
        redirect.State is { } state
            ? AuthorizeEndpoint.AppendQuery(redirect.PostLogoutRedirectUri, [new("state", state)])
            : redirect.PostLogoutRedirectUri;

    internal static string SignedOutLocation(UiOptions ui) =>
        AuthorizeEndpoint.AppendQuery(ui.SignedOutPath, [new("logout", SignedOutMarker)]);

    private static string ErrorLocation(LogoutErrorPage page, UiOptions ui, ILogger logger)
    {
        LogRefused(logger, page.Error, page.Reason);
        return AuthorizeEndpoint.AppendQuery(ui.ErrorPath, [new("error", page.Error)]);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Logout request refused: {Error} ({Reason}).")]
    private static partial void LogRefused(ILogger logger, string error, string reason);
}
