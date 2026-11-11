using System.Text;
using Heimdall.Api.Hosting;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Microsoft.Extensions.Options;

namespace Heimdall.Api.Endpoints;

/// <summary>Where the browser goes for the Angular pages. The pages get the stored request ID only.</summary>
public sealed class UiOptions
{
    public const string SectionName = "Heimdall:Ui";

    public string LoginPath { get; set; } = AccountPages.Prefix + "/login";

    public string ConsentPath { get; set; } = AccountPages.Prefix + "/consent";

    /// <summary>The account picker (#41). It gets <c>request_id</c>.</summary>
    public string SelectAccountPath { get; set; } = AccountPages.Prefix + "/select-account";

    /// <summary>The page for a refused request that Heimdall cannot send back to the client (U6).</summary>
    public string ErrorPath { get; set; } = AccountPages.Prefix + "/error";

    /// <summary>The page where the user confirms a sign-out that no matching hint started (D31, U17).</summary>
    public string LogoutPath { get; set; } = AccountPages.Prefix + "/logout";

    /// <summary>The page after a sign-out that goes back to no client (D32).</summary>
    public string SignedOutPath { get; set; } = AccountPages.Prefix + "/signed-out";

    /// <summary>The built account application, relative to the content root (U2).</summary>
    public string AccountDirectory { get; set; } = "wwwroot/account";
}

/// <summary>
/// <c>GET /oauth/v1/authorize</c> and <c>GET /oauth/v1/authorize/resume</c>. The logic is in
/// <see cref="AuthorizationService"/>. This class turns its outcome into a browser response.
/// </summary>
internal static partial class AuthorizeEndpoint
{
    public const string Path = "/oauth/v1/authorize";
    public const string ResumePath = "/oauth/v1/authorize/resume";

    public static void Map(WebApplication app)
    {
        app.MapGet(Path, AuthorizeAsync).RequireRateLimiting(RateLimits.AuthorizePolicy);
        app.MapGet(ResumePath, ResumeAsync).RequireRateLimiting(RateLimits.AuthorizePolicy);
    }

    private static async Task AuthorizeAsync(HttpContext context, AuthorizationService authorization, IOptions<UiOptions> ui, ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(typeof(AuthorizeEndpoint));

        // A repeated parameter makes the request ambiguous (RFC 6749, section 3.1). It could be client_id or
        // redirect_uri, so the error is never redirected.
        if (context.Request.Query.Any(p => p.Value.Count > 1))
        {
            await WriteAsync(context, new AuthorizeErrorPage(OAuthError.InvalidRequestCode, "repeated parameter"), ui.Value, logger).ConfigureAwait(false);
            return;
        }

        var parameters = context.Request.Query.ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);
        var outcome = await authorization.AuthorizeAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            parameters,
            context.Request.Cookies[SessionEndpoints.SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        await WriteAsync(context, outcome, ui.Value, logger).ConfigureAwait(false);
    }

    /// <summary>The login page sends the browser here after sign-in, with the stored request ID and nothing else.</summary>
    private static async Task ResumeAsync(HttpContext context, AuthorizationService authorization, IOptions<UiOptions> ui, ILoggerFactory loggers)
    {
        var outcome = await authorization.ResumeAsync(
            TenantResolutionMiddleware.GetRequestContext(context),
            context.Request.Query["request_id"].Count == 1 ? context.Request.Query["request_id"].ToString() : null,
            context.Request.Cookies[SessionEndpoints.SessionCookie],
            context.RequestAborted).ConfigureAwait(false);

        await WriteAsync(context, outcome, ui.Value, loggers.CreateLogger(typeof(AuthorizeEndpoint))).ConfigureAwait(false);
    }

    private static Task WriteAsync(HttpContext context, AuthorizeOutcome outcome, UiOptions ui, ILogger logger)
    {
        // A redirect can carry a code. No browser or proxy may keep it (D6).
        OAuthResponses.NoStore(context.Response);

        switch (outcome)
        {
            case AuthorizeErrorPage page:
                // Heimdall's own error page, never the client: the client or its redirect URI is not proven (U6). The
                // page shows text for a fixed list of codes only, and the code carries no reason (D5).
                LogRefused(logger, page.Error, page.Reason);
                return Redirect(context, AppendQuery(ui.ErrorPath, [new("error", page.Error)]));

            case AuthorizeRedirect redirect:
                if (redirect.Reason is { } reason)
                {
                    LogRefused(logger, redirect.Parameters[0].Value, reason);
                }

                return Redirect(context, AppendQuery(redirect.RedirectUri, redirect.Parameters));

            case AuthorizeLogin login:
                return Redirect(context, AppendQuery(ui.LoginPath, [new("request_id", login.RequestId.ToString())]));

            case AuthorizeConsent consent:
                return Redirect(context, AppendQuery(ui.ConsentPath, [new("request_id", consent.RequestId.ToString())]));

            case AuthorizeSelectAccount select:
                return Redirect(context, AppendQuery(ui.SelectAccountPath, [new("request_id", select.RequestId.ToString())]));

            default:
                throw new InvalidOperationException($"Unknown outcome {outcome.GetType().Name}.");
        }
    }

    private static Task Redirect(HttpContext context, string location)
    {
        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = location;
        return Task.CompletedTask;
    }

    /// <summary>Adds parameters to a URI that may already have a query. A registered URI has no fragment.</summary>
    internal static string AppendQuery(string uri, IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var builder = new StringBuilder(uri);
        var separator = uri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach (var (name, value) in parameters)
        {
            builder.Append(separator).Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }

        return builder.ToString();
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Authorization request refused: {Error} ({Reason}).")]
    private static partial void LogRefused(ILogger logger, string error, string reason);
}
