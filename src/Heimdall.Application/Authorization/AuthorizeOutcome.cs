namespace Heimdall.Application.Authorization;

/// <summary>What the <c>/authorize</c> endpoint sends back to the browser.</summary>
public abstract record AuthorizeOutcome;

/// <summary>
/// An error that Heimdall shows itself and never redirects. It applies while the client or the redirect URI is not
/// proven valid: a redirect then would be an open redirect (RFC 6749, section 4.1.2.1).
/// </summary>
/// <param name="Error">An OAuth error code.</param>
/// <param name="Reason">For the log only. It never goes into the response (D5).</param>
public sealed record AuthorizeErrorPage(string Error, string Reason) : AuthorizeOutcome;

/// <summary>
/// A redirect to the client's registered redirect URI, with either a code or an error. The parameters always
/// include <c>iss</c> (RFC 9207, D9), and <c>state</c> when the client sent one.
/// </summary>
/// <param name="Reason">For the log only, when the redirect carries an error.</param>
public sealed record AuthorizeRedirect(
    string RedirectUri,
    IReadOnlyList<KeyValuePair<string, string>> Parameters,
    string? Reason = null) : AuthorizeOutcome;

/// <summary>The user must sign in. The login page gets the stored request ID only.</summary>
public sealed record AuthorizeLogin(Guid RequestId) : AuthorizeOutcome;

/// <summary>The user must approve the client. The consent page gets the stored request ID only.</summary>
public sealed record AuthorizeConsent(Guid RequestId) : AuthorizeOutcome;

/// <summary>Show the account picker. The request is stored, and the page continues it by ID.</summary>
public sealed record AuthorizeSelectAccount(Guid RequestId) : AuthorizeOutcome;
