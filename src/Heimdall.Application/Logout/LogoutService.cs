using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Logout;

/// <summary>What the logout endpoint sends back to the browser.</summary>
public abstract record LogoutOutcome;

/// <summary>Back to the client's registered post-logout redirect URI, with <c>state</c> unchanged (D32).</summary>
public sealed record LogoutRedirect(string PostLogoutRedirectUri, string? State) : LogoutOutcome;

/// <summary>Heimdall's signed-out page. It names no reason, so it does not show which URIs a client registered (D32).</summary>
public sealed record LogoutSignedOut : LogoutOutcome
{
    public static LogoutSignedOut Instance { get; } = new();
}

/// <summary>
/// The user must confirm on a Heimdall page before the session ends (D31). <paramref name="Target"/> is where the
/// browser goes after the confirmation, or null for the signed-out page.
/// </summary>
public sealed record LogoutConfirm(LogoutTarget? Target) : LogoutOutcome;

/// <summary>A malformed request. Heimdall shows its error page, ends no session, and redirects nowhere.</summary>
/// <param name="Reason">For the log only. It never goes into the response (D5).</param>
public sealed record LogoutErrorPage(string Error, string Reason) : LogoutOutcome;

/// <summary>A checked redirect target: the URI was registered for this client when Heimdall checked it.</summary>
public sealed record LogoutTarget(Guid ClientPk, string PostLogoutRedirectUri, string? State);

/// <summary>
/// RP-Initiated Logout 1.0 at <c>/oauth/v1/logout</c>, and the confirmation at <c>/session/v1/logout</c> (D30 to D33).
/// </summary>
/// <remarks>
/// The session ends at once only with a valid <c>id_token_hint</c> for this browser's session. Any other request needs
/// the user's click on a Heimdall page, so a cross-site link cannot sign a user out (logout CSRF). A redirect goes only
/// to a URI that the client registered, compared by exact match, so the endpoint is not an open redirect.
/// </remarks>
public sealed class LogoutService
{
    /// <summary>The longest <c>state</c> that Heimdall returns (D32), the same limit as at <c>/authorize</c>.</summary>
    public const int MaxStateLength = AuthorizationRequest.MaxClientValueLength;

    private const string ReasonRpInitiated = "rp_initiated";
    private const string ReasonUserConfirmed = "user_confirmed";

    private readonly IClientStore _clients;
    private readonly SessionService _sessions;
    private readonly IIdTokenHintValidator _hints;
    private readonly ILogoutStore _store;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public LogoutService(
        IClientStore clients,
        SessionService sessions,
        IIdTokenHintValidator hints,
        ILogoutStore store,
        IAuditLog audit,
        TimeProvider time)
    {
        _clients = clients;
        _sessions = sessions;
        _hints = hints;
        _store = store;
        _audit = audit;
        _time = time;
    }

    /// <param name="parameters">The query or form parameters. The endpoint already refused repeated parameters.</param>
    /// <param name="sessionId">The session cookie, or null.</param>
    public async Task<LogoutOutcome> EndSessionAsync(
        RequestContext context,
        IReadOnlyDictionary<string, string> parameters,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parameters);

        string? Get(string name) => parameters.TryGetValue(name, out var value) && value.Length > 0 ? value : null;

        var state = Get("state");
        if (state?.Length > MaxStateLength)
        {
            return new LogoutErrorPage(OAuthError.InvalidRequestCode, "state too long");
        }

        // D30: a hint counts only when Heimdall signed it for this tenant and one of its clients. exp does not count.
        VerifiedIdTokenHint? hint = null;
        Client? client = null;
        if (Get("id_token_hint") is { } hintText)
        {
            hint = await _hints.ValidateAsync(context.Tenant.Id, hintText, cancellationToken).ConfigureAwait(false);
            if (hint is not null && hint.Issuer == context.Issuer && hint.Audiences is [var audience])
            {
                client = await _clients.FindAsync(context.Tenant.Id, audience, cancellationToken).ConfigureAwait(false);
            }

            if (client is null)
            {
                // A forged, foreign, or unreadable hint names nobody. The request continues as one without a hint (D31).
                hint = null;
            }
        }

        if (Get("client_id") is { } clientId)
        {
            if (client is not null && !string.Equals(client.ClientId, clientId, StringComparison.Ordinal))
            {
                return new LogoutErrorPage(OAuthError.InvalidRequestCode, "client_id differs from the aud of id_token_hint");
            }

            client ??= await _clients.FindAsync(context.Tenant.Id, clientId, cancellationToken).ConfigureAwait(false);
        }

        // D32: only a registered URI of an active client. Anything else gives the signed-out page and no redirect.
        LogoutTarget? target = null;
        if (Get("post_logout_redirect_uri") is { } uri
            && client is { Status: ClientStatus.Active }
            && client.IsPostLogoutRedirectUriAllowed(uri))
        {
            target = new LogoutTarget(client.Id, uri, state);
        }

        var live = await LiveSessionsAsync(context, sessionId, cancellationToken).ConfigureAwait(false);
        if (live.Count == 0)
        {
            // D31: no session, so nothing to end and nothing to confirm.
            return Finish(target);
        }

        // D31: at once only when the hint names a live session of this browser. An older hint of the same user does
        // not count. Only that session ends. The other accounts of the browser stay signed in.
        var named = hint is null
            ? null
            : live.FirstOrDefault(l => string.Equals(hint.Sid, l.Session.Sid, StringComparison.Ordinal)
                && string.Equals(hint.Subject, l.User.Id.ToString(), StringComparison.Ordinal));
        if (named is null)
        {
            return new LogoutConfirm(target);
        }

        await EndAsync(context, named.Session, ReasonRpInitiated, client!.ClientId, cancellationToken).ConfigureAwait(false);
        return Finish(target);
    }

    /// <summary>
    /// The user confirmed on the Heimdall page. Ends one account of the browser's session list, or every account,
    /// then checks the target again: an admin can disable the client or remove the URI while the page is open.
    /// </summary>
    /// <param name="sid">The <c>sid</c> of the one session to end, or null to end every live session of the list.</param>
    public async Task<LogoutOutcome> ConfirmAsync(
        RequestContext context,
        string? sessionId,
        LogoutTarget? target,
        string? sid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        Client? client = null;
        if (target is not null)
        {
            client = await _clients.FindByPkAsync(context.Tenant.Id, target.ClientPk, cancellationToken).ConfigureAwait(false);
            if (client is not { Status: ClientStatus.Active } || !client.IsPostLogoutRedirectUriAllowed(target.PostLogoutRedirectUri))
            {
                target = null;
            }
        }

        // The page names one account by its sid, or none for every account. A sid selects only inside the list that
        // the cookie authenticated (D29). A sid that names no live session of the list ends nothing.
        var live = await LiveSessionsAsync(context, sessionId, cancellationToken).ConfigureAwait(false);
        if (sid is not null)
        {
            live = live.Where(l => string.Equals(l.Session.Sid, sid, StringComparison.Ordinal)).ToList();
        }

        await EndAllAsync(context, live, ReasonUserConfirmed, target is null ? null : client!.ClientId, cancellationToken).ConfigureAwait(false);

        return Finish(target);
    }

    private async Task<List<ListedSession>> LiveSessionsAsync(RequestContext context, string? cookie, CancellationToken cancellationToken) =>
        (await _sessions.ListAsync(context, cookie, cancellationToken).ConfigureAwait(false)).Where(l => l.Live).ToList();

    /// <summary>
    /// Ends these sessions of the browser's session list. Each session ends in its own transaction (D33), so a
    /// failure in the middle leaves each session either ended with its families, or untouched.
    /// </summary>
    private async Task EndAllAsync(RequestContext context, List<ListedSession> live, string reason, string? clientId, CancellationToken cancellationToken)
    {
        foreach (var listed in live)
        {
            await EndAsync(context, listed.Session, reason, clientId, cancellationToken).ConfigureAwait(false);
        }
    }

    private static LogoutOutcome Finish(LogoutTarget? target) =>
        target is null ? LogoutSignedOut.Instance : new LogoutRedirect(target.PostLogoutRedirectUri, target.State);

    /// <summary>D33: one transaction ends the session, revokes its families, and queues the back-channel logouts.</summary>
    private async Task EndAsync(RequestContext context, Session session, string reason, string? clientId, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var end = await _store.EndSessionAsync(context.Tenant.Id, session.IdHash, session.Sid, now, cancellationToken).ConfigureAwait(false);
        if (!end.Ended)
        {
            // A concurrent sign-out of the same session did the work and wrote the events.
            return;
        }

        var data = new Dictionary<string, string>
        {
            // The hash, never the cookie value (as at sign-in). The sid links the event to the client's logout.
            ["session_hash"] = Convert.ToHexStringLower(session.IdHash.AsSpan()),
            ["sid"] = session.Sid,
            ["reason"] = reason,
            ["families_revoked"] = end.Families.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["backchannel_queued"] = end.QueuedClients.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
        if (clientId is not null)
        {
            data["client_id"] = clientId;
        }

        if (context.UserAgent is { } userAgent)
        {
            data["user_agent"] = userAgent;
        }

        await WriteAuditAsync(context, AuditEventTypes.SessionRevoked, session.UserId, null, null, data, cancellationToken).ConfigureAwait(false);
        foreach (var family in end.Families)
        {
            await WriteAuditAsync(
                context,
                AuditEventTypes.FamilyRevoked,
                family.UserId,
                family.ClientPk,
                family.FamilyId,
                new Dictionary<string, string> { ["reason"] = "user_logout", ["sid"] = session.Sid },
                cancellationToken).ConfigureAwait(false);
        }
    }

    private Task WriteAuditAsync(
        RequestContext context,
        string type,
        Guid userId,
        Guid? clientPk,
        Guid? familyId,
        Dictionary<string, string> data,
        CancellationToken cancellationToken) =>
        _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: userId,
                clientPk: clientPk,
                familyId: familyId,
                data: data),
            cancellationToken);
}
