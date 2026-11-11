using Heimdall.Application.Audit;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tokens;

namespace Heimdall.Application.Authorization;

/// <summary>What the consent page shows. Every value comes from the stored request and the client registration.</summary>
/// <param name="RedirectHost">The host of the registered redirect URI, so the user sees where the browser goes next.</param>
public sealed record ConsentPrompt(string ClientId, string ClientName, IReadOnlyList<string> Scopes, string RedirectHost);

/// <summary>
/// The consent page API for a client that requires consent. The user decides for one stored request. The page sends the
/// request ID and the decision only, so the browser cannot change the client or the scope (threat model, consent page,
/// Tampering). After a decision, the page sends the browser to <c>/authorize/resume</c>, which issues the code or the
/// <c>access_denied</c> error.
/// </summary>
/// <remarks>Persisted consent, so that a user approves a client once, is a Phase 3 item. Until then, each request asks.</remarks>
public sealed class ConsentService
{
    /// <summary>The page has no usable session for the request. It sends the user to the login page.</summary>
    public const string LoginRequiredCode = "login_required";

    private readonly IClientStore _clients;
    private readonly IAuthorizationStore _store;
    private readonly SessionService _sessions;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public ConsentService(IClientStore clients, IAuthorizationStore store, SessionService sessions, IAuditLog audit, TimeProvider time)
    {
        _clients = clients;
        _store = store;
        _sessions = sessions;
        _audit = audit;
        _time = time;
    }

    public async Task<Result<ConsentPrompt>> GetPromptAsync(
        RequestContext context,
        string? requestId,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        var loaded = await LoadAsync(context, requestId, sessionId, cancellationToken).ConfigureAwait(false);
        if (!loaded.IsSuccess)
        {
            return Result.Failure<ConsentPrompt>(loaded.Error);
        }

        var (request, client, _) = loaded.Value;
        return Result.Success(new ConsentPrompt(
            client.ClientId,
            client.Name,
            request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            new Uri(request.RedirectUri).Host));
    }

    /// <summary>Records the decision of the signed-in user. The page then sends the browser to the resume path.</summary>
    public async Task<Result<bool>> DecideAsync(
        RequestContext context,
        string? requestId,
        string? sessionId,
        bool approve,
        CancellationToken cancellationToken)
    {
        var loaded = await LoadAsync(context, requestId, sessionId, cancellationToken).ConfigureAwait(false);
        if (!loaded.IsSuccess)
        {
            return Result.Failure<bool>(loaded.Error);
        }

        var (request, client, userId) = loaded.Value;
        request.DecideConsent(userId, approve);
        try
        {
            await _store.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ConcurrentUpdateException)
        {
            return Result.Failure<bool>(OAuthError.InvalidRequest("request already used"));
        }

        // Threat model, consent page, Repudiation: each decision is audited, a denial too.
        await _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                approve ? AuditEventTypes.ConsentGranted : AuditEventTypes.ConsentDenied,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                actorUserId: userId,
                subjectUserId: userId,
                clientPk: client.Id,
                data: new Dictionary<string, string> { ["client_id"] = client.ClientId, ["scope"] = request.Scope }),
            cancellationToken).ConfigureAwait(false);

        return Result.Success(approve);
    }

    private async Task<Result<(AuthorizationRequest Request, Client Client, Guid UserId)>> LoadAsync(
        RequestContext context,
        string? requestId,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!Guid.TryParse(requestId, out var id))
        {
            return Fail(OAuthError.InvalidRequest("request_id malformed"));
        }

        var now = _time.GetUtcNow();
        var request = await _store.FindRequestAsync(context.Tenant.Id, id, cancellationToken).ConfigureAwait(false);
        // A pushed request that /authorize has not taken has no consent page yet (D42).
        if (request is null || request.RequestUriHash is not null || request.IsExpired(now))
        {
            return Fail(OAuthError.InvalidRequest(request is { RequestUriHash: null } ? "request expired" : "request unknown or used"));
        }

        // The same choice as the resume step (D51): the account of the request decides, and prompt=login and max_age
        // apply to the consent page too. So the consent is always the consent of the account that gets the code.
        var choice = await _sessions.ChooseAsync(context, request, sessionId, cancellationToken).ConfigureAwait(false);
        if (choice.Session is not { } session)
        {
            return Fail(new OAuthError(LoginRequiredCode, "no session that satisfies the request"));
        }

        var client = await _clients.FindByPkAsync(context.Tenant.Id, request.ClientPk, cancellationToken).ConfigureAwait(false);
        // prompt=consent asks for the page also when the client does not require it.
        if (client is not { Status: ClientStatus.Active } || !(client.RequireConsent || request.ForceConsent))
        {
            return Fail(OAuthError.InvalidRequest("client inactive or needs no consent"));
        }

        return Result.Success((request, client, session.User.Id));
    }

    private static Result<(AuthorizationRequest, Client, Guid)> Fail(OAuthError error) =>
        Result.Failure<(AuthorizationRequest, Client, Guid)>(error);
}
