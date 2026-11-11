using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Application;

/// <summary>A test fake. It keeps sessions in memory.</summary>
internal sealed class InMemorySessionStore : ISessionStore
{
    public List<Session> Sessions { get; } = [];

    public int SaveCount { get; private set; }

    public int Queries { get; private set; }

    /// <summary>The users to join with, as the real store joins the users table.</summary>
    public required InMemoryUserStore Users { get; init; }

    public Task<IReadOnlyList<(Session Session, User User)>> FindWithUsersAsync(
        Guid tenantId,
        IReadOnlyList<TokenHash> idHashes,
        CancellationToken cancellationToken)
    {
        Queries++;
        var found =
            from s in Sessions
            where s.TenantId == tenantId && idHashes.Contains(s.IdHash)
            join u in Users.Users on new { s.TenantId, Id = s.UserId } equals new { u.TenantId, u.Id }
            select (s, u);
        return Task.FromResult<IReadOnlyList<(Session Session, User User)>>(found.ToList());
    }

    /// <summary>When true, the next replace finds the session revoked, as after a concurrent sign-out.</summary>
    public bool LoseNextReplace { get; set; }

    /// <summary>The conditions of the conditional UPDATE in <c>EfSessionStore</c>.</summary>
    public Task<bool> ReplaceAsync(Session session, Session reauthenticated, CancellationToken cancellationToken)
    {
        if (LoseNextReplace)
        {
            LoseNextReplace = false;
            session.Revoke(reauthenticated.AuthTime);
        }

        var index = Sessions.FindIndex(s => s.TenantId == session.TenantId && s.IdHash == session.IdHash && s.RevokedAt is null);
        if (index < 0)
        {
            return Task.FromResult(false);
        }

        Sessions[index] = reauthenticated;
        return Task.FromResult(true);
    }

    public void Add(Session session) => Sessions.Add(session);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        SaveCount++;
        return Task.CompletedTask;
    }
}

/// <summary>
/// A test fake of the authorization store. A save applies all changes or none, as the database transaction does.
/// </summary>
internal sealed class InMemoryAuthorizationStore : IAuthorizationStore
{
    private readonly List<AuthorizationRequest> _added = [];
    private readonly List<AuthorizationRequest> _removed = [];
    private readonly List<AuthorizationCode> _codes = [];

    public List<AuthorizationRequest> Requests { get; } = [];

    public List<AuthorizationCode> Codes { get; } = [];

    public int SaveCount { get; private set; }

    /// <summary>When true, the next save fails as if another caller removed the same request first.</summary>
    public bool LoseNextSave { get; set; }

    public void AddRequest(AuthorizationRequest request) => _added.Add(request);

    public Task<AuthorizationRequest?> FindRequestAsync(Guid tenantId, Guid requestId, CancellationToken cancellationToken) =>
        Task.FromResult(Requests.SingleOrDefault(r => r.TenantId == tenantId && r.Id == requestId));

    public void RemoveRequest(AuthorizationRequest request) => _removed.Add(request);

    public int Takes { get; private set; }

    /// <summary>The conditions of the conditional UPDATE in <c>EfAuthorizationStore</c>.</summary>
    public Task<AuthorizationRequest?> TakePushedRequestAsync(Guid tenantId, TokenHash requestUriHash, Guid clientPk, DateTimeOffset now, CancellationToken cancellationToken)
    {
        Takes++;
        var request = Requests.SingleOrDefault(r =>
            r.TenantId == tenantId && r.RequestUriHash == requestUriHash && r.ClientPk == clientPk && r.ExpiresAt > now);
        if (request is not null)
        {
            InMemoryTokenStore.Set(request, nameof(AuthorizationRequest.RequestUriHash), (TokenHash?)null);
            InMemoryTokenStore.Set(request, nameof(AuthorizationRequest.ExpiresAt), now + AuthorizationRequest.Lifetime);
        }

        return Task.FromResult(request);
    }

    public void AddCode(AuthorizationCode code) => _codes.Add(code);

    public Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var conflict = LoseNextSave || _removed.Any(r => !Requests.Contains(r));
        if (conflict)
        {
            LoseNextSave = false;
            Clear();
            throw new ConcurrentUpdateException();
        }

        Requests.AddRange(_added);
        Requests.RemoveAll(_removed.Contains);
        Codes.AddRange(_codes);
        Clear();
        SaveCount++;
        return Task.CompletedTask;
    }

    private void Clear()
    {
        _added.Clear();
        _removed.Clear();
        _codes.Clear();
    }
}
