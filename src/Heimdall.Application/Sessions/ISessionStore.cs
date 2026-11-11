using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Sessions;

/// <summary>The <c>sessions</c> table of one tenant. Rows are found by the hash of the session ID (D12).</summary>
public interface ISessionStore
{
    /// <summary>
    /// The sessions with these ID hashes in the tenant, each with its user, tracked for change. A hash with no row, or
    /// with no user, gives no entry. Validation of a session list runs on many requests, so it costs one round trip
    /// for the whole list.
    /// </summary>
    Task<IReadOnlyList<(Session Session, User User)>> FindWithUsersAsync(
        Guid tenantId,
        IReadOnlyList<TokenHash> idHashes,
        CancellationToken cancellationToken);

    void Add(Session session);

    /// <summary>
    /// Replaces a session by its re-authenticated form (<see cref="Session.Reauthenticate"/>) in one conditional
    /// statement. False when the session was revoked in the meantime, so nothing changed.
    /// </summary>
    Task<bool> ReplaceAsync(Session session, Session reauthenticated, CancellationToken cancellationToken);

    Task SaveChangesAsync(CancellationToken cancellationToken);
}
