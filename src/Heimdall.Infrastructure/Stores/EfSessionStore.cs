using Heimdall.Application.Sessions;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Heimdall.Infrastructure.Stores;

internal sealed class EfSessionStore : ISessionStore
{
    private readonly HeimdallDbContext _db;

    public EfSessionStore(HeimdallDbContext db)
    {
        _db = db;
    }

    public async Task<IReadOnlyList<(Session Session, User User)>> FindWithUsersAsync(
        Guid tenantId,
        IReadOnlyList<TokenHash> idHashes,
        CancellationToken cancellationToken)
    {
        // The explicit tenant condition and the global query filter (D20) must both match. Both tables carry the
        // tenant filter and row-level security. The join also requires the same tenant.
        var hashes = idHashes.ToList();
        var found = await (
                from s in _db.Sessions
                where s.TenantId == tenantId && hashes.Contains(s.IdHash)
                join u in _db.Users on new { s.TenantId, Id = s.UserId } equals new { u.TenantId, u.Id }
                select new { Session = s, User = u })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return found.ConvertAll(f => (f.Session, f.User));
    }

    public async Task<bool> ReplaceAsync(Session session, Session reauthenticated, CancellationToken cancellationToken)
    {
        // The hash is the key of the row, so EF Core cannot change it on a tracked entity. One conditional statement
        // also closes the race with a sign-out: a revoked session matches no row.
        var tenantId = session.TenantId;
        var oldHash = session.IdHash.ToArray();
        var newHash = reauthenticated.IdHash.ToArray();
        var authTime = reauthenticated.AuthTime;
        var lastSeenAt = reauthenticated.LastSeenAt;
        var absoluteExpiresAt = reauthenticated.AbsoluteExpiresAt;
        var rows = await _db.Database.ExecuteSqlAsync(
            $"""
            UPDATE sessions
            SET id_hash = {newHash}, auth_time = {authTime}, last_seen_at = {lastSeenAt}, absolute_expires_at = {absoluteExpiresAt}
            WHERE tenant_id = {tenantId} AND id_hash = {oldHash} AND revoked_at IS NULL
            """,
            cancellationToken).ConfigureAwait(false);

        // The tracked entity names a key that no longer exists.
        _db.Entry(session).State = EntityState.Detached;
        return rows == 1;
    }

    public void Add(Session session) => _db.Sessions.Add(session);

    public Task SaveChangesAsync(CancellationToken cancellationToken) => _db.SaveChangesAsync(cancellationToken);
}
