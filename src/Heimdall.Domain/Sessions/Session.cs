using Heimdall.Domain.Common;
using Heimdall.Domain.Users;

namespace Heimdall.Domain.Sessions;

/// <summary>
/// A login session at Heimdall. The cookie holds a random ID. The server stores only its hash (D12).
/// </summary>
public sealed class Session
{
#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private Session()
    {
    }
#pragma warning restore CS8618

    private Session(
        TokenHash idHash,
        string sid,
        Guid tenantId,
        Guid userId,
        DateTimeOffset createdAt,
        DateTimeOffset absoluteExpiresAt)
    {
        IdHash = idHash;
        Sid = sid;
        TenantId = tenantId;
        UserId = userId;
        CreatedAt = createdAt;
        LastSeenAt = createdAt;
        AuthTime = createdAt;
        AbsoluteExpiresAt = absoluteExpiresAt;
    }

    public TokenHash IdHash { get; }

    /// <summary>The public session ID (D29). The ID token carries it, and each code and family records it.</summary>
    public string Sid { get; }

    public Guid TenantId { get; }

    public Guid UserId { get; }

    public DateTimeOffset CreatedAt { get; }

    public DateTimeOffset LastSeenAt { get; private set; }

    /// <summary>When the user last entered credentials. Used for <c>max_age</c> and the <c>auth_time</c> claim.</summary>
    public DateTimeOffset AuthTime { get; private init; }

    public DateTimeOffset AbsoluteExpiresAt { get; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>
    /// Starts a session after a successful sign-in. The caller creates a new ID and a new <c>sid</c> each time (D13, D29).
    /// </summary>
    public static Session Start(TokenHash idHash, string sid, Guid tenantId, Guid userId, TimeSpan absoluteLifetime, DateTimeOffset now)
    {
        SessionSid.Require(sid, nameof(sid));
        Guard.NotEmpty(tenantId, nameof(tenantId));
        Guard.NotEmpty(userId, nameof(userId));
        Guard.Positive(absoluteLifetime, nameof(absoluteLifetime));

        return new Session(idHash, sid, tenantId, userId, now, now + absoluteLifetime);
    }

    /// <summary>
    /// Checks every rule for a valid session. The tenant must match the request (see "Tenants" in the threat model),
    /// and a password change or a disabled account ends the session.
    /// </summary>
    public bool IsValid(Guid requestTenantId, User user, TimeSpan idleTimeout, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(user);

        return RevokedAt is null
            && TenantId == requestTenantId
            && user.Id == UserId
            && user.TenantId == TenantId
            && user.Status == UserStatus.Active
            && CreatedAt >= user.PasswordChangedAt
            && now < AbsoluteExpiresAt
            && now < LastSeenAt + idleTimeout;
    }

    /// <summary>
    /// The same session after the user entered credentials again in the same browser. It has a new cookie secret, so a
    /// secret known before this sign-in is worthless (D13). The <c>sid</c> stays, so the token families of the session
    /// stay linked to a session that a sign-out can end (D33). The absolute lifetime starts again.
    /// </summary>
    public Session Reauthenticate(TokenHash newIdHash, TimeSpan absoluteLifetime, DateTimeOffset now)
    {
        Guard.Positive(absoluteLifetime, nameof(absoluteLifetime));
        if (RevokedAt is not null)
        {
            throw new DomainException("A revoked session cannot be used.");
        }

        if (newIdHash == IdHash)
        {
            throw new DomainException("A sign-in needs a new session ID.");
        }

        return new Session(newIdHash, Sid, TenantId, UserId, CreatedAt, now + absoluteLifetime)
        {
            AuthTime = now,
            LastSeenAt = now,
        };
    }

    /// <summary>True when the user entered credentials no longer than <paramref name="maxAge"/> ago.</summary>
    public bool IsAuthenticatedWithin(TimeSpan maxAge, DateTimeOffset now) => now - AuthTime <= maxAge;

    /// <summary>Records activity. This moves the idle limit, never the absolute limit.</summary>
    public void Touch(DateTimeOffset now)
    {
        if (RevokedAt is not null)
        {
            throw new DomainException("A revoked session cannot be used.");
        }

        if (now > LastSeenAt)
        {
            LastSeenAt = now;
        }
    }

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}
