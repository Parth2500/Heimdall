using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;

namespace Heimdall.UnitTests.Domain;

public class SessionTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Idle = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan Absolute = TimeSpan.FromHours(12);

    private static readonly Guid TenantId = Guid.CreateVersion7();

    private static User NewUser(DateTimeOffset? createdAt = null) =>
        User.Create(Guid.CreateVersion7(), TenantId, "ada@example.com", "argon2id$hash", createdAt ?? Now.AddDays(-1));

    private static Session NewSession(User user) =>
        Session.Start(TokenHash.Compute("session-id"), "sid-for-tests-00000000", TenantId, user.Id, Absolute, Now);

    [Fact]
    public void New_session_is_valid()
    {
        var user = NewUser();
        var session = NewSession(user);

        Assert.True(session.IsValid(TenantId, user, Idle, Now.AddMinutes(1)));
    }

    [Fact]
    public void Session_from_another_tenant_is_rejected()
    {
        var user = NewUser();
        var session = NewSession(user);

        Assert.False(session.IsValid(Guid.CreateVersion7(), user, Idle, Now.AddMinutes(1)));
    }

    [Fact]
    public void Session_for_another_user_is_rejected()
    {
        var user = NewUser();
        var other = NewUser();
        var session = NewSession(user);

        Assert.False(session.IsValid(TenantId, other, Idle, Now.AddMinutes(1)));
    }

    [Fact]
    public void Session_ends_after_the_idle_timeout()
    {
        var user = NewUser();
        var session = NewSession(user);

        Assert.False(session.IsValid(TenantId, user, Idle, Now.AddMinutes(30)));
    }

    [Fact]
    public void Activity_moves_the_idle_limit()
    {
        var user = NewUser();
        var session = NewSession(user);

        session.Touch(Now.AddMinutes(20));

        Assert.True(session.IsValid(TenantId, user, Idle, Now.AddMinutes(40)));
    }

    [Fact]
    public void Activity_never_passes_the_absolute_limit()
    {
        var user = NewUser();
        var session = NewSession(user);

        for (var minutes = 20; minutes < 12 * 60; minutes += 20)
        {
            session.Touch(Now.AddMinutes(minutes));
        }

        Assert.False(session.IsValid(TenantId, user, Idle, Now.AddHours(12)));
    }

    [Fact]
    public void Password_change_ends_older_sessions()
    {
        var user = NewUser();
        var session = NewSession(user);

        user.ChangePassword("argon2id$new", Now.AddMinutes(5));

        Assert.False(session.IsValid(TenantId, user, Idle, Now.AddMinutes(6)));
    }

    [Fact]
    public void Disabled_user_ends_the_session()
    {
        var user = NewUser();
        var session = NewSession(user);

        user.Disable();

        Assert.False(session.IsValid(TenantId, user, Idle, Now.AddMinutes(1)));
    }

    [Fact]
    public void Revoked_session_is_invalid_and_cannot_be_used()
    {
        var user = NewUser();
        var session = NewSession(user);

        session.Revoke(Now.AddMinutes(1));

        Assert.False(session.IsValid(TenantId, user, Idle, Now.AddMinutes(2)));
        Assert.Throws<DomainException>(() => session.Touch(Now.AddMinutes(2)));
    }

    [Fact]
    public void Max_age_compares_with_the_last_sign_in()
    {
        var user = NewUser();
        var session = NewSession(user);
        session.Touch(Now.AddMinutes(25));

        Assert.True(session.IsAuthenticatedWithin(TimeSpan.FromMinutes(30), Now.AddMinutes(30)));
        Assert.False(session.IsAuthenticatedWithin(TimeSpan.FromMinutes(10), Now.AddMinutes(30)));
    }

    [Fact]
    public void Reauthentication_keeps_the_sid_and_replaces_the_id()
    {
        var user = NewUser();
        var session = NewSession(user);
        session.Touch(Now.AddMinutes(5));
        var later = Now.AddMinutes(10);

        var again = session.Reauthenticate(TokenHash.Compute("new-session-id"), Absolute, later);

        Assert.Equal(TokenHash.Compute("new-session-id"), again.IdHash);
        Assert.Equal(session.Sid, again.Sid);
        Assert.Equal(session.TenantId, again.TenantId);
        Assert.Equal(session.UserId, again.UserId);
        Assert.Equal(Now, again.CreatedAt);
        Assert.Equal(later, again.AuthTime);
        Assert.Equal(later, again.LastSeenAt);
        Assert.Equal(later + Absolute, again.AbsoluteExpiresAt);
        Assert.Null(again.RevokedAt);
        Assert.True(again.IsValid(TenantId, user, Idle, later));
        Assert.True(again.IsAuthenticatedWithin(TimeSpan.Zero, later));
    }

    [Fact]
    public void Reauthentication_of_a_revoked_session_is_refused()
    {
        var session = NewSession(NewUser());
        session.Revoke(Now);

        Assert.Throws<DomainException>(() => session.Reauthenticate(TokenHash.Compute("new-session-id"), Absolute, Now));
    }

    [Fact]
    public void Reauthentication_needs_a_new_id_and_a_positive_lifetime()
    {
        var session = NewSession(NewUser());

        Assert.Throws<DomainException>(() => session.Reauthenticate(TokenHash.Compute("session-id"), Absolute, Now));
        Assert.ThrowsAny<Exception>(() => session.Reauthenticate(TokenHash.Compute("new-session-id"), TimeSpan.Zero, Now));
    }
}
