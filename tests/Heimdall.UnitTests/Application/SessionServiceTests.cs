using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

public class SessionServiceTests
{
    private const string Password = "correct horse battery staple";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryUserStore _users;
    private readonly InMemorySessionStore _sessions;
    private readonly RecordingAuditLog _audit = new();
    private readonly SessionService _service;
    private readonly User _user;

    public SessionServiceTests()
    {
        _users = new InMemoryUserStore();
        _sessions = new InMemorySessionStore { Users = _users };
        var authenticator = new UserAuthenticator(
            _users,
            new FakePasswordHasher(),
            new InMemoryLoginThrottleStore(),
            new LoginThrottleOptions(),
            _audit,
            _time);
        _service = new SessionService(authenticator, _sessions, _audit, _time);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", FakePasswordHasher.HashOf(Password), Now);
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse("203.0.113.7"), "Firefox/140");

    private Task<SignInResult> SignIn(string password = Password, string? existing = null, RequestContext? context = null, string email = "alice@example.com") =>
        _service.SignInAsync(context ?? Context, email, password, existing, CancellationToken.None);

    private User AddUser(string email)
    {
        var user = User.Create(Guid.CreateVersion7(), _tenant.Id, email, FakePasswordHasher.HashOf(Password), Now);
        _users.Add(user);
        return user;
    }

    private Task<IReadOnlyList<ListedSession>> List(string? cookie) => _service.ListAsync(Context, cookie, CancellationToken.None);

    private Task<ValidSession?> Validate(string? sessionId) => _service.ValidateAsync(Context, sessionId, CancellationToken.None);

    [Fact]
    public async Task Sign_in_starts_a_session_and_stores_only_the_hash()
    {
        var result = await SignIn();

        Assert.True(result.Succeeded);
        Assert.Same(_user, result.User);
        Assert.Equal(SessionService.SessionIdLength, result.SessionId!.Length);
        Assert.True(System.Buffers.Text.Base64Url.IsValid(result.SessionId));

        var session = Assert.Single(_sessions.Sessions);
        Assert.Equal(TokenHash.Compute(result.SessionId), session.IdHash);
        Assert.Equal(_tenant.Id, session.TenantId);
        Assert.Equal(_user.Id, session.UserId);
        Assert.Equal(Now, session.AuthTime);
        Assert.Equal(Now + TenantSettings.Default.SessionAbsolute, session.AbsoluteExpiresAt);
        Assert.Equal(1, _sessions.SaveCount);

        // D29: the public sid is its own random value, not a part of the cookie secret.
        Assert.True(SessionSid.IsValid(session.Sid));
        Assert.DoesNotContain(session.Sid, result.SessionId, StringComparison.Ordinal);

        var started = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionStarted);
        Assert.Equal(_user.Id, started.SubjectUserId);
        Assert.Equal("corr-1", started.CorrelationId);
        Assert.Equal(Convert.ToHexStringLower(session.IdHash.AsSpan()), started.Data["session_hash"]);
        Assert.Equal("Firefox/140", started.Data["user_agent"]);
        Assert.DoesNotContain(result.SessionId, started.Data.Values);
    }

    [Fact]
    public async Task Sign_in_without_a_user_agent_audits_none()
    {
        await SignIn(context: Context with { UserAgent = null });

        Assert.False(_audit.Events.Single(e => e.Type == AuditEventTypes.SessionStarted).Data.ContainsKey("user_agent"));
    }

    [Fact]
    public async Task Each_sign_in_gets_a_new_session_id()
    {
        var first = await SignIn();
        var second = await SignIn();

        Assert.NotEqual(first.SessionId, second.SessionId);
        Assert.NotEqual(_sessions.Sessions[0].Sid, _sessions.Sessions[1].Sid);
    }

    [Fact]
    public async Task Sign_in_again_keeps_the_session_and_replaces_its_id()
    {
        // D13, session fixation: an ID that existed before the sign-in must not survive it. The sid stays, so the
        // token families of the session stay linked to a session that a sign-out can end (D33).
        var first = await SignIn();
        var sid = _sessions.Sessions[0].Sid;
        var firstHash = _sessions.Sessions[0].IdHash;
        _time.Advance(TimeSpan.FromMinutes(2));

        var second = await SignIn(existing: first.Cookie);

        var session = Assert.Single(_sessions.Sessions);
        Assert.Equal(sid, session.Sid);
        Assert.Equal(TokenHash.Compute(second.SessionId!), session.IdHash);
        Assert.Equal(Now.AddMinutes(2), session.AuthTime);
        Assert.Equal(Now.AddMinutes(2), session.LastSeenAt);
        Assert.Equal(Now, session.CreatedAt);
        Assert.Equal(Now.AddMinutes(2) + TenantSettings.Default.SessionAbsolute, session.AbsoluteExpiresAt);
        Assert.Equal(second.SessionId, second.Cookie);
        Assert.Null(await Validate(first.SessionId));
        Assert.NotNull(await Validate(second.Cookie));

        Assert.Single(_audit.Events, e => e.Type == AuditEventTypes.SessionStarted);
        var again = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionReauthenticated);
        Assert.Equal(_user.Id, again.SubjectUserId);
        Assert.Equal(Convert.ToHexStringLower(session.IdHash.AsSpan()), again.Data["session_hash"]);
        Assert.Equal(Convert.ToHexStringLower(firstHash.AsSpan()), again.Data["previous_session_hash"]);
        Assert.DoesNotContain(second.SessionId, again.Data.Values);
    }

    [Fact]
    public async Task Sign_in_again_after_a_concurrent_sign_out_starts_a_new_session()
    {
        var first = await SignIn();
        var sid = _sessions.Sessions[0].Sid;
        _sessions.LoseNextReplace = true;

        var second = await SignIn(existing: first.Cookie);

        Assert.Equal(2, _sessions.Sessions.Count);
        Assert.NotNull(_sessions.Sessions[0].RevokedAt);
        Assert.NotEqual(sid, _sessions.Sessions[1].Sid);
        Assert.Equal(second.SessionId, second.Cookie);
        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.SessionReauthenticated);
    }

    [Fact]
    public async Task Sign_in_again_to_an_ended_session_starts_a_new_session()
    {
        var first = await SignIn();
        var sid = _sessions.Sessions[0].Sid;
        _sessions.Sessions[0].Revoke(Now);

        var second = await SignIn(existing: first.Cookie);

        Assert.Equal(2, _sessions.Sessions.Count);
        Assert.NotEqual(sid, _sessions.Sessions[1].Sid);

        // One row for each account: the ended entry of the same user leaves the list.
        Assert.Equal(second.SessionId, second.Cookie);
    }

    [Fact]
    public async Task Sign_in_of_another_user_keeps_the_other_sessions()
    {
        var bob = AddUser("bob@example.com");
        var first = await SignIn();

        var second = await SignIn(existing: first.Cookie, email: "bob@example.com");

        Assert.Equal(first.SessionId + "." + second.SessionId, second.Cookie);
        Assert.All(_sessions.Sessions, s => Assert.Null(s.RevokedAt));
        var listed = await List(second.Cookie);
        Assert.Equal([_user.Id, bob.Id], listed.Select(l => l.User.Id));
        Assert.All(listed, l => Assert.True(l.Live));
        Assert.Equal([first.SessionId, second.SessionId], listed.Select(l => l.SessionId));
    }

    [Fact]
    public async Task Sign_in_never_adopts_a_session_id_of_the_request()
    {
        // D13: an attacker plants a list. The victim's session gets an ID that the attacker does not know.
        var planted = new string('A', SessionService.SessionIdLength);

        var result = await SignIn(existing: planted);

        Assert.Equal(result.SessionId, result.Cookie);
        Assert.DoesNotContain(planted, result.Cookie, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sign_in_again_moves_the_account_to_the_end_of_the_list()
    {
        AddUser("bob@example.com");
        var alice = await SignIn();
        var bob = await SignIn(existing: alice.Cookie, email: "bob@example.com");

        var again = await SignIn(existing: bob.Cookie);

        Assert.Equal(bob.SessionId + "." + again.SessionId, again.Cookie);
        Assert.Equal(2, _sessions.Sessions.Count);
    }

    [Fact]
    public async Task Full_list_refuses_a_new_account_and_ends_no_session()
    {
        string? cookie = null;
        for (var i = 0; i < SessionList.MaxSessions; i++)
        {
            AddUser($"user{i}@example.com");
            cookie = (await SignIn(existing: cookie, email: $"user{i}@example.com")).Cookie;
        }

        var result = await SignIn(existing: cookie);

        Assert.True(result.ListFull);
        Assert.False(result.Succeeded);
        Assert.Null(result.Cookie);
        Assert.Equal(SessionList.MaxSessions, _sessions.Sessions.Count);
        Assert.All(_sessions.Sessions, s => Assert.Null(s.RevokedAt));
    }

    [Fact]
    public async Task Full_list_still_lets_a_listed_account_sign_in_again()
    {
        string? cookie = null;
        for (var i = 0; i < SessionList.MaxSessions; i++)
        {
            AddUser($"user{i}@example.com");
            cookie = (await SignIn(existing: cookie, email: $"user{i}@example.com")).Cookie;
        }

        var result = await SignIn(existing: cookie, email: "user0@example.com");

        Assert.True(result.Succeeded);
        Assert.Equal(SessionList.MaxSessions, SessionList.Parse(result.Cookie).Count);
    }

    [Fact]
    public async Task Full_list_drops_the_oldest_ended_session_first()
    {
        string? cookie = null;
        var ids = new List<string>();
        for (var i = 0; i < SessionList.MaxSessions; i++)
        {
            AddUser($"user{i}@example.com");
            var signedIn = await SignIn(existing: cookie, email: $"user{i}@example.com");
            cookie = signedIn.Cookie;
            ids.Add(signedIn.SessionId!);
        }

        _sessions.Sessions[1].Revoke(Now);
        _sessions.Sessions[3].Revoke(Now);

        var result = await SignIn(existing: cookie);

        Assert.True(result.Succeeded);
        Assert.Equal(string.Join('.', ids[0], ids[2], ids[3], ids[4], result.SessionId), result.Cookie);
    }

    [Fact]
    public async Task List_marks_an_ended_session_and_skips_an_unknown_id()
    {
        AddUser("bob@example.com");
        var alice = await SignIn();
        var bob = await SignIn(existing: alice.Cookie, email: "bob@example.com");
        _sessions.Sessions[0].Revoke(Now);
        var unknown = new string('A', SessionService.SessionIdLength);
        var queries = _sessions.Queries;

        var listed = await List(unknown + "." + bob.Cookie);

        Assert.Equal([false, true], listed.Select(l => l.Live));
        Assert.Equal(queries + 1, _sessions.Queries);
        Assert.Equal(0, _sessions.SaveCount - 2);
    }

    [Fact]
    public async Task Validation_uses_the_latest_live_session_of_the_list()
    {
        var bob = AddUser("bob@example.com");
        var alice = await SignIn();
        var both = await SignIn(existing: alice.Cookie, email: "bob@example.com");

        Assert.Equal(bob.Id, (await Validate(both.Cookie))!.User.Id);

        _sessions.Sessions[1].Revoke(Now);
        Assert.Equal(_user.Id, (await Validate(both.Cookie))!.User.Id);
    }

    [Fact]
    public async Task Validation_of_a_list_costs_one_query()
    {
        AddUser("bob@example.com");
        var alice = await SignIn();
        var both = await SignIn(existing: alice.Cookie, email: "bob@example.com");
        var queries = _sessions.Queries;

        await Validate(both.Cookie);

        Assert.Equal(queries + 1, _sessions.Queries);
    }

    [Fact]
    public async Task Failed_sign_in_starts_no_session()
    {
        var result = await SignIn("wrong password here");

        Assert.False(result.Succeeded);
        Assert.Null(result.SessionId);
        Assert.Null(result.User);
        Assert.Empty(_sessions.Sessions);
        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.SessionStarted);
    }

    [Fact]
    public async Task Failed_sign_in_keeps_the_previous_session()
    {
        var first = await SignIn();

        var failed = await SignIn("wrong password here", existing: first.SessionId);

        Assert.Null(_sessions.Sessions[0].RevokedAt);
        Assert.Null(failed.Cookie);
        Assert.False(failed.ListFull);
        Assert.NotNull(await Validate(first.Cookie));
    }

    [Fact]
    public async Task Valid_session_returns_the_session_and_its_user()
    {
        var id = (await SignIn()).SessionId;

        var valid = await Validate(id);

        Assert.Same(_sessions.Sessions[0], valid!.Session);
        Assert.Same(_user, valid.User);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")] // 43 characters, not base64url
    public async Task Malformed_session_id_is_refused_before_the_store(string? id)
    {
        Assert.Null(await Validate(id));
        Assert.Equal(0, _sessions.Queries);
    }

    [Fact]
    public async Task Unknown_session_id_is_refused()
    {
        Assert.Null(await Validate(new string('A', SessionService.SessionIdLength)));
    }

    [Fact]
    public async Task Session_of_a_deleted_user_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _users.Users.Clear();

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Session_of_a_disabled_user_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _user.Disable();

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Session_after_the_idle_limit_is_refused()
    {
        var id = (await SignIn()).SessionId;
        _time.Advance(TenantSettings.Default.SessionIdle);

        Assert.Null(await Validate(id));
    }

    [Fact]
    public async Task Activity_within_a_minute_writes_nothing()
    {
        var id = (await SignIn()).SessionId;
        var saves = _sessions.SaveCount;
        _time.Advance(TimeSpan.FromMinutes(1) - TimeSpan.FromTicks(1));

        await Validate(id);

        Assert.Equal(saves, _sessions.SaveCount);
        Assert.Equal(Now, _sessions.Sessions[0].LastSeenAt);
    }

    [Fact]
    public async Task Activity_after_a_minute_moves_the_idle_limit()
    {
        var id = (await SignIn()).SessionId;
        var saves = _sessions.SaveCount;
        _time.Advance(TimeSpan.FromMinutes(1));

        await Validate(id);

        Assert.Equal(saves + 1, _sessions.SaveCount);
        Assert.Equal(Now.AddMinutes(1), _sessions.Sessions[0].LastSeenAt);
    }
}
