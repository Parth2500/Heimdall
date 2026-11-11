using System.Buffers.Text;
using System.Net;
using Heimdall.Application.Common;
using Heimdall.Application.Logout;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Tenants;
using Heimdall.Domain.Tokens;
using Heimdall.Domain.Users;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

/// <summary>RP-Initiated Logout and the confirmation (D30 to D33).</summary>
public class LogoutServiceTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Callback = "https://app.example.com/callback";
    private const string Bye = "https://app.example.com/bye";
    private const string Sid = "sid-of-the-session-001";
    private const string OtherSid = "sid-of-another-one-002";
    private const string Hint = "the-id-token-hint";
    private static readonly DateTimeOffset Now = new(2026, 10, 26, 12, 0, 0, TimeSpan.Zero);
    private static readonly TokenLifetimes Lifetimes = new(TimeSpan.FromMinutes(5), TimeSpan.FromDays(7), TimeSpan.FromDays(30));

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly List<Client> _clientList = [];
    private readonly InMemoryUserStore _users = new();
    private readonly InMemorySessionStore _sessions;
    private readonly InMemoryTokenStore _tokens = new();
    private readonly InMemoryLogoutStore _store;
    private readonly FakeIdTokenHintValidator _hints = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly LogoutService _service;
    private readonly Client _spa;
    private readonly User _user;

    public LogoutServiceTests()
    {
        _sessions = new InMemorySessionStore { Users = _users };
        _store = new InMemoryLogoutStore { Sessions = _sessions, Tokens = _tokens, Clients = _clientList };
        var authenticator = new UserAuthenticator(
            _users, new FakePasswordHasher(), new InMemoryLoginThrottleStore(), new LoginThrottleOptions(), _audit, _time);
        var sessions = new SessionService(authenticator, _sessions, _audit, _time);
        _service = new LogoutService(_clients, sessions, _hints, _store, _audit, _time);
        _spa = AddClient("spa", [Bye]);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now.AddDays(-1));
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"), "Firefox/140");

    private Client AddClient(string clientId, string[] postLogoutUris, string? backchannel = null, bool active = true)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            clientId,
            "App " + clientId,
            ClientType.Public,
            [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "offline_access"],
            [Callback],
            requireConsent: false,
            overrides: null,
            Now);
        client.UpdateLogoutUris(postLogoutUris, backchannel);
        if (active)
        {
            client.Approve();
        }

        _clients.Add(client);
        _clientList.Add(client);
        return client;
    }

    /// <summary>A valid session with <paramref name="sid"/>. Returns the cookie value.</summary>
    private string SignedIn(string sid = Sid)
    {
        var id = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(id), sid, _tenant.Id, _user.Id, TimeSpan.FromHours(12), Now));
        return id;
    }

    private Session SessionOf(string id) => _sessions.Sessions.Single(s => s.IdHash == TokenHash.Compute(id));

    private TokenFamily AddFamily(Client client, string? sid = Sid, string scope = "openid offline_access")
    {
        var family = TokenFamily.Start(Guid.CreateVersion7(), _tenant.Id, client.Id, _user.Id, Guid.CreateVersion7(), scope, Lifetimes, Now, sid: sid);
        _tokens.Families.Add(family);
        return family;
    }

    private void RegisterHint(string token = Hint, string? sid = Sid, string? audience = "spa", string issuer = Issuer, string? subject = null) =>
        _hints.Hints[token] = new VerifiedIdTokenHint(issuer, subject ?? _user.Id.ToString(), audience is null ? [] : [audience], sid);

    private Task<LogoutOutcome> EndSession(string? cookie, params (string Name, string Value)[] parameters) =>
        _service.EndSessionAsync(Context, parameters.ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal), cookie, CancellationToken.None);

    // ---- A valid hint for this session ends it at once (D31)

    [Fact]
    public async Task Hint_of_this_session_ends_it_and_redirects_with_state()
    {
        var cookie = SignedIn();
        RegisterHint();
        var family = AddFamily(_spa);

        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye), ("state", "xyz"));

        Assert.Equal(new LogoutRedirect(Bye, "xyz"), outcome);
        Assert.Equal(Now, SessionOf(cookie).RevokedAt);
        Assert.Equal(Now, family.RevokedAt);
        Assert.Equal(FamilyRevocationReason.UserLogout, family.RevocationReason);
        Assert.Equal((_tenant.Id, Hint), Assert.Single(_hints.Checked));
    }

    [Fact]
    public async Task Ended_session_is_audited_with_the_reason_and_the_client()
    {
        var cookie = SignedIn();
        RegisterHint();
        var family = AddFamily(_spa);

        await EndSession(cookie, ("id_token_hint", Hint));

        var revoked = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionRevoked);
        Assert.Equal(_user.Id, revoked.SubjectUserId);
        Assert.Equal("corr-1", revoked.CorrelationId);
        Assert.Equal("rp_initiated", revoked.Data["reason"]);
        Assert.Equal("spa", revoked.Data["client_id"]);
        Assert.Equal(Sid, revoked.Data["sid"]);
        Assert.Equal("1", revoked.Data["families_revoked"]);
        Assert.Equal("0", revoked.Data["backchannel_queued"]);
        Assert.Equal("Firefox/140", revoked.Data["user_agent"]);
        Assert.Equal(Convert.ToHexStringLower(SessionOf(cookie).IdHash.AsSpan()), revoked.Data["session_hash"]);
        Assert.DoesNotContain(cookie, revoked.Data.Values);

        var familyEvent = _audit.Events.Single(e => e.Type == AuditEventTypes.FamilyRevoked);
        Assert.Equal(family.Id, familyEvent.FamilyId);
        Assert.Equal(_spa.Id, familyEvent.ClientPk);
        Assert.Equal(_user.Id, familyEvent.SubjectUserId);
        Assert.Equal("user_logout", familyEvent.Data["reason"]);
        Assert.Equal(Sid, familyEvent.Data["sid"]);
    }

    [Fact]
    public async Task Sign_out_revokes_every_family_of_the_session_and_only_those()
    {
        var cookie = SignedIn();
        RegisterHint();
        var huginn = AddClient("huginn", []);
        var spaFamily = AddFamily(_spa);
        var offline = AddFamily(huginn, scope: "openid offline_access");
        var otherSession = AddFamily(_spa, OtherSid);
        var older = AddFamily(_spa, sid: null);

        await EndSession(cookie, ("id_token_hint", Hint));

        // D33: offline_access too. Another session's families and families with no sid stay.
        Assert.NotNull(spaFamily.RevokedAt);
        Assert.NotNull(offline.RevokedAt);
        Assert.Null(otherSession.RevokedAt);
        Assert.Null(older.RevokedAt);
        Assert.Equal(2, _audit.Events.Count(e => e.Type == AuditEventTypes.FamilyRevoked));
    }

    [Fact]
    public async Task Family_revoked_before_keeps_its_reason()
    {
        var cookie = SignedIn();
        RegisterHint();
        var family = AddFamily(_spa);
        family.Revoke(FamilyRevocationReason.ReuseDetected, Now.AddMinutes(-1));

        await EndSession(cookie, ("id_token_hint", Hint));

        Assert.Equal(FamilyRevocationReason.ReuseDetected, family.RevocationReason);
        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.FamilyRevoked);
    }

    [Fact]
    public async Task Clients_with_a_backchannel_uri_are_queued_once_each()
    {
        var cookie = SignedIn();
        RegisterHint();
        var huginn = AddClient("huginn", [], backchannel: "https://huginn.example.com/backchannel");
        AddFamily(_spa);
        AddFamily(huginn);
        AddFamily(huginn);
        var revokedEarlier = AddFamily(AddClient("mail", [], backchannel: "https://mail.example.com/backchannel"));
        revokedEarlier.Revoke(FamilyRevocationReason.ReuseDetected, Now.AddMinutes(-1));

        await EndSession(cookie, ("id_token_hint", Hint));

        // D34: a client whose family a reuse revoked can still hold its own session, so it gets a logout too.
        Assert.Equal(2, _store.Queued.Count);
        Assert.Contains(_store.Queued, q => q.ClientPk == huginn.Id && q.Sid == Sid && q.UserId == _user.Id);
        Assert.Equal("2", _audit.Events.Single(e => e.Type == AuditEventTypes.SessionRevoked).Data["backchannel_queued"]);
    }

    [Fact]
    public async Task Hint_without_a_registered_uri_ends_the_session_and_shows_the_signed_out_page()
    {
        var cookie = SignedIn();
        RegisterHint();

        var outcome = await EndSession(cookie, ("id_token_hint", Hint));

        Assert.Same(LogoutSignedOut.Instance, outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Hint_with_the_matching_client_id_counts()
    {
        var cookie = SignedIn();
        RegisterHint();

        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("client_id", "spa"), ("post_logout_redirect_uri", Bye));

        Assert.Equal(new LogoutRedirect(Bye, null), outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
    }

    // ---- Every other case needs the user's click (D31, logout CSRF)

    [Fact]
    public async Task No_hint_asks_the_user_and_keeps_the_target()
    {
        var cookie = SignedIn();
        AddFamily(_spa);

        var outcome = await EndSession(cookie, ("client_id", "spa"), ("post_logout_redirect_uri", Bye), ("state", "xyz"));

        Assert.Equal(new LogoutConfirm(new LogoutTarget(_spa.Id, Bye, "xyz")), outcome);
        Assert.Null(SessionOf(cookie).RevokedAt);
        Assert.Equal(0, _store.Calls);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Hint_of_one_session_ends_every_live_session_of_the_list()
    {
        // The endpoint deletes the cookie after a sign-out, so no session of the list may stay live behind it.
        var bob = User.Create(Guid.CreateVersion7(), _tenant.Id, "bob@example.com", "hash", Now.AddDays(-1));
        _users.Add(bob);
        var bobCookie = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(bobCookie), OtherSid, _tenant.Id, bob.Id, TimeSpan.FromHours(12), Now));
        var cookie = SignedIn();
        var bobFamily = TokenFamily.Start(Guid.CreateVersion7(), _tenant.Id, _spa.Id, bob.Id, Guid.CreateVersion7(), "openid", Lifetimes, Now, sid: OtherSid);
        _tokens.Families.Add(bobFamily);
        RegisterHint();

        // The hint names the first entry of the list, not the latest sign-in.
        var outcome = await EndSession(cookie + "." + bobCookie, ("id_token_hint", Hint));

        Assert.IsType<LogoutSignedOut>(outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
        Assert.NotNull(SessionOf(bobCookie).RevokedAt);
        Assert.NotNull(bobFamily.RevokedAt);
    }

    [Fact]
    public async Task Confirmed_sign_out_ends_every_live_session_of_the_list()
    {
        var bob = User.Create(Guid.CreateVersion7(), _tenant.Id, "bob@example.com", "hash", Now.AddDays(-1));
        _users.Add(bob);
        var bobCookie = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(bobCookie), OtherSid, _tenant.Id, bob.Id, TimeSpan.FromHours(12), Now));
        var cookie = SignedIn();

        await _service.ConfirmAsync(Context, bobCookie + "." + cookie, null, CancellationToken.None);

        Assert.NotNull(SessionOf(cookie).RevokedAt);
        Assert.NotNull(SessionOf(bobCookie).RevokedAt);
    }

    [Fact]
    public async Task Hint_of_an_older_session_asks_the_user()
    {
        var cookie = SignedIn();
        RegisterHint(sid: OtherSid);

        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye));

        Assert.Equal(new LogoutConfirm(new LogoutTarget(_spa.Id, Bye, null)), outcome);
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Hint_without_a_sid_asks_the_user()
    {
        var cookie = SignedIn();
        RegisterHint(sid: null);

        Assert.IsType<LogoutConfirm>(await EndSession(cookie, ("id_token_hint", Hint)));
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Hint_of_another_user_with_the_same_sid_asks_the_user()
    {
        var cookie = SignedIn();
        RegisterHint(subject: Guid.CreateVersion7().ToString());

        Assert.IsType<LogoutConfirm>(await EndSession(cookie, ("id_token_hint", Hint)));
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Forged_hint_names_nobody_and_asks_the_user()
    {
        var cookie = SignedIn();

        var outcome = await EndSession(cookie, ("id_token_hint", "forged"), ("post_logout_redirect_uri", Bye));

        // The hint does not count, so it names no client, and the URI has no client to be registered for.
        Assert.Equal(new LogoutConfirm(null), outcome);
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Hint_from_another_issuer_names_nobody()
    {
        var cookie = SignedIn();
        RegisterHint(issuer: "https://other.example.com");

        Assert.Equal(new LogoutConfirm(null), await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye)));
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Theory]
    [InlineData("unknown-client")]
    [InlineData(null)]
    public async Task Hint_for_no_single_client_of_the_tenant_names_nobody(string? audience)
    {
        var cookie = SignedIn();
        RegisterHint(audience: audience);

        Assert.Equal(new LogoutConfirm(null), await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye)));
    }

    [Fact]
    public async Task Hint_with_two_audiences_names_nobody()
    {
        var cookie = SignedIn();
        _hints.Hints[Hint] = new VerifiedIdTokenHint(Issuer, _user.Id.ToString(), ["spa", "huginn"], Sid);

        Assert.Equal(new LogoutConfirm(null), await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye)));
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Forged_hint_with_a_client_id_still_finds_the_client()
    {
        var cookie = SignedIn();

        var outcome = await EndSession(cookie, ("id_token_hint", "forged"), ("client_id", "spa"), ("post_logout_redirect_uri", Bye));

        Assert.Equal(new LogoutConfirm(new LogoutTarget(_spa.Id, Bye, null)), outcome);
    }

    // ---- No session: nothing to end, nothing to confirm (D31)

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-session")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Without_a_session_the_browser_goes_back_at_once(string? cookie)
    {
        var outcome = await EndSession(cookie, ("client_id", "spa"), ("post_logout_redirect_uri", Bye), ("state", "s1"));

        Assert.Equal(new LogoutRedirect(Bye, "s1"), outcome);
        Assert.Equal(0, _store.Calls);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Without_a_session_or_a_client_the_browser_sees_the_signed_out_page() =>
        Assert.Same(LogoutSignedOut.Instance, await EndSession(null));

    [Fact]
    public async Task Ended_session_counts_as_none()
    {
        var cookie = SignedIn();
        SessionOf(cookie).Revoke(Now.AddMinutes(-1));

        Assert.Equal(new LogoutRedirect(Bye, null), await EndSession(cookie, ("client_id", "spa"), ("post_logout_redirect_uri", Bye)));
        Assert.Equal(0, _store.Calls);
    }

    // ---- The redirect goes only to a registered URI of an active client (D32)

    [Theory]
    [InlineData("https://evil.example.com/")]
    [InlineData("https://app.example.com/bye/")]
    [InlineData("https://app.example.com/BYE")]
    [InlineData(Callback)]
    public async Task Unregistered_uri_gives_the_signed_out_page(string uri) =>
        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("client_id", "spa"), ("post_logout_redirect_uri", uri)));

    [Fact]
    public async Task Unknown_client_gives_the_same_signed_out_page() =>
        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("client_id", "nobody"), ("post_logout_redirect_uri", Bye)));

    [Fact]
    public async Task Uri_without_any_client_gives_the_signed_out_page() =>
        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("post_logout_redirect_uri", Bye)));

    [Fact]
    public async Task Uri_of_another_client_is_not_registered_for_this_one()
    {
        AddClient("huginn", ["https://huginn.example.com/bye"]);

        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("client_id", "spa"), ("post_logout_redirect_uri", "https://huginn.example.com/bye")));
    }

    [Fact]
    public async Task Pending_client_gets_no_redirect()
    {
        AddClient("pending", ["https://pending.example.com/bye"], active: false);

        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("client_id", "pending"), ("post_logout_redirect_uri", "https://pending.example.com/bye")));
    }

    [Fact]
    public async Task Empty_values_count_as_missing() =>
        Assert.Same(LogoutSignedOut.Instance, await EndSession(null, ("client_id", ""), ("post_logout_redirect_uri", ""), ("state", ""), ("id_token_hint", "")));

    [Fact]
    public async Task Empty_state_is_no_state() =>
        Assert.Equal(new LogoutRedirect(Bye, null), await EndSession(null, ("client_id", "spa"), ("post_logout_redirect_uri", Bye), ("state", "")));

    [Fact]
    public async Task State_of_the_limit_returns_unchanged()
    {
        var state = new string('s', LogoutService.MaxStateLength);

        Assert.Equal(new LogoutRedirect(Bye, state), await EndSession(null, ("client_id", "spa"), ("post_logout_redirect_uri", Bye), ("state", state)));
    }

    // ---- Malformed requests: an error page, no sign-out, no redirect

    [Fact]
    public async Task State_over_the_limit_is_an_error()
    {
        var cookie = SignedIn();
        RegisterHint();

        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye), ("state", new string('s', LogoutService.MaxStateLength + 1)));

        Assert.Equal(new LogoutErrorPage(OAuthError.InvalidRequestCode, "state too long"), outcome);
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Client_id_that_differs_from_the_hint_is_an_error()
    {
        var cookie = SignedIn();
        RegisterHint();
        AddClient("huginn", ["https://huginn.example.com/bye"]);

        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("client_id", "huginn"), ("post_logout_redirect_uri", "https://huginn.example.com/bye"));

        Assert.Equal(new LogoutErrorPage(OAuthError.InvalidRequestCode, "client_id differs from the aud of id_token_hint"), outcome);
        Assert.Null(SessionOf(cookie).RevokedAt);
    }

    // ---- The confirmation (POST /session/v1/logout)

    [Fact]
    public async Task Confirm_ends_the_session_and_goes_to_the_target()
    {
        var cookie = SignedIn();
        var family = AddFamily(_spa);

        var outcome = await _service.ConfirmAsync(Context, cookie, new LogoutTarget(_spa.Id, Bye, "xyz"), CancellationToken.None);

        Assert.Equal(new LogoutRedirect(Bye, "xyz"), outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
        Assert.NotNull(family.RevokedAt);
        var revoked = _audit.Events.Single(e => e.Type == AuditEventTypes.SessionRevoked);
        Assert.Equal("user_confirmed", revoked.Data["reason"]);
        Assert.Equal("spa", revoked.Data["client_id"]);
    }

    [Fact]
    public async Task Confirm_without_a_target_ends_the_session_and_names_no_client()
    {
        var cookie = SignedIn();

        var outcome = await _service.ConfirmAsync(Context, cookie, null, CancellationToken.None);

        Assert.Same(LogoutSignedOut.Instance, outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
        Assert.False(_audit.Events.Single(e => e.Type == AuditEventTypes.SessionRevoked).Data.ContainsKey("client_id"));
    }

    [Fact]
    public async Task Confirm_checks_the_uri_again()
    {
        var cookie = SignedIn();
        _spa.UpdateLogoutUris([], null);

        var outcome = await _service.ConfirmAsync(Context, cookie, new LogoutTarget(_spa.Id, Bye, null), CancellationToken.None);

        Assert.Same(LogoutSignedOut.Instance, outcome);
        Assert.NotNull(SessionOf(cookie).RevokedAt);
    }

    [Fact]
    public async Task Confirm_checks_the_client_again()
    {
        var cookie = SignedIn();
        _spa.Disable();

        Assert.Same(LogoutSignedOut.Instance, await _service.ConfirmAsync(Context, cookie, new LogoutTarget(_spa.Id, Bye, null), CancellationToken.None));
    }

    [Fact]
    public async Task Confirm_for_an_unknown_client_goes_nowhere() =>
        Assert.Same(LogoutSignedOut.Instance, await _service.ConfirmAsync(Context, null, new LogoutTarget(Guid.CreateVersion7(), Bye, null), CancellationToken.None));

    [Fact]
    public async Task Confirm_without_a_session_still_goes_back()
    {
        var outcome = await _service.ConfirmAsync(Context, null, new LogoutTarget(_spa.Id, Bye, "s"), CancellationToken.None);

        Assert.Equal(new LogoutRedirect(Bye, "s"), outcome);
        Assert.Equal(0, _store.Calls);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Sign_out_that_loses_the_race_writes_nothing()
    {
        var cookie = SignedIn();
        RegisterHint();

        // A concurrent request ended the row after this request validated the session.
        _store.LoseNextEnd = true;
        var outcome = await EndSession(cookie, ("id_token_hint", Hint), ("post_logout_redirect_uri", Bye));

        Assert.Equal(new LogoutRedirect(Bye, null), outcome);
        Assert.Equal(1, _store.Calls);
        Assert.Empty(_audit.Events);
    }
}
