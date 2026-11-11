using System.Buffers.Text;
using System.Net;
using Heimdall.Application.Authorization;
using Heimdall.Application.Common;
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

public class ConsentServiceTests
{
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryAuthorizationStore _store = new();
    private readonly InMemoryUserStore _users;
    private readonly InMemorySessionStore _sessions;
    private readonly RecordingAuditLog _audit = new();
    private readonly ConsentService _service;
    private readonly Client _app;
    private readonly User _user;
    private readonly AuthorizationRequest _request;
    private readonly string _sessionId;

    public ConsentServiceTests()
    {
        _users = new InMemoryUserStore();
        _sessions = new InMemorySessionStore { Users = _users };
        var authenticator = new UserAuthenticator(
            _users, new FakePasswordHasher(), new InMemoryLoginThrottleStore(), new LoginThrottleOptions(), _audit, _time);
        var sessions = new SessionService(authenticator, _sessions, _audit, _time);
        _service = new ConsentService(_clients, _store, sessions, _audit, _time);
        _app = AddClient("huginn", requireConsent: true);
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now.AddDays(-1));
        _users.Add(_user);
        _request = StoreRequest(_app);
        _sessionId = SignedIn(Now);
    }

    private RequestContext Context => new(_tenant, "https://acme.example.com", "corr-1", IPAddress.Parse("203.0.113.7"));

    private Client AddClient(string clientId, bool requireConsent)
    {
        var client = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, clientId, "Huginn chat", ClientType.Public, [GrantType.AuthorizationCode],
            ["openid", "profile", "email"], ["https://chat.example.com/callback"], requireConsent, overrides: null, Now);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    private AuthorizationRequest StoreRequest(
        Client client, bool forceLogin = false, TimeSpan? maxAge = null, bool forceConsent = false, TokenHash? requestUriHash = null)
    {
        var request = AuthorizationRequest.Create(
            Guid.CreateVersion7(), _tenant.Id, client.Id, "https://chat.example.com/callback", "openid email", "state", null,
            Challenge, forceLogin, maxAge, Now, requestUriHash: requestUriHash, forceConsent: forceConsent);
        _store.Requests.Add(request);
        return request;
    }

    private string SignedIn(DateTimeOffset authTime)
    {
        var id = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(id), "sid-for-tests-00000000", _tenant.Id, _user.Id, TimeSpan.FromHours(12), authTime));
        return id;
    }

    private Task<Result<ConsentPrompt>> Prompt(string? requestId = null, string? sessionId = null) =>
        _service.GetPromptAsync(Context, requestId ?? _request.Id.ToString(), sessionId ?? _sessionId, CancellationToken.None);

    private Task<Result<bool>> Decide(bool approve, string? requestId = null, string? sessionId = null) =>
        _service.DecideAsync(Context, requestId ?? _request.Id.ToString(), sessionId ?? _sessionId, approve, CancellationToken.None);

    private static void AssertError<T>(Result<T> result, string code, string reason)
    {
        Assert.False(result.IsSuccess);
        Assert.Equal(code, result.Error!.Code);
        Assert.Equal(reason, result.Error.AuditDetail);
    }

    [Fact]
    public async Task Prompt_shows_the_client_the_scopes_and_the_redirect_host()
    {
        var prompt = (await Prompt()).Value;

        Assert.Equal("huginn", prompt.ClientId);
        Assert.Equal("Huginn chat", prompt.ClientName);
        Assert.Equal(["openid", "email"], prompt.Scopes);
        Assert.Equal("chat.example.com", prompt.RedirectHost);
    }

    [Fact]
    public async Task Approval_is_recorded_for_this_user_and_audited()
    {
        var result = await Decide(approve: true);

        Assert.True(result.Value);
        Assert.True(_request.ConsentDecisionOf(_user.Id));
        Assert.Equal(1, _store.SaveCount);
        var granted = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.ConsentGranted, granted.Type);
        Assert.Equal(_user.Id, granted.ActorUserId);
        Assert.Equal(_user.Id, granted.SubjectUserId);
        Assert.Equal(_app.Id, granted.ClientPk);
        Assert.Equal("corr-1", granted.CorrelationId);
        Assert.Equal("huginn", granted.Data["client_id"]);
        Assert.Equal("openid email", granted.Data["scope"]);
    }

    [Fact]
    public async Task Denial_is_recorded_and_audited_too()
    {
        var result = await Decide(approve: false);

        Assert.False(result.Value);
        Assert.False(_request.ConsentDecisionOf(_user.Id));
        Assert.Equal(AuditEventTypes.ConsentDenied, Assert.Single(_audit.Events).Type);
    }

    [Fact]
    public async Task Decision_that_loses_a_race_is_request_already_used()
    {
        _store.LoseNextSave = true;

        AssertError(await Decide(approve: true), OAuthError.InvalidRequestCode, "request already used");
        Assert.Empty(_audit.Events);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Without_a_session_the_user_must_sign_in(string? sessionId)
    {
        var result = await _service.GetPromptAsync(Context, _request.Id.ToString(), sessionId, CancellationToken.None);

        AssertError(result, ConsentService.LoginRequiredCode, "no session that satisfies the request");
        AssertError(
            await _service.DecideAsync(Context, _request.Id.ToString(), sessionId, true, CancellationToken.None),
            ConsentService.LoginRequiredCode,
            "no session that satisfies the request");
        Assert.Null(_request.ConsentDecisionOf(_user.Id));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-guid")]
    public async Task Malformed_request_id_is_invalid_request(string requestId)
    {
        AssertError(await Prompt(requestId), OAuthError.InvalidRequestCode, "request_id malformed");
    }

    [Fact]
    public async Task Unknown_request_is_invalid_request()
    {
        AssertError(await Prompt(Guid.CreateVersion7().ToString()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Request_works_until_one_tick_before_it_expires()
    {
        _time.Advance(AuthorizationRequest.Lifetime - TimeSpan.FromTicks(1));

        Assert.True((await Prompt()).IsSuccess);
    }

    [Fact]
    public async Task Expired_request_is_invalid_request()
    {
        _time.Advance(AuthorizationRequest.Lifetime);

        AssertError(await Decide(approve: true), OAuthError.InvalidRequestCode, "request expired");
        Assert.Null(_request.ConsentDecisionOf(_user.Id));
    }

    [Fact]
    public async Task Prompt_login_request_needs_a_newer_sign_in()
    {
        // The same session rules as the resume step, so the consent page cannot skip prompt=login.
        var request = StoreRequest(_app, forceLogin: true);

        AssertError(
            await Decide(approve: true, request.Id.ToString()),
            ConsentService.LoginRequiredCode,
            "no session that satisfies the request");
        Assert.Null(request.ConsentDecisionOf(_user.Id));

        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.True((await Decide(approve: true, request.Id.ToString(), SignedIn(_time.GetUtcNow()))).IsSuccess);
    }

    [Fact]
    public async Task Disabled_client_is_refused()
    {
        _app.Disable();

        AssertError(await Prompt(), OAuthError.InvalidRequestCode, "client inactive or needs no consent");
    }

    [Fact]
    public async Task Client_that_needs_no_consent_is_refused()
    {
        var request = StoreRequest(AddClient("trusted", requireConsent: false));

        AssertError(await Decide(approve: true, request.Id.ToString()), OAuthError.InvalidRequestCode, "client inactive or needs no consent");
    }

    [Fact]
    public async Task Prompt_consent_request_of_a_client_that_needs_no_consent_is_decided()
    {
        // prompt=consent asks for the page also when the client does not require consent.
        var request = StoreRequest(AddClient("trusted", requireConsent: false), forceConsent: true);

        Assert.True((await Prompt(request.Id.ToString())).IsSuccess);
        Assert.True((await Decide(approve: true, request.Id.ToString())).IsSuccess);
        Assert.True(request.ConsentDecisionOf(_user.Id));
    }

    [Fact]
    public async Task Pushed_request_that_authorize_has_not_taken_is_unknown()
    {
        // D42: the request_id of a pushed request has no consent page until /authorize takes the request_uri.
        var request = StoreRequest(_app, requestUriHash: TokenHash.Compute("urn:ietf:params:oauth:request_uri:x"));

        AssertError(await Decide(approve: true, request.Id.ToString()), OAuthError.InvalidRequestCode, "request unknown or used");
        Assert.Null(request.ConsentDecisionOf(_user.Id));
    }
}
