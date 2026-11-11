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

public class AuthorizationServiceTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Callback = "https://app.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryAuthorizationStore _store = new();
    private readonly InMemoryUserStore _users;
    private readonly InMemorySessionStore _sessions;
    private readonly RecordingAuditLog _audit = new();
    private readonly FakeIdTokenHintValidator _hints = new();
    private readonly AuthorizationService _service;
    private readonly Client _spa;
    private readonly User _user;

    public AuthorizationServiceTests()
    {
        _users = new InMemoryUserStore();
        _sessions = new InMemorySessionStore { Users = _users };
        var authenticator = new UserAuthenticator(
            _users, new FakePasswordHasher(), new InMemoryLoginThrottleStore(), new LoginThrottleOptions(), _audit, _time);
        var sessions = new SessionService(authenticator, _sessions, _audit, _time);
        _service = new AuthorizationService(_clients, _store, sessions, _hints, _audit, _time);
        _spa = AddClient("spa");
        _user = User.Create(Guid.CreateVersion7(), _tenant.Id, "alice@example.com", "hash", Now.AddDays(-1));
        _users.Add(_user);
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private Client AddClient(
        string clientId,
        string[]? redirectUris = null,
        bool requireConsent = false,
        GrantType[]? grants = null)
    {
        var client = Client.Create(
            Guid.CreateVersion7(),
            _tenant.Id,
            clientId,
            "Single-page app",
            ClientType.Public,
            grants ?? [GrantType.AuthorizationCode, GrantType.RefreshToken],
            ["openid", "profile", "offline_access"],
            redirectUris ?? [Callback],
            requireConsent,
            overrides: null,
            Now);
        client.Approve();
        _clients.Add(client);
        return client;
    }

    /// <summary>A session that signed in at <paramref name="authTime"/>. Returns the cookie value.</summary>
    private string SignedIn(DateTimeOffset? authTime = null, User? user = null, string sid = "sid-for-tests-00000000")
    {
        var id = Base64Url.EncodeToString(Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray());
        _sessions.Add(Session.Start(TokenHash.Compute(id), sid, _tenant.Id, (user ?? _user).Id, TimeSpan.FromHours(12), authTime ?? Now));
        return id;
    }

    private const string BobSid = "sid-of-bob-00000000000";

    private User AddBob()
    {
        var bob = User.Create(Guid.CreateVersion7(), _tenant.Id, "bob@example.com", "hash", Now.AddDays(-1));
        _users.Add(bob);
        return bob;
    }

    /// <summary>Alice and Bob in one browser. Returns the cookie value and Bob.</summary>
    private (string Cookie, User Bob) TwoAccounts()
    {
        var bob = AddBob();
        return (SignedIn() + "." + SignedIn(user: bob, sid: BobSid), bob);
    }

    private void RegisterHint(string token, User user, string audience = "spa", string issuer = Issuer) =>
        _hints.Hints[token] = new Heimdall.Application.Logout.VerifiedIdTokenHint(issuer, user.Id.ToString(), [audience], "sid-for-tests-00000000");

    private Guid CodeUser() => Assert.Single(_store.Codes).UserId;

    private static Dictionary<string, string> Valid(params (string Name, string? Value)[] changes)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = "spa",
            ["redirect_uri"] = Callback,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["state"] = "af0ifjsldkj",
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };
        foreach (var (name, value) in changes)
        {
            if (value is null)
            {
                parameters.Remove(name);
            }
            else
            {
                parameters[name] = value;
            }
        }

        return parameters;
    }

    private Task<AuthorizeOutcome> Authorize(Dictionary<string, string> parameters, string? sessionId = null) =>
        _service.AuthorizeAsync(Context, parameters, sessionId, CancellationToken.None);

    private Task<AuthorizeOutcome> Resume(string? requestId, string? sessionId) =>
        _service.ResumeAsync(Context, requestId, sessionId, CancellationToken.None);

    private static void AssertPage(AuthorizeOutcome outcome, string error, string reason)
    {
        var page = Assert.IsType<AuthorizeErrorPage>(outcome);
        Assert.Equal(error, page.Error);
        Assert.Equal(reason, page.Reason);
    }

    private static void AssertErrorRedirect(AuthorizeOutcome outcome, string error, string reason, string? state = "af0ifjsldkj")
    {
        var redirect = Assert.IsType<AuthorizeRedirect>(outcome);
        Assert.Equal(Callback, redirect.RedirectUri);
        Assert.Equal(reason, redirect.Reason);
        var expected = new List<KeyValuePair<string, string>> { new("error", error) };
        if (state is not null)
        {
            expected.Add(new("state", state));
        }

        expected.Add(new("iss", Issuer));
        Assert.Equal(expected, redirect.Parameters);
    }

    private static string CodeOf(AuthorizeOutcome outcome)
    {
        var redirect = Assert.IsType<AuthorizeRedirect>(outcome);
        Assert.Null(redirect.Reason);
        Assert.Equal(Callback, redirect.RedirectUri);
        var code = Assert.Single(redirect.Parameters, p => p.Key == "code").Value;
        Assert.Equal(Issuer, Assert.Single(redirect.Parameters, p => p.Key == "iss").Value);
        return code;
    }

    // 1. Errors before the client and the redirect URI are proven: shown by Heimdall, never redirected.

    [Fact]
    public async Task Suspended_tenant_gets_an_error_page()
    {
        _tenant.Suspend();

        AssertPage(await Authorize(Valid()), OAuthError.InvalidRequestCode, "tenant suspended");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Missing_client_id_gets_an_error_page(string? clientId)
    {
        AssertPage(await Authorize(Valid(("client_id", clientId))), OAuthError.InvalidRequestCode, "client_id missing");
    }

    [Fact]
    public async Task Unknown_client_gets_an_error_page()
    {
        AssertPage(await Authorize(Valid(("client_id", "no-such-client"))), OAuthError.InvalidClientCode, "unknown client");
    }

    [Fact]
    public async Task Disabled_client_gets_an_error_page()
    {
        _spa.Disable();

        AssertPage(await Authorize(Valid()), OAuthError.InvalidClientCode, "client status Disabled");
    }

    [Theory]
    [InlineData("https://app.example.com/callback/")]
    [InlineData("https://APP.example.com/callback")]
    [InlineData("https://app.example.com/callback?x=1")]
    [InlineData("https://evil.example.com/callback")]
    public async Task Redirect_uri_that_is_not_an_exact_match_gets_an_error_page(string redirectUri)
    {
        AssertPage(
            await Authorize(Valid(("redirect_uri", redirectUri))),
            OAuthError.InvalidRequestCode,
            "redirect_uri not registered (exact match)");
    }

    [Fact]
    public async Task Missing_redirect_uri_uses_the_only_registered_one()
    {
        var outcome = await Authorize(Valid(("redirect_uri", null)));

        Assert.IsType<AuthorizeLogin>(outcome);
        Assert.Equal(Callback, Assert.Single(_store.Requests).RedirectUri);
    }

    [Fact]
    public async Task Missing_redirect_uri_with_several_registered_gets_an_error_page()
    {
        AddClient("two-uris", [Callback, "https://app.example.com/other"]);

        AssertPage(
            await Authorize(Valid(("client_id", "two-uris"), ("redirect_uri", null))),
            OAuthError.InvalidRequestCode,
            "redirect_uri missing");
    }

    // 2. Errors after that point go to the registered redirect URI, with state and iss.

    [Fact]
    public async Task State_of_the_maximum_length_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("state", new string('s', AuthorizationRequest.MaxClientValueLength)))));
    }

    [Fact]
    public async Task Oversized_state_is_not_echoed_back()
    {
        var outcome = await Authorize(Valid(("state", new string('s', AuthorizationRequest.MaxClientValueLength + 1))));

        AssertErrorRedirect(outcome, OAuthError.InvalidRequestCode, "state too long", state: null);
    }

    [Fact]
    public async Task Error_without_state_has_only_error_and_iss()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("state", null), ("response_type", "token"))),
            "unsupported_response_type",
            "response_type is not code",
            state: null);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("token")]
    [InlineData("code id_token")]
    public async Task Response_type_other_than_code_is_refused(string? responseType)
    {
        AssertErrorRedirect(await Authorize(Valid(("response_type", responseType))), "unsupported_response_type", "response_type is not code");
    }

    [Fact]
    public async Task Response_mode_query_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("response_mode", "query"))));
    }

    [Theory]
    [InlineData("fragment")]
    [InlineData("form_post")]
    public async Task Other_response_modes_are_refused(string mode)
    {
        AssertErrorRedirect(await Authorize(Valid(("response_mode", mode))), OAuthError.InvalidRequestCode, "response_mode not supported");
    }

    [Fact]
    public async Task Request_object_is_refused()
    {
        AssertErrorRedirect(await Authorize(Valid(("request", "eyJ..."))), "request_not_supported", "request object");
    }

    // ---- Pushed authorization requests (RFC 9126, D40 to D43)

    private const string OtherJkt = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    private Task<Result<PushedRequest>> Push(Dictionary<string, string> parameters, Client? client = null, string? proofKey = null) =>
        _service.PushAsync(Context, client ?? _spa, parameters, proofKey, CancellationToken.None);

    private static Dictionary<string, string> WithRequestUri(string requestUri, string clientId = "spa") =>
        new() { ["client_id"] = clientId, ["request_uri"] = requestUri };

    [Fact]
    public async Task Push_stores_the_checked_request_for_a_minute()
    {
        var result = await Push(Valid(("prompt", "login")));

        Assert.True(result.IsSuccess);
        Assert.StartsWith(AuthorizationService.RequestUriPrefix, result.Value.RequestUri, StringComparison.Ordinal);
        Assert.Equal(AuthorizationService.RequestUriPrefix.Length + 43, result.Value.RequestUri.Length);
        Assert.Equal(60, result.Value.ExpiresIn);

        var stored = Assert.Single(_store.Requests);
        Assert.Equal(TokenHash.Compute(result.Value.RequestUri), stored.RequestUriHash);
        Assert.Equal(Now.AddSeconds(60), stored.ExpiresAt);
        Assert.Equal(Callback, stored.RedirectUri);
        Assert.Equal("af0ifjsldkj", stored.State);
        Assert.True(stored.ForceLogin);
        Assert.False(stored.PromptNone);
    }

    [Fact]
    public async Task Each_push_gets_a_new_request_uri()
    {
        var first = await Push(Valid());
        var second = await Push(Valid());

        Assert.NotEqual(first.Value.RequestUri, second.Value.RequestUri);
    }

    [Fact]
    public async Task Pushed_request_gives_a_code_once()
    {
        var requestUri = (await Push(Valid())).Value.RequestUri;
        var session = SignedIn();

        var outcome = await Authorize(WithRequestUri(requestUri), session);

        Assert.Equal(43, CodeOf(outcome).Length);
        Assert.Equal("af0ifjsldkj", ((AuthorizeRedirect)outcome).Parameters[1].Value);
        Assert.Empty(_store.Requests);
        AssertPage(await Authorize(WithRequestUri(requestUri), session), OAuthError.InvalidRequestCode, "request_uri unknown, used, expired, or of another client");
    }

    [Fact]
    public async Task Pushed_request_waits_for_the_sign_in_and_resumes_by_its_id()
    {
        var requestUri = (await Push(Valid())).Value.RequestUri;

        var login = Assert.IsType<AuthorizeLogin>(await Authorize(WithRequestUri(requestUri)));

        // D42: taken once. The hash is gone, and the request lives for the sign-in pages.
        var stored = Assert.Single(_store.Requests);
        Assert.Null(stored.RequestUriHash);
        Assert.Equal(Now + AuthorizationRequest.Lifetime, stored.ExpiresAt);
        Assert.Equal(stored.Id, login.RequestId);
        Assert.Equal(43, CodeOf(await Resume(login.RequestId.ToString(), SignedIn())).Length);
    }

    [Fact]
    public async Task Pushed_request_cannot_be_resumed_before_authorize_takes_it()
    {
        await Push(Valid());

        AssertPage(await Resume(_store.Requests[0].Id.ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Parameters_in_the_address_change_nothing()
    {
        AddClient("evil", ["https://evil.example.com/cb"]);
        var requestUri = (await Push(Valid())).Value.RequestUri;
        var parameters = WithRequestUri(requestUri);
        parameters["redirect_uri"] = "https://evil.example.com/cb";
        parameters["scope"] = "openid profile offline_access";
        parameters["state"] = "changed";

        var redirect = Assert.IsType<AuthorizeRedirect>(await Authorize(parameters, SignedIn()));

        Assert.Equal(Callback, redirect.RedirectUri);
        Assert.Equal("af0ifjsldkj", redirect.Parameters[1].Value);
        Assert.Equal("openid profile", Assert.Single(_store.Codes).Scope);
    }

    [Fact]
    public async Task Request_uri_expires_after_a_minute()
    {
        var requestUri = (await Push(Valid())).Value.RequestUri;
        _time.Advance(AuthorizationRequest.PushedLifetime);

        AssertPage(await Authorize(WithRequestUri(requestUri), SignedIn()), OAuthError.InvalidRequestCode, "request_uri unknown, used, expired, or of another client");
    }

    [Fact]
    public async Task Request_uri_of_another_client_finds_nothing_and_does_not_burn_it()
    {
        AddClient("other");
        var requestUri = (await Push(Valid())).Value.RequestUri;

        AssertPage(await Authorize(WithRequestUri(requestUri, "other"), SignedIn()), OAuthError.InvalidRequestCode, "request_uri unknown, used, expired, or of another client");
        Assert.Equal(43, CodeOf(await Authorize(WithRequestUri(requestUri), SignedIn())).Length);
    }

    [Theory]
    [InlineData("https://evil.example.com/request")]
    [InlineData("urn:ietf:params:oauth:request_uri")]
    public async Task Request_uri_that_Heimdall_never_issues_is_refused_before_the_store(string requestUri)
    {
        AssertPage(await Authorize(WithRequestUri(requestUri)), OAuthError.InvalidRequestCode, "request_uri malformed");
        Assert.Equal(0, _store.Takes);
    }

    [Fact]
    public async Task Request_uri_of_128_characters_reaches_the_store()
    {
        var requestUri = AuthorizationService.RequestUriPrefix + new string('a', 128 - AuthorizationService.RequestUriPrefix.Length);

        AssertPage(await Authorize(WithRequestUri(requestUri)), OAuthError.InvalidRequestCode, "request_uri unknown, used, expired, or of another client");
        Assert.Equal(1, _store.Takes);
    }

    [Fact]
    public async Task Push_with_an_empty_client_id_uses_the_authenticated_client() =>
        Assert.True((await Push(Valid(("client_id", "")))).IsSuccess);

    [Fact]
    public async Task Oversized_request_uri_is_refused_before_the_store()
    {
        AssertPage(await Authorize(WithRequestUri(AuthorizationService.RequestUriPrefix + new string('a', 100))), OAuthError.InvalidRequestCode, "request_uri malformed");
        Assert.Equal(0, _store.Takes);
    }

    [Fact]
    public async Task Request_uri_still_needs_a_known_client()
    {
        var requestUri = (await Push(Valid())).Value.RequestUri;

        AssertPage(await Authorize(WithRequestUri(requestUri, "nobody")), OAuthError.InvalidClientCode, "unknown client");
    }

    [Fact]
    public async Task Redirect_uri_removed_after_the_push_is_refused()
    {
        var client = AddClient("shrinking", [Callback, "https://app.example.com/other"]);
        var requestUri = (await Push(Valid(("client_id", "shrinking")), client)).Value.RequestUri;
        typeof(Client).GetField("_redirectUris", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .SetValue(client, new List<string> { "https://app.example.com/other" });

        AssertPage(await Authorize(WithRequestUri(requestUri, "shrinking"), SignedIn()), OAuthError.InvalidClientCode, "redirect_uri removed after the push");
    }

    [Fact]
    public async Task Pushed_prompt_none_without_a_session_is_login_required()
    {
        var requestUri = (await Push(Valid(("prompt", "none")))).Value.RequestUri;

        AssertErrorRedirect(await Authorize(WithRequestUri(requestUri)), "login_required", "prompt=none without a usable session");
    }

    [Theory]
    [InlineData("scope", "openid admin", OAuthError.InvalidScopeCode)]
    [InlineData("redirect_uri", "https://evil.example.com/cb", OAuthError.InvalidRequestCode)]
    [InlineData("response_type", "token", "unsupported_response_type")]
    [InlineData("code_challenge_method", "plain", OAuthError.InvalidRequestCode)]
    [InlineData("request", "eyJ...", "request_not_supported")]
    public async Task Push_refuses_what_authorize_refuses_and_stores_nothing(string name, string value, string error)
    {
        var result = await Push(Valid((name, value)));

        Assert.Equal(error, result.Error!.Code);
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Push_keeps_the_reason_for_the_log()
    {
        Assert.Equal("scope not allowed for client", (await Push(Valid(("scope", "openid admin")))).Error!.AuditDetail);
        Assert.Equal("redirect_uri not registered (exact match)", (await Push(Valid(("redirect_uri", "https://evil.example.com/cb")))).Error!.AuditDetail);
    }

    [Fact]
    public async Task Push_cannot_carry_a_request_uri()
    {
        var result = await Push(Valid(("request_uri", AuthorizationService.RequestUriPrefix + "x")));

        Assert.Equal(new OAuthError(OAuthError.InvalidRequestCode, "request_uri in a pushed request"), result.Error);
    }

    [Fact]
    public async Task Push_client_id_must_name_the_authenticated_client()
    {
        AddClient("other");

        var result = await Push(Valid(("client_id", "other")));

        Assert.Equal(new OAuthError(OAuthError.InvalidRequestCode, "client_id differs from the authenticated client"), result.Error);
    }

    [Fact]
    public async Task Push_without_a_client_id_uses_the_authenticated_client()
    {
        Assert.True((await Push(Valid(("client_id", null)))).IsSuccess);
        Assert.Equal(_spa.Id, Assert.Single(_store.Requests).ClientPk);
    }

    [Fact]
    public async Task Push_for_a_suspended_tenant_is_invalid_client()
    {
        _tenant.Suspend();

        Assert.Equal(OAuthError.InvalidClientCode, (await Push(Valid())).Error!.Code);
    }

    [Fact]
    public async Task Proof_at_the_push_binds_the_code_like_dpop_jkt()
    {
        await Push(Valid(), proofKey: DpopJkt);

        Assert.Equal(DpopJkt, Assert.Single(_store.Requests).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Proof_and_dpop_jkt_of_the_same_key_are_accepted()
    {
        Assert.True((await Push(Valid(("dpop_jkt", DpopJkt)), proofKey: DpopJkt)).IsSuccess);
    }

    [Fact]
    public async Task Proof_and_dpop_jkt_of_two_keys_are_refused()
    {
        var result = await Push(Valid(("dpop_jkt", DpopJkt)), proofKey: OtherJkt);

        Assert.Equal(new OAuthError(OAuthError.InvalidDpopProofCode, "DPoP proof key differs from dpop_jkt"), result.Error);
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Browser_request_ignores_no_proof_key()
    {
        // At /authorize a proof cannot exist. Only dpop_jkt binds the code there.
        CodeOf(await Authorize(Valid(), SignedIn()));

        Assert.Null(Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Client_that_requires_par_gets_an_error_without_a_request_uri()
    {
        _spa.RequirePushedRequests(true);

        AssertErrorRedirect(await Authorize(Valid(), SignedIn()), OAuthError.InvalidRequestCode, "client requires pushed authorization requests");
    }

    [Fact]
    public async Task Client_that_requires_par_signs_in_with_a_request_uri()
    {
        _spa.RequirePushedRequests(true);
        var requestUri = (await Push(Valid())).Value.RequestUri;

        Assert.Equal(43, CodeOf(await Authorize(WithRequestUri(requestUri), SignedIn())).Length);
    }

    [Fact]
    public async Task Client_without_the_grant_is_unauthorized_client()
    {
        var service = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "billing", "Billing", ClientType.Confidential, [GrantType.ClientCredentials],
            ["openid"], [Callback], requireConsent: false, overrides: null, Now, ["https://api.example.com"]);
        service.Approve();
        _clients.Add(service, ("secret", null));

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "billing"))),
            OAuthError.UnauthorizedClientCode,
            "authorization_code not allowed");
    }

    [Theory]
    [InlineData(null)] // RFC 7636: a missing method means plain.
    [InlineData("plain")]
    [InlineData("s256")]
    public async Task Code_challenge_method_other_than_S256_is_refused(string? method)
    {
        AssertErrorRedirect(
            await Authorize(Valid(("code_challenge_method", method))),
            OAuthError.InvalidRequestCode,
            "code_challenge_method is not S256");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("too-short")]
    public async Task Missing_or_malformed_code_challenge_is_refused(string? challenge)
    {
        AssertErrorRedirect(
            await Authorize(Valid(("code_challenge", challenge))),
            OAuthError.InvalidRequestCode,
            "code_challenge malformed or missing");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("openid \"x\"")]
    public async Task Missing_or_malformed_scope_is_refused(string? scope)
    {
        AssertErrorRedirect(await Authorize(Valid(("scope", scope))), OAuthError.InvalidScopeCode, "scope malformed or missing");
    }

    [Fact]
    public async Task Scope_that_is_not_allowed_is_refused_not_reduced()
    {
        AssertErrorRedirect(await Authorize(Valid(("scope", "openid admin"))), OAuthError.InvalidScopeCode, "scope not allowed for client");
    }

    [Fact]
    public async Task Offline_access_without_the_refresh_grant_is_refused()
    {
        AddClient("no-refresh", grants: [GrantType.AuthorizationCode]);

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "no-refresh"), ("scope", "openid offline_access"))),
            OAuthError.InvalidScopeCode,
            "offline_access without the refresh_token grant");
    }

    [Fact]
    public async Task Offline_access_with_the_refresh_grant_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("scope", "openid offline_access"))));
    }

    [Theory]
    [InlineData("login login")]
    [InlineData("consent unknown")]
    public async Task Unsupported_or_repeated_prompt_is_refused(string prompt)
    {
        AssertErrorRedirect(await Authorize(Valid(("prompt", prompt))), OAuthError.InvalidRequestCode, "prompt not supported");
    }

    [Theory]
    [InlineData("none login")]
    [InlineData("none consent")]
    public async Task Prompt_none_with_another_value_is_refused(string prompt)
    {
        AssertErrorRedirect(await Authorize(Valid(("prompt", prompt))), OAuthError.InvalidRequestCode, "prompt=none with another value");
    }

    [Fact]
    public async Task Prompt_consent_shows_the_consent_page_for_a_client_that_needs_no_consent()
    {
        // OpenID Connect Core, section 11: a client that asks for offline_access sends prompt=consent.
        var outcome = await Authorize(Valid(("prompt", "consent")), SignedIn());

        var consent = Assert.IsType<AuthorizeConsent>(outcome);
        var stored = Assert.Single(_store.Requests);
        Assert.Equal(stored.Id, consent.RequestId);
        Assert.True(stored.ForceConsent);
    }

    [Fact]
    public async Task Prompt_login_consent_asks_for_both()
    {
        var outcome = await Authorize(Valid(("prompt", "login consent")), SignedIn(Now.AddMinutes(-1)));

        Assert.IsType<AuthorizeLogin>(outcome);
        var stored = Assert.Single(_store.Requests);
        Assert.True(stored.ForceLogin);
        Assert.True(stored.ForceConsent);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData(" 5")]
    [InlineData("1.5")]
    [InlineData("99999999999")]
    public async Task Malformed_max_age_is_refused(string maxAge)
    {
        AssertErrorRedirect(await Authorize(Valid(("max_age", maxAge))), OAuthError.InvalidRequestCode, "max_age malformed");
    }

    [Fact]
    public async Task Nonce_of_the_maximum_length_is_accepted()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("nonce", new string('n', AuthorizationRequest.MaxClientValueLength)))));
    }

    [Fact]
    public async Task Oversized_nonce_is_refused()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("nonce", new string('n', AuthorizationRequest.MaxClientValueLength + 1)))),
            OAuthError.InvalidRequestCode,
            "nonce too long");
    }

    [Theory]
    [InlineData("too-short")]
    [InlineData("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4=")]
    [InlineData("0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I")]
    public async Task Malformed_dpop_jkt_is_refused(string dpopJkt)
    {
        AssertErrorRedirect(await Authorize(Valid(("dpop_jkt", dpopJkt))), OAuthError.InvalidRequestCode, "dpop_jkt malformed");
    }

    // 3. A valid request: sign-in, consent, and the code.

    [Fact]
    public async Task Without_a_session_the_request_is_stored_and_the_user_signs_in()
    {
        var outcome = await Authorize(Valid(("scope", "openid profile openid"), ("max_age", "300")));

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeLogin(request.Id), outcome);
        Assert.Equal(_tenant.Id, request.TenantId);
        Assert.Equal(_spa.Id, request.ClientPk);
        Assert.Equal(Callback, request.RedirectUri);
        Assert.Equal("openid profile", request.Scope);
        Assert.Equal("af0ifjsldkj", request.State);
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
        Assert.Equal(Challenge, request.CodeChallenge);
        Assert.False(request.ForceLogin);
        Assert.Equal(TimeSpan.FromMinutes(5), request.MaxAge);
        Assert.Equal(Now, request.CreatedAt);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Signed_in_user_gets_a_code_with_state_and_iss()
    {
        var authTime = Now.AddMinutes(-3);
        var sessionId = SignedIn(authTime);

        var outcome = await Authorize(Valid(), sessionId);

        var code = CodeOf(outcome);
        Assert.Equal(43, code.Length);
        Assert.Equal(
            [new("code", code), new("state", "af0ifjsldkj"), new("iss", Issuer)],
            ((AuthorizeRedirect)outcome).Parameters);

        var stored = Assert.Single(_store.Codes);
        Assert.Equal(TokenHash.Compute(code), stored.CodeHash);
        Assert.Equal(_tenant.Id, stored.TenantId);
        Assert.Equal(_spa.Id, stored.ClientPk);
        Assert.Equal(_user.Id, stored.UserId);
        Assert.Equal(Callback, stored.RedirectUri);
        Assert.Equal("openid profile", stored.Scope);
        Assert.Equal(Challenge, stored.CodeChallenge);
        Assert.Equal("n-0S6_WzA2Mj", stored.Nonce);
        Assert.Equal(Assert.Single(_sessions.Sessions).Sid, stored.Sid);
        Assert.Equal(authTime, stored.AuthTime);
        Assert.Equal(Now, stored.CreatedAt);

        // A signed-in user gets the code at once, so the request is never stored: one save, for the code only.
        Assert.Empty(_store.Requests);
        Assert.Equal(1, _store.SaveCount);

        var issued = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.CodeIssued, issued.Type);
        Assert.Equal(_user.Id, issued.SubjectUserId);
        Assert.Equal(_spa.Id, issued.ClientPk);
        Assert.Equal("corr-1", issued.CorrelationId);
        Assert.Equal(Now, issued.OccurredAt);
        Assert.Equal("spa", issued.Data["client_id"]);
        Assert.Equal("openid profile", issued.Data["scope"]);
    }

    private const string DpopJkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    [Fact]
    public async Task Dpop_jkt_goes_with_the_code_when_the_user_is_signed_in()
    {
        CodeOf(await Authorize(Valid(("dpop_jkt", DpopJkt)), SignedIn()));

        Assert.Equal(DpopJkt, Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Dpop_jkt_is_stored_with_the_request_and_reaches_the_code_after_sign_in()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("dpop_jkt", DpopJkt))));
        var request = Assert.Single(_store.Requests);
        Assert.Equal(DpopJkt, request.DpopKeyThumbprint);

        CodeOf(await Resume(request.Id.ToString(), SignedIn()));

        Assert.Equal(DpopJkt, Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Without_dpop_jkt_the_code_is_not_bound()
    {
        CodeOf(await Authorize(Valid(), SignedIn()));

        Assert.Null(Assert.Single(_store.Codes).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Code_without_state_has_only_code_and_iss()
    {
        var outcome = await Authorize(Valid(("state", null)), SignedIn());

        var code = CodeOf(outcome);
        Assert.Equal([new("code", code), new("iss", Issuer)], ((AuthorizeRedirect)outcome).Parameters);
    }

    [Fact]
    public async Task Each_code_is_new_random_text()
    {
        var sessionId = SignedIn();

        var first = CodeOf(await Authorize(Valid(), sessionId));
        var second = CodeOf(await Authorize(Valid(), sessionId));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task Prompt_none_without_a_session_is_login_required_and_stores_nothing()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("prompt", "none"))),
            "login_required",
            "prompt=none without a usable session");
        Assert.Empty(_store.Requests);
        Assert.Equal(0, _store.SaveCount);
    }

    [Fact]
    public async Task Prompt_none_with_a_session_returns_a_code_without_a_stored_request()
    {
        CodeOf(await Authorize(Valid(("prompt", "none")), SignedIn()));

        Assert.Empty(_store.Requests);
        Assert.Single(_store.Codes);
        Assert.Equal(1, _store.SaveCount);
    }

    [Fact]
    public async Task Prompt_login_asks_again_even_with_a_session()
    {
        var outcome = await Authorize(Valid(("prompt", "login")), SignedIn());

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeLogin(request.Id), outcome);
        Assert.True(request.ForceLogin);
    }

    [Fact]
    public async Task Prompt_login_then_a_new_sign_in_gives_a_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid(("prompt", "login")), SignedIn());
        _time.Advance(TimeSpan.FromSeconds(30));
        var fresh = SignedIn(_time.GetUtcNow());

        CodeOf(await Resume(request.RequestId.ToString(), fresh));
    }

    [Fact]
    public async Task Max_age_asks_again_when_the_sign_in_is_older()
    {
        var sessionId = SignedIn(Now.AddMinutes(-2));

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("max_age", "60")), sessionId));
        CodeOf(await Authorize(Valid(("max_age", "120")), sessionId));
    }

    [Fact]
    public async Task Max_age_zero_always_asks_again()
    {
        _time.Advance(TimeSpan.FromSeconds(1));

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("max_age", "0")), SignedIn(Now)));
    }

    [Fact]
    public async Task Client_that_requires_consent_asks_the_user()
    {
        AddClient("consent-app", requireConsent: true);

        var outcome = await Authorize(Valid(("client_id", "consent-app")), SignedIn());

        var request = Assert.Single(_store.Requests);
        Assert.Equal(new AuthorizeConsent(request.Id), outcome);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Prompt_none_with_required_consent_is_consent_required()
    {
        AddClient("consent-app", requireConsent: true);

        AssertErrorRedirect(
            await Authorize(Valid(("client_id", "consent-app"), ("prompt", "none")), SignedIn()),
            "consent_required",
            "client requires consent");
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Approval_then_resume_issues_the_code()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: true);

        CodeOf(await Resume(request.RequestId.ToString(), sessionId));
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Denial_ends_the_request_with_access_denied()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: false);

        AssertErrorRedirect(await Resume(request.RequestId.ToString(), sessionId), "access_denied", "user denied consent");

        Assert.Empty(_store.Requests);
        Assert.Empty(_store.Codes);
        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Denial_that_loses_a_race_is_request_already_used()
    {
        AddClient("consent-app", requireConsent: true);
        var sessionId = SignedIn();
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), sessionId);
        _store.Requests.Single().DecideConsent(_user.Id, approved: false);
        _store.LoseNextSave = true;

        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request already used");
    }

    [Fact]
    public async Task Decision_of_another_user_does_not_count()
    {
        AddClient("consent-app", requireConsent: true);
        var request = (AuthorizeConsent)await Authorize(Valid(("client_id", "consent-app")), SignedIn());
        _store.Requests.Single().DecideConsent(_user.Id, approved: true);
        var bob = User.Create(Guid.CreateVersion7(), _tenant.Id, "bob@example.com", "hash", Now.AddDays(-1));
        _users.Add(bob);

        var outcome = await Resume(request.RequestId.ToString(), SignedIn(user: bob));

        Assert.Equal(new AuthorizeConsent(request.RequestId), outcome);
    }

    // 4. Resume of a stored request.

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    public async Task Malformed_request_id_gets_an_error_page(string? requestId)
    {
        AssertPage(await Resume(requestId, SignedIn()), OAuthError.InvalidRequestCode, "request_id malformed");
    }

    [Fact]
    public async Task Unknown_request_gets_an_error_page()
    {
        AssertPage(await Resume(Guid.CreateVersion7().ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task Request_works_until_one_tick_before_it_expires()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _time.Advance(AuthorizationRequest.Lifetime - TimeSpan.FromTicks(1));

        CodeOf(await Resume(request.RequestId.ToString(), SignedIn(_time.GetUtcNow())));
    }

    [Fact]
    public async Task Expired_request_gets_an_error_page()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _time.Advance(AuthorizationRequest.Lifetime);

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn(_time.GetUtcNow())), OAuthError.InvalidRequestCode, "request expired");
    }

    [Fact]
    public async Task Resume_without_a_session_returns_to_sign_in()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());

        Assert.Equal(request, await Resume(request.RequestId.ToString(), null));
    }

    [Fact]
    public async Task Resume_after_the_client_was_disabled_gets_an_error_page()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _spa.Disable();

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidClientCode, "client changed during sign-in");
    }

    [Fact]
    public async Task Request_of_another_tenant_is_unknown()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        var stored = _store.Requests.Single();
        _store.Requests.Clear();
        _store.Requests.Add(AuthorizationRequest.Create(
            stored.Id, Guid.CreateVersion7(), stored.ClientPk, stored.RedirectUri, stored.Scope, stored.State, stored.Nonce,
            stored.CodeChallenge, stored.ForceLogin, stored.MaxAge, stored.CreatedAt));

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request unknown or used");
    }

    [Fact]
    public async Task One_request_gives_one_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        var sessionId = SignedIn();
        CodeOf(await Resume(request.RequestId.ToString(), sessionId));

        AssertPage(await Resume(request.RequestId.ToString(), sessionId), OAuthError.InvalidRequestCode, "request unknown or used");
        Assert.Single(_store.Codes);
    }

    [Fact]
    public async Task Resume_that_loses_a_race_gets_request_already_used_and_no_code()
    {
        var request = (AuthorizeLogin)await Authorize(Valid());
        _store.LoseNextSave = true;

        AssertPage(await Resume(request.RequestId.ToString(), SignedIn()), OAuthError.InvalidRequestCode, "request already used");
        Assert.Empty(_store.Codes);
        Assert.Empty(_audit.Events);
    }

    // ---- The account choice (#41, D51 to D53)

    [Fact]
    public async Task One_live_session_and_no_hint_gets_the_code()
    {
        Assert.IsType<AuthorizeRedirect>(await Authorize(Valid(), SignedIn()));
        Assert.Equal(_user.Id, CodeUser());
    }

    [Fact]
    public async Task Several_live_sessions_and_no_hint_show_the_picker()
    {
        var (cookie, _) = TwoAccounts();

        var outcome = await Authorize(Valid(), cookie);

        var picker = Assert.IsType<AuthorizeSelectAccount>(outcome);
        Assert.Equal(Assert.Single(_store.Requests).Id, picker.RequestId);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Prompt_none_with_several_live_sessions_is_account_selection_required()
    {
        var (cookie, _) = TwoAccounts();

        var outcome = await Authorize(Valid(("prompt", "none")), cookie);

        AssertErrorRedirect(outcome, "account_selection_required", "prompt=none with several accounts and no hint");
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task One_ended_session_and_no_live_one_show_the_picker()
    {
        var cookie = SignedIn();
        _sessions.Sessions[0].Revoke(Now);

        Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
    }

    [Fact]
    public async Task One_live_session_beside_an_ended_one_shows_the_picker()
    {
        var (cookie, _) = TwoAccounts();
        _sessions.Sessions[0].Revoke(Now);

        Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
    }

    [Fact]
    public async Task Selection_chooses_the_account_of_the_code()
    {
        var (cookie, _) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));

        var selected = await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, "sid-for-tests-00000000", CancellationToken.None);
        var outcome = await Resume(picker.RequestId.ToString(), cookie);

        Assert.True(selected.IsSuccess);
        Assert.IsType<AuthorizeRedirect>(outcome);
        Assert.Equal(_user.Id, CodeUser());
        var audit = _audit.Events.Single(e => e.Type == AuditEventTypes.AccountSelected);
        Assert.Equal(_user.Id, audit.SubjectUserId);
        Assert.Equal("sid-for-tests-00000000", audit.Data["sid"]);
        Assert.Equal(picker.RequestId.ToString(), audit.Data["request_id"]);
    }

    [Fact]
    public async Task Later_selection_replaces_the_earlier_one()
    {
        var (cookie, bob) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
        await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, "sid-for-tests-00000000", CancellationToken.None);
        await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, BobSid, CancellationToken.None);

        await Resume(picker.RequestId.ToString(), cookie);

        Assert.Equal(bob.Id, CodeUser());
    }

    [Fact]
    public async Task Selection_of_a_session_outside_the_list_is_refused()
    {
        // D52: the sid only selects inside the list that the cookie authenticated. Bob's session is live, but this
        // browser does not hold it.
        var bob = AddBob();
        SignedIn(user: bob, sid: BobSid);
        var cookie = SignedIn();
        var login = Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("prompt", "login")), cookie));

        var selected = await _service.SelectAsync(Context, login.RequestId.ToString(), cookie, BobSid, CancellationToken.None);

        Assert.False(selected.IsSuccess);
        Assert.Null(_store.Requests[0].SelectedSid);
        Assert.DoesNotContain(_audit.Events, e => e.Type == AuditEventTypes.AccountSelected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-sid")]
    public async Task Selection_without_a_listed_sid_is_refused(string? sid)
    {
        var (cookie, _) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));

        Assert.False((await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, sid, CancellationToken.None)).IsSuccess);
    }

    [Fact]
    public async Task Selection_of_an_ended_session_is_refused()
    {
        var (cookie, _) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
        _sessions.Sessions[1].Revoke(Now);

        Assert.False((await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, BobSid, CancellationToken.None)).IsSuccess);
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("0198c2a0-0000-7000-8000-000000000000")]
    public async Task Selection_for_an_unknown_request_is_refused(string requestId)
    {
        var (cookie, _) = TwoAccounts();

        Assert.False((await _service.SelectAsync(Context, requestId, cookie, BobSid, CancellationToken.None)).IsSuccess);
    }

    [Fact]
    public async Task Selection_for_an_expired_request_is_refused()
    {
        var (cookie, _) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
        _time.Advance(AuthorizationRequest.Lifetime);

        Assert.False((await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, BobSid, CancellationToken.None)).IsSuccess);
    }

    [Fact]
    public async Task Selected_session_that_ended_before_the_resume_does_not_count()
    {
        var (cookie, _) = TwoAccounts();
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
        await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, BobSid, CancellationToken.None);
        _sessions.Sessions[1].Revoke(Now);

        // Alice is the one live session now, but one ended account is in the list, so the user chooses again.
        Assert.IsType<AuthorizeSelectAccount>(await Resume(picker.RequestId.ToString(), cookie));
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Selected_session_that_left_the_cookie_does_not_count()
    {
        var bob = AddBob();
        var alice = SignedIn();
        var bobId = SignedIn(user: bob, sid: BobSid);
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), alice + "." + bobId));
        await _service.SelectAsync(Context, picker.RequestId.ToString(), alice + "." + bobId, BobSid, CancellationToken.None);

        // Another browser holds only Alice's session and resumes the request.
        Assert.IsType<AuthorizeRedirect>(await Resume(picker.RequestId.ToString(), alice));
        Assert.Equal(_user.Id, CodeUser());
    }

    [Fact]
    public async Task Prompt_select_account_shows_the_picker_with_one_live_session()
    {
        var cookie = SignedIn();

        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(("prompt", "select_account")), cookie));
        Assert.True(_store.Requests[0].SelectAccount);

        // Only a selection for this request satisfies it.
        Assert.IsType<AuthorizeSelectAccount>(await Resume(picker.RequestId.ToString(), cookie));
        await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, "sid-for-tests-00000000", CancellationToken.None);
        Assert.IsType<AuthorizeRedirect>(await Resume(picker.RequestId.ToString(), cookie));
    }

    [Fact]
    public async Task Prompt_select_account_ignores_the_hints()
    {
        var (cookie, bob) = TwoAccounts();
        RegisterHint("hint", bob);

        var outcome = await Authorize(Valid(("prompt", "select_account"), ("id_token_hint", "hint"), ("login_hint", "bob@example.com")), cookie);

        Assert.IsType<AuthorizeSelectAccount>(outcome);
    }

    [Fact]
    public async Task Prompt_select_account_without_a_session_shows_the_sign_in_page()
    {
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("prompt", "select_account"))));
    }

    [Fact]
    public async Task Prompt_none_with_select_account_is_refused()
    {
        AssertErrorRedirect(await Authorize(Valid(("prompt", "none select_account"))), OAuthError.InvalidRequestCode, "prompt=none with another value");
    }

    [Fact]
    public async Task Login_hint_chooses_the_live_session_of_that_user()
    {
        var (cookie, bob) = TwoAccounts();

        Assert.IsType<AuthorizeRedirect>(await Authorize(Valid(("login_hint", " Bob@Example.com ")), cookie));
        Assert.Equal(bob.Id, CodeUser());
    }

    [Fact]
    public async Task Login_hint_works_with_prompt_none()
    {
        var (cookie, _) = TwoAccounts();

        Assert.IsType<AuthorizeRedirect>(await Authorize(Valid(("login_hint", "alice@example.com"), ("prompt", "none")), cookie));
        Assert.Equal(_user.Id, CodeUser());
    }

    [Fact]
    public async Task Login_hint_without_a_live_session_shows_the_sign_in_page_and_is_stored()
    {
        var (cookie, _) = TwoAccounts();

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("login_hint", "carol@example.com")), cookie));
        Assert.Equal("carol@example.com", _store.Requests[0].LoginHint);
    }

    [Fact]
    public async Task Login_hint_without_a_live_session_and_prompt_none_is_login_required()
    {
        var (cookie, _) = TwoAccounts();

        var outcome = await Authorize(Valid(("login_hint", "carol@example.com"), ("prompt", "none")), cookie);

        // The same answer for an unknown account and for an account that is not signed in (D53).
        AssertErrorRedirect(outcome, "login_required", "prompt=none without a usable session");
    }

    [Theory]
    [InlineData("not an email")]
    [InlineData("alice")]
    [InlineData("@example.com")]
    [InlineData("alice@")]
    [InlineData("a@b@c")]
    [InlineData("alice @example.com")]
    public async Task Login_hint_that_is_no_email_address_is_ignored(string hint)
    {
        Assert.IsType<AuthorizeRedirect>(await Authorize(Valid(("login_hint", hint)), SignedIn()));
    }

    [Fact]
    public async Task Login_hint_longer_than_an_email_address_is_ignored()
    {
        var hint = new string('a', 250) + "@b.io";

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("login_hint", hint))));
        Assert.Null(_store.Requests[0].LoginHint);
        Assert.Equal(254, AuthorizationRequest.MaxLoginHintLength);
        Assert.True(AuthorizationRequest.IsLoginHint(new string('a', 249) + "@b.io"));
    }

    [Fact]
    public async Task Id_token_hint_chooses_the_live_session_of_that_user()
    {
        var (cookie, bob) = TwoAccounts();
        RegisterHint("hint", bob);

        Assert.IsType<AuthorizeRedirect>(await Authorize(Valid(("id_token_hint", "hint"), ("prompt", "none")), cookie));
        Assert.Equal(bob.Id, CodeUser());
        Assert.Equal((_tenant.Id, "hint"), Assert.Single(_hints.Checked));
    }

    [Fact]
    public async Task Id_token_hint_wins_over_login_hint()
    {
        var (cookie, _) = TwoAccounts();
        RegisterHint("hint", _user);

        await Authorize(Valid(("id_token_hint", "hint"), ("login_hint", "bob@example.com")), cookie);

        Assert.Equal(_user.Id, CodeUser());
    }

    [Fact]
    public async Task Id_token_hint_of_a_user_without_a_live_session_never_gives_another_account()
    {
        var bob = AddBob();
        RegisterHint("hint", bob);
        var cookie = SignedIn();

        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", "hint"), ("prompt", "none")), cookie),
            "login_required",
            "prompt=none without a usable session");
        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("id_token_hint", "hint")), cookie));
        Assert.Equal(bob.Id, _store.Requests[0].HintUserId);
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Id_token_hint_that_heimdall_cannot_verify_is_refused()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", "forged")), SignedIn()),
            OAuthError.InvalidRequestCode,
            "id_token_hint not valid for this client");
    }

    [Fact]
    public async Task Id_token_hint_of_another_client_is_refused()
    {
        RegisterHint("hint", _user, audience: "other");

        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", "hint")), SignedIn()),
            OAuthError.InvalidRequestCode,
            "id_token_hint not valid for this client");
    }

    [Fact]
    public async Task Id_token_hint_of_another_issuer_is_refused()
    {
        RegisterHint("hint", _user, issuer: "https://other.example.com");

        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", "hint")), SignedIn()),
            OAuthError.InvalidRequestCode,
            "id_token_hint not valid for this client");
    }

    [Fact]
    public async Task Id_token_hint_with_a_subject_that_is_no_user_id_is_refused()
    {
        _hints.Hints["hint"] = new Heimdall.Application.Logout.VerifiedIdTokenHint(Issuer, "spa", ["spa"], null);

        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", "hint")), SignedIn()),
            OAuthError.InvalidRequestCode,
            "id_token_hint not valid for this client");
    }

    [Fact]
    public async Task Oversized_id_token_hint_is_refused_before_the_signature_check()
    {
        AssertErrorRedirect(
            await Authorize(Valid(("id_token_hint", new string('a', 4097))), SignedIn()),
            OAuthError.InvalidRequestCode,
            "id_token_hint not valid for this client");
        Assert.Empty(_hints.Checked);
    }

    [Fact]
    public async Task Prompt_login_with_several_sessions_shows_the_sign_in_page_not_the_picker()
    {
        var (cookie, _) = TwoAccounts();

        Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("prompt", "login")), cookie));
    }

    [Fact]
    public async Task Selected_session_must_still_satisfy_max_age()
    {
        var bob = AddBob();
        var cookie = SignedIn(Now.AddMinutes(-20)) + "." + SignedIn(user: bob, sid: BobSid);
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(("max_age", "60")), cookie));
        await _service.SelectAsync(Context, picker.RequestId.ToString(), cookie, "sid-for-tests-00000000", CancellationToken.None);

        Assert.IsType<AuthorizeLogin>(await Resume(picker.RequestId.ToString(), cookie));
    }

    [Fact]
    public async Task Choice_reads_the_session_list_once()
    {
        var (cookie, _) = TwoAccounts();
        var queries = _sessions.Queries;

        await Authorize(Valid(("login_hint", "bob@example.com")), cookie);

        Assert.Equal(queries + 1, _sessions.Queries);
    }

    [Fact]
    public async Task Sign_in_during_the_request_is_the_choice()
    {
        // "Use another account" on the picker: the user signs in as Bob on the page of this request.
        var bob = AddBob();
        var alice = SignedIn();
        var carol = User.Create(Guid.CreateVersion7(), _tenant.Id, "carol@example.com", "hash", Now.AddDays(-1));
        _users.Add(carol);
        var cookie = alice + "." + SignedIn(user: carol, sid: "sid-of-carol-000000000");
        var picker = Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
        _time.Advance(TimeSpan.FromSeconds(30));
        cookie += "." + SignedIn(_time.GetUtcNow(), bob, BobSid);

        Assert.IsType<AuthorizeRedirect>(await Resume(picker.RequestId.ToString(), cookie));
        Assert.Equal(bob.Id, CodeUser());
    }

    [Fact]
    public async Task Sign_in_during_the_request_wins_over_login_hint()
    {
        // The hint only fills the email field. The user typed another account.
        var bob = AddBob();
        var login = Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("login_hint", "alice@example.com"))));
        _time.Advance(TimeSpan.FromSeconds(30));

        Assert.IsType<AuthorizeRedirect>(await Resume(login.RequestId.ToString(), SignedIn(_time.GetUtcNow(), bob, BobSid)));
        Assert.Equal(bob.Id, CodeUser());
    }

    [Fact]
    public async Task Sign_in_of_another_user_during_the_request_never_wins_over_id_token_hint()
    {
        var bob = AddBob();
        RegisterHint("hint", _user);
        var login = Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("id_token_hint", "hint"))));
        _time.Advance(TimeSpan.FromSeconds(30));

        Assert.IsType<AuthorizeLogin>(await Resume(login.RequestId.ToString(), SignedIn(_time.GetUtcNow(), bob, BobSid)));
        Assert.Empty(_store.Codes);
    }

    [Fact]
    public async Task Two_sign_ins_during_the_request_show_the_picker()
    {
        var bob = AddBob();
        var login = Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("prompt", "login"))));
        _time.Advance(TimeSpan.FromSeconds(30));
        var cookie = SignedIn(_time.GetUtcNow()) + "." + SignedIn(_time.GetUtcNow(), bob, BobSid);

        Assert.IsType<AuthorizeSelectAccount>(await Resume(login.RequestId.ToString(), cookie));
    }

    [Fact]
    public async Task Sign_in_at_the_instant_of_the_request_is_not_a_choice()
    {
        var (cookie, _) = TwoAccounts();

        // Both sessions have the time of the request. Neither is "after" it.
        Assert.IsType<AuthorizeSelectAccount>(await Authorize(Valid(), cookie));
    }

    [Fact]
    public async Task Explicit_selection_wins_over_a_sign_in_during_the_request()
    {
        var bob = AddBob();
        var alice = SignedIn();
        var login = Assert.IsType<AuthorizeLogin>(await Authorize(Valid(("prompt", "login")), alice));
        _time.Advance(TimeSpan.FromSeconds(30));
        var cookie = SignedIn(_time.GetUtcNow()) + "." + SignedIn(_time.GetUtcNow().AddSeconds(-1), bob, BobSid);
        await _service.SelectAsync(Context, login.RequestId.ToString(), cookie, BobSid, CancellationToken.None);

        Assert.IsType<AuthorizeRedirect>(await Resume(login.RequestId.ToString(), cookie));
        Assert.Equal(bob.Id, CodeUser());
    }
}
