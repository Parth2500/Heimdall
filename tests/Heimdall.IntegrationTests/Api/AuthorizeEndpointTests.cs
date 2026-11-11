using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// <c>/authorize</c> over HTTP, with a real login session. Each test maps to a rule of RFC 6749 section 4.1,
/// RFC 7636, RFC 9207, RFC 9700, or the threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class AuthorizeEndpointTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // RFC 7636, appendix B: the challenge of the verifier above.
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public AuthorizeEndpointTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Setup(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            await Api.DisposeAsync();
        }
    }

    private async Task<Setup> SetUpAsync(bool signIn = true, bool requireConsent = false)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, requireConsent: requireConsent);
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        if (signIn)
        {
            using var login = await browser.LoginAsync(Email, Password);
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        return new Setup(api, tenant, browser);
    }

    private static string AuthorizeUrl(params (string Name, string Value)[] overrides)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid profile",
            ["state"] = "xyz-state",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };
        foreach (var (name, value) in overrides)
        {
            parameters[name] = value;
        }

        return QueryHelpers.AddQueryString("oauth/v1/authorize", parameters.Where(p => p.Value is not null));
    }

    /// <summary>The query of a redirect Location, as a dictionary.</summary>
    private static Dictionary<string, string> QueryOf(HttpResponseMessage response, out string target)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        var question = location.IndexOf('?', StringComparison.Ordinal);
        target = question < 0 ? location : location[..question];
        return QueryHelpers.ParseQuery(question < 0 ? string.Empty : location[question..])
            .ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);
    }

    private static Task AssertErrorPageAsync(HttpResponseMessage response, string error)
    {
        // Never a redirect to the client: the client or redirect URI is not proven valid. Heimdall's own page only (U6).
        var query = QueryOf(response, out var target);
        Assert.Equal("/account/error", target);
        Assert.Equal(new Dictionary<string, string> { ["error"] = error }, query);
        return Task.CompletedTask;
    }

    [DockerFact]
    public async Task Signed_in_user_gets_a_code_with_state_and_iss()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());

        var query = QueryOf(response, out var target);
        Assert.Equal(Callback, target);
        Assert.Equal("xyz-state", query["state"]);
        Assert.Equal(setup.Tenant.Issuer, query["iss"]);
        Assert.Equal(43, query["code"].Length);
        Assert.True(response.Headers.CacheControl?.NoStore);

        // Only the hash is stored, with the checked request values.
        await using var scope = setup.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(setup.Tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var code = await db.AuthorizationCodes.AsNoTracking().SingleAsync();
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(query["code"])), code.CodeHash.ToArray());
        Assert.Equal(Callback, code.RedirectUri);
        Assert.Equal("openid profile", code.Scope);
        Assert.Equal(Challenge, code.CodeChallenge);
        Assert.Equal(code.CreatedAt + TimeSpan.FromMinutes(5), code.ExpiresAt);
        Assert.Null(code.RedeemedAt);
        Assert.True(await db.AuditEvents.AnyAsync(e => e.TenantId == setup.Tenant.Tenant.Id && e.Type == AuditEventTypes.CodeIssued));
    }

    [DockerFact]
    public async Task No_session_sends_the_browser_to_login_and_resume_returns_only_to_the_stored_request()
    {
        await using var setup = await SetUpAsync(signIn: false);

        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());
        var loginQuery = QueryOf(first, out var loginPath);
        Assert.Equal("/account/login", loginPath);
        Assert.Equal(["request_id"], loginQuery.Keys);

        using var login = await setup.Browser.LoginAsync(Email, Password);
        using var resumed = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={loginQuery["request_id"]}");

        var query = QueryOf(resumed, out var target);
        Assert.Equal(Callback, target);
        Assert.Equal("xyz-state", query["state"]);
        Assert.True(query.ContainsKey("code"));

        // One stored request gives one code.
        using var again = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={loginQuery["request_id"]}");
        await AssertErrorPageAsync(again, "invalid_request");
    }

    [DockerFact]
    public async Task Concurrent_resumes_of_one_request_give_one_code()
    {
        await using var setup = await SetUpAsync(signIn: false);
        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());
        var requestId = QueryOf(first, out _)["request_id"];
        using var login = await setup.Browser.LoginAsync(Email, Password);

        var responses = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ =>
            setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}")));

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.Found, r.StatusCode));
        Assert.Equal(5, responses.Count(r => r.Headers.Location!.OriginalString.StartsWith("/account/error?", StringComparison.Ordinal)));
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [DockerFact]
    public async Task Unknown_client_is_an_error_page()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("client_id", "no-such-client")));

        await AssertErrorPageAsync(response, "invalid_client");
    }

    [DockerTheory]
    [InlineData("https://app.example.com/callback/")]
    [InlineData("https://app.example.com/callback?x=1")]
    [InlineData("https://APP.example.com/callback")]
    [InlineData("https://app.example.com.attacker.example/callback")]
    [InlineData("https://attacker.example/callback")]
    public async Task Redirect_uri_that_is_not_an_exact_match_is_never_redirected_to(string redirectUri)
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("redirect_uri", redirectUri)));

        await AssertErrorPageAsync(response, "invalid_request");
    }

    [DockerFact]
    public async Task Missing_redirect_uri_uses_the_only_registered_one()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("redirect_uri", null!)));

        QueryOf(response, out var target);
        Assert.Equal(Callback, target);
    }

    [DockerFact]
    public async Task Repeated_parameter_is_an_error_page()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl() + "&scope=openid");

        await AssertErrorPageAsync(response, "invalid_request");
    }

    public static TheoryData<string, string?, string> RedirectedErrors => new()
    {
        { "response_type", "token", "unsupported_response_type" },
        { "code_challenge_method", null, "invalid_request" },
        { "code_challenge_method", "plain", "invalid_request" },
        { "code_challenge", "too-short", "invalid_request" },
        { "code_challenge", null, "invalid_request" },
        { "scope", "openid admin", "invalid_scope" },
        { "scope", null, "invalid_scope" },
        { "response_mode", "fragment", "invalid_request" },
        { "prompt", "none login", "invalid_request" },
        { "max_age", "-1", "invalid_request" },
    };

    [DockerTheory]
    [MemberData(nameof(RedirectedErrors))]
    public async Task Errors_after_the_redirect_check_go_to_the_client_with_state_and_iss(string name, string? value, string error)
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl((name, value!)));

        var query = QueryOf(response, out var target);
        Assert.Equal(Callback, target);
        Assert.Equal(error, query["error"]);
        Assert.Equal("xyz-state", query["state"]);
        Assert.Equal(setup.Tenant.Issuer, query["iss"]);
        Assert.False(query.ContainsKey("code"));
        Assert.False(query.ContainsKey("error_description"));
    }

    [DockerFact]
    public async Task Prompt_none_without_a_session_returns_login_required()
    {
        await using var setup = await SetUpAsync(signIn: false);

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "none")));

        Assert.Equal("login_required", QueryOf(response, out _)["error"]);
    }

    [DockerFact]
    public async Task Prompt_none_with_a_session_returns_a_code()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "none")));

        Assert.True(QueryOf(response, out _).ContainsKey("code"));
    }

    [DockerFact]
    public async Task Prompt_login_needs_a_sign_in_after_the_request()
    {
        await using var setup = await SetUpAsync();

        // A session exists, but it is older than the request.
        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "login")));
        var requestId = QueryOf(first, out var path)["request_id"];
        Assert.Equal("/account/login", path);

        using var stillOld = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}");
        QueryOf(stillOld, out var stillLogin);
        Assert.Equal("/account/login", stillLogin);

        setup.Api.Time.Advance(TimeSpan.FromSeconds(1));
        using var login = await setup.Browser.LoginAsync(Email, Password);
        using var resumed = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}");
        Assert.True(QueryOf(resumed, out _).ContainsKey("code"));
    }

    [DockerFact]
    public async Task Max_age_sends_an_old_sign_in_back_to_login()
    {
        await using var setup = await SetUpAsync();
        setup.Api.Time.Advance(TimeSpan.FromMinutes(10));

        using var tooOld = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("max_age", "300")));
        using var fresh = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("max_age", "900")));

        QueryOf(tooOld, out var path);
        Assert.Equal("/account/login", path);
        Assert.True(QueryOf(fresh, out _).ContainsKey("code"));
    }

    [DockerFact]
    public async Task Client_that_requires_consent_goes_to_the_consent_page()
    {
        await using var setup = await SetUpAsync(requireConsent: true);

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());

        var query = QueryOf(response, out var path);
        Assert.Equal("/account/consent", path);
        Assert.Equal(["request_id"], query.Keys);
    }

    [DockerFact]
    public async Task Stored_request_of_one_tenant_cannot_be_resumed_at_another()
    {
        await using var setup = await SetUpAsync(signIn: false);
        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());
        var requestId = QueryOf(first, out _)["request_id"];

        var other = await setup.Api.AddTenantAsync();
        await setup.Api.AddUserAsync(other, Email, Password);
        using var otherBrowser = new BrowserSession(setup.Api, other.Host);
        using var login = await otherBrowser.LoginAsync(Email, Password);

        using var response = await otherBrowser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}");
        await AssertErrorPageAsync(response, "invalid_request");
    }

    [DockerFact]
    public async Task Expired_request_cannot_be_resumed()
    {
        await using var setup = await SetUpAsync(signIn: false);
        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());
        var requestId = QueryOf(first, out _)["request_id"];

        setup.Api.Time.Advance(TimeSpan.FromMinutes(10));
        using var login = await setup.Browser.LoginAsync(Email, Password);
        using var response = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}");

        await AssertErrorPageAsync(response, "invalid_request");
    }

    [DockerFact]
    public async Task Verifier_and_challenge_constants_match_RFC_7636()
    {
        // Guards the constants the other tests and the next step (redemption) depend on.
        await Task.CompletedTask;
        Assert.Equal(Challenge, Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))));
    }

    // ---- Several accounts in one browser (#41, D51 to D53)

    private static async Task<string> CodeEmailAsync(Setup setup, string code)
    {
        await using var scope = setup.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(setup.Tenant.Tenant.Id);
        var db = scope.ServiceProvider.GetRequiredService<HeimdallDbContext>();
        var hash = Heimdall.Domain.Common.TokenHash.Compute(code);
        var userId = (await db.AuthorizationCodes.AsNoTracking().SingleAsync(c => c.CodeHash == hash)).UserId;
        return (await db.Users.AsNoTracking().SingleAsync(u => u.Id == userId)).Email;
    }

    private static async Task AddBobAsync(Setup setup)
    {
        await setup.Api.AddUserAsync(setup.Tenant, "bob@example.com", Password);
        using var login = await setup.Browser.LoginAsync("bob@example.com", Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
    }

    [DockerFact]
    public async Task Two_accounts_and_no_hint_send_the_browser_to_the_account_picker()
    {
        await using var setup = await SetUpAsync();
        await AddBobAsync(setup);

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl());

        var query = QueryOf(response, out var path);
        Assert.Equal("/account/select-account", path);
        Assert.Equal(["request_id"], query.Keys);
    }

    [DockerFact]
    public async Task Two_accounts_and_prompt_none_give_account_selection_required()
    {
        await using var setup = await SetUpAsync();
        await AddBobAsync(setup);

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "none")));

        var query = QueryOf(response, out var target);
        Assert.Equal(Callback, target);
        Assert.Equal("account_selection_required", query["error"]);
        Assert.Equal(setup.Tenant.Issuer, query["iss"]);
    }

    [DockerFact]
    public async Task Login_hint_chooses_between_two_accounts_and_is_stored_for_the_sign_in_page()
    {
        await using var setup = await SetUpAsync();
        await AddBobAsync(setup);

        using var alice = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("login_hint", Email), ("prompt", "none")));
        Assert.Equal(Email, await CodeEmailAsync(setup, QueryOf(alice, out _)["code"]));

        using var bob = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("login_hint", "BOB@example.com")));
        Assert.Equal("bob@example.com", await CodeEmailAsync(setup, QueryOf(bob, out _)["code"]));

        // An account that is not signed in, or does not exist: the sign-in page, with the hint in the stored request.
        using var carol = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("login_hint", "carol@example.com")));
        var requestId = QueryOf(carol, out var path)["request_id"];
        Assert.Equal("/account/login", path);
        await using var scope = setup.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(setup.Tenant.Tenant.Id);
        var stored = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuthorizationRequests.AsNoTracking()
            .SingleAsync(r => r.Id == Guid.Parse(requestId));
        Assert.Equal("carol@example.com", stored.LoginHint);
    }

    [DockerFact]
    public async Task Sign_in_as_another_account_during_the_request_gets_the_code_for_that_account()
    {
        await using var setup = await SetUpAsync();
        using var first = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "select_account")));
        var requestId = QueryOf(first, out var path)["request_id"];
        Assert.Equal("/account/select-account", path);

        setup.Api.Time.Advance(TimeSpan.FromSeconds(1));
        await AddBobAsync(setup);
        using var resumed = await setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={requestId}");

        Assert.Equal("bob@example.com", await CodeEmailAsync(setup, QueryOf(resumed, out _)["code"]));
    }

    [DockerFact]
    public async Task Forged_id_token_hint_is_refused()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("id_token_hint", "eyJhbGciOiJSUzI1NiJ9.e30.AAAA")));

        Assert.Equal("invalid_request", QueryOf(response, out _)["error"]);
    }

    [DockerFact]
    public async Task Prompt_select_account_is_accepted()
    {
        await using var setup = await SetUpAsync(signIn: false);

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, AuthorizeUrl(("prompt", "select_account")));

        // No session in the list: nothing to pick from, so the sign-in page.
        QueryOf(response, out var path);
        Assert.Equal("/account/login", path);
    }
}
