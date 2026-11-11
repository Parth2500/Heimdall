using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// The consent page API (<c>/session/v1/consent</c>) for a client that requires consent. Each test maps to a row of the
/// login, session, and consent table in the threat model.
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class ConsentTests
{
    private const string Email = "alice@example.com";
    private const string OtherEmail = "bob@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public ConsentTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Setup(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, string RequestId) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            await Api.DisposeAsync();
        }
    }

    /// <summary>Signs in and sends /authorize for a client that requires consent. Returns the stored request ID.</summary>
    private async Task<Setup> SetUpAsync(bool requireConsent = true, string? prompt = null)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, requireConsent: requireConsent);
        await api.AddUserAsync(tenant, Email, Password);
        await api.AddUserAsync(tenant, OtherEmail, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using (var login = await browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        var url = QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["redirect_uri"] = Callback,
            ["scope"] = "openid profile",
            ["state"] = "xyz-state",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
            ["prompt"] = prompt,
        });
        string requestId;
        using (var authorize = await browser.SendAsync(HttpMethod.Get, url))
        {
            Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
            requestId = QueryOf(authorize, out _).GetValueOrDefault("request_id") ?? string.Empty;
        }

        return new Setup(api, tenant, browser, requestId);
    }

    private static Dictionary<string, string> QueryOf(HttpResponseMessage response, out string path)
    {
        var location = response.Headers.Location!.OriginalString;
        var question = location.IndexOf('?', StringComparison.Ordinal);
        path = question < 0 ? location : location[..question];
        return question < 0
            ? []
            : QueryHelpers.ParseQuery(location[question..]).ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal);
    }

    private static Task<HttpResponseMessage> DecideAsync(Setup setup, bool approve, string? requestId = null, bool withXsrf = true) =>
        setup.Browser.SendAsync(
            HttpMethod.Post,
            "session/v1/consent",
            JsonContent.Create(new { request_id = requestId ?? setup.RequestId, approve }),
            withXsrf);

    private static Task<HttpResponseMessage> ResumeAsync(Setup setup) =>
        setup.Browser.SendAsync(HttpMethod.Get, $"oauth/v1/authorize/resume?request_id={setup.RequestId}");

    private static async Task<int> AuditCountAsync(Setup setup, string type)
    {
        await using var scope = setup.Api.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .CountAsync(e => e.TenantId == setup.Tenant.Tenant.Id && e.Type == type);
    }

    [DockerFact]
    public async Task Prompt_shows_only_stored_and_registered_values()
    {
        await using var setup = await SetUpAsync();

        using var response = await setup.Browser.SendAsync(HttpMethod.Get, $"session/v1/consent?request_id={setup.RequestId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("web-app", body.GetProperty("client_id").GetString());
        Assert.Equal("Web app", body.GetProperty("client_name").GetString());
        Assert.Equal(["openid", "profile"], body.GetProperty("scopes").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal("app.example.com", body.GetProperty("redirect_host").GetString());
    }

    [DockerFact]
    public async Task Approval_then_resume_issues_the_code()
    {
        await using var setup = await SetUpAsync();

        using var decision = await DecideAsync(setup, approve: true);
        using var resume = await ResumeAsync(setup);

        Assert.Equal(HttpStatusCode.NoContent, decision.StatusCode);
        var query = QueryOf(resume, out var path);
        Assert.Equal(Callback, path);
        Assert.True(query.ContainsKey("code"));
        Assert.Equal("xyz-state", query["state"]);
        Assert.Equal(1, await AuditCountAsync(setup, AuditEventTypes.ConsentGranted));
    }

    [DockerFact]
    public async Task Prompt_consent_asks_also_for_a_client_that_needs_no_consent()
    {
        // OpenID Connect Core, section 3.1.2.1. The flag round-trips through the stored request.
        await using var setup = await SetUpAsync(requireConsent: false, prompt: "consent");

        using var resumeBefore = await ResumeAsync(setup);
        using var decision = await DecideAsync(setup, approve: true);
        using var resume = await ResumeAsync(setup);

        QueryOf(resumeBefore, out var pathBefore);
        Assert.Equal("/account/consent", pathBefore);
        Assert.Equal(HttpStatusCode.NoContent, decision.StatusCode);
        var query = QueryOf(resume, out var path);
        Assert.Equal(Callback, path);
        Assert.True(query.ContainsKey("code"));
    }

    [DockerFact]
    public async Task Denial_then_resume_returns_access_denied_and_ends_the_request()
    {
        await using var setup = await SetUpAsync();

        using var decision = await DecideAsync(setup, approve: false);
        using var resume = await ResumeAsync(setup);
        using var approveLater = await DecideAsync(setup, approve: true);
        using var resumeAgain = await ResumeAsync(setup);

        var query = QueryOf(resume, out var path);
        Assert.Equal(Callback, path);
        Assert.Equal("access_denied", query["error"]);
        Assert.Equal("xyz-state", query["state"]);
        Assert.Equal(setup.Tenant.Issuer, query["iss"]);
        Assert.False(query.ContainsKey("code"));

        // The denial ended the request: a later approval cannot turn it into a code.
        Assert.Equal(HttpStatusCode.BadRequest, approveLater.StatusCode);
        Assert.Equal("/account/error?error=invalid_request", resumeAgain.Headers.Location?.OriginalString);
        Assert.Equal(1, await AuditCountAsync(setup, AuditEventTypes.ConsentDenied));
    }

    [DockerFact]
    public async Task Decision_of_one_user_does_not_count_for_another_user()
    {
        await using var setup = await SetUpAsync();
        using (var approve = await DecideAsync(setup, approve: true))
        {
            Assert.Equal(HttpStatusCode.NoContent, approve.StatusCode);
        }

        // A second user signs in on the same browser before the resume.
        using (var login = await setup.Browser.LoginAsync(OtherEmail, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        using var resume = await ResumeAsync(setup);

        // Two live sessions and no choice for this request: the user picks the account first (D51). The approval of the
        // first user gives no code.
        QueryOf(resume, out var path);
        Assert.Equal("/account/select-account", path);
    }

    [DockerFact]
    public async Task Decision_needs_the_antiforgery_token_and_the_tenant_origin()
    {
        await using var setup = await SetUpAsync();

        using var noXsrf = await DecideAsync(setup, approve: true, withXsrf: false);
        setup.Browser.Origin = "https://evil.example.com";
        using var foreignOrigin = await DecideAsync(setup, approve: true);
        setup.Browser.Origin = setup.Tenant.Issuer;
        using var resume = await ResumeAsync(setup);

        Assert.Equal(HttpStatusCode.Forbidden, noXsrf.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, foreignOrigin.StatusCode);
        QueryOf(resume, out var path);
        Assert.Equal("/account/consent", path);
    }

    [DockerFact]
    public async Task Without_a_session_the_page_gets_login_required()
    {
        await using var setup = await SetUpAsync();
        using (var logout = await setup.Browser.LogoutAsync())
        {
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        }

        using var prompt = await setup.Browser.SendAsync(HttpMethod.Get, $"session/v1/consent?request_id={setup.RequestId}");
        using var decision = await DecideAsync(setup, approve: true);

        Assert.Equal(HttpStatusCode.Unauthorized, prompt.StatusCode);
        Assert.Equal("""{"error":"login_required"}""", await prompt.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, decision.StatusCode);
    }

    [DockerFact]
    public async Task Unknown_request_or_missing_decision_is_invalid_request()
    {
        await using var setup = await SetUpAsync();

        using var unknown = await DecideAsync(setup, approve: true, requestId: Guid.NewGuid().ToString());
        using var noDecision = await setup.Browser.SendAsync(
            HttpMethod.Post,
            "session/v1/consent",
            JsonContent.Create(new { request_id = setup.RequestId }));

        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, noDecision.StatusCode);
    }

    [DockerFact]
    public async Task Client_without_required_consent_cannot_use_the_consent_api()
    {
        await using var setup = await SetUpAsync(requireConsent: false);

        // A browser with no session gets a stored request, then signs in.
        using var browser = new BrowserSession(setup.Api, setup.Tenant.Host);
        string requestId;
        using (var authorize = await browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "web-app",
            ["scope"] = "openid",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        })))
        {
            requestId = QueryOf(authorize, out var path)["request_id"];
            Assert.Equal("/account/login", path);
        }

        using (var login = await browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        using var prompt = await browser.SendAsync(HttpMethod.Get, $"session/v1/consent?request_id={requestId}");

        Assert.Equal(HttpStatusCode.BadRequest, prompt.StatusCode);
    }
}
