using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Heimdall.Api.Endpoints;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Heimdall.IntegrationTests.Api;

/// <summary>The login API and the session cookie. Each test maps to a row of the login table in the threat model.</summary>
[Collection(PostgresGroup.Name)]
public sealed class SessionEndpointTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";

    private readonly PostgresFixture _postgres;

    public SessionEndpointTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private static async Task<string?> ErrorOf(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("error").GetString();
    }

    private static async Task<List<Heimdall.Domain.Sessions.Session>> SessionsAsync(HeimdallApiFactory api, TestTenant tenant)
    {
        await using var scope = api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Sessions.AsNoTracking().OrderBy(s => s.CreatedAt).ToListAsync();
    }

    private async Task<(HeimdallApiFactory Api, TestTenant Tenant)> SetUpAsync()
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddUserAsync(tenant, Email, Password);
        return (api, tenant);
    }

    [DockerFact]
    public async Task Login_sets_a_host_only_HttpOnly_Lax_session_cookie()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);

        using var response = await browser.LoginAsync(Email, Password);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = browser.LastSetCookies[SessionEndpoints.SessionCookie].ToLowerInvariant();
        Assert.Contains("httponly", cookie, StringComparison.Ordinal);
        Assert.Contains("secure", cookie, StringComparison.Ordinal);
        Assert.Contains("samesite=lax", cookie, StringComparison.Ordinal);
        Assert.Contains("path=/", cookie, StringComparison.Ordinal);
        Assert.DoesNotContain("domain=", cookie, StringComparison.Ordinal);
        Assert.DoesNotContain("expires=", cookie, StringComparison.Ordinal);
        Assert.Equal(43, browser.SessionId?.Length);

        using var me = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        using var body = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.Equal(Email, body.RootElement.GetProperty("email").GetString());
    }

    [DockerFact]
    public async Task Database_stores_only_the_hash_of_the_session_id()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var response = await browser.LoginAsync(Email, Password);

        await using var scope = api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
        var session = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().Sessions.AsNoTracking().SingleAsync();

        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(browser.SessionId!)), session.IdHash.ToArray());
        var started = await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .SingleAsync(e => e.TenantId == tenant.Tenant.Id && e.Type == AuditEventTypes.SessionStarted);
        Assert.Equal(Convert.ToHexStringLower(session.IdHash.AsSpan()), started.Data["session_hash"]);
        Assert.DoesNotContain(browser.SessionId!, JsonSerializer.Serialize(started.Data), StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task Unknown_email_and_wrong_password_get_the_same_answer()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);

        using var unknown = await browser.LoginAsync("nobody@example.com", Password);
        using var wrong = await browser.LoginAsync(Email, "wrong password here");

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(await unknown.Content.ReadAsStringAsync(), await wrong.Content.ReadAsStringAsync());
        Assert.Equal("invalid_credentials", await ErrorOf(wrong));
        Assert.Null(browser.SessionId);
    }

    [DockerFact]
    public async Task Login_without_the_antiforgery_header_is_refused()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);

        using var response = await browser.LoginAsync(Email, Password, withXsrf: false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(browser.SessionId);
    }

    [DockerFact]
    public async Task Login_from_a_foreign_origin_is_refused()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        await browser.GetCsrfAsync();
        browser.Origin = "https://attacker.example";

        using var response = await browser.LoginAsync(Email, Password);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(browser.SessionId);
    }

    [DockerFact]
    public async Task Login_with_a_form_body_is_refused()
    {
        // A cross-site HTML form can send only form or text bodies, never JSON.
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        await browser.GetCsrfAsync();

        using var response = await browser.SendAsync(
            HttpMethod.Post,
            "session/v1/login",
            new FormUrlEncodedContent([new("email", Email), new("password", Password)]));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Null(browser.SessionId);
    }

    [DockerFact]
    public async Task New_sign_in_ends_the_old_session()
    {
        // D13, session fixation: an ID known before sign-in is worthless after it.
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var first = await browser.LoginAsync(Email, Password);
        var oldId = browser.SessionId!;

        using var second = await browser.LoginAsync(Email, Password);

        Assert.NotEqual(oldId, browser.SessionId);
        using var replay = new BrowserSession(api, tenant.Host);
        replay.Cookies[SessionEndpoints.SessionCookie] = oldId;
        using var me = await replay.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [DockerFact]
    public async Task Sign_in_again_keeps_the_sid_and_replaces_the_session_id()
    {
        // The account picker design, P4: one conditional UPDATE replaces the key of the row.
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var first = await browser.LoginAsync(Email, Password);
        var before = await SessionsAsync(api, tenant);

        using var second = await browser.LoginAsync(Email, Password);

        var after = Assert.Single(await SessionsAsync(api, tenant));
        Assert.Equal(Assert.Single(before).Sid, after.Sid);
        Assert.NotEqual(before[0].IdHash, after.IdHash);
        Assert.Equal(Heimdall.Domain.Common.TokenHash.Compute(browser.SessionId!), after.IdHash);
        Assert.True(after.AuthTime >= before[0].AuthTime);
        Assert.Null(after.RevokedAt);
        using var me = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [DockerFact]
    public async Task Two_accounts_sign_in_to_one_browser()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        await api.AddUserAsync(tenant, "bob@example.com", Password);
        using var browser = new BrowserSession(api, tenant.Host);
        using var first = await browser.LoginAsync(Email, Password);
        var aliceId = browser.SessionId!;

        using var second = await browser.LoginAsync("bob@example.com", Password);

        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
        var ids = browser.SessionId!.Split('.');
        Assert.Equal(2, ids.Length);
        Assert.Equal(aliceId, ids[0]);
        var sessions = await SessionsAsync(api, tenant);
        Assert.Equal(2, sessions.Count);
        Assert.All(sessions, s => Assert.Null(s.RevokedAt));

        // The session of the latest sign-in answers, until /authorize chooses by selection (#41, next step).
        using var me = await browser.MeAsync();
        using var json = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
        Assert.Equal("bob@example.com", json.RootElement.GetProperty("email").GetString());

        // Each ID alone is still one valid session.
        using var alone = new BrowserSession(api, tenant.Host);
        alone.Cookies[SessionEndpoints.SessionCookie] = aliceId;
        using var aliceMe = await alone.MeAsync();
        using var aliceJson = JsonDocument.Parse(await aliceMe.Content.ReadAsStringAsync());
        Assert.Equal(Email, aliceJson.RootElement.GetProperty("email").GetString());
    }

    [DockerFact]
    public async Task Sixth_account_is_refused_and_the_cookie_stays()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        for (var i = 0; i < 5; i++)
        {
            await api.AddUserAsync(tenant, $"user{i}@example.com", Password);
            using var login = await browser.LoginAsync($"user{i}@example.com", Password);
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }

        var cookie = browser.SessionId!;

        using var sixth = await browser.LoginAsync(Email, Password);

        Assert.Equal(HttpStatusCode.Conflict, sixth.StatusCode);
        Assert.Equal("session_limit", await ErrorOf(sixth));
        Assert.Equal(cookie, browser.SessionId);
        Assert.Equal(5, (await SessionsAsync(api, tenant)).Count);
    }

    [DockerFact]
    public async Task Cookie_with_one_malformed_id_is_no_session()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);

        using var replay = new BrowserSession(api, tenant.Host);
        replay.Cookies[SessionEndpoints.SessionCookie] = browser.SessionId + ".not-a-session-id";
        using var me = await replay.MeAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [DockerFact]
    public async Task Logout_ends_the_session_and_deletes_the_cookie()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        var id = browser.SessionId!;

        using var logout = await browser.LogoutAsync();

        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        Assert.Null(browser.SessionId);
        using var replay = new BrowserSession(api, tenant.Host);
        replay.Cookies[SessionEndpoints.SessionCookie] = id;
        using var me = await replay.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [DockerFact]
    public async Task Logout_without_the_antiforgery_header_is_refused()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);

        using var logout = await browser.LogoutAsync(withXsrf: false);

        Assert.Equal(HttpStatusCode.Forbidden, logout.StatusCode);
        using var me = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [DockerFact]
    public async Task Session_of_one_tenant_is_not_valid_at_another()
    {
        var (api, tenantA) = await SetUpAsync();
        await using var _ = api;
        var tenantB = await api.AddTenantAsync();
        using var browser = new BrowserSession(api, tenantA.Host);
        using var login = await browser.LoginAsync(Email, Password);

        using var other = new BrowserSession(api, tenantB.Host);
        other.Cookies[SessionEndpoints.SessionCookie] = browser.SessionId!;
        using var me = await other.MeAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [DockerFact]
    public async Task Password_change_ends_the_session()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);

        api.Time.Advance(TimeSpan.FromSeconds(1));
        await using (var scope = api.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantScope>().Set(tenant.Tenant.Id);
            var users = scope.ServiceProvider.GetRequiredService<IUserStore>();
            var user = await users.FindByEmailAsync(tenant.Tenant.Id, Email, CancellationToken.None);
            var hash = await scope.ServiceProvider.GetRequiredService<IPasswordHasher>().HashAsync("a brand new password", CancellationToken.None);
            user!.ChangePassword(hash, api.Time.GetUtcNow());
            await users.SaveChangesAsync(CancellationToken.None);
        }

        using var me = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [DockerFact]
    public async Task Idle_session_ends_and_activity_never_passes_the_absolute_limit()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        var settings = tenant.Tenant.Settings;
        using var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);

        // Activity before the idle limit keeps the session alive, until the absolute limit.
        var elapsed = TimeSpan.Zero;
        var step = settings.SessionIdle - TimeSpan.FromMinutes(1);
        while (elapsed + step < settings.SessionAbsolute)
        {
            api.Time.Advance(step);
            elapsed += step;
            using var alive = await browser.MeAsync();
            Assert.Equal(HttpStatusCode.OK, alive.StatusCode);
        }

        api.Time.Advance(settings.SessionAbsolute - elapsed);
        using var expired = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);

        // A fresh session that sees no activity ends at the idle limit.
        using var again = await browser.LoginAsync(Email, Password);
        api.Time.Advance(settings.SessionIdle);
        using var idle = await browser.MeAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, idle.StatusCode);
    }

    [DockerFact]
    public async Task Responses_forbid_framing_and_sniffing()
    {
        var (api, tenant) = await SetUpAsync();
        await using var _ = api;
        using var browser = new BrowserSession(api, tenant.Host);

        using var response = await browser.SendAsync(HttpMethod.Get, "session/v1/csrf");

        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
        Assert.Contains("frame-ancestors 'none'", Assert.Single(response.Headers.GetValues("Content-Security-Policy")), StringComparison.Ordinal);
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.True(response.Headers.CacheControl?.NoStore);
    }
}
