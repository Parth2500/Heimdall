using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Heimdall.Api.Endpoints;
using Heimdall.Application.Audit;
using Heimdall.Application.Tokens;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Tokens;
using Heimdall.Infrastructure.Logout;
using Heimdall.Infrastructure.Persistence;
using Heimdall.Infrastructure.Telemetry;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// RP-Initiated Logout at <c>/oauth/v1/logout</c> and the confirmation at <c>/session/v1/logout</c>, with real sessions,
/// real ID tokens, and the sign-out transaction in PostgreSQL (D30 to D34).
/// </summary>
[Collection(PostgresGroup.Name)]
public sealed class LogoutTests
{
    private const string Email = "alice@example.com";
    private const string Password = "correct horse battery staple";
    private const string Callback = "https://app.example.com/callback";
    private const string Bye = "https://app.example.com/bye";
    private const string Backchannel = "https://app.example.com/backchannel-logout";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly PostgresFixture _postgres;

    public LogoutTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    private sealed record Flow(HeimdallApiFactory Api, TestTenant Tenant, BrowserSession Browser, HttpClient Http) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            Http.Dispose();
            await Api.DisposeAsync();
        }
    }

    private sealed record Tokens(string IdToken, string RefreshToken, string Sid);

    private async Task<Flow> SetUpAsync(string? backchannel = null)
    {
        var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        await api.AddWebClientAsync(tenant, postLogoutRedirectUris: [Bye], backchannelLogoutUri: backchannel);
        await api.AddWebClientAsync(tenant, clientId: "other-app", postLogoutRedirectUris: ["https://other.example.com/bye"]);
        await api.AddUserAsync(tenant, Email, Password);
        var browser = new BrowserSession(api, tenant.Host);
        using var login = await browser.LoginAsync(Email, Password);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return new Flow(api, tenant, browser, api.ClientFor(tenant.Host));
    }

    private static async Task<HttpResponseMessage> AuthorizeAsync(Flow flow, string clientId = "web-app") =>
        await flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = Callback,
            ["scope"] = "openid offline_access",
            ["state"] = "s1",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        }));

    /// <summary>Signs in to the client: a code, then tokens. Returns the ID token, the refresh token, and its sid.</summary>
    private static async Task<Tokens> SignInToClientAsync(Flow flow, string clientId = "web-app")
    {
        using var authorize = await AuthorizeAsync(flow, clientId);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!.OriginalString;
        var code = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["code"].ToString();

        using var token = await flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"),
            new("code", code),
            new("code_verifier", Verifier),
            new("redirect_uri", Callback),
            new("client_id", clientId),
        ]));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var body = JsonDocument.Parse(await token.Content.ReadAsStringAsync()).RootElement;
        var idToken = body.GetProperty("id_token").GetString()!;
        return new Tokens(idToken, body.GetProperty("refresh_token").GetString()!, new JsonWebToken(idToken).GetClaim("sid").Value);
    }

    private static Task<HttpResponseMessage> RefreshAsync(Flow flow, string refreshToken, string clientId = "web-app") =>
        flow.Http.PostAsync("oauth/v1/token", new FormUrlEncodedContent(
        [
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken),
            new("client_id", clientId),
        ]));

    private static Task<HttpResponseMessage> LogoutAsync(Flow flow, params (string Name, string Value)[] parameters) =>
        flow.Browser.SendAsync(HttpMethod.Get, QueryHelpers.AddQueryString("oauth/v1/logout", parameters.Select(p => new KeyValuePair<string, string?>(p.Name, p.Value))));

    private static Task<HttpResponseMessage> ConfirmAsync(Flow flow, string? logoutRequest) =>
        flow.Browser.SendAsync(HttpMethod.Post, "session/v1/logout", JsonContent.Create(new Dictionary<string, string?> { ["logout_request"] = logoutRequest }));

    private static async Task<bool> SessionIsValidAsync(Flow flow)
    {
        using var me = await flow.Browser.MeAsync();
        return me.StatusCode == HttpStatusCode.OK;
    }

    private static async Task<List<TokenFamily>> FamiliesAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().TokenFamilies.AsNoTracking().ToListAsync();
    }

    private static async Task<List<BackchannelLogoutRecord>> QueuedAsync(Flow flow)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantScope>().Set(flow.Tenant.Tenant.Id);
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().BackchannelLogouts.AsNoTracking().ToListAsync();
    }

    [DockerFact]
    public async Task Discovery_names_the_end_session_endpoint()
    {
        await using var flow = await SetUpAsync();

        var document = JsonDocument.Parse(await flow.Http.GetStringAsync(".well-known/openid-configuration")).RootElement;

        Assert.Equal(flow.Tenant.Issuer + "/oauth/v1/logout", document.GetProperty("end_session_endpoint").GetString());
        Assert.False(document.GetProperty("frontchannel_logout_supported").GetBoolean());
    }

    [DockerFact]
    public async Task Hint_of_this_session_ends_it_revokes_its_tokens_and_redirects()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", Bye), ("state", "af0ifjsldkj"));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Bye + "?state=af0ifjsldkj", response.Headers.Location!.OriginalString);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Null(flow.Browser.SessionId);
        Assert.False(await SessionIsValidAsync(flow));

        // D33: the refresh token of that sign-in ends too, and the family records why.
        using var refresh = await RefreshAsync(flow, tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        var family = Assert.Single(await FamiliesAsync(flow));
        Assert.Equal(FamilyRevocationReason.UserLogout, family.RevocationReason);
        Assert.Equal(tokens.Sid, family.Sid);
    }

    [DockerFact]
    public async Task Next_sign_in_asks_for_the_password()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);
        using (var logout = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken)))
        {
            Assert.Equal(HttpStatusCode.Found, logout.StatusCode);
        }

        using var authorize = await AuthorizeAsync(flow);

        Assert.StartsWith("/account/login?request_id=", authorize.Headers.Location!.OriginalString, StringComparison.Ordinal);
    }

    [DockerFact]
    public async Task Expired_hint_still_ends_the_session()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);
        // D30: exp does not count. The ID token lives 5 minutes. The session is still inside its idle limit.
        flow.Api.Time.Advance(TimeSpan.FromMinutes(10));

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", Bye));

        Assert.Equal(Bye, response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Form_post_works_like_a_get()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await flow.Browser.SendAsync(HttpMethod.Post, "oauth/v1/logout", new FormUrlEncodedContent(
        [
            new("id_token_hint", tokens.IdToken),
            new("post_logout_redirect_uri", Bye),
        ]));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(Bye, response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Without_a_hint_the_user_confirms_first()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye), ("state", "s2"));

        // D31: a cross-site link reaches only the confirm page. The session and the cookie stay.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        Assert.StartsWith("/account/logout?logout_request=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("app.example.com", location, StringComparison.Ordinal);
        Assert.NotNull(flow.Browser.SessionId);
        Assert.True(await SessionIsValidAsync(flow));

        var logoutRequest = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["logout_request"].ToString();
        using var confirm = await ConfirmAsync(flow, logoutRequest);

        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var body = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(Bye + "?state=s2", body.GetProperty("redirect_to").GetString());
        Assert.Null(flow.Browser.SessionId);
        Assert.False(await SessionIsValidAsync(flow));
        using var refresh = await RefreshAsync(flow, tokens.RefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
    }

    [DockerFact]
    public async Task Hint_of_an_older_session_needs_the_click()
    {
        await using var flow = await SetUpAsync();
        var old = await SignInToClientAsync(flow);

        // The user signs out and in again: a new session with a new sid.
        using (var signOut = await flow.Browser.LogoutAsync())
        {
            Assert.Equal(HttpStatusCode.OK, signOut.StatusCode);
        }

        using (var again = await flow.Browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }

        using var response = await LogoutAsync(flow, ("id_token_hint", old.IdToken), ("post_logout_redirect_uri", Bye));

        Assert.StartsWith("/account/logout?logout_request=", response.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.True(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Sign_out_after_a_second_sign_in_revokes_the_families_from_before_it()
    {
        // The account picker design, P4: a second sign-in of the same user keeps the session and its sid. So the
        // families from before it still belong to a session that a sign-out ends (D33).
        await using var flow = await SetUpAsync();
        var first = await SignInToClientAsync(flow);
        using (var again = await flow.Browser.LoginAsync(Email, Password))
        {
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }

        using var response = await LogoutAsync(flow, ("id_token_hint", first.IdToken), ("post_logout_redirect_uri", Bye));

        Assert.Equal(Bye, response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
        Assert.All(await FamiliesAsync(flow), f => Assert.Equal(FamilyRevocationReason.UserLogout, f.RevocationReason));
    }

    [DockerFact]
    public async Task Changed_logout_request_loses_only_the_redirect()
    {
        await using var flow = await SetUpAsync();
        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye));
        var location = response.Headers.Location!.OriginalString;
        var logoutRequest = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["logout_request"].ToString();

        using var confirm = await ConfirmAsync(flow, logoutRequest[..^2] + (logoutRequest[^2] == 'A' ? "BB" : "AA"));

        var body = JsonDocument.Parse(await confirm.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("/account/signed-out?logout=done", body.GetProperty("redirect_to").GetString());
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Unregistered_uri_goes_to_the_signed_out_page()
    {
        await using var flow = await SetUpAsync();
        var tokens = await SignInToClientAsync(flow);

        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken), ("post_logout_redirect_uri", "https://evil.example.com/"));

        // D32: no open redirect. The session still ends, because the hint names it.
        Assert.Equal("/account/signed-out?logout=done", response.Headers.Location!.OriginalString);
        Assert.False(await SessionIsValidAsync(flow));
    }

    [DockerFact]
    public async Task Uri_of_another_client_goes_to_the_signed_out_page()
    {
        await using var flow = await SetUpAsync();

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", "https://other.example.com/bye"));

        // The URI is not registered for web-app, so the confirm page gets no target to seal.
        Assert.Equal("/account/logout", response.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Repeated_parameter_is_an_error_and_ends_nothing()
    {
        await using var flow = await SetUpAsync();

        using var response = await flow.Browser.SendAsync(HttpMethod.Get, "oauth/v1/logout?client_id=web-app&client_id=other-app");

        Assert.Equal("/account/error?error=invalid_request", response.Headers.Location!.OriginalString);
        Assert.True(await SessionIsValidAsync(flow));
        Assert.NotNull(flow.Browser.SessionId);
    }

    [DockerFact]
    public async Task Without_a_session_the_browser_goes_back_at_once()
    {
        await using var flow = await SetUpAsync();
        flow.Browser.Cookies.Remove(SessionEndpoints.SessionCookie);

        using var response = await LogoutAsync(flow, ("client_id", "web-app"), ("post_logout_redirect_uri", Bye), ("state", "s3"));

        Assert.Equal(Bye + "?state=s3", response.Headers.Location!.OriginalString);
    }

    [DockerFact]
    public async Task Sign_out_queues_one_backchannel_logout_for_each_client_that_registered_a_uri()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInToClientAsync(flow);
        await SignInToClientAsync(flow);
        await SignInToClientAsync(flow, "other-app");

        using (var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken)))
        {
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        }

        // D34: web-app has two families of this session and one row. other-app registered no URI.
        var queued = Assert.Single(await QueuedAsync(flow));
        Assert.Equal(tokens.Sid, queued.Sid);
        Assert.Equal(0, queued.Attempts);
        Assert.Equal(3, (await FamiliesAsync(flow)).Count(f => f.RevocationReason == FamilyRevocationReason.UserLogout));
    }

    [DockerFact]
    public async Task Concurrent_sign_outs_end_the_session_once()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInToClientAsync(flow);
        var cookie = flow.Browser.SessionId!;

        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using var browser = new BrowserSession(flow.Api, flow.Tenant.Host);
            browser.Cookies[SessionEndpoints.SessionCookie] = cookie;
            using var response = await browser.SendAsync(HttpMethod.Get, "oauth/v1/logout?id_token_hint=" + Uri.EscapeDataString(tokens.IdToken));
            return response.StatusCode;
        }));

        Assert.All(responses, status => Assert.Equal(HttpStatusCode.Found, status));
        Assert.Single(await QueuedAsync(flow));
    }

    // ---- Back-channel delivery (D34, D35)

    /// <summary>Stands in for the client's server. It records each call and answers with the next status.</summary>
    private sealed class ClientServer : HttpMessageHandler
    {
        public List<(Uri Uri, string ContentType, Dictionary<string, string> Form)> Calls { get; } = [];

        public Queue<HttpStatusCode> Answers { get; } = new();

        public bool Unreachable { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Unreachable)
            {
                throw new HttpRequestException("connection refused");
            }

            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Calls.Add((request.RequestUri!, request.Content.Headers.ContentType!.MediaType!, QueryHelpers.ParseQuery(body).ToDictionary(p => p.Key, p => p.Value.ToString())));
            return new HttpResponseMessage(Answers.Count > 0 ? Answers.Dequeue() : HttpStatusCode.OK);
        }
    }

    private static BackchannelLogoutDelivery Delivery(Flow flow, ClientServer server, BackchannelLogoutOptions? options = null)
    {
        var services = flow.Api.Services;
        return new BackchannelLogoutDelivery(
            services.GetRequiredService<PlatformDbContextFactory>(),
            services.GetRequiredService<ITokenSigner>(),
            services.GetRequiredService<IIssuerResolver>(),
            services.GetRequiredService<IAuditLog>(),
            services.GetRequiredService<HeimdallMetrics>(),
            options ?? new BackchannelLogoutOptions(),
            flow.Api.Time,
            NullLogger<BackchannelLogoutDelivery>.Instance,
            server);
    }

    private static async Task<Tokens> SignInAndOutAsync(Flow flow)
    {
        // A pass covers every tenant. The tests of this collection run one at a time, so rows that other tests left
        // are removed here, and each pass sees only this test's rows.
        await using (var db = flow.Api.Services.GetRequiredService<PlatformDbContextFactory>().Create())
        {
            await db.Database.ExecuteSqlAsync($"DELETE FROM backchannel_logouts WHERE tenant_id <> {flow.Tenant.Tenant.Id}");
        }

        var tokens = await SignInToClientAsync(flow);
        using var response = await LogoutAsync(flow, ("id_token_hint", tokens.IdToken));
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        return tokens;
    }

    private static async Task<List<AuditEvent>> AuditAsync(Flow flow, string type)
    {
        await using var scope = flow.Api.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<HeimdallDbContext>().AuditEvents.AsNoTracking()
            .Where(e => e.TenantId == flow.Tenant.Tenant.Id && e.Type == type).ToListAsync();
    }

    [DockerFact]
    public async Task Discovery_says_that_backchannel_logout_carries_sid()
    {
        await using var flow = await SetUpAsync();

        var document = JsonDocument.Parse(await flow.Http.GetStringAsync(".well-known/openid-configuration")).RootElement;

        Assert.True(document.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.True(document.GetProperty("backchannel_logout_session_supported").GetBoolean());
    }

    [DockerFact]
    public async Task Delivery_posts_a_signed_logout_token_and_removes_the_row()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInAndOutAsync(flow);
        var server = new ClientServer();
        using var delivery = Delivery(flow, server);

        var result = await delivery.RunOnceAsync(CancellationToken.None);

        Assert.Equal(new BackchannelPassResult(1, 0, 0), result);
        Assert.Empty(await QueuedAsync(flow));
        var call = Assert.Single(server.Calls);
        Assert.Equal(Backchannel, call.Uri.ToString());
        Assert.Equal("application/x-www-form-urlencoded", call.ContentType);

        // D34, Back-Channel Logout 1.0, section 2.4. An independent library checks the token against the JWKS.
        var jwks = new JsonWebKeySet(await flow.Http.GetStringAsync(".well-known/jwks.json"));
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(call.Form["logout_token"], new TokenValidationParameters
        {
            ValidIssuer = flow.Tenant.Issuer,
            ValidAudience = "web-app",
            ValidAlgorithms = ["RS256"],
            ValidTypes = ["logout+jwt"],
            IssuerSigningKeys = jwks.GetSigningKeys(),
            LifetimeValidator = (_, _, _, _) => true,
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);
        var jwt = (JsonWebToken)validation.SecurityToken;
        Assert.Equal(new JsonWebToken(tokens.IdToken).Subject, jwt.Subject);
        Assert.Equal(tokens.Sid, jwt.GetClaim("sid").Value);
        Assert.Matches("^[0-9a-f]{32}$", jwt.Id);
        Assert.Equal(120, jwt.GetPayloadValue<long>("exp") - jwt.GetPayloadValue<long>("iat"));
        Assert.False(jwt.TryGetPayloadValue<string>("nonce", out _));
        var events = JsonDocument.Parse(jwt.GetPayloadValue<JsonElement>("events").GetRawText()).RootElement;
        Assert.Equal(JsonValueKind.Object, events.GetProperty("http://schemas.openid.net/event/backchannel-logout").ValueKind);
    }

    [DockerFact]
    public async Task Failed_call_waits_and_retries_with_a_new_token()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        await SignInAndOutAsync(flow);
        var server = new ClientServer();
        server.Answers.Enqueue(HttpStatusCode.ServiceUnavailable);
        using var delivery = Delivery(flow, server);

        Assert.Equal(new BackchannelPassResult(0, 1, 0), await delivery.RunOnceAsync(CancellationToken.None));
        var row = Assert.Single(await QueuedAsync(flow));
        Assert.Equal(1, row.Attempts);
        // PostgreSQL keeps microseconds, so the stored time can differ by less than one.
        Assert.Equal(flow.Api.Time.GetUtcNow() + TimeSpan.FromSeconds(30), row.NextAttemptAt, TimeSpan.FromMilliseconds(1));

        // Not due yet, so the next pass takes nothing.
        Assert.Equal(new BackchannelPassResult(0, 0, 0), await delivery.RunOnceAsync(CancellationToken.None));

        flow.Api.Time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(new BackchannelPassResult(1, 0, 0), await delivery.RunOnceAsync(CancellationToken.None));
        Assert.Empty(await QueuedAsync(flow));
        Assert.Equal(2, server.Calls.Count);
        Assert.NotEqual(server.Calls[0].Form["logout_token"], server.Calls[1].Form["logout_token"]);
    }

    [DockerFact]
    public async Task Waits_double_after_each_failure()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        await SignInAndOutAsync(flow);
        var server = new ClientServer { Unreachable = true };
        using var delivery = Delivery(flow, server);

        foreach (var wait in new[] { 30, 60, 120 })
        {
            await delivery.RunOnceAsync(CancellationToken.None);
            var row = Assert.Single(await QueuedAsync(flow));
            Assert.Equal(flow.Api.Time.GetUtcNow() + TimeSpan.FromSeconds(wait), row.NextAttemptAt, TimeSpan.FromMilliseconds(1));
            flow.Api.Time.Advance(TimeSpan.FromSeconds(wait));
        }
    }

    [DockerFact]
    public async Task Last_failed_retry_drops_the_row_and_audits_it()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        var tokens = await SignInAndOutAsync(flow);
        var server = new ClientServer { Unreachable = true };
        using var delivery = Delivery(flow, server, new BackchannelLogoutOptions { MaxRetries = 1 });

        Assert.Equal(new BackchannelPassResult(0, 1, 0), await delivery.RunOnceAsync(CancellationToken.None));
        flow.Api.Time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(new BackchannelPassResult(0, 0, 1), await delivery.RunOnceAsync(CancellationToken.None));

        Assert.Empty(await QueuedAsync(flow));
        var dropped = Assert.Single(await AuditAsync(flow, AuditEventTypes.BackchannelLogoutDropped));
        Assert.Equal("web-app", dropped.Data["client_id"]);
        Assert.Equal(tokens.Sid, dropped.Data["sid"]);
        Assert.Equal("2", dropped.Data["attempts"]);
    }

    [DockerFact]
    public async Task Taken_row_stays_with_its_pass_for_the_lease()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        await SignInAndOutAsync(flow);

        // A server takes the row, then stops before the call ends: only the lease brings the row back.
        await using (var db = flow.Api.Services.GetRequiredService<PlatformDbContextFactory>().Create())
        {
            var leaseUntil = flow.Api.Time.GetUtcNow() + new BackchannelLogoutOptions().Lease;
            await db.Database.ExecuteSqlAsync($"UPDATE backchannel_logouts SET attempts = 1, next_attempt_at = {leaseUntil}");
        }

        var server = new ClientServer();
        using var delivery = Delivery(flow, server);
        Assert.Equal(new BackchannelPassResult(0, 0, 0), await delivery.RunOnceAsync(CancellationToken.None));

        flow.Api.Time.Advance(new BackchannelLogoutOptions().Lease);
        Assert.Equal(new BackchannelPassResult(1, 0, 0), await delivery.RunOnceAsync(CancellationToken.None));
    }

    [DockerFact]
    public async Task Client_that_removed_its_uri_gets_no_call()
    {
        await using var flow = await SetUpAsync(backchannel: Backchannel);
        await SignInAndOutAsync(flow);
        await using (var db = flow.Api.Services.GetRequiredService<PlatformDbContextFactory>().Create())
        {
            await db.Database.ExecuteSqlAsync($"UPDATE clients SET backchannel_logout_uri = NULL");
        }

        var server = new ClientServer();
        using var delivery = Delivery(flow, server);

        Assert.Equal(new BackchannelPassResult(0, 0, 0), await delivery.RunOnceAsync(CancellationToken.None));
        Assert.Empty(server.Calls);
        Assert.Empty(await QueuedAsync(flow));
    }
}
