using System.Net;
using System.Text.Json;

namespace Heimdall.IntegrationTests.Api;

/// <summary>The OpenAPI document of the session API and its Scalar page (#22). Development only.</summary>
[Collection(PostgresGroup.Name)]
public sealed class ApiDocumentationTests
{
    private readonly PostgresFixture _postgres;

    public ApiDocumentationTests(PostgresFixture postgres)
    {
        _postgres = postgres;
    }

    [DockerFact]
    public async Task Document_describes_only_the_session_api()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var response = await http.GetAsync("openapi/v1.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.StartsWith("3.1", document.GetProperty("openapi").GetString(), StringComparison.Ordinal);
        var paths = document.GetProperty("paths").EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal);
        Assert.Equal(
            ["/session/v1/accounts", "/session/v1/consent", "/session/v1/csrf", "/session/v1/forget", "/session/v1/login", "/session/v1/logout", "/session/v1/me", "/session/v1/select"],
            paths);
        var login = document.GetProperty("paths").GetProperty("/session/v1/login").GetProperty("post");
        Assert.True(login.GetProperty("requestBody").GetProperty("content").TryGetProperty("application/json", out _));
    }

    [DockerFact]
    public async Task Page_gets_its_own_policy_and_still_cannot_be_framed()
    {
        await using var api = new HeimdallApiFactory(_postgres);
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        // /scalar redirects to /scalar/, the page itself.
        using var response = await http.GetAsync("scalar/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var policy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("connect-src 'self'", policy, StringComparison.Ordinal);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    [DockerFact]
    public async Task Production_serves_neither_the_document_nor_the_page()
    {
        await using var api = new HeimdallApiFactory(_postgres, environment: "Production");
        var tenant = await api.AddTenantAsync();
        using var http = api.ClientFor(tenant.Host);

        using var document = await http.GetAsync("openapi/v1.json");
        using var page = await http.GetAsync("scalar/");

        Assert.Equal(HttpStatusCode.NotFound, document.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, page.StatusCode);
    }
}
