using System.Net.Http.Json;
using Heimdall.Api.Endpoints;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Heimdall.IntegrationTests.Api;

/// <summary>
/// Acts like a browser on one tenant origin, but keeps cookies by hand so tests can read every Set-Cookie attribute.
/// It sends the antiforgery header the way Angular's HttpClient does.
/// </summary>
internal sealed class BrowserSession : IDisposable
{
    private readonly HttpClient _http;

    public BrowserSession(WebApplicationFactory<Program> api, string host)
    {
        _http = api.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri($"https://{host}/"),
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
        Origin = "https://" + host;
    }

    public Dictionary<string, string> Cookies { get; } = new(StringComparer.Ordinal);

    /// <summary>The raw Set-Cookie headers of the last response, by cookie name.</summary>
    public Dictionary<string, string> LastSetCookies { get; } = new(StringComparer.Ordinal);

    public string Origin { get; set; }

    public string? SessionId => Cookies.GetValueOrDefault(SessionEndpoints.SessionCookie);

    public void Dispose() => _http.Dispose();

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, HttpContent? content = null, bool withXsrf = true)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        if (Cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", Cookies.Select(c => $"{c.Key}={c.Value}")));
        }

        if (method != HttpMethod.Get)
        {
            request.Headers.Add("Origin", Origin);
            if (withXsrf && Cookies.TryGetValue(SessionEndpoints.XsrfCookie, out var token))
            {
                request.Headers.Add(SessionEndpoints.XsrfHeader, token);
            }
        }

        var response = await _http.SendAsync(request);
        LastSetCookies.Clear();
        if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            foreach (var header in setCookies)
            {
                var pair = header.Split(';')[0];
                var name = pair[..pair.IndexOf('=', StringComparison.Ordinal)];
                var value = pair[(name.Length + 1)..];
                LastSetCookies[name] = header;

                // An expiry in the past deletes the cookie, as a browser would.
                if (header.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase) || value.Length == 0)
                {
                    Cookies.Remove(name);
                }
                else
                {
                    Cookies[name] = value;
                }
            }
        }

        return response;
    }

    public async Task GetCsrfAsync()
    {
        using var response = await SendAsync(HttpMethod.Get, "session/v1/csrf");
        response.EnsureSuccessStatusCode();
    }

    public async Task<HttpResponseMessage> LoginAsync(string email, string password, bool withXsrf = true)
    {
        if (!Cookies.ContainsKey(SessionEndpoints.XsrfCookie))
        {
            await GetCsrfAsync();
        }

        return await SendAsync(HttpMethod.Post, "session/v1/login", JsonContent.Create(new { email, password }), withXsrf);
    }

    public Task<HttpResponseMessage> MeAsync() => SendAsync(HttpMethod.Get, "session/v1/me");

    public Task<HttpResponseMessage> LogoutAsync(bool withXsrf = true) => SendAsync(HttpMethod.Post, "session/v1/logout", withXsrf: withXsrf);

    /// <summary>Signs one account out, by the sid of its session.</summary>
    public Task<HttpResponseMessage> LogoutAsync(string sid) => SendAsync(HttpMethod.Post, "session/v1/logout", JsonContent.Create(new { sid }));

    public Task<HttpResponseMessage> AccountsAsync(string? requestId = null) =>
        SendAsync(HttpMethod.Get, requestId is null ? "session/v1/accounts" : $"session/v1/accounts?request_id={requestId}");

    public Task<HttpResponseMessage> SelectAsync(string requestId, string sid, bool withXsrf = true) =>
        SendAsync(HttpMethod.Post, "session/v1/select", JsonContent.Create(new { request_id = requestId, sid }), withXsrf);

    public Task<HttpResponseMessage> ForgetAsync(string sid, bool withXsrf = true) =>
        SendAsync(HttpMethod.Post, "session/v1/forget", JsonContent.Create(new { sid }), withXsrf);
}
