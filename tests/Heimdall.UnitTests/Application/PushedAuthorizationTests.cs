using System.Net;
using Heimdall.Application.Authorization;
using Heimdall.Application.Clients;
using Heimdall.Application.Common;
using Heimdall.Application.Dpop;
using Heimdall.Application.Sessions;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Clients;
using Heimdall.Domain.Tenants;
using Microsoft.Extensions.Time.Testing;

namespace Heimdall.UnitTests.Application;

/// <summary>The client step of PAR (D40): authentication, the optional DPoP proof, then the checks of /authorize.</summary>
public class PushedAuthorizationTests
{
    private const string Issuer = "https://acme.example.com";
    private const string Callback = "https://app.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    private static readonly DateTimeOffset Now = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);

    private readonly Tenant _tenant = Tenant.Create(Guid.CreateVersion7(), "acme.example.com", "Acme", TenantSettings.Default, Now);
    private readonly FakeTimeProvider _time = new(Now);
    private readonly InMemoryClientStore _clients = new();
    private readonly InMemoryAuthorizationStore _store = new();
    private readonly FakeDpopProofValidator _proofs = new();
    private readonly InMemoryDpopReplayStore _replay = new();
    private readonly RecordingAuditLog _audit = new();
    private readonly FakeIdTokenHintValidator _hints = new();
    private readonly PushedAuthorization _service;

    public PushedAuthorizationTests()
    {
        var users = new InMemoryUserStore();
        var sessions = new SessionService(
            new UserAuthenticator(users, new FakePasswordHasher(), new InMemoryLoginThrottleStore(), new LoginThrottleOptions(), _audit, _time),
            new InMemorySessionStore { Users = users },
            _audit,
            _time);
        _service = new PushedAuthorization(
            new ClientAuthenticator(_clients, new FakeClientAssertionValidator(), new InMemoryClientAssertionReplayStore(), _time),
            new DpopTokenCheck(_proofs, _replay),
            new AuthorizationService(_clients, _store, sessions, _hints, _audit, _time),
            _audit,
            _time);

        var web = Client.Create(
            Guid.CreateVersion7(), _tenant.Id, "web", "Web", ClientType.Confidential,
            [GrantType.AuthorizationCode], ["openid"], [Callback], false, null, Now);
        web.Approve();
        _clients.Add(web, ("web-secret", null));
    }

    private RequestContext Context => new(_tenant, Issuer, "corr-1", IPAddress.Parse("203.0.113.7"));

    private static Dictionary<string, string> Parameters() => new()
    {
        ["response_type"] = "code",
        ["redirect_uri"] = Callback,
        ["scope"] = "openid",
        ["code_challenge"] = Challenge,
        ["code_challenge_method"] = "S256",
    };

    private Task<Result<PushedRequest>> Push(string? secret = "web-secret", string? proof = null, string clientId = "web") =>
        _service.PushAsync(Context, new PushRequest(clientId, secret, Parameters(), proof), CancellationToken.None);

    [Fact]
    public async Task Authenticated_client_pushes_its_request()
    {
        var result = await Push();

        Assert.True(result.IsSuccess);
        Assert.Single(_store.Requests);
        Assert.Empty(_audit.Events);
    }

    [Fact]
    public async Task Wrong_secret_is_refused_audited_and_stores_nothing()
    {
        var result = await Push(secret: "wrong");

        Assert.Equal(OAuthError.InvalidClientCode, result.Error!.Code);
        var refused = Assert.Single(_audit.Events);
        Assert.Equal(AuditEventTypes.PushRefused, refused.Type);
        Assert.Equal("web", refused.Data["client_id"]);
        Assert.Equal(OAuthError.InvalidClientCode, refused.Data["error"]);
        Assert.Equal(result.Error.AuditDetail, refused.Data["reason"]);
        Assert.NotEmpty(refused.Data["reason"]);
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Long_or_missing_client_id_is_cut_or_empty_in_the_audit_event()
    {
        await Push(clientId: new string('c', 300));
        await _service.PushAsync(Context, new PushRequest(null, null, Parameters(), null), CancellationToken.None);

        Assert.Equal(128, _audit.Events[0].Data["client_id"].Length);
        Assert.Equal(string.Empty, _audit.Events[1].Data["client_id"]);
    }

    [Fact]
    public async Task Proof_is_checked_for_the_par_address_and_binds_the_code()
    {
        var result = await Push(proof: FakeDpopProofValidator.Proof(Jkt));

        Assert.True(result.IsSuccess);
        var (_, request) = Assert.Single(_proofs.Checked);
        Assert.Equal(new DpopRequest("POST", new Uri(Issuer + "/oauth/v1/par")), request);
        Assert.Equal(Jkt, Assert.Single(_store.Requests).DpopKeyThumbprint);
    }

    [Fact]
    public async Task Bad_proof_is_invalid_dpop_proof()
    {
        var result = await Push(proof: "not-a-proof");

        Assert.Equal(OAuthError.InvalidDpopProofCode, result.Error!.Code);
        Assert.Empty(_store.Requests);
    }

    [Fact]
    public async Task Replayed_proof_is_refused()
    {
        var proof = FakeDpopProofValidator.Proof(Jkt);
        await Push(proof: proof);

        Assert.Equal(new OAuthError(OAuthError.InvalidDpopProofCode, "proof replayed"), (await Push(proof: proof)).Error);
    }
}
