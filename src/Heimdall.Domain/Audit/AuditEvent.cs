using System.Net;
using System.Text.RegularExpressions;
using Heimdall.Domain.Common;

namespace Heimdall.Domain.Audit;

/// <summary>Event type names. Use these constants, not free text, so queries and alerts stay stable.</summary>
public static class AuditEventTypes
{
    public const string CodeIssued = "code.issued";
    public const string CodeRedeemed = "code.redeemed";
    public const string CodeReuseDetected = "code.reuse_detected";
    public const string TokenIssued = "token.issued";
    public const string TokenRejected = "token.rejected";
    public const string RefreshRotated = "refresh.rotated";
    public const string RefreshReuseDetected = "refresh.reuse_detected";
    public const string FamilyRevoked = "family.revoked";
    public const string RevocationRefused = "revocation.refused";
    public const string IntrospectionRefused = "introspection.refused";
    public const string PushRefused = "par.refused";
    public const string UserInfoRead = "userinfo.read";
    public const string LoginSucceeded = "login.succeeded";
    public const string LoginFailed = "login.failed";
    public const string SessionStarted = "session.started";
    public const string SessionReauthenticated = "session.reauthenticated";
    public const string SessionRevoked = "session.revoked";
    public const string BackchannelLogoutDropped = "backchannel_logout.dropped";
    public const string ConsentGranted = "consent.granted";
    public const string ConsentDenied = "consent.denied";
    public const string ConsentRevoked = "consent.revoked";
    public const string ClientChanged = "client.changed";
    public const string TenantChanged = "tenant.changed";
    public const string KeyCreated = "key.created";
    public const string KeyActivated = "key.activated";
    public const string KeyRetired = "key.retired";
    public const string KeyRemoved = "key.removed";
}

/// <summary>
/// An append-only record of a security event. It cannot change after creation. The application role can only insert
/// and read it (migration EnableRowLevelSecurity).
/// </summary>
public sealed class AuditEvent
{
    private static readonly Regex TypePattern = new(
        "^[a-z]+(_[a-z]+)*\\.[a-z]+(_[a-z]+)*$",
        RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    // Keys that suggest a secret value. D7: secrets never go into the audit log.
    private static readonly string[] ForbiddenKeyParts = ["password", "secret", "token", "verifier", "assertion", "cookie"];

#pragma warning disable CS8618 // EF Core sets the properties after it calls this constructor.
    private AuditEvent()
    {
    }
#pragma warning restore CS8618

    private AuditEvent(
        Guid id,
        Guid? tenantId,
        DateTimeOffset occurredAt,
        string type,
        string correlationId,
        IPAddress? sourceIp,
        Guid? actorUserId,
        Guid? subjectUserId,
        Guid? clientPk,
        Guid? familyId,
        IReadOnlyDictionary<string, string> data)
    {
        Id = id;
        TenantId = tenantId;
        OccurredAt = occurredAt;
        Type = type;
        CorrelationId = correlationId;
        SourceIp = sourceIp;
        ActorUserId = actorUserId;
        SubjectUserId = subjectUserId;
        ClientPk = clientPk;
        FamilyId = familyId;
        Data = data;
    }

    public Guid Id { get; }

    /// <summary>Null for platform events.</summary>
    public Guid? TenantId { get; }

    public DateTimeOffset OccurredAt { get; }

    public string Type { get; }

    public string CorrelationId { get; }

    public IPAddress? SourceIp { get; }

    public Guid? ActorUserId { get; }

    public Guid? SubjectUserId { get; }

    public Guid? ClientPk { get; }

    public Guid? FamilyId { get; }

    /// <summary>Extra detail, such as old and new values of a setting. Never secrets.</summary>
    public IReadOnlyDictionary<string, string> Data { get; }

    public static AuditEvent Record(
        Guid id,
        Guid? tenantId,
        string type,
        string correlationId,
        DateTimeOffset now,
        IPAddress? sourceIp = null,
        Guid? actorUserId = null,
        Guid? subjectUserId = null,
        Guid? clientPk = null,
        Guid? familyId = null,
        IReadOnlyDictionary<string, string>? data = null)
    {
        Guard.NotEmpty(id, nameof(id));

        var normalizedType = Guard.NotBlank(type, nameof(type));
        if (!TypePattern.IsMatch(normalizedType))
        {
            throw new DomainException("An audit event type has the form 'area.action', in lowercase.");
        }

        var copy = new Dictionary<string, string>(data ?? new Dictionary<string, string>(), StringComparer.Ordinal);
        foreach (var key in copy.Keys)
        {
            if (key.Equals("code", StringComparison.OrdinalIgnoreCase)
                || ForbiddenKeyParts.Any(part => key.Contains(part, StringComparison.OrdinalIgnoreCase)))
            {
                throw new DomainException($"The audit data key '{key}' suggests a secret value. Secrets must not be logged.");
            }
        }

        return new AuditEvent(
            id,
            tenantId,
            now,
            normalizedType,
            Guard.NotBlank(correlationId, nameof(correlationId)),
            sourceIp,
            actorUserId,
            subjectUserId,
            clientPk,
            familyId,
            copy);
    }
}
