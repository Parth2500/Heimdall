using System.Buffers.Text;
using System.Security.Cryptography;
using Heimdall.Application.Audit;
using Heimdall.Application.Common;
using Heimdall.Application.Users;
using Heimdall.Domain.Audit;
using Heimdall.Domain.Common;
using Heimdall.Domain.Sessions;
using Heimdall.Domain.Users;

namespace Heimdall.Application.Sessions;

/// <param name="SessionId">The session ID of this sign-in. Shown only here; the server keeps only its hash.</param>
/// <param name="Cookie">The new value of the session cookie: the browser's session list with this sign-in.</param>
/// <param name="User">The signed-in user.</param>
/// <param name="ListFull">True when the credentials were right, but the browser already holds the most sessions.</param>
public sealed record SignInResult(string? SessionId, string? Cookie, User? User, bool ListFull = false)
{
    public static SignInResult Failed { get; } = new(null, null, null);

    public static SignInResult Full { get; } = new(null, null, null, ListFull: true);

    public bool Succeeded => SessionId is not null;
}

/// <param name="Session">The valid session.</param>
/// <param name="User">Its user.</param>
public sealed record ValidSession(Session Session, User User);

/// <summary>One entry of a browser's session list that has a row in the database.</summary>
/// <param name="SessionId">The session ID from the cookie.</param>
/// <param name="Session">Its session.</param>
/// <param name="User">The user of the session.</param>
/// <param name="Live">True when the session passes every rule of <see cref="Session.IsValid"/>.</param>
public sealed record ListedSession(string SessionId, Session Session, User User, bool Live);

/// <summary>
/// Login sessions at Heimdall (D11 to D13, D18). The cookie holds the browser's session list: up to five random
/// 256-bit IDs, one for each signed-in account (<see cref="SessionList"/>). The server stores only the SHA-256 hash
/// of each ID, so a database leak gives no usable session (D12).
/// </summary>
public sealed class SessionService
{
    /// <summary>The length of a session ID: 32 random bytes as base64url without padding.</summary>
    public const int SessionIdLength = SessionList.SessionIdLength;

    // Activity moves the idle limit. Writing it at most once a minute keeps validation from writing on every request.
    private static readonly TimeSpan TouchInterval = TimeSpan.FromMinutes(1);

    private readonly UserAuthenticator _authenticator;
    private readonly ISessionStore _sessions;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;

    public SessionService(
        UserAuthenticator authenticator,
        ISessionStore sessions,
        IAuditLog audit,
        TimeProvider time)
    {
        _authenticator = authenticator;
        _sessions = sessions;
        _audit = audit;
        _time = time;
    }

    /// <summary>
    /// Signs in with email and password, and returns the browser's new session list. Sessions of other users stay in
    /// the list. A live session of the same user is re-authenticated: it keeps its <c>sid</c> and gets a new session
    /// ID. Every sign-in issues a new session ID and never adopts one from the request, so an ID that an attacker
    /// planted before sign-in is worthless (D13, session fixation).
    /// </summary>
    /// <param name="cookie">The browser's session cookie, if any.</param>
    /// <exception cref="PasswordHasherBusyException">The server is at its hashing limit.</exception>
    public async Task<SignInResult> SignInAsync(
        RequestContext context,
        string? email,
        string? password,
        string? cookie,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var login = await _authenticator.AuthenticateAsync(context, email, password, cancellationToken).ConfigureAwait(false);
        if (!login.Succeeded)
        {
            return SignInResult.Failed;
        }

        var user = login.User!;
        var now = _time.GetUtcNow();
        var listed = await ListAsync(context, cookie, cancellationToken).ConfigureAwait(false);
        var sessionId = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        // The list shows one row for each account, so the new entry replaces every entry of the same user.
        var others = listed.Where(l => l.User.Id != user.Id).ToList();

        if (listed.LastOrDefault(l => l.Live && l.User.Id == user.Id) is { } current)
        {
            var reauthenticated = current.Session.Reauthenticate(TokenHash.Compute(sessionId), context.Tenant.Settings.SessionAbsolute, now);
            if (await _sessions.ReplaceAsync(current.Session, reauthenticated, cancellationToken).ConfigureAwait(false))
            {
                await WriteAuditAsync(context, AuditEventTypes.SessionReauthenticated, reauthenticated, current.Session.IdHash, cancellationToken)
                    .ConfigureAwait(false);
                return new SignInResult(sessionId, SessionList.Format(others.Select(l => l.SessionId).Append(sessionId)), user);
            }

            // A sign-out ended the session between the read and the update. The sign-in starts a new session.
        }

        // A full list first loses its ended sessions, oldest entry first. Heimdall never ends a live session to make room.
        while (others.Count >= SessionList.MaxSessions && others.FindIndex(l => !l.Live) is >= 0 and var ended)
        {
            others.RemoveAt(ended);
        }

        if (others.Count >= SessionList.MaxSessions)
        {
            return SignInResult.Full;
        }

        // D29: the public sid is separate random bits. It must not be derived from the cookie secret.
        var sid = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        var session = Session.Start(TokenHash.Compute(sessionId), sid, context.Tenant.Id, user.Id, context.Tenant.Settings.SessionAbsolute, now);
        _sessions.Add(session);
        await _sessions.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await WriteAuditAsync(context, AuditEventTypes.SessionStarted, session, null, cancellationToken).ConfigureAwait(false);
        return new SignInResult(sessionId, SessionList.Format(others.Select(l => l.SessionId).Append(sessionId)), user);
    }

    /// <summary>
    /// The browser's session list, in the order of the cookie: each session that has a row, with its user, and
    /// whether it is live (see <see cref="Session.IsValid"/>). One query for the whole list. It records no activity.
    /// </summary>
    public async Task<IReadOnlyList<ListedSession>> ListAsync(RequestContext context, string? cookie, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // A malformed cookie is refused before the database.
        var ids = SessionList.Parse(cookie);
        if (ids.Count == 0)
        {
            return [];
        }

        var hashes = ids.Select(TokenHash.Compute).ToList();
        var found = await _sessions.FindWithUsersAsync(context.Tenant.Id, hashes, cancellationToken).ConfigureAwait(false);

        var now = _time.GetUtcNow();
        var listed = new List<ListedSession>(found.Count);
        for (var i = 0; i < ids.Count; i++)
        {
            foreach (var (session, user) in found)
            {
                if (session.IdHash == hashes[i])
                {
                    listed.Add(new ListedSession(ids[i], session, user, session.IsValid(context.Tenant.Id, user, context.Tenant.Settings.SessionIdle, now)));
                }
            }
        }

        return listed;
    }

    /// <summary>
    /// Returns a live session of the browser's list and its user, and records its activity. A session is live when
    /// every rule holds (see <see cref="Session.IsValid"/>): the tenant matches, the user is active, the password did
    /// not change since sign-in, and neither the idle nor the absolute limit passed.
    /// </summary>
    /// <remarks>
    /// With several live sessions, this returns the session of the latest sign-in. This is a step of the account
    /// picker build (#41): the next step makes <c>/authorize</c> choose by the user's selection and the client's hints.
    /// </remarks>
    public async Task<ValidSession?> ValidateAsync(RequestContext context, string? cookie, CancellationToken cancellationToken)
    {
        var listed = await ListAsync(context, cookie, cancellationToken).ConfigureAwait(false);
        if (listed.LastOrDefault(l => l.Live) is not { } latest)
        {
            return null;
        }

        var now = _time.GetUtcNow();
        if (now - latest.Session.LastSeenAt >= TouchInterval)
        {
            latest.Session.Touch(now);
            await _sessions.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return new ValidSession(latest.Session, latest.User);
    }

    private Task WriteAuditAsync(RequestContext context, string type, Session session, TokenHash? previous, CancellationToken cancellationToken)
    {
        var data = new Dictionary<string, string>
        {
            // The hash, never the ID. It links events of one session without giving anyone a usable cookie.
            ["session_hash"] = Convert.ToHexStringLower(session.IdHash.AsSpan()),
        };
        if (previous is { } previousHash)
        {
            // A re-authentication changes the hash. The earlier events of the session carry this one.
            data["previous_session_hash"] = Convert.ToHexStringLower(previousHash.AsSpan());
        }

        if (context.UserAgent is { } userAgent)
        {
            data["user_agent"] = userAgent;
        }

        return _audit.WriteAsync(
            AuditEvent.Record(
                Guid.CreateVersion7(),
                context.Tenant.Id,
                type,
                context.CorrelationId,
                _time.GetUtcNow(),
                context.SourceIp,
                subjectUserId: session.UserId,
                data: data),
            cancellationToken);
    }
}
