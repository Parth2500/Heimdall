using System.Buffers.Text;

namespace Heimdall.Application.Sessions;

/// <summary>
/// The value of the session cookie: the session IDs of one browser, joined by <c>.</c> (account picker design, P1).
/// Each ID is one session of one user. Base64url text has no <c>.</c>, so the split is exact.
/// </summary>
public static class SessionList
{
    /// <summary>The most sessions that one browser holds (P2). A platform rule with no setting.</summary>
    public const int MaxSessions = 5;

    /// <summary>The length of a session ID: 32 random bytes as base64url without padding.</summary>
    public const int SessionIdLength = 43;

    private const char Separator = '.';

    // Checked before the split, so an oversized cookie costs one length comparison.
    private const int MaxLength = (MaxSessions * SessionIdLength) + MaxSessions - 1;

    /// <summary>
    /// The session IDs of a cookie value, in order. Empty when the value is missing or malformed: a wrong length, a
    /// character outside base64url, more than <see cref="MaxSessions"/> IDs, or one ID twice. A malformed value is
    /// refused as a whole, before the database.
    /// </summary>
    public static IReadOnlyList<string> Parse(string? cookie)
    {
        if (cookie is null || cookie.Length < SessionIdLength || cookie.Length > MaxLength)
        {
            return [];
        }

        var ids = cookie.Split(Separator);
        if (ids.Length > MaxSessions
            || ids.Any(id => id.Length != SessionIdLength || !Base64Url.IsValid(id))
            || ids.Distinct(StringComparer.Ordinal).Count() != ids.Length)
        {
            return [];
        }

        return ids;
    }

    /// <summary>The cookie value for these session IDs.</summary>
    public static string Format(IEnumerable<string> sessionIds) => string.Join(Separator, sessionIds);
}
