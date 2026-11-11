using Heimdall.Application.Sessions;

namespace Heimdall.UnitTests.Application;

public class SessionListTests
{
    // A real ID: 32 bytes as base64url. The last character of 43 carries only 4 bits, so not every text is valid.
    private static string Id(char fill) => System.Buffers.Text.Base64Url.EncodeToString(Enumerable.Repeat((byte)fill, 32).ToArray());

    [Fact]
    public void One_id_is_a_list_of_one()
    {
        Assert.Equal([Id('A')], SessionList.Parse(Id('A')));
    }

    [Fact]
    public void Ids_keep_their_order()
    {
        var cookie = SessionList.Format([Id('B'), Id('A'), Id('C')]);

        Assert.Equal(Id('B') + "." + Id('A') + "." + Id('C'), cookie);
        Assert.Equal([Id('B'), Id('A'), Id('C')], SessionList.Parse(cookie));
    }

    [Fact]
    public void The_most_sessions_are_accepted()
    {
        var ids = Enumerable.Range(0, SessionList.MaxSessions).Select(i => Id((char)('A' + i))).ToList();

        Assert.Equal(ids, SessionList.Parse(SessionList.Format(ids)));
        Assert.Equal(5, SessionList.MaxSessions);
    }

    [Fact]
    public void One_session_more_than_the_limit_is_refused_as_a_whole()
    {
        var ids = Enumerable.Range(0, SessionList.MaxSessions + 1).Select(i => Id((char)('A' + i)));

        Assert.Empty(SessionList.Parse(SessionList.Format(ids)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData(".")]
    public void Missing_or_short_value_is_empty(string? cookie)
    {
        Assert.Empty(SessionList.Parse(cookie));
    }

    [Fact]
    public void One_malformed_id_refuses_the_whole_list()
    {
        Assert.Empty(SessionList.Parse(Id('A') + "." + new string('A', SessionList.SessionIdLength - 1)));
        Assert.Empty(SessionList.Parse(Id('A') + "." + new string('A', SessionList.SessionIdLength + 1)));
        Assert.Empty(SessionList.Parse(Id('A') + "." + new string('+', SessionList.SessionIdLength)));
        Assert.Empty(SessionList.Parse(Id('A') + "."));
        Assert.Empty(SessionList.Parse("." + Id('A')));
        Assert.Empty(SessionList.Parse(Id('A') + ".." + Id('B')));
        Assert.Empty(SessionList.Parse(Id('A') + "," + Id('B')));
        Assert.Empty(SessionList.Parse(new string('+', SessionList.SessionIdLength)));
    }

    [Fact]
    public void One_id_twice_refuses_the_whole_list()
    {
        Assert.Empty(SessionList.Parse(Id('A') + "." + Id('A')));
    }
}
