namespace Corvus.Core;

/// <summary>A call's deadline: the smaller of <see cref="ServerFactor"/> x --timeout and the client's limit minus <see cref="ClientMargin"/>.</summary>
public static class Deadlines
{
    /// <summary>Multiple of --timeout after which a call not marked long-running ends.</summary>
    public const int ServerFactor = 2;

    /// <summary>A call answers this long before the client gives up on it, so the answer arrives in time.</summary>
    public static TimeSpan ClientMargin { get; } = TimeSpan.FromSeconds(5);

    /// <summary>The shortest deadline handed out; a client limit under margin + this still gets a short answer window.</summary>
    public static TimeSpan Minimum { get; } = TimeSpan.FromSeconds(1);

    /// <summary>The time from the call's start by which it answers; null when unbounded; long-running tools get no server deadline.</summary>
    public static TimeSpan? Effective(bool longRunning, ServerOptions options, ClientLimits client)
    {
        TimeSpan? server = longRunning ? null : Server(options);
        TimeSpan? fromClient = client.DeadlineSeconds is { } s ? Max(TimeSpan.FromSeconds(s) - ClientMargin, Minimum) : null;
        return (server, fromClient) switch
        {
            ({ } a, { } b) => a < b ? a : b,
            ({ } a, null) => a,
            (null, { } b) => b,
            _ => null,
        };
    }

    /// <summary>The server's own deadline for a tool that is not long-running.</summary>
    public static TimeSpan Server(ServerOptions options) => TimeSpan.FromSeconds((double)options.TimeoutSeconds * ServerFactor);

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;
}
