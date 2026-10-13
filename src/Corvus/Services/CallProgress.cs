namespace Corvus.Services;

/// <summary>
/// Progress of the tool call running on this async flow (done, total, message), for services deep below a tool: C# edits
/// (decompile, compile, merge), edit replays, simplify and compare. A tool sets the receiver; without one, reports are dropped.
/// </summary>
public static class CallProgress
{
    private static readonly AsyncLocal<Action<int, int, string>?> Current = new();

    /// <summary>Sends this flow's reports to <paramref name="report"/> until disposed.</summary>
    public static IDisposable Begin(Action<int, int, string> report)
    {
        var previous = Current.Value;
        Current.Value = report;
        return new Scope(() => Current.Value = previous);
    }

    public static void Report(int done, int total, string message) => Current.Value?.Invoke(done, total, message);

    private sealed class Scope(Action exit) : IDisposable
    {
        public void Dispose() => exit();
    }
}
