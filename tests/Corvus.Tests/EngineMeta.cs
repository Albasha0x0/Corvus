using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Runs a direct tool call with a collector, so the engine provenance it puts in _meta can be read.</summary>
internal static class EngineMeta
{
    public static async Task<(string Text, OutputCall Call)> Run(Func<Task<string>> call)
    {
        var collector = ToolOutput.Collect();
        var text = await call();
        return (text, collector);
    }

    /// <summary>The push lines (names, types, PDB, marks) of a call, one per line.</summary>
    public static string Pushed(OutputCall call) =>
        call.EngineMeta.GetValueOrDefault("pushed") is List<string> list ? string.Join("\n", list) : "";

    /// <summary>The call's text with its push lines appended, for tests that read both.</summary>
    public static async Task<string> WithPushes(Func<Task<string>> call)
    {
        var (text, c) = await Run(call);
        return text + "\n" + Pushed(c);
    }
}
