using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Direct tool calls that return text and hand their record to the call filter: both parts.</summary>
internal static class BuildToolCalls
{
    public static async Task<(T Record, string Text)> Collected<T>(Func<Task<string>> call)
    {
        var collector = ToolOutput.Collect();
        var text = await call();
        return (Assert.IsType<T>(collector.Value), text);
    }
}
