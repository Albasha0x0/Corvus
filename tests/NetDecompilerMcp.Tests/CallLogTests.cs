using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>The optional per-call log: one Debug line per tool call with the tool, outcome and time, never the arguments.</summary>
public class CallLogTests
{
    private sealed class Capture : ILoggerProvider, ILogger
    {
        public readonly ConcurrentQueue<string> Lines = new();
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue($"{logLevel}: {formatter(state, exception)}");
        public void Dispose() { }
    }

    [Fact]
    public async Task EachCallLogsToolOutcomeAndTime()
    {
        var capture = new Capture();
        using var services = new ServiceCollection().AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Debug)).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "decompile_type",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["type"] = System.Text.Json.JsonSerializer.SerializeToElement("Secret.Path") },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "x" }] }), default);
        await CallFilter.Run(request, null, services, _ => throw new ToolError(ErrorCode.NotFound, "no such type"), default);
        Assert.Collection(capture.Lines,
            l => Assert.Matches(@"^Debug: Tool decompile_type ok in \d+ ms$", l),
            l => Assert.Matches(@"^Debug: Tool decompile_type error not_found in \d+ ms$", l));
        Assert.DoesNotContain(capture.Lines, l => l.Contains("Secret.Path"));
    }

    [Fact]
    public void LogLevelOption()
    {
        Assert.Equal(LogLevel.Information, ServerOptions.Parse([]).LogLevel);
        Assert.Equal(LogLevel.Debug, ServerOptions.Parse(["--log-level", "Debug"]).LogLevel);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--log-level", "loud"]));
    }
}
