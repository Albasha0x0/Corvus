using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

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
    public async Task TraceWritesOneJsonLinePerCall_WhenAsked()
    {
        using var dir = new TempDir();
        var path = dir.File("calls.jsonl");
        var options = ServerOptions.Parse([ServerOptions.TraceOption, path]);
        Assert.Equal(Path.GetFullPath(path), options.TracePath);
        using var services = new ServiceCollection().AddSingleton(options).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "decompile_type",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["type"] = System.Text.Json.JsonSerializer.SerializeToElement("Ns.Type") },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "12345" }] }), default);
        await CallFilter.Run(request, null, services, _ => throw new ToolError(ErrorCode.NotFound, "no such type"), default);
        var lines = File.ReadAllLines(path).Select(l => System.Text.Json.JsonDocument.Parse(l).RootElement).ToList();
        Assert.Equal(2, lines.Count);
        Assert.Equal("decompile_type", lines[0].GetProperty("tool").GetString());
        Assert.Equal("Ns.Type", lines[0].GetProperty("args").GetProperty("type").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, lines[0].GetProperty("error").ValueKind);
        Assert.Equal(5, lines[0].GetProperty("chars").GetInt64());
        Assert.True(lines[0].GetProperty("ms").GetDouble() >= 0);
        Assert.Equal("not_found", lines[1].GetProperty("error").GetString());

        // off by default; never an engine database
        Assert.Null(ServerOptions.Parse([]).TracePath);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse([ServerOptions.TraceOption, dir.File("app.i64")]));
    }

    [Fact]
    public void LogLevelOption()
    {
        Assert.Equal(LogLevel.Information, ServerOptions.Parse([]).LogLevel);
        Assert.Equal(LogLevel.Debug, ServerOptions.Parse(["--log-level", "Debug"]).LogLevel);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--log-level", "loud"]));
    }
}
