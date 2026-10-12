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
        // The server's default level: the line is always on.
        using var services = new ServiceCollection().AddLogging(b => b.AddProvider(capture).SetMinimumLevel(ServerOptions.Parse([]).LogLevel)).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "decompile_type",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["type"] = System.Text.Json.JsonSerializer.SerializeToElement("Secret.Path") },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "x" }] }), default);
        await CallFilter.Run(request, null, services, _ => throw new ToolError(ErrorCode.NotFound, "no such type"), default);
        await CallFilter.Run(request, null, services, async _ =>
        {
            await Task.Yield();
            Corvus.Native.Providers.EngineUse.Note("ida"); // what an engine request on the call's flow records
            return new CallToolResult { Content = [new TextContentBlock { Text = "x" }] };
        }, default);
        Assert.Collection(capture.Lines,
            l => Assert.Matches(@"^Information: call tool=decompile_type outcome=ok ms=\d+ in=17 out=1 engine=-$", l),
            l => Assert.Matches(@"^Information: call tool=decompile_type outcome=not_found ms=\d+ in=17 out=\d+ engine=-$", l),
            l => Assert.Matches(@"^Information: call tool=decompile_type outcome=ok ms=\d+ in=17 out=1 engine=ida$", l));
        Assert.DoesNotContain(capture.Lines, l => l.Contains("Secret.Path"));
    }

    [Theory]
    [InlineData("password", "hunter2", "[redacted]")]
    [InlineData("apiKey", "abc", "[redacted]")]
    [InlineData("code", "env GITHUB_TOKEN=ghp_abc and DB_PASSWORD: 's3cret x'", "env GITHUB_TOKEN=[redacted] and DB_PASSWORD: [redacted]")]
    [InlineData("code", "Authorization: Bearer abcdefghijkl.mnop", "Authorization: Bearer [redacted]")]
    [InlineData("url", "https://user:pa55@host/x", "https://user:[redacted]@host/x")]
    [InlineData("code", "key AKIAABCDEFGHIJKLMNOP; jwt eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl", "key [redacted]; jwt [redacted]")]
    [InlineData("member", "Ns.TokenReader::Read(string)", "Ns.TokenReader::Read(string)")]
    [InlineData("query", "password", "password")]
    public void TraceMasksSecretsInArguments(string name, string value, string expected)
    {
        var buffer = new MemoryStream();
        using (var w = new System.Text.Json.Utf8JsonWriter(buffer))
            Redaction.Write(w, System.Text.Json.JsonSerializer.SerializeToElement(new[] { value }), null);
        var array = System.Text.Json.JsonDocument.Parse(buffer.ToArray()).RootElement;
        // by name only when the name says so, in text always
        var named = new MemoryStream();
        using (var w = new System.Text.Json.Utf8JsonWriter(named))
        {
            w.WriteStartObject();
            w.WritePropertyName(name);
            Redaction.Write(w, System.Text.Json.JsonSerializer.SerializeToElement(value), name);
            w.WriteEndObject();
        }
        var result = System.Text.Json.JsonDocument.Parse(named.ToArray()).RootElement.GetProperty(name).GetString();
        Assert.Equal(expected, result);
        if (!Redaction.IsSecretName(name)) Assert.Equal(expected, array[0].GetString());
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
        // names only without --trace-args
        Assert.False(lines[0].TryGetProperty("args", out _));
        Assert.Equal("type", lines[0].GetProperty("argNames")[0].GetString());
        Assert.DoesNotContain("Ns.Type", File.ReadAllText(path));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, lines[0].GetProperty("error").ValueKind);
        Assert.Equal(5, lines[0].GetProperty("chars").GetInt64());
        Assert.True(lines[0].GetProperty("ms").GetDouble() >= 0);
        Assert.Equal("not_found", lines[1].GetProperty("error").GetString());

        var withValues = ServerOptions.Parse([ServerOptions.TraceOption, path, ServerOptions.TraceArgsOption]);
        Assert.True(withValues.TraceArguments);
        using var valueServices = new ServiceCollection().AddSingleton(withValues).BuildServiceProvider();
        await CallFilter.Run(request, null, valueServices, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "1" }] }), default);
        var last = System.Text.Json.JsonDocument.Parse(File.ReadAllLines(path)[^1]).RootElement;
        Assert.Equal("Ns.Type", last.GetProperty("args").GetProperty("type").GetString());

        // off by default; never an engine database
        Assert.Null(ServerOptions.Parse([]).TracePath);
        Assert.False(ServerOptions.Parse([]).TraceArguments);
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
