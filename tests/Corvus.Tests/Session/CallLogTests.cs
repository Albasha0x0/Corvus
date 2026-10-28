using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The per-call log (S14.1): one information line per tool call with the tool, outcome, time, estimated tokens per part and engine, never the arguments.</summary>
public class CallLogTests
{
    private sealed class Capture : ILoggerProvider, ILogger
    {
        public readonly ConcurrentQueue<string> Lines = new();
        public readonly ConcurrentQueue<IReadOnlyList<KeyValuePair<string, object?>>> Fields = new();
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Lines.Enqueue($"{logLevel}: {formatter(state, exception)}");
            if (state is IReadOnlyList<KeyValuePair<string, object?>> fields) Fields.Enqueue(fields);
        }
        public void Dispose() { }
    }

    [Fact]
    public async Task Each_call_logs_its_tool_outcome_and_time()
    {
        var capture = new Capture();
        // The server's default level: the line is always on.
        using var services = new ServiceCollection().AddLogging(b => b.AddProvider(capture).SetMinimumLevel(ServerOptions.Parse([]).LogLevel)).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "decompile_member",
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
            l => Assert.Matches(@"^Information: call tool=decompile_member outcome=ok ms=\d+ textTokens=1 structuredTokens=0 engine=-$", l),
            l => Assert.Matches(@"^Information: call tool=decompile_member outcome=not_found ms=\d+ textTokens=\d+ structuredTokens=0 engine=-$", l),
            l => Assert.Matches(@"^Information: call tool=decompile_member outcome=ok ms=\d+ textTokens=1 structuredTokens=0 engine=ida$", l));
        Assert.DoesNotContain(capture.Lines, l => l.Contains("Secret.Path"));
    }

    /// <summary>The fields a JSON log (CORVUS_LOG_FORMAT=json) writes per call: these and no argument value.</summary>
    [Fact]
    public async Task Log_line_fields_are_fixed()
    {
        var capture = new Capture();
        using var services = new ServiceCollection().AddLogging(b => b.AddProvider(capture)).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "list_types",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["assembly"] = System.Text.Json.JsonSerializer.SerializeToElement("Secret.dll") },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult
        {
            Content = [new TextContentBlock { Text = "three words here" }],
            StructuredContent = System.Text.Json.JsonSerializer.SerializeToElement(new { items = new[] { "abcd" } }),
        }), default);
        var fields = Assert.Single(capture.Fields).ToDictionary(f => f.Key, f => f.Value);
        Assert.Equal(["Tool", "Outcome", "Ms", "TextTokens", "StructuredTokens", "Engine", "{OriginalFormat}"], fields.Keys);
        Assert.Equal("list_types", fields["Tool"]);
        Assert.Equal("ok", fields["Outcome"]);
        Assert.Equal((long)TokenEstimate.Of("three words here"), fields["TextTokens"]);
        Assert.Equal(CallLog.EstimateTokens("""{"items":["abcd"]}"""), fields["StructuredTokens"]);
        Assert.DoesNotContain(fields.Values, v => v?.ToString()?.Contains("Secret") == true);
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
    public void Trace_masks_secrets_in_arguments(string name, string value, string expected)
    {
        var buffer = new MemoryStream();
        using (var w = new System.Text.Json.Utf8JsonWriter(buffer))
            Redaction.Write(w, System.Text.Json.JsonSerializer.SerializeToElement(new[] { value }), null);
        var array = System.Text.Json.JsonDocument.Parse(buffer.ToArray()).RootElement;
        // By name only when the name says so, in text always.
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
    public void A_text_of_a_million_letters_is_masked_within_seconds()
    {
        // The scan was quadratic: about 4 s for 400,000 letters. Thread CPU time, so descheduling does not count.
        var cpu = ThreadCpuClock.Now();
        Assert.Equal(1_000_000, Redaction.Text(new string('F', 1_000_000)).Length);
        var took = ThreadCpuClock.Now() - cpu;
        Assert.True(took < TimeSpan.FromSeconds(5), $"{took.TotalSeconds:0.0} s of CPU");
        Assert.Equal(new string('a', 40) + "://user:[redacted]@host", Redaction.Text(new string('a', 40) + "://user:pa55@host"));
    }

    [Fact]
    public async Task Trace_writes_one_JSON_line_per_call_when_asked()
    {
        using var dir = new TempDir();
        var path = dir.File("calls.jsonl");
        var options = ServerOptions.Parse([ServerOptions.TraceOption, path]);
        Assert.Equal(Path.GetFullPath(path), options.TracePath);
        using var services = new ServiceCollection().AddSingleton(options).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "decompile_member",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["type"] = System.Text.Json.JsonSerializer.SerializeToElement("Ns.Type") },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "12345" }] }), default);
        await CallFilter.Run(request, null, services, _ => throw new ToolError(ErrorCode.NotFound, "no such type"), default);
        var lines = File.ReadAllLines(path).Select(l => System.Text.Json.JsonDocument.Parse(l).RootElement).ToList();
        Assert.Equal(2, lines.Count);
        Assert.Equal("decompile_member", lines[0].GetProperty("tool").GetString());
        // Names only without --trace-args.
        Assert.False(lines[0].TryGetProperty("args", out _));
        Assert.Equal("type", lines[0].GetProperty("argNames")[0].GetString());
        Assert.DoesNotContain("Ns.Type", File.ReadAllText(path));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, lines[0].GetProperty("error").ValueKind);
        Assert.Equal(5, lines[0].GetProperty("chars").GetInt64());
        Assert.Equal(TokenEstimate.Of("12345"), lines[0].GetProperty("textTokens").GetInt64());
        Assert.Equal(CallLog.RunId, lines[0].GetProperty("run").GetString());
        Assert.True(lines[0].GetProperty("ms").GetDouble() >= 0);
        Assert.Equal("not_found", lines[1].GetProperty("error").GetString());

        var withValues = ServerOptions.Parse([ServerOptions.TraceOption, path, ServerOptions.TraceArgsOption]);
        Assert.True(withValues.TraceArguments);
        using var valueServices = new ServiceCollection().AddSingleton(withValues).BuildServiceProvider();
        await CallFilter.Run(request, null, valueServices, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "1" }] }), default);
        var last = System.Text.Json.JsonDocument.Parse(File.ReadAllLines(path)[^1]).RootElement;
        Assert.Equal("Ns.Type", last.GetProperty("args").GetProperty("type").GetString());

        // Off by default; never an engine database.
        Assert.Null(ServerOptions.Parse([]).TracePath);
        Assert.False(ServerOptions.Parse([]).TraceArguments);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse([ServerOptions.TraceOption, dir.File("app.i64")]));
    }

    [Fact]
    public async Task The_audit_log_has_one_line_per_call_with_the_input_and_result_hashes()
    {
        using var dir = new TempDir();
        var input = dir.File("sample.bin");
        File.WriteAllBytes(input, [1, 2, 3, 4]);
        var path = dir.File("audit.jsonl");
        var options = ServerOptions.Parse([ServerOptions.AuditOption, path]);
        Assert.Equal(Path.GetFullPath(path), options.AuditPath);
        using var services = new ServiceCollection().AddSingleton(options).BuildServiceProvider();
        var request = new CallToolRequestParams
        {
            Name = "summarize_file",
            Arguments = new Dictionary<string, System.Text.Json.JsonElement> { ["path"] = System.Text.Json.JsonSerializer.SerializeToElement(input) },
        };
        await CallFilter.Run(request, null, services, _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "12345" }] }), default, "sample-client");
        await CallFilter.Run(new CallToolRequestParams { Name = "server_status" }, null, services,
            _ => ValueTask.FromResult(new CallToolResult { Content = [new TextContentBlock { Text = "ok" }] }), default);
        var lines = File.ReadAllLines(path).Select(l => System.Text.Json.JsonDocument.Parse(l).RootElement).ToList();
        Assert.Equal(2, lines.Count);
        var first = lines[0];
        Assert.Equal(("summarize_file", "sample-client", Corvus.Setup.Installation.Version, Environment.UserName),
            (first.GetProperty("tool").GetString(), first.GetProperty("client").GetString(), first.GetProperty("version").GetString(),
             first.GetProperty("user").GetString()!.Split('\\')[^1]));
        Assert.Equal(input, first.GetProperty("arguments").GetProperty("path").GetString());
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(input))), first.GetProperty("inputSha256").GetString());
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData("12345"u8)), first.GetProperty("resultSha256").GetString());
        Assert.True(DateTimeOffset.TryParse(first.GetProperty("time").GetString(), out var time) && time.Offset == TimeSpan.Zero);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, lines[1].GetProperty("inputSha256").ValueKind);
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            Assert.Null(Corvus.Native.Providers.PrivateFile.OtherWriters(file));
    }

    [Fact]
    public void An_audit_path_outputs_may_not_reach_is_refused_at_start_up()
    {
        using var dir = new TempDir();
        var e = Assert.Throws<ArgumentException>(() => ServerOptions.Parse([ServerOptions.AuditOption, Path.Combine(dir.Path, ".git", "audit.jsonl")]));
        Assert.Contains("in a repository's .git folder", e.Message);
        Assert.Null(ServerOptions.Parse([]).AuditPath);
    }

    [Fact]
    public void The_log_level_option_parses_and_rejects_unknown_levels()
    {
        Assert.Equal(LogLevel.Information, ServerOptions.Parse([]).LogLevel);
        Assert.Equal(LogLevel.Debug, ServerOptions.Parse(["--log-level", "Debug"]).LogLevel);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--log-level", "loud"]));
    }
}
