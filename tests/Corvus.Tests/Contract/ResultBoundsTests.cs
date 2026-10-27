using System.Diagnostics;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Over stdio, on a real library: results that would be huge come back bounded, and a cancelled call stops.</summary>
public abstract class ResultBoundsTests : IAsyncLifetime
{
    private const int MaxOutput = 20_000;
    private readonly TempDir _dir = new();
    private McpClient _client = null!;

    private static string Library => RealPackages.Lib("Newtonsoft.Json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll");

    /// <summary>The protocol version the client speaks (null: the SDK's newest).</summary>
    protected virtual string? ProtocolVersion => null;

    private string Trace => _dir.File("trace.jsonl");

    public async Task InitializeAsync() => _client = await McpProtocolTests.StartServerAsync(null, ProtocolVersion,
        ["--no-index", "--no-watch", "--max-output", MaxOutput.ToString(), "--trace", Trace, "--load", Library]);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    public sealed class Paging(Xunit.Abstractions.ITestOutputHelper output) : ResultBoundsTests
    {
        /// <summary>Calls that ask for everything (no or extreme limits).</summary>
        private static IEnumerable<(string Tool, Dictionary<string, object?> Args)> Unbounded() =>
        [
            ("decompile_member", new() { ["member"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader" }),
            ("decompile_member", new() { ["member"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader", ["maxTokens"] = int.MaxValue }),
            ("get_il", new() { ["symbol"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader" }),
            ("search_symbols", new() { ["query"] = "*", ["limit"] = int.MaxValue }),
            ("list_types", new() { ["limit"] = int.MaxValue }),
            ("search_strings", new() { ["query"] = "*", ["limit"] = int.MaxValue }),
            ("search_il", new() { ["pattern"] = "call *", ["limit"] = int.MaxValue }),
            ("find_references", new() { ["symbol"] = "Newtonsoft.Json.JsonReader::Read", ["limit"] = int.MaxValue }),
            ("get_call_tree", new() { ["method"] = "Newtonsoft.Json.JsonReader::Read", ["depth"] = int.MaxValue, ["limit"] = int.MaxValue }),
            ("find_call_paths", new() { ["to"] = "Newtonsoft.Json.JsonReader::Read", ["maxDepth"] = int.MaxValue, ["limit"] = int.MaxValue }),
            ("get_type_hierarchy", new() { ["type"] = "System.Object", ["limit"] = int.MaxValue }),
            ("extract_strings", new() { ["assembly"] = "Newtonsoft.Json" }),
            ("survey_features", new() { ["assembly"] = "Newtonsoft.Json" }),
        ];

        /// <summary>Each part of a page stays within its class budget (or maxTokens up to the client ceiling) + 5%, in estimated tokens.</summary>
        [Trait("Speed", "Slow")]
        [Fact]
        public async Task Huge_results_come_back_paged()
        {
            var problems = new List<string>();
            // Untimed warm-up: the test claims bounded pages, not cold-start time, so the decompiler is JIT-compiled first.
            await _client.CallToolAsync("decompile_member", new Dictionary<string, object?> { ["member"] = "Newtonsoft.Json.JsonConvert" });
            foreach (var (tool, args) in Unbounded())
            {
                using var cts = new CancellationTokenSource(ContractSweep.CallLimit);
                var watch = Stopwatch.StartNew();
                var result = await _client.CallToolAsync(tool, args, cancellationToken: cts.Token);
                var text = Text(result);
                int structured = result.StructuredContent?.ToString().Length ?? 0;
                output.WriteLine($"{tool} ({string.Join(", ", args.Keys)}): {text.Length} chars of text, {structured} structured, {watch.ElapsedMilliseconds} ms");
                if (result.IsError == true) problems.Add($"{tool}: {text[..Math.Min(300, text.Length)]}");
                int budget = args.ContainsKey("maxTokens") ? Corvus.Core.ClientProfiles.Unknown.MaxTokens : Corvus.Mcp.OutputClasses.Budget(Corvus.Mcp.ToolContract.Of(tool).Output);
                int limit = budget * 105 / 100, textTokens = Corvus.Core.TokenEstimate.Of(text);
                int structuredTokens = result.StructuredContent is { } s ? Corvus.Core.TokenEstimate.Of(s.ToString()) : 0;
                if (textTokens > limit) problems.Add($"{tool} ({string.Join(", ", args.Keys)}): {textTokens} tokens of text, over {limit}");
                if (structuredTokens > limit) problems.Add($"{tool}: {structuredTokens} tokens of structured content, over {limit}");
            }
            Assert.True(problems.Count == 0, string.Join("\n", problems));
        }
    }

    public sealed class Cancellation(Xunit.Abstractions.ITestOutputHelper output) : ResultBoundsTests
    {
        protected override string? ProtocolVersion => "2025-11-25";

        [Fact]
        public async Task Cancelled_call_stops_and_the_server_stays_responsive()
        {
            // The SDK client sends no notifications/cancelled, so the call and its cancellation go by hand, back to back.
            var exportDir = _dir.File("export");
            var id = new RequestId("export-to-cancel");
            var arguments = new Dictionary<string, System.Text.Json.JsonElement>
            {
                ["assembly"] = System.Text.Json.JsonSerializer.SerializeToElement("Newtonsoft.Json"),
                ["outputDirectory"] = System.Text.Json.JsonSerializer.SerializeToElement(exportDir),
            };
            _ = _client.SendRequestAsync<CallToolRequestParams, CallToolResult>(RequestMethods.ToolsCall,
                new CallToolRequestParams { Name = "export_project", Arguments = arguments }, ModelContextProtocol.McpJsonUtilities.DefaultOptions, id)
                .AsTask().ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted); // never answered once cancelled
            int Files() => Directory.Exists(exportDir) ? Directory.EnumerateFiles(exportDir, "*", SearchOption.AllDirectories).Count() : 0;
            await _client.SendNotificationAsync(NotificationMethods.CancelledNotification,
                new CancelledNotificationParams { RequestId = id, Reason = "test" }, ModelContextProtocol.McpJsonUtilities.DefaultOptions);

            // The export's handler ends as cancelled, and writes nothing after that.
            Assert.Equal("cancelled", await McpProtocolTests.TracedOutcome(Trace, "export_project", TimeSpan.FromMinutes(2)));
            int files = Files();

            // A read and an edit both answer while the cancelled export winds down, each within the sweep's per-call limit.
            var watch = Stopwatch.StartNew();
            using var readLimit = new CancellationTokenSource(ContractSweep.CallLimit);
            var read = await _client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Newtonsoft.Json.JsonConvert", ["section"] = "methods", ["limit"] = 500 }, cancellationToken: readLimit.Token);
            Assert.Contains("SerializeObject", Text(read));
            output.WriteLine($"read after the cancellation: {watch.ElapsedMilliseconds} ms");
            watch.Restart();
            using var editLimit = new CancellationTokenSource(ContractSweep.CallLimit);
            var edit = await _client.CallToolAsync("stub_method",
                new Dictionary<string, object?> { ["method"] = "Newtonsoft.Json.JsonConvert::ToString(bool)", ["value"] = "\"x\"", ["dryRun"] = false }, cancellationToken: editLimit.Token);
            Assert.True(edit.IsError != true, Text(edit));
            Assert.Equal(files, Files());
            output.WriteLine($"edit after the read: {watch.ElapsedMilliseconds} ms");
        }
    }
}
