using System.Diagnostics;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace NetDecompilerMcp.Tests;

/// <summary>Over stdio, on a real library: results that would be huge come back bounded, and a cancelled call stops.</summary>
public abstract class ResultBoundsTests : IAsyncLifetime
{
    private const int MaxOutput = 20_000;
    /// <summary>The largest page a caller can ask for with maxChars (see OutputPager.Page).</summary>
    private const int MaxPage = 500_000;
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
            ("decompile_type", new() { ["type"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader" }),
            ("decompile_type", new() { ["type"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader", ["maxChars"] = int.MaxValue }),
            ("get_il", new() { ["symbol"] = "Newtonsoft.Json.Serialization.JsonSerializerInternalReader" }),
            ("search_symbols", new() { ["query"] = "*", ["limit"] = int.MaxValue }),
            ("list_types", new() { ["limit"] = int.MaxValue }),
            ("search_strings", new() { ["query"] = "*", ["limit"] = int.MaxValue }),
            ("search_il", new() { ["pattern"] = "call *", ["limit"] = int.MaxValue }),
            ("find_references", new() { ["symbol"] = "Newtonsoft.Json.JsonReader::Read", ["limit"] = int.MaxValue }),
            ("get_call_tree", new() { ["method"] = "Newtonsoft.Json.JsonReader::Read", ["depth"] = int.MaxValue, ["maxNodes"] = int.MaxValue }),
            ("find_call_paths", new() { ["to"] = "Newtonsoft.Json.JsonReader::Read", ["maxDepth"] = int.MaxValue, ["maxPaths"] = int.MaxValue }),
            ("get_type_hierarchy", new() { ["type"] = "System.Object", ["limit"] = int.MaxValue }),
            ("extract_strings", new() { ["assembly"] = "Newtonsoft.Json" }),
            ("survey_features", new() { ["assembly"] = "Newtonsoft.Json" }),
        ];

        /// <summary>Each page stays within the server's limit (or the caller's maxChars, itself capped), text and structured content alike.</summary>
        [Trait("Speed", "Slow")]
        [Fact]
        public async Task HugeResultsComeBackPaged()
        {
            var problems = new List<string>();
            foreach (var (tool, args) in Unbounded())
            {
                using var cts = new CancellationTokenSource(ContractSweep.CallLimit);
                var watch = Stopwatch.StartNew();
                var result = await _client.CallToolAsync(tool, args, cancellationToken: cts.Token);
                var text = Text(result);
                int structured = result.StructuredContent?.ToString().Length ?? 0;
                output.WriteLine($"{tool} ({string.Join(", ", args.Keys)}): {text.Length} chars of text, {structured} structured, {watch.ElapsedMilliseconds} ms");
                if (result.IsError == true) problems.Add($"{tool}: {text[..Math.Min(300, text.Length)]}");
                // The page plus its header and footer.
                int limit = (args.ContainsKey("maxChars") ? MaxPage : MaxOutput) + 500;
                if (text.Length > limit) problems.Add($"{tool} ({string.Join(", ", args.Keys)}): {text.Length} chars of text, over {limit}");
                if (structured > MaxOutput + 500) problems.Add($"{tool}: {structured} chars of structured content, over {MaxOutput + 500}");
            }
            Assert.True(problems.Count == 0, string.Join("\n", problems));
        }
    }

    public sealed class Cancellation(Xunit.Abstractions.ITestOutputHelper output) : ResultBoundsTests
    {
        protected override string? ProtocolVersion => "2025-11-25";

        [Fact]
        public async Task CancelledCallStopsAndTheServerStaysResponsive()
        {
            // The SDK's client does not send notifications/cancelled when a call's token is cancelled, so the call and its
            // cancellation are sent by hand, back to back: the server reads the cancellation right after starting the call,
            // seconds before the export could end, however late this process gets to run.
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

            // A read and an edit (which needs the exclusive lock, so waits for the export to let go) both answer; the time is
            // logged rather than asserted, as a machine busy with other tests can make the first calls slow.
            var watch = Stopwatch.StartNew();
            using var limit = new CancellationTokenSource(ContractSweep.CallLimit);
            var read = await _client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Newtonsoft.Json.JsonConvert" }, cancellationToken: limit.Token);
            Assert.Contains("SerializeObject", Text(read));
            var edit = await _client.CallToolAsync("stub_method",
                new Dictionary<string, object?> { ["method"] = "Newtonsoft.Json.JsonConvert::ToString(bool)", ["value"] = "\"x\"" }, cancellationToken: limit.Token);
            Assert.True(edit.IsError != true, Text(edit));
            Assert.Equal(files, Files());
            output.WriteLine($"read and edit after the cancellation: {watch.ElapsedMilliseconds} ms");
        }
    }
}
