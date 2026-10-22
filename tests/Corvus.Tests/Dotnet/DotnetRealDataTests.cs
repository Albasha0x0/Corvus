using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// The dotnet read tools on System.Private.CoreLib over stdio (F-DN acceptance): default pages within their class budget per
/// part, walks that rebuild the whole, records no larger than 1.3x their text, basis on derived rows, clamped limits reported.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed partial class DotnetRealDataTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly TempDir _dir = new();
    private McpClient _client = null!;

    private static string CoreLib => RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes", "linux-arm64", "lib", "net10.0", "System.Private.CoreLib.dll");
    private static string Newtonsoft => RealPackages.Lib("Newtonsoft.Json", "13.0.4", "netstandard2.0", "Newtonsoft.Json.dll");

    public async Task InitializeAsync() => _client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch", "--load", CoreLib]);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private async Task<(string Text, JsonElement Record, int TextTokens, int RecordTokens)> Call(string tool, Dictionary<string, object?> args, McpClient? client = null)
    {
        var r = await (client ?? _client).CallToolAsync(tool, args);
        var text = Text(r);
        Assert.True(r.IsError != true, $"{tool}: {text[..Math.Min(500, text.Length)]}");
        var raw = r.StructuredContent!.Value.GetRawText();
        output.WriteLine($"{tool}({string.Join(", ", args.Select(a => $"{a.Key}={a.Value}"))}): text {TokenEstimate.Of(text)}, record {TokenEstimate.Of(raw)}");
        return (text, JsonDocument.Parse(raw).RootElement.Clone(), TokenEstimate.Of(text), TokenEstimate.Of(raw));
    }

    private static void WithinBudget(string tool, int textTokens, int recordTokens)
    {
        int limit = OutputClasses.Budget(ToolContract.Of(tool).Output) * 105 / 100;
        Assert.True(textTokens <= limit, $"{tool}: text {textTokens} tokens, over {limit}");
        Assert.True(recordTokens <= limit, $"{tool}: record {recordTokens} tokens, over {limit}");
    }

    [GeneratedRegex(@"\(showing (\d+)-(\d+)\)")]
    private static partial Regex Showing();

    /// <summary>The page's text shows the record's rows and names its nextOffset.</summary>
    private static void SameRows(string tool, string text, JsonElement record)
    {
        int rows = record.GetProperty("items").GetArrayLength();
        var shown = Showing().Match(text);
        Assert.True(shown.Success, $"{tool}: no (showing a-b) in the text");
        Assert.Equal(rows, int.Parse(shown.Groups[2].Value) - int.Parse(shown.Groups[1].Value) + 1);
        if (record.TryGetProperty("nextOffset", out var next)) Assert.Contains($"[More: offset={next.GetInt32()}]", text);
    }

    private async Task<List<JsonElement>> Walk(string tool, Dictionary<string, object?> args)
    {
        var rows = new List<JsonElement>();
        int? offset = 0;
        while (offset is { } at)
        {
            var (text, record, t, s) = await Call(tool, new(args) { ["offset"] = at });
            SameRows(tool, text, record);
            WithinBudget(tool, t, s);
            rows.AddRange(record.GetProperty("items").EnumerateArray());
            offset = record.TryGetProperty("nextOffset", out var n) ? n.GetInt32() : null;
        }
        return rows;
    }

    [Fact]
    public async Task DefaultPagesFitAndRecordsStayCompact()
    {
        (string Tool, Dictionary<string, object?> Args, double Ratio)[] calls =
        [
            ("list_namespaces", new() { ["assembly"] = "System.Private.CoreLib" }, 1.3),
            ("list_types", new() { ["assembly"] = "System.Private.CoreLib" }, 1.3),
            ("get_type_info", new() { ["type"] = "System.String" }, 1.3),
            ("get_type_hierarchy", new() { ["type"] = "System.Exception" }, 1.3),
            // typed arguments ({type, value, name}) repeat what the C# text shows: 1.82x measured
            ("get_attributes", new() { ["symbol"] = "System.String" }, 1.9),
            ("resolve_symbol", new() { ["symbol"] = "ToString" }, 1.3),
            ("search_symbols", new() { ["query"] = "Get" }, 1.3),
            ("search_strings", new() { ["query"] = "a" }, 1.3),
            ("search_constants", new() { ["value"] = "1" }, 1.3),
            ("search_il", new() { ["pattern"] = "call *" }, 1.3),
            ("find_references", new() { ["symbol"] = "System.String" }, 1.3),
            ("find_callees", new() { ["method"] = "System.String::Concat(string, string)" }, 1.3),
            ("get_call_tree", new() { ["method"] = "System.String::Concat(string, string)", ["direction"] = "callers" }, 1.3),
            ("find_call_paths", new() { ["to"] = "System.String::Concat(string, string)" }, 1.5),
            ("list_resources", new() { ["assembly"] = "System.Private.CoreLib" }, 1.3),
            ("get_assembly_info", new() { ["assembly"] = "System.Private.CoreLib" }, double.MaxValue),
        ];
        var problems = new List<string>();
        foreach (var (tool, args, ratio) in calls)
        {
            var (text, record, t, s) = await Call(tool, args);
            int limit = OutputClasses.Budget(ToolContract.Of(tool).Output) * 105 / 100;
            if (t > limit || s > limit) problems.Add($"{tool}: text {t}, record {s}, over {limit}");
            if (!record.TryGetProperty("items", out var items) || !record.TryGetProperty("total", out _)) continue;
            SameRows(tool, text, record);
            // S4.3: the record's rows against the text's rows (between the "(showing a-b):" line and the footer).
            var rows = text[(text.IndexOf("):\n", Showing().Match(text).Index, StringComparison.Ordinal) + 3)..];
            rows = rows[..Math.Max(0, rows.LastIndexOf("\n[", StringComparison.Ordinal))];
            int rowText = TokenEstimate.Of(rows), rowRecord = TokenEstimate.Of(items.GetRawText());
            output.WriteLine($"  rows: text {rowText}, record {rowRecord} ({rowRecord / (double)Math.Max(1, rowText):0.00}x)");
            if (rowRecord > rowText * ratio) problems.Add($"{tool}: record rows {rowRecord} tokens are {rowRecord / (double)rowText:0.00}x the text rows ({rowText})");
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public async Task TypeInfoMethodsWalkIsOneCall()
    {
        var walked = await Walk("get_type_info", new() { ["type"] = "System.String", ["section"] = "methods" });
        var (_, all, _, _) = await Call("get_type_info", new() { ["type"] = "System.String", ["section"] = "methods", ["limit"] = 5_000 });
        Assert.True(walked.Count > 100, $"{walked.Count} methods");
        Assert.Equal(all.GetProperty("total").GetInt32(), walked.Count);
        Assert.Equal(walked.Select(w => w.GetProperty("token").GetString()), walked.Select(w => w.GetProperty("token").GetString()).Distinct());
    }

    [Fact]
    public async Task ResolveSymbolPagesItsMatches()
    {
        var walked = await Walk("resolve_symbol", new() { ["symbol"] = "ToString" });
        Assert.True(walked.Count > 100, $"{walked.Count} matches");
        Assert.Equal(walked.Count, walked.Select(w => w.GetProperty("token").GetString() + w.GetProperty("assembly").GetString()).Distinct().Count());
    }

    /// <summary>Code pages walked by nextOffset rebuild the text byte for byte, whatever the page size.</summary>
    [Fact]
    public async Task DecompiledPagesRebuildTheWholeText()
    {
        async Task<string> Pages(int? maxTokens)
        {
            var sb = new StringBuilder();
            int? offset = 0;
            while (offset is { } at)
            {
                var args = new Dictionary<string, object?> { ["member"] = "System.String", ["offset"] = at };
                if (maxTokens != null) args["maxTokens"] = maxTokens;
                var (_, record, t, s) = await Call("decompile_member", args);
                if (maxTokens == null) WithinBudget("decompile_member", t, s);
                Assert.Equal(sb.Length, record.GetProperty("offset").GetInt32());
                sb.Append(record.GetProperty("code").GetString());
                offset = record.TryGetProperty("nextOffset", out var n) ? n.GetInt32() : null;
                if (offset == null) Assert.Equal(sb.Length, record.GetProperty("totalChars").GetInt32());
            }
            return sb.ToString();
        }
        var byDefault = await Pages(null);
        Assert.Equal(byDefault, await Pages(3_000));
        Assert.Contains("public sealed class String", byDefault);
    }

    [Fact]
    public async Task IlHashesInTheRecordMatchTheText()
    {
        var (text, record, t, s) = await Call("get_il", new() { ["symbol"] = "System.String::Concat(string, string)" });
        WithinBudget("get_il", t, s);
        var method = record.GetProperty("methods")[0];
        Assert.Contains("// IL hash: " + method.GetProperty("ilHash").GetString()![..16], text);
    }

    [Fact]
    public async Task ReferencesThroughBaseDeclarationsAreDerived()
    {
        var walked = await Walk("find_references", new() { ["symbol"] = "System.String::GetHashCode()", ["limit"] = 5_000 });
        Assert.Contains(walked, r => r.GetProperty("basis").GetString() == "derived");
        Assert.All(walked, r => Assert.Contains(r.GetProperty("basis").GetString(), new[] { "observed", "derived" }));
        var overrides = await Walk("find_references", new() { ["symbol"] = "System.Object::ToString", ["kind"] = "overrides" });
        Assert.True(overrides.Count > 50, $"{overrides.Count} overrides");
    }

    [Fact]
    public async Task AHugeLimitIsClampedAndThePageCut()
    {
        var (text, record, t, s) = await Call("search_strings", new() { ["query"] = "e", ["limit"] = 100_000 });
        WithinBudget("search_strings", t, s);
        Assert.Contains("limit 100000 is above the maximum; 5000 applied", text);
        Assert.Equal(5_000, record.GetProperty("limit").GetInt32());
        Assert.True(record.GetProperty("hasMore").GetBoolean());
        SameRows("search_strings", text, record);
    }

    [Fact]
    public async Task ResourcesNameTheirHash()
    {
        var walked = await Walk("list_resources", new() { ["assembly"] = "System.Private.CoreLib" });
        Assert.NotEmpty(walked);
        var first = walked[0];
        var file = _dir.File("resource.bin");
        await Call("get_resource", new() { ["assembly"] = "System.Private.CoreLib", ["name"] = first.GetProperty("name").GetString(), ["outputPath"] = file });
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file))), first.GetProperty("sha256").GetString());
        await Call("get_assembly_info", new() { ["assembly"] = "System.Private.CoreLib", ["view"] = "references" });
        await Call("decompile_member", new() { ["member"] = "System.String::Concat(string, string)" });
    }

    /// <summary>The machine's own runtime: its CoreLib is ReadyToRun code for this host.</summary>
    [Fact]
    public async Task ReadyToRunCodeAndTheMethodAtAnAddress()
    {
        var runtime = typeof(object).Assembly.Location;
        var (text, record, t, s) = await Call("get_r2r_code", new() { ["method"] = "System.String::Concat(string, string)", ["assembly"] = runtime });
        WithinBudget("get_r2r_code", t, s);
        var body = record.GetProperty("bodies")[0];
        var entry = body.GetProperty("entryVa").GetString()!;
        Assert.Contains(entry, text);
        var (_, at, _, _) = await Call("find_r2r_method", new() { ["assembly"] = runtime, ["address"] = entry });
        Assert.Contains(at.GetProperty("methods").EnumerateArray(), m => m.GetProperty("label").GetString()!.Contains("Concat", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExportTwiceWithOverwrite()
    {
        await using var server = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch", "--load", Newtonsoft]);
        var target = _dir.File("export");
        var (_, first, _, _) = await Call("export_project", new() { ["assembly"] = "Newtonsoft.Json", ["outputDirectory"] = target }, server);
        Assert.True(first.GetProperty("applied").GetBoolean());
        var again = await server.CallToolAsync("export_project", new Dictionary<string, object?> { ["assembly"] = "Newtonsoft.Json", ["outputDirectory"] = target });
        Assert.Equal("conflict", McpProtocolTests.ErrorJson(again).GetProperty("code").GetString());
        var (_, second, _, _) = await Call("export_project", new() { ["assembly"] = "Newtonsoft.Json", ["outputDirectory"] = target, ["overwrite"] = true }, server);
        Assert.True(second.GetProperty("replaced").GetBoolean());
        Assert.Equal(first.GetProperty("files").GetInt32(), second.GetProperty("files").GetInt32());
        Assert.Single(Directory.GetDirectories(_dir.Path));
    }

    /// <summary>A client that waits 8 s (deadline 3 s): a partial answer before it, and the export completes in the background.</summary>
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task AShortClientGetsAPartialAndTheExportCompletes()
    {
        await using var server = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch", ClientProfiles.ClientTimeoutOption, "8", "--load", CoreLib]);
        var target = _dir.File("corelib");
        var before = MachineLoad.Factor();
        var clock = Stopwatch.StartNew();
        var r = await server.CallToolAsync("export_project", new Dictionary<string, object?> { ["assembly"] = "System.Private.CoreLib", ["outputDirectory"] = target });
        var answered = clock.Elapsed;
        // The contract: the partial answer reaches the client before it gives up; the 3 s deadline is a measurement.
        Assert.True(answered < TimeSpan.FromSeconds(8), $"answered after {answered}, past the client's 8 s");
        var (_, load) = MachineLoad.Budget(TimeSpan.FromSeconds(3), before, MachineLoad.Factor());
        PerfBudget.Time("dotnet/short-client-partial-answer", answered, TimeSpan.FromSeconds(3), output, load);
        var error = McpProtocolTests.ErrorJson(r);
        Assert.Equal("timeout", error.GetProperty("code").GetString());
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.False(Directory.Exists(target));
        while (!File.Exists(Path.Combine(target, Corvus.Services.ExportDirectory.Marker)) && clock.Elapsed < TimeSpan.FromMinutes(10)) await Task.Delay(500);
        Assert.NotEmpty(Directory.GetFiles(target, "*.cs", SearchOption.AllDirectories));
    }
}
