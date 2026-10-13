using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The result builder and the filter's fitting: budgets per part, one continuation, the same rows in both parts.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public class ToolOutputTests
{
    private static ServiceProvider Services(ServerOptions? options = null) =>
        new ServiceCollection().AddSingleton(options ?? new ServerOptions()).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly)).AddSingleton(new OutputPager(options ?? new ServerOptions()))
            .BuildServiceProvider();

    private static JsonElement Schema(params string[] parameters) =>
        JsonSerializer.SerializeToElement(new { type = "object", properties = parameters.ToDictionary(p => p, p => (object)new { type = "integer" }) });

    private static Task<CallToolResult> Call(ServiceProvider services, string tool, Func<CallToolRequestParams, CallToolResult> work,
        Dictionary<string, object?>? args = null, JsonElement? schema = null)
    {
        var request = new CallToolRequestParams
        {
            Name = tool,
            Arguments = (args ?? []).ToDictionary(a => a.Key, a => JsonSerializer.SerializeToElement(a.Value)),
        };
        return CallFilter.Run(request, schema, services, _ => ValueTask.FromResult(work(request)), default).AsTask();
    }

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private static JsonElement Record(CallToolResult r) => JsonDocument.Parse(r.StructuredContent!.Value.GetRawText()).RootElement;

    private static int Tokens(string s) => TokenEstimate.Of(s);

    private static TypeList Types(int offset, int count, int total) =>
        new(Enumerable.Range(offset, count).Select(i => new TypeEntry($"0x{i:X8}", $"Some.Namespace.Of.Types.Type{i}") { Assembly = "A" }).ToList(), offset, total);

    /// <summary>A bare record (the SDK puts its JSON in the text block): readable text from the same rows, the list envelope, no truncated.</summary>
    [Fact]
    public async Task BareListRecordIsRenderedAndFitted()
    {
        using var services = Services();
        var record = Types(0, 2_000, 5_000);
        var r = await Call(services, "list_types", _ => new CallToolResult
        {
            Content = [new TextContentBlock { Text = JsonSerializer.Serialize(record, Catalog.ToolSerializerOptions) }],
            StructuredContent = JsonSerializer.SerializeToElement(record, Catalog.ToolSerializerOptions),
        });
        var text = Text(r);
        var json = Record(r);
        int rows = json.GetProperty("items").GetArrayLength();
        Assert.InRange(rows, 10, 1_999);
        Assert.False(json.TryGetProperty("truncated", out _));
        Assert.True(json.GetProperty("hasMore").GetBoolean());
        Assert.Equal(rows, json.GetProperty("nextOffset").GetInt32());
        Assert.True(json.GetProperty("totalExact").GetBoolean());
        Assert.Contains($"(showing 1-{rows})", text);
        Assert.EndsWith($"[More: offset={rows}]\n", text);
        Assert.Equal(rows + 1, text.Split('\n').Count(l => l.StartsWith("  ", StringComparison.Ordinal))); // header row + rows
        Assert.NotEqual(r.StructuredContent!.Value.GetRawText(), text);
        // Fitted 5% under the 6,000 budget (CallFilter.FitTokens).
        Assert.InRange(Tokens(text), 1, 5_700);
        Assert.InRange(Tokens(r.StructuredContent!.Value.GetRawText()), 1, 5_700);
        Assert.DoesNotContain(":null", r.StructuredContent!.Value.GetRawText());
    }

    /// <summary>PageRows text with a record: both parts keep the same rows, the text re-rendered with the record's count.</summary>
    [Fact]
    public async Task PagedTextAndRecordKeepTheSameRows()
    {
        var options = new ServerOptions();
        using var services = Services(options);
        var pager = new OutputPager(options);
        // Rows cheap as text and heavy as JSON, so the record binds.
        var all = Enumerable.Range(0, 3_000).Select(i => $"r{i}").ToList();
        var r = await Call(services, "list_exports", request =>
        {
            var text = ToolOutput.With(pager.PageRows(all, 0, 3_000, "export"), new ExportList("img",
                all.Take(3_000).Select((_, i) => new ExportEntry(i, $"0x{i:X}", $"Name{i}WithAFairlyLongExportNameThatCostsTokens", null, null)).ToList(), 0, all.Count, false));
            return new CallToolResult { Content = [new TextContentBlock { Text = text }] };
        });
        var json = Record(r);
        int rows = json.GetProperty("items").GetArrayLength();
        Assert.InRange(rows, 10, 2_999);
        Assert.Contains($"(showing 1-{rows})", Text(r));
        Assert.Contains($"[More: offset={rows}]", Text(r));
        Assert.Equal(rows, json.GetProperty("nextOffset").GetInt32());
    }

    /// <summary>A tool whose text cannot be cut by rows is asked again for fewer rows, so both parts agree.</summary>
    [Fact]
    public async Task ToolTextThatCannotBeCutIsAskedForFewerRows()
    {
        using var services = Services();
        var limits = new List<int>();
        var r = await Call(services, "search_symbols", request =>
        {
            int limit = request.Arguments!["limit"].GetInt32();
            limits.Add(limit);
            var record = Types(0, limit, 10_000);
            var text = string.Join("\n", record.Items.Select(t => $"  {t.Name}  {t.Token} with some more words on the line")) + "\n";
            return new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With(text, record) }] };
        }, new() { ["limit"] = 5_000 }, Schema("limit", "offset"));
        Assert.True(limits.Count is 2 or 3, string.Join(",", limits));
        var json = Record(r);
        Assert.Equal(limits[^1], json.GetProperty("items").GetArrayLength());
        Assert.Equal(limits[^1], Text(r).Split('\n').Count(l => l.StartsWith("  Some", StringComparison.Ordinal)));
        Assert.Equal(limits[^1], json.GetProperty("nextOffset").GetInt32());
        Assert.InRange(Tokens(Text(r)), 1, 6_300);
    }

    [Fact]
    public async Task LimitsAreCheckedAndClamped()
    {
        using var services = Services();
        var schema = Schema("limit", "offset");
        int seen = 0;
        CallToolResult Work(CallToolRequestParams request)
        {
            seen = request.Arguments!["limit"].GetInt32();
            return new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("none\n", Types(0, 0, 0)) }] };
        }
        var zero = await Call(services, "list_types", Work, new() { ["limit"] = 0 }, schema);
        Assert.StartsWith("Error (invalid_argument) in list_types: limit must be from 1 to 5000, not 0.", Text(zero));
        var negative = await Call(services, "list_types", Work, new() { ["offset"] = -1 }, schema);
        Assert.StartsWith("Error (invalid_argument) in list_types: offset must be 0 or more", Text(negative));
        var huge = await Call(services, "list_types", Work, new() { ["limit"] = 1_000_000 }, schema);
        Assert.Equal(5_000, seen);
        Assert.Equal(5_000, Record(huge).GetProperty("limit").GetInt32());
        Assert.Contains("limit 1000000 is above the maximum; 5000 applied.", Text(huge));
        Assert.Contains("limit 1000000", Record(huge).GetProperty("warnings")[0].GetString());
        Assert.Equal(0, Record(huge).GetProperty("items").GetArrayLength());
        Assert.False(Record(huge).GetProperty("hasMore").GetBoolean());
    }

    /// <summary>D2: a read-only report over its budget keeps its head and names the whole result; never an error.</summary>
    [Fact]
    public async Task OversizedReportKeepsItsHeadAndAResultId()
    {
        using var services = Services();
        var big = string.Concat(Enumerable.Range(0, 5_000).Select(i => $"line {i} of the report with words\n"));
        var r = await Call(services, "get_pe_info", _ => new CallToolResult { Content = [new TextContentBlock { Text = big }] });
        Assert.NotEqual(true, r.IsError);
        var text = Text(r);
        Assert.StartsWith("line 0 of", text);
        var id = System.Text.RegularExpressions.Regex.Match(text, @"read_result id=(r-[0-9a-f]{12})").Groups[1].Value;
        Assert.InRange(Tokens(text), 1, 4_200);
        Assert.Equal(big, services.GetRequiredService<ResultStore>().Read(id).Text);
    }

    /// <summary>
    /// A text page that fits beside a record that does not: the kept result is the record, not the page (whose own footer would
    /// read as read_result's continuation), and the page is not shortened for a record it cannot fit.
    /// </summary>
    [Fact]
    public async Task OversizedRecordBesideAPageKeepsTheRecord()
    {
        var options = new ServerOptions();
        using var services = Services(options);
        var pager = new OutputPager(options);
        var body = string.Concat(Enumerable.Range(0, 400).Select(i => $"line {i}\n"));
        var rows = Enumerable.Range(0, 3_000).Select(i => new { block = $"0x{i:X8}", successors = new[] { $"0x{i + 1:X8}" } }).ToList();
        var r = await Call(services, "get_cfg", _ => new CallToolResult
        {
            Content = [new TextContentBlock { Text = ToolOutput.Text(pager, body, 0, new { function = "f", blocks = rows }) }],
        }, new() { ["maxTokens"] = 2_000 });
        var text = Text(r);
        Assert.StartsWith("line 0\nline 1\n", text);
        Assert.DoesNotContain("[More: offset=", text);
        var id = Record(r).GetProperty("resultId").GetString()!;
        var kept = services.GetRequiredService<ResultStore>().Read(id).Text;
        Assert.StartsWith("{", kept);
        Assert.DoesNotContain("[More: offset=", kept);
        Assert.InRange(Tokens(r.StructuredContent!.Value.GetRawText()), 1, 2_100);
        Assert.Matches($@"^Cut to fit: blocks \d+ of 3000 kept; read_result id={id} has the whole record$", Record(r).GetProperty("warnings")[0].GetString());
    }

    /// <summary>S2: a report record cut to its budget names every array that lost entries; the tool's own warnings stay first.</summary>
    [Fact]
    public async Task CutReportRecordNamesWhatItDropped()
    {
        using var services = Services();
        var sections = Enumerable.Range(0, 6).Select(i => new { name = $"s{i}", fields = Enumerable.Range(0, 40).Select(j => $"field {j} of section {i} with some words").ToArray() }).ToArray();
        var r = await Call(services, "server_status", _ =>
        {
            ToolOutput.Warn("stated by the tool");
            return new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.Report("status", new { server = "x", sections }) }] };
        }, new() { ["maxTokens"] = 1_000 });
        var record = Record(r);
        var warnings = record.GetProperty("warnings").EnumerateArray().Select(w => w.GetString()!).ToList();
        Assert.Equal("stated by the tool", warnings[0]);
        int kept = record.GetProperty("sections").GetArrayLength();
        Assert.InRange(kept, 1, 5);
        Assert.Contains($"sections {kept} of 6", warnings[1]);
        Assert.DoesNotContain($"sections[{kept}]", warnings[1]);
        Assert.InRange(Tokens(r.StructuredContent!.Value.GetRawText()), 1, 1_050);
    }

    /// <summary>An error over the error budget (160 compiler diagnostics) sends its head and keeps the full error (S1.3, G1).</summary>
    [Fact]
    public async Task LongErrorKeepsItsHeadWithinTheErrorBudget()
    {
        using var services = Services();
        var message = "C# compilation failed (160 error(s)). Nothing was changed.\n" +
                      string.Concat(Enumerable.Range(0, 160).Select(i => $"  CS1705 at decompiled context line {i}: Assembly 'PresentationFramework' uses 'WindowsBase, Version=6.0.2.0'\n"));
        var r = await Call(services, "add_members_csharp", _ => throw new ToolError(ErrorCode.InvalidArgument, message, "fix the body") { Details = new { parameter = "code" } });
        var first = ((TextContentBlock)r.Content[0]).Text;
        Assert.StartsWith("Error (invalid_argument) in add_members_csharp: C# compilation failed (160 error(s)).", first);
        Assert.EndsWith("\nNext: fix the body", first);
        Assert.InRange(Tokens(first), 1, 1_000);
        var json = McpProtocolTests.ErrorJson(r);
        var id = json.GetProperty("details").GetProperty("resultId").GetString()!;
        Assert.Equal("code", json.GetProperty("details").GetProperty("parameter").GetString());
        Assert.Contains($"read_result id={id}", first);
        Assert.Contains("line 159:", services.GetRequiredService<ResultStore>().Read(id).Text);
        var small = await Call(services, "add_members_csharp", _ => throw new ToolError(ErrorCode.InvalidArgument, "short", "fix it"));
        Assert.DoesNotContain("read_result", ((TextContentBlock)small.Content[0]).Text);
    }

    /// <summary>maxTokens raises the page up to the client ceiling; below 500 it is an argument error.</summary>
    [Fact]
    public async Task MaxTokensSetsTheBudget()
    {
        Assert.Equal(6_000, CallFilter.Budget("list_types", null, null));
        Assert.Equal(8_000, CallFilter.Budget("decompile_member", null, null));
        Assert.Equal(5_700, CallFilter.FitTokens(6_000));
        var limits = ClientProfiles.Resolve(new ServerOptions(), null);
        var args = new Dictionary<string, JsonElement> { ["maxTokens"] = JsonSerializer.SerializeToElement(24_000) };
        Assert.Equal(limits.MaxTokens, CallFilter.Budget("list_types", args, limits));
        args["maxTokens"] = JsonSerializer.SerializeToElement(100);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => CallFilter.Budget("list_types", args, limits)).Code);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task TextPagesCarryTheirPositionAndBody()
    {
        var options = new ServerOptions();
        using var services = Services(options);
        var pager = new OutputPager(options);
        var code = string.Concat(Enumerable.Range(0, 4_000).Select(i => $"    int value{i} = Compute({i}, \"text\");\r\n"));
        var r = await Call(services, "decompile_native", _ => new CallToolResult
        {
            Content = [new TextContentBlock { Text = ToolOutput.Text(pager, code, 0, new { function = "f" }) }],
        });
        var text = Text(r);
        var json = Record(r);
        Assert.DoesNotContain("\r", text);
        int next = json.GetProperty("nextOffset").GetInt32();
        Assert.Contains($"[More: offset={next}]", text);
        Assert.Equal(code.Replace("\r\n", "\n").Length, json.GetProperty("totalChars").GetInt32());
        Assert.StartsWith("    int value0", json.GetProperty("code").GetString());
        Assert.StartsWith(json.GetProperty("code").GetString()!, text, StringComparison.Ordinal);
        Assert.InRange(Tokens(text), 1, 8_400);
        Assert.InRange(Tokens(r.StructuredContent!.Value.GetRawText()), 1, 8_400);
    }

    [Fact]
    public async Task NoticesComeLastInBothParts()
    {
        var options = new ServerOptions();
        var workspace = new AssemblyWorkspace(options);
        using var services = new ServiceCollection().AddSingleton(options).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly)).AddSingleton(workspace).BuildServiceProvider();
        workspace.Notify("loaded x from y");
        var ok = await Call(services, "get_pe_info", _ => new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("summary\n", new { name = "x" }) }] });
        Assert.StartsWith("summary", Text(ok));
        Assert.EndsWith("[workspace] loaded x from y", Text(ok));
        Assert.Equal("loaded x from y", Record(ok).GetProperty("notices")[0].GetString());
        workspace.Notify("loaded x from y");
        var error = await Call(services, "get_pe_info", _ => throw new ToolError(ErrorCode.NotFound, "no such image"));
        Assert.StartsWith("Error (not_found)", ((TextContentBlock)error.Content[0]).Text);
        Assert.StartsWith("[workspace]", ((TextContentBlock)error.Content[^1]).Text);
    }

    /// <summary>S4.1 (c): an "Incomplete:" line of the tool's text reaches the record as a warning.</summary>
    [Fact]
    public async Task IncompleteTextBecomesAWarning()
    {
        using var services = Services();
        var r = await Call(services, "search_strings", _ => new CallToolResult
        {
            Content = [new TextContentBlock { Text = ToolOutput.With("Incomplete: the regex timed out on 1 string.\n0 occurrences\n", Types(0, 0, 0)) }],
        });
        Assert.Equal("Incomplete: the regex timed out on 1 string.", Record(r).GetProperty("warnings")[0].GetString());
        Assert.Null(ContractSweep.Incomplete("search_strings", Text(r), Record(r)));
    }

    [Fact]
    public async Task JsonModeSendsTheRecordAsText()
    {
        using var services = Services();
        Environment.SetEnvironmentVariable(CallFilter.ResultModeVariable, "json");
        try
        {
            var r = await Call(services, "get_pe_info", _ => new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("summary\n", new { name = "x", nothing = (string?)null }) }] });
            Assert.Equal("""{"name":"x"}""", Text(r));
        }
        finally
        {
            Environment.SetEnvironmentVariable(CallFilter.ResultModeVariable, null);
        }
    }

    [Fact]
    public async Task ProvenanceNamesInputsAndRecomputes()
    {
        using var services = Services();
        var r = await Call(services, "get_pe_info", _ => new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("summary\n", new { name = "x" }) }] },
            new() { ["path"] = Env.FixturePath });
        var p = r.Meta![ToolOutput.ProvenanceKey]!.AsObject();
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Env.FixturePath))), (string)p["input"]![0]!["sha256"]!);
        Assert.Equal(ToolOutput.ResultSha256(r), (string)p["resultSha256"]!);
        Assert.Equal("complete", (string)p["coverage"]!);
        Assert.Equal("get_pe_info", (string)p["tool"]!);
        Assert.InRange(p.ToJsonString().Length, 1, 1_024);
    }

    /// <summary>An error carries provenance too (inputs, tool, arguments, version), without a result hash or coverage.</summary>
    [Fact]
    public async Task ErrorsCarryProvenance()
    {
        using var services = Services();
        var r = await Call(services, "get_pe_info", _ => throw new ToolError(ErrorCode.Unsupported, "not a PE"), new() { ["path"] = Env.FixturePath });
        Assert.True(r.IsError);
        var p = r.Meta![ToolOutput.ProvenanceKey]!.AsObject();
        Assert.Equal("get_pe_info", (string)p["tool"]!);
        Assert.Equal(64, ((string)p["args"]!).Length);
        Assert.Single(p["input"]!.AsArray());
        Assert.NotNull(p["corvus"]);
        Assert.False(p.ContainsKey("resultSha256"));
        Assert.False(p.ContainsKey("coverage"));
    }

    [Fact]
    public void SchemasGetTheEnvelope()
    {
        var root = JsonNode.Parse("""
            {"type":"object","properties":{"items":{"type":"array"},"offset":{"type":"integer"},"total":{"type":"integer"},"truncated":{"type":"boolean"},
             "note":{"type":["string","null"]}},"required":["items","offset","total","truncated","note"]}
            """)!.AsObject();
        ToolOutput.Envelope(root, OutputClass.List);
        var props = root["properties"]!.AsObject();
        Assert.False(props.ContainsKey("truncated"));
        foreach (var f in new[] { "limit", "totalExact", "hasMore", "nextOffset", "notices", "warnings", "coverage", "resultId" }) Assert.True(props.ContainsKey(f), f);
        Assert.Equal(["items", "offset", "total"], root["required"]!.AsArray().Select(n => (string)n!));
    }

    /// <summary>Rows under another name (get_call_arguments's calls) get the list envelope and the text shows the same rows.</summary>
    [Fact]
    public async Task NamedRowArraysAreLists()
    {
        using var services = Services();
        var entries = Enumerable.Range(0, 3_000).Select(i => new { path = $"lib/Module{i}.dll", status = "changed", detail = $"0x{i:X8} bytes differ" }).ToArray();
        var record = JsonSerializer.SerializeToElement(new { oldFolder = "a", newFolder = "b", total = 3_000, offset = 0, truncated = false, entries, notes = new[] { "n" } }, Catalog.ToolSerializerOptions);
        var r = await Call(services, "compare_folders", _ => new CallToolResult { Content = [new TextContentBlock { Text = record.GetRawText() }], StructuredContent = record });
        var json = Record(r);
        int rows = json.GetProperty("entries").GetArrayLength();
        Assert.InRange(rows, 10, 2_999);
        Assert.False(json.TryGetProperty("truncated", out _));
        Assert.Equal(rows, json.GetProperty("nextOffset").GetInt32());
        Assert.Contains($"(showing 1-{rows})", Text(r));
    }

    /// <summary>A list without a row offset (get_call_tree) drops truncated and continues through a kept result.</summary>
    [Fact]
    public async Task ListsWithoutARowOffsetContinueThroughAResultId()
    {
        using var services = Services();
        var record = new { root = "A::B", items = Enumerable.Range(0, 5).Select(i => new { label = $"n{i}" }).ToArray(), total = 9, truncated = true };
        var r = await Call(services, "get_call_tree", _ => new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("A::B\n  n0\n", record) }] });
        var json = Record(r);
        Assert.False(json.TryGetProperty("truncated", out _));
        Assert.True(json.GetProperty("hasMore").GetBoolean());
        Assert.False(json.TryGetProperty("nextOffset", out _));
        var id = json.GetProperty("resultId").GetString()!;
        Assert.Contains($"read_result id={id}", Text(r));
        Assert.Null(ContractSweep.Incomplete("get_call_tree", Text(r), json));
    }

    /// <summary>A text tool declaring TextPageRecord gets its page, offset, nextOffset and totalChars as the record.</summary>
    [Fact]
    public async Task TextToolsGetAPageRecord()
    {
        var options = new ServerOptions();
        using var services = Services(options);
        var pager = new OutputPager(options);
        var body = string.Concat(Enumerable.Range(0, 3_000).Select(i => $"struct C{i} {{ int field{i}; }};\n"));
        var r = await Call(services, "generate_cpp_binding", _ =>
        {
            var text = pager.Page(body, 0);
            return new CallToolResult { Content = [new TextContentBlock { Text = text }], StructuredContent = JsonSerializer.SerializeToElement(text) };
        });
        var json = Record(r);
        int next = json.GetProperty("nextOffset").GetInt32();
        Assert.Equal(0, json.GetProperty("offset").GetInt32());
        Assert.Equal(body.Length, json.GetProperty("totalChars").GetInt32());
        Assert.Equal(body[..next], json.GetProperty("code").GetString());
        Assert.Contains($"[More: offset={next}]", Text(r));
    }

    /// <summary>A missing input path reads the same in every tool: the shared file text, or its directory twin for folder parameters.</summary>
    [Fact]
    public async Task MissingPathsShareOneText()
    {
        using var dir = new TempDir();
        var missing = dir.File("no-such");
        using var workspace = new AssemblyWorkspace();
        var add = Assert.Throws<ToolError>(() => workspace.AddSearchDirectory(missing));
        Assert.Equal(Targets.DirectoryNotFound(missing).Message, add.Message);
        var buckets = await Assert.ThrowsAsync<ToolError>(() => new Corvus.Services.MinidumpService().Bucket(missing, false, null, 4, null, false, false, 10, null, 0, 10, null, default));
        Assert.Equal(Targets.DirectoryNotFound(missing).Message, buckets.Message);
        var folders = Assert.Throws<ToolError>(() => new Corvus.Services.Analysis.FolderCompare().Compare(missing, dir.Path, null, null, null, 10, 0, 10, null, default));
        Assert.Equal(Targets.FileNotFound(missing).Message, folders.Message);
        Assert.All(new[] { add, buckets, folders }, e => Assert.Equal(Targets.FileNotFoundNext, e.NextFor(null)));
    }

    /// <summary>Timings (compare_folders' seconds) leave the record for _meta, so equal calls give equal records.</summary>
    [Fact]
    public async Task TimingsMoveToMeta()
    {
        using var services = Services();
        var record = JsonSerializer.SerializeToElement(new { view = "changed", seconds = 1.25 });
        var r = await Call(services, "compare_folders", _ => new CallToolResult { Content = [new TextContentBlock { Text = record.GetRawText() }], StructuredContent = record });
        Assert.False(Record(r).TryGetProperty("seconds", out _));
        Assert.Equal(1.25, (double)r.Meta!["corvus/timings"]!["seconds"]!);
    }

    /// <summary>Every list-shaped output schema has its rows where the filter looks for them.</summary>
    [Fact]
    public void EveryPagedSchemaNamesItsRows()
    {
        var missing = Catalog.OfThisBuild(Corvus.Core.Toolsets.All).Tools
            .Where(t => t["outputSchema"]?["properties"] is JsonObject props && props["offset"] is not null && props["total"] is not null && !ToolOutput.IsListSchema(props, (string)t["name"]!))
            .Select(t => $"{t["name"]}: [{string.Join(", ", t["outputSchema"]!["properties"]!.AsObject().Select(p => p.Key))}]").ToList();
        Assert.True(missing.Count == 0, "offset and total without items (add their rows to ToolOutput.RowArrays):\n" + string.Join("\n", missing));
    }

    [Fact]
    public void RendererAlignsRowsAndEscapesMarkers()
    {
        var record = JsonNode.Parse("""{"image":"a.dll","items":[{"name":"x","size":1},{"name":"Error (oops)","size":22}],"offset":0,"total":2}""")!.AsObject();
        var text = RecordText.Render(record, (0, 2, 2, false, 2));
        Assert.Equal("image: a.dll\n2 rows (showing 1-2):\n  name                size\n  x                   1\n  \\u2063Error (oops)  22\n[End: 2 rows]\n", text);
    }

    /// <summary>Fields past the column cap (dump_stack's token, ilOffset) stay in the text as one key=value cell.</summary>
    [Fact]
    public void RendererKeepsFieldsPastTheColumnCap()
    {
        var row = new JsonObject();
        for (int i = 0; i < 12; i++) row[$"c{i}"] = i;
        row["token"] = "0x06000006";
        row["ilOffset"] = 60;
        var record = new JsonObject { ["frames"] = new JsonArray(row, new JsonObject { ["c0"] = 1 }), ["offset"] = 0, ["total"] = 2 };
        var text = RecordText.Render(record, "frames", (0, 2, 2, false, 2));
        Assert.EndsWith("more", text.Split('\n')[1]);
        Assert.Contains("token=0x06000006; ilOffset=60", text);
    }
}
