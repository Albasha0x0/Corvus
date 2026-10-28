using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The result builder and the filter's fitting: budgets per part, one continuation, the same rows in both parts.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public class ToolOutputTests(ITestOutputHelper output)
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
    public async Task A_bare_list_record_is_rendered_and_fitted()
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
    public async Task Paged_text_and_record_keep_the_same_rows()
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
    public async Task Tool_text_that_cannot_be_cut_is_asked_for_fewer_rows()
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
    public async Task Limits_are_checked_and_clamped()
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
    public async Task An_oversized_report_keeps_its_head_and_a_result_ID()
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

    /// <summary>A page beside a record that does not fit: the kept result is the record, and the page is not shortened for it.</summary>
    [Fact]
    public async Task An_oversized_record_beside_a_page_keeps_the_record()
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
        Assert.Matches($@"^Cut to fit: blocks \d+ of 3000(, code characters \d+ of \d+)? kept; read_result id={id} has the whole record$", Record(r).GetProperty("warnings")[0].GetString());
    }

    /// <summary>A record cut by shortening a long string (a read_result page) names that string in its warning.</summary>
    [Fact]
    public async Task A_shortened_string_is_named_in_the_warning()
    {
        using var services = Services();
        var code = string.Concat(Enumerable.Range(0, 2_000).Select(i => $"line {i}\n"));
        var r = await Call(services, "server_status", _ => new CallToolResult
        {
            Content = [new TextContentBlock { Text = ToolOutput.Report("page", new { id = "r-0", code }) }],
        }, new() { ["maxTokens"] = 2_000 });
        Assert.Matches($@"^Cut to fit: code characters \d+ of {code.Length} kept; read_result id=r-[0-9a-f]{{12}} has the whole record$",
            Record(r).GetProperty("warnings")[0].GetString());
    }

    /// <summary>N9: a 20,000-node record is cut to its budget in a few passes (one pass per dropped row took 87 s).</summary>
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_huge_record_is_cut_within_its_time_budget()
    {
        using var services = Services();
        var nodes = Enumerable.Range(0, 20_000).Select(i => new { address = $"0x{i:X8}", name = $"sub_{i:X8}", depth = i % 7, callees = new[] { $"0x{i + 1:X8}", $"0x{i + 2:X8}" } }).ToList();
        OutputCall? call = null;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var r = await Call(services, "server_status", _ =>
        {
            call = OutputCall.Current;
            return new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.Report("tree", new { root = "f", frontier = nodes, other = nodes.Take(500).ToList() }) }] };
        }, new() { ["maxTokens"] = 2_000 });
        PerfBudget.Time("session/huge-record-cut", watch.Elapsed, TimeSpan.FromSeconds(5), output);
        // Each pass takes off half the estimated excess: a few dozen passes, not one per dropped row.
        Assert.InRange(call!.CutPasses, 1, 64);
        var record = Record(r);
        Assert.InRange(Tokens(r.StructuredContent!.Value.GetRawText()), 1_000, 2_100);
        int kept = record.GetProperty("frontier").GetArrayLength();
        Assert.InRange(kept, 1, 19_999);
        Assert.Contains($"frontier {kept} of 20000", record.GetProperty("warnings")[0].GetString());
    }

    /// <summary>S2: a report record cut to its budget names every array that lost entries; the tool's own warnings stay first.</summary>
    [Fact]
    public async Task A_cut_report_record_names_what_it_dropped()
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
    public async Task A_long_error_keeps_its_head_within_the_error_budget()
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
    public async Task Max_tokens_sets_the_budget()
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
    public async Task Text_pages_carry_their_position_and_body()
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
    public async Task Notices_come_last_in_both_parts()
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

    [Fact]
    public async Task Tag_characters_in_a_record_and_a_notice_are_escaped_in_both_parts()
    {
        var options = new ServerOptions();
        var workspace = new AssemblyWorkspace(options);
        using var services = new ServiceCollection().AddSingleton(options).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly)).AddSingleton(workspace).BuildServiceProvider();
        workspace.Notify("loaded Lab\U000E0041.dll");
        var r = await Call(services, "get_pe_info", _ => new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("name Lab\U000E0041\n", new { name = "Lab\U000E0041" }) }] });
        Assert.Contains("name Lab\\U000e0041", Text(r));
        Assert.EndsWith("[workspace] loaded Lab\\U000e0041.dll", Text(r));
        Assert.Equal("Lab\\U000e0041", Record(r).GetProperty("name").GetString());
        Assert.Equal("loaded Lab\\U000e0041.dll", Record(r).GetProperty("notices")[0].GetString());
    }

    /// <summary>S4.1 (c): an "Incomplete:" line of the tool's text reaches the record as a warning.</summary>
    [Fact]
    public async Task Incomplete_text_becomes_a_warning()
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
    public async Task JSON_mode_sends_the_record_as_text()
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
    public async Task Provenance_names_inputs_and_recomputes()
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

    [Fact]
    public async Task A_workspace_notice_leaves_the_result_hash_unchanged()
    {
        // A leftover unsaved-edit journal's one-time notice broke NotesTests' rerun check (2026-10-23).
        using var workspace = new AssemblyWorkspace();
        using var services = new ServiceCollection().AddSingleton(new ServerOptions()).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly))
            .AddSingleton(new OutputPager(new ServerOptions())).AddSingleton(workspace).BuildServiceProvider();
        CallToolResult Work(CallToolRequestParams _) => new() { Content = [new TextContentBlock { Text = ToolOutput.With("summary", new { name = "x" }) }] };
        CallToolResult Plain(CallToolRequestParams _) => new() { Content = [new TextContentBlock { Text = "summary" }] };
        var quiet = await Call(services, "get_pe_info", Work);
        var quietText = await Call(services, "get_pe_info", Plain);
        workspace.Notify("1 unsaved edit(s) from a session that ended without saving");
        var noticed = await Call(services, "get_pe_info", Work);
        workspace.Notify("1 unsaved edit(s) from a session that ended without saving");
        var noticedText = await Call(services, "get_pe_info", Plain);
        Assert.Contains(ToolOutput.NoticePrefix, Text(noticed));
        Assert.Contains(ToolOutput.NoticePrefix, Text(noticedText));
        Assert.Equal(ToolOutput.ResultSha256(quiet), ToolOutput.ResultSha256(noticed));
        Assert.Equal((string)quiet.Meta![ToolOutput.ProvenanceKey]!["resultSha256"]!, (string)noticed.Meta![ToolOutput.ProvenanceKey]!["resultSha256"]!);
        Assert.Equal((string)quietText.Meta![ToolOutput.ProvenanceKey]!["resultSha256"]!, (string)noticedText.Meta![ToolOutput.ProvenanceKey]!["resultSha256"]!);
    }

    [Fact]
    public void A_text_result_ending_in_a_newline_keeps_the_hash_earlier_versions_saved()
    {
        // Notes saved by 2.4.0 carry this hash; their evidence must still match after the notice fix (b4715960).
        var result = new CallToolResult { Content = [new TextContentBlock { Text = "two blocks\n" }, new TextContentBlock { Text = "summary\n" }] };
        Assert.Equal("2c2a3138e55eac946fd3a733aae2935248e72f985b27778faad67afeaa55b2f1", ToolOutput.ResultSha256(result));
    }

    /// <summary>MM-9 and E6: a record's stop flag makes coverage partial; facets reach the provenance, the record and the text.</summary>
    [Fact]
    public async Task A_stop_flag_makes_coverage_partial_and_facets_reach_every_part()
    {
        using var services = Services();
        var r = await Call(services, "get_pe_info", _ =>
        {
            ToolOutput.Facet("callers", "not decoded");
            ToolOutput.Facet("pseudocode");
            return new CallToolResult { Content = [new TextContentBlock { Text = ToolOutput.With("summary\n", new { name = "x", truncated = true }) }] };
        }, new() { ["path"] = Env.FixturePath });
        var p = r.Meta![ToolOutput.ProvenanceKey]!.AsObject();
        Assert.Equal("partial", (string)p["coverage"]!);
        Assert.Equal("unavailable: not decoded", (string)p["facets"]!["callers"]!);
        Assert.Equal("available", (string)p["facets"]!["pseudocode"]!);
        Assert.Equal("unavailable: not decoded", Record(r).GetProperty("coverage").GetProperty("facets").GetProperty("callers").GetString());
        Assert.Contains("[Unavailable: callers (not decoded)]", ((TextContentBlock)r.Content[0]).Text);
    }

    /// <summary>An error carries provenance too (inputs, tool, arguments, version), without a result hash or coverage.</summary>
    [Fact]
    public async Task Errors_carry_provenance()
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

    /// <summary>E2: results that may quote the analyzed file, errors and tools the contract does not list included, are marked untrusted.</summary>
    [Theory]
    [InlineData("get_pe_info", false, true)]
    [InlineData("get_pe_info", true, true)]
    [InlineData("a_tool_added_later", false, true)]
    [InlineData("server_status", false, false)]
    public async Task File_derived_results_are_marked_untrusted(string tool, bool error, bool marked)
    {
        using var services = Services();
        var r = await Call(services, tool, _ => error ? throw new ToolError(ErrorCode.Unsupported, "not a PE")
            : new CallToolResult { Content = [new TextContentBlock { Text = "x" }] });
        var p = r.Meta![ToolOutput.ProvenanceKey]!.AsObject();
        Assert.Equal(marked, p.ContainsKey("untrustedContent"));
        if (marked) Assert.Equal("analysis_target", (string)p["source"]!);
    }

    [Fact]
    public void Schemas_get_the_envelope()
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
    public async Task Named_row_arrays_are_lists()
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
    public async Task Lists_without_a_row_offset_continue_through_a_result_ID()
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
    public async Task Text_tools_get_a_page_record()
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
    public async Task Missing_paths_share_one_text()
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
    public async Task Timings_move_to_meta()
    {
        using var services = Services();
        var record = JsonSerializer.SerializeToElement(new { view = "changed", seconds = 1.25 });
        var r = await Call(services, "compare_folders", _ => new CallToolResult { Content = [new TextContentBlock { Text = record.GetRawText() }], StructuredContent = record });
        Assert.False(Record(r).TryGetProperty("seconds", out _));
        Assert.Equal(1.25, (double)r.Meta!["corvus/timings"]!["seconds"]!);
    }

    /// <summary>Every list-shaped output schema has its rows where the filter looks for them.</summary>
    [Fact]
    public void Every_paged_schema_names_its_rows()
    {
        var missing = Catalog.OfThisBuild(Corvus.Core.Toolsets.All).Tools
            .Where(t => t["outputSchema"]?["properties"] is JsonObject props && props["offset"] is not null && props["total"] is not null && !ToolOutput.IsListSchema(props, (string)t["name"]!))
            .Select(t => $"{t["name"]}: [{string.Join(", ", t["outputSchema"]!["properties"]!.AsObject().Select(p => p.Key))}]").ToList();
        Assert.True(missing.Count == 0, "offset and total without items (add their rows to ToolOutput.RowArrays):\n" + string.Join("\n", missing));
    }

    [Fact]
    public void The_renderer_aligns_rows_and_escapes_markers()
    {
        var record = JsonNode.Parse("""{"image":"a.dll","items":[{"name":"x","size":1},{"name":"Error (oops)","size":22}],"offset":0,"total":2}""")!.AsObject();
        var text = RecordText.Render(record, (0, 2, 2, false, 2));
        Assert.Equal("image: a.dll\n2 rows (showing 1-2):\n  name                size\n  x                   1\n  \\u2063Error (oops)  22\n[End: 2 rows]\n", text);
        var one = JsonNode.Parse("""{"items":[{"name":"x"}],"offset":0,"total":1}""")!.AsObject();
        Assert.StartsWith("1 row (showing 1-1):", RecordText.Render(one, (0, 1, 1, false, 1)));
    }

    /// <summary>Fields past the column cap (dump_stack's token, ilOffset) stay in the text as one key=value cell.</summary>
    [Fact]
    public void The_renderer_keeps_fields_past_the_column_cap()
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
