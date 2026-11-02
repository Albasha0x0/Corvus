using System.Text.RegularExpressions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Every tool that reads saved state answers the same in a second server process on the same data folder.</summary>
[Trait("Speed", "Slow")]
public partial class RestartStateTests
{
    /// <summary>Tools with no restart case, each with the reason the check cannot apply.</summary>
    internal static readonly Dictionary<string, string> NoRestartCase = new(StringComparer.Ordinal)
    {
        ["reanalyze_native"] = "the changed analysis lives in the engine's own database file, which the scripted engine does not keep; reserved for the lead heavy queue",
        ["ida_python"] = "a script's effect is in the engine's own database file, which the scripted engine does not keep; reserved for the lead heavy queue",
        ["ghidra_script"] = "a script's effect is in the engine's own database file, which the scripted engine does not keep; reserved for the lead heavy queue",
        ["export_engine_database"] = "the exported file is the engine's own database, which the scripted engine does not keep; reserved for the lead heavy queue",
        ["live_events"] = "a session is held in memory, so a restart ends it; RestartStateLiveTests checks the old id is refused with the list call",
        ["live_timeline"] = "a timeline run is held in memory, so a restart ends it; RestartStateLiveTests checks the refusal names the list call",
        ["live_coverage"] = "a coverage run is held in memory, so a restart ends it; RestartStateLiveTests checks the refusal names the list call",
        ["live_console"] = "a console run is held in memory, so a restart ends it; RestartStateLiveTests checks the refusal names the list call",
        ["emulate_native"] = "a stopped run is held in memory for resume, so a restart ends it; IntegerEmulationTests covers the refusal of an unknown run id",
    };

    /// <summary>Tools whose restart case is another test, as Class.Method.</summary>
    internal static readonly Dictionary<string, string> HeldElsewhere = new(StringComparer.Ordinal)
    {
        ["load_assembly"] = nameof(RestartStateTests) + "." + nameof(Load_offers_the_journal_of_an_ended_process),
        ["apply_metadata_names"] = Held<RestartStateAotTests>(nameof(RestartStateAotTests.Aot_tools_answer_the_same_from_a_restored_name_layer_as_after_apply)),
        ["get_method_addresses"] = Held<RestartStateAotTests>(nameof(RestartStateAotTests.Aot_tools_answer_the_same_from_a_restored_name_layer_as_after_apply)),
        ["find_method_by_address"] = Held<RestartStateAotTests>(nameof(RestartStateAotTests.Aot_tools_answer_the_same_from_a_restored_name_layer_as_after_apply)),
        ["migrate_native_names"] = Held<RestartStateBuildTests>(nameof(RestartStateBuildTests.Names_migrated_in_one_process_are_carried_in_the_next)),
        ["decompile_java"] = Held<JavaDecompilerTests>(nameof(JavaDecompilerTests.A_new_service_on_the_same_cache_folder_answers_without_starting_the_decompiler)),
        ["decompile_native"] = Held<RestartStateEngineTests>(nameof(RestartStateEngineTests.Engine_reads_answer_the_same_after_the_saved_names_reach_a_new_session)),
        ["search_decompiled"] = Held<RestartStateEngineTests>(nameof(RestartStateEngineTests.Engine_reads_answer_the_same_after_the_saved_names_reach_a_new_session)),
        ["get_engine_status"] = Held<RestartStateEngineTests>(nameof(RestartStateEngineTests.Engine_reads_answer_the_same_after_the_saved_names_reach_a_new_session)),
        ["set_native_type"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["set_native_local"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["set_native_stack_var"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["get_native_frame"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["declare_native_types"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["list_native_types"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["define_native"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
        ["set_native_operand"] = Held<RestartStateEngineTypesTests>(nameof(RestartStateEngineTypesTests.Engine_type_tools_restore_the_saved_user_types_into_a_new_session)),
    };

    private static string Held<T>(string method) => typeof(T).Name + "." + method;

    /// <summary>Fields that name the moment or the process: timings and kept-result ids.</summary>
    [GeneratedRegex(@"\d+ parsed, \d+ cached|""(parsed|cached)"":\d+|\b\d+(\.\d+)? ?ms\b|""(elapsedMs|ms|durationMs)"":\d+|\br-[0-9a-f]{8,}\b")]
    private static partial Regex Volatile();

    private static string FirstDifference(string a, string b)
    {
        var x = a.Split('\n'); var y = b.Split('\n');
        var i = Enumerable.Range(0, Math.Min(x.Length, y.Length)).FirstOrDefault(n => x[n] != y[n], Math.Min(x.Length, y.Length));
        string Cut(string[] l) => i < l.Length ? l[i][..Math.Min(l[i].Length, 300)] : "";
        return $"line {i + 1}: [{Cut(x)}] vs [{Cut(y)}]";
    }

    /// <summary>Load and restore notices: a [workspace] line, or the notices array with its strings skipped whole.</summary>
    [GeneratedRegex(@"\[workspace\][^\r\n]*(\r?\n)?|,""notices"":\[(?:[^\]""]|""(?:[^""\\]|\\.)*"")*\]")]
    private static partial Regex Notice();

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private static string Normalized(CallToolResult r) =>
        Volatile().Replace(Notice().Replace($"error={r.IsError == true}\n{Text(r)}\n{r.StructuredContent?.GetRawText()}", ""), "~");

    private static Task<McpClient> Start(TempDir dir) => McpProtocolTests.StartServerAsync(null, null, [], new Dictionary<string, string?>
    {
        [Corvus.Native.Providers.DataFolder.RootVariable] = dir.File("data"),
        ["CORVUS_ANNOTATIONS_DIR"] = dir.File("annotations"),
        [Corvus.Services.MinidumpService.BucketCacheVariable] = dir.File("buckets"),
        ["TEMP"] = dir.File("temp"), ["TMP"] = dir.File("temp"), ["TMPDIR"] = dir.File("temp"),
        [Corvus.Core.OutputRoots.Variable] = dir.Path,
    });

    /// <summary>The read that shows a tool's saved state, when the tool itself only writes it.</summary>
    private static readonly Dictionary<string, string> ReadBy = new(StringComparer.Ordinal)
    {
        ["rename_native"] = "list_native_edits", ["comment_native"] = "list_native_edits",
        ["record_note"] = "list_notes", ["update_note"] = "list_notes",
    };

    /// <summary>The read after the setup, one per stateful tool; the tool's table row decides which tools are here.</summary>
    internal static Dictionary<string, Dictionary<string, object?>> Probes(TempDir dir)
    {
        var native = McpProtocolTests.NativeSample(dir);
        var cases = McpProtocolTests.ToolCases(dir);
        var probes = new Dictionary<string, Dictionary<string, object?>>(StringComparer.Ordinal);
        foreach (var (tool, row) in Corvus.Mcp.ToolContract.Table)
        {
            if (row.State is Corvus.Mcp.ToolState.Names or Corvus.Mcp.ToolState.Cache && !NoRestartCase.ContainsKey(tool) && !HeldElsewhere.ContainsKey(tool)
                && cases.TryGetValue(tool, out var c))
                probes[tool] = c.Args;
        }
        // The names and comment are the setup; their restart case is the reads of the saved sidecar.
        // The journal of edits is the process's own; the saved names and comments are listed by search.
        probes["list_native_edits"] = new() { ["image"] = native, ["search"] = "*" };
        foreach (var tool in new[] { "rename_native", "comment_native" }) probes[tool] = probes["list_native_edits"];
        probes["list_notes"] = new() { ["anchor"] = McpProtocolTests.NativeSample(dir) };
        probes["record_note"] = probes["list_notes"];
        probes["update_note"] = probes["list_notes"];
        probes["save_session"] = new() { ["outputPath"] = dir.File("restart.session.json"), ["include"] = "notes,annotations" };
        probes["read_result"] = new() { ["id"] = "$kept" };
        return probes;
    }

    /// <summary>A small assembly with three string literals, so a page of one keeps the rest as a result.</summary>
    private static string Strings(TempDir dir)
    {
        var path = dir.File("strings.dll");
        if (!File.Exists(path))
            File.WriteAllBytes(path, Roslyn.Compile("Strings", "namespace S { public class T { public string[] V = [\"https://a.example/x\", \"https://b.example/y\", \"https://c.example/z\"]; } }",
                new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, deterministic: true)));
        return path;
    }

    // A note or name saved by one process answers the same in the next.
    [Fact]
    public async Task Saved_names_notes_and_kept_results_answer_the_same_after_a_restart()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("temp"));
        var cases = McpProtocolTests.ToolCases(dir);
        var probes = Probes(dir);
        var native = McpProtocolTests.NativeSample(dir);
        // The tiny PDB beside the sample ends the symbol search, so machine-wide caches are not counted.
        McpProtocolTests.PdbSample(dir);

        async Task<Dictionary<string, string>> Answers(McpClient client, string kept)
        {
            var answers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (tool, args) in probes.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                var bound = args.ToDictionary(a => a.Key, a => a.Value is "$kept" ? kept : a.Value);
                answers[tool] = Normalized(await client.CallToolAsync(ReadBy.GetValueOrDefault(tool, tool), bound));
            }
            return answers;
        }

        Dictionary<string, string> first;
        string keptId;
        await using (var a = await Start(dir))
        {
            await a.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = native });
            foreach (var tool in new[] { "rename_native", "comment_native" })
                Assert.True((await a.CallToolAsync(tool, cases[tool].Args)).IsError != true, tool);
            var note = await a.CallToolAsync("record_note", new Dictionary<string, object?> { ["text"] = "restart check", ["anchor"] = native });
            Assert.True(note.IsError != true, Text(note));
            var page = Text(await a.CallToolAsync("extract_strings", new Dictionary<string, object?> { ["path"] = Strings(dir), ["limit"] = 1 }));
            keptId = Regex.Match(page, @"read_result id=(r-[0-9a-f]+)").Groups[1].Value;
            Assert.True(keptId.Length > 0, page);
            first = await Answers(a, keptId);
        }

        // A writer refuses an existing file: each process writes its own.
        foreach (var args in probes.Values)
            if (args.TryGetValue("outputPath", out var output) && output is string file) File.Delete(file);
        Dictionary<string, string> second;
        string journalView;
        await using (var b = await Start(dir))
        {
            second = await Answers(b, keptId);
            journalView = Text(await b.CallToolAsync("list_native_edits", new Dictionary<string, object?> { ["image"] = native }));
        }
        // The edit journal is the process's own: the reply names where the saved names are listed.
        Assert.Contains("search=\"*\"", journalView);
        // One edit of this process does not hide the saved marks of the earlier one.
        await using var c = await Start(dir);
        await c.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = native });
        var renamed = cases["rename_native"].Args.ToDictionary(x => x.Key, x => x.Key == "name" ? "SweepFunc2" : x.Value);
        Assert.True((await c.CallToolAsync("rename_native", renamed)).IsError != true);
        var oneEdit = Text(await c.CallToolAsync("list_native_edits", new Dictionary<string, object?> { ["image"] = native }));
        Assert.Contains("1 in this journal", oneEdit);

        var differing = first.Where(p => p.Value != second[p.Key]).Select(p => p.Key).ToList();
        Assert.True(differing.Count == 0, "answers differ after a restart: " + string.Join("; ", differing.Select(t => $"{t}: {FirstDifference(first[t], second[t])}")));
        // A tool that fails or answers nothing in both processes proves nothing.
        var empty = first.Where(p => !p.Value.StartsWith("error=False", StringComparison.Ordinal) || p.Value.Length < 40).Select(p => p.Key).ToList();
        Assert.True(empty.Count == 0, "probes that fail or answer nothing: " + string.Join(", ", empty.Select(t => $"{t}: {first[t][..Math.Min(first[t].Length, 200)]}")));
        Assert.Contains("SweepFunc", first["list_native_edits"]);
        Assert.Contains("SweepFunc", first["list_functions"]);
        Assert.Contains("restart check", first["list_notes"]);
        Assert.DoesNotContain("not_found", first["read_result"]);
    }

    // Edits left unsaved by an ended process are offered again on load.
    [Fact]
    public async Task Load_offers_the_journal_of_an_ended_process()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("temp"));
        var path = dir.File("journaled.dll");
        File.WriteAllBytes(path, Roslyn.Compile("Journaled", "namespace J { public class G { public int Scale(int x) => x * 2; } }",
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, deterministic: true)));
        await using (var a = await Start(dir))
        {
            await a.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path });
            var stub = await a.CallToolAsync("stub_method", new Dictionary<string, object?> { ["method"] = "J.G::Scale", ["value"] = "0", ["dryRun"] = false });
            Assert.True(stub.IsError != true, Text(stub));
            // A later call lets the journal sync write the edit.
            Assert.Contains("1 edit", Text(await a.CallToolAsync("list_edits", new Dictionary<string, object?> { ["assembly"] = "journaled" })));
        }
        await using var b = await Start(dir);
        var load = Text(await b.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path }));
        // The offer is a [workspace] notice on the reply of the load or the next call.
        var next = Text(await b.CallToolAsync("list_edits", new Dictionary<string, object?> { ["assembly"] = "journaled" }));
        Assert.True((load + next).Contains("apply_edits", StringComparison.Ordinal) && (load + next).Contains("1 unsaved edit", StringComparison.Ordinal), load + " | " + next);
    }
}
