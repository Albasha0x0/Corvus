using System.Text.RegularExpressions;
using Corvus.Mcp;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Every tool that changes state leaves edit lists, name layers, notes and loaded files as they were when its call is an error.</summary>
[Trait("Speed", "Slow")]
public partial class EditAtomicityTests
{
    /// <summary>Tools the table marks as changing, with the reason no bad call can change what the snapshot reads.</summary>
    private static readonly Dictionary<string, string> NoSnapshotState = new(StringComparer.Ordinal)
    {
        ["update_note"] = "covered by its own atomicity test",
        ["live_session"] = "needs a running process", ["live_break"] = "needs a running process", ["live_watch"] = "needs a running process",
        ["live_events"] = "needs a running process", ["live_script"] = "needs a running process", ["live_coverage"] = "needs a running process",
        ["live_timeline"] = "needs a running process", ["live_console"] = "needs a running process",
        ["get_android_device_info"] = "needs a device", ["pull_android_package"] = "needs a device", ["pull_android_file"] = "needs a device",
        ["install_android_package"] = "needs a device", ["uninstall_android_package"] = "needs a device", ["get_android_resource"] = "writes a file only",
        ["set_native_type"] = "needs an engine to resolve the target", ["set_native_local"] = "needs an engine to resolve the function",
        ["set_native_stack_var"] = "needs an engine to resolve the function", ["declare_native_types"] = "declarations are parsed by the engine",
        ["define_native"] = "needs an engine to create the entry", ["reanalyze_native"] = "reruns the engine analysis",
        ["set_native_operand"] = "needs an engine to resolve the instruction", ["ida_python"] = "runs a script in the engine",
        ["ghidra_script"] = "runs a script in the engine", ["export_engine_database"] = "writes a file only",
        ["export_method_symbols"] = "writes a file only", ["extract_embedded"] = "writes a file only", ["unpack_container"] = "writes a file only",
        ["get_resource"] = "writes a file only", ["export_project"] = "writes a file only", ["export_edits"] = "writes a file only",
        ["save_assembly"] = "writes a file only", ["export_native_annotations"] = "writes a file only", ["save_native"] = "writes a file only",
        ["export_native_patches"] = "writes a file only", ["save_session"] = "writes a file only", ["read_result"] = "writes a file only",
        ["open_minidump"] = "opens a dump file",
    };

    private static readonly string NewBuild = "missing-build.dll";

    // Regression for 53e62d7ca: renames accepted a name holding a control character.
    /// <summary>One call per state-changing tool that fails its checks after it has resolved what it acts on.</summary>
    private static Dictionary<string, Dictionary<string, object?>> BadCalls(TempDir dir)
    {
        var native = McpProtocolTests.NativeSample(dir);
        var script = dir.File("two-edits.json");
        var corrupt = dir.File("corrupt.session.json");
        File.WriteAllText(corrupt, "{ not a session");
        return new(StringComparer.Ordinal)
        {
            ["rename_symbol"] = new() { ["symbol"] = "Account", ["newName"] = "bad\0name", ["dryRun"] = false },
            ["rename_namespace"] = new() { ["assembly"] = "TestFixture", ["oldNamespace"] = "Fixture.Model", ["newNamespace"] = "bad\0name", ["dryRun"] = false },
            ["stub_method"] = new() { ["method"] = "Account::Score", ["value"] = "not a number", ["dryRun"] = false },
            ["patch_method_csharp"] = new() { ["method"] = "Shop::PriceOf(string, int)", ["code"] = "return missingName;", ["dryRun"] = false },
            ["patch_method_il"] = new() { ["method"] = "Account::Score", ["il"] = "ldc.i4.7\nbogus_opcode\nret", ["dryRun"] = false },
            ["add_members_csharp"] = new() { ["type"] = "Shop", ["code"] = "public int Fine() { return 1; } public int Broken() { return missingName; }", ["dryRun"] = false },
            ["add_types_csharp"] = new() { ["assembly"] = "TestFixture", ["code"] = "namespace Extras { public class Fine {} public class Broken : Missing {} }", ["dryRun"] = false },
            ["simplify_methods"] = new() { ["symbol"] = "Account", ["passes"] = new[] { "fold", "bogus" }, ["dryRun"] = false },
            ["undo_edit"] = new() { ["assembly"] = "TestFixture", ["number"] = 99 },
            ["revert_edits"] = new() { ["assembly"] = "NoSuchAssembly" },
            ["apply_edits"] = new() { ["path"] = script, ["dryRun"] = false },
            ["rename_native"] = new() { ["image"] = native, ["address"] = "First", ["name"] = "bad name!", ["dryRun"] = false },
            ["comment_native"] = new() { ["image"] = native, ["address"] = "not an address", ["text"] = "x", ["dryRun"] = false },
            ["patch_bytes"] = new() { ["image"] = native, ["address"] = "First", ["hex"] = "9z", ["dryRun"] = false },
            ["patch_asm"] = new() { ["image"] = native, ["address"] = "First", ["assembly"] = "nop\nbogus rax, rbx", ["dryRun"] = false },
            ["undo_native_edit"] = new() { ["image"] = native, ["editId"] = "native.dll#99" },
            ["migrate_native_names"] = new() { ["oldImage"] = native, ["newImage"] = dir.File(NewBuild), ["dryRun"] = false },
            ["migrate_native_patches"] = new() { ["oldImage"] = native, ["newImage"] = dir.File(NewBuild), ["dryRun"] = false },
            ["update_to_new_build"] = new() { ["oldImage"] = native, ["newImage"] = dir.File(NewBuild), ["dryRun"] = false },
            ["apply_metadata_names"] = new() { ["image"] = native, ["assembly"] = "NoSuchAssembly" },
            ["load_pdb"] = new() { ["image"] = native, ["path"] = dir.File("missing.pdb") },
            ["record_note"] = new() { ["text"] = "must not be stored", ["kind"] = "bogus", ["anchor"] = "TestFixture" },
            ["load_session"] = new() { ["path"] = corrupt, ["dryRun"] = false },
            ["load_assembly"] = new() { ["path"] = dir.File("missing.dll") },
            ["unload_assembly"] = new() { ["assembly"] = "NoSuchAssembly" },
            ["reload_assembly"] = new() { ["assembly"] = "NoSuchAssembly" },
            ["add_search_directory"] = new() { ["directory"] = dir.File("missing-folder") },
        };
    }

    [GeneratedRegex(@"\b\d+(\.\d+)? ?ms\b|\b\d+\.\d+ s\b|""(elapsedMs|ms|durationMs|updatedAt|createdAt)"":""?[^,}]+|\br-[0-9a-f]{8,}\b")]
    private static partial Regex Volatile();

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private static string Normalized(CallToolResult r) => Volatile().Replace($"error={r.IsError == true}\n{Text(r)}\n{r.StructuredContent?.GetRawText()}", "~");

    private static async Task<string> Snapshot(McpClient client, string native)
    {
        var reads = new (string Tool, Dictionary<string, object?> Args)[]
        {
            ("list_assemblies", new()),
            ("list_edits", new() { ["assembly"] = "TestFixture" }),
            ("diff_edits", new() { ["assembly"] = "TestFixture" }),
            ("list_types", new() { ["namespace"] = "Fixture.Model" }),
            ("list_native_edits", new() { ["image"] = native, ["search"] = "*" }),
            ("list_functions", new() { ["image"] = native }),
            ("list_notes", new() { ["status"] = "all" }),
        };
        var parts = new List<string>();
        foreach (var (tool, args) in reads) parts.Add(tool + ":\n" + Normalized(await client.CallToolAsync(tool, args)));
        return string.Join("\n\n", parts);
    }

    [Fact]
    public void Every_tool_that_changes_state_has_a_bad_call_or_a_reason()
    {
        using var dir = new TempDir();
        var bad = BadCalls(dir);
        var changing = ToolEffects.Table.Where(t => !t.Value.ReadOnly).Select(t => t.Key).ToList();
        var uncovered = changing.Where(t => !bad.ContainsKey(t) && !NoSnapshotState.ContainsKey(t)).Order(StringComparer.Ordinal).ToList();
        Assert.True(uncovered.Count == 0, "state-changing tools with neither a bad call nor a reason: " + string.Join(", ", uncovered));
        var stale = bad.Keys.Concat(NoSnapshotState.Keys).Where(t => !changing.Contains(t)).Order(StringComparer.Ordinal).ToList();
        Assert.True(stale.Count == 0, "listed tools the table marks read-only: " + string.Join(", ", stale));
        Assert.Empty(bad.Keys.Intersect(NoSnapshotState.Keys));
    }

    [Fact]
    public async Task A_state_changing_call_that_is_an_error_leaves_edits_names_notes_and_files_as_they_were()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("temp"));
        var native = McpProtocolTests.NativeSample(dir);
        var bad = BadCalls(dir);
        await using var client = await McpProtocolTests.StartServerAsync(null, null, ["--load", Env.FixturePath], new Dictionary<string, string?>
        {
            [Corvus.Native.Providers.DataFolder.RootVariable] = dir.File("data"),
            ["CORVUS_ANNOTATIONS_DIR"] = dir.File("annotations"),
            ["TEMP"] = dir.File("temp"), ["TMP"] = dir.File("temp"), ["TMPDIR"] = dir.File("temp"),
            [Corvus.Core.OutputRoots.Variable] = dir.Path,
        });

        async Task Ok(string tool, Dictionary<string, object?> args)
        {
            var r = await client.CallToolAsync(tool, args);
            Assert.True(r.IsError != true, tool + ": " + Text(r));
        }

        await Ok("load_assembly", new() { ["path"] = native });
        // A baseline of earlier work, so a call that undoes or replays it shows.
        await Ok("stub_method", new() { ["method"] = "Secret::Validate", ["value"] = "true", ["dryRun"] = false });
        await Ok("rename_native", new() { ["image"] = native, ["address"] = "First", ["name"] = "BaseName", ["dryRun"] = false });
        await Ok("record_note", new() { ["text"] = "baseline", ["anchor"] = "TestFixture" });
        // A script of one valid and one invalid edit, taken from a valid one.
        await Ok("stub_method", new() { ["method"] = "Account::Score", ["value"] = "7", ["dryRun"] = false });
        await Ok("export_edits", new() { ["assembly"] = "TestFixture", ["outputPath"] = dir.File("edits.json") });
        await Ok("undo_edit", new() { ["assembly"] = "TestFixture" });
        File.WriteAllText(dir.File("two-edits.json"), File.ReadAllText(dir.File("edits.json")).Replace("\"7\"", "\"not a number\""));

        var before = await Snapshot(client, native);
        Assert.Contains("BaseName", before);
        Assert.Contains("baseline", before);
        var changed = new List<string>();
        var succeeded = new List<string>();
        foreach (var (tool, args) in bad.OrderBy(b => b.Key, StringComparer.Ordinal))
        {
            var result = await client.CallToolAsync(tool, args);
            if (result.IsError != true) succeeded.Add($"{tool}: {Text(result)[..Math.Min(Text(result).Length, 160)]}");
            var after = await Snapshot(client, native);
            if (after != before)
            {
                var a = before.Split('\n'); var b = after.Split('\n');
                var i = Enumerable.Range(0, Math.Min(a.Length, b.Length)).FirstOrDefault(n => a[n] != b[n], Math.Min(a.Length, b.Length));
                changed.Add($"{tool}: line {i + 1}: [{(i < a.Length ? a[i] : "")}] became [{(i < b.Length ? b[i] : "")}]");
                // The next tool starts from the state the earlier one left.
                before = after;
            }
        }
        Assert.True(succeeded.Count + changed.Count == 0,
            "bad calls that were not errors: " + string.Join("; ", succeeded) + "; errors that changed state: " + string.Join("; ", changed));
    }
}
