using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// S12.2 recorded samples: ProtocolSamples/&lt;tool&gt;.json holds a call on the fixture and its normalized response; a change
/// of shape shows as a diff. CORVUS_UPDATE_DOCS=1 records every sample again (and the <see cref="Seed"/> calls).
/// </summary>
[Collection(InProcessCatalogCollection.Name)]
public partial class ProtocolSampleTests
{
    private static string Folder => Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "ProtocolSamples");

    public static string SampleFile(string tool) => Path.Combine(Folder, tool + ".json");

    /// <summary>The calls recorded when no sample exists yet.</summary>
    private static readonly Dictionary<string, Dictionary<string, object?>> Seed = new(StringComparer.Ordinal)
    {
        ["list_assemblies"] = [],
        ["list_namespaces"] = new() { ["assembly"] = "TestFixture" },
        ["list_types"] = new() { ["assembly"] = "TestFixture", ["limit"] = 3 },
        ["get_type_info"] = new() { ["type"] = "Account" },
        ["search_symbols"] = new() { ["query"] = "Charge", ["limit"] = 5 },
        ["decompile_member"] = new() { ["member"] = "Account::CheckLicense" },
        ["get_il"] = new() { ["symbol"] = "Account::CheckLicense" },
        ["find_references"] = new() { ["symbol"] = "Account::Charge(int)" },
        ["get_assembly_info"] = new() { ["assembly"] = "TestFixture" },
        ["get_attributes"] = new() { ["symbol"] = "NativeThing::First" },
        ["get_type_hierarchy"] = new() { ["type"] = "Entity" },
        ["resolve_symbol"] = new() { ["symbol"] = "Account::Charge" },
        ["search_strings"] = new() { ["query"] = "LICENSE" },
        ["search_constants"] = new() { ["value"] = "0x3E8" },
        ["search_il"] = new() { ["pattern"] = "ldstr *LICENSE*; call *Validate*", ["context"] = 3 },
        ["find_callees"] = new() { ["method"] = "Account::Charge(int, string)", ["distinct"] = true },
        ["get_call_tree"] = new() { ["method"] = "Account::Charge(int)", ["depth"] = 2 },
        ["find_call_paths"] = new() { ["to"] = "Account::Charge(int)", ["limit"] = 3 },
        ["list_resources"] = new() { ["assembly"] = "TestFixture" },
        ["get_resource"] = new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt" },
        ["export_project"] = new() { ["assembly"] = "TestFixture", ["outputDirectory"] = "sample-export" },
        ["get_r2r_code"] = new() { ["method"] = "Account::Charge(int)" },
        ["find_r2r_method"] = new() { ["assembly"] = "TestFixture", ["address"] = "rva:0x2050" },
        ["summarize_file"] = new() { ["assembly"] = "TestFixture" },
        ["survey_features"] = new() { ["assembly"] = "TestFixture", ["category"] = "all" },
        ["extract_strings"] = new() { ["assembly"] = "TestFixture", ["limit"] = 5 },
        ["extract_embedded"] = new() { ["assembly"] = "TestFixture" },
        ["get_il2cpp_info"] = new() { ["symbol"] = "NativeThing" },
        ["find_method_by_address"] = new() { ["address"] = "0x1000", ["kind"] = "rva" },
        ["export_il2cpp_symbols"] = new() { ["outputDirectory"] = "sample-il2cpp", ["assembly"] = "TestFixture", ["formats"] = "header" },
        ["generate_cpp_binding"] = new() { ["type"] = "Account", ["style"] = "mono" },
        ["symbolize_stack_text"] = new() { ["text"] = "System.Exception: boom\n   at Fixture.Model.Account.Charge(Int32 amount)" },
        // Edits preview by default; stub_method applies, so undo_edit (recorded after it) has an edit to undo.
        ["add_members_csharp"] = new() { ["type"] = "Account", ["code"] = "public int Twice(int x) { return x * 2; }" },
        ["add_types_csharp"] = new() { ["assembly"] = "TestFixture", ["code"] = "namespace Mods { public static class M { public static int One() { return 1; } } }" },
        ["diff_edits"] = new() { ["assembly"] = "TestFixture" },
        ["list_edits"] = new() { ["assembly"] = "TestFixture" },
        ["patch_method_csharp"] = new() { ["method"] = "Secret::Validate", ["code"] = "return true;" },
        ["patch_method_il"] = new() { ["method"] = "Account::Score", ["il"] = "ldc.i4.7\nret" },
        ["rename_namespace"] = new() { ["assembly"] = "TestFixture", ["oldNamespace"] = "Fixture.Model", ["newNamespace"] = "Model" },
        ["rename_symbol"] = new() { ["symbol"] = "Account", ["newName"] = "Customer" },
        ["simplify_methods"] = new() { ["symbol"] = "Account" },
        ["stub_method"] = new() { ["method"] = "Secret::Validate", ["value"] = "true", ["dryRun"] = false },
        ["undo_edit"] = new() { ["assembly"] = "TestFixture" },
        ["compare_native_images"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB, ["limit"] = 3 },
        ["map_address_between_builds"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB, ["addresses"] = new[] { "First", "no_such_name" } },
        ["diff_function"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB, ["address"] = "First" },
        ["make_code_pattern"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["search_code_pattern"] = new() { ["pattern"] = "C3", ["images"] = new[] { BuildA }, ["limit"] = 3 },
        ["migrate_native_names"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB },
        ["migrate_native_patches"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB },
        ["update_to_new_build"] = new() { ["oldImage"] = BuildA, ["newImage"] = BuildB, ["include"] = new[] { "names", "patches" } },
        ["export_native_patches"] = new() { ["image"] = BuildA, ["outputPath"] = "sample-patches.json", ["overwrite"] = true },
        // Session, results and notes ($name: a value from SetupAsync).
        ["add_search_directory"] = new() { ["directory"] = "samples" },
        ["load_assembly"] = new() { ["path"] = In + "loaded.dll" },
        ["reload_assembly"] = new() { ["assembly"] = "loaded.dll" },
        ["unload_assembly"] = new() { ["assembly"] = "loaded.dll" },
        ["read_result"] = new() { ["id"] = "$kept" },
        ["save_assembly"] = new() { ["assembly"] = "TestFixture", ["outputPath"] = In + "saved.dll" },
        ["save_session"] = new() { ["outputPath"] = In + "work.session.json", ["include"] = SessionParts },
        ["load_session"] = new() { ["path"] = In + "setup.session.json" },
        ["record_note"] = new() { ["text"] = "the first export returns at once", ["anchor"] = "edit.dll@First", ["tags"] = new[] { "flow" } },
        ["update_note"] = new() { ["id"] = "$note", ["expectedRevision"] = 1, ["status"] = "answered", ["appendText"] = "It does." },
        ["list_notes"] = new() { ["anchor"] = "edit.dll", ["status"] = "all" },
        ["convert_number"] = new() { ["numbers"] = new[] { "0x41424344", "-1" } },
        // .NET edit scripts and builds
        ["export_edits"] = new() { ["assembly"] = In + "v1.dll", ["outputPath"] = In + "edits.json" },
        ["apply_edits"] = new() { ["path"] = In + "setup-edits.json" },
        ["revert_edits"] = new() { ["assembly"] = In + "v1.dll" },
        ["compare_assemblies"] = new() { ["oldAssembly"] = In + "v1.dll", ["newAssembly"] = In + "v2.dll" },
        ["find_counterpart"] = new() { ["symbol"] = "Gauge::Read", ["oldAssembly"] = In + "v1.dll", ["newAssembly"] = In + "v2.dll", ["diff"] = true },
        ["compare_folders"] = new() { ["oldPath"] = In + "folders-old", ["newPath"] = In + "folders-new", ["caseSensitive"] = true },
        // Containers and Android packages
        ["search_container"] = new() { ["path"] = In + "lz4.nupkg", ["query"] = "LZ4Codec", ["kind"] = "type" },
        ["unpack_container"] = new() { ["path"] = In + "lz4.nupkg", ["outputDirectory"] = In + "unpack", ["load"] = false, ["limit"] = 5 },
        ["unity_overview"] = new() { ["path"] = In + "MonoGame" },
        ["get_android_manifest"] = new() { ["path"] = In + "app.apk" },
        ["list_android_resources"] = new() { ["path"] = In + "app.apk", ["type"] = "string" },
        ["get_android_resource"] = new() { ["path"] = In + "app.apk", ["name"] = "@xml/network_security_config" },
        ["list_dex_classes"] = new() { ["path"] = In + "app.apk", ["query"] = "Main" },
        ["get_dex_class"] = new() { ["path"] = In + "app.apk", ["class"] = "com.example.app.Main" },
        ["disassemble_dex"] = new() { ["path"] = In + "app.apk", ["symbol"] = AndroidSamples.ComputeInt },
        ["search_dex"] = new() { ["path"] = In + "app.apk", ["kind"] = "string", ["query"] = "api.example" },
        ["find_dex_references"] = new() { ["path"] = In + "app.apk", ["target"] = AndroidSamples.Log },
        ["list_jni_bindings"] = new() { ["path"] = In + "app.apk" },
        ["map_java_dotnet"] = new() { ["symbol"] = AndroidSamples.Link, ["path"] = In + "xamarin.apk" },
        // Minidumps
        ["open_minidump"] = new() { ["path"] = In + "synth.dmp" },
        ["dump_stack"] = new() { ["dump"] = In + "synth.dmp" },
        ["read_dump_memory"] = new() { ["dump"] = In + "synth.dmp", ["address"] = "synth+0x1000", ["length"] = 32 },
        ["bucket_minidumps"] = new() { ["folder"] = In + "dumps" },
        // Native reading (build A is never edited)
        ["get_pe_info"] = new() { ["image"] = BuildA },
        ["get_nativeaot_info"] = new() { ["image"] = In + "aot.dll" },
        ["list_imports"] = new() { ["image"] = BuildA },
        ["list_exports"] = new() { ["image"] = BuildA },
        ["list_functions"] = new() { ["image"] = BuildA, ["limit"] = 5 },
        ["list_globals"] = new() { ["image"] = BuildA, ["limit"] = 5 },
        ["list_cpp_classes"] = new() { ["image"] = BuildA },
        ["get_exception_info"] = new() { ["image"] = BuildA },
        ["resolve_address"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["read_bytes"] = new() { ["image"] = BuildA, ["address"] = "First", ["length"] = 32 },
        ["search_bytes"] = new() { ["image"] = BuildA, ["pattern"] = "ExitProcess", ["text"] = true },
        ["search_native_strings"] = new() { ["image"] = BuildA, ["limit"] = 5 },
        ["disassemble"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["inspect_instruction"] = new() { ["image"] = BuildA, ["address"] = "First", ["limit"] = 2 },
        ["search_instructions"] = new() { ["image"] = BuildA, ["mnemonic"] = "^ret$", ["limit"] = 5 },
        ["get_cfg"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["find_xrefs"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["get_call_arguments"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["resolve_call_targets"] = new() { ["image"] = BuildA, ["address"] = "First", ["scope"] = "function" },
        ["trace_native_values"] = new() { ["image"] = BuildA, ["address"] = "First", ["location"] = "rcx" },
        ["native_call_tree"] = new() { ["image"] = BuildA, ["function"] = "First" },
        ["analyze_native_function"] = new() { ["image"] = BuildA, ["address"] = "First" },
        ["trace_native_feature"] = new() { ["image"] = BuildA, ["query"] = "First" },
        ["find_similar_functions"] = new() { ["image"] = BuildA, ["address"] = "First", ["minScore"] = 0, ["limit"] = 3 },
        ["find_virtual_calls"] = new() { ["image"] = BuildA },
        ["verify_native_imports"] = new() { ["assembly"] = "TestFixture", ["platform"] = "windows" },
        ["load_pdb"] = new() { ["image"] = In + "tiny.dll" },
        ["search_pdb_symbols"] = new() { ["image"] = In + "tiny.dll", ["query"] = "Foo" },
        ["get_native_type"] = new() { ["image"] = In + "typed.dll", ["name"] = "Game", ["at"] = "0xD8" },
        ["apply_il2cpp_names"] = new() { ["image"] = In + "il2cpp.dll", ["assembly"] = "TestFixture" },
        // Native edits (edit.dll has a fresh hash every run, so its sidecar starts empty)
        ["comment_native"] = new() { ["image"] = In + "edit.dll", ["address"] = "First", ["text"] = "entry", ["dryRun"] = false },
        ["export_native_annotations"] = new() { ["image"] = In + "edit.dll", ["outputPath"] = In + "annotations.py", ["format"] = "ida" },
        ["list_native_edits"] = new() { ["image"] = In + "edit.dll" },
        ["patch_asm"] = new() { ["image"] = In + "edit.dll", ["address"] = "First", ["assembly"] = "nop" },
        ["patch_bytes"] = new() { ["image"] = In + "edit.dll", ["address"] = "First", ["hex"] = "90", ["dryRun"] = false },
        ["rename_native"] = new() { ["image"] = In + "edit.dll", ["address"] = "First", ["name"] = "SampleEntry", ["dryRun"] = false },
        ["save_native"] = new() { ["image"] = In + "edit.dll", ["outputPath"] = In + "patched.dll" },
        ["undo_native_edit"] = new() { ["image"] = In + "edit.dll" },
    };

    /// <summary>Two builds of a synthetic native image beside the fixtures (trailing bytes give each its own hash, so no other test's annotations apply).</summary>
    private const string BuildA = "sample-build-a.dll", BuildB = "sample-build-b.dll";

    private static void WriteBuilds()
    {
        var folder = Path.GetDirectoryName(Env.FixturePath)!;
        File.WriteAllBytes(Path.Combine(folder, BuildA), [.. NativePeTests.KitchenSink(is64: true), 0xA1, 0xA2]);
        File.WriteAllBytes(Path.Combine(folder, BuildB), [.. NativePeTests.KitchenSink(is64: true), 0xB1, 0xB2, 0xB3]);
    }

    [Fact]
    public async Task SamplesMatch()
    {
        bool update = Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1";
        var calls = Directory.Exists(Folder)
            ? Directory.GetFiles(Folder, "*.json").ToDictionary(f => Path.GetFileNameWithoutExtension(f),
                f => JsonNode.Parse(File.ReadAllText(f))!["arguments"]!.AsObject().ToDictionary(p => p.Key, p => (object?)JsonSerializer.Deserialize<JsonElement>(p.Value!.ToJsonString())))
            : [];
        if (update)
            foreach (var (tool, args) in Seed) calls.TryAdd(tool, args);

        WriteBuilds();
        WriteInputs();
        try
        {
            await RecordAsync(calls, update);
        }
        finally
        {
            DeleteFreshSidecars();
        }
    }

    private static async Task RecordAsync(Dictionary<string, Dictionary<string, object?>> calls, bool update)
    {
        await using var server = await InProcessServer.StartAsync();
        var values = await SetupAsync(server.Client);
        var stale = new List<string>();
        foreach (var (tool, args) in calls.OrderBy(c => c.Key, StringComparer.Ordinal))
        {
            // An export starts from no directory, so every run records the same outcome.
            if (args.GetValueOrDefault("outputDirectory") is { } output && Directory.Exists(output.ToString())) Directory.Delete(output.ToString()!, recursive: true);
            foreach (var (before, beforeArgs) in Before.GetValueOrDefault(tool, [])) await CallAsync(server.Client, before, beforeArgs);
            var result = await server.Client.CallToolAsync(tool, Bind(args, values));
            foreach (var (cleanup, cleanupArgs) in After.GetValueOrDefault(tool, [])) await CallAsync(server.Client, cleanup, cleanupArgs);
            var sample = new JsonObject
            {
                ["tool"] = tool,
                ["arguments"] = JsonSerializer.SerializeToNode(args),
                ["isError"] = result.IsError == true,
                ["content"] = new JsonArray([.. result.Content.OfType<TextContentBlock>().Select(b => (JsonNode)Normalize(b.Text, tool))]),
                ["structuredContent"] = result.StructuredContent is { } s ? JsonNode.Parse(Normalize(s.GetRawText(), tool, json: true)) : null,
            };
            var text = sample.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, NewLine = "\n" }) + "\n";
            var file = SampleFile(tool);
            if (update)
            {
                Directory.CreateDirectory(Folder);
                File.WriteAllText(file, text);
            }
            else if (File.ReadAllText(file).ReplaceLineEndings("\n") != text) stale.Add(tool);
        }
        Assert.True(stale.Count == 0, "protocol samples changed (check the diff, then CORVUS_UPDATE_DOCS=1 records them): " + string.Join(", ", stale));
    }

    // Never from inside a \uXXXX escape (JSON kept as a JSON string escapes its quotes).
    [GeneratedRegex(@"(?<!\\u[0-9a-fA-F]{0,3})(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|r-[0-9a-f]{12})")]
    private static partial Regex Volatile();

    /// <summary>Tools whose written file holds the machine's image path, so its size differs per checkout.</summary>
    private static readonly HashSet<string> PathSized = ["export_native_patches", "export_native_annotations"];

    /// <summary>The written file's size in the text (", 642 bytes;") and the record ("bytes":642).</summary>
    [GeneratedRegex(@"(, )\d+(?= bytes;)|(""bytes"":\s*)\d+")]
    private static partial Regex WrittenBytes();

    /// <summary>A file's entropy in the text ("entropy 5.24") and the record ("entropy":5.24).</summary>
    [GeneratedRegex(@"(entropy |""entropy"":\s*)\d+(\.\d+)?")]
    private static partial Regex Entropy();

    [GeneratedRegex(@"(\d[\d,]*) chars\b|(""totalChars"":\s*)\d+")]
    private static partial Regex KeptChars();

    /// <summary>A note's random id (NotesService.NewId); times of notes and kept edit scripts.</summary>
    [GeneratedRegex(@"\bn[a-z2-7]{8}\b")]
    private static partial Regex NoteId();

    [GeneratedRegex(@"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")]
    private static partial Regex Timestamp();

    /// <summary>A path under the fixtures or the repo, up to a quote, whitespace or a separator of a list; text may quote JSON (\\).</summary>
    [GeneratedRegex(@"<(fixtures|repo)>(?:\\+|/)(?:\\+|[^\s""'`,;|<>()\\])*")]
    private static partial Regex FixturePath();

    /// <summary>The same in JSON text, where a backslash is "\\" and a lone one starts an escape.</summary>
    [GeneratedRegex(@"<(fixtures|repo)>(?:\\\\|/)(?:\\\\|[^\s""'`,;|<>()\\])*")]
    private static partial Regex FixturePathJson();

    [GeneratedRegex(@"\\+")]
    private static partial Regex Backslashes();

    /// <summary>Machine paths, hashes and entropy (a built fixture's bytes differ per checkout), GUIDs and result ids become labels.</summary>
    private static string Normalize(string text, string tool, bool json = false)
    {
        foreach (var (path, label) in new[] { (Path.GetDirectoryName(Env.FixturePath)!, "<fixtures>"), (DocsTests.RepoRoot(), "<repo>") })
            foreach (var form in new[] { path, path.Replace('\\', '/'), JsonEncodedText.Encode(path).ToString() })
                text = text.Replace(form, label, StringComparison.OrdinalIgnoreCase);
        // Separators inside a fixture path are '/' on every OS (JSON text escapes a backslash as two).
        text = (json ? FixturePathJson() : FixturePath()).Replace(text, m => Backslashes().Replace(m.Value, "/"));
        text = Entropy().Replace(text, m => m.Groups[1].Value[0] == '"' ? m.Groups[1].Value + "\"<entropy>\"" : m.Groups[1].Value + "<entropy>");
        if (tool is "record_note" or "update_note" or "list_notes" or "read_result")
            text = Timestamp().Replace(NoteId().Replace(text, "<note>"), "<time>");
        if (PathSized.Contains(tool))
            text = WrittenBytes().Replace(text, m => m.Groups[1].Success ? m.Groups[1].Value + "<bytes>" : m.Groups[2].Value + "\"<bytes>\"");
        // A kept text has the OS's line ends, so its length differs per OS.
        if (tool == "read_result")
            text = KeptChars().Replace(text, m => m.Groups[1].Success ? "<chars> chars" : m.Groups[2].Value + "\"<chars>\"");
        // A text that names a machine path has a length per checkout.
        else if (json && (text.Contains("<fixtures>", StringComparison.Ordinal) || text.Contains("<repo>", StringComparison.Ordinal)))
            text = KeptChars().Replace(text, m => m.Groups[2].Success ? m.Groups[2].Value + "\"<chars>\"" : m.Value);
        if (json) text = text.Replace(@"\r\n", @"\n");
        return Volatile().Replace(text, "<id>").ReplaceLineEndings("\n");
    }
}
