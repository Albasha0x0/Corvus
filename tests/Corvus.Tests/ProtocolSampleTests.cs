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
        await using var server = await InProcessServer.StartAsync();
        var stale = new List<string>();
        foreach (var (tool, args) in calls.OrderBy(c => c.Key, StringComparer.Ordinal))
        {
            // An export starts from no directory, so every run records the same outcome.
            if (args.GetValueOrDefault("outputDirectory") is { } output && Directory.Exists(output.ToString())) Directory.Delete(output.ToString()!, recursive: true);
            var result = await server.Client.CallToolAsync(tool, args);
            var sample = new JsonObject
            {
                ["tool"] = tool,
                ["arguments"] = JsonSerializer.SerializeToNode(args),
                ["isError"] = result.IsError == true,
                ["content"] = new JsonArray([.. result.Content.OfType<TextContentBlock>().Select(b => (JsonNode)Normalize(b.Text))]),
                ["structuredContent"] = result.StructuredContent is { } s ? JsonNode.Parse(Normalize(s.GetRawText())) : null,
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

    [GeneratedRegex("[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|r-[0-9a-f]{12}")]
    private static partial Regex Volatile();

    /// <summary>Machine paths, hashes (a built fixture's MD5 differs per checkout), GUIDs and result ids become labels.</summary>
    private static string Normalize(string text)
    {
        foreach (var (path, label) in new[] { (Path.GetDirectoryName(Env.FixturePath)!, "<fixtures>"), (DocsTests.RepoRoot(), "<repo>") })
            foreach (var form in new[] { path, path.Replace('\\', '/'), JsonEncodedText.Encode(path).ToString() })
                text = text.Replace(form, label, StringComparison.OrdinalIgnoreCase);
        text = text.Replace(@"<fixtures>\\", "<fixtures>/").Replace(@"<fixtures>\", "<fixtures>/");
        return Volatile().Replace(text, "<id>").ReplaceLineEndings("\n");
    }
}
