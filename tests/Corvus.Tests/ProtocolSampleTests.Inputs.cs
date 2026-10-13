using System.Security.Cryptography;
using System.Text.Json;
using Corvus.Native.Annotations;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>The sample inputs: files written beside the fixtures under <see cref="In"/>, setup calls and cleanups.</summary>
public partial class ProtocolSampleTests
{
    /// <summary>Inputs folder, relative to the fixtures (the server's working directory), rewritten on every run.</summary>
    private const string In = "samples/";

    /// <summary>Images that tools annotate or name persistently: a random tail gives each run its own hash (and sidecar).</summary>
    private static readonly string[] FreshImages = ["edit.dll", "tiny.dll", "typed.dll", "il2cpp.dll"];

    private static string InputsFolder => Path.Combine(Path.GetDirectoryName(Env.FixturePath)!, "samples");

    private static void WriteInputs()
    {
        if (Directory.Exists(InputsFolder)) Directory.Delete(InputsFolder, recursive: true);
        var dir = new TempDir(InputsFolder);
        File.WriteAllBytes(dir.File("loaded.dll"), [.. NativePeTests.KitchenSink(is64: true), 0xC1]);
        File.WriteAllBytes(dir.File("edit.dll"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(dir.File("il2cpp.dll"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(dir.File("aot.dll"), NativeAotHeaderTests.Sample().Build());
        McpProtocolTests.PdbSample(dir);
        PdbTypeFixture.Image(dir);
        foreach (var name in FreshImages)
        {
            using var file = new FileStream(dir.File(name), FileMode.Append);
            file.Write(RandomNumberGenerator.GetBytes(16));
        }
        AndroidSamples.Save(dir, "app.apk", AndroidSamples.Apk(30, ("classes.dex", AndroidSamples.Dex())));
        AndroidSamples.SaveXamarin(dir);
        UnityOverviewTests.MonoSample(dir);
        File.Copy(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"), dir.File("lz4.nupkg"));
        McpProtocolTests.FolderPair(dir, "old");
        McpProtocolTests.FolderPair(dir, "new");
        SyntheticCrash.Write(dir);
        Directory.CreateDirectory(dir.File("dumps"));
        File.Copy(dir.File("synth.dmp"), Path.Combine(dir.File("dumps"), "synth.dmp"));
        File.WriteAllBytes(dir.File("v1.dll"), Build("v1"));
        File.WriteAllBytes(dir.File("v2.dll"), Build("v2"));
    }

    /// <summary>Two builds of a small library: one method renamed, one body changed, one type added.</summary>
    private static byte[] Build(string version)
    {
        var source = version == "v1"
            ? "namespace Sample.Meter { public class Gauge { public int Read(int x) => x + 1; public int Scale(int x) => x * 2; } }"
            : "namespace Sample.Meter { public class Gauge { public int ReadValue(int x) => x + 1; public int Scale(int x) => x * 3; } public class Dial { } }";
        return Roslyn.Compile("Sample.Meter", source, new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(
            Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, deterministic: true));
    }

    /// <summary>Calls made before the samples (not recorded); each named value is what "$name" arguments become.</summary>
    private static async Task<Dictionary<string, string>> SetupAsync(McpClient client)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        await CallAsync(client, "load_assembly", new() { ["path"] = In + "edit.dll" });
        var note = await CallAsync(client, "record_note", new() { ["text"] = "checks the license", ["anchor"] = "edit.dll", ["kind"] = "question" });
        values["note"] = note.StructuredContent!.Value.GetProperty("id").GetString()!;
        var compared = await CallAsync(client, "compare_assemblies", new() { ["oldAssembly"] = In + "v1.dll", ["newAssembly"] = In + "v2.dll", ["tokenMap"] = true });
        values["kept"] = compared.StructuredContent!.Value.GetProperty("tokenMapResultId").GetString()!;
        foreach (var (tool, args) in Unload) await CallAsync(client, tool, args);
        foreach (var (tool, args) in (IEnumerable<(string, Dictionary<string, object?>)>)[.. Edited, ExportScript, .. Discard])
            await CallAsync(client, tool, args);
        await CallAsync(client, "save_session", new() { ["outputPath"] = In + "setup.session.json" });
        return values;
    }

    /// <summary>v1 loaded with one applied edit; samples on edit scripts work on it, so TestFixture's edit history stays empty.</summary>
    private static readonly (string, Dictionary<string, object?>)[] Edited =
        [("load_assembly", new() { ["path"] = In + "v1.dll" }), ("stub_method", new() { ["method"] = "Sample.Meter.Gauge::Scale", ["value"] = "0", ["dryRun"] = false })];

    private static readonly (string, Dictionary<string, object?>) ExportScript =
        ("export_edits", new() { ["assembly"] = In + "v1.dll", ["outputPath"] = In + "setup-edits.json" });

    private static readonly (string, Dictionary<string, object?>)[] Discard =
        [("revert_edits", new() { ["assembly"] = In + "v1.dll" }), ("unload_assembly", new() { ["assembly"] = In + "v1.dll" })];

    /// <summary>Calls made before a sample (not recorded).</summary>
    private static readonly Dictionary<string, (string Tool, Dictionary<string, object?> Args)[]> Before = new(StringComparer.Ordinal)
    {
        ["apply_edits"] = [("load_assembly", new() { ["path"] = In + "v1.dll" })],
        ["export_edits"] = Edited,
        ["revert_edits"] = Edited,
    };

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private static async Task<CallToolResult> CallAsync(McpClient client, string tool, Dictionary<string, object?> args)
    {
        var r = await client.CallToolAsync(tool, args);
        Assert.False(r.IsError == true, $"{tool}: {Text(r)}");
        return r;
    }

    private static readonly (string, Dictionary<string, object?>)[] Unload =
        [("unload_assembly", new() { ["assembly"] = In + "v1.dll" }), ("unload_assembly", new() { ["assembly"] = In + "v2.dll" })];

    /// <summary>Calls made after a sample (not recorded), so what it loaded reaches no later sample.</summary>
    private static readonly Dictionary<string, (string Tool, Dictionary<string, object?> Args)[]> After = new(StringComparer.Ordinal)
    {
        ["compare_assemblies"] = Unload,
        ["find_counterpart"] = Unload,
        ["apply_edits"] = [Discard[1]],
        ["export_edits"] = Discard,
        ["revert_edits"] = [Discard[1]],
    };

    /// <summary>The arguments with "$name" string values replaced from <paramref name="values"/>.</summary>
    private static Dictionary<string, object?> Bind(Dictionary<string, object?> args, Dictionary<string, string> values) =>
        args.ToDictionary(a => a.Key, a => a.Value switch
        {
            string s when s.StartsWith('$') && values.TryGetValue(s[1..], out var v) => v,
            JsonElement { ValueKind: JsonValueKind.String } e when e.GetString() is { } s && s.StartsWith('$') && values.TryGetValue(s[1..], out var v) => v,
            var other => other,
        });

    /// <summary>Removes the sidecars and notes of this run's fresh images from the shared test data folder.</summary>
    private static void DeleteFreshSidecars()
    {
        var store = new AnnotationStore();
        foreach (var name in FreshImages)
        {
            var file = Path.Combine(InputsFolder, name);
            if (!File.Exists(file)) continue;
            var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file)));
            foreach (var folder in new[] { store.Root, Path.Combine(store.Root, "notes") })
                if (Directory.Exists(folder))
                    foreach (var f in Directory.EnumerateFiles(folder, sha + "*")) File.Delete(f);
        }
    }
}
