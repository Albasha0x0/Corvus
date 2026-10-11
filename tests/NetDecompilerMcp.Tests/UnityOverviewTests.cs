using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>unity_overview over tiny synthetic game layouts: Mono, Il2Cpp (readable, encrypted, tampered header), input forms, not Unity.</summary>
public sealed class UnityOverviewTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A Mono title: Game.exe, Game_Data (globalgamemanagers 2022.3.62f1, Managed with Assembly-CSharp), MonoBleedingEdge, Burst, Addressables, EAC.</summary>
    internal static string MonoSample(TempDir dir)
    {
        var game = Path.Combine(dir.Path, "MonoGame");
        if (Directory.Exists(game)) return game;
        var data = Path.Combine(game, "Game_Data");
        Directory.CreateDirectory(Path.Combine(data, "Managed"));
        File.WriteAllBytes(Path.Combine(game, "Game.exe"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(data, "globalgamemanagers"), SerializedHeader(22, "2022.3.62f1"));
        File.Copy(Env.FixturePath, Path.Combine(data, "Managed", "Assembly-CSharp.dll"));
        File.WriteAllBytes(Path.Combine(data, "Managed", "Unity.Addressables.dll"), []);
        File.WriteAllText(Path.Combine(data, "app.info"), "Studio\nMono Game");
        Touch(game, "MonoBleedingEdge", "EmbedRuntime", "mono-2.0-bdwgc.dll");
        Touch(data, "Plugins", "x86_64", "lib_burst_generated.dll");
        Touch(data, "StreamingAssets", "aa", "catalog.json");
        Touch(game, "EasyAntiCheat", "Settings.json");
        return game;
    }

    /// <summary>An Il2Cpp title: GameAssembly.dll, Game_Data/il2cpp_data/Metadata/global-metadata.dat (v27 by default) and data.unity3d 2021.1.5f1.</summary>
    private string Il2CppSample(string name, byte[]? metadata = null)
    {
        var game = Path.Combine(_dir.Path, name);
        var data = Path.Combine(game, "Game_Data");
        Directory.CreateDirectory(Path.Combine(data, "il2cpp_data", "Metadata"));
        File.WriteAllBytes(Path.Combine(game, "Game.exe"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(game, "GameAssembly.dll"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(data, "data.unity3d"), [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0]);
        File.WriteAllText(Path.Combine(data, "ScriptingAssemblies.json"), """{"names":["Assembly-CSharp.dll","Unity.Burst.dll","mscorlib.dll"],"types":[16,16,16]}""");
        File.WriteAllBytes(Path.Combine(data, "il2cpp_data", "Metadata", "global-metadata.dat"), metadata ?? Metadata(27, ["Player", "Update", "a", "b"]));
        return game;
    }

    [Fact]
    public void Mono_title_reports_version_backend_markers_and_the_managed_folder_as_next_step()
    {
        var game = MonoSample(_dir);
        var r = UnityOverview.Inspect(game, false, default);
        Assert.Equal("2022.3.62f1", r.Engine.Version);
        Assert.Equal("serialized_file", Assert.Single(r.Engine.Claims).Source); // the synthetic exe has no version resource
        Assert.Equal("single_source", r.Engine.Agreement);
        Assert.Equal(("mono", "readable"), (r.Backend.Kind, r.Backend.ManagedState));
        Assert.StartsWith("mono-2.0-bdwgc", r.Backend.MonoRuntime);
        Assert.Equal("not_applicable", r.Backend.MetadataState);
        Assert.Equal(("windows", "x64"), (r.Platform, r.Architecture));
        Assert.Equal(("Studio", "Mono Game"), (r.Company, r.Product));
        var names = r.Markers.Select(m => m.Name).ToList();
        Assert.Contains("Easy Anti-Cheat", names);
        Assert.Contains("Burst", names);
        Assert.Contains("Addressables", names);
        Assert.Contains(r.Folders, f => f.Kind == "addressables" && f.Note!.Contains("catalog.json"));
        var step = r.NextSteps[0];
        Assert.Equal(("load_assembly", Path.Combine(game, "Game_Data", "Managed")), (step.Tool, step.Arguments["path"]));

        // Every input form names the same title.
        foreach (var input in new[] { Path.Combine(game, "Game.exe"), Path.Combine(game, "Game_Data"), Path.Combine(game, "Game_Data", "Managed") })
            Assert.Equal(game, UnityOverview.Inspect(input, false, default).GameDirectory);
    }

    /// <summary>An .apk reads like its extracted game files; a package without Il2Cpp metadata says what to do instead.</summary>
    [Fact]
    public void An_android_package_is_read_through_its_extracted_game_files()
    {
        var apk = Path.Combine(_dir.Path, "game.apk");
        using (var zip = System.IO.Compression.ZipFile.Open(apk, System.IO.Compression.ZipArchiveMode.Create))
        {
            void Entry(string name, byte[] bytes)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(bytes);
            }
            Entry("lib/arm64-v8a/libil2cpp.so", [0x7F, 0x45, 0x4C, 0x46, 2]);
            Entry("lib/arm64-v8a/libunity.so", [0x7F, 0x45, 0x4C, 0x46, 2]);
            Entry("assets/bin/Data/Managed/Metadata/global-metadata.dat", Metadata(27, ["Player"]));
            Entry("assets/bin/Data/data.unity3d", [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0]);
        }
        var mono = Path.Combine(_dir.Path, "mono.apk");
        using (var zip = System.IO.Compression.ZipFile.Open(mono, System.IO.Compression.ZipArchiveMode.Create)) zip.CreateEntry("assets/bin/Data/Managed/Assembly-CSharp.dll");
        var previous = Environment.GetEnvironmentVariable(Services.Il2CppRawLoader.RootVariable);
        Environment.SetEnvironmentVariable(Services.Il2CppRawLoader.RootVariable, Path.Combine(_dir.Path, "cache"));
        try
        {
            var r = UnityOverview.Inspect(apk, false, default);
            Assert.Equal(("il2cpp", "readable", "2021.1.5f1"), (r.Backend.Kind, r.Backend.MetadataState, r.Engine.Version));
            Assert.Contains(r.Notes, n => n.StartsWith($"Read from the game files of {apk}", StringComparison.Ordinal));
            var error = Assert.Throws<ToolError>(() => UnityOverview.Inspect(mono, false, default));
            Assert.Contains("unpack_container", error.Remediation);
        }
        finally { Environment.SetEnvironmentVariable(Services.Il2CppRawLoader.RootVariable, previous); }
    }

    [Fact]
    public void Il2Cpp_title_states_metadata_readability_and_branches_the_next_step()
    {
        var readable = UnityOverview.Inspect(Il2CppSample("Readable"), false, default);
        Assert.Equal(("il2cpp", "readable", 27), (readable.Backend.Kind, readable.Backend.MetadataState, readable.Backend.MetadataVersion));
        Assert.Equal(("2021.1.5f1", "bundle_header"), (readable.Engine.Version, readable.Engine.Claims[0].Source));
        Assert.Equal(("2020.2 - 2021.1", "consistent"), (readable.Engine.MetadataRange, readable.Engine.MetadataCheck));
        Assert.Equal(3, readable.Backend.ScriptingAssemblies);
        Assert.Contains(readable.Markers, m => m.Name == "Burst");
        Assert.Equal(["load_assembly", "apply_il2cpp_names"], readable.NextSteps.Select(s => s.Action));
        Assert.EndsWith("global-metadata.dat", readable.NextSteps[0].Arguments["path"]);

        var game = Il2CppSample("Encrypted", [0x12, 0x34, 0x56, 0x78, .. new byte[200]]);
        var encrypted = UnityOverview.Inspect(Path.Combine(game, "GameAssembly.dll"), false, default);
        Assert.Equal(game, encrypted.GameDirectory);
        Assert.Equal("encrypted", encrypted.Backend.MetadataState);
        Assert.Equal("not_checked", encrypted.Engine.MetadataCheck);
        Assert.Equal("dump_from_memory", encrypted.NextSteps[0].Action);
        Assert.Contains(encrypted.Markers, m => m.Category == "encryption");

        var tampered = Metadata(27, ["x"]);
        BinaryPrimitives.WriteInt32LittleEndian(tampered.AsSpan(4), 0x01B89E24);
        var t = UnityOverview.Inspect(Path.Combine(Il2CppSample("Tampered", tampered), "Game_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), false, default);
        Assert.Equal("header_tampered", t.Backend.MetadataState);
        Assert.Contains("version field", t.Backend.MetadataStateReason);

        var old = UnityOverview.Inspect(Il2CppSample("Old", Metadata(23, ["x"])), false, default);
        Assert.Equal(("unsupported_version", "use_external_dumper"), (old.Backend.MetadataState, old.NextSteps[0].Action));
        Assert.Equal("inconsistent", old.Engine.MetadataCheck); // v23 is 5.6 - 2017.1, the bundle says 2021.1
    }

    [Fact]
    public void An_iOS_app_is_an_Il2Cpp_title_with_UnityFramework_and_a_macOS_universal_binary_has_both_cpus()
    {
        var app = Path.Combine(_dir.Path, "Game.app");
        var data = Path.Combine(app, "Data");
        Directory.CreateDirectory(Path.Combine(data, "Managed", "Metadata"));
        File.WriteAllBytes(Path.Combine(data, "globalgamemanagers"), SerializedHeader(22, "2021.3.1f1"));
        File.WriteAllBytes(Path.Combine(data, "Managed", "Metadata", "global-metadata.dat"), Metadata(29, ["Player", "Update"]));
        var framework = Path.Combine(app, "Frameworks", "UnityFramework.framework", "UnityFramework");
        Directory.CreateDirectory(Path.GetDirectoryName(framework)!);
        File.WriteAllBytes(framework, [0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01, .. new byte[24]]);
        foreach (var input in new[] { app, data, Path.Combine(data, "Managed", "Metadata", "global-metadata.dat") })
        {
            var r = UnityOverview.Inspect(input, false, default);
            Assert.Equal((app, "ios", "arm64"), (r.GameDirectory, r.Platform, r.Architecture));
            Assert.Equal(("il2cpp", framework, "readable"), (r.Backend.Kind, r.Backend.NativeBinary, r.Backend.MetadataState));
            Assert.Equal(["load_assembly", "apply_il2cpp_names"], r.NextSteps.Select(s => s.Action));
        }
        byte[] fat = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0x01, 0, 0, 0x07, .. new byte[16], 0x01, 0, 0, 0x0C, .. new byte[16]];
        Assert.Equal("universal (x64, arm64)", UnityOverview.MachOArchitecture(fat));
        Assert.Null(UnityOverview.MachOArchitecture([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52])); // a Java class file
    }

    [Fact]
    public void Not_a_unity_title_is_a_typed_error_saying_what_was_looked_for()
    {
        var e = Assert.Throws<ToolError>(() => UnityOverview.Inspect(Env.FixturePath, false, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("not_a_unity_title", e.Message);
        Assert.Contains("globalgamemanagers", e.Message);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => UnityOverview.Inspect(_dir.File("missing"), false, default)).Code);
    }

    internal static byte[] SerializedHeader(int format, string version)
    {
        var bytes = new byte[(format >= 22 ? 48 : 20) + version.Length + 1 + 16];
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), (uint)format);
        Encoding.ASCII.GetBytes(version).CopyTo(bytes, format >= 22 ? 48 : 20);
        return bytes;
    }

    /// <summary>A metadata header (0x100 bytes of offset / size pairs) whose string heap holds <paramref name="names"/>.</summary>
    private static byte[] Metadata(int version, string[] names)
    {
        var heap = Encoding.UTF8.GetBytes(string.Join('\0', names) + "\0");
        var bytes = new byte[0x100 + heap.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0xFAB11BAF);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), version);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), 0x100);   // string literals: empty, right after the header
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(24), 0x100);  // string heap
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28), heap.Length);
        heap.CopyTo(bytes, 0x100);
        return bytes;
    }

    private static void Touch(string root, params string[] parts)
    {
        var path = Path.Combine([root, .. parts]);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, []);
    }
}

/// <summary>
/// unity_overview over the Unity titles installed on this machine: Steam library folders (from the Steam registry key) and
/// NDM_UNITY_TITLES (';'-separated game folders). Prints per-title results and timings; each overview must finish in seconds.
/// </summary>
[Collection(SweepCollection.Name)]
[Trait("Speed", "Slow")]
public sealed class UnityOverviewRealTests(ITestOutputHelper output)
{
    [Fact]
    public void Installed_titles_are_overviewed_in_seconds()
    {
        var titles = Titles().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (titles.Count == 0) { output.WriteLine("No Unity titles found (Steam libraries, NDM_UNITY_TITLES)."); return; }
        int unity = 0;
        var total = Stopwatch.StartNew();
        foreach (var title in titles)
        {
            var watch = Stopwatch.StartNew();
            UnityOverview.Report r;
            try { r = UnityOverview.Inspect(title, Environment.GetEnvironmentVariable("NDM_DIE") != null, default); }
            catch (ToolError e) when (e.Code == ErrorCode.Unsupported) { continue; }
            watch.Stop();
            unity++;
            output.WriteLine($"{Path.GetFileName(title)}: {watch.Elapsed.TotalSeconds:0.00} s | Unity {r.Engine.Version} ({r.Engine.Agreement}; " +
                             $"{string.Join(", ", r.Engine.Claims.Select(c => $"{c.Source}={c.Normalized}"))}) | {r.Backend.Kind} {r.Platform}/{r.Architecture}" +
                             (r.Backend.Kind == "il2cpp" ? $" | metadata v{r.Backend.MetadataVersion} {r.Backend.MetadataState} range {r.Engine.MetadataRange} {r.Engine.MetadataCheck}" : "") +
                             (r.Backend.Kind == "mono" ? $" | {r.Backend.MonoRuntime}; {r.Backend.DotnetProfile}; {r.Backend.ManagedAssemblies} DLLs {r.Backend.ManagedState}" : "") +
                             (r.Backend.UnreadableNameRatio is { } q ? $" | unreadable names {q:P1} of {r.Backend.NamesRead}" : ""));
            output.WriteLine($"    markers: {string.Join("; ", r.Markers.Select(m => $"{m.Category}:{m.Name}"))}");
            output.WriteLine($"    next: {string.Join(" -> ", r.NextSteps.Select(s => s.Action + (s.Arguments.TryGetValue("path", out var p) ? $"({p})" : "")))}");
            foreach (var note in r.Notes) output.WriteLine($"    note: {note}");
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(r.Markers.Any(m => m.Source == "detect_it_easy") ? 30 : 10), $"{title}: {watch.Elapsed}");
            Assert.NotEqual("unknown", r.Backend.Kind);
            Assert.NotNull(r.Engine.Version);
            Assert.NotEmpty(r.NextSteps);
        }
        output.WriteLine($"{unity} Unity title(s) of {titles.Count} folders, {total.Elapsed.TotalSeconds:0.0} s");
    }

    private static IEnumerable<string> Titles()
    {
        if (Environment.GetEnvironmentVariable("NDM_UNITY_TITLES") is { Length: > 0 } list)
            foreach (var t in list.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                if (Directory.Exists(t) || File.Exists(t)) yield return t;
        if (!OperatingSystem.IsWindows()) yield break;
        var steam = Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        if (steam == null) yield break;
        var libraries = new List<string> { steam };
        var vdf = Path.Combine(steam, "steamapps", "libraryfolders.vdf");
        if (File.Exists(vdf))
            libraries.AddRange(Regex.Matches(File.ReadAllText(vdf), "\"path\"\\s+\"([^\"]+)\"").Select(m => m.Groups[1].Value.Replace(@"\\", @"\")));
        foreach (var library in libraries.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var common = Path.Combine(library, "steamapps", "common");
            if (!Directory.Exists(common)) continue;
            foreach (var game in Directory.EnumerateDirectories(common))
                if (File.Exists(Path.Combine(game, "UnityPlayer.dll")) || Directory.EnumerateDirectories(game, "*_Data").Any())
                    yield return game;
        }
    }
}
