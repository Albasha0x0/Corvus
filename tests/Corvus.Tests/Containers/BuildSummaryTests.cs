using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using AssetRipper.Primitives;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using LibCpp2IL.Metadata;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_build over tiny synthetic build layouts: Mono, AOT (readable, encrypted, changed header), input forms, other builds.</summary>
public sealed class BuildSummaryTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A Mono build: App.exe, App_Data (globalgamemanagers 2022.3.62f1, Managed with Assembly-CSharp), MonoBleedingEdge, Burst, Addressables, EAC.</summary>
    internal static string MonoSample(TempDir dir)
    {
        var folder = Path.Combine(dir.Path, "MonoApp");
        if (Directory.Exists(folder)) return folder;
        var data = Path.Combine(folder, "App_Data");
        Directory.CreateDirectory(Path.Combine(data, "Managed"));
        File.WriteAllBytes(Path.Combine(folder, "App.exe"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(data, "globalgamemanagers"), SerializedHeader(22, "2022.3.62f1"));
        File.Copy(Env.FixturePath, Path.Combine(data, "Managed", "Assembly-CSharp.dll"));
        File.WriteAllBytes(Path.Combine(data, "Managed", "Unity.Addressables.dll"), []);
        File.WriteAllText(Path.Combine(data, "app.info"), "Studio\nMono App");
        Touch(folder, "MonoBleedingEdge", "EmbedRuntime", "mono-2.0-bdwgc.dll");
        Touch(data, "Plugins", "x86_64", "lib_burst_generated.dll");
        Touch(data, "StreamingAssets", "aa", "catalog.json");
        Touch(folder, "EasyAntiCheat", "Settings.json");
        return folder;
    }

    /// <summary>An AOT build: GameAssembly.dll, App_Data/il2cpp_data/Metadata/global-metadata.dat (v27 by default) and data.unity3d 2021.1.5f1.</summary>
    private string AotSample(string name, byte[]? metadata = null)
    {
        var folder = Path.Combine(_dir.Path, name);
        var data = Path.Combine(folder, "App_Data");
        Directory.CreateDirectory(Path.Combine(data, "il2cpp_data", "Metadata"));
        File.WriteAllBytes(Path.Combine(folder, "App.exe"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(folder, "GameAssembly.dll"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(data, "data.unity3d"), [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0]);
        File.WriteAllText(Path.Combine(data, "ScriptingAssemblies.json"), """{"names":["Assembly-CSharp.dll","Unity.Burst.dll","mscorlib.dll"],"types":[16,16,16]}""");
        File.WriteAllBytes(Path.Combine(data, "il2cpp_data", "Metadata", "global-metadata.dat"), metadata ?? Metadata(27, ["Player", "Update", "a", "b"]));
        return folder;
    }

    [Fact]
    public void A_Mono_build_reports_version_backend_markers_and_the_managed_folder_as_next_step()
    {
        var folder = MonoSample(_dir);
        var r = BuildSummary.Inspect(folder, false, default);
        Assert.Equal("2022.3.62f1", r.Engine.Version);
        // The synthetic exe has no version resource.
        Assert.Equal("serialized_file", Assert.Single(r.Engine.Claims).Source);
        Assert.Equal("single_source", r.Engine.Agreement);
        Assert.Equal(("mono", "readable"), (r.Backend.Kind, r.Backend.ManagedState));
        Assert.StartsWith("mono-2.0-bdwgc", r.Backend.MonoRuntime);
        Assert.Equal("not_applicable", r.Backend.MetadataState);
        Assert.Equal(("windows", "x64"), (r.Platform, r.Architecture));
        Assert.Equal(("Studio", "Mono App"), (r.Company, r.Product));
        var names = r.Markers.Select(m => m.Name).ToList();
        Assert.Contains("EasyAntiCheat", names);
        Assert.Contains("Burst", names);
        Assert.Contains("Addressables", names);
        Assert.Contains(r.Folders, f => f.Kind == "addressables" && f.Note!.Contains("catalog.json"));
        var step = r.NextSteps[0];
        Assert.Equal(("load_assembly", Path.Combine(folder, "App_Data", "Managed")), (step.Tool, step.Arguments["path"]));

        // Every input form names the same build.
        foreach (var input in new[] { Path.Combine(folder, "App.exe"), Path.Combine(folder, "App_Data"), Path.Combine(folder, "App_Data", "Managed") })
            Assert.Equal(folder, BuildSummary.Inspect(input, false, default).AppDirectory);
    }

    [Fact]
    public void Two_calls_give_the_same_bytes()
    {
        var folder = MonoSample(_dir);
        string Json() => System.Text.Json.JsonSerializer.Serialize(BuildSummary.Inspect(folder, false, default));
        var first = Json();
        Assert.Equal(first, Json());
        Assert.DoesNotContain("Seconds", first);
    }

    /// <summary>An .apk reads like its extracted build files; a package without AOT metadata says what to do instead.</summary>
    [Fact]
    public void An_android_package_is_read_through_its_extracted_build_files()
    {
        var apk = Path.Combine(_dir.Path, "app.apk");
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
        byte[] header = [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0];
        void Zip(string path, params (string Name, byte[] Bytes)[] entries)
        {
            using var zip = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create);
            foreach (var (name, bytes) in entries)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(bytes);
            }
        }
        var assembly = File.ReadAllBytes(Env.FixturePath);
        var mono = Path.Combine(_dir.Path, "mono.apk");
        Zip(mono, ("assets/bin/Data/Managed/Assembly-CSharp.dll", assembly), ("assets/bin/Data/data.unity3d", header),
            ("lib/arm64-v8a/libunity.so", [0x7F, 0x45, 0x4C, 0x46, 2]), ("lib/arm64-v8a/libmonobdwgc-2.0.so", [0x7F, 0x45, 0x4C, 0x46, 2]));
        // A zipped Windows build: the folder above <Product>_Data becomes the build root.
        var desktop = Path.Combine(_dir.Path, "title.zip");
        Zip(desktop, ("Title v1.0/Title.exe", File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Env.FixturePath)!, "Corvus.Tests.dll"))),
            ("Title v1.0/Title_Data/data.unity3d", header), ("Title v1.0/Title_Data/Managed/Assembly-CSharp.dll", assembly));
        var r = BuildSummary.Inspect(apk, false, default);
        Assert.Equal(("aot", "readable", "2021.1.5f1"), (r.Backend.Kind, r.Backend.MetadataState, r.Engine.Version));
        Assert.Contains(r.Notes, n => n.StartsWith($"Read from the build files of {apk}", StringComparison.Ordinal));
        var m = BuildSummary.Inspect(mono, false, default);
        Assert.Equal(("mono", "android", "2021.1.5f1"), (m.Backend.Kind, m.Platform, m.Engine.Version));
        var d = BuildSummary.Inspect(desktop, false, default);
        Assert.Equal(("mono", "2021.1.5f1"), (d.Backend.Kind, d.Engine.Version));
        Assert.EndsWith("Title.exe", d.Executable);
    }

    /// <summary>A zipped build past the 260-character limit: folders above the zip and inside it are each over 100 characters.</summary>
    [Fact]
    public void A_zipped_build_under_a_deep_path_is_read_from_a_short_cache_path()
    {
        var deep = Path.Combine(_dir.Path, new string('a', 100), new string('b', 100), new string('c', 100));
        Directory.CreateDirectory(deep);
        var zip = Path.Combine(deep, "title.zip");
        var top = new string('t', 120) + "/" + new string('u', 120) + "/";
        byte[] header = [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2021.1.5f1\0"u8, 0, 0, 0, 0];
        using (var archive = System.IO.Compression.ZipFile.Open(zip, System.IO.Compression.ZipArchiveMode.Create))
            foreach (var (name, bytes) in new[] { (top + "Title.exe", File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Env.FixturePath)!, "Corvus.Tests.dll"))),
                         (top + "Title_Data/data.unity3d", header), (top + "Title_Data/Managed/Assembly-CSharp.dll", File.ReadAllBytes(Env.FixturePath)) })
            {
                using var s = archive.CreateEntry(name).Open();
                s.Write(bytes);
            }
        Assert.True(zip.Length > 300 && (top + "Title_Data/Managed/Assembly-CSharp.dll").Length > 260);
        var r = BuildSummary.Inspect(zip, false, default);
        Assert.Equal(("mono", "2021.1.5f1"), (r.Backend.Kind, r.Engine.Version));
        Assert.EndsWith("Title.exe", r.Executable);
        var folder = Path.GetDirectoryName(r.Executable)!;
        Assert.All(Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories), f => Assert.True(f.Length < 260, f));
    }

    [Fact]
    public void WebGl_build_reads_its_data_file_and_names_the_wasm()
    {
        // WebPlayerData: magic, header length, then (offset, size, name length, name) per file.
        (string Name, byte[] Bytes)[] files = [("data.unity3d", [.. "UnityFS\0"u8, 0, 0, 0, 8, .. "5.x.x\0"u8, .. "2022.3.10f1\0"u8, 0, 0, 0, 0]),
            ("Il2CppData/Metadata/global-metadata.dat", Metadata(29, ["Player"]))];
        int header = 20 + files.Sum(f => 12 + f.Name.Length);
        var table = new MemoryStream();
        table.Write("UnityWebData1.0\0"u8);
        table.Write(BitConverter.GetBytes(header));
        int at = header;
        foreach (var (name, bytes) in files)
        {
            table.Write(BitConverter.GetBytes(at));
            table.Write(BitConverter.GetBytes(bytes.Length));
            table.Write(BitConverter.GetBytes(name.Length));
            table.Write(System.Text.Encoding.UTF8.GetBytes(name));
            at += bytes.Length;
        }
        foreach (var (_, bytes) in files) table.Write(bytes);
        var build = Directory.CreateDirectory(Path.Combine(_dir.Path, "web", "Build")).FullName;
        using (var gz = new System.IO.Compression.GZipStream(File.Create(Path.Combine(build, "web.data.gz")), System.IO.Compression.CompressionLevel.Fastest))
            gz.Write(table.ToArray());
        File.WriteAllBytes(Path.Combine(build, "web.wasm"), [.. "\0asm"u8, 1, 0, 0, 0]);
        var r = BuildSummary.Inspect(Path.Combine(_dir.Path, "web"), false, default);
        Assert.Equal(("webgl", "aot", "2022.3.10f1", 29), (r.Platform, r.Backend.Kind, r.Engine.Version, r.Backend.MetadataVersion));
        Assert.Contains(r.Notes, n => n.StartsWith("WebGL code: web.wasm, WebAssembly", StringComparison.Ordinal));
        var failures = FormatFuzz.Run(table.ToArray(), b => { try { WebGlBuild.Entries(b, "x.data"); } catch (ToolError) { } }, 500);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    [Fact]
    public void An_AOT_build_states_metadata_readability_and_branches_the_next_step()
    {
        var readable = BuildSummary.Inspect(AotSample("Readable"), false, default);
        Assert.Equal(("aot", "readable", 27), (readable.Backend.Kind, readable.Backend.MetadataState, readable.Backend.MetadataVersion));
        Assert.Equal(("2021.1.5f1", "bundle_header"), (readable.Engine.Version, readable.Engine.Claims[0].Source));
        Assert.Equal(("2020.2 - 2021.1", "consistent"), (readable.Engine.MetadataRange, readable.Engine.MetadataCheck));
        Assert.Equal(3, readable.Backend.ScriptingAssemblies);
        Assert.Contains(readable.Markers, m => m.Name == "Burst");
        Assert.Equal(["load_assembly", "apply_metadata_names"], readable.NextSteps.Select(s => s.Action));
        Assert.EndsWith("global-metadata.dat", readable.NextSteps[0].Arguments["path"]);

        var folder = AotSample("Encrypted", [0x12, 0x34, 0x56, 0x78, .. new byte[200]]);
        var encrypted = BuildSummary.Inspect(Path.Combine(folder, "GameAssembly.dll"), false, default);
        Assert.Equal(folder, encrypted.AppDirectory);
        Assert.Equal("encrypted", encrypted.Backend.MetadataState);
        Assert.Equal("not_checked", encrypted.Engine.MetadataCheck);
        Assert.Equal("dump_from_memory", encrypted.NextSteps[0].Action);
        Assert.Contains(encrypted.Markers, m => m.Category == "encryption");

        var tampered = Metadata(27, ["x"]);
        BinaryPrimitives.WriteInt32LittleEndian(tampered.AsSpan(4), 0x01B89E24);
        var t = BuildSummary.Inspect(Path.Combine(AotSample("Tampered", tampered), "App_Data", "il2cpp_data", "Metadata", "global-metadata.dat"), false, default);
        Assert.Equal("header_tampered", t.Backend.MetadataState);
        Assert.Contains("version field", t.Backend.MetadataStateReason);

        var old = BuildSummary.Inspect(AotSample("Old", Metadata(23, ["x"])), false, default);
        Assert.Equal(("unsupported_version", "load_dummy_assemblies"), (old.Backend.MetadataState, old.NextSteps[0].Action));
        // v23 is 5.6 - 2017.1, the bundle says 2021.1.
        Assert.Equal("inconsistent", old.Engine.MetadataCheck);
    }

    [Fact]
    public void An_iOS_app_is_an_AOT_build_and_a_macOS_universal_binary_has_both_CPUs()
    {
        var app = Path.Combine(_dir.Path, "Example.app");
        var data = Path.Combine(app, "Data");
        Directory.CreateDirectory(Path.Combine(data, "Managed", "Metadata"));
        File.WriteAllBytes(Path.Combine(data, "globalgamemanagers"), SerializedHeader(22, "2021.3.1f1"));
        File.WriteAllBytes(Path.Combine(data, "Managed", "Metadata", "global-metadata.dat"), Metadata(29, ["Player", "Update"]));
        var framework = Path.Combine(app, "Frameworks", "UnityFramework.framework", "UnityFramework");
        Directory.CreateDirectory(Path.GetDirectoryName(framework)!);
        File.WriteAllBytes(framework, [0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01, .. new byte[24]]);
        foreach (var input in new[] { app, data, Path.Combine(data, "Managed", "Metadata", "global-metadata.dat") })
        {
            var r = BuildSummary.Inspect(input, false, default);
            Assert.Equal((app, "ios", "arm64"), (r.AppDirectory, r.Platform, r.Architecture));
            Assert.Equal(("aot", framework, "readable"), (r.Backend.Kind, r.Backend.NativeBinary, r.Backend.MetadataState));
            Assert.Equal(["load_assembly", "apply_metadata_names"], r.NextSteps.Select(s => s.Action));
        }
        byte[] fat = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0x01, 0, 0, 0x07, .. new byte[16], 0x01, 0, 0, 0x0C, .. new byte[16]];
        Assert.Equal("universal (x64, arm64)", BuildSummary.MachOArchitecture(fat));
        // A Java class file.
        Assert.Null(BuildSummary.MachOArchitecture([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52]));
    }

    [Fact]
    public void A_path_without_a_build_is_a_typed_error_saying_what_was_looked_for()
    {
        var e = Assert.Throws<ToolError>(() => BuildSummary.Inspect(Env.FixturePath, false, default));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("not a build (no UnityPlayer, libunity, GameAssembly or data folder", e.Message);
        Assert.Contains("not_a_build", e.Message);
        // The full list stays in details.
        Assert.Contains("globalgamemanagers", System.Text.Json.JsonSerializer.Serialize(e.Details));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => BuildSummary.Inspect(_dir.File("missing"), false, default)).Code);
    }

    [Fact]
    public async Task The_tool_text_is_rows_with_the_record_beside_it()
    {
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await new Corvus.Tools.BuildSummaryTools().SummarizeBuild(MonoSample(_dir));
        var report = Assert.IsType<BuildSummary.Report>(collector.Value);
        Assert.DoesNotContain("{\"", text);
        Assert.Contains($"Backend: mono, {report.Backend.ManagedAssemblies} assemblies", text);
        Assert.Contains("Next:\n  load_assembly path=", text);
    }

    /// <summary>The layout a fixture is written in: definition sizes and whether rgctx entries precede the images section.</summary>
    private sealed record LayoutSizes(int Header, bool Rgctx, int Image, int Type, int Method);

    // One row per definition layout of metadata versions 24 to 39, with a runtime version that selects it for the reader.
    public static TheoryData<string, int, string, string> Layouts => new()
    {
        { "v24.0", 24, "2018.2.0f1", "v24.0" },
        { "v24.1", 24, "2018.3.0f1", "v24.1-24.15" },
        { "v24.15", 24, "2018.4.34f1", "v24.1-24.15" },
        { "v24.2", 24, "2019.1.0f1", "v24.2-24.5" },
        { "v24.5", 24, "2019.4.21f1", "v24.2-24.5" },
        { "v27", 27, "2020.1.0f1", "v27" },
        { "v27.1", 27, "2020.2.4f1", "v27" },
        { "v27.2", 27, "2021.1.0f1", "v27" },
        { "v29", 29, "2021.3.0f1", "v29" },
        { "v29.1", 29, "2022.1.0f1", "v29" },
        { "v31", 31, "2022.2.0f1", "v31" },
        { "v31.1", 31, "2022.3.33f1", "v31" },
        { "v35", 35, "6000.0.0f1", "v35" },
        { "v38", 38, "6000.1.0f1", "v38" },
        { "v39", 39, "6000.2.0f1", "v39" },
    };

    private static LayoutSizes SizesOf(string name, int header) => name switch
    {
        "v24.0" => new(header, true, 32, 104, 56),
        "v24.1" or "v24.15" => new(header, true, 40, 100, 52),
        "v24.2" or "v24.5" => new(header, false, 40, 92, 32),
        "v27" or "v27.1" or "v27.2" or "v29" or "v29.1" => new(header, false, 40, 88, 32),
        "v31" or "v31.1" => new(header, false, 40, 88, 36),
        "v35" => new(header, false, 40, 84, 36),
        _ => new(header, false, 34, 81, 30),
    };

    /// <summary>
    /// A global-metadata.dat in <paramref name="layout"/>: every header section present, a one-name string heap, images
    /// of <paramref name="imageTypes"/> types each (2 and 3 by default), zero-filled type and method tables, and 4 KiB of
    /// zeros after the data for the reader, which reads one record of an empty section.
    /// </summary>
    private static byte[] LayoutMetadata(LayoutSizes layout, int[]? imageTypes = null, int methods = 7)
    {
        imageTypes ??= [2, 3];
        int types = imageTypes.Sum();
        bool counted = layout.Header >= 38;
        var names = new List<string>
        {
            "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods", "parameterDefaultValues", "fieldDefaultValues",
            "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters", "fields", "genericParameters", "genericParameterConstraints",
            "genericContainers", "nestedTypes", "interfaces", "vtableMethods", "interfaceOffsets", "typeDefinitions",
        };
        if (layout.Rgctx) names.Add("rgctxEntries");
        names.AddRange(["images", "assemblies"]);
        if (layout.Header < 27) names.AddRange(["metadataUsageLists", "metadataUsagePairs"]);
        names.AddRange(["fieldRefs", "referencedAssemblies"]);
        names.AddRange(layout.Header < 29 ? ["attributesInfo", "attributeTypes"] : ["attributeData", "attributeDataRange"]);
        names.AddRange(["unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges", "windowsRuntimeTypeNames"]);
        if (layout.Header >= 27) names.Add("windowsRuntimeStrings");
        names.Add("exportedTypeDefinitions");
        int stride = counted ? 12 : 8, headerSize = 8 + names.Count * stride;

        // From v38 an image's type indexes are 1 byte wide for up to 255 types.
        int width = counted ? 1 : 4, first = 0;
        var image = new byte[imageTypes.Length * layout.Image];
        for (int i = 0; i < imageTypes.Length; i++)
        {
            var entry = image.AsSpan(i * layout.Image);
            if (width == 1) entry[8] = (byte)first;
            else BinaryPrimitives.WriteInt32LittleEndian(entry[8..], first);
            BinaryPrimitives.WriteUInt32LittleEndian(entry[(8 + width)..], (uint)imageTypes[i]);
            first += imageTypes[i];
        }
        var contents = new Dictionary<string, (byte[] Bytes, int Count)>
        {
            ["string"] = ("a\0"u8.ToArray(), 1),
            ["images"] = (image, imageTypes.Length),
            ["typeDefinitions"] = (new byte[types * layout.Type], types),
            ["methods"] = (new byte[methods * layout.Method], methods),
        };
        // From v38 the reader sizes a type index by the interface offsets section: one 8-byte entry gives 4 bytes.
        if (counted) contents["interfaceOffsets"] = (new byte[8], 1);
        var body = new List<byte>();
        var header = new byte[headerSize];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0xFAB11BAF);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), layout.Header);
        for (int i = 0; i < names.Count; i++)
        {
            var (bytes, count) = contents.TryGetValue(names[i], out var c) ? c : ([], 0);
            var at = header.AsSpan(8 + i * stride);
            BinaryPrimitives.WriteInt32LittleEndian(at, headerSize + body.Count);
            BinaryPrimitives.WriteInt32LittleEndian(at[4..], bytes.Length);
            if (counted) BinaryPrimitives.WriteInt32LittleEndian(at[8..], count);
            body.AddRange(bytes);
        }
        return [.. header, .. body, .. new byte[4096]];
    }

    /// <summary>The image, type and method definitions the built-in metadata reader reads from <paramref name="bytes"/>.</summary>
    private static (int Images, int Types, int Methods) ReaderCounts(byte[] bytes, string engine)
    {
        lock (AotMetadataReader.Gate)
        {
            var meta = Il2CppMetadata.ReadFrom(bytes, UnityVersion.Parse(engine));
            return (meta.imageDefinitions.Length, meta.typeDefs.Length, meta.methodDefs.Length);
        }
    }

    [Theory]
    [MemberData(nameof(Layouts))]
    public void Counts_match_the_metadata_reader_in_every_definition_layout(string name, int header, string engine, string layout)
    {
        var bytes = LayoutMetadata(SizesOf(name, header));
        var b = BuildSummary.Inspect(AotSample("Counts " + name, bytes), false, default).Backend;
        Assert.Equal("readable", b.MetadataState);
        Assert.Equal(new AotMetadataCounts.Counts(2, 5, 7, layout, null), b.MetadataCounts);
        Assert.Equal((2, 5, 7), ReaderCounts(bytes, engine));
    }

    [Fact]
    public void Counts_of_the_2021_3_layout_match_the_metadata_reader()
    {
        var bytes = new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Assembly("mscorlib", "4.0.0.0")
            .Field("value", "Example.MarkerAttribute").Build();
        var (images, types, methods) = ReaderCounts(bytes, "2021.3.0f1");
        // The writer points its empty first section past the data; the overview reads that offset as the header size.
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8 + 2 * 8)));
        var b = BuildSummary.Inspect(AotSample("Writer", bytes), false, default).Backend;
        Assert.Equal(new AotMetadataCounts.Counts(images, types, methods, "v29", null), b.MetadataCounts);
    }

    [Fact]
    public void Images_that_do_not_add_up_to_the_type_table_leave_the_counts_unknown_with_the_reason()
    {
        var bytes = LayoutMetadata(SizesOf("v29", 29));
        // The second image's type count (3) becomes 4: its range runs one past the 5 types.
        int images = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8 + 20 * 8));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(images + 40 + 12), 4);
        var b = BuildSummary.Inspect(AotSample("Mismatch", bytes), false, default).Backend;
        var c = b.MetadataCounts!;
        Assert.Equal(((int?)null, (int?)null, (int?)null), (c.Images, c.Types, c.Methods));
        Assert.StartsWith("v29: image 1 names types 2 to 5, outside the 5", c.Reason);
    }

    [Fact]
    public void An_images_table_over_the_read_limit_leaves_the_counts_unknown_and_unread()
    {
        int entries = AotMetadataCounts.MaxImagesTable / 40 + 1;
        var bytes = LayoutMetadata(SizesOf("v29", 29), imageTypes: [5, .. new int[entries - 1]]);
        BuildSummary.BytesRead = 0;
        var b = BuildSummary.Inspect(AotSample("Large", bytes), false, default).Backend;
        Assert.Null(b.MetadataCounts!.Images);
        Assert.Contains("over the 1,048,576-byte limit", b.MetadataCounts.Reason);
        Assert.True(BuildSummary.BytesRead < AotMetadataCounts.MaxImagesTable, $"{BuildSummary.BytesRead} bytes read");
    }

    [Fact]
    [FuzzEntry(typeof(AotMetadataCounts))]
    public void Fuzzed_metadata_headers_never_throw_while_counting()
    {
        var failures = FormatFuzz.Run(LayoutMetadata(SizesOf("v29", 29)), b => AotMetadataCounts.Read(b,
            (offset, count) => offset < 0 || offset >= b.Length ? [] : b.AsSpan((int)offset, (int)Math.Min(count, b.Length - offset)).ToArray()), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void Encrypted_metadata_is_not_counted()
    {
        var b = BuildSummary.Inspect(AotSample("Encrypted counts", [0x12, 0x34, 0x56, 0x78, .. new byte[200]]), false, default).Backend;
        Assert.Equal("encrypted", b.MetadataState);
        Assert.Null(b.MetadataCounts);
    }

    internal static byte[] SerializedHeader(int format, string version)
    {
        var bytes = new byte[(format >= 22 ? 48 : 20) + version.Length + 1 + 16];
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), (uint)format);
        Encoding.ASCII.GetBytes(version).CopyTo(bytes, format >= 22 ? 48 : 20);
        return bytes;
    }

    /// <summary>A metadata header (0x100 bytes of offset / size pairs) whose string heap holds <paramref name="names"/>.</summary>
    internal static byte[] Metadata(int version, string[] names)
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

/// <summary>summarize_build over CORVUS_ASSET_BUILDS; each summary finishes in seconds.</summary>
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
public sealed class BuildSummaryRealTests(ITestOutputHelper output)
{
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Real_builds_are_summarized_in_seconds()
    {
        var builds = Builds().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (builds.Count == 0) { output.WriteLine("No builds (CORVUS_ASSET_BUILDS)."); return; }
        int found = 0;
        var total = Stopwatch.StartNew();
        foreach (var build in builds)
        {
            BuildSummary.BytesRead = 0;
            var watch = Stopwatch.StartNew();
            BuildSummary.Report r;
            try { r = BuildSummary.Inspect(build, Environment.GetEnvironmentVariable("CORVUS_DIE") != null, default); }
            catch (ToolError e) when (e.Code == ErrorCode.Unsupported) { continue; }
            watch.Stop();
            found++;
            output.WriteLine($"{Path.GetFileName(build)}: {watch.Elapsed.TotalSeconds:0.00} s | engine {r.Engine.Version} ({r.Engine.Agreement}; " +
                             $"{string.Join(", ", r.Engine.Claims.Select(c => $"{c.Source}={c.Normalized}"))}) | {r.Backend.Kind} {r.Platform}/{r.Architecture}" +
                             (r.Backend.Kind == "aot" ? $" | metadata v{r.Backend.MetadataVersion} {r.Backend.MetadataState} range {r.Engine.MetadataRange} {r.Engine.MetadataCheck}" : "") +
                             (r.Backend.Kind == "mono" ? $" | {r.Backend.MonoRuntime}; {r.Backend.DotnetProfile}; {r.Backend.ManagedAssemblies} DLLs {r.Backend.ManagedState}" : "") +
                             (r.Backend.UnreadableNameRatio is { } q ? $" | unreadable names {q:P1} of {r.Backend.NamesRead}" : ""));
            // File heads, the string heap capped at 16 MiB, the images table capped at 1 MiB and two JSON lists of at most 4 MiB:
            // never a whole binary or data file.
            Assert.InRange(BuildSummary.BytesRead, 1, 25L << 20);
            if (r.Backend.MetadataCounts is { Images: { } images } counts && r.Engine.Version != null)
                lock (AotMetadataReader.Gate)
                {
                    var meta = Il2CppMetadata.ReadFrom(File.ReadAllBytes(r.Backend.Metadata!), UnityVersion.Parse(r.Engine.Version));
                    Assert.Equal((meta.imageDefinitions.Length, meta.typeDefs.Length, (int?)meta.methodDefs.Length),
                        (images, counts.Types!.Value, counts.Methods));
                }
            if (r.Backend.MetadataCounts is { } read)
                output.WriteLine($"    metadata counts: {read.Images} images, {read.Types} types, {read.Methods} methods ({read.Layout}){(read.Reason is { } why ? "; " + why : "")}");
            output.WriteLine($"    markers: {string.Join("; ", r.Markers.Select(m => $"{m.Category}:{m.Name}"))}");
            output.WriteLine($"    next: {string.Join(" -> ", r.NextSteps.Select(s => s.Action + (s.Arguments.TryGetValue("path", out var p) ? $"({p})" : "")))}");
            foreach (var note in r.Notes) output.WriteLine($"    note: {note}");
            if (r.Markers.Any(m => m.Source == "detect_it_easy")) PerfBudget.Time("containers/build-summary-with-die", watch.Elapsed, TimeSpan.FromSeconds(30), output);
            else PerfBudget.Time("containers/build-summary", watch.Elapsed, TimeSpan.FromSeconds(10), output);
            Assert.NotEqual("unknown", r.Backend.Kind);
            Assert.NotNull(r.Engine.Version);
            Assert.NotEmpty(r.NextSteps);
        }
        output.WriteLine($"{found} build(s) of {builds.Count} folders, {total.Elapsed.TotalSeconds:0.0} s");
    }

    /// <summary>The summarize_build tool on each build: a build's report within the report budget per part, with its runtime version, backend and next steps.</summary>
    [Fact, Trait("Data", "Real")]
    public async Task Summarize_build_reports_each_build()
    {
        var builds = Builds().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (builds.Count == 0) { output.WriteLine("No builds (CORVUS_ASSET_BUILDS)."); return; }
        await using var server = await InProcessServer.StartAsync();
        int found = 0;
        foreach (var build in builds)
        {
            var r = await server.Client.CallToolAsync("summarize_build", new Dictionary<string, object?> { ["path"] = build });
            var text = string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
            if (r.IsError == true) { Assert.Contains("not_a_build", text); continue; }
            found++;
            var record = r.StructuredContent!.Value;
            int budget = Corvus.Mcp.OutputClasses.Budget(Corvus.Mcp.ToolContract.Of("summarize_build").Output) * 105 / 100;
            output.WriteLine($"{Path.GetFileName(build)}: text {TokenEstimate.Of(text)}, record {TokenEstimate.Of(record.GetRawText())} tokens");
            Assert.True(TokenEstimate.Of(text) <= budget && TokenEstimate.Of(record.GetRawText()) <= budget, build);
            Assert.False(string.IsNullOrEmpty(record.GetProperty("engine").GetProperty("version").GetString()));
            Assert.Contains(record.GetProperty("backend").GetProperty("kind").GetString(), new[] { "mono", "aot" });
            Assert.True(record.GetProperty("nextSteps").GetArrayLength() > 0);
        }
        output.WriteLine($"{found} build(s) of {builds.Count} folders");
    }

    private static IEnumerable<string> Builds()
    {
        if (Environment.GetEnvironmentVariable("CORVUS_ASSET_BUILDS") is { Length: > 0 } list)
            foreach (var t in list.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                if (Directory.Exists(t) || File.Exists(t)) yield return t;
    }
}
