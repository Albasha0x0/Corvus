using System.IO.Compression;
using Corvus.Core;
using Corvus.Core.Unity;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>
/// extract_strings over Unity serialized files, bundles, build folders and packages the tests write: MonoBehaviour
/// string fields classified as code strings are, located by file, asset and field, with unread layouts counted.
/// </summary>
public sealed class UnityAssetStringsTests : IDisposable
{
    private const long ScriptPath = 2, HolderPath = 10;
    // Reserved documentation names and addresses (RFC 2606, RFC 5737).
    internal const string Url = "https://cfg.example.com/api/v2/poll", Ip = "203.0.113.7", Mirror = "https://m1.example.net/a", MirrorIp = "198.51.100.20";
    internal static readonly string Blob = Key(1);

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>The base64 of 32 bytes counting up from <paramref name="first"/>.</summary>
    private static string Key(int first) => Convert.ToBase64String([.. Enumerable.Range(first, 32).Select(i => (byte)i)]);

    private static IEnumerable<TreeNode> Text(int level, string name) =>
        [new(level, "string", name, -1), new(level + 1, "Array", "Array", -1, 0x4000, true), new(level + 2, "int", "size", 4), new(level + 2, "char", "data", 1)];

    private static List<TreeNode> Base() =>
    [
        new(0, "MonoBehaviour", "Base", -1),
        new(1, "PPtr<GameObject>", "m_GameObject", 12), new(2, "int", "m_FileID", 4), new(2, "SInt64", "m_PathID", 8),
        new(1, "UInt8", "m_Enabled", 1, 0x4000),
        new(1, "PPtr<MonoScript>", "m_Script", 12), new(2, "int", "m_FileID", 4), new(2, "SInt64", "m_PathID", 8),
        .. Text(1, "m_Name"),
    ];

    /// <summary>The type tree of Net.Config: url, host, blob, assetGuid, label and a List&lt;string&gt; mirrors.</summary>
    private static List<TreeNode> ConfigTree() =>
    [
        .. Base(), .. Text(1, "url"), .. Text(1, "host"), .. Text(1, "blob"), .. Text(1, "assetGuid"), .. Text(1, "label"),
        new(1, "vector", "mirrors", -1), new(2, "Array", "Array", -1, 0x4000, true), new(3, "int", "size", 4), .. Text(3, "data"),
    ];

    private static List<TreeNode> ScriptTree() =>
        [new(0, "MonoScript", "Base", -1), .. Text(1, "m_Name"), new(1, "int", "m_ExecutionOrder", 4), new(1, "Hash128", "m_PropertiesHash", 16),
         .. Text(1, "m_ClassName"), .. Text(1, "m_Namespace"), .. Text(1, "m_AssemblyName")];

    private static byte[] ConfigData(string[] mirrors)
    {
        var d = new UnityFileWriter.Data().Pointer(0, 0).U8(1).Align().Pointer(0, ScriptPath).String("Endpoints")
            .String(Url).String(Ip).String(Blob).String("0123456789abcdef0123456789abcdef").String("PlayerController2D").I32(mirrors.Length);
        foreach (var m in mirrors) d.String(m);
        return d.ToArray();
    }

    private static byte[] Script(string ns, string name) =>
        new UnityFileWriter.Data().String(name).I32(0).Zero(16).String(name).String(ns).String("Assembly-CSharp.dll").ToArray();

    /// <summary>A serialized file with the Net.Config asset (or the class <paramref name="script"/> names) and its MonoScript, with or without type trees.</summary>
    internal static byte[] ConfigFile(bool typeTrees = true, string[]? mirrors = null, (string Namespace, string Name)? script = null)
    {
        var w = new UnityFileWriter(22, typeTrees);
        w.Types.Add(new(SerializedFile.ClassMonoBehaviour, 0, typeTrees ? ConfigTree() : null));
        w.Types.Add(new(SerializedFile.ClassMonoScript, -1, typeTrees ? ScriptTree() : null));
        w.Objects.Add((ScriptPath, 1, Script(script?.Namespace ?? "Net", script?.Name ?? "Config")));
        w.Objects.Add((HolderPath, 0, ConfigData(mirrors ?? [Mirror, MirrorIp + ":8443"])));
        return w.Build();
    }

    /// <summary>A serialized file without type trees holding one TextAsset per name and script bytes.</summary>
    private static byte[] TextAssetFile(params (string Name, byte[] Script)[] assets)
    {
        var w = new UnityFileWriter(22, typeTrees: false);
        w.Types.Add(new(SerializedFile.ClassTextAsset, -1, null));
        long id = 1;
        foreach (var (name, script) in assets) w.Objects.Add((id++, 0, new UnityFileWriter.Data().String(name).I32(script.Length).Bytes(script).Align().ToArray()));
        return w.Build();
    }

    private string Write(string relative, byte[] bytes)
    {
        var path = Path.Combine(_dir.Path, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static InspectionService.ValueReport Strings(string path, InspectionService.AssetReadLimits? limits = null) =>
        new InspectionService(new AssemblyWorkspace()).ExtractStrings(null, path, null, default, limits);

    private static ExtractedValue Row(InspectionService.ValueReport report, string type, string value) =>
        Assert.Single(report.Values, v => v.Type == type && v.Value == value);

    [Fact]
    public void Asset_string_fields_give_typed_values_located_by_file_asset_and_field()
    {
        var report = Strings(Write("App_Data/sharedassets0.assets", ConfigFile()));
        Assert.Equal(["sharedassets0.assets: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
        Assert.Equal(["sharedassets0.assets: Endpoints (Script: Net.Config).host"], Row(report, "ipv4", Ip).Locations);
        Assert.Contains("sharedassets0.assets: Endpoints (Script: Net.Config).url", Row(report, "domain", "cfg.example.com").Locations);
        Assert.Null(report.Partial);
    }

    [Fact]
    public void A_list_of_strings_locates_each_element_by_index()
    {
        var report = Strings(Write("App_Data/level0", ConfigFile()));
        Assert.Equal(["level0: Endpoints (Script: Net.Config).mirrors[0]"], Row(report, "url", Mirror).Locations);
        Assert.Equal(["level0: Endpoints (Script: Net.Config).mirrors[1]"], Row(report, "ipv4", MirrorIp).Locations);
    }

    [Fact]
    public void A_base64_field_is_an_encoded_value_with_its_length_and_nothing_decoded()
    {
        var row = Row(Strings(Write("App_Data/level0", ConfigFile())), "encoded", Blob);
        Assert.Equal("base64, 32 bytes", row.Detail);
        Assert.Equal(["level0: Endpoints (Script: Net.Config).blob"], row.Locations);
    }

    [Fact]
    public void An_identifier_and_an_asset_guid_are_not_encoded_values()
    {
        var encoded = Strings(Write("App_Data/level0", ConfigFile())).Values.Where(v => v.Type == "encoded").Select(v => v.Value);
        Assert.Equal([Blob], encoded);
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef", "hex, 16 bytes")]
    [InlineData("QUJDREVGR0hJSktMTU5PUFFSU1RVVldY", "base64, 24 bytes")]
    [InlineData("PlayerController2DSpawner", null)]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef", null)]
    [InlineData("aGVsbG8gd29ybGQ=", null)]
    public void Only_a_whole_long_hex_or_base64_value_is_encoded(string text, string? detail)
    {
        var row = Values.FromFields([(text, "Holder.value")], out _, default).SingleOrDefault(v => v.Type == "encoded");
        Assert.Equal(detail, row?.Detail);
    }

    [Fact]
    public void Encoded_values_past_the_cap_of_a_file_are_counted_not_listed()
    {
        var mirrors = Enumerable.Range(0, Values.MaxEncoded + 5).Select(i => Key(i + 40)).ToArray();
        var report = Strings(Write("App_Data/level0", ConfigFile(mirrors: mirrors)));
        Assert.Equal(Values.MaxEncoded, report.Values.Count(v => v.Type == "encoded"));
        Assert.Contains("encoded values past 100 per file are not listed", report.Partial);
        Assert.Contains(report.Notes, n => n.StartsWith("level0: ", StringComparison.Ordinal) && n.Contains("encoded values past the first 100"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void A_bundle_entry_is_located_under_the_bundle(int codec)
    {
        var report = Strings(Write("cfg.bundle", UnityFileWriter.Bundle(codec, ("CAB-0a1b2c", ConfigFile()))));
        Assert.Equal(["cfg.bundle/CAB-0a1b2c: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
    }

    [Fact]
    public void An_asset_whose_layout_does_not_read_is_counted_unknown_and_makes_the_result_partial()
    {
        // No type trees and no Managed folder: the script's layout is unknown.
        var report = Strings(Write("App_Data/level0", ConfigFile(typeTrees: false)));
        Assert.DoesNotContain(report.Values, v => v.Type == "url");
        Assert.Contains("1 of 1 MonoBehaviour assets are partial or unknown", report.Partial);
        Assert.Contains("no assembly for Net.Config", report.Partial);
        Assert.Equal(["assets"], report.PartialIn);
    }

    [Fact]
    public void An_il2cpp_build_without_its_binary_names_why_its_scripts_stay_unknown()
    {
        Write("App/App_Data/level0", ConfigFile(typeTrees: false));
        Write("App/App_Data/il2cpp_data/Metadata/global-metadata.dat", new Il2CppMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Build());
        var report = Strings(Path.Combine(_dir.Path, "App"));
        Assert.Contains(report.Notes, n => n.Contains("field types are in the Il2Cpp binary, which is not beside the metadata", StringComparison.Ordinal));
        Assert.Contains("1 of 1 MonoBehaviour assets are partial or unknown", report.Partial);
    }

    [Fact]
    public void A_field_typed_in_the_unread_Il2Cpp_binary_is_unknown_not_skipped()
    {
        // A read of the metadata alone in a cache of the test's own: every dummy field has the placeholder type.
        Write("App/App_Data/level0", ConfigFile(typeTrees: false, script: ("", "Program")));
        var metadata = Write("App/App_Data/il2cpp_data/Metadata/global-metadata.dat", new Il2CppMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Field("url").Build());
        var cache = Path.Combine(_dir.Path, "il2cpp-cache");
        using (var workspace = new AssemblyWorkspace())
            new Il2CppRawLoader(workspace, cache).Load(Il2CppBuildFiles.Find(metadata, metadataOnly: true)!, loadBinary: false, null, default);
        var report = Strings(Path.Combine(_dir.Path, "App"), new InspectionService.AssetReadLimits(UnityAssetStrings.MaxBytes, Il2CppCache: cache));
        Assert.DoesNotContain(report.Values, v => v.Type == "url");
        Assert.Contains("a field whose type is in the Il2Cpp binary, which was not read", report.Partial);
        Assert.DoesNotContain(report.Notes, n => n.StartsWith("Il2Cpp build not read", StringComparison.Ordinal));
    }

    [Fact]
    public void A_json_text_asset_gives_its_values_located_by_file_and_asset()
    {
        var json = $$"""{"api": {"url": "{{Url}}", "hosts": ["{{Ip}}"]}, "key": "{{Blob}}", "retries": 3}""";
        var report = Strings(Write("App_Data/resources.assets", TextAssetFile(("ServerConfig", System.Text.Encoding.UTF8.GetBytes(json)))));
        Assert.Equal(["resources.assets: ServerConfig (TextAsset)"], Row(report, "url", Url).Locations);
        Assert.Equal(["resources.assets: ServerConfig (TextAsset)"], Row(report, "ipv4", Ip).Locations);
        Assert.Equal("base64, 32 bytes", Row(report, "encoded", Blob).Detail);
        Assert.Contains("TextAssets: 1 json read as config.", report.Notes[0]);
        Assert.Null(report.Partial);
    }

    [Fact]
    public void Xml_and_ini_text_assets_are_read_and_other_text_is_counted_not_read()
    {
        var report = Strings(Write("App_Data/resources.assets", TextAssetFile(
            ("Hosts", System.Text.Encoding.UTF8.GetBytes($"""<?xml version="1.0"?><cfg><server host="{MirrorIp}"/><mirror>{Mirror}</mirror></cfg>""")),
            ("Mirrors", System.Text.Encoding.UTF8.GetBytes($"; mirrors\n[net]\nmirror = \"{Mirror}\"\n")),
            ("Story", "Visit https://notes.example.org for the full text."u8.ToArray()),
            ("Mesh", [0x00, 0x01, 0x02, 0x03]))));
        Assert.Equal(["resources.assets: Hosts (TextAsset)"], Row(report, "ipv4", MirrorIp).Locations);
        Assert.Equal(["resources.assets: Hosts (TextAsset)", "resources.assets: Mirrors (TextAsset)"], Row(report, "url", Mirror).Locations);
        Assert.DoesNotContain(report.Values, v => v.Value == "https://notes.example.org");
        Assert.Contains("TextAssets: 1 xml, 1 ini read as config; 2 other text or binary not read.", report.Notes[0]);
    }

    [Fact]
    [FuzzEntry(typeof(ConfigText))]
    public void Fuzzed_config_text_never_throws()
    {
        string[] seeds =
        [
            $$"""{"api": {"url": "{{Url}}", "hosts": ["{{Ip}}", 3, null]}, "key": "{{Blob}}"}""",
            $"""<?xml version="1.0"?><cfg a="{Ip}"><m><![CDATA[{Mirror}]]></m></cfg>""",
            $"; c\n[net]\nurl = '{Url}'\nhost=\"{Ip}\"\n",
        ];
        foreach (var seed in seeds)
        {
            var failures = FormatFuzz.Run(System.Text.Encoding.UTF8.GetBytes(seed), b => ConfigText.Read(b), 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    [Fact]
    public void A_text_asset_that_does_not_read_makes_the_result_partial()
    {
        var w = new UnityFileWriter(22, typeTrees: false);
        w.Types.Add(new(SerializedFile.ClassTextAsset, -1, null));
        // The script claims more bytes than the object holds.
        w.Objects.Add((1, 0, new UnityFileWriter.Data().String("Cut").I32(1_000).Bytes("{}"u8.ToArray()).Align().ToArray()));
        var report = Strings(Write("App_Data/resources.assets", w.Build()));
        Assert.Contains("1 TextAssets do not read", report.Partial);
        Assert.Equal(["assets"], report.PartialIn);
    }

    /// <summary>The self-built Il2Cpp build with its binary, read into a cache of the test's own.</summary>
    [RequiresRealDataFact("CORVUS_IL2CPP_BUILD")]
    [Trait("Speed", "Slow")]
    public void A_real_il2cpp_build_lays_out_its_scripts_without_an_earlier_load()
    {
        var build = RealData.Path("CORVUS_IL2CPP_BUILD");
        var cache = Path.Combine(_dir.Path, "il2cpp-cache");
        var report = Strings(build, new InspectionService.AssetReadLimits(UnityAssetStrings.MaxBytes, Il2CppCache: cache));
        Assert.Contains(report.Notes, n => n.StartsWith("Il2Cpp build read for the script layouts", StringComparison.Ordinal));
        Assert.NotNull(Il2CppRawLoader.CachedDummies(Il2CppBuildFiles.Find(build)!, cache));
        Assert.Contains(report.Notes, n => System.Text.RegularExpressions.Regex.IsMatch(n, @"MonoBehaviour assets, [1-9][\d,]* read"));
        Assert.DoesNotContain("in the Il2Cpp binary", report.Partial ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void A_build_folder_reads_its_data_folder_and_streaming_assets()
    {
        Write("App/App_Data/level0", ConfigFile());
        Write("App/App_Data/StreamingAssets/aa/cfg.bundle", UnityFileWriter.Bundle(2, ("CAB-1", ConfigFile())));
        var url = Row(Strings(Path.Combine(_dir.Path, "App")), "url", Url);
        Assert.Equal(["level0: Endpoints (Script: Net.Config).url", "StreamingAssets/aa/cfg.bundle/CAB-1: Endpoints (Script: Net.Config).url"], url.Locations);
        Assert.Equal(2, url.Count);
    }

    [Fact]
    public void A_changed_asset_file_in_a_subfolder_is_read_again_not_reused()
    {
        Write("App/App_Data/level0", ConfigFile());
        var bundle = Write("App/App_Data/StreamingAssets/aa/cfg.bundle", UnityFileWriter.Bundle(2, ("CAB-1", ConfigFile())));
        var folder = Path.Combine(_dir.Path, "App");
        Assert.DoesNotContain(Strings(folder).Values, v => v.Value == "https://m2.example.net/b");
        // The rewrite leaves the build folder's own write time as it was.
        var folderTime = Directory.GetLastWriteTimeUtc(folder);
        File.WriteAllBytes(bundle, UnityFileWriter.Bundle(2, ("CAB-1", ConfigFile(mirrors: ["https://m2.example.net/b"]))));
        Directory.SetLastWriteTimeUtc(folder, folderTime);
        Assert.Equal(["StreamingAssets/aa/cfg.bundle/CAB-1: Endpoints (Script: Net.Config).mirrors[0]"], Row(Strings(folder), "url", "https://m2.example.net/b").Locations);
    }

    [Fact]
    public void A_mono_build_joins_its_script_assembly_strings_with_its_asset_strings()
    {
        Write("App/App_Data/level0", ConfigFile());
        Write("App/App_Data/Managed/Assembly-CSharp.dll", Roslyn.Release("Assembly-CSharp", """public static class C { public static string U() => "https://api.example.org/v1"; }"""));
        var report = Strings(Path.Combine(_dir.Path, "App"));
        Assert.StartsWith("Managed/Assembly-CSharp.dll: ", Row(report, "url", "https://api.example.org/v1").Locations[0]);
        Assert.Equal(["level0: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
    }

    [Fact]
    public void A_folder_without_a_unity_build_is_refused_as_not_a_unity_build()
    {
        Write("plain/notes.txt", "text"u8.ToArray());
        var e = Assert.Throws<ToolError>(() => Strings(Path.Combine(_dir.Path, "plain")));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("not_a_unity_build", e.Message);
    }

    [Fact]
    public void A_zipped_desktop_build_reads_its_assets_in_place()
    {
        var zip = Path.Combine(_dir.Path, "app.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            foreach (var (name, bytes) in new[] { ("App/App_Data/globalgamemanagers", new UnityFileWriter(22, true).Build()), ("App/App_Data/sharedassets0.assets", ConfigFile()) })
                using (var stream = archive.CreateEntry(name).Open()) stream.Write(bytes);
        var report = Strings(zip);
        Assert.Equal(["sharedassets0.assets: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
    }

    [Fact]
    public void An_android_package_reads_the_assets_under_bin_Data()
    {
        var apk = Path.Combine(_dir.Path, "app.apk");
        using (var archive = ZipFile.Open(apk, ZipArchiveMode.Create))
            foreach (var (name, bytes) in new[] { ("assets/bin/Data/level0", ConfigFile()), ("AndroidManifest.xml", new byte[8]) })
                using (var stream = archive.CreateEntry(name).Open()) stream.Write(bytes);
        var report = Strings(apk);
        Assert.Equal(["level0: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
    }

    [Fact]
    public void A_split_asset_file_is_read_as_one()
    {
        var bytes = ConfigFile();
        Write("App_Data/level0.split0", bytes[..(bytes.Length / 2)]);
        Write("App_Data/level0.split1", bytes[(bytes.Length / 2)..]);
        Write("App_Data/globalgamemanagers", new UnityFileWriter(22, true).Build());
        var report = Strings(Path.Combine(_dir.Path, "App_Data"));
        Assert.Equal(["level0: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
    }

    [Fact]
    public void A_byte_limit_keeps_the_rows_of_the_files_read_and_names_the_rest()
    {
        var first = Write("App/App_Data/level0", ConfigFile());
        Write("App/App_Data/level1", ConfigFile(mirrors: ["https://later.example.net/b"]));
        var report = Strings(Path.Combine(_dir.Path, "App"), new(new FileInfo(first).Length));
        Assert.Equal(["level0: Endpoints (Script: Net.Config).url"], Row(report, "url", Url).Locations);
        Assert.DoesNotContain(report.Values, v => v.Value == "https://later.example.net/b");
        Assert.Contains("level1 and 0 later files are not", report.Partial);
    }

    [Fact]
    public void A_time_limit_that_has_passed_reads_nothing_and_says_so()
    {
        Write("App/App_Data/level0", ConfigFile());
        var report = Strings(Path.Combine(_dir.Path, "App"), new(UnityAssetStrings.MaxBytes, TimeSpan.Zero));
        Assert.Empty(report.Values);
        Assert.Contains("the time limit ended the read after 0 of 1 asset files", report.Partial);
    }
}
