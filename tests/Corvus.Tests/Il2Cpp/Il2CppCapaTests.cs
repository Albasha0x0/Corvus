using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// capa's view of Il2Cpp code on a built game binary: x64 functions that call methods named as the class library's
/// file write, registry read and HTTP request methods, whose own bodies are a bare ret.
/// </summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class Il2CppCapaTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>The script.json methods of the game: RVA and Il2CppDumper name; two methods share the code at 0x1340.</summary>
    internal static readonly (uint Rva, string Name)[] Methods =
    [
        (0x1000, "Game.Saver$$Save"),
        (0x1040, "Game.Settings$$Load"),
        (0x1080, "Game.Updater$$Check"),
        (0x1100, "System.IO.File$$WriteAllText"),
        (0x1200, "Microsoft.Win32.Registry$$get_CurrentUser"),
        (0x1240, "Microsoft.Win32.RegistryKey$$GetValue"),
        (0x1300, "System.Net.Http.HttpClient$$GetAsync"),
        (0x1340, "Game.Folded$$First"),
        (0x1340, "Game.Folded$$Second"),
    ];

    /// <summary>The .text section (RVA 0x1000) of the game binary: each caller's calls, then ret; every callee a bare ret.</summary>
    internal static byte[] Text()
    {
        var code = new byte[0x400];
        Array.Fill(code, (byte)0xCC);
        void Calls(uint at, params uint[] targets)
        {
            int p = (int)(at - 0x1000);
            foreach (var target in targets)
            {
                code[p] = 0xE8;
                BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(p + 1), (int)(target - (at + 5)));
                at += 5;
                p += 5;
            }
            code[p] = 0xC3;
        }
        Calls(0x1000, 0x1100, 0x1340);
        Calls(0x1040, 0x1200, 0x1240);
        Calls(0x1080, 0x1300);
        foreach (var rva in new uint[] { 0x1100, 0x1200, 0x1240, 0x1300, 0x1340 }) code[rva - 0x1000] = 0xC3;
        return code;
    }

    internal static byte[] GameAssembly() => Il2CppStringTests.Pe64([(".text", 0x1000, Text(), 0x60000020), (".data", 0x5000, new byte[0x100], 0xC0000040)]);

    private static IReadOnlyList<Il2CppCallee> Names(uint rva) =>
        [.. Methods.Where(m => m.Rva == rva).Select(m => m.Name.Split("$$")).Select(p => Il2CppCapa.FromScriptName(p[0], p[1])!)];

    private (INativeImage Image, Il2CppCodeFeatures Features, string Path) Read()
    {
        var path = _dir.File("GameAssembly.dll");
        File.WriteAllBytes(path, GameAssembly());
        var image = NativeImageLoader.Open(path);
        return (image, Il2CppCapa.Read(image, [.. Methods.Select(m => m.Rva)], Names, null, default), path);
    }

    [Fact]
    public void Direct_calls_are_named_in_dotnet_form_and_code_shared_by_two_methods_is_left_out()
    {
        var (_, features, _) = Read();
        Assert.Equal((8, 5, 1, 0), (features.FunctionsRead, features.Calls, features.Ambiguous, features.Unnamed));
        Assert.Equal([(0x1000u, "System.IO.File::WriteAllText"), (0x1040u, "Microsoft.Win32.Registry::get_CurrentUser"),
            (0x1040u, "Microsoft.Win32.RegistryKey::GetValue"), (0x1080u, "System.Net.Http.HttpClient::GetAsync")],
            features.Functions.SelectMany(f => f.Calls.Select(c => (f.Rva, c.Callee.Api))));
        Assert.Equal([0x1040u, 0x1045u], features.Functions[1].Calls.Select(c => c.Site));
        Assert.Equal(0x1100u, features.Functions[0].Calls[0].Target);
    }

    [Fact]
    public void Generic_and_nested_names_take_the_form_capa_gives_them()
    {
        Assert.Equal(new Il2CppCallee("System.Collections.Generic", "Dictionary`2", "Add"),
            Il2CppCapa.FromScriptName("System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<int>>", "Add"));
        Assert.Equal(new Il2CppCallee("", "Global", ".ctor"), Il2CppCapa.FromScriptName("Global", ".ctor"));
        Assert.Null(Il2CppCapa.FromScriptName("Game.Saver", ""));
    }

    [Fact]
    public void The_freeze_file_is_capas_version_3_with_dotnet_features_at_each_call()
    {
        var (image, features, path) = Read();
        var freeze = Il2CppCapa.Freeze(image, features, path);
        Assert.Equal("capa0000"u8.ToArray(), freeze[..8]);
        using var z = new ZLibStream(new MemoryStream(freeze, 8, freeze.Length - 8), CompressionMode.Decompress);
        using var doc = JsonDocument.Parse(z);
        var root = doc.RootElement;
        Assert.Equal((3, "static"), (root.GetProperty("version").GetInt32(), root.GetProperty("flavor").GetString()));
        Assert.Equal(["format=dotnet", "os=windows", "arch=amd64"], root.GetProperty("features").GetProperty("global").EnumerateArray()
            .Select(g => g.GetProperty("feature")).Select(f => $"{f.GetProperty("type").GetString()}={f.GetProperty(f.GetProperty("type").GetString()!).GetString()}"));
        var settings = root.GetProperty("features").GetProperty("functions")[1];
        Assert.Equal(0x180001040UL, settings.GetProperty("address").GetProperty("value").GetUInt64());
        var first = settings.GetProperty("basic blocks")[0].GetProperty("instructions")[0];
        Assert.Equal(0x180001040UL, first.GetProperty("address").GetProperty("value").GetUInt64());
        // An accessor is a property read, as capa reports a call through a property.
        Assert.Equal(["property Microsoft.Win32.Registry::CurrentUser read", "property Microsoft.Win32.Registry::CurrentUser", "class Microsoft.Win32.Registry",
            "namespace Microsoft.Win32"], first.GetProperty("features").EnumerateArray().Select(e => e.GetProperty("feature"))
            .Select(f => $"{f.GetProperty("type").GetString()} {f.GetProperty(f.GetProperty("type").GetString()!).GetString()}"
                         + (f.TryGetProperty("access", out var a) ? $" {a.GetString()}" : "")));
    }

    [Fact]
    public void Rules_matched_only_at_no_address_are_left_out_of_capas_result()
    {
        const string result = """
            {"meta":{},"rules":{
              "write file in .NET":{"meta":{"name":"write file in .NET","namespace":"host-interaction/file-system/write"},
                "matches":[[{"type":"absolute","value":6442455040},{}]]},
              "compiled to the .NET platform":{"meta":{"name":"compiled to the .NET platform","namespace":"runtime/dotnet"},
                "matches":[[{"type":"no address"},{}]]}}}
            """;
        var run = new ExternalTools.RunResult(0, Encoding.UTF8.GetBytes(result), "", false, false, null);
        var read = Il2CppCapa.Read(run, "capa 10.0.0", tested: true);
        Assert.Equal(("matched", null), (read.State, read.Note));
        var rule = Assert.Single(read.Rules);
        Assert.Equal(("write file in .NET", "host-interaction/file-system/write", 0x180001000UL), (rule.Name, rule.Namespace, Assert.Single(rule.Addresses)));
    }

    [Fact]
    public void A_refused_freeze_file_is_unknown_with_capas_message_and_the_tested_version()
    {
        var run = new ExternalTools.RunResult(1, [], "ERROR: unsupported freeze format version: 3\n", false, false, null);
        var read = Il2CppCapa.Read(run, "capa 11.0.0", tested: false);
        Assert.Equal("unknown", read.State);
        Assert.Contains("exit 1: ERROR: unsupported freeze format version: 3", read.Note);
        Assert.Contains("tested with capa 10.0.0", read.Note);
    }

    [Fact]
    public void Capa_not_found_is_reported_unavailable_with_the_variable_to_set()
    {
        using var env = new EnvironmentScope().Set("CORVUS_CAPA", Path.Combine(Path.GetTempPath(), "no-capa", "capa.exe"));
        var result = Il2CppCapa.Match([], default);
        Assert.Equal("unavailable", result.State);
        Assert.Contains("CORVUS_CAPA", result.Note);
    }

    /// <summary>A real capa 10.0.0 named by CORVUS_CAPA reads the freeze file and matches its .NET rules at the callers.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void Capa_matches_its_dotnet_rules_at_the_functions_that_make_the_calls()
    {
        if (Environment.GetEnvironmentVariable(ExternalTools.Capa.Variable) is not { Length: > 0 }) return;
        var (image, features, path) = Read();
        var result = Il2CppCapa.Match(Il2CppCapa.Freeze(image, features, path), default);
        output.WriteLine($"{result.Checker}: {string.Join("; ", result.Rules.Select(r => $"{r.Name} at {string.Join(",", r.Addresses.Select(a => $"0x{a:X}"))}"))}");
        Assert.True(result.State == "matched", result.Note);
        Assert.True(result.Tested, $"{result.Checker} is not the tested capa {Il2CppCapa.TestedVersion}");
        var at = result.Rules.ToDictionary(r => r.Name, r => r.Addresses);
        Assert.Equal([0x180001000UL], at["write file in .NET"]);
        Assert.Equal([0x180001040UL], at["query or enumerate registry value"]);
        Assert.Equal([0x180001080UL], at["send HTTP request"]);
        Assert.DoesNotContain("compiled to the .NET platform", at.Keys);
    }
}
