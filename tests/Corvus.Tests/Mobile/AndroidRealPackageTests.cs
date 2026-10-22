using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// The DEX and bridge tools over MCP on real Android code from NuGet: mono.android.dex and mono.android.jar (Java callable wrappers),
/// Mono.Android.dll and libmono-android.release.so, packed as an APK beside a synthetic manifest.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("reference-tool")]
public sealed class AndroidRealPackageTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private const string Ref = "Microsoft.Android.Ref.35", Runtime = "Microsoft.Android.Runtime.35.android-arm64", Version = "35.0.105";
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] RefFile(string name) => File.ReadAllBytes(RealPackages.File(Ref, Version, "ref", "net9.0", name));

    private string Apk() => AndroidSamples.Save(_dir, "mono.apk", AndroidSamples.Apk(30, ("classes.dex", RefFile("mono.android.dex")),
        ("assemblies/Mono.Android.dll", RefFile("Mono.Android.dll")),
        ("lib/arm64-v8a/libmono-android.release.so", File.ReadAllBytes(RealPackages.File(Runtime, Version, "runtimes", "android-arm64", "native", "libmono-android.release.so")))));

    private async Task<(string Text, JsonElement Record)> Call(McpClient client, string tool, Dictionary<string, object?> args)
    {
        var r = await client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool}: {text.Length} chars\n{string.Join("\n", text.Split('\n').Take(4))}");
        Assert.True(r.IsError != true, text);
        return (text, r.StructuredContent!.Value);
    }

    [Fact]
    public async Task DexAndBridgeTools()
    {
        var apk = Apk();
        await using var server = await InProcessServer.StartAsync();
        var c = server.Client;
        var (_, classes) = await Call(c, "list_dex_classes", new() { ["path"] = apk });
        Assert.True(classes.GetProperty("total").GetInt32() > 300);
        var (_, walk) = await Call(c, "list_dex_classes", new() { ["path"] = apk, ["offset"] = classes.GetProperty("nextOffset").GetInt32() });
        Assert.Equal(classes.GetProperty("total").GetInt32(), walk.GetProperty("total").GetInt32());

        var (_, cls) = await Call(c, "get_dex_class", new() { ["path"] = apk, ["class"] = "android.app.ActivityTracker", ["members"] = "methods" });
        Assert.Contains(cls.GetProperty("items").EnumerateArray(), m => m.GetProperty("id").GetString()!.Contains("->n_onActivityCreated(", StringComparison.Ordinal));

        var (smali, _) = await Call(c, "disassemble_dex", new() { ["path"] = apk, ["symbol"] = "android.app.ActivityTracker" });
        Assert.StartsWith("# Landroid/app/ActivityTracker; in classes.dex:", smali);
        var (_, hits) = await Call(c, "search_dex", new() { ["path"] = apk, ["kind"] = "method", ["query"] = "n_*" });
        Assert.True(hits.GetProperty("total").GetInt32() > 100);
        var (_, refs) = await Call(c, "find_dex_references", new() { ["path"] = apk, ["target"] = "mono.android.TypeManager" });
        Assert.True(refs.GetProperty("total").GetInt32() > 0);

        var (_, jni) = await Call(c, "list_jni_bindings", new() { ["path"] = apk });
        Assert.Contains(jni.GetProperty("libraries").EnumerateArray(), l => l.GetProperty("library").GetString()!.EndsWith("libmono-android.release.so", StringComparison.Ordinal));

        var (_, pair) = await Call(c, "map_java_dotnet", new() { ["symbol"] = "Landroid/app/Activity;", ["path"] = apk });
        Assert.Equal("Android.App.Activity", pair.GetProperty("items")[0].GetProperty("dotNet").GetString());
    }

    /// <summary>decompile_java on the real jar of .class files, when the JADX server is configured.</summary>
    [RequiresRealDataFact("CORVUS_JAVA_DECOMPILER")]
    public async Task DecompileJavaOnAJar()
    {
        await using var server = await InProcessServer.StartAsync();
        var (java, record) = await Call(server.Client, "decompile_java", new() { ["path"] = RealPackages.File(Ref, Version, "ref", "net9.0", "mono.android.jar"), ["symbol"] = "mono.android.TypeManager" });
        Assert.Contains("class TypeManager", java);
        Assert.True(record.GetProperty("totalChars").GetInt32() > 0);
    }
}
