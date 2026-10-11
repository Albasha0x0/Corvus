using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Services.Mobile;

namespace NetDecompilerMcp.Tests;

/// <summary>The Android tools on a real package (NDM_ANDROID_PACKAGE): every reader completes on real data.</summary>
public class AndroidRealTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private static string Package => RealData.Path(RealData.AndroidPackage);

    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.AndroidPackage)]
    public void ManifestAndResources()
    {
        var service = new AndroidPackageService(new OutputPager(new ServerOptions()));
        var m = service.Manifest(Package);
        output.WriteLine($"{m.Package} {m.VersionName}: {m.Components.Count} components, {m.Permissions.Count} permissions; issues: {string.Join("; ", m.Issues)}");
        output.WriteLine(string.Join("\n", m.Highlights));
        Assert.NotEmpty(m.Package);
        Assert.NotEmpty(m.Components);
        Assert.Contains(m.Components, c => c.Launcher);
        var resources = service.Resources(Package, null, null, null, 0, 10);
        output.WriteLine($"{resources.Total} resource values in {resources.Types.Count} types");
        Assert.True(resources.Total > 0);
        Assert.Contains("<manifest", service.Resource(Package, "AndroidManifest.xml", null, false, 0, null));
        using var p = AndroidPackage.Open(Package);
        output.WriteLine(string.Join("\n", AndroidRuntime.Detect(p).Select(r => $"{r.Family}: {r.Note} [{string.Join(", ", r.Evidence)}]")));
    }

    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.AndroidPackage)]
    public void DexIndexAndQueries()
    {
        var dex = new DexService();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var index = dex.Index(Package, default);
        output.WriteLine($"{index.Files.Count} DEX, {index.Classes.Count} classes, {index.Methods.Count} methods in {watch.ElapsedMilliseconds} ms; notes: {index.Notes.Count}");
        watch.Restart();
        output.WriteLine($"{index.Refs.Count} references, {index.Consts.Count} constants in {watch.ElapsedMilliseconds} ms");
        Assert.True(index.Classes.Count > 100);
        Assert.Empty(index.Files.SelectMany(f => f.Issues));
        // Every method body decodes to its end without truncation.
        int truncated = 0;
        foreach (var m in index.Methods.Values)
            if (m.Encoded.CodeOffset != 0 && m.File.Code(m.Encoded.CodeOffset) is { } code && Dalvik.Decode(code.Instructions).Sum(i => i.Length) != code.Instructions.Length) truncated++;
        Assert.Equal(0, truncated);

        var manifest = new AndroidPackageService(new OutputPager(new ServerOptions())).Manifest(Package);
        var launcher = manifest.Components.First(c => c.Launcher).Name;
        var detail = dex.GetClass(Package, launcher, default);
        output.WriteLine($"{detail.Descriptor}: {detail.Methods.Count} methods, super {detail.Super}; kotlin {detail.Kotlin}");
        var method = detail.Methods.First(m => m.CodeUnits > 0);
        var callees = dex.References(Package, method.Id, null, "from", 0, 50, default);
        output.WriteLine($"{method.Id} -> {callees.Total} references");
        var strings = dex.Search(Package, "string", "http", 0, 5, default);
        output.WriteLine($"'http' strings: {strings.Total}; {string.Join(" | ", strings.Items.Select(h => $"{h.Value} @ {h.Method}+{h.Offset}"))}");
        var callers = dex.References(Package, "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I", null, "to", 0, 5, default);
        output.WriteLine($"Log.d callers: {callers.Total}");
    }
}
