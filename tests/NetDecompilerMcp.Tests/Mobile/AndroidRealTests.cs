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
}
