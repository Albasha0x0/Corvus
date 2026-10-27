using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>WPF's compiled XAML (BAML) in .resources entries comes back as XAML.</summary>
public class BamlTests
{
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task BAML_entries_are_decompiled_to_XAML()
    {
        // WPF theme assembly from the desktop runtime; its .g.resources holds BAML.
        var aero2 = Frameworks.All.Value.Where(s => s.Name == "Microsoft.WindowsDesktop.App")
            .Select(s => Path.Combine(s.Dir, "PresentationFramework.Aero2.dll")).FirstOrDefault(File.Exists);
        if (aero2 == null) return; // needs the Windows desktop runtime
        using var env = new Env(aero2);
        var tools = new ResourceTools(env.Workspace, env.Resources, env.Decompiler, env.Pager);
        var listing = await tools.GetResource(env.Fixture.Id, "PresentationFramework.Aero2.g.resources");
        var entry = listing.Split('\n').Select(l => l.Trim()).First(l => l.Contains(".baml")).Split("  ")[0];
        var xaml = await tools.GetResource(env.Fixture.Id, "PresentationFramework.Aero2.g.resources", entry);
        Assert.StartsWith($"<!-- {entry}: XAML decompiled from BAML", xaml);
        Assert.Contains("ResourceDictionary", xaml);

        // savePath still writes the raw BAML
        using var dir = new TempDir();
        var saved = dir.File("theme.baml");
        await tools.GetResource(env.Fixture.Id, "PresentationFramework.Aero2.g.resources", entry, saved);
        Assert.Equal((byte)0x0C, File.ReadAllBytes(saved)[0]); // BAML stream header: "MSBAML" length prefix
    }
}
