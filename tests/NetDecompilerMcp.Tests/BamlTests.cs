using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>WPF's compiled XAML (BAML) in .resources entries comes back as XAML.</summary>
public class BamlTests
{
    [Fact]
    public async Task BamlEntries_AreDecompiledToXaml()
    {
        // a WPF theme assembly of the installed desktop runtime: its .g.resources holds BAML resource dictionaries
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

    [Fact]
    public async Task RealAppWindow_WhenPresent()
    {
        var app = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"Downloads\WindowTop.v5.31.8.Portable\WindowTop.exe");
        if (!File.Exists(app)) return; // a Costura-packed WPF app on the developer machine
        using var env = new Env(app);
        var xaml = await new ResourceTools(env.Workspace, env.Resources, env.Decompiler, env.Pager)
            .GetResource(env.Fixture.Id, "WindowTop.g.resources", "managers/activationmanagers/common/ui/loginlicenseprogresswindow.baml");
        // the root type lives in FluentWPF, which ships only inside the exe (Costura): resolved from there
        Assert.Contains("<fw:AcrylicWindow x:Class=", xaml);
        Assert.Contains("xmlns:fw=\"clr-namespace:SourceChord.FluentWPF;assembly=FluentWPF\"", xaml);
    }
}
