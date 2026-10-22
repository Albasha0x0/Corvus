using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

public sealed class NativeLinkSweepTests(ITestOutputHelper output)
{
    /// <summary>
    /// Imports of a System32 sample bound with only the sample loaded, then again after loading every provider one
    /// level deep: counts by status and unresolved reasons. Static imports of a system DLL must resolve except for
    /// API set contracts without a host on this system.
    /// </summary>
    [Trait("Speed", "Slow")]
    [WindowsFact]
    public void System32ImportsBind()
    {
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var sample = Directory.EnumerateFiles(system, "*.dll").Order(StringComparer.OrdinalIgnoreCase).Where((_, i) => i % 25 == 0).Take(80)
            .Concat(new[] { "kernel32.dll", "user32.dll", "advapi32.dll", "combase.dll", "shell32.dll" }.Select(n => Path.Combine(system, n)))
            .Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        using var dir = new TempDir();
        using var ws = new AssemblyWorkspace(new ServerOptions { BackgroundIndexing = false });
        var link = new NativeLinkService(ws, new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, null, new AnnotationStore(dir.File("ann"))));
        var natives = new List<LoadedNative>();
        foreach (var f in sample)
            try { if (ws.LoadAny(f).Native is { } n) natives.Add(n); }
            catch (ToolError) { }

        var sw = Stopwatch.StartNew();
        var first = Report("sample only", natives, link, out _);
        var bindTime = sw.Elapsed;
        sw.Restart();
        int loaded = 0;
        foreach (var n in natives.ToList())
            loaded += link.LoadProviders(ws.Read(() => link.BindAll(n)), int.MaxValue).Loaded.Count;
        output.WriteLine($"loaded {loaded} provider images in {sw.Elapsed.TotalSeconds:0.0} s; first pass bound {first} imports in {bindTime.TotalMilliseconds:0} ms");
        Report("providers loaded", natives, link, out var unresolved);

        // Static (not delay-loaded) imports of system DLLs resolve, apart from API set contracts this system does not host.
        var bad = unresolved.Where(u => !u.Delay && u.Reason != "api_set_unmapped").ToList();
        foreach (var u in bad.Take(40)) output.WriteLine($"  static unresolved: {u.Text}");
        Assert.Empty(bad);
    }

    private int Report(string title, List<LoadedNative> natives, NativeLinkService link, out List<(bool Delay, string Reason, string Text)> unresolved)
    {
        int bound = 0, notLoaded = 0, imports = 0;
        unresolved = [];
        var reasons = new Dictionary<string, int>();
        foreach (var n in natives)
        {
            var bindings = link.BindAll(n);
            for (int i = 0; i < bindings.Count; i++)
            {
                imports++;
                var b = bindings[i];
                if (b.Status == NativeLinkService.Bound) bound++;
                else if (b.Status == NativeLinkService.NotLoaded) notLoaded++;
                else
                {
                    reasons[b.Reason] = reasons.GetValueOrDefault(b.Reason) + 1;
                    var import = n.Image.Imports[i];
                    unresolved.Add((import.IsDelayLoad, b.Reason, $"{n.Id}: {import.Module}!{import.Name ?? "#" + import.Ordinal}{(import.IsDelayLoad ? " [delay]" : "")}: {NativeLinkService.Describe(b)}"));
                }
            }
        }
        output.WriteLine($"{title}: {natives.Count} images, {imports} imports: {bound} bound ({100.0 * bound / Math.Max(1, imports):0.0}%), " +
                         $"{notLoaded} provider not loaded, {imports - bound - notLoaded} unresolved" +
                         (reasons.Count > 0 ? $" ({string.Join(", ", reasons.OrderByDescending(r => r.Value).Select(r => $"{r.Key} {r.Value}"))})" : ""));
        foreach (var g in unresolved.GroupBy(u => (u.Delay, u.Reason)))
            output.WriteLine($"  {(g.Key.Delay ? "delay" : "static")} {g.Key.Reason}: {g.Count()}, e.g. {g.First().Text}");
        return bound;
    }
}
