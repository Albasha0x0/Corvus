using ModelContextProtocol.Protocol;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js on jQuery's minified build and its source map (NuGet jQuery 3.7.1), checked against the unminified file.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class JsRealTests
{
    private static string Script(string name) => RealPackages.File("jQuery", "3.7.1", "Content", "Scripts", name);

    [Fact]
    public async Task Minified_jQuery_maps_back_to_its_source()
    {
        var min = Script("jquery-3.7.1.min.js");
        await using var server = await InProcessServer.StartAsync();
        var r = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = min });
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.True(r.IsError != true && text.Contains("1 sources"), text);

        // every named segment sampled points at that name in the unminified source
        var map = JsAnalysis.Map(min);
        var original = File.ReadAllLines(Script("jquery-3.7.1.js"));
        var minified = File.ReadAllLines(min);
        int checkedNames = 0;
        for (int line = 0; line < minified.Length; line++)
            for (int column = 0; column < minified[line].Length; column += 37)
                if (map.Find(line, column) is { Name: >= 0 } seg)
                {
                    var name = map.Names[seg.Name];
                    // a quoted property key ("* text": ...) maps to its opening quote
                    var at = original[seg.OriginalLine].AsSpan(seg.OriginalColumn);
                    if (at.Length > 0 && at[0] is '"' or '\'') at = at[1..];
                    Assert.True(at.StartsWith(name),
                        $"{line + 1}:{column + 1} -> {seg.OriginalLine + 1}:{seg.OriginalColumn + 1} should start with {name}");
                    checkedNames++;
                }
        Assert.True(checkedNames > 1000, $"{checkedNames} named segments checked");
        Assert.Empty(map.Issues);
    }

    /// <summary>jQuery's map has no sourcesContent: its one source is the unminified file beside the map, written as the original tree.</summary>
    [Fact]
    public void Minified_jQuery_unpacks_to_its_original_tree()
    {
        using var dir = new TempDir();
        using var ws = new Corvus.Core.AssemblyWorkspace();
        var report = new Corvus.Services.Analysis.UnpackService(ws).Unpack(Script("jquery-3.7.1.min.js"), dir.File("out"), load: false, Corvus.Core.AnalysisLimits.Default, default);
        var map = JsAnalysis.Map(Script("jquery-3.7.1.min.js"));
        var written = report.Files.Where(f => f.Origin.Contains(" of the map (", StringComparison.Ordinal)).ToList();
        Assert.Equal(map.Sources.Count, written.Count);
        Assert.Equal(File.ReadAllBytes(Script("jquery-3.7.1.js")), File.ReadAllBytes(Assert.Single(written).Path));
        Assert.Contains(report.Notes, n => n.StartsWith("1 source(s) in the map, written under original/: 0 from sourcesContent, 1 from files beside the map, 0 without content", StringComparison.Ordinal));
    }
}
