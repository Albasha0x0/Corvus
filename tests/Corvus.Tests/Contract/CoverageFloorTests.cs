using System.Xml.Linq;

namespace Corvus.Tests;

/// <summary>Line coverage per source area from a full run's report (CORVUS_COVERAGE_REPORT, set by ./test.ps1 -Full -Coverage) stays above Ratchets/coverage.txt.</summary>
public class CoverageFloorTests
{
    public const string ReportVariable = "CORVUS_COVERAGE_REPORT";

    /// <summary>Percentage points below a measurement that its floor is recorded at: sampled sweeps and missing engines move coverage a little.</summary>
    private const double Margin = 1.0;

    [Fact]
    [Trait("Speed", "Slow")]
    public void Coverage_stays_above_its_floor()
    {
        if (Environment.GetEnvironmentVariable(ReportVariable) is not { Length: > 0 } report) return; // only after a coverage run
        var floors = Measure(Directory.Exists(report) ? Directory.EnumerateFiles(report, "coverage.cobertura.xml", SearchOption.AllDirectories) : [report])
            .ToDictionary(e => e.Key, e => Math.Max(0, Math.Floor((e.Value - Margin) * 10) / 10), StringComparer.Ordinal);
        CountRatchet.Check("coverage", $"line coverage per source area of src/Corvus may only rise (floors {Margin} point below the run that set them)", floors, floor: true);
    }

    [Fact]
    public void Areas_and_total_are_read_from_a_Cobertura_report()
    {
        using var dir = new TempDir();
        var file = Path.Combine(dir.Path, "coverage.cobertura.xml");
        static XElement Class(string path, params (int Line, int Hits)[] lines) => new("class", new XAttribute("filename", path),
            new XElement("lines", lines.Select(l => new XElement("line", new XAttribute("number", l.Line), new XAttribute("hits", l.Hits)))));
        new XDocument(new XElement("coverage", new XElement("packages", new XElement("package", new XElement("classes",
            Class(@"C:\r\src\Corvus\Native\Elf\ElfFile.cs", (1, 1), (2, 0), (3, 4)),
            Class(@"C:\r\src\Corvus\Native\Elf\ElfFile.cs", (2, 1)),                // a nested class: line 2 is covered after all
            Class("/r/src/Corvus/Core/Pool.cs", (10, 0), (11, 0)),
            Class("/r/obj/Generated.cs", (1, 1))))))).Save(file);
        var relative = Path.Combine(dir.Path, "relative.cobertura.xml");
        new XDocument(new XElement("coverage", new XElement("sources", new XElement("source", @"D:\w\src\Corvus\")),
            new XElement("packages", new XElement("package", new XElement("classes", Class(@"Tools\Dotnet\Decompile.cs", (5, 1), (6, 0))))))).Save(relative);
        Assert.Equal(50.0, Measure([relative])["src/Corvus/Tools/Dotnet"]);
        var measured = Measure([file]);
        Assert.Equal(100.0, measured["src/Corvus/Native/Elf"]);
        Assert.Equal(0.0, measured["src/Corvus/Core"]);
        Assert.Equal(60.0, measured["total"]);
        Assert.Equal(3, measured.Count);
    }

    /// <summary>Line coverage in percent (one decimal) per area: src/Corvus/&lt;folder&gt;, one level deeper under Native, Services and Tools; plus "total".</summary>
    internal static Dictionary<string, double> Measure(IEnumerable<string> reports)
    {
        var lines = new Dictionary<(string File, int Line), bool>();
        foreach (var report in reports)
        {
            var document = XDocument.Load(report);
            // Coverlet writes file names relative to the <source> folder of their project.
            var source = ((string?)document.Descendants("source").FirstOrDefault() ?? "").Replace('\\', '/');
            foreach (var cls in document.Descendants("class"))
            {
                var path = ((string?)cls.Attribute("filename") ?? "").Replace('\\', '/');
                if (!path.Contains("src/Corvus/", StringComparison.Ordinal)) path = source.TrimEnd('/') + "/" + path;
                var at = path.IndexOf("src/Corvus/", StringComparison.Ordinal);
                if (at < 0 || path.Contains("/obj/", StringComparison.Ordinal)) continue; // generated sources
                path = path[at..];
                foreach (var line in cls.Descendants("line"))
                {
                    var key = (path, (int)line.Attribute("number")!);
                    lines[key] = lines.GetValueOrDefault(key) || (long)line.Attribute("hits")! > 0;
                }
            }
        }
        static string Area(string path)
        {
            var parts = path.Split('/');
            return parts.Length > 4 && parts[2] is "Native" or "Services" or "Tools" ? string.Join('/', parts[..4]) : string.Join('/', parts[..Math.Min(3, parts.Length - 1)]);
        }
        static double Percent(IEnumerable<bool> hits) { var all = hits.ToList(); return Math.Round(100.0 * all.Count(h => h) / all.Count, 1); }
        var result = lines.GroupBy(l => Area(l.Key.File)).ToDictionary(g => g.Key, g => Percent(g.Select(l => l.Value)), StringComparer.Ordinal);
        if (lines.Count > 0) result["total"] = Percent(lines.Values);
        return result;
    }
}
