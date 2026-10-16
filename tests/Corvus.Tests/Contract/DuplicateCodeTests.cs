using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Tests;

/// <summary>
/// Static gates (E19): the dead-code analyzers are errors in the build, and copied blocks of source are counted per file
/// pair against Ratchets/duplicate-lines.txt, which may only fall.
/// </summary>
public partial class DuplicateCodeTests
{
    /// <summary>Significant lines (no blanks, comments, lone braces or usings) a copy must span to count.</summary>
    internal const int Window = 8;

    private static readonly string Root = DocsTests.RepoRoot();

    [GeneratedRegex(@"^(?:[{}()\[\];,]+|using [\w.=\s]+;|#(?:region|endregion|nullable|pragma)\b.*|\[.*\])$")]
    private static partial Regex Trivial();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Space();

    [Fact]
    public void DeadCodeAnalyzersAreErrors()
    {
        var editorconfig = File.ReadAllText(Path.Combine(Root, ".editorconfig"));
        Assert.Contains("dotnet_diagnostic.IDE0051.severity = error", editorconfig, StringComparison.Ordinal);
        Assert.Contains("dotnet_diagnostic.IDE0052.severity = error", editorconfig, StringComparison.Ordinal);
        Assert.Contains("<EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>", File.ReadAllText(Path.Combine(Root, "Directory.Build.props")), StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void DuplicateLinesOnlyFall()
    {
        var measured = Measure(Path.Combine(Root, "src"));
        CountRatchet.Check("duplicate-lines", $"no new copied block of {Window} or more significant lines under src/", measured, floor: false);
    }

    [Fact]
    public void ACopiedBlockIsFound()
    {
        using var dir = new TempDir();
        var body = string.Join("\n", Enumerable.Range(0, Window).Select(i => $"var v{i} = Compute({i}) + offset;"));
        File.WriteAllText(Path.Combine(dir.Path, "A.cs"), "class A {\nvoid M() {\n" + body + "\n}\n}\n");
        File.WriteAllText(Path.Combine(dir.Path, "B.cs"), "class B {\n// a copy\nvoid N() {\n" + body.Replace("\n", "\n\n    ") + "\n}\n}\n");
        File.WriteAllText(Path.Combine(dir.Path, "C.cs"), "class C {\n" + string.Join("\n", body.Split('\n').Take(Window - 1)) + "\n}\n");
        Assert.Equal(new Dictionary<string, double> { ["A.cs <-> B.cs"] = 2 * Window }, Measure(dir.Path));
    }

    /// <summary>Per file pair (same-file copies too), the significant lines of both sides that lie in a shared window.</summary>
    internal static Dictionary<string, double> Measure(string root)
    {
        var files = Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".g.cs", StringComparison.Ordinal) && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/')).Order(StringComparer.Ordinal).ToList();
        var lines = files.Select(f => Significant(File.ReadAllLines(Path.Combine(root, f))).Select(Hash).ToArray()).ToList();

        var windows = new Dictionary<(ulong, ulong), List<(int File, int Start)>>();
        for (var f = 0; f < files.Count; f++)
            for (var i = 0; i + Window <= lines[f].Length; i++)
            {
                ulong a = 1469598103934665603, b = 0;
                for (var k = 0; k < Window; k++) { a = (a ^ lines[f][i + k]) * 1099511628211; b = b * 31 + lines[f][i + k]; }
                if (!windows.TryGetValue((a, b), out var at)) windows[(a, b)] = at = [];
                at.Add((f, i));
            }

        var covered = new Dictionary<(int, int), (HashSet<int> Left, HashSet<int> Right)>();
        foreach (var at in windows.Values.Where(w => w.Count > 1))
            for (var x = 0; x < at.Count; x++)
                for (var y = x + 1; y < at.Count; y++)
                {
                    var (p, q) = (at[x], at[y]);
                    if (p.File == q.File && q.Start - p.Start < Window) continue; // overlapping repeats of one run
                    if (!covered.TryGetValue((p.File, q.File), out var sides)) covered[(p.File, q.File)] = sides = ([], []);
                    for (var k = 0; k < Window; k++) { sides.Left.Add(p.Start + k); sides.Right.Add(q.Start + k); }
                }
        return covered.ToDictionary(
            e => $"{files[e.Key.Item1]} <-> {files[e.Key.Item2]}",
            e => (double)(e.Key.Item1 == e.Key.Item2 ? e.Value.Left.Union(e.Value.Right).Count() : e.Value.Left.Count + e.Value.Right.Count),
            StringComparer.Ordinal);
    }

    private static IEnumerable<string> Significant(IEnumerable<string> source)
    {
        var block = false;
        foreach (var raw in source)
        {
            var line = Space().Replace(raw.Trim(), " ");
            if (block) { if (line.Contains("*/", StringComparison.Ordinal)) block = false; continue; }
            if (line.StartsWith("/*", StringComparison.Ordinal)) { block = !line.Contains("*/", StringComparison.Ordinal); continue; }
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || Trivial().IsMatch(line)) continue;
            yield return line;
        }
    }

    private static ulong Hash(string line)
    {
        ulong h = 14695981039346656037;
        foreach (var b in Encoding.UTF8.GetBytes(line)) h = (h ^ b) * 1099511628211;
        return h;
    }
}
