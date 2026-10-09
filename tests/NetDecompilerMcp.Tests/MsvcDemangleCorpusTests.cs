using System.Diagnostics;
using System.Text;
using NetDecompilerMcp.Native.Msvc;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The managed undecorator against DbgHelp over every decorated name found on this machine.</summary>
public class MsvcDemangleCorpusTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Speed", "Slow")]
    public void AgreesWithDbgHelpOnTheMachineCorpus()
    {
        if (!DbgHelp.IsAvailable) return;
        var sw = Stopwatch.StartNew();
        var names = MsvcCorpus.DecoratedNames().Order(StringComparer.Ordinal).ToList();
        var harvest = sw.Elapsed;
        Assert.True(names.Count > 1000, $"only {names.Count} decorated names found");

        var full = Compare(names, MsvcDemangleOptions.Default with { DecodeStringLiterals = false, Ptr64 = true }, DbgHelp.Complete);
        var nameOnly = Compare(names, new MsvcDemangleOptions { Style = MsvcNameStyle.NameOnly, DecodeStringLiterals = false, Ptr64 = true }, DbgHelp.NameOnly);

        var report = new StringBuilder();
        report.AppendLine($"{names.Count} names (harvest {harvest.TotalSeconds:F1} s, total {sw.Elapsed.TotalSeconds:F1} s)");
        full.Write(report, "full");
        nameOnly.Write(report, "name-only");
        var path = Path.Combine(Path.GetTempPath(), "ndm-msvc-demangle-report.txt");
        File.WriteAllText(path, report.ToString());
        output.WriteLine(report.ToString().Split('\n').Take(60).Aggregate("", (a, l) => a + l + "\n"));
        output.WriteLine($"report: {path}");

        Assert.Equal(0, full.Internal);
        Assert.True(full.Agreement >= 0.995, $"full agreement {full.Agreement:P3}, see {path}");
        Assert.True(nameOnly.Agreement >= 0.995, $"name-only agreement {nameOnly.Agreement:P3}, see {path}");
        // differences outside the known (DbgHelp-side) categories stay rare on any machine
        Assert.True(full.Uncategorized + nameOnly.Uncategorized <= names.Count / 2000, $"uncategorized differences: full {full.Uncategorized}, name-only {nameOnly.Uncategorized}; see {path}");
    }

    /// <summary>Every corpus name with a few random edits: no internal error, bounded time.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void MutatedCorpusNeverFailsInternally()
    {
        var names = MsvcCorpus.DecoratedNames().Order(StringComparer.Ordinal).ToList();
        var rng = new Random(42);
        const string alphabet = "?@$0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        var sw = Stopwatch.StartNew();
        int mutated = 0;
        foreach (var original in names)
        {
            var chars = original.ToCharArray().ToList();
            for (int e = rng.Next(1, 4); e > 0 && chars.Count > 0; e--)
            {
                int at = rng.Next(chars.Count);
                switch (rng.Next(3))
                {
                    case 0: chars[at] = alphabet[rng.Next(alphabet.Length)]; break;
                    case 1: chars.RemoveAt(at); break;
                    default: chars.Insert(at, alphabet[rng.Next(alphabet.Length)]); break;
                }
            }
            var name = new string(chars.ToArray());
            var r = MsvcDemangler.Demangle(name);
            Assert.True(r.Error == null || !r.Error.StartsWith("internal error", StringComparison.Ordinal), $"{name}: {r.Error}");
            mutated++;
        }
        output.WriteLine($"{mutated} mutated names in {sw.Elapsed.TotalSeconds:F1} s");
        Assert.True(sw.Elapsed < TimeSpan.FromMinutes(2));
    }

    private sealed class Outcome
    {
        public int Total, Agree, Internal;
        public readonly Dictionary<string, List<(string Name, string? Ours, string? Theirs)>> Categories = [];

        public double Agreement => Total == 0 ? 1 : (double)Agree / Total;

        public int Uncategorized => Categories.Where(c => !c.Key.StartsWith("known:", StringComparison.Ordinal)).Sum(c => c.Value.Count);

        public void Add(string category, string name, string? ours, string? theirs)
        {
            if (!Categories.TryGetValue(category, out var list)) Categories[category] = list = [];
            list.Add((name, ours, theirs));
        }

        public void Write(StringBuilder sb, string title)
        {
            sb.AppendLine($"== {title}: {Agree}/{Total} agree ({Agreement:P3}); internal errors {Internal}");
            foreach (var (category, list) in Categories.OrderByDescending(c => c.Value.Count))
                sb.AppendLine($"  {category}: {list.Count}");
            foreach (var (category, list) in Categories.OrderByDescending(c => c.Value.Count))
            {
                sb.AppendLine($"-- {category} ({list.Count})");
                foreach (var (name, ours, theirs) in list.Where((_, i) => i % Math.Max(1, list.Count / 40) == 0).Take(40))
                    sb.AppendLine($"  {name}\n    ours:    {ours}\n    dbghelp: {theirs}");
            }
        }
    }

    private static Outcome Compare(List<string> names, MsvcDemangleOptions options, int flags)
    {
        var o = new Outcome();
        foreach (var name in names)
        {
            o.Total++;
            var ours = MsvcDemangler.Demangle(name, options);
            var theirs = DbgHelp.Undecorate(name, flags);
            if (ours.Error?.StartsWith("internal error", StringComparison.Ordinal) == true) o.Internal++;
            bool dbghelpFailed = theirs == null || theirs == name;
            if (!ours.Success && dbghelpFailed) { o.Agree++; continue; }
            if (ours.Success && !dbghelpFailed && DbgHelp.Normalize(ours.Text!) == DbgHelp.Normalize(theirs!)) { o.Agree++; continue; }
            o.Add(Categorize(name, ours, theirs, dbghelpFailed), name, ours.Text ?? "<" + ours.Error + ">", theirs);
        }
        return o;
    }

    /// <summary>
    /// Known, justified differences get their own category (prefixed "known:"); the rest is "other". Every known
    /// category is a case where DbgHelp's output is wrong or malformed, or where it accepts input it cannot decode.
    /// </summary>
    private static string Categorize(string name, MsvcDemangleResult ours, string? theirs, bool dbghelpFailed)
    {
        bool cli = name.Contains("$$F", StringComparison.Ordinal) || name.Contains("$$H", StringComparison.Ordinal) || name.Contains(".cctor", StringComparison.Ordinal)
            || name.Contains("$A", StringComparison.Ordinal) || name.Contains("@vc.", StringComparison.Ordinal);
        if (dbghelpFailed && ours.Success)
            return cli ? "known: C++/CLI or C++/CX name DbgHelp rejects (managed prefixes $$F/$$H, .cctor, dotted namespaces)" : "dbghelp failed";
        if (!ours.Success)
        {
            if (name.StartsWith("??_C@", StringComparison.Ordinal))
                return "known: string literal with trailing characters (DbgHelp prints \" ?? ?? ::...\")";
            if (name.Contains("??__E", StringComparison.Ordinal) || name.Contains("??__F", StringComparison.Ordinal))
                return "known: C++/CLI dynamic initializer nested in a name (DbgHelp reads the anonymous namespace key as a member name)";
            if (name.Contains("$AA__Z", StringComparison.Ordinal))
                return "known: C++/CLI boxed value type (__Z)";
            if (DbgHelp.Undecorate(name, DbgHelp.Complete) is var full && (full == null || full == name))
                return "known: invalid type encoding after the name (DbgHelp full form rejects it too; its name-only form stops after the name)";
            return "ours failed: " + ours.Error;
        }
        if (theirs!.Contains("`vcall'{", StringComparison.Ordinal))
            return "known: vcall thunk (DbgHelp appends \"' }'\" / drops \"{flat}\")";
        if (System.Text.RegularExpressions.Regex.IsMatch(theirs, @"(^|[^?])\bA0x[0-9a-f]+::"))
            return "known: back-referenced anonymous namespace (DbgHelp prints the raw key \"A0x...\")";
        if (theirs.Contains(" ?? ", StringComparison.Ordinal) || theirs.Contains("cli::array<char >", StringComparison.Ordinal))
            return "known: cli::array (DbgHelp output malformed)";
        return "other";
    }
}
