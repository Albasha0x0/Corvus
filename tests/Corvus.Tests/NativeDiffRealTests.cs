using System.Diagnostics;
using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;
using Corvus.Native.Pdb;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Build matching on real pairs of builds found at run time: versions of one DLL in a local symbol store (C:\symbols,
/// with their PDBs) and side-by-side .NET runtimes. Functions named alike in both builds' PDBs (or exports) are the
/// ground truth; the matcher runs without names and is scored per tier.
/// </summary>
[Trait("Speed", "Slow")]
public class NativeDiffRealTests(ITestOutputHelper output)
{
    public sealed record Score(string Label, int OldFunctions, int NewFunctions, int Truth, int Matched, int[] Pairs, int[] Correct, int[] Wrong, double Seconds,
        string TruthSource, int MapTried, int MapCorrect, string Missed);

    /// <summary>Consecutive versions (same architecture) of one file, oldest first.</summary>
    public static IEnumerable<(string Old, string New, string Label)> DiscoverPairs(int max)
    {
        var groups = new List<(string Name, List<string> Files)>();
        if (OperatingSystem.IsWindows() && Directory.Exists(@"C:\symbols"))
            foreach (var dir in Directory.EnumerateDirectories(@"C:\symbols", "*.dll"))
            {
                var name = Path.GetFileName(dir);
                var files = Directory.EnumerateDirectories(dir).Select(d => Path.Combine(d, name)).Where(File.Exists).ToList();
                // the installed copies are builds too (their PDB is often in the store)
                var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                files.AddRange(new[] { "System32", "SysWOW64" }.Select(s => Path.Combine(windows, s, name)).Where(File.Exists));
                if (files.Count > 1) groups.Add((name, files));
            }
        foreach (var programs in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            var dotnet = Path.Combine(Environment.GetFolderPath(programs), "dotnet", "shared", "Microsoft.NETCore.App");
            if (!Directory.Exists(dotnet)) continue;
            foreach (var name in new[] { "coreclr.dll", "clrjit.dll" })
            {
                var files = Directory.EnumerateDirectories(dotnet).Select(d => Path.Combine(d, name)).Where(File.Exists).ToList();
                if (files.Count > 1) groups.Add((name, files));
            }
        }

        int count = 0;
        foreach (var (name, files) in groups.OrderBy(g => g.Name.StartsWith("c", StringComparison.OrdinalIgnoreCase) && g.Files[0].Contains("dotnet") ? 1 : 0))
        {
            var images = new List<(string Path, PeFile Pe, ulong Version, bool Pdb)>();
            foreach (var f in files)
            {
                try
                {
                    var pe = PeFile.Open(f);
                    images.Add((f, pe, pe.VersionInfo?.Fixed?.FileVersion ?? 0, PdbLocator.Locate(pe).Path != null));
                }
                catch (Exception) { }
            }
            foreach (var arch in images.GroupBy(i => i.Pe.Arch).Where(g => g.Key is NativeArch.X64 or NativeArch.X86))
            {
                var ordered = arch.Where(i => i.Pdb || name is "coreclr.dll" or "clrjit.dll").DistinctBy(i => i.Version).OrderBy(i => i.Version).ToList();
                // same major.minor only: a pair from one release line
                for (int k = 1; k < ordered.Count; k++)
                {
                    if (ordered[k].Version >> 32 != ordered[k - 1].Version >> 32) continue;
                    yield return (ordered[k - 1].Path, ordered[k].Path, $"{name} {arch.Key} {Dotted(ordered[k - 1].Version)} -> {Dotted(ordered[k].Version)}");
                    if (++count >= max) yield break;
                    break; // one pair per file and architecture
                }
            }
        }
    }

    private static string Dotted(ulong v) => $"{v >> 48}.{(v >> 32) & 0xFFFF}.{(v >> 16) & 0xFFFF}.{v & 0xFFFF}";

    /// <summary>Indexes both builds (function starts from their PDBs when present), matches them without names, and scores the pairs.</summary>
    public static Score Evaluate(string oldPath, string newPath, string label, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var (oldIndex, oldNames, source) = Load(oldPath, ct);
        var (newIndex, newNames, _) = Load(newPath, ct);
        var match = BuildMatcher.Match(ImagePrints.Build(oldIndex, ct), ImagePrints.Build(newIndex, ct), new MatchOptions { UseNames = false }, ct);

        // truth: a name unique among the functions of each build
        Dictionary<string, int> Unique(ImagePrints prints, Dictionary<uint, string> names)
        {
            var result = new Dictionary<string, int>(StringComparer.Ordinal);
            var dup = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in prints.Functions)
                if (names.TryGetValue(p.Start, out var n) && !result.TryAdd(n, p.Index)) dup.Add(n);
            foreach (var d in dup) result.Remove(d);
            return result;
        }
        var oldByName = Unique(match.Old, oldNames);
        var newByName = Unique(match.New, newNames);
        var truth = new Dictionary<int, int>();
        foreach (var (name, o) in oldByName) if (newByName.TryGetValue(name, out var n)) truth[o] = n;
        var truthTargets = truth.Values.ToHashSet();

        var pairs = new int[6];
        var correct = new int[6];
        var wrong = new int[6];
        foreach (var p in match.Pairs)
        {
            pairs[p.Tier]++;
            if (truth.TryGetValue(p.Old, out var t)) { if (t == p.New) correct[p.Tier]++; else wrong[p.Tier]++; }
            else if (truthTargets.Contains(p.New)) wrong[p.Tier]++;
        }

        // why truth pairs were missed
        var missed = new Dictionary<string, int>();
        foreach (var (o, n) in truth)
        {
            if (match.ByOld[o]?.New == n) continue;
            var a = match.Old.Functions[o];
            string why = match.ByOld[o] != null ? "matched_elsewhere"
                : match.ByNew[n] != null ? "target_taken"
                : match.Ambiguous.TryGetValue((true, o), out var amb) ? "ambiguous_" + amb.Reason
                : a.Instructions < 3 ? "small"
                : match.BestSeen.TryGetValue((true, o), out var best) ? $"best_{(int)(best * 10) / 10.0:0.0}"
                : "never_compared";
            missed[why] = missed.GetValueOrDefault(why) + 1;
        }

        // address mapping: instructions inside truth pairs whose functions are byte-identical after masking map to the same index
        var mapper = new AddressMapper(match);
        int tried = 0, mapped = 0;
        var decoderOld = new MaskedDecoder(oldIndex.Image);
        var decoderNew = new MaskedDecoder(newIndex.Image);
        foreach (var (o, n) in truth.Take(400))
        {
            if (match.ByOld[o]?.New != n) continue;
            var oldCode = FunctionCode.Instructions(oldIndex, decoderOld, match.Old.Functions[o].Function, ct, out _);
            var newCode = FunctionCode.Instructions(newIndex, decoderNew, match.New.Functions[n].Function, ct, out _);
            if (oldCode.Count < 4 || oldCode.Count != newCode.Count || match.Old.Functions[o].BytesHash != match.New.Functions[n].BytesHash) continue;
            int k = oldCode.Count / 2;
            tried++;
            if (mapper.Map(oldCode[k].Rva, ct).NewRva == newCode[k].Rva) mapped++;
        }
        // code patterns made in the old build, searched in the new one: found once at the counterpart
        var patterns = new Dictionary<string, int>();
        var newSections = CodePatterns.CodeSections(newIndex.Image);
        foreach (var (o, n) in truth.Where((_, i) => i % Math.Max(1, truth.Count / 100) == 0).Take(100))
        {
            var made = CodePatterns.Make(oldIndex, match.Old.Functions[o].Start, 64, allowReference: true, referenceOnly: false, ct);
            string outcome;
            if (!made.Unique) outcome = "not_unique_in_old";
            else
            {
                var hits = CodePatterns.Find(newSections, made.Pattern, 4, out int total, ct);
                uint want = match.New.Functions[n].Start;
                if (total == 0) outcome = "not_found";
                else if (total > 1) outcome = "several_hits";
                else if (made.Anchor == "address") outcome = hits[0] == want ? "found" : "wrong";
                else
                {
                    var bytes = new byte[4];
                    newIndex.Image.Read(hits[0] + (uint)made.OperandOffset!.Value, bytes);
                    uint got = made.OperandKind == "absolute" ? (uint)(BitConverter.ToUInt32(bytes) - newIndex.Image.ImageBase)
                        : hits[0] + (uint)made.InstructionEnd!.Value + (uint)BitConverter.ToInt32(bytes);
                    outcome = got == want ? "found_by_reference" : "wrong";
                }
            }
            patterns[outcome] = patterns.GetValueOrDefault(outcome) + 1;
        }
        missed["patterns: " + string.Join(" ", patterns.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key}={kv.Value}"))] = 0;

        return new Score(label, match.Old.Functions.Length, match.New.Functions.Length, truth.Count, match.Pairs.Count, pairs, correct, wrong,
            sw.Elapsed.TotalSeconds, source, tried, mapped, string.Join(", ", missed.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}")));
    }

    private static (NativeCodeIndex Index, Dictionary<uint, string> Names, string Source) Load(string path, CancellationToken ct)
    {
        var pe = PeFile.Open(path);
        var names = new Dictionary<uint, string>();
        string source = "exports";
        IReadOnlyCollection<uint>? starts = null;
        if (PdbLocator.Locate(pe).Path is { } pdbPath)
        {
            var pdb = PdbFile.Open(pdbPath, pe.Sections, ct);
            var chosen = PdbNaming.Choose(pdb, pe.SizeOfImage, ct);
            foreach (var n in chosen) if (n.IsFunction) names[n.Rva] = n.Name;
            starts = chosen.Where(n => n.IsFunction).Select(n => n.Rva).ToArray();
            source = "pdb";
        }
        else
            foreach (var e in pe.Exports) if (e.Name != null && e.ForwardedTo == null) names.TryAdd(e.Rva, e.Name);
        var index = NativeCodeIndex.Build(pe, starts != null ? new CodeIndexOptions { SymbolStarts = starts } : null, null, ct);
        return (index, names, source);
    }

    public static string Format(Score s)
    {
        var sb = new StringBuilder();
        int totalCorrect = s.Correct.Sum(), totalWrong = s.Wrong.Sum();
        sb.AppendLine($"{s.Label}: {s.OldFunctions} / {s.NewFunctions} functions, truth {s.Truth} ({s.TruthSource}), matched {s.Matched}, {s.Seconds:0.0} s");
        for (int t = 1; t <= 5; t++)
        {
            int judged = s.Correct[t] + s.Wrong[t];
            sb.AppendLine($"  tier {t} {MatchResult.TierNames[t],-14} pairs {s.Pairs[t],6}  judged {judged,6}  precision {(judged == 0 ? "-" : $"{100.0 * s.Correct[t] / judged:0.00}%"),8}" +
                          $"  recall share {(s.Truth == 0 ? "-" : $"{100.0 * s.Correct[t] / s.Truth:0.00}%")}");
        }
        sb.AppendLine($"  overall precision {(totalCorrect + totalWrong == 0 ? "-" : $"{100.0 * totalCorrect / (totalCorrect + totalWrong):0.00}%")}, " +
                      $"recall {(s.Truth == 0 ? "-" : $"{100.0 * totalCorrect / s.Truth:0.00}%")}; address mapping {s.MapCorrect}/{s.MapTried}");
        sb.AppendLine($"  missed: {s.Missed}");
        return sb.ToString();
    }

    [Fact]
    public void Real_build_pairs_match_with_high_precision()
    {
        int max = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_DIFF_PAIRS"), out var m) ? m : 6;
        var pairs = DiscoverPairs(max).ToList();
        if (pairs.Count == 0) { output.WriteLine("No pairs of builds found (C:\\symbols, side-by-side .NET runtimes): nothing to check."); return; }
        var report = new StringBuilder();
        foreach (var (o, n, label) in pairs)
        {
            var s = Evaluate(o, n, label);
            var text = Format(s);
            report.Append(text);
            output.WriteLine(text);
            int judged = s.Correct.Sum() + s.Wrong.Sum();
            if (judged >= 100) Assert.True(s.Correct.Sum() >= 0.95 * judged, text);
            if (s.MapTried > 0) Assert.Equal(s.MapTried, s.MapCorrect);
        }
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "ndm-native-diff-eval.txt"), report.ToString());
    }
}
