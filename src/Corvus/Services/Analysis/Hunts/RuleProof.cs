using System.Diagnostics;
using Corvus.Core;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>The folders a set of queries is checked against and the thresholds that decide a verdict.</summary>
public sealed record ProofOptions(string CleanFolder, string? PriorBuildsFolder = null, int DropAt = RuleProof.DefaultDropAt, int MaxFiles = RuleProof.DefaultMaxFiles,
    int UnreadPercent = RuleProof.DefaultUnreadPercent, int MinFiles = RuleProof.DefaultMinFiles);

/// <summary>One fact of a query: the clean files that carry it and, with prior builds, the builds that hold it.</summary>
public sealed record FactProof(string Fact, int CleanHits, IReadOnlyList<string> Samples, int? PriorHits = null, IReadOnlyList<string>? MissingFrom = null, string? Status = null);

/// <summary>The verdict (keep, review or drop) of a query with its reason, clean hits, sample paths and prior-build standing.</summary>
public sealed record HuntProof(string Verdict, string Reason, int CleanHits, IReadOnlyList<string> Samples, IReadOnlyList<FactProof> Facts, int? PriorHits = null, string? Status = null);

/// <summary>
/// What one folder scan read: files found, read, not read and past the bound, 
/// copies of the file itself, and per fact kind the files that could not show it.
/// </summary>
public sealed record ProofFolder(string Folder, int Found, int Read, int NotRead, int Skipped, IReadOnlyList<string> Unread, int CopyCount,
    IReadOnlyList<string> Copies, IReadOnlyDictionary<string, int> UnknownByKind)
{
    /// <summary>Files whose facts are unknown: not read or past the bound.</summary>
    public int Unknown => NotRead + Skipped;

    /// <summary>False when anything is unknown, or a read file could not show a fact kind.</summary>
    public bool Complete => Unknown == 0 && UnknownByKind.Count == 0;
}

/// <summary>The scans behind a proof: thresholds, speed and each folder.</summary>
public sealed record ProofScan(int DropAt, int UnreadPercent, int MinFiles, double Seconds, double FilesPerMinute, ProofFolder Clean, ProofFolder? Prior);

/// <summary>Checks hunting queries against a folder of clean files and a folder of prior builds before a rule is enabled.</summary>
public static class RuleProof
{
    /// <summary>Clean files carrying a fact at which its query is dropped.</summary>
    public const int DefaultDropAt = 3;

    /// <summary>Files read per folder; files past it are unknown.</summary>
    public const int DefaultMaxFiles = 2_000;

    /// <summary>Share of unknown clean files, in percent, above which a query with no clean hit is a review, not a keep.</summary>
    public const int DefaultUnreadPercent = 5;

    /// <summary>Clean files that must show a query's facts before no hit is a keep.</summary>
    public const int DefaultMinFiles = 20;

    /// <summary>Sample paths, lost builds and unread files named per result.</summary>
    public const int Named = 5;

    private const int MaxFactsShown = 10;

    /// <summary>What a reader returns for one file: whether it is a copy of the file under proof, and the facts and unknown kinds otherwise.</summary>
    internal sealed record FileRead(bool Copy, IReadOnlyList<HuntFact> Facts, IReadOnlySet<string> Unknown);

    // One folder's read files, the fact kinds each could not show, and the files that hold each query fact.
    private sealed record Scan(ProofFolder Folder, List<string> Files, List<int> Masks, Dictionary<string, List<int>> Holders);

    /// <summary>
    /// <paramref name="set"/> with a verdict on each query and the queries ranked, keep first and fewest clean hits first.
    /// <paramref name="sha1"/> names the file the queries came from: a clean or prior file with the same bytes is named, not counted.
    /// Throws InvalidArgument for a threshold out of range and NotFound for a missing folder.
    /// </summary>
    public static HuntSet Apply(InspectionService inspection, HuntSet set, string sha1, ProofOptions options, CancellationToken ct) =>
        Apply(set, options, (path, token) => ReadWith(inspection, path, sha1, token), ct);

    private static FileRead ReadWith(InspectionService inspection, string path, string sha1, CancellationToken ct)
    {
        var summary = inspection.Summarize(null, path, ct, new FileViewOptions("hunts"));
        if (summary.Views.GetValueOrDefault("hunts")?.Detail is not HuntSet read) throw new InvalidDataException("the file has no hunts view");
        if (summary.File.Sha1.Length > 0 && string.Equals(summary.File.Sha1, sha1, StringComparison.OrdinalIgnoreCase)) return new FileRead(true, [], new HashSet<string>());
        return new FileRead(false, read.Facts, read.UnknownKinds);
    }

    internal static HuntSet Apply(HuntSet set, ProofOptions options, Func<string, CancellationToken, FileRead> reader, CancellationToken ct)
    {
        if (options.DropAt < 1) throw new ToolError(ErrorCode.InvalidArgument, "dropAt is below 1.", "pass dropAt of 1 or more");
        if (options.MaxFiles < 1) throw new ToolError(ErrorCode.InvalidArgument, "maxFiles is below 1.", "pass maxFiles of 1 or more");
        if (options.MinFiles < 1) throw new ToolError(ErrorCode.InvalidArgument, "minFiles is below 1.", "pass minFiles of 1 or more");
        RequireFolder("cleanFolder", options.CleanFolder);
        if (options.PriorBuildsFolder != null) RequireFolder("priorBuildsFolder", options.PriorBuildsFolder);
        var facts = set.Hunts.SelectMany(h => h.Facts).Distinct(StringComparer.Ordinal).ToList();
        var clock = Stopwatch.StartNew();
        var clean = ScanFolder(options.CleanFolder, facts, reader, options.MaxFiles, ct);
        var prior = options.PriorBuildsFolder == null ? null : ScanFolder(options.PriorBuildsFolder, facts, reader, options.MaxFiles, ct);
        var seconds = clock.Elapsed.TotalSeconds;
        var read = clean.Folder.Read + (prior?.Folder.Read ?? 0);
        var scan = new ProofScan(options.DropAt, options.UnreadPercent, options.MinFiles, Math.Round(seconds, 2), seconds > 0 ? Math.Round(read * 60 / seconds, 1) : 0, clean.Folder, prior?.Folder);
        var judged = set.Hunts.Select((h, i) => (Hunt: h with { Proof = Judge(h, clean, prior, options) }, Index: i))
            .OrderBy(x => Rank(x.Hunt.Proof!.Verdict)).ThenBy(x => x.Hunt.Proof!.CleanHits).ThenBy(x => x.Index).Select(x => x.Hunt).ToList();
        var notes = new List<string>(set.Notes);
        if (!clean.Folder.Complete)
            notes.Add($"The clean scan is partial ({Reasons(clean.Folder)}): a query with no clean hit is not shown absent from the files that could not show its facts.");
        if (prior is { Folder.Complete: false })
            notes.Add($"The prior-build scan is partial ({Reasons(prior.Folder)}): a fact listed as new may be in a build not read.");
        if (prior is { Folder.Read: 0 }) notes.Add("No prior build was read, so no fact has a prior-build standing.");
        return set with { Hunts = judged, Notes = notes, Proof = scan };
    }

    private static string Reasons(ProofFolder f)
    {
        var parts = new List<string>();
        if (f.NotRead > 0) parts.Add($"{f.NotRead:N0} not read");
        if (f.Skipped > 0) parts.Add($"{f.Skipped:N0} past maxFiles");
        foreach (var (kind, count) in f.UnknownByKind.OrderBy(k => k.Key, StringComparer.Ordinal)) parts.Add($"{count:N0} could not show {kind}");
        return string.Join(", ", parts);
    }

    private static void RequireFolder(string name, string path)
    {
        if (!Directory.Exists(path)) throw new ToolError(ErrorCode.NotFound, $"{name} {path} is not a folder.", $"pass an existing folder for {name}");
    }

    private static int Rank(string verdict) => verdict switch { "keep" => 0, "review" => 1, _ => 2 };

    private static string KindOf(string fact)
    {
        int at = fact.IndexOf(':', StringComparison.Ordinal);
        return at < 0 ? fact : fact[..at];
    }

    // One bit per fact kind; a kind no query uses has none.
    private static int Bit(string kind)
    {
        int i = HuntKind.All.ToList().IndexOf(kind);
        return i < 0 ? 0 : 1 << i;
    }

    private static string FactKey(string fact)
    {
        int at = fact.IndexOf(':', StringComparison.Ordinal);
        return at < 0 ? fact : FactKey(fact[..at], fact[(at + 1)..]);
    }

    // Names and hashes compare without case.
    private static string FactKey(string kind, string value)
    {
        var v = value.Trim();
        return kind + ":" + (kind is HuntKind.DllName or HuntKind.OriginalFileName or HuntKind.Domain or HuntKind.NamedPipe or HuntKind.FilePath or HuntKind.RegistryKey or HuntKind.Sha1
            ? v.ToUpperInvariant() : v);
    }

    private static List<string> Walk(string root, CancellationToken ct)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var paths = new List<string>();
        foreach (var path in Directory.EnumerateFiles(root, "*", options))
        {
            ct.ThrowIfCancellationRequested();
            paths.Add(path);
        }
        paths.Sort(StringComparer.OrdinalIgnoreCase);
        return paths;
    }

    private static Scan ScanFolder(string folder, List<string> facts, Func<string, CancellationToken, FileRead> reader, int max, CancellationToken ct)
    {
        var found = Walk(folder, ct);
        var paths = found.Take(max).ToList();
        var files = new List<string>();
        var masks = new List<int>();
        var holders = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var unknownByKind = new Dictionary<string, int>(StringComparer.Ordinal);
        var unread = new List<string>();
        var copies = new List<string>();
        int notRead = 0;
        var keys = facts.Select(f => (Fact: f, Key: FactKey(f))).ToList();
        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var read = reader(path, ct);
                if (read.Copy) { copies.Add(path); continue; }
                int index = files.Count, mask = 0;
                files.Add(path);
                foreach (var kind in read.Unknown)
                {
                    mask |= Bit(kind);
                    unknownByKind[kind] = unknownByKind.GetValueOrDefault(kind) + 1;
                }
                masks.Add(mask);
                var has = read.Facts.Select(f => FactKey(f.Kind, f.Value)).ToHashSet(StringComparer.Ordinal);
                foreach (var (fact, key) in keys.Where(k => has.Contains(k.Key)))
                {
                    if (!holders.TryGetValue(fact, out var list)) holders[fact] = list = [];
                    list.Add(index);
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                notRead++;
                if (unread.Count < Named) unread.Add($"{path}: {e.Message.Split('\n')[0].Trim()}");
            }
        }
        var summary = new ProofFolder(folder, found.Count, files.Count, notRead, found.Count - paths.Count, unread, copies.Count,
            [.. copies.Take(Named)], unknownByKind);
        return new Scan(summary, files, masks, holders);
    }

    private static HuntProof Judge(Hunt hunt, Scan clean, Scan? prior, ProofOptions options)
    {
        var facts = hunt.Facts.Select(f =>
        {
            var hits = clean.Holders.GetValueOrDefault(f) ?? [];
            var samples = hits.Take(Named).Select(i => clean.Files[i]).ToList();
            if (prior is not { Files.Count: > 0 }) return new FactProof(f, hits.Count, samples);
            var held = prior.Holders.GetValueOrDefault(f) ?? [];
            var missing = Enumerable.Range(0, prior.Files.Count).Except(held).Take(Named).Select(i => Path.GetRelativePath(prior.Folder.Folder, prior.Files[i])).ToList();
            var status = held.Count == prior.Files.Count ? "durable" : held.Count == 0 ? "new" : "partial";
            return new FactProof(f, hits.Count, samples, held.Count, missing, status);
        }).ToList();
        // A query is an OR over its facts, so a file carrying any of them alerts.
        var union = hunt.Facts.SelectMany(f => clean.Holders.GetValueOrDefault(f) ?? []).Distinct().Order().ToList();
        var worst = facts.Count == 0 ? null : facts.MaxBy(f => f.CleanHits)!;
        int hits = union.Count;
        var unionSamples = union.Take(Named).Select(i => clean.Files[i]).ToList();
        int kinds = hunt.Facts.Aggregate(0, (m, f) => m | Bit(KindOf(f)));
        int blind = clean.Masks.Count(m => (m & kinds) != 0);
        int informative = clean.Folder.Read - blind;
        int lost = clean.Folder.Unknown + blind;
        long total = clean.Folder.Found - clean.Folder.CopyCount;
        var names = string.Join(", ", hunt.Facts.Select(KindOf).Distinct().Order(StringComparer.Ordinal));
        string verdict, reason;
        if (hunt.Facts.Any(f => f.StartsWith(HuntKind.Sha1 + ":", StringComparison.Ordinal)) && clean.Folder.CopyCount > 0)
            (verdict, reason) = ("review", $"A clean file has the same bytes: {clean.Folder.Copies[0]}");
        else if (hits >= options.DropAt) (verdict, reason) = ("drop", $"{hits:N0} clean files carry {Show(worst!.Fact)}");
        else if (hits > 0) (verdict, reason) = ("review", $"{hits:N0} clean {(hits == 1 ? "file carries" : "files carry")} {Show(worst!.Fact)}");
        else if (clean.Folder.Read == 0) (verdict, reason) = ("review", "No clean file was read");
        else if (lost * 100 > (long)options.UnreadPercent * total)
            (verdict, reason) = ("review", $"{lost:N0} of {total:N0} clean files could not show {names} ({Reasons(clean.Folder)})");
        else if (informative < options.MinFiles)
            (verdict, reason) = ("review", $"Only {informative:N0} clean files could show {names}; the minimum is {options.MinFiles:N0}");
        else (verdict, reason) = ("keep", $"No hit in {informative:N0} clean files that could show {names}" + (lost > 0 ? $"; {Reasons(clean.Folder)}" : ""));
        string? standing = null;
        int? priorHits = null;
        if (prior is { Files.Count: > 0 } && facts.Count > 0)
        {
            standing = facts.All(f => f.Status == "durable") ? "durable" : facts.All(f => f.Status == "new") ? "new" : "changed";
            priorHits = facts.Min(f => f.PriorHits);
            var absent = facts.SelectMany(f => f.MissingFrom ?? []).Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToList();
            reason += standing switch
            {
                "durable" => $"; durable in all {prior.Files.Count:N0} prior builds",
                "new" => $"; new, in none of {prior.Files.Count:N0} prior builds",
                _ => $"; missing from {string.Join(", ", absent)}",
            };
        }
        return new HuntProof(verdict, reason, hits, unionSamples,[.. facts.OrderByDescending(f => f.CleanHits).Take(MaxFactsShown)], priorHits, standing);
    }

    private static string Show(string fact) => fact.Length > 80 ? fact[..77] + "..." : fact;
}
