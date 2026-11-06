using System.Diagnostics;
using Corvus.Core;

namespace Corvus.Services.Analysis.Hunts;

/// <summary>The folders a set of queries is checked against and the thresholds that decide a verdict.</summary>
public sealed record ProofOptions(string CleanFolder, string? PriorBuildsFolder = null, int DropAt = RuleProof.DefaultDropAt, int MaxFiles = RuleProof.DefaultMaxFiles,
    int UnreadPercent = RuleProof.DefaultUnreadPercent);

/// <summary>One fact of a query: the clean files that carry it and, with prior builds, the builds that hold it.</summary>
public sealed record FactProof(string Fact, int CleanHits, IReadOnlyList<string> Samples, int? PriorHits = null, IReadOnlyList<string>? MissingFrom = null, string? Status = null);

/// <summary>The verdict (keep, review or drop) of a query with its reason, clean hits, sample paths and prior-build standing.</summary>
public sealed record HuntProof(string Verdict, string Reason, int CleanHits, IReadOnlyList<string> Samples, IReadOnlyList<FactProof> Facts, int? PriorHits = null, string? Status = null);

/// <summary>What one folder scan read: files found, files read, files not read with the reason, files read in part, files past the bound and copies of the file itself.</summary>
public sealed record ProofFolder(string Folder, int Found, int Read, int NotRead, IReadOnlyList<string> Unread, int ReadInPart, int Skipped, IReadOnlyList<string> Copies)
{
    /// <summary>Files whose facts are unknown: not read, read in part or past the bound.</summary>
    public int Unknown => NotRead + ReadInPart + Skipped;

    /// <summary>False when any file's facts are unknown.</summary>
    public bool Complete => Unknown == 0;
}

/// <summary>The scans behind a proof: thresholds, speed and each folder.</summary>
public sealed record ProofScan(int DropAt, int UnreadPercent, double Seconds, double FilesPerMinute, ProofFolder Clean, ProofFolder? Prior);

/// <summary>Checks hunting queries against a folder of clean files and a folder of prior builds before a rule is enabled.</summary>
public static class RuleProof
{
    /// <summary>Clean files carrying a fact at which its query is dropped.</summary>
    public const int DefaultDropAt = 3;

    /// <summary>Files read per folder; files past it are unknown.</summary>
    public const int DefaultMaxFiles = 2_000;

    /// <summary>Share of unknown clean files, in percent, above which a query with no clean hit is a review, not a keep.</summary>
    public const int DefaultUnreadPercent = 5;

    /// <summary>Sample paths, lost builds and unread files named per result.</summary>
    public const int Named = 5;

    private const int MaxFactsShown = 10;

    private sealed record Scan(ProofFolder Folder, List<string> Files, Dictionary<string, List<int>> Holders);

    /// <summary>
    /// <paramref name="set"/> with a verdict on each query and the queries ranked, keep first and fewest clean hits first.
    /// <paramref name="sha1"/> names the file the queries came from: a clean or prior file with the same bytes is named, not counted.
    /// Throws InvalidArgument for a threshold below 1 and NotFound for a missing folder.
    /// </summary>
    public static HuntSet Apply(InspectionService inspection, HuntSet set, string sha1, ProofOptions options, CancellationToken ct)
    {
        if (options.DropAt < 1) throw new ToolError(ErrorCode.InvalidArgument, "dropAt is below 1.", "pass dropAt of 1 or more");
        if (options.MaxFiles < 1) throw new ToolError(ErrorCode.InvalidArgument, "maxFiles is below 1.", "pass maxFiles of 1 or more");
        RequireFolder("cleanFolder", options.CleanFolder);
        if (options.PriorBuildsFolder != null) RequireFolder("priorBuildsFolder", options.PriorBuildsFolder);
        var keys = set.Hunts.SelectMany(h => h.Facts).Select(FactKey).ToHashSet(StringComparer.Ordinal);
        var clock = Stopwatch.StartNew();
        var clean = ScanFolder(inspection, options.CleanFolder, keys, sha1, options.MaxFiles, ct);
        var prior = options.PriorBuildsFolder == null ? null : ScanFolder(inspection, options.PriorBuildsFolder, keys, sha1, options.MaxFiles, ct);
        var seconds = clock.Elapsed.TotalSeconds;
        var read = clean.Folder.Read + (prior?.Folder.Read ?? 0);
        var scan = new ProofScan(options.DropAt, options.UnreadPercent, Math.Round(seconds, 2), seconds > 0 ? Math.Round(read * 60 / seconds, 1) : 0, clean.Folder, prior?.Folder);
        var judged = set.Hunts.Select((h, i) => (Hunt: h with { Proof = Judge(h, clean, prior, options) }, Index: i))
            .OrderBy(x => Rank(x.Hunt.Proof!.Verdict)).ThenBy(x => x.Hunt.Proof!.CleanHits).ThenBy(x => x.Index).Select(x => x.Hunt).ToList();
        var notes = new List<string>(set.Notes);
        if (!clean.Folder.Complete)
            notes.Add($"The clean scan is partial ({Reasons(clean.Folder)}): a query with no clean hit is not shown absent from the files not read.");
        if (prior is { Folder.Complete: false })
            notes.Add($"The prior-build scan is partial ({Reasons(prior.Folder)}): a fact listed as new may be in a build not read.");
        if (prior is { Folder.Read: 0 }) notes.Add("No prior build was read, so no fact has a prior-build standing.");
        return set with { Hunts = judged, Notes = notes, Proof = scan };
    }

    private static string Reasons(ProofFolder f)
    {
        var parts = new List<string>();
        if (f.NotRead > 0) parts.Add($"{f.NotRead:N0} not read");
        if (f.ReadInPart > 0) parts.Add($"{f.ReadInPart:N0} read in part");
        if (f.Skipped > 0) parts.Add($"{f.Skipped:N0} past maxFiles");
        return string.Join(", ", parts);
    }

    private static void RequireFolder(string name, string path)
    {
        if (!Directory.Exists(path)) throw new ToolError(ErrorCode.NotFound, $"{name} {path} is not a folder.", $"pass an existing folder for {name}");
    }

    private static int Rank(string verdict) => verdict switch { "keep" => 0, "review" => 1, _ => 2 };

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

    private static Scan ScanFolder(InspectionService inspection, string folder, HashSet<string> keys, string sha1, int max, CancellationToken ct)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        var paths = new List<string>();
        int found = 0;
        foreach (var path in Directory.EnumerateFiles(folder, "*", options))
        {
            ct.ThrowIfCancellationRequested();
            found++;
            if (paths.Count < max) paths.Add(path);
        }
        paths.Sort(StringComparer.OrdinalIgnoreCase);
        var files = new List<string>();
        var holders = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var unread = new List<string>();
        var copies = new List<string>();
        int notRead = 0, inPart = 0;
        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var summary = inspection.Summarize(null, path, ct, new FileViewOptions("hunts"));
                if (summary.Views.GetValueOrDefault("hunts")?.Detail is not HuntSet read) throw new InvalidDataException("the file has no hunts view");
                if (summary.File.Sha1.Length > 0 && string.Equals(summary.File.Sha1, sha1, StringComparison.OrdinalIgnoreCase)) { copies.Add(path); continue; }
                if (HuntFacts.ReadInPart(read.Notes)) inPart++;
                int index = files.Count;
                files.Add(path);
                foreach (var key in read.Facts.Select(f => FactKey(f.Kind, f.Value)).Where(keys.Contains).Distinct(StringComparer.Ordinal))
                {
                    if (!holders.TryGetValue(key, out var list)) holders[key] = list = [];
                    list.Add(index);
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                notRead++;
                if (unread.Count < Named) unread.Add($"{path}: {e.Message.Split('\n')[0].Trim()}");
            }
        }
        return new Scan(new ProofFolder(folder, found, files.Count, notRead, unread, inPart, found - paths.Count, [.. copies.Take(Named)]), files, holders);
    }

    private static HuntProof Judge(Hunt hunt, Scan clean, Scan? prior, ProofOptions options)
    {
        var facts = hunt.Facts.Select(f =>
        {
            var key = FactKey(f);
            var hits = clean.Holders.GetValueOrDefault(key) ?? [];
            var samples = hits.Take(Named).Select(i => clean.Files[i]).ToList();
            if (prior is not { Files.Count: > 0 }) return new FactProof(f, hits.Count, samples);
            var held = prior.Holders.GetValueOrDefault(key) ?? [];
            var missing = Enumerable.Range(0, prior.Files.Count).Except(held).Take(Named).Select(i => Path.GetRelativePath(prior.Folder.Folder, prior.Files[i])).ToList();
            var status = held.Count == prior.Files.Count ? "durable" : held.Count == 0 ? "new" : "partial";
            return new FactProof(f, hits.Count, samples, held.Count, missing, status);
        }).ToList();
        var worst = facts.Count == 0 ? null : facts.MaxBy(f => f.CleanHits)!;
        int hits = worst?.CleanHits ?? 0;
        string verdict, reason;
        if (hunt.Facts.Any(f => f.StartsWith(HuntKind.Sha1 + ":", StringComparison.Ordinal)) && clean.Folder.Copies.Count > 0)
            (verdict, reason) = ("review", $"A clean file has the same bytes: {clean.Folder.Copies[0]}");
        else if (hits >= options.DropAt) (verdict, reason) = ("drop", $"{hits:N0} clean files carry {Show(worst!.Fact)}");
        else if (hits > 0) (verdict, reason) = ("review", $"{hits:N0} clean {(hits == 1 ? "file carries" : "files carry")} {Show(worst!.Fact)}");
        else if (clean.Folder.Read == 0) (verdict, reason) = ("review", "No clean file was read");
        else if (clean.Folder.Unknown * 100 > (long)options.UnreadPercent * clean.Folder.Found)
            (verdict, reason) = ("review", $"No hit in {clean.Folder.Read:N0} files read; {Reasons(clean.Folder)}");
        else (verdict, reason) = ("keep", $"No hit in {clean.Folder.Read:N0} clean files" + (clean.Folder.Unknown > 0 ? $"; {Reasons(clean.Folder)}" : ""));
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
        return new HuntProof(verdict, reason, hits, worst?.Samples ?? [], [.. facts.OrderByDescending(f => f.CleanHits).Take(MaxFactsShown)], priorHits, standing);
    }

    private static string Show(string fact) => fact.Length > 80 ? fact[..77] + "..." : fact;
}
