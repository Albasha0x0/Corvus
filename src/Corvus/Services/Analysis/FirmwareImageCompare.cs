using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Diff;

namespace Corvus.Services.Analysis;

/// <summary>Compares two firmware filesystem images file by file and counts the function changes of each changed native binary.</summary>
public static class FirmwareImageCompare
{
    /// <summary>Most changed native binaries whose functions are compared in one call; limit lowers it.</summary>
    public const int MaxBinaries = 50;
    private const long MaxImageBytes = 1L << 30;
    private const int MaxDepth = 3;

    private static readonly AnalysisLimits Limits = new() { MaxItems = FolderCompare.DefaultMaxEntries };

    /// <summary>One changed native binary: path and function counts from the matched builds, or why they are unknown.</summary>
    private sealed record BinaryDiff(string Path, int? Matched, int? Identical, int? Changed, int? Removed, int? Added, string? Note)
    {
        public override string ToString() => Matched == null ? $"{Path}: functions unknown ({Note})"
            : $"{Path}: {Matched} matched, {Identical} identical, {Changed} changed, {Removed} removed, {Added} added" + (Note != null ? $" ({Note})" : "");
    }

    private sealed record Files(string Kind, SortedDictionary<string, byte[]> ByPath, List<string> Notes, bool Complete);

    /// <summary>The comparison of two firmware filesystem image files; null when either is not one, so the caller compares them as plain paths.</summary>
    public static FolderCompare.Comparison? Compare(string oldPath, string newPath, string? change, int offset, int limit, CancellationToken ct)
    {
        if (!File.Exists(oldPath) || !File.Exists(newPath)) return null;
        var view = string.IsNullOrWhiteSpace(change) ? "changed" : change.Trim().ToLowerInvariant();
        if (!FolderCompare.Views.Contains(view)) return null;
        if (Read(oldPath, ct) is not { } o || Read(newPath, ct) is not { } n) return null;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var rows = new List<FolderCompare.Entry>();
        foreach (var path in o.ByPath.Keys.Union(n.ByPath.Keys, StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            o.ByPath.TryGetValue(path, out var a);
            n.ByPath.TryGetValue(path, out var b);
            string state = a == null ? "added" : b == null ? "removed" : a.AsSpan().SequenceEqual(b) ? "unchanged" : "modified";
            rows.Add(new FolderCompare.Entry(state, a == null ? null : path, b == null ? null : path, KindOf(b ?? a!), a?.Length, b?.Length,
                null, null, null, null, null, null, null));
        }
        var selected = rows.Where(r => view switch
        {
            "all" => true,
            "changed" => r.Change != "unchanged",
            _ => r.Change == view,
        }).ToList();
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, FolderCompare.MaxLimit);
        var page = selected.Skip(offset).Take(limit).ToList();
        var native = rows.Where(r => r.Change == "modified" && r.Kind is "elf" or "pe").ToList();
        var notes = new List<string> { $"firmware images: {o.Kind} and {n.Kind}, compared file by file" };
        var diffs = new List<BinaryDiff>();
        int bound = Math.Min(limit, MaxBinaries);
        foreach (var r in native.Take(bound))
            diffs.Add(Diff(r.NewPath!, o.ByPath[r.NewPath!], n.ByPath[r.NewPath!], ct));
        notes.AddRange(diffs.Select(d => d.ToString()));
        if (native.Count > bound) notes.Add(Reached(native.Count, bound));
        int Count(string c) => rows.Count(r => r.Change == c);
        bool complete = o.Complete && n.Complete;
        var counts = new FolderCompare.Counts(Count("unchanged"), Count("modified"), Count("added"), Count("removed"), 0, 0, 0, 0, 0, 0, 0, !complete);
        FolderCompare.Side Side(string p, Files f) => new(p, "firmware image", f.ByPath.Count, f.ByPath.Values.Sum(v => (long)v.Length), f.Complete, f.ByPath.Count, 0, 0, f.Notes);
        return new FolderCompare.Comparison(Side(oldPath, o), Side(newPath, n), "bytes", true, counts, view, offset, selected.Count,
            offset + page.Count < selected.Count, page, notes, Math.Round(sw.Elapsed.TotalSeconds, 2));
    }

    /// <summary>Adds function counts for the modified native binaries on a page of two compared folders; the comparison is returned unchanged when none are modified.</summary>
    public static FolderCompare.Comparison WithBinaries(FolderCompare.Comparison comparison, string oldPath, string newPath, int limit, CancellationToken ct)
    {
        if (!Directory.Exists(oldPath) || !Directory.Exists(newPath)) return comparison;
        var native = comparison.Entries.Where(e => e.Change == "modified" && e.Kind is "elf" or "pe" && e.OldPath != null && e.NewPath != null).ToList();
        if (native.Count == 0) return comparison;
        var diffs = new List<BinaryDiff>();
        int bound = Math.Min(limit, MaxBinaries);
        foreach (var e in native.Take(bound))
        {
            byte[] a, b;
            try
            {
                a = File.ReadAllBytes(Path.Combine(oldPath, e.OldPath!));
                b = File.ReadAllBytes(Path.Combine(newPath, e.NewPath!));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                diffs.Add(new BinaryDiff(e.NewPath!, null, null, null, null, null, "not read: " + ex.Message));
                continue;
            }
            diffs.Add(Diff(e.NewPath!, a, b, ct));
        }
        var notes = comparison.Notes.Concat(diffs.Select(d => d.ToString()));
        if (native.Count > bound) notes = notes.Append(Reached(native.Count, bound));
        return comparison with { Notes = [.. notes] };
    }

    private static string Reached(int changed, int bound) =>
        $"binary limit reached: {changed - bound} of {changed} changed binaries were not compared (at most {bound} per call; limit sets it, up to {MaxBinaries})";

    private static string? KindOf(byte[] bytes) => Blob.Identify(bytes.AsSpan(0, Math.Min(bytes.Length, 4096))) switch
    {
        "elf" => "elf",
        "native PE" or "NativeAOT executable" => "pe",
        "mach-o" => "macho",
        _ => null,
    };

    /// <summary>The files of a firmware filesystem image by path; null when the file is not one or is over 1 GiB.</summary>
    private static Files? Read(string path, CancellationToken ct)
    {
        if (new FileInfo(path).Length > MaxImageBytes) return null;
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        var notes = new List<string>();
        var kind = Flatten(File.ReadAllBytes(path), Path.GetFileName(path), "", 0, files, notes, ct);
        if (kind == null || files.Count == 0) return null;
        bool complete = files.Count < Limits.MaxItems;
        if (!complete) notes.Add($"stopped at {Limits.MaxItems:N0} files: the rest are unknown");
        return new Files(kind, files, notes, complete);
    }

    private static bool Filesystem(string kind) =>
        kind is "squashfs" or "cramfs" or "jffs2" or "UBI" or "UBIFS" or "cpio" or "romfs" or "FIT" || kind.StartsWith("ext", StringComparison.Ordinal) || kind.StartsWith("FAT", StringComparison.Ordinal);

    /// <summary>Adds the files of a filesystem, or of each filesystem part of a firmware image; returns the container kind, or null for anything else.</summary>
    private static string? Flatten(byte[] data, string name, string prefix, int depth, SortedDictionary<string, byte[]> files, List<string> notes, CancellationToken ct)
    {
        ContainerContents c;
        try { c = Containers.Open(data, name, Limits, ct, allFiles: true); }
        catch (ToolError) { return null; }
        if (Filesystem(c.Kind))
        {
            foreach (var item in c.Items)
                if (files.Count < Limits.MaxItems) files[prefix + item.Name.TrimStart('.', '/')] = item.Bytes;
            notes.AddRange(c.Notes);
            return c.Kind;
        }
        if (c.Kind != "firmware image" || depth >= MaxDepth) return null;
        var parts = new List<string>();
        foreach (var item in c.Items)
            if (Flatten(item.Bytes, item.Name, prefix + item.Name + "/", depth + 1, files, notes, ct) is { } part) parts.Add(part);
        return parts.Count > 0 ? "firmware image of " + string.Join(", ", parts) : null;
    }

    private static BinaryDiff Diff(string path, byte[] oldBytes, byte[] newBytes, CancellationToken ct)
    {
        BinaryDiff Unknown(string why) => new(path, null, null, null, null, null, why);
        try
        {
            var (oldImage, newImage) = (NativeImageLoader.FromBytes(oldBytes, path), NativeImageLoader.FromBytes(newBytes, path));
            if (oldImage.Arch != newImage.Arch) return Unknown($"architectures differ ({oldImage.Arch}, {newImage.Arch}): functions not matched");
            var (oldIndex, newIndex) = (NativeCodeIndex.Build(oldImage, ct: ct), NativeCodeIndex.Build(newImage, ct: ct));
            if (oldIndex.Support != CodeSupport.Full || newIndex.Support != CodeSupport.Full)
                return Unknown((oldIndex.SupportNote ?? newIndex.SupportNote ?? "instructions are not decoded for this architecture") + ": functions unknown");
            var match = BuildMatcher.Match(ImagePrints.Of(oldIndex, ct), ImagePrints.Of(newIndex, ct), new MatchOptions(), ct);
            int identical = match.Pairs.Count(p => !match.Old.Functions[p.Old].Failed && match.Old.Functions[p.Old].BytesHash == match.New.Functions[p.New].BytesHash);
            return new BinaryDiff(path, match.Pairs.Count, identical, match.Pairs.Count - identical, match.ByOld.Count(m => m == null), match.ByNew.Count(m => m == null),
                match.Ambiguous.Count > 0 ? $"{match.Ambiguous.Count} ambiguous function(s) are counted as removed or added" : null);
        }
        catch (Exception ex) when (ex is ToolError or InvalidDataException or BadImageFormatException or NotSupportedException)
        {
            return Unknown("not read: " + ex.Message);
        }
    }
}
