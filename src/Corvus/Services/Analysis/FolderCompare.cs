using System.ComponentModel;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using Corvus.Core;
using Corvus.Native.Pe;
using Blob = Corvus.Core.Blob;

namespace Corvus.Services.Analysis;

/// <summary>
/// Two folders, zip-family archives or files compared entry by entry: streaming hashes (an archive's central directory CRC-32
/// and size, so archive entries are not read), moves by content, case-only renames, links reported and never followed, and an
/// incomplete or unreadable side never reported as unchanged. Inventories stay in a small LRU so paging does not re-hash.
/// </summary>
public sealed class FolderCompare
{
    public const int DefaultLimit = 100, MaxLimit = 2000, DefaultMaxEntries = 200_000, MaxEntriesCap = 1_000_000;
    private const int MaxDetails = 200, MaxCandidates = 5, MaxDiffLines = 80, MaxDiffBytes = 64 * 1024, CacheCapacity = 8, ProbeBytes = 4096;
    private const long MaxFactBytes = 256L << 20;
    public static readonly string[] Views = ["changed", "modified", "added", "removed", "moved", "renamed", "unreadable", "unchanged", "all"];

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json", ".xml", ".config", ".ini", ".cfg", ".conf", ".txt", ".yaml", ".yml", ".toml", ".props", ".targets", ".csproj", ".nuspec",
        ".properties", ".plist", ".manifest", ".md", ".csv", ".resx", ".xaml", ".js", ".css", ".html", ".htm", ".lua", ".sh", ".bat", ".cmd", ".ps1",
    };
    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll", ".exe", ".sys", ".winmd", ".so", ".dylib", ".node", ".ocx", ".cpl", ".drv", ".efi",
    };

    /// <summary>Path of the walked root plus the walk settings, to its last inventory.</summary>
    private readonly LinkedList<(string Key, Inventory Inventory)> _cache = new();

    /// <summary>Total bytes hashed per call (both sides); past it entries are compared by size only.</summary>
    internal long MaxHashBytes { get; set; } = 64L << 30;

    public sealed record Side(
        string Path,
        [property: Description("folder, zip (central directory: CRC-32 and size, entries not read) or file.")] string Kind,
        int Entries, long Bytes,
        [property: Description("False when the walk stopped (maxEntries, a folder not listed): absent paths are then unmatched, not added or removed.")] bool Complete,
        [property: Description("Files hashed in this call; Reused: hashes kept from an earlier call (same path, size and write time).")] int Hashed, int Reused,
        [property: Description("Archive entries whose content was read (for details on this page only).")] int EntryReads,
        IReadOnlyList<string> Problems);

    public sealed record Counts(int Unchanged, int Modified, int Added, int Removed, int Moved, int MovedAmbiguous, int Renamed, int Unreadable, int Unverified, int Unmatched,
        [property: Description("Links (symbolic links, junctions) among the entries; compared by target, never followed.")] int Links,
        [property: Description("A side is incomplete: Unchanged is a lower bound.")] bool UnchangedAtLeast);

    public sealed record Facts(
        [property: Description("dotnet, pe, elf or macho.")] string Format,
        string? Machine, string? Timestamp,
        [property: Description("Version resource FileVersion (PE).")] string? Version,
        string? Mvid, string? AssemblyVersion, string? BuildId);

    public sealed record Entry(
        [property: Description("modified, added, removed, moved (same content, other path), moved_ambiguous, renamed (case only, same content), " +
                               "unreadable (locked or denied: unknown), unverified (equal size, not hashed: over the byte budget), unmatched (the other side is incomplete), unchanged.")] string Change,
        string? OldPath, string? NewPath,
        [property: Description("dotnet, pe, elf, macho, zip, text, link or file; null past the first 200 entries of a page.")] string? Kind,
        long? OldSize, long? NewSize,
        Facts? Old, Facts? New,
        [property: Description("moved_ambiguous: paths on the other side with the same content (up to five) and their count.")] IReadOnlyList<string>? Candidates, int? CandidateCount,
        [property: Description("A ready-to-run next call for this entry.")] string? NextStep,
        [property: Description("Unified diff of a text file of up to 64 KiB, cut at 80 lines.")] string? Diff,
        string? Note);

    public sealed record Comparison(
        Side Old, Side New,
        [property: Description("sha256 (folders and files), or crc32+size when a side is an archive.")] string HashBasis,
        bool CaseSensitive, Counts Counts,
        [property: Description("The change filter of Entries.")] string View,
        int Offset, int Total, bool Truncated,
        IReadOnlyList<Entry> Entries,
        IReadOnlyList<string> Notes, double Seconds);

    private sealed record Row(string Change, InventoryEntry? Old, InventoryEntry? New, IReadOnlyList<string>? Candidates = null, int? CandidateCount = null, string? Note = null)
    {
        public string SortKey => New?.Path ?? Old!.Path;
    }

    public Comparison Compare(string oldPath, string newPath, string? change, bool? caseSensitive, string? exclude, int maxEntries, int offset, int limit,
        Action<int, int>? progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var view = string.IsNullOrWhiteSpace(change) ? "changed" : change.Trim().ToLowerInvariant();
        if (!Views.Contains(view))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown change filter '{change}'.", "use " + string.Join(", ", Views));
        if (maxEntries is < 1 or > MaxEntriesCap)
            throw new ToolError(ErrorCode.InvalidArgument, $"maxEntries must be 1-{MaxEntriesCap:N0}, not {maxEntries}.");
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, MaxLimit);
        var oldRoot = Root(oldPath, "oldPath");
        var newRoot = Root(newPath, "newPath");
        var filter = new PathFilter(exclude);
        var notes = new List<string>();

        var (oldInv, oldPrevious) = Walk(oldRoot, filter, exclude, maxEntries, ct);
        var (newInv, newPrevious) = Walk(newRoot, filter, exclude, maxEntries, ct);
        long budget = MaxHashBytes;
        int toHash = new[] { oldInv, newInv }.Sum(i => i.Kind == Core.Inventory.Zip ? 0 : i.Entries.Count(e => e.LinkTarget == null && !e.HasContentKey));
        int hashedBefore = 0;
        if (oldInv.Kind != Core.Inventory.Zip || newInv.Kind != Core.Inventory.Zip)
        {
            StreamingInventory.Hash(oldInv, oldPrevious, ref budget, d => progress?.Invoke(d, toHash), ct);
            hashedBefore = oldInv.Hashed + oldInv.Reused;
            StreamingInventory.Hash(newInv, newPrevious, ref budget, d => progress?.Invoke(hashedBefore + d, toHash), ct);
        }
        Remember(Key(oldRoot, exclude, maxEntries), oldInv);
        Remember(Key(newRoot, exclude, maxEntries), newInv);

        bool sha = oldInv.Kind != Core.Inventory.Zip && newInv.Kind != Core.Inventory.Zip;
        bool ignoreCase = !(caseSensitive ?? !(OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()));
        if (ignoreCase && (CaseCollision(oldInv) || CaseCollision(newInv)))
        {
            ignoreCase = false;
            notes.Add("paths that differ only by case exist on one side: compared case-sensitively");
        }
        var rows = Pair(oldInv, newInv, sha, ignoreCase, ct);
        var counts = Count(rows, oldInv.Complete && newInv.Complete);
        if (!oldInv.Complete || !newInv.Complete)
            notes.Add("a side is incomplete: paths absent from it are 'unmatched', and unchanged is a lower bound");
        if (rows.Any(r => r.Change == "unverified"))
            notes.Add($"the hash budget ({MaxHashBytes:N0} bytes) ran out: entries past it were compared by size only (unverified)");
        if (oldInv.Kind == Core.Inventory.File && newInv.Kind == Core.Inventory.File && oldInv.Problems.Count == 0 && newInv.Problems.Count == 0)
            notes.Add("two single files: compared as one entry");

        var selected = rows.Where(r => view switch
        {
            "all" => true,
            "changed" => r.Change != "unchanged",
            "moved" => r.Change is "moved" or "moved_ambiguous",
            _ => r.Change == view,
        }).OrderBy(r => r.SortKey, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.SortKey, StringComparer.Ordinal).ToList();
        var page = selected.Skip(offset).Take(limit).ToList();
        if (page.Count > MaxDetails) notes.Add($"kind, facts, next steps and diffs for the first {MaxDetails} entries of the page");

        var entries = new List<Entry>(page.Count);
        using (var oldReader = new StreamingInventory.ContentReader(oldInv))
        using (var newReader = new StreamingInventory.ContentReader(newInv))
            for (int i = 0; i < page.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                entries.Add(i < MaxDetails ? Detail(page[i], oldInv, newInv, oldReader, newReader) : Plain(page[i], null));
            }

        return new Comparison(Summary(oldInv), Summary(newInv), sha ? "sha256" : "crc32+size", !ignoreCase, counts, view, offset, selected.Count,
            offset + page.Count < selected.Count, entries, notes, Math.Round(sw.Elapsed.TotalSeconds, 2));
    }

    private static string Root(string path, string parameter)
    {
        string full;
        try { full = Path.GetFullPath((path ?? "").Trim()); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ToolError(ErrorCode.InvalidArgument, $"{parameter} '{path}' is not a valid path: {ex.Message}");
        }
        if (string.IsNullOrWhiteSpace(path) || !Path.Exists(full))
            throw new ToolError(ErrorCode.NotFound, $"{parameter}: nothing at '{path}'.", "pass a folder, a zip-family archive (.zip, .nupkg, .apk, ...) or a file");
        return Path.TrimEndingDirectorySeparator(full);
    }

    private static string Key(string root, string? exclude, int maxEntries) => $"{root}|{exclude}|{maxEntries}";

    /// <summary>A fresh walk, reusing the hashes of the last walk of the same root; an unchanged archive's whole inventory is reused.</summary>
    private (Inventory Inventory, IReadOnlyDictionary<string, InventoryEntry>? Previous) Walk(string root, PathFilter filter, string? exclude, int maxEntries, CancellationToken ct)
    {
        var previous = Recall(Key(root, exclude, maxEntries));
        if (previous is { Kind: Core.Inventory.Zip, Complete: true } && File.Exists(root))
        {
            var info = new FileInfo(root);
            if (previous.FileStamp == (info.Length, info.LastWriteTimeUtc.Ticks))
            {
                previous.EntryReads = 0;
                return (previous, null);
            }
        }
        var inv = StreamingInventory.Enumerate(root, filter, maxEntries, ct);
        return (inv, previous?.Entries.Where(e => e.Sha256 != null).ToDictionary(e => e.Path, StringComparer.Ordinal));
    }

    private Inventory? Recall(string key)
    {
        lock (_cache)
            for (var node = _cache.First; node != null; node = node.Next)
                if (node.Value.Key == key) return node.Value.Inventory;
        return null;
    }

    private void Remember(string key, Inventory inv)
    {
        lock (_cache)
        {
            for (var node = _cache.First; node != null; node = node.Next)
                if (node.Value.Key == key) { _cache.Remove(node); break; }
            _cache.AddFirst((key, inv));
            while (_cache.Count > CacheCapacity) _cache.RemoveLast();
        }
    }

    private static bool CaseCollision(Inventory inv) =>
        inv.Entries.Count != inv.Entries.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();

    private enum Same { Yes, No, Unverified, Unreadable }

    private static Same Equal(InventoryEntry a, InventoryEntry b, bool sha)
    {
        if (a.LinkTarget != null || b.LinkTarget != null)
            return a.LinkTarget != null && b.LinkTarget != null && string.Equals(a.LinkTarget, b.LinkTarget, StringComparison.OrdinalIgnoreCase) ? Same.Yes : Same.No;
        if (a.Error != null || b.Error != null) return Same.Unreadable;
        if (a.Size != b.Size) return Same.No;
        if (sha && a.Sha256 != null && b.Sha256 != null) return a.Sha256 == b.Sha256 ? Same.Yes : Same.No;
        if (a.Crc32 != null && b.Crc32 != null) return a.Crc32 == b.Crc32 ? Same.Yes : Same.No;
        return Same.Unverified;
    }

    /// <summary>The move key: content hash, or CRC-32 and size; null for links, empty files and unread entries.</summary>
    private static string? ContentKey(InventoryEntry e, bool sha) =>
        e.LinkTarget != null || e.Error != null || e.Size == 0 ? null
        : sha ? e.Sha256
        : e.Crc32 is { } crc ? $"{crc:x8}:{e.Size}" : null;

    private static List<Row> Pair(Inventory oldInv, Inventory newInv, bool sha, bool ignoreCase, CancellationToken ct)
    {
        var rows = new List<Row>();
        if (oldInv.Kind == Core.Inventory.File && newInv.Kind == Core.Inventory.File)
        {
            var (a, b) = (oldInv.Entries[0], newInv.Entries[0]);
            rows.Add(new Row(Change(Equal(a, b, sha)), a, b));
            return rows;
        }
        var comparer = ignoreCase ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var byPath = newInv.Entries.ToDictionary(e => e.Path, comparer);
        var removed = new List<InventoryEntry>();
        var paired = new HashSet<InventoryEntry>(ReferenceEqualityComparer.Instance);
        foreach (var o in oldInv.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (!byPath.TryGetValue(o.Path, out var n)) { removed.Add(o); continue; }
            paired.Add(n);
            var same = Equal(o, n, sha);
            bool caseOnly = !string.Equals(o.Path, n.Path, StringComparison.Ordinal);
            rows.Add(caseOnly && same == Same.Yes ? new Row("renamed", o, n, Note: "only the case of the path changed")
                : new Row(Change(same), o, n, Note: caseOnly ? "the case of the path changed too" : null));
        }
        var added = newInv.Entries.Where(e => !paired.Contains(e)).ToList();

        // Moves: unpaired entries grouped by content; a unique pair is a move, more candidates on either side are ambiguous.
        var oldByKey = removed.Where(e => ContentKey(e, sha) != null).GroupBy(e => ContentKey(e, sha)!).ToDictionary(g => g.Key, g => g.ToList());
        var newByKey = added.Where(e => ContentKey(e, sha) != null).GroupBy(e => ContentKey(e, sha)!).ToDictionary(g => g.Key, g => g.ToList());
        var moved = new HashSet<InventoryEntry>(ReferenceEqualityComparer.Instance);
        foreach (var (key, olds) in oldByKey)
        {
            if (!newByKey.TryGetValue(key, out var news)) continue;
            if (olds.Count == 1 && news.Count == 1)
                rows.Add(new Row("moved", olds[0], news[0]));
            else
            {
                foreach (var o in olds)
                    rows.Add(new Row("moved_ambiguous", o, null, news.Take(MaxCandidates).Select(n => n.Path).ToList(), news.Count));
                foreach (var n in news)
                    rows.Add(new Row("moved_ambiguous", null, n, olds.Take(MaxCandidates).Select(o => o.Path).ToList(), olds.Count));
            }
            moved.UnionWith(olds);
            moved.UnionWith(news);
        }
        foreach (var o in removed.Where(e => !moved.Contains(e)))
            rows.Add(new Row(newInv.Complete ? "removed" : "unmatched", o, null, Note: newInv.Complete ? null : "the new side is incomplete"));
        foreach (var n in added.Where(e => !moved.Contains(e)))
            rows.Add(new Row(oldInv.Complete ? "added" : "unmatched", null, n, Note: oldInv.Complete ? null : "the old side is incomplete"));
        return rows;
    }

    private static string Change(Same same) => same switch
    {
        Same.Yes => "unchanged",
        Same.No => "modified",
        Same.Unreadable => "unreadable",
        _ => "unverified",
    };

    private static Counts Count(List<Row> rows, bool complete)
    {
        int C(string change) => rows.Count(r => r.Change == change);
        return new Counts(C("unchanged"), C("modified"), C("added"), C("removed"), C("moved"), C("moved_ambiguous"), C("renamed"), C("unreadable"),
            C("unverified"), C("unmatched"), rows.Count(r => (r.Old ?? r.New)!.LinkTarget != null), !complete);
    }

    private static Side Summary(Inventory inv)
    {
        var problems = inv.Problems.Take(20).ToList();
        int unreadable = inv.Entries.Count(e => e.Error != null);
        if (unreadable > 0) problems.Add($"{unreadable} file(s) could not be read (locked or denied): reported unreadable");
        return new Side(inv.Root, inv.Kind, inv.Entries.Count, inv.Entries.Sum(e => e.Size), inv.Complete, inv.Hashed, inv.Reused, inv.EntryReads, problems);
    }

    private static Entry Plain(Row r, string? kind, Facts? oldFacts = null, Facts? newFacts = null, string? next = null, string? diff = null, string? note = null) =>
        new(r.Change, r.Old?.Path, r.New?.Path, kind, r.Old?.LinkTarget != null ? null : r.Old?.Size, r.New?.LinkTarget != null ? null : r.New?.Size,
            oldFacts, newFacts, r.Candidates, r.CandidateCount, next, diff, note ?? r.Note);

    private static Entry Detail(Row r, Inventory oldInv, Inventory newInv, StreamingInventory.ContentReader oldReader, StreamingInventory.ContentReader newReader)
    {
        var any = (r.New ?? r.Old)!;
        if (any.LinkTarget != null)
            return Plain(r, "link", note: $"link to {any.LinkTarget} (not followed)" + (r.Old?.LinkTarget is { } t && r.New?.LinkTarget is { } u && t != u ? $"; was {t}" : ""));
        var ext = Path.GetExtension(any.Path);
        string guess = TextExtensions.Contains(ext) ? "text" : "file";
        if (r.Change is "unchanged" or "unreadable" or "unverified" or "renamed") return Plain(r, guess);
        string kind = Kind(r.New != null ? Probe(newInv, r.New, newReader, ext) : null) ?? Kind(r.Old != null ? Probe(oldInv, r.Old, oldReader, ext) : null) ?? guess;

        Facts? oldFacts = null, newFacts = null;
        if (kind is "dotnet" or "pe" or "elf" or "macho" && r.Change != "moved")
        {
            if (r.Old != null) oldFacts = FactsOf(oldReader.Read(r.Old, MaxFactBytes, whole: true), kind, any.Path);
            if (r.New != null) newFacts = FactsOf(newReader.Read(r.New, MaxFactBytes, whole: true), kind, any.Path);
        }
        string? diff = null, note = null;
        if (kind == "text" && r.Change == "modified")
        {
            var a = oldReader.Read(r.Old!, MaxDiffBytes, whole: true);
            var b = newReader.Read(r.New!, MaxDiffBytes, whole: true);
            if (a is { } x && b is { } y && Blob.LooksLikeText(x) && Blob.LooksLikeText(y))
                diff = CapLines(TextDiff.Unified(Encoding.UTF8.GetString(x), Encoding.UTF8.GetString(y), "old/" + r.Old!.Path, "new/" + r.New!.Path));
            else note = "text over 64 KiB or not text: no inline diff";
        }
        if (oldFacts?.Mvid != null && oldFacts.Mvid == newFacts?.Mvid)
            note = "same MVID: the same compilation with other bytes (signature, resources or post-processing)";
        return Plain(r, kind, oldFacts, newFacts, NextStep(r, kind, oldInv, newInv), diff, note);
    }

    /// <summary>The first bytes of an entry; archive entries are read only when their extension says binary or text.</summary>
    private static byte[]? Probe(Inventory inv, InventoryEntry e, StreamingInventory.ContentReader reader, string ext) =>
        inv.Kind == Core.Inventory.Zip && !BinaryExtensions.Contains(ext) && !TextExtensions.Contains(ext) ? null : reader.Read(e, ProbeBytes, whole: false);

    private static string? Kind(byte[]? prefix) => prefix == null ? null : Blob.Identify(prefix) switch
    {
        ".NET assembly" => "dotnet",
        "native PE" or "NativeAOT executable" => "pe",
        "elf" => "elf",
        "mach-o" => "macho",
        "zip" => "zip",
        "text" => "text",
        _ => "file",
    };

    private static string CapLines(string diff)
    {
        var lines = diff.Split('\n');
        return lines.Length <= MaxDiffLines ? diff : string.Join('\n', lines.Take(MaxDiffLines)) + $"\n... {lines.Length - MaxDiffLines} more line(s)";
    }

    private static Facts? FactsOf(byte[]? bytes, string kind, string path)
    {
        if (bytes == null) return null;
        try
        {
            if (kind is "elf" or "macho")
                return NativeImageFacts.Of(path, bytes) is { } f ? new Facts(kind, f.Facts.Machine, null, null, null, null, f.Facts.BuildId) : null;
            using var pe = new PEReader(new MemoryStream(bytes, writable: false));
            var coff = pe.PEHeaders.CoffHeader;
            string? mvid = null, assemblyVersion = null;
            if (pe.HasMetadata)
            {
                var md = pe.GetMetadataReader();
                mvid = md.GetGuid(md.GetModuleDefinition().Mvid).ToString();
                if (md.IsAssembly) assemblyVersion = md.GetAssemblyDefinition().Version.ToString();
            }
            string? version = null;
            try
            {
                var info = PeFile.FromBytes(bytes, path).VersionInfo;
                version = info?.Fixed is { FileVersion: not 0 } fx ? fx.FileVersionText : info?.Get("FileVersion");
            }
            catch (ToolError) { }
            return new Facts(kind, PeNames.Machine((ushort)coff.Machine), $"0x{(uint)coff.TimeDateStamp:X8}", version, mvid, assemblyVersion, null);
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ToolError) { return null; }
    }

    private static string Location(Inventory inv, InventoryEntry e) => inv.Kind switch
    {
        Core.Inventory.Folder => Path.Combine(inv.Root, e.Path.Replace('/', Path.DirectorySeparatorChar)),
        Core.Inventory.Zip => $"{inv.Root}!/{e.Path}",
        _ => inv.Root,
    };

    private static string? NextStep(Row r, string kind, Inventory oldInv, Inventory newInv)
    {
        if (r.Change is "moved" or "moved_ambiguous")
            return kind is "dotnet" or "pe" or "elf" or "macho" ? "same bytes at another path: nothing to compare; load from the new path" : null;
        if (r.Change != "modified") return null;
        if (oldInv.Kind == Core.Inventory.Zip || newInv.Kind == Core.Inventory.Zip)
            return kind is "dotnet" or "pe" or "elf" or "macho"
                ? $"unpack_container path=\"{(oldInv.Kind == Core.Inventory.Zip ? oldInv.Root : newInv.Root)}\" (each archive side), then compare the extracted files"
                : null;
        var (a, b) = (Location(oldInv, r.Old!), Location(newInv, r.New!));
        var name = Path.GetFileName(b);
        var load = $"load_assembly path=\"{a}\"; load_assembly path=\"{b}\"; ";
        if (name.Equals("global-metadata.dat", StringComparison.OrdinalIgnoreCase))
            return $"Il2Cpp metadata changed: load both game folders, then update_to_new_build oldImage=GameAssembly.dll newImage=GameAssembly.dll#2 (Il2Cpp mapping)";
        return kind switch
        {
            "dotnet" => load + $"compare_assemblies oldAssembly={name} newAssembly={name}#2",
            "pe" or "elf" or "macho" => load + $"compare_native_images oldImage={name} newImage={name}#2; update_to_new_build carries names, patches and notes",
            "zip" => $"compare_folders oldPath=\"{a}\" newPath=\"{b}\"",
            _ => null,
        };
    }
}
