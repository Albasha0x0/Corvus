using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>Qt resource collections: a binary .rcc file ("qres", versions 1 to 3) or the arrays rcc compiles into a program.</summary>
/// <remarks>Big-endian; tree nodes are 14 bytes, or 22 with a modification time; zlib data is in qCompress form.</remarks>
internal static class QtResources
{
    public const string Kind = "Qt resource collection (rcc)";
    private const ushort Compressed = 1, Directory = 2, CompressedZstd = 4;
    private const int MaxNodes = 1_000_000, MaxDepth = 64;

    /// <summary>Where one collection's arrays start in the bytes, and its format version (2 stands for 2 and 3 when compiled in).</summary>
    public sealed record Collection(int Version, int Tree, int Names, int Data, int? At = null);

    /// <summary>One file; Language 1 and Territory 0 are the default locale, Modified is null in version 1 or when zero.</summary>
    public sealed record Entry(string Path, int Language, int Territory, string? Compression, long Stored, int DataAt, DateTime? Modified)
    {
        public bool IsDefaultLocale => Language is 0 or 1 && Territory == 0;
    }

    /// <summary>A binary .rcc file: "qres" and a format version from 1 to 3.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 20 && b.StartsWith("qres"u8) && BinaryPrimitives.ReadUInt32BigEndian(b[4..]) is >= 1 and <= 3;

    /// <summary>The collection a binary .rcc file holds; throws <see cref="ToolError"/> when its offsets lie outside the file.</summary>
    public static Collection Header(ReadOnlySpan<byte> b, string name)
    {
        if (!Looks(b)) throw Malformed(name, "no qres header");
        int version = (int)BinaryPrimitives.ReadUInt32BigEndian(b[4..]);
        uint tree = BinaryPrimitives.ReadUInt32BigEndian(b[8..]), data = BinaryPrimitives.ReadUInt32BigEndian(b[12..]), names = BinaryPrimitives.ReadUInt32BigEndian(b[16..]);
        if (tree >= b.Length || data >= b.Length || names >= b.Length) throw Malformed(name, "an array offset lies past the end");
        return new Collection(version, (int)tree, (int)names, (int)data);
    }

    /// <summary>The collections compiled into a program image whose names pass Qt's hash and data entries chain; empty when none.</summary>
    public static List<Collection> Embedded(byte[] image, CancellationToken ct)
    {
        var found = new List<Collection>();
        var refs = new Lazy<CodeReferences?>(() => CodeReferences.Read(image));
        ReadOnlySpan<byte> root = [0, 0, 0, 0, 0, 2];
        var span = image.AsSpan();
        for (int at = 0, next; at < image.Length && (next = span[at..].IndexOf(root)) >= 0;)
        {
            ct.ThrowIfCancellationRequested();
            int tree = at + next;
            at = tree + 1;
            // Compilers align an array of 16 bytes or more, and a tree has at least two nodes.
            if (tree % 4 != 0 || tree + 14 > image.Length || BinaryPrimitives.ReadUInt32BigEndian(span[(tree + 10)..]) != 1
                || BinaryPrimitives.ReadUInt32BigEndian(span[(tree + 6)..]) is 0 or > 65535) continue;
            foreach (int version in (int[])[2, 1])
                if (Locate(image, tree, version, refs, ct) is { } c) { found.Add(c); break; }
        }
        return found;
    }

    /// <summary>The names and data arrays of a tree at <paramref name="tree"/>; null when they are not found.</summary>
    private static Collection? Locate(byte[] b, int tree, int version, Lazy<CodeReferences?> refs, CancellationToken ct)
    {
        var nodes = Walk(b, tree, version);
        if (nodes == null || nodes.Count < 2) return null;
        var nameOffsets = nodes.Skip(1).Select(n => n.Name).Distinct().Order().ToArray();
        // Each name is written once and back to back, so the gap to the next offset gives a name's length.
        var lengths = new int[nameOffsets.Length - 1];
        for (int k = 0; k < lengths.Length; k++)
        {
            long gap = nameOffsets[k + 1] - (long)nameOffsets[k] - 6;
            if (gap <= 0 || (gap & 1) != 0 || gap > 2 * ushort.MaxValue) return null;
            lengths[k] = (int)(gap / 2);
        }
        var files = nodes.Where(n => !n.IsDirectory).Select(n => n.DataOffset).Distinct().Order().ToArray();
        if (files.Length == 0 || files[0] != 0) return null;
        int treeEnd = tree + (nodes.Max(n => n.Index) + 1) * (version >= 2 ? 22 : 14);
        // MSVC places data, names and tree in that order; GCC the reverse.
        int names = Names(b, nameOffsets, lengths, tree - 1, Math.Max(0, tree - (8 << 20)), tree, ct);
        if (names >= 0)
        {
            int data = files.Length > 1 ? Chain(b, files, names, backward: true) : Single(b, tree, names, names, backward: true, refs.Value);
            if (data >= 0) return new Collection(version, tree, names, data, tree);
        }
        names = Names(b, nameOffsets, lengths, treeEnd, (int)Math.Min(b.Length - 6L, treeEnd + (8L << 20)), b.Length, ct);
        if (names < 0) return null;
        int last = (int)nameOffsets[^1];
        int namesEnd = names + last + 6 + 2 * BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(names + last));
        int after = files.Length > 1 ? Chain(b, files, namesEnd, backward: false) : Single(b, tree, names, namesEnd, backward: false, refs.Value);
        return after < 0 ? null : new Collection(version, tree, names, after, tree);
    }

    /// <summary>The first start toward <paramref name="to"/> where every name offset holds a valid name; -1 when none.</summary>
    private static int Names(byte[] b, uint[] offsets, int[] lengths, int from, int to, int limit, CancellationToken ct)
    {
        int step = to >= from ? 1 : -1;
        for (int s = from; step > 0 ? s <= to : s >= to; s += step)
        {
            if ((s & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (s + (long)offsets[^1] + 6 > limit) { if (step > 0) break; continue; }
            // A tree of one name has no gap to measure: a file name of at most 255 characters is assumed.
            bool fits = lengths.Length > 0 || BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(s + (int)offsets[0])) is > 0 and <= 255;
            for (int k = 0; k < lengths.Length && fits; k++) fits = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(s + (int)offsets[k])) == lengths[k];
            if (fits && offsets.All(o => NameAt(b, s + o, limit) != null)) return s;
        }
        return -1;
    }

    /// <summary>The data array start nearest to <paramref name="edge"/> whose entry sizes chain through every file offset.</summary>
    private static int Chain(byte[] b, uint[] files, int edge, bool backward)
    {
        Span<byte> first = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(first, files[1] - 4);
        int limit = backward ? edge : b.Length;
        bool Fits(int d)
        {
            for (int k = 0; k < files.Length; k++)
            {
                long p = d + (long)files[k];
                if (p + 4 > limit) return false;
                long end = files[k] + 4L + BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)p));
                if (k + 1 < files.Length ? end != files[k + 1] : d + end > limit) return false;
            }
            return true;
        }
        if (backward)
        {
            for (int hi = edge, d; (d = b.AsSpan(0, hi).LastIndexOf(first)) >= 0; hi = d + 3)
                if (Fits(d)) return d;
        }
        else
        {
            for (int lo = edge, d; lo < b.Length && (d = b.AsSpan(lo).IndexOf(first)) >= 0; lo += d + 1)
                if (Fits(lo + d)) return lo + d;
        }
        return -1;
    }

    /// <summary>A one-file data array start near <paramref name="edge"/>; with code references it must be loaded beside the tree.</summary>
    private static int Single(byte[] b, int tree, int names, int edge, bool backward, CodeReferences? refs)
    {
        bool Fits(long d)
        {
            if (d < 0 || d + 4 > b.Length) return false;
            long end = d + 4L + BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)d));
            if (end <= d + 4 || end > b.Length) return false;
            return backward ? end <= edge && end >= edge - 16 && !b.AsSpan((int)end, edge - (int)end).ContainsAnyExcept((byte)0) : d >= edge && d <= edge + 32;
        }
        if (refs != null)
        {
            foreach (var site in refs.Sites(tree))
                foreach (var target in refs.Near(site, 96))
                    if (target != tree && target != names && Fits(target)) return (int)target;
            return -1;
        }
        foreach (int align in (int[])[16, 4, 1])
            if (backward)
            {
                for (int d = edge - 5, low = Math.Max(0, edge - (64 << 20)); d >= low; d--)
                    if (d % align == 0 && Fits(d)) return d;
            }
            else
            {
                for (int d = edge; d <= edge + 32; d++)
                    if (d % align == 0 && Fits(d)) return d;
            }
        return -1;
    }

    private readonly record struct Node(int Index, uint Name, ushort Flags, uint Count, uint First, ushort Territory, ushort Language, uint DataOffset, ulong Modified)
    {
        public bool IsDirectory => (Flags & Directory) != 0;
    }

    /// <summary>Every node reachable from the root, root first; null when a node lies outside the bytes or a child index does not follow its parent.</summary>
    private static List<Node>? Walk(byte[] b, int tree, int version)
    {
        int size = version >= 2 ? 22 : 14;
        var nodes = new List<Node>();
        var seen = new HashSet<int>();
        var todo = new Stack<int>();
        todo.Push(0);
        while (todo.Count > 0)
        {
            int i = todo.Pop();
            if (!seen.Add(i)) continue;
            long p = tree + (long)i * size;
            if (p + size > b.Length || nodes.Count >= MaxNodes) return null;
            var s = b.AsSpan((int)p, size);
            uint name = BinaryPrimitives.ReadUInt32BigEndian(s);
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(s[4..]);
            ulong modified = size == 22 ? BinaryPrimitives.ReadUInt64BigEndian(s[14..]) : 0;
            if ((flags & Directory) != 0)
            {
                uint count = BinaryPrimitives.ReadUInt32BigEndian(s[6..]), first = BinaryPrimitives.ReadUInt32BigEndian(s[10..]);
                if (count > 65535 || count > 0 && first <= (uint)i || first + (long)count > MaxNodes) return null;
                nodes.Add(new Node(i, name, flags, count, first, 0, 0, 0, modified));
                for (uint c = first + count; c > first; c--) todo.Push((int)(c - 1));
            }
            else nodes.Add(new Node(i, name, flags, 0, 0, BinaryPrimitives.ReadUInt16BigEndian(s[6..]), BinaryPrimitives.ReadUInt16BigEndian(s[8..]),
                BinaryPrimitives.ReadUInt32BigEndian(s[10..]), modified));
        }
        return nodes;
    }

    /// <summary>The name entry at <paramref name="at"/> (length, Qt hash, UTF-16BE text) when it ends by <paramref name="limit"/> and its hash matches; else null.</summary>
    private static string? NameAt(byte[] b, long at, long limit)
    {
        if (at < 0 || at + 6 > limit) return null;
        int length = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan((int)at));
        if (length == 0 || at + 6 + 2L * length > limit) return null;
        var units = b.AsSpan((int)at + 6, 2 * length);
        uint h = 0;
        for (int i = 0; i < units.Length; i += 2)
        {
            char c = (char)BinaryPrimitives.ReadUInt16BigEndian(units[i..]);
            // A file name holds no control characters; zero bytes would otherwise pass the hash.
            if (c < 0x20) return null;
            h = Step(h, c);
        }
        return h == BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)at + 2)) ? Encoding.BigEndianUnicode.GetString(units) : null;
    }

    /// <summary>Qt's resource name hash (qt_hash) of UTF-16 code units.</summary>
    public static uint Hash(string s)
    {
        uint h = 0;
        foreach (char c in s) h = Step(h, c);
        return h;
    }

    private static uint Step(uint h, char c)
    {
        h = (h << 4) + c;
        h ^= (h & 0xF0000000) >> 23;
        return h & 0x0FFFFFFF;
    }

    /// <summary>The files of a collection in tree order; damaged nodes and names are notes.</summary>
    public static List<Entry> Entries(byte[] b, Collection c, List<string> notes, CancellationToken ct)
    {
        var entries = new List<Entry>();
        int size = c.Version >= 2 ? 22 : 14, skipped = 0;
        var seen = new HashSet<uint>();
        void Skip(string note)
        {
            if (skipped++ < 5) notes.Add(note);
        }
        void Visit(uint index, string prefix, int depth)
        {
            ct.ThrowIfCancellationRequested();
            long p = c.Tree + (long)index * size;
            if (depth > MaxDepth || p + size > b.Length || !seen.Add(index) || seen.Count > MaxNodes) { Skip($"tree node {index} lies outside the bytes or repeats; skipped"); return; }
            var s = b.AsSpan((int)p, size);
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(s[4..]);
            string path = prefix;
            if (index != 0)
            {
                var name = NameAt(b, c.Names + (long)BinaryPrimitives.ReadUInt32BigEndian(s), b.Length);
                if (name == null) { Skip($"tree node {index}: its name fails Qt's hash; skipped"); return; }
                path = prefix.Length == 0 ? name : prefix + "/" + name;
            }
            if ((flags & Directory) != 0)
            {
                uint count = BinaryPrimitives.ReadUInt32BigEndian(s[6..]), first = BinaryPrimitives.ReadUInt32BigEndian(s[10..]);
                if (count > 0 && first <= index) { Skip($"tree node {index}: its children do not follow it; skipped"); return; }
                if (c.Tree + (first + (long)count) * size > b.Length) { Skip($"tree node {index}: its children lie past the end; skipped"); return; }
                for (uint k = 0; k < count && seen.Count <= MaxNodes; k++) Visit(first + k, path, depth + 1);
                return;
            }
            uint offset = BinaryPrimitives.ReadUInt32BigEndian(s[10..]);
            long at = c.Data + (long)offset;
            if (at + 4 > b.Length) { Skip($"{path}: data at 0x{at:X} lies past the end; skipped"); return; }
            long stored = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan((int)at));
            if (at + 4 + stored > b.Length) { Skip($"{path}: data runs past the end; skipped"); return; }
            ulong ms = size == 22 ? BinaryPrimitives.ReadUInt64BigEndian(s[14..]) : 0;
            DateTime? modified = ms is > 0 and < 253402300800000 ? DateTime.UnixEpoch.AddMilliseconds(ms) : null;
            string? compression = (flags & CompressedZstd) != 0 ? "zstd" : (flags & Compressed) != 0 ? "zlib" : null;
            entries.Add(new Entry(path, BinaryPrimitives.ReadUInt16BigEndian(s[8..]), BinaryPrimitives.ReadUInt16BigEndian(s[6..]), compression, stored, (int)at + 4, modified));
        }
        Visit(0, "", 0);
        if (skipped > 5) notes.Add($"{skipped - 5:N0} more tree nodes skipped");
        return entries;
    }

    /// <summary>A file's content, expanded; throws <see cref="ToolError"/> when it does not expand or passes <paramref name="max"/> bytes.</summary>
    public static byte[] Content(byte[] b, Entry e, long max, string name)
    {
        var stored = b.AsSpan(e.DataAt, (int)e.Stored);
        if (e.Compression == null) return stored.ToArray();
        try
        {
            Stream z = e.Compression == "zstd"
                ? new ZstdSharp.DecompressionStream(new MemoryStream(b, e.DataAt, (int)e.Stored, writable: false))
                : stored.Length >= 4 ? new ZLibStream(new MemoryStream(b, e.DataAt + 4, (int)e.Stored - 4, writable: false), CompressionMode.Decompress)
                : throw new InvalidDataException("shorter than its size field");
            using (z)
                return Blob.ReadBounded(z, max) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{name}: {e.Path} expands past the {max:N0}-byte item limit.", "raise the limits");
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ZstdSharp.ZstdException)
        {
            throw Malformed(name, $"{e.Path} does not expand as {e.Compression} ({ex.Message})");
        }
    }

    /// <summary>The path a file is extracted to: a locale variant carries Qt's language and territory numbers before its extension.</summary>
    public static string ItemPath(Entry e)
    {
        if (e.IsDefaultLocale) return e.Path;
        string ext = Path.GetExtension(e.Path);
        return e.Path[..^ext.Length] + $" (language {e.Language}, territory {e.Territory})" + ext;
    }

    /// <summary>One container level: every collection's files as entries, and as items when <paramref name="allFiles"/> or a nested binary or package.</summary>
    public static ContainerContents Open(byte[] data, IReadOnlyList<Collection> collections, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        var paths = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        int files = 0, failed = 0;
        bool stopped = false;
        foreach (var c in collections)
        {
            var list = Entries(data, c, notes, ct);
            files += list.Count;
            foreach (var e in list)
            {
                var path = ItemPath(e);
                // Collections compiled into one program share the ":/" root; a repeated path is the same file registered twice.
                if (!paths.Add(path)) continue;
                var detail = string.Join(", ", new[] { e.Compression, e.IsDefaultLocale ? null : $"language {e.Language}, territory {e.Territory}",
                    e.Modified is { } m ? $"modified {m:yyyy-MM-dd HH:mm:ss} UTC" : null }.Where(d => d != null));
                byte[]? content = null;
                try { content = Content(data, e, limits.MaxItemBytes, name); }
                catch (ToolError ex) { if (failed++ < 3) notes.Add(ex.Message); }
                entries.Add(new ContainerEntry(path, content?.Length ?? e.Stored, detail.Length > 0 ? detail : null));
                if (content == null || stopped || !(allFiles || Containers.IsInteresting(path))) continue;
                if (items.Count >= limits.MaxItems || (total += content.Length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); stopped = true; continue; }
                items.Add(new ExtractedItem(path, content, "Qt resource"));
            }
        }
        if (failed > 3) notes.Add($"{failed - 3} more files do not expand.");
        if (!allFiles && !stopped && entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        notes.Insert(0, collections is [{ At: null } one]
            ? $"Qt resource collection, format version {one.Version}: {files:N0} file(s)."
            : $"{collections.Count} Qt resource collection(s) compiled into the image (qRegisterResourceData; trees at " +
              string.Join(", ", collections.Take(8).Select(c => $"0x{c.Tree:X}")) + (collections.Count > 8 ? ", ..." : "") + $"): {files:N0} file(s).");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    private static ToolError Malformed(string name, string what) => new(ErrorCode.MalformedInput, $"{name}: not a readable Qt resource collection: {what}.");
}

/// <summary>Addresses the code loads (x64 lea, ARM64 adrp/add, x86 push/mov), as file offsets with their instructions'.</summary>
internal sealed class CodeReferences
{
    private readonly Dictionary<long, List<long>> _sites = [];
    private readonly SortedList<long, long> _bySite = [];

    /// <summary>The references of an image's executable sections; null for another machine or an image that does not parse.</summary>
    public static CodeReferences? Read(byte[] image)
    {
        Native.INativeImage native;
        try { native = Native.NativeImageLoader.FromBytes(image); }
        catch (Exception ex) when (ex is ToolError or BadImageFormatException or ArgumentException or InvalidOperationException) { return null; }
        if (native.Arch is not (Native.NativeArch.X64 or Native.NativeArch.Arm64 or Native.NativeArch.X86)) return null;
        var refs = new CodeReferences();
        foreach (var section in native.Sections.Where(x => x.IsExecutable && x.RawSize > 0))
        {
            long from = section.RawOffset, to = Math.Min(image.Length, (long)section.RawOffset + Math.Min(section.RawSize, section.MappedSize));
            for (long i = from; i < to; i++)
            {
                uint rva = section.Rva + (uint)(i - from);
                long target = -1;
                int width = 1;
                switch (native.Arch)
                {
                    case Native.NativeArch.X64 when i + 7 <= to && (image[i] & 0xFB) == 0x48 && image[i + 1] == 0x8D && (image[i + 2] & 0xC7) == 0x05:
                        target = Offset(native, rva + 7u + (uint)BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan((int)i + 3)));
                        width = 7;
                        break;
                    case Native.NativeArch.X86 when i + 5 <= to && (image[i] == 0x68 || image[i] is >= 0xB8 and <= 0xBF):
                        ulong va = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)i + 1));
                        target = va >= native.ImageBase && va - native.ImageBase < uint.MaxValue ? Offset(native, (uint)(va - native.ImageBase)) : -1;
                        width = 5;
                        break;
                    case Native.NativeArch.Arm64 when (i - from) % 4 == 0 && i + 4 <= to:
                        width = 4;
                        uint insn = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)i));
                        if ((insn & 0x9F000000) != 0x90000000) break;
                        long page = ((long)rva & ~0xFFFL) + ((long)(((insn >> 5) & 0x7FFFF) << 2 | (insn >> 29) & 3) << 43 >> 31);
                        // The add that completes the address follows within four instructions.
                        for (long j = i + 4; j < Math.Min(to, i + 20); j += 4)
                        {
                            uint add = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)j));
                            if ((add & 0xFF800000) != 0x91000000 || (add >> 5 & 0x1F) != (insn & 0x1F)) continue;
                            long address = page + ((long)(add >> 10 & 0xFFF) << ((add >> 22 & 1) == 1 ? 12 : 0));
                            target = address is >= 0 and <= uint.MaxValue ? Offset(native, (uint)address) : -1;
                            break;
                        }
                        break;
                }
                if (target < 0) continue;
                if (!refs._sites.TryGetValue(target, out var list)) refs._sites[target] = list = [];
                list.Add(i);
                refs._bySite[i] = target;
                i += width - 1;
            }
        }
        return refs;
    }

    private static long Offset(Native.INativeImage native, uint rva) => native.TryRvaToFileOffset(rva, out long offset) ? offset : -1;

    /// <summary>The instructions that load <paramref name="target"/>; empty when none does.</summary>
    public IReadOnlyList<long> Sites(long target) => _sites.TryGetValue(target, out var list) ? list : [];

    /// <summary>The addresses loaded within <paramref name="distance"/> bytes of the instruction at <paramref name="site"/>.</summary>
    public IEnumerable<long> Near(long site, int distance)
    {
        var keys = _bySite.Keys;
        int lo = 0, hi = keys.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (keys[mid] < site - distance) lo = mid + 1;
            else hi = mid;
        }
        for (int k = lo; k < keys.Count && keys[k] <= site + distance; k++) yield return _bySite.Values[k];
    }
}

/// <summary>Binary .rcc files as a container: one collection's files.</summary>
internal sealed class QtResourceReader : IContainerReader
{
    public string Kind => QtResources.Kind;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => QtResources.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        QtResources.Open(data, [QtResources.Header(data, name)], name, allFiles, limits, ct);
}
