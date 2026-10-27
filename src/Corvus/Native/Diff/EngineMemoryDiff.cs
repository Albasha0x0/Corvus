using System.ComponentModel;
using Corvus.Core;
using Corvus.Native.Patching;
using Corvus.Native.Providers;

namespace Corvus.Native.Diff;

/// <summary>A range where the engine's memory and the file's bytes differ, or where one side has no bytes.</summary>
public sealed record MemoryRange(
    string Section,
    [property: Description("Offset in the file; absent where the file has no bytes (zero fill).")] string? FileOffset,
    [property: Description("The address in the engine's database.")] string EngineAddress,
    uint Length,
    [property: Description("patched (database or session edit), engine_fixup (written by the engine's loader), relocation_applied (a declared relocation slot), differs (unexplained), " +
                           "unclassified (engine fixups unreadable), uninitialized (no bytes on either side), unknown (file bytes the engine does not hold).")] string Kind,
    [property: Description("The edit, fixup type and symbol, or why there are no bytes.")] string? Detail,
    [property: Description("The first 16 bytes on each side, in hex.")] string? FileBytes,
    string? EngineBytes);

/// <summary>Ranges of one kind in a section and the bytes they cover.</summary>
public sealed record MemoryKindCount(string Kind, int Ranges, long Bytes);

/// <summary>One section compared: bytes held by both sides, equal, the file's bytes the engine does not hold, zero fill, and ranges by kind.</summary>
public sealed record MemorySection(string Name, string EngineAddress, long Size, long Compared, long Equal,
    [property: Description("File bytes the engine does not hold.")] long Unknown,
    [property: Description("Bytes past the file data (zero fill).")] long ZeroFill,
    IReadOnlyList<MemoryKindCount> Kinds);

/// <summary>The file's bytes compared with an engine's memory; <see cref="FixupsListed"/> false means no range is classified as a fixup.</summary>
public sealed record EngineMemoryReport(string Engine,
    [property: Description("The image base in the engine's database.")] string EngineBase,
    [property: Description("The image base in the file's header.")] string FileBase,
    bool FixupsListed, int Fixups,
    IReadOnlyList<MemorySection> Sections, IReadOnlyList<MemoryRange> Ranges, IReadOnlyList<string> Notes);

/// <summary>Compares an engine's memory with the file by page digest, reading back and attributing only differing pages.</summary>
public static class EngineMemoryDiff
{
    /// <summary>Digest page size in bytes.</summary>
    public const int PageSize = 4096;

    /// <summary>Bytes per memory request (under both workers' 16 MB limit).</summary>
    private const uint Chunk = 4 << 20;

    /// <summary>Most fixups listed; more are named in a note and leave later ranges unattributed.</summary>
    public const int MaxFixups = 2_000_000;

    /// <summary>Bytes shown per side of a range.</summary>
    private const int ShownBytes = 16;

    /// <summary>Compares <paramref name="fileBytes"/> with the engine memory <paramref name="control"/> reads; <paramref name="edits"/> are this session's patches.</summary>
    public static async Task<EngineMemoryReport> CompareAsync(string engine, INativeImage image, ReadOnlyMemory<byte> fileBytes, ulong engineBase,
        INativeEngineControl control, IReadOnlyList<NativePatch> edits, CancellationToken ct)
    {
        var notes = new List<string>();
        EngineFixupList? fixups = null;
        try { fixups = await control.FixupsAsync(MaxFixups, ct).ConfigureAwait(false); }
        catch (ToolError e) when (e.Code == ErrorCode.Unsupported)
        {
            notes.Add($"{engine}: {e.Message.TrimEnd('.')}; differing ranges are unclassified, not attributed to fixups");
        }
        if (fixups?.Truncated == true) notes.Add($"{engine} lists more than {MaxFixups} fixups; ranges past the last one listed are not attributed to fixups");
        if (fixups != null && fixups.Patched == null) notes.Add($"{engine} keeps no patch record; only this session's edits are named as patched");
        var why = new Attribution(image, engineBase, edits, fixups);
        long delta = (long)(engineBase - image.ImageBase);
        if (delta != 0) notes.Add($"{engine} loaded the image at 0x{engineBase:X}, the file's base is 0x{image.ImageBase:X}");

        var sections = new List<MemorySection>();
        var ranges = new List<MemoryRange>();
        uint covered = 0;
        foreach (var (name, rva, size) in Regions(image))
        {
            ct.ThrowIfCancellationRequested();
            // Overlapping sections (segments and their sections) are compared once, in the first one.
            uint lo = Math.Max(rva, covered), hi = (uint)Math.Min((long)rva + size, image.SizeOfImage);
            if (lo >= hi) continue;
            covered = hi;
            var region = new Region(name, image, fileBytes, lo, hi, engineBase);
            await region.CompareAsync(control, why, ct).ConfigureAwait(false);
            sections.Add(region.Summary());
            ranges.AddRange(region.Ranges);
        }
        return new EngineMemoryReport(engine, $"0x{engineBase:X}", $"0x{image.ImageBase:X}", fixups != null, fixups?.Fixups.Count ?? 0, sections, ranges, notes);
    }

    /// <summary>The headers (bytes before the first section that the file maps) and each section, in address order.</summary>
    private static IEnumerable<(string Name, uint Rva, long Size)> Regions(INativeImage image)
    {
        var list = image.Sections.Where(s => s.MappedSize > 0).OrderBy(s => s.Rva).ToList();
        uint first = list.Count > 0 ? list[0].Rva : image.SizeOfImage;
        if (first > 0 && image.TryRvaToFileOffset(0, out _)) yield return ("headers", 0, first);
        foreach (var s in list) yield return (s.Name.Length > 0 ? s.Name : $"0x{s.Rva:X}", s.Rva, s.MappedSize);
    }

    /// <summary>Why a byte differs: the first of this session's edits, the database's patches, fixups and rebased relocations that covers it.</summary>
    private sealed class Attribution
    {
        // In priority order: an edit of this session, a patch the database records, a loader fixup.
        private readonly SpanSet[] _sets;
        // Relocation slots the file declares, by start: their width and type name.
        private readonly Dictionary<uint, (int Width, string Type)> _slots = [];
        private readonly int _width;
        private readonly long _delta;
        private readonly bool _classifies;

        public Attribution(INativeImage image, ulong engineBase, IReadOnlyList<NativePatch> edits, EngineFixupList? fixups)
        {
            _classifies = fixups != null;
            _sets =
            [
                new([.. edits.Select(e => (e.Rva, e.EndRva, "patched", "session edit: " + e.Description))]),
                new([.. (fixups?.Patched ?? []).Select(p => (p.Rva, p.Rva + (uint)p.Bytes.Length, "patched", "patched in the database"))]),
                new([.. (fixups?.Fixups ?? []).Select(f => (f.Rva, f.Rva + (uint)Math.Max(1, f.Size), "engine_fixup", f.Target != null ? $"{f.Type} -> {f.Target}" : f.Type))]),
            ];
            _width = image.Is64Bit ? 8 : 4;
            _delta = (long)(engineBase - image.ImageBase);
            if (image is Elf.ElfFile elf)
            {
                foreach (var r in elf.Relocations)
                    if (elf.TryVaToRva(r.Offset, out uint at)) _slots.TryAdd(at, (_width, Elf.ElfNames.RelocationType(elf.Machine, r.Type)));
            }
            else
                foreach (var at in image.RelocationRvas) _slots.TryAdd(at, (_width, "base relocation"));
        }

        /// <summary>The kind and detail of a differing byte; <paramref name="file"/> and <paramref name="held"/> read a byte of each side or null.</summary>
        public (string Kind, string? Detail) Of(uint rva, Func<uint, byte?> file, Func<uint, byte?> held)
        {
            foreach (var set in _sets)
                if (set.Covering(rva) is { } hit) return hit;
            for (long slot = Math.Max(0, (long)rva - _width + 1); slot <= rva && _slots.Count > 0; slot++)
                if (_slots.TryGetValue((uint)slot, out var r) && rva < slot + r.Width)
                    return ("relocation_applied", _delta != 0 && Moved((uint)slot, file, held)
                        ? $"{r.Type} at 0x{slot:X} moved by 0x{_delta:X}"
                        : $"{r.Type} at 0x{slot:X}, written by the engine's loader; the engine records no fixup there");
            return (_classifies ? "differs" : "unclassified", null);
        }

        /// <summary>True when the pointer at <paramref name="slot"/> differs by exactly the base delta.</summary>
        private bool Moved(uint slot, Func<uint, byte?> file, Func<uint, byte?> held)
        {
            ulong a = 0, b = 0;
            for (int i = _width - 1; i >= 0; i--)
            {
                if (file((uint)(slot + i)) is not { } x || held((uint)(slot + i)) is not { } y) return false;
                a = a << 8 | x;
                b = b << 8 | y;
            }
            ulong mask = _width == 8 ? ulong.MaxValue : uint.MaxValue;
            return (b - a & mask) == ((ulong)_delta & mask);
        }
    }

    /// <summary>Spans sorted by start; a lookup returns the kind and detail of the span covering an address.</summary>
    private sealed class SpanSet
    {
        private readonly (uint Start, uint End, string Kind, string Detail)[] _spans;
        // Largest end among spans [0, i], so a lookup stops once no earlier span can reach the address.
        private readonly uint[] _reach;

        public SpanSet((uint Start, uint End, string Kind, string Detail)[] spans)
        {
            Array.Sort(spans, (x, y) => x.Start.CompareTo(y.Start));
            _spans = spans;
            _reach = new uint[spans.Length];
            for (int i = 0; i < spans.Length; i++) _reach[i] = Math.Max(spans[i].End, i > 0 ? _reach[i - 1] : 0);
        }

        public (string Kind, string? Detail)? Covering(uint rva)
        {
            int lo = 0, hi = _spans.Length - 1, last = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                if (_spans[mid].Start <= rva) { last = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            for (int i = last; i >= 0 && _reach[i] > rva; i--)
                if (rva < _spans[i].End) return (_spans[i].Kind, _spans[i].Detail);
            return null;
        }
    }

    /// <summary>One region compared: counters and the ranges found.</summary>
    private sealed class Region
    {
        private readonly string _name;
        private readonly INativeImage _image;
        private readonly ReadOnlyMemory<byte> _file;
        private readonly uint _lo, _hi;
        private readonly ulong _engineBase;
        private readonly long _backed;
        // File offset of _lo when the region's file bytes are one contiguous run; -1 otherwise.
        private readonly long _offset = -1;
        private readonly List<(uint Rva, MemoryRange Range)> _ranges = [];
        private long _compared, _equal, _unknown, _zeroFill;
        // Engine bytes read back for differing pages, by page RVA, with which bytes the engine held.
        private readonly Dictionary<uint, (byte[] Bytes, System.Collections.BitArray Held)> _held = [];

        public Region(string name, INativeImage image, ReadOnlyMemory<byte> file, uint lo, uint hi, ulong engineBase)
        {
            (_name, _image, _file, _lo, _hi, _engineBase) = (name, image, file, lo, hi, engineBase);
            _backed = image.FileBackedLength(lo, hi - lo);
            if (_backed > 0 && image.TryRvaToFileOffset(lo, out long a) && image.TryRvaToFileOffset((uint)(lo + _backed - 1), out long b)
                && b - a == _backed - 1 && b < file.Length)
                _offset = a;
        }

        public IEnumerable<MemoryRange> Ranges => _ranges.OrderBy(r => r.Rva).Select(r => r.Range);

        /// <summary>The file's byte at <paramref name="rva"/>: a file byte, 0 in zero fill, null where the file maps nothing.</summary>
        private byte? File(uint rva)
        {
            if (rva >= _lo && rva < _hi)
            {
                if (rva - _lo >= _backed) return 0;
                if (_offset >= 0) return _file.Span[(int)(_offset + rva - _lo)];
            }
            return _image.TryRvaToFileOffset(rva, out long o) && o < _file.Length ? _file.Span[(int)o] : null;
        }

        private byte? Held(uint rva)
        {
            uint page = rva / PageSize * PageSize;
            return _held.TryGetValue(page, out var p) && p.Held[(int)(rva - page)] ? p.Bytes[rva - page] : null;
        }

        private bool Backed(uint rva) => rva - _lo < _backed;

        public async Task CompareAsync(INativeEngineControl control, Attribution why, CancellationToken ct)
        {
            var differing = new List<(uint Start, uint End)>();
            uint next = _lo;
            for (uint at = _lo; at < _hi; at = (uint)Math.Min(_hi, (long)at + Chunk))
            {
                uint want = (uint)Math.Min(Chunk, _hi - at);
                foreach (var page in await control.MemoryPagesAsync(at, want, PageSize, ct).ConfigureAwait(false))
                {
                    uint pLo = Math.Max(page.Rva, Math.Max(at, next)), pHi = (uint)Math.Min((long)page.Rva + page.Length, (long)at + want);
                    if (pLo >= pHi) continue;
                    if (pLo > next) Gap(next, pLo);
                    next = pHi;
                    // A page clipped by the request is read back rather than digested.
                    if (pLo != page.Rva || pHi != page.Rva + (uint)page.Length || FileDigest(pLo, pHi) != page.Hash) differing.Add((pLo, pHi));
                    else Count(pLo, pHi, pHi - pLo);
                }
            }
            if (next < _hi) Gap(next, _hi);
            foreach (var (s, e) in differing) await ReadBackAsync(control, s, e, ct).ConfigureAwait(false);
            foreach (var (s, e) in differing) Diff(s, e, why);
        }

        private string FileDigest(uint s, uint e)
        {
            var buf = new byte[e - s];
            if (_offset >= 0)
            {
                long backedEnd = Math.Min(e, _lo + _backed);
                if (backedEnd > s) _file.Span.Slice((int)(_offset + s - _lo), (int)(backedEnd - s)).CopyTo(buf);
            }
            else
                for (uint i = s; i < e; i++) buf[i - s] = File(i) ?? 0;
            return NativeMemoryPage.Digest(buf);
        }

        /// <summary>Counts [s, e) as held by the engine, <paramref name="equal"/> bytes of it equal to the file.</summary>
        private void Count(uint s, uint e, long equal)
        {
            long backed = Math.Max(0, Math.Min(e, _lo + _backed) - s);
            _compared += backed;
            _zeroFill += e - s - backed;
            _equal += Math.Min(equal, backed);
        }

        /// <summary>[s, e) the engine does not hold: unknown where the file has bytes, uninitialized in zero fill.</summary>
        private void Gap(uint s, uint e)
        {
            uint split = (uint)Math.Clamp(_lo + _backed, s, e);
            if (split > s)
            {
                _unknown += split - s;
                Add(s, split, "unknown", "the engine holds no bytes here", false);
            }
            if (e > split)
            {
                _zeroFill += e - split;
                Add(split, e, "uninitialized", "no file bytes (zero fill) and none in the engine", false);
            }
        }

        private async Task ReadBackAsync(INativeEngineControl control, uint s, uint e, CancellationToken ct)
        {
            foreach (var run in await control.MemoryAsync(s, e - s, ct).ConfigureAwait(false))
                for (int i = 0; i < run.Bytes.Length; i++)
                {
                    uint rva = run.Rva + (uint)i, page = rva / PageSize * PageSize;
                    if (!_held.TryGetValue(page, out var p)) _held[page] = p = (new byte[PageSize], new System.Collections.BitArray(PageSize));
                    p.Bytes[rva - page] = run.Bytes[i];
                    p.Held[(int)(rva - page)] = true;
                }
        }

        /// <summary>The differing bytes of [s, e) as ranges, split where the attribution changes.</summary>
        private void Diff(uint s, uint e, Attribution why)
        {
            long equal = 0;
            uint? start = null;
            (string Kind, string? Detail) current = ("", null);
            for (uint rva = s; ; rva++)
            {
                bool differs = rva < e && File(rva) != Held(rva);
                var kind = differs ? why.Of(rva, File, Held) : ("", null);
                if (start is { } st && (!differs || kind != current))
                {
                    Add(st, rva, current.Kind, current.Detail, true);
                    start = null;
                }
                if (rva == e) break;
                if (!differs) equal++;
                else if (start == null) (start, current) = (rva, kind);
            }
            Count(s, e, equal);
        }

        private void Add(uint s, uint e, string kind, string? detail, bool bytes)
        {
            string? Hex(Func<uint, byte?> side)
            {
                var shown = new byte[Math.Min(ShownBytes, e - s)];
                for (int i = 0; i < shown.Length; i++)
                    if (side(s + (uint)i) is { } b) shown[i] = b;
                    else return null;
                return Convert.ToHexString(shown);
            }
            string? offset = Backed(s) && _image.TryRvaToFileOffset(s, out long off) ? $"0x{off:X}" : null;
            _ranges.Add((s, new MemoryRange(_name, offset, $"0x{_engineBase + s:X}", e - s, kind, detail,
                bytes && Backed(s) ? Hex(File) : null, bytes ? Hex(Held) : null)));
        }

        public MemorySection Summary()
        {
            var kinds = _ranges.GroupBy(r => r.Range.Kind).OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => new MemoryKindCount(g.Key, g.Count(), g.Sum(r => (long)r.Range.Length))).ToList();
            return new MemorySection(_name, $"0x{_engineBase + _lo:X}", _hi - _lo, _compared, _equal, _unknown, _zeroFill, kinds);
        }
    }
}
