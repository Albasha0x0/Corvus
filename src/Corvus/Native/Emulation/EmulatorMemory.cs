using System.Buffers.Binary;

namespace Corvus.Native.Emulation;

/// <summary>A read of an address that nothing maps.</summary>
public sealed class EmulatorFaultException(ulong address, string message) : Exception(message)
{
    public ulong Address { get; } = address;
}

/// <summary>An instruction or operand the emulator does not model.</summary>
public sealed class EmulatorUnsupportedException(string message) : Exception(message);

/// <summary>One emulation's memory: the image copied on write, a private zeroed region and written bytes; any other read faults.</summary>
public sealed class EmulatorMemory
{
    public const int PageSize = 0x1000;
    private const int MaxPages = 1 << 16;

    private sealed class Page
    {
        public readonly byte[] Data = new byte[PageSize];
        // Readable bytes of a page outside the image and the region; null when every byte is readable.
        public ulong[]? Valid;
        public readonly ulong[] Written = new ulong[PageSize / 64];
    }

    private readonly INativeImage _image;
    private readonly ulong _imageBase, _imageEnd, _regionBase, _regionEnd;
    private readonly Dictionary<ulong, Page> _pages = [];

    public EmulatorMemory(INativeImage image, ulong imageBase, ulong regionBase, ulong regionSize)
    {
        _image = image;
        _imageBase = imageBase;
        _imageEnd = imageBase + image.SizeOfImage;
        _regionBase = regionBase;
        _regionEnd = regionBase + regionSize;
    }

    /// <summary>Whether writes are recorded as the program's (off while the caller places its inputs).</summary>
    public bool Tracking { get; set; }

    public bool InImage(ulong va) => va >= _imageBase && va < _imageEnd;

    public bool InRegion(ulong va) => va >= _regionBase && va < _regionEnd;

    /// <summary>Whether the byte at <paramref name="va"/> can be read.</summary>
    public bool Mapped(ulong va)
    {
        if (InImage(va) || InRegion(va)) return true;
        return _pages.TryGetValue(va & ~(ulong)(PageSize - 1), out var p) && (p.Valid == null || Bit(p.Valid, (int)(va & (PageSize - 1))));
    }

    private static bool Bit(ulong[] bits, int i) => (bits[i >> 6] & 1UL << (i & 63)) != 0;

    private Page Get(ulong va, bool forWrite)
    {
        ulong page = va & ~(ulong)(PageSize - 1);
        if (_pages.TryGetValue(page, out var p)) return p;
        bool backed = InImage(page) || InImage(page + PageSize - 1) || InRegion(page);
        if (!backed && !forWrite) throw new EmulatorFaultException(va, $"read of unmapped memory at 0x{va:x}");
        if (_pages.Count >= MaxPages) throw new EmulatorUnsupportedException($"the run touched more than {MaxPages:N0} pages");
        p = new Page();
        if (backed)
        {
            ulong from = Math.Max(page, _imageBase), to = Math.Min(page + PageSize, _imageEnd);
            if (from < to) _image.Read((uint)(from - _imageBase), p.Data.AsSpan((int)(from - page), (int)(to - from)));
            // A page straddling the image end is readable only inside the image (or the region).
            if (!(InImage(page) && InImage(page + PageSize - 1)) && !InRegion(page))
            {
                p.Valid = new ulong[PageSize / 64];
                for (int i = 0; i < PageSize; i++) if (InImage(page + (ulong)i)) p.Valid[i >> 6] |= 1UL << (i & 63);
            }
        }
        else p.Valid = new ulong[PageSize / 64];
        _pages[page] = p;
        return p;
    }

    public void Read(ulong va, Span<byte> into)
    {
        for (int done = 0; done < into.Length;)
        {
            ulong at = va + (ulong)done, page = at & ~(ulong)(PageSize - 1);
            int off = (int)(at - page), n = Math.Min(PageSize - off, into.Length - done);
            var p = Get(at, false);
            if (p.Valid != null)
                for (int i = 0; i < n; i++)
                    if (!Bit(p.Valid, off + i)) throw new EmulatorFaultException(at + (ulong)i, $"read of unmapped memory at 0x{at + (ulong)i:x}");
            p.Data.AsSpan(off, n).CopyTo(into[done..]);
            done += n;
        }
    }

    public void Write(ulong va, ReadOnlySpan<byte> bytes)
    {
        for (int done = 0; done < bytes.Length;)
        {
            ulong at = va + (ulong)done, page = at & ~(ulong)(PageSize - 1);
            int off = (int)(at - page), n = Math.Min(PageSize - off, bytes.Length - done);
            var p = Get(at, true);
            bytes.Slice(done, n).CopyTo(p.Data.AsSpan(off));
            for (int i = off; i < off + n; i++)
            {
                if (p.Valid != null) p.Valid[i >> 6] |= 1UL << (i & 63);
                if (Tracking) p.Written[i >> 6] |= 1UL << (i & 63);
            }
            done += n;
        }
    }

    public ulong ReadUInt(ulong va, int size, bool bigEndian = false)
    {
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        Read(va, b[..size]);
        if (!bigEndian) return BinaryPrimitives.ReadUInt64LittleEndian(b);
        ulong v = 0;
        for (int i = 0; i < size; i++) v = v << 8 | b[i];
        return v;
    }

    public void WriteUInt(ulong va, ulong value, int size)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        Write(va, b[..size]);
    }

    /// <summary>Whether the program wrote the byte at <paramref name="va"/>.</summary>
    public bool WasWritten(ulong va) =>
        _pages.TryGetValue(va & ~(ulong)(PageSize - 1), out var p) && Bit(p.Written, (int)(va & (PageSize - 1)));

    /// <summary>The ranges the program wrote, in address order, adjacent pages joined.</summary>
    public List<(ulong Start, ulong Length)> WrittenRanges()
    {
        var ranges = new List<(ulong Start, ulong Length)>();
        foreach (var page in _pages.Keys.Order())
        {
            var p = _pages[page];
            for (int i = 0; i < PageSize; i++)
            {
                if (!Bit(p.Written, i)) continue;
                ulong va = page + (ulong)i;
                if (ranges.Count > 0 && ranges[^1].Start + ranges[^1].Length == va) ranges[^1] = (ranges[^1].Start, ranges[^1].Length + 1);
                else ranges.Add((va, 1));
            }
        }
        return ranges;
    }
}
