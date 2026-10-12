namespace Corvus.Native.Code;

/// <summary>
/// The decodable bytes of an image: a copy of every executable section's raw-backed extent (zero fill past the raw
/// data is not code), indexed by RVA. Also maps those bytes to a dense bit index for per-byte bitmaps.
/// </summary>
internal sealed class ImageCode
{
    /// <summary>Executable sections larger than this are cut (reported as a truncation).</summary>
    public const int MaxSectionBytes = 1 << 30;

    internal sealed class Region
    {
        public required NativeSection Section { get; init; }
        public required uint Rva { get; init; }
        public required byte[] Bytes { get; init; }
        /// <summary>Offset of this region in the dense bit index.</summary>
        public required long BitBase { get; init; }
        public uint End => Rva + (uint)Bytes.Length;
    }

    private readonly Region[] _regions;
    private readonly uint[] _regionStarts;

    public INativeImage Image { get; }
    public IReadOnlyList<Region> Regions => _regions;
    /// <summary>Total number of code bytes (size of the dense bit index).</summary>
    public long TotalBytes { get; }
    public List<string> Truncations { get; } = [];

    public ImageCode(INativeImage image)
    {
        Image = image;
        var regions = new List<Region>();
        long bitBase = 0;
        foreach (var s in image.Sections.Where(s => s.IsExecutable).OrderBy(s => s.Rva))
        {
            // The loader does not map a section that starts past SizeOfImage.
            if (s.Rva >= image.SizeOfImage) continue;
            long length = s.VirtualSize == 0 ? s.RawSize : Math.Min(s.VirtualSize, s.RawSize);
            if ((ulong)s.Rva + (ulong)length > image.SizeOfImage)
                length = image.SizeOfImage - s.Rva;
            // Only the bytes the file backs: a raw size past the end of the file reads as zeros, which are not code.
            length = image.FileBackedLength(s.Rva, length);
            if (length <= 0) continue;
            // Overlapping section headers: the earlier section wins.
            if (regions.Count > 0 && s.Rva < regions[^1].End) continue;
            if (length > MaxSectionBytes - bitBase)
            {
                Truncations.Add($"section {s.Name}: only the first {Math.Max(0, MaxSectionBytes - bitBase)} of {length} bytes are analyzed");
                length = MaxSectionBytes - bitBase;
                if (length <= 0) continue;
            }
            var bytes = new byte[length];
            int read = image.Read(s.Rva, bytes);
            if (read < bytes.Length) Array.Resize(ref bytes, read);
            if (bytes.Length == 0) continue;
            regions.Add(new Region { Section = s, Rva = s.Rva, Bytes = bytes, BitBase = bitBase });
            bitBase += bytes.Length;
        }
        _regions = regions.ToArray();
        _regionStarts = _regions.Select(r => r.Rva).ToArray();
        TotalBytes = bitBase;
        OtherRanges = OtherInstructionSet(image);
    }

    /// <summary>A hybrid image's code of the other instruction set (x64 in ARM64X, ARM64 / ARM64EC in an x64 image), sorted; empty otherwise.</summary>
    public (uint Start, uint End)[] OtherRanges { get; }

    /// <summary>The code map ranges of a hybrid PE in the instruction set its header machine does not name, sorted.</summary>
    public static (uint Start, uint End)[] OtherInstructionSet(INativeImage image)
    {
        if (image is not Pe.PeFile pe || Pe.PeHybrid.Of(pe) is not { } hybrid) return [];
        bool arm = image.Arch == NativeArch.Arm64;
        return [.. hybrid.CodeRanges.Where(r => r.Length > 0 && (arm ? r.Arch == "x64" : r.Arch is "ARM64" or "ARM64EC"))
            .Select(r => (r.Rva, r.Rva + r.Length)).OrderBy(r => r.Item1)];
    }

    public static bool InRanges((uint Start, uint End)[] ranges, uint rva)
    {
        int lo = 0, hi = ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (rva < ranges[mid].Start) hi = mid - 1;
            else if (rva >= ranges[mid].End) lo = mid + 1;
            else return true;
        }
        return false;
    }

    /// <summary>The code region containing <paramref name="rva"/>, or null.</summary>
    public Region? RegionAt(uint rva)
    {
        int i = Array.BinarySearch(_regionStarts, rva);
        if (i < 0) i = ~i - 1;
        if (i < 0) return null;
        var r = _regions[i];
        return rva - r.Rva < (uint)r.Bytes.Length ? r : null;
    }

    public bool IsCode(uint rva) => RegionAt(rva) != null;

    /// <summary>Dense bit index of a code byte, or -1.</summary>
    public long BitIndex(uint rva) => RegionAt(rva) is { } r ? r.BitBase + (rva - r.Rva) : -1;
}

/// <summary>A fixed-size bit set over the dense code byte index of <see cref="ImageCode"/>.</summary>
internal sealed class CodeBitmap
{
    private readonly ulong[] _bits;

    public CodeBitmap(long size) => _bits = new ulong[(size + 63) / 64];

    public bool this[long i]
    {
        get => i >= 0 && (_bits[i >> 6] & (1UL << (int)(i & 63))) != 0;
        set
        {
            if (i < 0) return;
            if (value) _bits[i >> 6] |= 1UL << (int)(i & 63);
            else _bits[i >> 6] &= ~(1UL << (int)(i & 63));
        }
    }

    /// <summary>The first clear bit at or after <paramref name="start"/>, or <paramref name="end"/> when there is none before it.</summary>
    public long NextClear(long start, long end)
    {
        for (long i = start; i < end; i = (i | 63) + 1)
        {
            ulong clear = ~_bits[i >> 6] >> (int)(i & 63);
            if (clear != 0) return Math.Min(end, i + System.Numerics.BitOperations.TrailingZeroCount(clear));
        }
        return end;
    }

    public void SetRange(long start, int count)
    {
        long end = start + count;
        if (start < 0) start = 0;
        while (start < end)
        {
            int bit = (int)(start & 63);
            int n = (int)Math.Min(64 - bit, end - start);
            _bits[start >> 6] |= (n == 64 ? ulong.MaxValue : (1UL << n) - 1) << bit;
            start += n;
        }
    }
}
