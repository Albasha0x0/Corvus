namespace NetDecompilerMcp.Native.Code;

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

    public void SetRange(long start, int count)
    {
        for (long i = start; i < start + count; i++) this[i] = true;
    }
}
