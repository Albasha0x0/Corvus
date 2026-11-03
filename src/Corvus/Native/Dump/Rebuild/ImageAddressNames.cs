using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Names the function or data an RVA of a mapped PE image falls in, from its exception table, exports and sections.</summary>
public sealed class ImageAddressNames
{
    /// <summary>Most exports and exception table entries read; the rest are not named.</summary>
    public const int MaxEntries = 1 << 20;

    private const uint Executable = 0x20000000;
    private const uint Code = 0x20;
    private const int MaxNameBytes = 256;

    private readonly ulong _base;
    private readonly List<Section> _sections = [];
    private readonly List<(uint Rva, string Name)> _exports = [];
    private readonly List<(uint Begin, uint End)> _functions = [];
    private readonly Dictionary<uint, string> _exportAt = [];

    private ImageAddressNames(ulong imageBase) => _base = imageBase;

    /// <summary>
    /// Whether the image has an exception table that names code by function; false means code is named by the
    /// nearest export at or below and marked approximate.
    /// </summary>
    public bool HasFunctionTable { get; private set; }

    /// <summary>Reads the section table, exports and exception table of <paramref name="mapped"/> (offset = RVA); a part that cannot be read leaves the names from the others.</summary>
    public static ImageAddressNames For(byte[] mapped, ulong imageBase)
    {
        var names = new ImageAddressNames(imageBase);
        try { names.Read(mapped); }
        catch (ArgumentOutOfRangeException) { }
        return names;
    }

    /// <summary>
    /// Returns the name of the function holding <paramref name="rva"/> in code, or the export or section with an
    /// offset in data; a leading <c>~</c> marks a name that is approximate. Null when the RVA is in no section.
    /// </summary>
    public string? NameAt(uint rva)
    {
        var section = _sections.FirstOrDefault(s => rva >= s.Rva && rva - s.Rva < s.Size);
        if (section is null) return null;
        if (!section.IsCode) return Below(rva, section) ?? Offset(section.Name, rva - section.Rva);

        if (HasFunctionTable)
        {
            int at = _functions.BinarySearch((rva, 0), Comparer<(uint Begin, uint End)>.Create((a, b) => a.Begin.CompareTo(b.Begin)));
            int index = at >= 0 ? at : ~at - 1;
            if (index >= 0 && rva < _functions[index].End)
            {
                uint begin = _functions[index].Begin;
                return _exportAt.GetValueOrDefault(begin) ?? $"sub_{_base + begin:X}";
            }
        }
        string? below = Below(rva, section);
        return below is null ? Offset(section.Name, rva - section.Rva) : "~" + below;
    }

    // Only an export in the same section names an address, so a neighbour does
    // not.
    private string? Below(uint rva, Section section)
    {
        int lo = 0, hi = _exports.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_exports[mid].Rva <= rva) lo = mid + 1; else hi = mid;
        }
        if (lo == 0) return null;
        // Of equal addresses the first read wins, as the sort is stable.
        uint best = _exports[lo - 1].Rva;
        if (best < section.Rva) return null;
        return Offset(_exportAt[best], rva - best);
    }

    private static string Offset(string name, uint delta) => delta == 0 ? name : $"{name}+0x{delta:X}";

    private void Read(byte[] image)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        if (image[nt] != 'P' || image[nt + 1] != 'E') return;
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 4));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 6));
        int optional = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 20));
        int opt = nt + 24;
        int dirs = opt + (BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(opt)) == 0x20B ? 112 : 96);

        uint pdataRva = 0, pdataSize = 0;
        for (int i = 0; i < count; i++)
        {
            int h = opt + optional + 40 * i;
            string name = Encoding.ASCII.GetString(image, h, 8).TrimEnd('\0');
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 8));
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 12));
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(h + 36));
            _sections.Add(new Section(name, va, size, (flags & (Executable | Code)) != 0));
            if (name == ".pdata") (pdataRva, pdataSize) = (va, size);
        }

        uint dirRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs + 3 * 8));
        uint dirSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs + 3 * 8 + 4));
        if (dirRva != 0) (pdataRva, pdataSize) = (dirRva, dirSize);

        try { ReadExports(image, BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs)), BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs + 4))); }
        finally { IndexExports(); }
        if (pdataRva != 0 && machine is 0x8664 or 0xAA64) ReadFunctions(image, pdataRva, pdataSize, machine == 0xAA64);
    }

    // Sorted by address for a binary search; the first export read at an
    // address names it.
    private void IndexExports()
    {
        var sorted = _exports.Select((e, i) => (e, i)).OrderBy(x => x.e.Rva).ThenBy(x => x.i).Select(x => x.e).ToList();
        _exports.Clear();
        _exports.AddRange(sorted);
        foreach (var (rva, name) in sorted) _exportAt.TryAdd(rva, name);
    }

    private void ReadFunctions(byte[] image, uint rva, uint size, bool arm64)
    {
        // An ARM64 entry holds a begin and unwind data; its end is the next
        // begin.
        int width = arm64 ? 8 : 12;
        long entries = Math.Min(size / width, MaxEntries);
        if (rva + entries * width > image.Length) return;
        var begins = new List<(uint Begin, uint End)>();
        for (long i = 0; i < entries; i++)
        {
            int at = (int)(rva + i * width);
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at));
            if (begin == 0) continue;
            uint end = arm64 ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at + 4));
            begins.Add((begin, end));
        }
        begins.Sort((a, b) => a.Begin.CompareTo(b.Begin));
        for (int i = 0; i < begins.Count; i++)
        {
            var (begin, end) = begins[i];
            if (arm64)
            {
                var section = _sections.FirstOrDefault(s => begin >= s.Rva && begin - s.Rva < s.Size);
                uint limit = section is null ? begin : section.Rva + section.Size;
                end = i + 1 < begins.Count ? Math.Min(begins[i + 1].Begin, limit) : limit;
            }
            if (end > begin) _functions.Add((begin, end));
        }
        HasFunctionTable = _functions.Count > 0;
    }

    private void ReadExports(byte[] image, uint rva, uint size)
    {
        if (rva == 0 || rva + 40 > image.Length) return;
        uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 16));
        uint functionCount = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 20)), MaxEntries);
        uint nameCount = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 24)), MaxEntries);
        uint functions = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 28));
        uint names = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 32));
        uint ordinals = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)rva + 36));
        if ((long)functions + 4L * functionCount > image.Length || (long)names + 4L * nameCount > image.Length
            || (long)ordinals + 2L * nameCount > image.Length) return;

        var named = new string?[functionCount];
        for (int i = 0; i < nameCount; i++)
        {
            int index = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)ordinals + 2 * i));
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)names + 4 * i));
            if (index < functionCount && nameRva < image.Length) named[index] = ReadName(image, nameRva);
        }
        for (int i = 0; i < functionCount; i++)
        {
            uint target = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)functions + 4 * i));
            // A target inside the export directory is a forwarder and has no
            // address here.
            if (target == 0 || target >= image.Length || (target >= rva && target - rva < size)) continue;
            _exports.Add((target, named[i] ?? $"#{ordinalBase + (uint)i}"));
        }
    }

    private static string? ReadName(byte[] image, uint rva)
    {
        var span = image.AsSpan((int)rva, (int)Math.Min(MaxNameBytes, image.Length - rva));
        int end = span.IndexOf((byte)0);
        return end < 0 ? null : Encoding.ASCII.GetString(span[..end]);
    }

    private sealed record Section(string Name, uint Rva, uint Size, bool IsCode);
}
