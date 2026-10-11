using System.Buffers.Binary;

namespace Corvus.Native.NativeAot;

/// <summary>
/// Finds NativeAOT module headers in PE, ELF and Mach-O images: through the module list or symbols the image has, else a
/// scan of the initialized non-executable sections for "RTR\0" at 4-byte alignment whose shape is a NativeAOT header
/// (row size 2 pointers + 8, row type 1, 1–127 rows with distinct ids, starts and ends inside the image) and, when the
/// image has relocations (PE base relocations, ELF RELATIVE, Mach-O rebases), one at every row start. Several headers
/// (multi-module images) are all returned.
/// </summary>
public static class NativeAotLocator
{
    public const uint Signature = 0x00525452; // "RTR\0"
    private const int MaxRows = 127;
    private static readonly byte[] SignatureBytes = "RTR\0"u8.ToArray();

    /// <summary>How many bytes of <paramref name="section"/> the file holds: header sizes can claim more than the file has.</summary>
    internal static int FileBytes(INativeImage image, NativeSection section)
    {
        long size = Math.Min(section.RawSize, section.MappedSize);
        if (image.FileSize > 0) size = Math.Min(size, Math.Max(0, image.FileSize - section.RawOffset));
        return (int)Math.Min(size, Array.MaxLength);
    }

    /// <summary>
    /// Cheap signs of a NativeAOT image without reading its header: the sections the compiler names (.managed / hydrated in
    /// PE, __managedcode / __modules / .hydrated in ELF and Mach-O) or the DotNetRuntimeDebugHeader export or symbol.
    /// </summary>
    public static bool HasMarkers(INativeImage image) =>
        image.Sections.Any(s => SectionName(s.Name) is ".managed" or "hydrated" or ".hydrated" or "__managedcode" or "__modules")
        || DebugHeaderRva(image) != null;

    /// <summary>A Mach-O section name without its segment ("__DATA,__modules" → "__modules").</summary>
    private static string SectionName(string name) => name[(name.IndexOf(',') + 1)..];

    /// <summary>Whether <paramref name="name"/> is the C symbol <paramref name="plain"/>; Mach-O prefixes C names with '_'.</summary>
    private static bool IsSymbol(string? name, string plain) =>
        name != null && (name == plain || name.Length == plain.Length + 1 && name[0] == '_' && name.AsSpan(1).SequenceEqual(plain));

    /// <summary>
    /// The module headers: those the image lists (the __modules section of ELF and Mach-O images, a pointer per module, or
    /// __ReadyToRunHeader symbols), else those a scan finds.
    /// </summary>
    public static IReadOnlyList<NativeAotHeader> Find(INativeImage image, CancellationToken ct = default)
    {
        var listed = Listed(image);
        return listed.Count > 0 ? listed : Scan(image, ct);
    }

    private static List<NativeAotHeader> Listed(INativeImage image)
    {
        var found = new List<NativeAotHeader>();
        void Add(uint rva)
        {
            if (found.TrueForAll(h => h.Rva != rva) && TryRead(image, rva) is { } header) found.Add(header);
        }
        int pointer = image.Is64Bit ? 8 : 4;
        foreach (var section in image.Sections.Where(s => SectionName(s.Name) == "__modules"))
        {
            var bytes = new byte[Math.Min(section.MappedSize, 4096)];
            int n = image.Read(section.Rva, bytes);
            for (int at = 0; at + pointer <= n; at += pointer)
            {
                ulong va = pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
                if (ToRva(image, va, image.SizeOfImage - 1, out uint rva)) Add(rva);
            }
        }
        foreach (var symbol in image.Symbols)
            if (IsSymbol(symbol.Name, "__ReadyToRunHeader")) Add(symbol.Rva);
        return found;
    }

    private static List<NativeAotHeader> Scan(INativeImage image, CancellationToken ct)
    {
        var found = new List<NativeAotHeader>();
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.RawSize == 0) continue;
            ct.ThrowIfCancellationRequested();
            var bytes = new byte[FileBytes(image, section)];
            int n = image.Read(section.Rva, bytes);
            var span = bytes.AsSpan(0, n);
            for (int at = 0; ;)
            {
                int hit = span[at..].IndexOf(SignatureBytes);
                if (hit < 0) break;
                at += hit;
                uint rva = section.Rva + (uint)at;
                if (rva % 4 == 0 && TryRead(image, rva) is { } header) found.Add(header);
                at += 4;
            }
        }
        return found;
    }

    /// <summary>The header at <paramref name="rva"/>, or null when the bytes there are not a plausible NativeAOT header.</summary>
    public static NativeAotHeader? TryRead(INativeImage image, uint rva)
    {
        Span<byte> head = stackalloc byte[16];
        if (image.Read(rva, head) != head.Length || BinaryPrimitives.ReadUInt32LittleEndian(head) != Signature) return null;
        ushort major = BinaryPrimitives.ReadUInt16LittleEndian(head[4..]);
        ushort minor = BinaryPrimitives.ReadUInt16LittleEndian(head[6..]);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(head[8..]);
        int rows = BinaryPrimitives.ReadUInt16LittleEndian(head[12..]);
        int pointer = image.Is64Bit ? 8 : 4;
        if (head[14] != 2 * pointer + 8 || head[15] != 1 || rows is 0 or > MaxRows) return null;

        var table = new byte[rows * head[14]];
        if (image.Read(rva + 16, table) != table.Length) return null;
        var relocations = image.RelocationRvas;
        bool relocated = relocations.Count > 0;
        var sections = new List<NativeAotSection>(rows);
        var ids = new HashSet<int>();
        for (int i = 0; i < rows; i++)
        {
            var row = table.AsSpan(i * head[14]);
            int id = BinaryPrimitives.ReadInt32LittleEndian(row);
            uint rowFlags = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
            ulong start = pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(row[8..]) : BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
            ulong end = pointer == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(row[16..]) : BinaryPrimitives.ReadUInt32LittleEndian(row[12..]);
            if (!ids.Add(id) || id is < 100 or > 1000) return null;
            if (!ToRva(image, start, image.SizeOfImage - 1, out uint startRva)) return null;
            uint endRva = 0;
            if ((rowFlags & 1) != 0 && (!ToRva(image, end, image.SizeOfImage, out endRva) || endRva < startRva)) return null;
            if (relocated && !BinarySearch(relocations, rva + 16 + (uint)(i * head[14]) + 8)) return null;
            sections.Add(new NativeAotSection(id, rowFlags, startRva, endRva));
        }
        return new NativeAotHeader(rva, major, minor, flags, sections, relocated);
    }

    /// <summary>
    /// The major version of the DotNetRuntimeDebugHeader export or symbol ("DNDH" cookie, u16 major), or null when the
    /// image has none.
    /// </summary>
    public static int? DebugHeaderMajor(INativeImage image)
    {
        if (DebugHeaderRva(image) is not { } rva) return null;
        Span<byte> b = stackalloc byte[6];
        if (image.Read(rva, b) != b.Length || !b[..4].SequenceEqual("DNDH"u8)) return null;
        return BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
    }

    private static uint? DebugHeaderRva(INativeImage image) =>
        image.Exports.FirstOrDefault(e => IsSymbol(e.Name, "DotNetRuntimeDebugHeader") && e.ForwardedTo == null)?.Rva
        ?? image.Symbols.FirstOrDefault(s => IsSymbol(s.Name, "DotNetRuntimeDebugHeader"))?.Rva;

    private static bool ToRva(INativeImage image, ulong va, uint maxRva, out uint rva)
    {
        rva = 0;
        if (va < image.ImageBase || va - image.ImageBase > maxRva) return false;
        rva = (uint)(va - image.ImageBase);
        return true;
    }

    private static bool BinarySearch(IReadOnlyList<uint> sorted, uint value)
    {
        int lo = 0, hi = sorted.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (sorted[mid] == value) return true;
            if (sorted[mid] < value) lo = mid + 1;
            else hi = mid - 1;
        }
        return false;
    }
}
