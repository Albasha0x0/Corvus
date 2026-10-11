using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace Corvus.Native.Go;

/// <summary>Layout generation of a Go function table, by its header magic.</summary>
public enum GoTableVersion { Go12, Go116, Go118, Go120 }

/// <summary>One function of a Go function table: entry RVA, size up to the next entry, and its Go name.</summary>
public readonly record struct GoFunction(uint Rva, uint Size, string? Name);

/// <summary>
/// The Go runtime's function table (pclntab) of any Go 1.2 to 1.24 build, ELF, PE or Mach-O, stripped or not: found by
/// section name (.gopclntab, __gopclntab) or else by its header magic in the image's sections, then validated (entries
/// ascending and in code, names printable).
/// </summary>
public sealed class GoFunctionTable
{
    private const int MaxFunctions = 1 << 21;
    private const int MaxName = 4096;
    private static readonly ConditionalWeakTable<INativeImage, StrongBox<GoFunctionTable?>> Cache = new();

    public GoTableVersion Version { get; }
    /// <summary>RVA of the table header.</summary>
    public uint Rva { get; }
    /// <summary>Sorted by RVA.</summary>
    public IReadOnlyList<GoFunction> Functions { get; }

    private GoFunctionTable(GoTableVersion version, uint rva, List<GoFunction> functions)
    {
        Version = version;
        Rva = rva;
        Functions = functions;
    }

    /// <summary>The image's Go function table, or null when it has none (read once per image).</summary>
    public static GoFunctionTable? Of(INativeImage image) => Cache.GetValue(image, i => new StrongBox<GoFunctionTable?>(Find(i))).Value;

    /// <summary>The Go releases that write this layout.</summary>
    public string VersionText => Version switch
    {
        GoTableVersion.Go12 => "go1.2-1.15",
        GoTableVersion.Go116 => "go1.16-1.17",
        GoTableVersion.Go118 => "go1.18-1.19",
        _ => "go1.20+",
    };

    private static GoFunctionTable? Find(INativeImage image)
    {
        try
        {
            if (image.Arch is not (NativeArch.X86 or NativeArch.X64 or NativeArch.Arm or NativeArch.Arm64 or NativeArch.RiscV or NativeArch.Mips or NativeArch.PowerPc)) return null;
            var named = image.Sections.Where(s => s.Name.EndsWith("gopclntab", StringComparison.Ordinal)).ToList();
            foreach (var s in named)
                if (Read(image, s.Rva, s.MappedSize) is { } t) return t;
            if (named.Count > 0) return null;
            // stripped of section names (PE keeps runtime.pclntab in .rdata): look for the header in data, then in code
            byte[]? buffer = null;
            foreach (var s in image.Sections.OrderBy(s => s.IsExecutable))
                if (s.MappedSize >= 64 && Scan(image, s, buffer ??= new byte[ScanChunk + 16]) is { } t) return t;
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException) { }
        return null;
    }

    private const int ScanChunk = 1 << 16;

    private static GoFunctionTable? Scan(INativeImage image, NativeSection s, byte[] bytes)
    {
        const int Chunk = ScanChunk;
        for (uint offset = 0; offset < s.MappedSize; offset += Chunk)
        {
            int n = image.Read(s.Rva + offset, bytes);
            for (int p = 0; p + 16 <= n && p < Chunk; p += 4)
            {
                if (bytes[p + 3] != 0xFF || bytes[p + 2] != 0xFF || bytes[p + 1] != 0xFF || bytes[p + 4] != 0 || bytes[p + 5] != 0) continue;
                if (Header(bytes.AsSpan(p)) == null) continue;
                uint at = offset + (uint)p;
                if (Read(image, s.Rva + at, s.MappedSize - at) is { } t) return t;
            }
            if (n < Chunk) break;
        }
        return null;
    }

    private static GoFunctionTable? Read(INativeImage image, uint rva, uint size)
    {
        if (size < 64 || size > 1 << 28) return null;
        var bytes = new byte[size];
        int n = image.Read(rva, bytes);
        if (n < bytes.Length) Array.Resize(ref bytes, n);
        return Header(bytes) != null ? Parse(image, bytes, rva) : null;
    }

    private static GoTableVersion? Header(ReadOnlySpan<byte> t)
    {
        if (t.Length < 16 || t[4] != 0 || t[5] != 0 || t[6] is not (1 or 2 or 4) || t[7] is not (4 or 8)) return null;
        return BinaryPrimitives.ReadUInt32LittleEndian(t) switch
        {
            0xFFFFFFFB => GoTableVersion.Go12,
            0xFFFFFFFA => GoTableVersion.Go116,
            0xFFFFFFF0 => GoTableVersion.Go118,
            0xFFFFFFF1 => GoTableVersion.Go120,
            _ => null,
        };
    }

    private static GoFunctionTable? Parse(INativeImage image, byte[] t, uint rva)
    {
        var version = Header(t)!.Value;
        int ptr = t[7];
        if (ptr != (image.Is64Bit ? 8 : 4)) return null;
        ulong Ptr(long off) => off < 0 || off + ptr > t.Length ? ulong.MaxValue : ptr == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(t.AsSpan((int)off)) : BinaryPrimitives.ReadUInt32LittleEndian(t.AsSpan((int)off));
        uint U32(long off) => off < 0 || off + 4 > t.Length ? uint.MaxValue : BinaryPrimitives.ReadUInt32LittleEndian(t.AsSpan((int)off));

        ulong nfunc = Ptr(8);
        if (nfunc == 0 || nfunc > MaxFunctions) return null;
        int count = (int)nfunc;
        // where entries, func records and names are, per layout
        long functab, nameBase;
        ulong textStart = 0;
        switch (version)
        {
            case GoTableVersion.Go12:
                functab = 8 + ptr;
                nameBase = 0;
                break;
            case GoTableVersion.Go116:
                nameBase = (long)Ptr(8 + 2 * ptr);
                functab = (long)Ptr(8 + 6 * ptr);
                break;
            default:
                textStart = Ptr(8 + 2 * ptr);
                nameBase = (long)Ptr(8 + 3 * ptr);
                functab = (long)Ptr(8 + 7 * ptr);
                // the field is relocated at load; an image whose rebases are not applied leaves it 0
                if (textStart == 0 && image.Sections.FirstOrDefault(s => s.IsExecutable) is { } text) textStart = image.ImageBase + text.Rva;
                break;
        }
        if (functab <= 0 || functab >= t.Length || nameBase < 0 || nameBase >= t.Length) return null;
        bool wide = version is GoTableVersion.Go12 or GoTableVersion.Go116;
        int entrySize = wide ? 2 * ptr : 8;
        if (functab + (long)(count + 1) * entrySize > t.Length) return null;
        long recordBase = version == GoTableVersion.Go12 ? 0 : functab;

        ulong Entry(int i) => wide ? Ptr(functab + (long)i * entrySize) : U32(functab + (long)i * entrySize) + textStart;
        long Record(int i) => (long)(wide ? Ptr(functab + (long)i * entrySize + ptr) : U32(functab + (long)i * entrySize + 4));

        var functions = new List<GoFunction>(count);
        ulong previous = 0;
        int bad = 0;
        for (int i = 0; i < count; i++)
        {
            ulong va = Entry(i), next = Entry(i + 1);
            if (va < previous || va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) { bad++; continue; }
            previous = va;
            uint at = (uint)(va - image.ImageBase);
            if (image.SectionAt(at) is not { IsExecutable: true }) { bad++; continue; }
            long record = recordBase + Record(i);
            int nameOff = record + ptr + 4 <= t.Length && record >= 0 ? BinaryPrimitives.ReadInt32LittleEndian(t.AsSpan((int)(record + (wide ? ptr : 4)))) : -1;
            string? name = nameOff >= 0 ? Name(t, nameBase + nameOff) : null;
            uint size = next > va && next - va < uint.MaxValue ? (uint)(next - va) : 0;
            functions.Add(new GoFunction(at, size, name));
        }
        // a table is valid when nearly every entry is in code and most have names
        if (functions.Count == 0 || bad > count / 16 || functions.Count(f => f.Name != null) < functions.Count * 3 / 4) return null;
        return new GoFunctionTable(version, rva, functions);
    }

    private static string? Name(ReadOnlySpan<byte> t, long at)
    {
        if (at < 0 || at >= t.Length) return null;
        var rest = t[(int)at..];
        int end = rest[..Math.Min(rest.Length, MaxName)].IndexOf((byte)0);
        if (end <= 0) return null;
        foreach (byte b in rest[..end])
            if (b < 0x20 || b == 0x7F) return null;
        return Encoding.UTF8.GetString(rest[..end]);
    }
}
