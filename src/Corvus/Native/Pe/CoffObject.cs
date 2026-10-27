using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native.Pe;

/// <summary>A section of a COFF object: its raw bytes and the relocations the linker applies to them.</summary>
public sealed record CoffSection(int Number, string Name, uint Characteristics, byte[] Data, IReadOnlyList<CoffRelocation> Relocations)
{
    /// <summary>IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE.</summary>
    public bool IsCode => (Characteristics & 0x20) != 0 || (Characteristics & 0x2000_0000) != 0;

    /// <summary>IMAGE_SCN_LNK_COMDAT: the linker keeps one copy of the section among the objects that define it.</summary>
    public bool IsComdat => (Characteristics & 0x1000) != 0;
}

/// <summary>A relocation: the offset in its section, the symbol it refers to and the machine's relocation type.</summary>
public readonly record struct CoffRelocation(uint Offset, int Symbol, ushort Type);

/// <summary>A symbol table record; <see cref="Section"/> is 1-based, 0 for undefined, negative for absolute and debug.</summary>
public sealed record CoffSymbol(int Index, string Name, uint Value, int Section, ushort Type, byte StorageClass)
{
    /// <summary>IMAGE_SYM_DTYPE_FUNCTION in the complex type bits.</summary>
    public bool IsFunction => (Type & 0x30) == 0x20;

    /// <summary>IMAGE_SYM_CLASS_EXTERNAL.</summary>
    public bool IsExternal => StorageClass == 2;
}

/// <summary>A COFF object file (regular or /bigobj): sections, relocations and symbols, unlinked.</summary>
public sealed class CoffObject
{
    private const int MaxSections = 1 << 16;

    // ANON_OBJECT_HEADER_BIGOBJ class id {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}.
    private static readonly byte[] BigObjId = [0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8];

    public ushort Machine { get; }
    public NativeArch Arch => PeNames.Arch(Machine);
    public IReadOnlyList<CoffSection> Sections { get; }
    public IReadOnlyList<CoffSymbol> Symbols { get; }

    private CoffObject(ushort machine, IReadOnlyList<CoffSection> sections, IReadOnlyList<CoffSymbol> symbols)
    {
        Machine = machine;
        Sections = sections;
        Symbols = symbols;
    }

    /// <summary>The object in <paramref name="data"/>; null with <paramref name="reason"/> for import, LTCG or non-COFF input.</summary>
    public static CoffObject? Read(ReadOnlySpan<byte> data, out string? reason)
    {
        reason = null;
        if (data.Length < 20) { reason = "shorter than a COFF file header"; return null; }
        ushort sig1 = U16(data, 0), sig2 = U16(data, 2);
        bool bigObj = false;
        if (sig1 == 0 && sig2 == 0xFFFF)
        {
            ushort version = U16(data, 4);
            if (data.Length >= 56 && version >= 2 && data.Slice(12, 16).SequenceEqual(BigObjId)) bigObj = true;
            else
            {
                reason = version == 0 ? "an import object (it names a DLL export; no code)" : "an anonymous object (link-time code generation: no machine code)";
                return null;
            }
        }
        ushort machine = bigObj ? U16(data, 6) : sig1;
        // IMAGE_FILE_MACHINE_UNKNOWN: an object of directives or data that runs on any machine.
        if (machine == 0) { reason = "an object with no machine (directives or data only)"; return null; }
        if (PeNames.Arch(machine) == NativeArch.Unknown) { reason = $"machine 0x{machine:X4} is not a known COFF machine"; return null; }
        long sectionCount = bigObj ? U32(data, 44) : U16(data, 2);
        long symbolTable = bigObj ? U32(data, 48) : U32(data, 8);
        long symbolCount = bigObj ? U32(data, 52) : U32(data, 12);
        int optional = bigObj ? 0 : U16(data, 16);
        int symbolSize = bigObj ? 20 : 18;
        long sectionTable = (bigObj ? 56 : 20) + optional;
        if (sectionCount > MaxSections || sectionTable + sectionCount * 40 > data.Length) { reason = "the section table runs past the end of the file"; return null; }
        if (symbolTable < 0 || symbolTable + symbolCount * symbolSize > data.Length || symbolCount > PeLimits.MaxSymbols)
        {
            reason = "the symbol table runs past the end of the file";
            return null;
        }
        long strings = symbolTable + symbolCount * symbolSize;
        var sections = new List<CoffSection>((int)sectionCount);
        for (int i = 0; i < sectionCount; i++)
        {
            int at = (int)(sectionTable + i * 40);
            var name = SectionName(data, at, strings);
            uint size = U32(data, at + 16), raw = U32(data, at + 20), relocAt = U32(data, at + 24), characteristics = U32(data, at + 36);
            int relocCount = U16(data, at + 32);
            // IMAGE_SCN_LNK_NRELOC_OVFL: the real count is in the first relocation's address field.
            bool overflow = (characteristics & 0x0100_0000) != 0 && relocCount == 0xFFFF;
            // IMAGE_SCN_CNT_UNINITIALIZED_DATA has no raw bytes.
            byte[] bytes = (characteristics & 0x80) != 0 || raw == 0 ? [] : raw + (long)size <= data.Length ? data.Slice((int)raw, (int)size).ToArray() : [];
            var relocations = new List<CoffRelocation>();
            if (relocAt != 0)
            {
                long count = overflow && relocAt + 10 <= data.Length ? U32(data, (int)relocAt) : relocCount;
                for (long r = overflow ? 1 : 0; r < count && relocAt + (r + 1) * 10 <= data.Length && relocations.Count < PeLimits.MaxRelocations; r++)
                {
                    int ra = (int)(relocAt + r * 10);
                    relocations.Add(new CoffRelocation(U32(data, ra), (int)U32(data, ra + 4), U16(data, ra + 8)));
                }
            }
            sections.Add(new CoffSection(i + 1, name, characteristics, bytes, relocations));
        }
        var symbols = new List<CoffSymbol>();
        for (long i = 0; i < symbolCount; i++)
        {
            int at = (int)(symbolTable + i * symbolSize);
            uint value = U32(data, at + 8);
            int section = bigObj ? (int)U32(data, at + 12) : (short)U16(data, at + 12);
            int tail = bigObj ? 16 : 14;
            ushort type = U16(data, at + tail);
            byte storage = data[at + tail + 2];
            int aux = data[at + tail + 3];
            symbols.Add(new CoffSymbol((int)i, SymbolName(data, at, strings), value, section, type, storage));
            i += aux;
        }
        return new CoffObject(machine, sections, symbols);
    }

    /// <summary>Bytes a relocation of <paramref name="type"/> rewrites on <paramref name="machine"/>; 0 for ABSOLUTE and unknown types.</summary>
    public static int Width(ushort machine, ushort type) => PeNames.Arch(machine) switch
    {
        NativeArch.X64 => type switch { 1 => 8, (>= 2 and <= 9) or 0xB or 0xD or 0xE or 0x10 => 4, 0xA => 2, 0xC => 1, _ => 0 },
        NativeArch.X86 => type switch { 6 or 7 or 0xB or 0xC or 0x14 => 4, 0xA => 2, 0xD => 1, _ => 0 },
        NativeArch.Arm64 => type switch { >= 1 and <= 0xC or 0xF or 0x10 or 0x11 => 4, 0xD => 2, 0xE => 8, _ => 0 },
        // MOV32 and THUMB_MOV32 rewrite a MOVW and MOVT pair.
        NativeArch.Arm => type switch { 1 or 2 or 3 or 4 or 0xA or 0xF or 0x12 or 0x14 or 0x15 => 4, 0x10 or 0x11 => 8, 0xE => 2, _ => 0 },
        _ => 0,
    };

    private static string SectionName(ReadOnlySpan<byte> data, int at, long strings)
    {
        var raw = data.Slice(at, 8);
        int len = raw.IndexOf((byte)0);
        var name = Encoding.UTF8.GetString(raw[..(len < 0 ? 8 : len)]);
        // A long name is "/<decimal offset>" into the string table.
        return name.Length > 1 && name[0] == '/' && uint.TryParse(name.AsSpan(1), out uint offset) ? StringAt(data, strings + offset) ?? name : name;
    }

    private static string SymbolName(ReadOnlySpan<byte> data, int at, long strings)
    {
        if (U32(data, at) != 0)
        {
            var raw = data.Slice(at, 8);
            int len = raw.IndexOf((byte)0);
            return Encoding.UTF8.GetString(raw[..(len < 0 ? 8 : len)]);
        }
        return StringAt(data, strings + U32(data, at + 4)) ?? "";
    }

    private static string? StringAt(ReadOnlySpan<byte> data, long at)
    {
        if (at < 0 || at >= data.Length) return null;
        var rest = data.Slice((int)at, (int)Math.Min(data.Length - at, PeLimits.MaxNameLength));
        int end = rest.IndexOf((byte)0);
        return end > 0 ? Encoding.UTF8.GetString(rest[..end]) : null;
    }

    private static ushort U16(ReadOnlySpan<byte> d, int at) => BinaryPrimitives.ReadUInt16LittleEndian(d[at..]);
    private static uint U32(ReadOnlySpan<byte> d, int at) => BinaryPrimitives.ReadUInt32LittleEndian(d[at..]);
}
