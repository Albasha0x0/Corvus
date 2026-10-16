using System.Buffers.Binary;
using Corvus.Native.Elf;

namespace Corvus.Native.Dwarf;

/// <summary>
/// The relocations of a relocatable object's (ET_REL) DWARF sections: .rela.debug_* and .rel.debug_* applied as the
/// linker would, with each symbol's value plus its section's address (0 in an object, so code addresses are section
/// offsets). The absolute data relocations compilers emit into debug sections are applied on x64, x86, AArch64, ARM,
/// RISC-V (with the ADD/SUB/SET pairs of .debug_line), PowerPC64 and s390x; other types are reported.
/// </summary>
internal sealed class DebugRelocations
{
    /// <summary>One section header of the object, by index.</summary>
    public readonly record struct Header(int Index, string Name, uint Type, long Offset, long Size, uint Link, uint Info, ulong Address);

    private const long MaxEntries = 1 << 24;
    private const ushort EmS390 = 22;
    private readonly Dictionary<string, List<Header>> _byTarget = new(StringComparer.Ordinal);
    private readonly Dictionary<int, Header> _headers = [];
    private readonly Dictionary<uint, (ulong[] Values, ushort[] Sections)> _symbols = [];
    private readonly ushort _machine;
    private readonly bool _is64, _bigEndian;
    private readonly Func<long, int, byte[]> _read;
    private readonly List<string> _notes;

    private DebugRelocations(ushort machine, bool is64, bool bigEndian, Func<long, int, byte[]> read, List<string> notes)
    {
        (_machine, _is64, _bigEndian, _read, _notes) = (machine, is64, bigEndian, read, notes);
    }

    /// <summary>The relocations of each DWARF section of the object, or null when it has none.</summary>
    public static DebugRelocations? Of(IReadOnlyList<Header> headers, ushort machine, bool is64, bool bigEndian, Func<long, int, byte[]> read, List<string> notes)
    {
        var r = new DebugRelocations(machine, is64, bigEndian, read, notes);
        foreach (var h in headers) r._headers[h.Index] = h;
        foreach (var h in headers.Where(h => h.Type is 4 or 9))
        {
            if (!r._headers.TryGetValue((int)h.Info, out var target)) continue;
            string key = target.Name.StartsWith(".zdebug_", StringComparison.Ordinal) ? "." + target.Name[2..] : target.Name;
            if (!key.StartsWith(".debug_", StringComparison.Ordinal)) continue;
            (r._byTarget.TryGetValue(key, out var list) ? list : r._byTarget[key] = []).Add(h);
        }
        return r._byTarget.Count > 0 ? r : null;
    }

    public bool Has(string section) => _byTarget.ContainsKey(section);

    /// <summary><paramref name="data"/> (the section's bytes) with its relocations applied, in place.</summary>
    public byte[] Apply(string section, byte[] data)
    {
        var unknown = new HashSet<uint>();
        foreach (var rel in _byTarget[section])
        {
            bool rela = rel.Type == 4;
            int size = _is64 ? rela ? 24 : 16 : rela ? 12 : 8;
            long count = Math.Min(rel.Size / size, MaxEntries);
            var table = _read(rel.Offset, (int)Math.Min(count * size, int.MaxValue));
            var symbols = Symbols(rel.Link);
            for (long i = 0; i < count && (i + 1) * size <= table.Length; i++)
            {
                var e = table.AsSpan((int)(i * size));
                ulong offset = Word(e, 0), info = Word(e[(_is64 ? 8 : 4)..], 0);
                long addend = rela ? (long)Word(e[(_is64 ? 16 : 8)..], 0) : 0;
                uint type = _is64 ? (uint)info : (uint)(info & 0xFF);
                uint symbol = _is64 ? (uint)(info >> 32) : (uint)(info >> 8);
                ulong s = symbol < symbols.Values.Length ? symbols.Values[symbol] + SectionAddress(symbols.Sections[symbol]) : 0;
                if (!Patch(data, offset, type, s, addend, rela)) unknown.Add(type);
            }
        }
        if (unknown.Count > 0)
            _notes.Add($"{section}: relocation types {string.Join(", ", unknown.Order().Take(8))} of {ElfNames.Machine(_machine)} are not applied; values they set read as stored");
        return data;
    }

    private ulong SectionAddress(ushort index) => index is > 0 and < 0xFF00 && _headers.TryGetValue(index, out var h) ? h.Address : 0;

    /// <summary>One relocation: false when its type is not known.</summary>
    private bool Patch(byte[] data, ulong offset, uint type, ulong s, long addend, bool rela)
    {
        // (width in bytes, operation): 0 S + A, 1 add S + A to the stored value, 2 subtract it, 3 six-bit set, 4 six-bit subtract
        (int Width, int Op) how = (_machine, type) switch
        {
            (ElfNames.EmX64, 1) => (8, 0), // R_X86_64_64
            (ElfNames.EmX64, 10 or 11) => (4, 0), // _32, _32S
            (ElfNames.EmX64, 17) => (8, 0), // DTPOFF64
            (ElfNames.EmX64, 21) => (4, 0), // DTPOFF32
            (ElfNames.EmX86, 1) => (4, 0), // R_386_32
            (ElfNames.EmX86, 35) => (4, 0), // R_386_TLS_LDO_32
            (ElfNames.EmAarch64, 257) => (8, 0), // ABS64
            (ElfNames.EmAarch64, 258) => (4, 0), // ABS32
            (ElfNames.EmArm, 2) => (4, 0), // R_ARM_ABS32
            (ElfNames.EmArm, 32) => (4, 0), // TLS_LDO32
            (ElfNames.EmRiscV, 1) => (4, 0),
            (ElfNames.EmRiscV, 2) => (8, 0),
            (ElfNames.EmRiscV, 33) => (1, 1), (ElfNames.EmRiscV, 34) => (2, 1), (ElfNames.EmRiscV, 35) => (4, 1), (ElfNames.EmRiscV, 36) => (8, 1),
            (ElfNames.EmRiscV, 37) => (1, 2), (ElfNames.EmRiscV, 38) => (2, 2), (ElfNames.EmRiscV, 39) => (4, 2), (ElfNames.EmRiscV, 40) => (8, 2),
            (ElfNames.EmRiscV, 52) => (1, 4), (ElfNames.EmRiscV, 53) => (1, 3),
            (ElfNames.EmRiscV, 54) => (1, 0), (ElfNames.EmRiscV, 55) => (2, 0), (ElfNames.EmRiscV, 56) => (4, 0), // SET8, SET16, SET32
            (ElfNames.EmRiscV, 51) => (0, 0), // R_RISCV_RELAX: a hint
            (ElfNames.EmPpc64, 38) => (8, 0), (ElfNames.EmPpc64, 1) => (4, 0),
            (EmS390, 22) => (8, 0), (EmS390, 4) => (4, 0),
            (_, 0) => (0, 0), // NONE
            _ => (-1, 0),
        };
        if (how.Width < 0) return false;
        if (how.Width == 0 || offset > (ulong)(data.Length - how.Width)) return true;
        var at = data.AsSpan((int)offset, how.Width);
        ulong stored = Read(at);
        ulong value = how.Op switch
        {
            0 => s + (ulong)(rela ? addend : (long)stored),
            1 => stored + s + (ulong)addend,
            2 => stored - (s + (ulong)addend),
            3 => (stored & 0xC0) | ((s + (ulong)addend) & 0x3F),
            _ => (stored & 0xC0) | ((stored - (s + (ulong)addend)) & 0x3F),
        };
        Write(at, value);
        return true;
    }

    private (ulong[] Values, ushort[] Sections) Symbols(uint symtab)
    {
        if (_symbols.TryGetValue(symtab, out var cached)) return cached;
        var result = (Values: Array.Empty<ulong>(), Sections: Array.Empty<ushort>());
        if (_headers.TryGetValue((int)symtab, out var h) && h.Type is 2 or 11)
        {
            int size = _is64 ? 24 : 16;
            long count = Math.Min(h.Size / size, MaxEntries);
            var bytes = _read(h.Offset, (int)(count * size));
            count = bytes.Length / size;
            result = (new ulong[count], new ushort[count]);
            for (int i = 0; i < count; i++)
            {
                var e = bytes.AsSpan(i * size);
                result.Values[i] = _is64 ? Word(e[8..], 0) : U32(e[4..]);
                result.Sections[i] = U16(e[(_is64 ? 6 : 14)..]);
            }
        }
        return _symbols[symtab] = result;
    }

    private ulong Word(ReadOnlySpan<byte> s, int at) => _is64 ? U64(s[at..]) : U32(s[at..]);
    private ulong U64(ReadOnlySpan<byte> s) => _bigEndian ? BinaryPrimitives.ReadUInt64BigEndian(s) : BinaryPrimitives.ReadUInt64LittleEndian(s);
    private uint U32(ReadOnlySpan<byte> s) => _bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(s) : BinaryPrimitives.ReadUInt32LittleEndian(s);
    private ushort U16(ReadOnlySpan<byte> s) => _bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(s) : BinaryPrimitives.ReadUInt16LittleEndian(s);

    private ulong Read(ReadOnlySpan<byte> at) => at.Length switch
    {
        1 => at[0],
        2 => U16(at),
        4 => U32(at),
        _ => U64(at),
    };

    private void Write(Span<byte> at, ulong value)
    {
        switch (at.Length)
        {
            case 1: at[0] = (byte)value; break;
            case 2: if (_bigEndian) BinaryPrimitives.WriteUInt16BigEndian(at, (ushort)value); else BinaryPrimitives.WriteUInt16LittleEndian(at, (ushort)value); break;
            default: ByteView.Put(at, value, at.Length, _bigEndian); break;
        }
    }
}
