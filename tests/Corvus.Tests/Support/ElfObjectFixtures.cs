using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>A .symtab entry the fixture writes; <see cref="Section"/> 1 is .text, 0 undefined.</summary>
public sealed record ElfObjectSymbol(string Name, ulong Value, ulong Size, byte Type, byte Bind, ushort Section);

/// <summary>
/// ELF64 little-endian relocatable objects (ET_REL) written from their parts as the System V ABI lays them out:
/// .text, .rela.text, .symtab, .strtab and .shstrtab.
/// </summary>
public static class ElfObjectFixtures
{
    public const byte Function = 2, NoType = 0, Object = 1, Local = 0, Global = 1;

    /// <summary>An object of <paramref name="machine"/>; symbol i of <paramref name="symbols"/> has index i + 1.</summary>
    public static byte[] Write(ushort machine, byte[] text, (ulong Offset, uint Type, int Symbol, long Addend)[] relocations, ElfObjectSymbol[] symbols)
    {
        var strtab = new MemoryStream();
        strtab.WriteByte(0);
        uint Name(MemoryStream table, string s)
        {
            uint at = (uint)table.Length;
            table.Write(Encoding.UTF8.GetBytes(s));
            table.WriteByte(0);
            return at;
        }
        // Locals come first; sh_info of .symtab is the first global's index.
        var symtab = new byte[(symbols.Length + 1) * 24];
        for (int i = 0; i < symbols.Length; i++)
        {
            var y = symbols[i];
            var e = symtab.AsSpan((i + 1) * 24);
            BinaryPrimitives.WriteUInt32LittleEndian(e, Name(strtab, y.Name));
            e[4] = (byte)(y.Bind << 4 | y.Type);
            BinaryPrimitives.WriteUInt16LittleEndian(e[6..], y.Section);
            BinaryPrimitives.WriteUInt64LittleEndian(e[8..], y.Value);
            BinaryPrimitives.WriteUInt64LittleEndian(e[16..], y.Size);
        }
        var rela = new byte[relocations.Length * 24];
        for (int i = 0; i < relocations.Length; i++)
        {
            var (offset, type, symbol, addend) = relocations[i];
            var e = rela.AsSpan(i * 24);
            BinaryPrimitives.WriteUInt64LittleEndian(e, offset);
            BinaryPrimitives.WriteUInt64LittleEndian(e[8..], (ulong)symbol << 32 | type);
            BinaryPrimitives.WriteInt64LittleEndian(e[16..], addend);
        }
        var shstrtab = new MemoryStream();
        shstrtab.WriteByte(0);
        uint[] names = [0, Name(shstrtab, ".text"), Name(shstrtab, ".rela.text"), Name(shstrtab, ".symtab"), Name(shstrtab, ".strtab"), Name(shstrtab, ".shstrtab")];
        byte[][] bodies = [[], text, rela, symtab, strtab.ToArray(), shstrtab.ToArray()];
        var file = new MemoryStream();
        file.Write(new byte[64]);
        var offsets = new long[bodies.Length];
        for (int i = 1; i < bodies.Length; i++)
        {
            while (file.Length % 8 != 0) file.WriteByte(0);
            offsets[i] = file.Length;
            file.Write(bodies[i]);
        }
        while (file.Length % 8 != 0) file.WriteByte(0);
        long shoff = file.Length;
        int firstGlobal = 1 + symbols.Count(y => y.Bind == Local);
        // (type, flags, link, info, align, entry size) per section; SHF_ALLOC | SHF_EXECINSTR for .text, SHF_INFO_LINK for .rela.text.
        (uint, ulong, uint, uint, ulong, ulong)[] headers = [(0, 0, 0, 0, 0, 0), (1, 6, 0, 0, 16, 0), (4, 0x40, 3, 1, 8, 24), (2, 0, 4, (uint)firstGlobal, 8, 24), (3, 0, 0, 0, 1, 0), (3, 0, 0, 0, 1, 0)];
        for (int i = 0; i < headers.Length; i++)
        {
            var (type, flags, link, info, align, entry) = headers[i];
            var h = new byte[64];
            BinaryPrimitives.WriteUInt32LittleEndian(h, names[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(4), type);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(8), flags);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(24), (ulong)offsets[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(32), (ulong)bodies[i].Length);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(40), link);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(44), info);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(48), align);
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(56), entry);
            file.Write(h);
        }
        var bytes = file.ToArray();
        "\u007fELF"u8.CopyTo(bytes);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(16), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(18), machine);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(40), (ulong)shoff);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(52), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(58), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(60), (ushort)headers.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(62), (ushort)(headers.Length - 1));
        return bytes;
    }
}
