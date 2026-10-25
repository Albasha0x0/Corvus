using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>A section the fixture writes: name, characteristics, raw bytes and (offset, symbol index, type) relocations.</summary>
public sealed record CoffFixtureSection(string Name, uint Characteristics, byte[] Data, (uint Offset, int Symbol, ushort Type)[] Relocations);

/// <summary>A symbol table record the fixture writes, without auxiliary records.</summary>
public sealed record CoffFixtureSymbol(string Name, uint Value, short Section, ushort Type, byte Storage);

/// <summary>COFF objects and Microsoft librarian archives written from their parts, as the PE and COFF specification lays them out.</summary>
public static class CoffFixtures
{
    public const uint Code = 0x6000_0020; // IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ
    public const uint Data = 0xC000_0040; // IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE

    private static readonly byte[] BigObjId = [0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8];

    /// <summary>An object of <paramref name="machine"/>; names over 8 bytes go to the string table.</summary>
    public static byte[] Object(ushort machine, IReadOnlyList<CoffFixtureSection> sections, IReadOnlyList<CoffFixtureSymbol> symbols, bool bigObj = false)
    {
        var strings = new MemoryStream();
        strings.Write(new byte[4]);
        uint Intern(string s)
        {
            uint at = (uint)strings.Length;
            strings.Write(Encoding.UTF8.GetBytes(s));
            strings.WriteByte(0);
            return at;
        }
        int header = bigObj ? 56 : 20, symbolSize = bigObj ? 20 : 18;
        int at = header + sections.Count * 40;
        var raw = new List<(int Data, int Relocs)>();
        foreach (var s in sections)
        {
            int data = at;
            at += s.Data.Length;
            raw.Add((data, s.Relocations.Length == 0 ? 0 : at));
            at += s.Relocations.Length * 10;
        }
        int symbolTable = at;
        var file = new byte[symbolTable + symbols.Count * symbolSize];
        var span = file.AsSpan();
        if (bigObj)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(span[2..], 0xFFFF);
            BinaryPrimitives.WriteUInt16LittleEndian(span[4..], 2);
            BinaryPrimitives.WriteUInt16LittleEndian(span[6..], machine);
            BigObjId.CopyTo(span[12..]);
            BinaryPrimitives.WriteUInt32LittleEndian(span[44..], (uint)sections.Count);
            BinaryPrimitives.WriteUInt32LittleEndian(span[48..], (uint)symbolTable);
            BinaryPrimitives.WriteUInt32LittleEndian(span[52..], (uint)symbols.Count);
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(span, machine);
            BinaryPrimitives.WriteUInt16LittleEndian(span[2..], (ushort)sections.Count);
            BinaryPrimitives.WriteUInt32LittleEndian(span[8..], (uint)symbolTable);
            BinaryPrimitives.WriteUInt32LittleEndian(span[12..], (uint)symbols.Count);
        }
        for (int i = 0; i < sections.Count; i++)
        {
            var s = sections[i];
            var h = span[(header + i * 40)..];
            var name = s.Name.Length <= 8 ? Encoding.UTF8.GetBytes(s.Name) : Encoding.ASCII.GetBytes("/" + Intern(s.Name));
            name.CopyTo(h);
            BinaryPrimitives.WriteUInt32LittleEndian(h[16..], (uint)s.Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(h[20..], (uint)raw[i].Data);
            BinaryPrimitives.WriteUInt32LittleEndian(h[24..], (uint)raw[i].Relocs);
            BinaryPrimitives.WriteUInt16LittleEndian(h[32..], (ushort)s.Relocations.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(h[36..], s.Characteristics);
            s.Data.CopyTo(span[raw[i].Data..]);
            for (int r = 0; r < s.Relocations.Length; r++)
            {
                var rel = span[(raw[i].Relocs + r * 10)..];
                BinaryPrimitives.WriteUInt32LittleEndian(rel, s.Relocations[r].Offset);
                BinaryPrimitives.WriteUInt32LittleEndian(rel[4..], (uint)s.Relocations[r].Symbol);
                BinaryPrimitives.WriteUInt16LittleEndian(rel[8..], s.Relocations[r].Type);
            }
        }
        for (int i = 0; i < symbols.Count; i++)
        {
            var y = symbols[i];
            var e = span[(symbolTable + i * symbolSize)..];
            if (y.Name.Length <= 8) Encoding.UTF8.GetBytes(y.Name).CopyTo(e);
            else BinaryPrimitives.WriteUInt32LittleEndian(e[4..], Intern(y.Name));
            BinaryPrimitives.WriteUInt32LittleEndian(e[8..], y.Value);
            int tail = bigObj ? 16 : 14;
            if (bigObj) BinaryPrimitives.WriteInt32LittleEndian(e[12..], y.Section);
            else BinaryPrimitives.WriteInt16LittleEndian(e[12..], y.Section);
            BinaryPrimitives.WriteUInt16LittleEndian(e[tail..], y.Type);
            e[tail + 2] = y.Storage;
        }
        var table = strings.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(table, (uint)table.Length);
        return [.. file, .. table];
    }

    /// <summary>
    /// An archive as Microsoft's librarian writes it: a "/" linker member, a "//" long-name member whose names end with
    /// NUL, then the members (names over 15 bytes as "/offset").
    /// </summary>
    public static byte[] Library(params (string Name, byte[] Data)[] members)
    {
        var output = new MemoryStream();
        output.Write("!<arch>\n"u8);
        void Member(string name, byte[] data)
        {
            output.Write(Encoding.ASCII.GetBytes($"{name,-16}{"0",-12}{"",-6}{"",-6}{"0",-8}{data.Length,-10}`\n"));
            output.Write(data);
            if ((data.Length & 1) != 0) output.WriteByte((byte)'\n');
        }
        Member("/", new byte[4]);
        var longNames = new MemoryStream();
        var named = members.Select(m =>
        {
            if (m.Name.Length < 16) return (Header: m.Name + "/", m.Data);
            var header = "/" + longNames.Length;
            longNames.Write(Encoding.UTF8.GetBytes(m.Name));
            longNames.WriteByte(0);
            return (Header: header, m.Data);
        }).ToList();
        Member("//", longNames.ToArray());
        foreach (var (header, data) in named) Member(header, data);
        return output.ToArray();
    }
}
