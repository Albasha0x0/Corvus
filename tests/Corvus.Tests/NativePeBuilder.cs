using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// Builds small PE32 / PE32+ images in memory for parser tests: DOS header at 0, PE header at 0x80, sections laid out
/// at the file and section alignment unless placed explicitly. Fields can be patched after <see cref="Build"/>.
/// </summary>
internal sealed class PeBuilder
{
    public sealed class Section
    {
        public required string Name { get; init; }
        public uint Rva { get; set; }
        public byte[] Data { get; set; } = [];
        public uint VirtualSize { get; set; }
        public uint Characteristics { get; set; } = 0x40000040; // initialized data, read
        /// <summary>Explicit raw pointer / raw size; default: laid out after the previous section.</summary>
        public uint? RawOffset { get; set; }
        public uint? RawSize { get; set; }
    }

    public bool Is64 { get; set; } = true;
    public ushort Machine { get; set; } = 0x8664;
    public ushort Characteristics { get; set; } = 0x0022;
    public ushort DllCharacteristics { get; set; } = 0x8160;
    public ulong ImageBase { get; set; } = 0x140000000;
    public uint SectionAlignment { get; set; } = 0x1000;
    public uint FileAlignment { get; set; } = 0x200;
    public uint EntryPoint { get; set; }
    public uint? SizeOfImage { get; set; }
    public uint NumberOfRvaAndSizes { get; set; } = 16;
    public (uint Rva, uint Size)[] Directories { get; } = new (uint, uint)[16];
    public List<Section> Sections { get; } = [];
    public byte[] Overlay { get; set; } = [];

    public const int PeOffset = 0x80;
    /// <summary>e_lfanew.</summary>
    public int HeaderOffset { get; set; } = PeOffset;
    public int OptionalOffset => HeaderOffset + 24;
    public int SectionTableOffset => OptionalOffset + (Is64 ? 240 : 224);

    /// <summary>RVA the next added section gets.</summary>
    public uint NextRva => Sections.Count == 0 ? SectionAlignment : Align(Sections[^1].Rva + Math.Max(Sections[^1].VirtualSize, (uint)Sections[^1].Data.Length), SectionAlignment);

    public Section Add(string name, byte[] data, uint characteristics = 0x40000040, uint? virtualSize = null)
    {
        var s = new Section { Name = name, Rva = NextRva, Data = data, Characteristics = characteristics, VirtualSize = virtualSize ?? (uint)data.Length };
        Sections.Add(s);
        return s;
    }

    /// <summary>Adds a section whose content is built knowing its RVA.</summary>
    public Section Add(string name, Func<uint, byte[]> content, uint characteristics = 0x40000040)
    {
        uint rva = NextRva;
        var data = content(rva);
        var s = new Section { Name = name, Rva = rva, Data = data, Characteristics = characteristics, VirtualSize = (uint)data.Length };
        Sections.Add(s);
        return s;
    }

    public static uint Align(uint v, uint a) => (v + a - 1) & ~(a - 1);

    public byte[] Build()
    {
        uint headers = Align((uint)(SectionTableOffset + Sections.Count * 40), FileAlignment);
        uint raw = headers;
        var placed = new List<(uint Offset, uint Size)>();
        foreach (var s in Sections)
        {
            uint size = s.RawSize ?? Align((uint)s.Data.Length, FileAlignment);
            uint offset = s.RawOffset ?? (size == 0 ? 0 : raw);
            placed.Add((offset, size));
            if (s.RawOffset == null && size != 0) raw = offset + size;
        }
        uint fileEnd = Math.Max(headers, raw);
        for (int i = 0; i < Sections.Count; i++)
            if (Sections[i].RawOffset != null)
                fileEnd = Math.Max(fileEnd, placed[i].Offset + Math.Min(placed[i].Size, (uint)Sections[i].Data.Length));
        var file = new byte[fileEnd + Overlay.Length];
        var f = file.AsSpan();

        f[0] = (byte)'M';
        f[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(f[0x3C..], HeaderOffset);
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(f[HeaderOffset..]);
        int coff = HeaderOffset + 4;
        BinaryPrimitives.WriteUInt16LittleEndian(f[coff..], Machine);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 2)..], (ushort)Sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 16)..], (ushort)(Is64 ? 240 : 224));
        BinaryPrimitives.WriteUInt16LittleEndian(f[(coff + 18)..], Characteristics);

        int o = OptionalOffset;
        BinaryPrimitives.WriteUInt16LittleEndian(f[o..], (ushort)(Is64 ? 0x20b : 0x10b));
        BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 16)..], EntryPoint);
        if (Is64) BinaryPrimitives.WriteUInt64LittleEndian(f[(o + 24)..], ImageBase);
        else BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 28)..], (uint)ImageBase);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 32)..], SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 36)..], FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(o + 40)..], 6);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(o + 48)..], 6);
        uint imageEnd = Sections.Count == 0 ? Align(headers, SectionAlignment) : Sections.Max(s => Align(s.Rva + Math.Max(s.VirtualSize, (uint)s.Data.Length), SectionAlignment));
        BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 56)..], SizeOfImage ?? imageEnd);
        BinaryPrimitives.WriteUInt32LittleEndian(f[(o + 60)..], headers);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(o + 68)..], 3);
        BinaryPrimitives.WriteUInt16LittleEndian(f[(o + 70)..], DllCharacteristics);
        int counts = o + (Is64 ? 108 : 92);
        BinaryPrimitives.WriteUInt32LittleEndian(f[counts..], NumberOfRvaAndSizes);
        for (int i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(f[(counts + 4 + i * 8)..], Directories[i].Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(counts + 8 + i * 8)..], Directories[i].Size);
        }

        for (int i = 0; i < Sections.Count; i++)
        {
            var s = Sections[i];
            int at = SectionTableOffset + i * 40;
            var name = Encoding.ASCII.GetBytes(s.Name);
            name.AsSpan(0, Math.Min(8, name.Length)).CopyTo(f[at..]);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(at + 8)..], s.VirtualSize);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(at + 12)..], s.Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(at + 16)..], placed[i].Size);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(at + 20)..], placed[i].Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(f[(at + 36)..], s.Characteristics);
            int copy = (int)Math.Min((long)s.Data.Length, Math.Max(0, file.Length - Overlay.Length - (long)placed[i].Offset));
            if (placed[i].Size != 0 && copy > 0) s.Data.AsSpan(0, Math.Min(copy, (int)placed[i].Size)).CopyTo(f[(int)placed[i].Offset..]);
        }
        Overlay.CopyTo(f[(int)fileEnd..]);
        return file;
    }
}

/// <summary>Little-endian writer for section contents (tables, strings) at known RVAs.</summary>
internal sealed class PeBlob
{
    private readonly List<byte> bytes = [];

    public PeBlob(uint rva) => Rva = rva;

    public uint Rva { get; }
    public uint Here => Rva + (uint)bytes.Count;
    public int Length => bytes.Count;

    public uint U16(ushort v) { uint at = Here; bytes.Add((byte)v); bytes.Add((byte)(v >> 8)); return at; }
    public uint U32(uint v) { uint at = Here; for (int i = 0; i < 4; i++) bytes.Add((byte)(v >> (8 * i))); return at; }
    public uint U64(ulong v) { uint at = Here; for (int i = 0; i < 8; i++) bytes.Add((byte)(v >> (8 * i))); return at; }
    public uint Ptr(bool is64, ulong v) => is64 ? U64(v) : U32((uint)v);
    public uint Bytes(ReadOnlySpan<byte> b) { uint at = Here; bytes.AddRange(b.ToArray()); return at; }
    public uint Ascii(string s) { uint at = Here; bytes.AddRange(Encoding.ASCII.GetBytes(s)); bytes.Add(0); return at; }
    public uint Utf16(string s) { uint at = Here; bytes.AddRange(Encoding.Unicode.GetBytes(s)); return at; }
    public uint Zero(int n) { uint at = Here; bytes.AddRange(new byte[n]); return at; }
    public void Align(int a) { while (bytes.Count % a != 0) bytes.Add(0); }

    /// <summary>Overwrites a 32-bit value written earlier at <paramref name="rva"/>.</summary>
    public void Patch32(uint rva, uint v)
    {
        int at = (int)(rva - Rva);
        for (int i = 0; i < 4; i++) bytes[at + i] = (byte)(v >> (8 * i));
    }

    public void Patch16(uint rva, ushort v)
    {
        int at = (int)(rva - Rva);
        bytes[at] = (byte)v;
        bytes[at + 1] = (byte)(v >> 8);
    }

    public byte[] ToArray() => [.. bytes];
}
