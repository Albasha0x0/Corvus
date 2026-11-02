using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>One section of a <see cref="PeSpec"/>; the virtual size is the length of <paramref name="Raw"/>.</summary>
internal sealed record SectionSpec(string Name, uint Characteristics, byte[] Raw);

/// <summary>An absolute pointer at <paramref name="Offset"/> in a section, written as image base plus <paramref name="TargetRva"/>.</summary>
internal sealed record PointerSite(string Section, int Offset, uint TargetRva);

/// <summary>Layout of a synthetic PE; a null <paramref name="ImageBase"/> picks the usual base of the width.</summary>
internal sealed record PeSpec(
    bool Is64Bit,
    IReadOnlyList<SectionSpec> Sections,
    IReadOnlyList<PointerSite>? Pointers = null,
    ulong? ImageBase = null,
    uint FileAlignment = 0x200,
    uint SectionAlignment = 0x1000)
{
    /// <summary>The image base written to the optional header.</summary>
    public ulong Base => ImageBase ?? (Is64Bit ? 0x140000000UL : 0x10000000UL);
}

/// <summary>Builds synthetic PE files and their mapped form for rebuild tests.</summary>
internal static class RebuildFixtures
{
    private const int Dos = 0x40;
    private const ushort Dir64 = 10;
    private const ushort HighLow = 3;

    /// <summary>Returns a PE file in file layout; pointer sites get a .reloc section. Throws on a site outside its section.</summary>
    public static byte[] Pe(PeSpec spec)
    {
        var sections = spec.Sections.Select(s => (s.Name, s.Characteristics, Raw: (byte[])s.Raw.Clone())).ToList();
        var rva = new List<uint>();
        uint next = spec.SectionAlignment;
        foreach (var s in sections)
        {
            rva.Add(next);
            next = Align(next + (uint)Math.Max(s.Raw.Length, 1), spec.SectionAlignment);
        }

        var sites = new List<uint>();
        foreach (var p in spec.Pointers ?? [])
        {
            int i = sections.FindIndex(s => s.Name == p.Section);
            int width = spec.Is64Bit ? 8 : 4;
            if (i < 0 || p.Offset < 0 || p.Offset + width > sections[i].Raw.Length)
                throw new ArgumentException($"Pointer site {p.Section}+{p.Offset:X} is outside its section.");
            ulong value = spec.Base + p.TargetRva;
            if (spec.Is64Bit) BinaryPrimitives.WriteUInt64LittleEndian(sections[i].Raw.AsSpan(p.Offset), value);
            else BinaryPrimitives.WriteUInt32LittleEndian(sections[i].Raw.AsSpan(p.Offset), (uint)value);
            sites.Add(rva[i] + (uint)p.Offset);
        }

        uint relocRva = 0, relocSize = 0;
        if (sites.Count > 0)
        {
            var table = RelocationTable(sites, spec.Is64Bit);
            relocRva = next;
            relocSize = (uint)table.Length;
            sections.Add((".reloc", 0x42000040, table));
            rva.Add(relocRva);
            next = Align(next + relocSize, spec.SectionAlignment);
        }

        int optional = spec.Is64Bit ? 240 : 224;
        uint headers = Align((uint)(Dos + 4 + 20 + optional + 40 * sections.Count), spec.FileAlignment);
        var rawOffsets = new List<uint>();
        uint file = headers;
        foreach (var s in sections)
        {
            rawOffsets.Add(file);
            file += Align((uint)s.Raw.Length, spec.FileAlignment);
        }

        var pe = new byte[file];
        pe[0] = (byte)'M';
        pe[1] = (byte)'Z';
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(0x3C), Dos);
        int at = Dos;
        Encoding.ASCII.GetBytes("PE\0\0").CopyTo(pe, at);
        at += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at), spec.Is64Bit ? (ushort)0x8664 : (ushort)0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 2), (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 16), (ushort)optional);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 18), spec.Is64Bit ? (ushort)0x2022 : (ushort)0x2102);
        at += 20;
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at), spec.Is64Bit ? (ushort)0x20B : (ushort)0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 32), spec.SectionAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 36), spec.FileAlignment);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 40), 6);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 48), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 56), next);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 60), headers);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(at + 68), 3);
        int dirs;
        if (spec.Is64Bit)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 24), spec.Base);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 72), 0x100000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 80), 0x1000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 88), 0x100000);
            BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(at + 96), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 108), 16);
            dirs = at + 112;
        }
        else
        {
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 28), (uint)spec.Base);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 72), 0x100000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 76), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 80), 0x100000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 84), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 92), 16);
            dirs = at + 96;
        }
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 5 * 8), relocRva);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(dirs + 5 * 8 + 4), relocSize);

        int headerTable = at + optional;
        for (int i = 0; i < sections.Count; i++)
        {
            int h = headerTable + 40 * i;
            var name = Encoding.ASCII.GetBytes(sections[i].Name);
            name.AsSpan(0, Math.Min(8, name.Length)).CopyTo(pe.AsSpan(h));
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 8), (uint)sections[i].Raw.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 12), rva[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 16), Align((uint)sections[i].Raw.Length, spec.FileAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 20), rawOffsets[i]);
            BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(h + 36), sections[i].Characteristics);
            sections[i].Raw.CopyTo(pe, (int)rawOffsets[i]);
        }
        return pe;
    }

    /// <summary>Returns the image in mapped layout, each section at its virtual address; a malformed file throws.</summary>
    public static byte[] Mapped(byte[] file)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int optional = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        int opt = nt + 24;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(opt + 56));
        uint headers = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(opt + 60));
        var mapped = new byte[size];
        file.AsSpan(0, (int)Math.Min(headers, (uint)file.Length)).CopyTo(mapped);
        for (int i = 0; i < count; i++)
        {
            int h = opt + optional + 40 * i;
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 8));
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 12));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 16));
            uint rawAt = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 20));
            file.AsSpan((int)rawAt, (int)Math.Min(rawSize, virtualSize)).CopyTo(mapped.AsSpan((int)va));
        }
        return mapped;
    }

    private static byte[] RelocationTable(List<uint> sites, bool is64)
    {
        var table = new List<byte>();
        foreach (var page in sites.GroupBy(s => s & ~0xFFFu).OrderBy(g => g.Key))
        {
            var entries = page.Order().Select(s => (ushort)(((uint)(is64 ? Dir64 : HighLow) << 12) | (s & 0xFFF))).ToList();
            if (entries.Count % 2 != 0) entries.Add(0);
            var block = new byte[8 + entries.Count * 2];
            BinaryPrimitives.WriteUInt32LittleEndian(block, page.Key);
            BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4), (uint)block.Length);
            for (int i = 0; i < entries.Count; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(8 + i * 2), entries[i]);
            table.AddRange(block);
        }
        return [.. table];
    }

    private static uint Align(uint value, uint alignment) => (value + alignment - 1) / alignment * alignment;
}
