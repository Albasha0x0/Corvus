using System.Buffers.Binary;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Builds a small x64 (or, with <see cref="Is32"/>, x86) NativeAOT-shaped PE: .text (code), .rdata (blobs, module header),
/// .data (MethodTables, frozen objects), an uninitialized "hydrated" section and .reloc for every pointer written through
/// <see cref="Pointer"/>.
/// </summary>
internal sealed class NativeAotBuilder
{
    public const ulong ImageBase64 = 0x140000000, ImageBase32 = 0x400000;
    public const uint TextRva = 0x1000, RdataRva = 0x2000, DataRva = 0x10000, HydratedRva = 0x20000, RelocRva = 0x30000;
    public const uint HydratedSize = 0x8000;

    /// <summary>An x86 image: 4-byte pointers, HIGHLOW relocations, 16-byte header rows.</summary>
    public bool Is32 { get; init; }
    public ulong ImageBase => Is32 ? ImageBase32 : ImageBase64;
    public int PointerSize => Is32 ? 4 : 8;
    public ushort Major { get; set; } = 16;
    public ushort Minor { get; set; }
    /// <summary>Row starts get base relocations (a real image always has them).</summary>
    public bool RelocateRows { get; set; } = true;
    public bool WithHydratedSection { get; set; } = true;
    public byte[] Text { get; set; } = new byte[0x100];
    public PeBlob Rdata { get; } = new(RdataRva);
    public PeBlob Data { get; } = new(DataRva);
    public List<(int Id, uint Flags, uint Start, uint End)> Rows { get; } = [];
    public uint HeaderRva { get; private set; }
    private readonly List<uint> relocations = [];

    /// <summary>Writes the VA of <paramref name="targetRva"/> into <paramref name="blob"/> and records a DIR64 relocation for it.</summary>
    public uint Pointer(PeBlob blob, uint targetRva)
    {
        uint at = blob.Ptr(!Is32, ImageBase + targetRva);
        relocations.Add(at);
        return at;
    }

    public void Row(int id, uint start, uint end, uint flags = 1) => Rows.Add((id, flags, start, end));

    /// <summary>Places <paramref name="bytes"/> in .rdata (4-aligned) as ReflectionMapBlob <paramref name="blobId"/>; returns its RVA.</summary>
    public uint Blob(int blobId, byte[] bytes) => Section(300 + blobId, bytes);

    public uint Section(int id, byte[] bytes)
    {
        Rdata.Align(4);
        uint at = Rdata.Bytes(bytes);
        Row(id, at, at + (uint)bytes.Length);
        return at;
    }

    public byte[] Build()
    {
        Rdata.Align(8);
        HeaderRva = Rdata.U32(0x00525452);
        Rdata.U16(Major);
        Rdata.U16(Minor);
        Rdata.U32(0);
        Rdata.U16((ushort)Rows.Count);
        Rdata.Bytes([(byte)(2 * PointerSize + 8), 1]);
        foreach (var (id, flags, start, end) in Rows)
        {
            Rdata.U32((uint)id);
            Rdata.U32(flags);
            uint s = Rdata.Ptr(!Is32, ImageBase + start);
            if (RelocateRows) relocations.Add(s);
            uint e = Rdata.Ptr(!Is32, (flags & 1) != 0 ? ImageBase + end : 0);
            if (RelocateRows && (flags & 1) != 0) relocations.Add(e);
        }
        Assert.True(Rdata.Length <= DataRva - RdataRva && Data.Length <= HydratedRva - DataRva, "fixture sections overflow");

        var pe = new PeBuilder { ImageBase = ImageBase, EntryPoint = TextRva, Is64 = !Is32, Machine = (ushort)(Is32 ? 0x14C : 0x8664) };
        pe.Sections.Add(new PeBuilder.Section { Name = ".text", Rva = TextRva, Data = Text, VirtualSize = (uint)Text.Length, Characteristics = 0x60000020 });
        pe.Sections.Add(new PeBuilder.Section { Name = ".rdata", Rva = RdataRva, Data = Rdata.ToArray(), VirtualSize = (uint)Rdata.Length });
        pe.Sections.Add(new PeBuilder.Section { Name = ".data", Rva = DataRva, Data = Data.ToArray(), VirtualSize = Math.Max(1, (uint)Data.Length), Characteristics = 0xC0000040 });
        if (WithHydratedSection)
            pe.Sections.Add(new PeBuilder.Section { Name = "hydrated", Rva = HydratedRva, Data = [], VirtualSize = HydratedSize, Characteristics = 0xC0000080, RawSize = 0, RawOffset = 0 });
        var reloc = Relocations();
        pe.Sections.Add(new PeBuilder.Section { Name = ".reloc", Rva = RelocRva, Data = reloc, VirtualSize = (uint)reloc.Length, Characteristics = 0x42000040 });
        pe.Directories[5] = (RelocRva, (uint)reloc.Length);
        return pe.Build();
    }

    public PeFile Image() => PeFile.FromBytes(Build());

    /// <summary>Base relocation blocks: one per 4 KB page, DIR64 (HIGHLOW on x86) entries, padded to 4 bytes.</summary>
    private byte[] Relocations()
    {
        var blob = new List<byte>();
        foreach (var page in relocations.Order().GroupBy(r => r & ~0xFFFu))
        {
            var entries = page.Select(r => (ushort)((Is32 ? 0x3000u : 0xA000u) | (r & 0xFFF))).ToList();
            if (entries.Count % 2 != 0) entries.Add(0);
            var block = new byte[8 + 2 * entries.Count];
            BinaryPrimitives.WriteUInt32LittleEndian(block, page.Key);
            BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(4), (uint)block.Length);
            for (int i = 0; i < entries.Count; i++) BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(8 + 2 * i), entries[i]);
            blob.AddRange(block);
        }
        return blob.Count == 0 ? new byte[8] : [.. blob];
    }
}
