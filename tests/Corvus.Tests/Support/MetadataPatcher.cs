using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace Corvus.Tests;

/// <summary>Byte-level metadata malformations: extra or duplicate streams, header flags, out-of-range rows; grown metadata moves to the end of the last section.</summary>
internal static class MetadataPatcher
{
    public sealed record Stream(string Name, byte[] Data);

    /// <summary>The metadata root's stream list, transformed and written back.</summary>
    public static byte[] RewriteStreams(byte[] image, Func<List<Stream>, List<Stream>> transform)
    {
        var (mdOffset, mdSize) = MetadataLocation(image);
        var md = image.AsSpan(mdOffset, mdSize);
        int versionLength = BinaryPrimitives.ReadInt32LittleEndian(md[12..]);
        int headerEnd = 16 + versionLength; // flags u16, stream count u16 follow
        int count = BinaryPrimitives.ReadUInt16LittleEndian(md[(headerEnd + 2)..]);
        var streams = new List<Stream>();
        int at = headerEnd + 4;
        for (int i = 0; i < count; i++)
        {
            int offset = BinaryPrimitives.ReadInt32LittleEndian(md[at..]);
            int size = BinaryPrimitives.ReadInt32LittleEndian(md[(at + 4)..]);
            int nameEnd = md[(at + 8)..].IndexOf((byte)0);
            var name = Encoding.ASCII.GetString(md.Slice(at + 8, nameEnd));
            at += 8 + ((nameEnd + 4) & ~3);
            streams.Add(new Stream(name, md.Slice(offset, size).ToArray()));
        }
        streams = transform(streams);

        var root = new MemoryStream();
        root.Write(md[..(headerEnd + 2)]);
        root.Write(BitConverter.GetBytes((ushort)streams.Count));
        int headersSize = streams.Sum(s => 8 + ((Encoding.ASCII.GetByteCount(s.Name) + 4) & ~3));
        int dataAt = (int)root.Length + headersSize;
        foreach (var s in streams)
        {
            root.Write(BitConverter.GetBytes(dataAt));
            root.Write(BitConverter.GetBytes(s.Data.Length));
            var name = Encoding.ASCII.GetBytes(s.Name);
            root.Write(name);
            root.Write(new byte[((name.Length + 4) & ~3) - name.Length]);
            dataAt += (s.Data.Length + 3) & ~3;
        }
        foreach (var s in streams)
        {
            root.Write(s.Data);
            root.Write(new byte[((s.Data.Length + 3) & ~3) - s.Data.Length]);
        }
        return AppendMetadata(image, root.ToArray());
    }

    /// <summary>The tables stream (#~) with its header changed: extra Valid bits (row counts inserted) and/or the extra-data flag (a uint inserted).</summary>
    public static byte[] RewriteTablesHeader(byte[] image, IReadOnlyList<int> extraTables, uint? extraData) => RewriteStreams(image, streams =>
        streams.Select(s => s.Name != "#~" ? s : s with { Data = TablesHeader(s.Data, extraTables, extraData) }).ToList());

    private static byte[] TablesHeader(byte[] data, IReadOnlyList<int> extraTables, uint? extraData)
    {
        ulong valid = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(8));
        var counts = new SortedDictionary<int, uint>();
        int at = 24;
        for (int t = 0; t < 64; t++)
            if ((valid & (1UL << t)) != 0) { counts[t] = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)); at += 4; }
        byte heapSizes = data[6];
        int rest = at + ((heapSizes & 0x40) != 0 ? 4 : 0);
        foreach (var t in extraTables) { valid |= 1UL << t; counts[t] = 0; }
        var output = new MemoryStream();
        output.Write(data.AsSpan(0, 6));
        output.WriteByte(extraData != null ? (byte)(heapSizes | 0x40) : heapSizes);
        output.WriteByte(data[7]);
        output.Write(BitConverter.GetBytes(valid));
        output.Write(data.AsSpan(16, 8));
        foreach (var c in counts.Values) output.Write(BitConverter.GetBytes(c));
        if (extraData is { } extra) output.Write(BitConverter.GetBytes(extra));
        output.Write(data.AsSpan(rest));
        return output.ToArray();
    }

    /// <summary>File offset and size of one table row's bytes (from the unmodified image).</summary>
    public static (int Offset, int Size) Row(byte[] image, TableIndex table, int rid)
    {
        using var pe = new PEReader(new MemoryStream(image));
        var md = pe.GetMetadataReader();
        int start = pe.PEHeaders.MetadataStartOffset + md.GetTableMetadataOffset(table);
        int size = md.GetTableRowSize(table);
        return (start + (rid - 1) * size, size);
    }

    public static int RowCount(byte[] image, TableIndex table)
    {
        using var pe = new PEReader(new MemoryStream(image));
        return pe.GetMetadataReader().GetTableRowCount(table);
    }

    /// <summary>The ImplMap row (of rid) whose MemberForwarded is this method row; ImplMap columns: Flags, MemberForwarded, ImportName, ImportScope.</summary>
    public static int ImplMapRidOf(byte[] image, string methodName)
    {
        using var pe = new PEReader(new MemoryStream(image));
        var md = pe.GetMetadataReader();
        foreach (var h in md.MethodDefinitions)
        {
            var m = md.GetMethodDefinition(h);
            if (md.GetString(m.Name) != methodName) continue;
            int methodRid = MetadataTokens.GetRowNumber(h);
            int count = md.GetTableRowCount(TableIndex.ImplMap);
            int rowSize = md.GetTableRowSize(TableIndex.ImplMap);
            Assert.Equal(8, rowSize); // small indexes only
            int start = pe.PEHeaders.MetadataStartOffset + md.GetTableMetadataOffset(TableIndex.ImplMap);
            for (int rid = 1; rid <= count; rid++)
            {
                ushort forwarded = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(start + (rid - 1) * rowSize + 2));
                if (forwarded == (methodRid << 1 | 1)) return rid; // MemberForwarded tag 1 = MethodDef
            }
        }
        throw new InvalidOperationException($"no ImplMap row for {methodName}");
    }

    public static byte[] SetUInt16(byte[] image, int offset, ushort value)
    {
        var copy = image.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(copy.AsSpan(offset), value);
        return copy;
    }

    private static (int Offset, int Size) MetadataLocation(byte[] image)
    {
        using var pe = new PEReader(new MemoryStream(image));
        return (pe.PEHeaders.MetadataStartOffset, pe.PEHeaders.MetadataSize);
    }

    /// <summary>Writes <paramref name="metadata"/> after the last section's raw data, grows that section, and points the CLI header at it.</summary>
    private static byte[] AppendMetadata(byte[] image, byte[] metadata)
    {
        using var pe = new PEReader(new MemoryStream(image));
        var headers = pe.PEHeaders;
        var last = headers.SectionHeaders.MaxBy(s => s.PointerToRawData);
        int lastIndex = headers.SectionHeaders.IndexOf(last);
        int fileAlign = headers.PEHeader!.FileAlignment, sectionAlign = headers.PEHeader.SectionAlignment;
        int oldRaw = last.SizeOfRawData;
        int newRaw = (oldRaw + metadata.Length + fileAlign - 1) / fileAlign * fileAlign;
        int rva = last.VirtualAddress + oldRaw;
        var output = new byte[last.PointerToRawData + newRaw];
        image.AsSpan(0, Math.Min(image.Length, output.Length)).CopyTo(output);
        metadata.CopyTo(output, last.PointerToRawData + oldRaw);

        // PEHeaderStartOffset is the optional header's start; the section table follows it.
        int sectionHeader = headers.PEHeaderStartOffset + headers.CoffHeader.SizeOfOptionalHeader + lastIndex * 40;
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(sectionHeader + 8), newRaw);   // VirtualSize
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(sectionHeader + 16), newRaw);  // SizeOfRawData
        int sizeOfImage = (last.VirtualAddress + newRaw + sectionAlign - 1) / sectionAlign * sectionAlign;
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(headers.PEHeaderStartOffset + 56), sizeOfImage);
        // Section characteristics: readable (the metadata is read through it).
        uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(sectionHeader + 36));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(sectionHeader + 36), characteristics | 0x40000000);

        Assert.True(headers.TryGetDirectoryOffset(headers.PEHeader.CorHeaderTableDirectory, out int cor));
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(cor + 8), rva);
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(cor + 12), metadata.Length);
        return output;
    }
}
