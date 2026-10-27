using LibCpp2IL.Metadata;

namespace Corvus.Services;

/// <summary>
/// Reads the custom attribute types of an image's members: attributesInfo before metadata v29, attributeData from v29;
/// arguments are not decoded.
/// </summary>
internal static class AotAttributeTypes
{
    /// <summary>
    /// Attribute type definition indexes per metadata token; tokens without attributes are absent. Throws when ranges or
    /// blobs are out of bounds.
    /// </summary>
    public static Dictionary<uint, int[]> Read(Il2CppMetadata meta, Il2CppImageDefinition image, Func<int, int?> definition)
    {
        var result = new Dictionary<uint, int[]>();
        int start = image.customAttributeStart;
        long count = image.customAttributeCount;
        if (count == 0) return result;
        if (meta.MetadataVersion < 29)
        {
            var ranges = meta.attributeTypeRanges ?? throw new InvalidDataException("the attributesInfo section was not read");
            var attributeTypes = meta.attributeTypes ?? throw new InvalidDataException("the attributeTypes section was not read");
            Check(start, count, ranges.Count, "attributesInfo");
            for (int i = start; i < start + count; i++)
            {
                var r = ranges[i];
                Check(r.start, r.count, attributeTypes.Length, "attributeTypes");
                var types = new List<int>(r.count);
                for (int k = r.start; k < r.start + r.count; k++)
                    if (definition(attributeTypes[k]) is { } d) types.Add(d);
                result[r.token] = [.. types];
            }
            return result;
        }
        var data = meta.AttributeDataRanges ?? throw new InvalidDataException("the attributeDataRange section was not read");
        var section = meta.metadataHeader.attributeData;
        Check(start, count, data.Count, "attributeDataRange");
        // A range ends where the next begins; the runtime writes one entry past the last for the end.
        long end = start + count < data.Count ? data[(int)(start + count)].startOffset : section.Size;
        long first = data[start].startOffset;
        if (first > end || end > section.Size) throw new InvalidDataException($"attributeData range 0x{first:X}-0x{end:X} is outside the section (0x{section.Size:X} bytes)");
        var bytes = meta.ReadByteArrayAtRawAddress(section.Offset + first, (int)(end - first));
        for (int i = start; i < start + count; i++)
        {
            long from = data[i].startOffset, to = i + 1 < start + count ? data[i + 1].startOffset : end;
            if (from < first || to < from || to > end) throw new InvalidDataException($"attributeData entry {i} (0x{from:X}-0x{to:X}) is out of order");
            var types = new List<int>();
            foreach (int method in Constructors(bytes.AsSpan((int)(from - first), (int)(to - from))))
            {
                if (method < 0 || method >= meta.methodDefs.Length) throw new InvalidDataException($"attributeData entry {i} names method {method} of {meta.methodDefs.Length}");
                types.Add(meta.methodDefs[method].declaringTypeIdx.Value);
            }
            result[data[i].token] = [.. types];
        }
        return result;
    }

    /// <summary>The constructor method indexes at the start of one attribute data blob; throws on a truncated blob.</summary>
    public static int[] Constructors(ReadOnlySpan<byte> blob)
    {
        int at = 0;
        uint count = CompressedUInt(blob, ref at);
        if (count > (uint)(blob.Length - at) / 4) throw new InvalidDataException($"attribute data names {count} constructors in {blob.Length} bytes");
        var methods = new int[count];
        for (int k = 0; k < methods.Length; k++, at += 4) methods[k] = BitConverter.ToInt32(blob[at..]);
        return methods;
    }

    /// <summary>The metadata's compressed unsigned integer: big-endian, 1, 2, 4 or 5 bytes; 0xFE and 0xFF for the top two values.</summary>
    private static uint CompressedUInt(ReadOnlySpan<byte> b, ref int at)
    {
        if (at >= b.Length) throw new InvalidDataException("attribute data is empty");
        byte first = b[at++];
        int extra = (first & 0x80) == 0 ? 0 : (first & 0xC0) == 0x80 ? 1 : (first & 0xE0) == 0xC0 ? 3 : first == 0xF0 ? 4 : first is 0xFE or 0xFF ? 0 : -1;
        if (extra < 0) throw new InvalidDataException($"attribute data starts with 0x{first:X2}, not a compressed integer");
        if (at + extra > b.Length) throw new InvalidDataException("attribute data ends inside a compressed integer");
        uint value = first switch { 0xFE => uint.MaxValue - 1, 0xFF => uint.MaxValue, 0xF0 => 0, _ => (uint)(first & (extra == 0 ? 0x7F : extra == 1 ? 0x3F : 0x1F)) };
        for (int k = 0; k < extra; k++) value = value << 8 | b[at++];
        return value;
    }

    private static void Check(long start, long count, long length, string section)
    {
        if (start < 0 || count < 0 || start + count > length) throw new InvalidDataException($"{section} range {start}+{count} is outside its {length} entries");
    }
}
