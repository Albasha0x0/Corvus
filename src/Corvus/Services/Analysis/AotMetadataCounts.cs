using System.Buffers.Binary;
using System.ComponentModel;

namespace Corvus.Services.Analysis;

/// <summary>Image, type and method counts of a global-metadata.dat from its header and images table; unconfirmed counts are null with a reason.</summary>
// From v38 the header holds the counts; before, they are section sizes over the definition sizes of the layout whose
// images add up to the type count.
public static class AotMetadataCounts
{
    /// <summary>The counts, the layout read, and why they are unknown; Reason is null when every count is known.</summary>
    public sealed record Counts(
        [property: Description("Images; null when unknown.")] int? Images,
        [property: Description("Type definitions; null when unknown.")] int? Types,
        [property: Description("Method definitions; null when unknown.")] int? Methods,
        [property: Description("Layout the counts were read with.")] string? Layout,
        [property: Description("Why a count is unknown.")] string? Reason);

    /// <summary>The images table read at most; a larger one leaves the counts unknown.</summary>
    public const int MaxImagesTable = 1 << 20;

    // Header section indexes: methods, type definitions, and images (one later in v24.0 and v24.1, after rgctx entries).
    private const int MethodsSection = 5, TypesSection = 19, ImagesSection = 20;

    /// <summary>Definition sizes in bytes of a layout before v38, all indexes 4 bytes wide.</summary>
    private sealed record Layout(string Name, int Images, int Image, int Type, int Method);

    private static readonly Layout V24_0 = new("v24.0", ImagesSection + 1, 32, 104, 56);
    private static readonly Layout V24_1 = new("v24.1-24.15", ImagesSection + 1, 40, 100, 52);
    private static readonly Layout V24_2 = new("v24.2-24.5", ImagesSection, 40, 92, 32);

    private static IReadOnlyList<Layout> LayoutsFor(int version) => version switch
    {
        24 => [V24_0, V24_1, V24_2],
        >= 27 and <= 30 => [new($"v{version}", ImagesSection, 40, 88, 32)],
        >= 31 and <= 34 => [new($"v{version}", ImagesSection, 40, 88, 36)],
        >= 35 and <= 37 => [new($"v{version}", ImagesSection, 40, 84, 36)],
        _ => [],
    };

    /// <summary>Counts from the header in <paramref name="head"/> and <paramref name="read"/>; bad input gives unknown counts, never an exception.</summary>
    internal static Counts Read(byte[] head, Func<long, int, byte[]> read)
    {
        if (head.Length < 8) return Unknown("the header is not readable");
        int version = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(4));
        if (version is >= 38 and <= 39) return FromHeader(head, version, read);
        var layouts = LayoutsFor(version);
        if (layouts.Count == 0) return Unknown($"no definition layout for metadata version {version}");
        var found = new List<Counts>();
        string? failed = null;
        foreach (var layout in layouts)
        {
            var (counts, why) = Try(layout, head, read);
            if (counts != null) found.Add(counts);
            else failed ??= $"{layout.Name}: {why}";
        }
        if (found.Count == 0) return Unknown(failed!);
        if (found.DistinctBy(c => (c.Images, c.Types, c.Methods)).Count() > 1)
            return Unknown($"ambiguous: layouts {string.Join(" and ", found.Select(c => c.Layout))} each read");
        return found[0] with { Layout = string.Join(", ", found.Select(c => c.Layout)) };
    }

    private static (Counts?, string?) Try(Layout layout, byte[] head, Func<long, int, byte[]> read)
    {
        if (Section(head, layout.Images, 8) is not { } imagesSection || Section(head, TypesSection, 8) is not { } typesSection
            || Section(head, MethodsSection, 8) is not { } methodsSection)
            return (null, "the header is shorter than its section list");
        var (imagesAt, imagesSize, _) = imagesSection;
        int typesSize = typesSection.Size, methodsSize = methodsSection.Size;
        if (imagesSize <= 0) return (null, "the images section is empty");
        if (imagesSize % layout.Image != 0)
            return (null, $"the images section ({imagesSize:N0} bytes) is not a whole number of {layout.Image}-byte image definitions");
        if (typesSize < 0 || typesSize % layout.Type != 0)
            return (null, $"the type definitions section ({typesSize:N0} bytes) is not a whole number of {layout.Type}-byte definitions");
        int types = typesSize / layout.Type;
        if (SumTypes(imagesAt, imagesSize, layout.Image, 4, types, read) is { Error: { } error }) return (null, error);
        int? methods = methodsSize >= 0 && methodsSize % layout.Method == 0 ? methodsSize / layout.Method : null;
        return (new Counts(imagesSize / layout.Image, types, methods, layout.Name,
            methods == null ? $"the methods section ({methodsSize:N0} bytes) is not a whole number of {layout.Method}-byte method definitions" : null), null);
    }

    /// <summary>v38 and later: counts from the header, confirmed by the images table read with the type index width.</summary>
    private static Counts FromHeader(byte[] head, int version, Func<long, int, byte[]> read)
    {
        if (Section(head, ImagesSection, 12) is not { } imagesSection || Section(head, TypesSection, 12) is not { } typesSection
            || Section(head, MethodsSection, 12) is not { } methodsSection)
            return Unknown("the header is shorter than its section list");
        var (imagesAt, imagesSize, images) = imagesSection;
        var (_, typesSize, types) = typesSection;
        var (_, methodsSize, methods) = methodsSection;
        if (images <= 0 || types < 0 || methods < 0) return Unknown($"the header counts are not counts (images {images}, types {types}, methods {methods})");
        // An image's first type and exported type start are type indexes, 1, 2 or 4 bytes wide by the type count.
        int width = types <= 0xFF ? 1 : types <= 0xFFFF ? 2 : 4, image = 32 + 2 * width;
        if ((long)images * image != imagesSize)
            return Unknown($"the images section ({imagesSize:N0} bytes) is not {images} image definitions of {image} bytes");
        if (types > 0 && typesSize % types != 0 || methods > 0 && methodsSize % methods != 0)
            return Unknown("a section size is not a whole number of its counted entries");
        if (SumTypes(imagesAt, imagesSize, image, width, types, read) is { Error: { } error }) return Unknown(error);
        return new Counts(images, types, methods, $"v{version}", null);
    }

    /// <summary>Checks that the images' type ranges lie inside the type table and add up to its count; Error names the first failure.</summary>
    private static (long Sum, string? Error) SumTypes(int at, int size, int image, int width, int types, Func<long, int, byte[]> read)
    {
        if (size > MaxImagesTable) return (0, $"the images table is {size:N0} bytes, over the {MaxImagesTable:N0}-byte limit");
        if (at < 0) return (0, "the images section offset is negative");
        var table = read(at, size);
        if (table.Length != size) return (0, "the images table runs past the end of the file");
        long sum = 0;
        for (int i = 0; i < size / image; i++)
        {
            var entry = table.AsSpan(i * image);
            long first = width switch
            {
                1 => entry[8] == 0xFF ? -1 : entry[8],
                2 => BinaryPrimitives.ReadUInt16LittleEndian(entry[8..]) is var w && w == 0xFFFF ? -1 : w,
                _ => BinaryPrimitives.ReadInt32LittleEndian(entry[8..]),
            };
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(entry[(8 + width)..]);
            if (count > 0 && (first < 0 || first + count > types))
                return (0, $"image {i} names types {first} to {first + count - 1}, outside the {types} the type definitions section holds");
            sum += count;
        }
        return sum == types ? (sum, null) : (sum, $"the images list {sum} types, not the {types} the type definitions section holds");
    }

    /// <summary>The header's section entry at <paramref name="index"/>; Count is 0 before v38. Null past the head.</summary>
    private static (int Offset, int Size, int Count)? Section(byte[] head, int index, int stride)
    {
        int at = 8 + index * stride;
        if (at + stride > head.Length) return null;
        return (BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(at)), BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(at + 4)),
            stride == 12 ? BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(at + 8)) : 0);
    }

    private static Counts Unknown(string reason) => new(null, null, null, null, reason);
}
