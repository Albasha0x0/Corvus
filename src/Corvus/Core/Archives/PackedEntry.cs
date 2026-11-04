using System.IO.Compression;

namespace Corvus.Core.Archives;

/// <summary>Reads and decodes the zlib or LZ4 entries the BSA and BA2 readers share.</summary>
internal static class PackedEntry
{
    /// <summary>
    /// Decodes <paramref name="body"/> to exactly <paramref name="original"/> bytes, with zlib or, when
    /// <paramref name="lz4"/> is given, with it; throws InvalidDataException for damaged data or a size the codec
    /// cannot produce.
    /// </summary>
    public static byte[] Decode(byte[] body, long original, Func<byte[], long, byte[]>? lz4)
    {
        // The most one input byte expands to: Deflate 1032, an LZ4 block 255.
        if (original > (body.Length + 16L) * (lz4 != null ? 255 : 1032))
            throw new InvalidDataException($"{original:N0} bytes declared from {body.Length:N0}, more than the codec can produce");
        byte[] output;
        try
        {
            if (lz4 != null) output = lz4(body, original);
            else
            {
                using var z = new ZLibStream(new MemoryStream(body, writable: false), CompressionMode.Decompress);
                output = Blob.ReadBounded(z, original) ?? throw new InvalidDataException($"decodes past {original:N0} bytes");
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            throw new InvalidDataException($"damaged data: {ex.Message}", ex);
        }
        if (output.Length != original) throw new InvalidDataException($"{output.Length:N0} of {original:N0} bytes decoded");
        return output;
    }

    /// <summary>The <paramref name="n"/> bytes at <paramref name="at"/>; throws EndOfStreamException past the end.</summary>
    public static byte[] Range(Stream s, long at, int n)
    {
        var b = new byte[n];
        s.Position = at;
        s.ReadExactly(b);
        return b;
    }

    /// <summary>The lists a reader fills and the contents built from them, with the member-name notes added.</summary>
    public sealed class Listing(string kind)
    {
        public List<string> Notes { get; } = [];
        public List<ExtractedItem> Items { get; } = [];
        public List<ContainerEntry> Entries { get; } = [];
        public List<string> Names { get; } = [];

        public ContainerContents Done()
        {
            Notes.AddRange(MemberNames.Notes(Names));
            return new ContainerContents(kind, Items, Notes) { Entries = Entries };
        }
    }
}
