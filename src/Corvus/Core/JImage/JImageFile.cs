using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core.JImage;

/// <summary>A Java runtime image (jimage, lib/modules), format 1.0 and 1.1, with zip and compact-cp decompression.</summary>
internal sealed class JImageFile
{
    public const string Kind = "Java runtime image (jimage)";
    private const uint Magic = 0xCAFEDADA, CompressedMagic = 0xCAFEFAFA;
    private const int HeaderSize = 28, CompressedHeaderSize = 29, MaxLayers = 8;
    // Attribute kinds of a location (ImageLocation.java); 8, the preview flags, came with format 1.1.
    private const int Module = 1, Parent = 2, Base = 3, Extension = 4, Offset = 5, Compressed = 6, Uncompressed = 7, Kinds = 9;
    private const uint HashMultiplier = 0x01000193;

    /// <summary>A resource: its module, its path inside the module, where its bytes start after the index, and its sizes (CompressedSize 0: stored).</summary>
    public sealed record Resource(string Module, string Path, long Offset, long CompressedSize, long Size, int Location);

    // The header and tables; resource bytes after them are read through _readAt, from memory or a seekable stream.
    private readonly byte[] _data;
    private readonly long _length;
    private readonly Func<long, int, byte[]> _readAt;
    private readonly int _redirect, _offsets, _locations, _strings, _locationsSize, _stringsSize;

    public int Major { get; }
    public int Minor { get; }
    public bool BigEndian { get; }
    public int TableLength { get; }
    public long IndexSize { get; }
    public List<Resource> Resources { get; } = [];
    /// <summary>The /modules and /packages directory entries the runtime builds its file system view from.</summary>
    public int Directories { get; }
    public List<string> Notes { get; } = [];

    /// <summary>Whether <paramref name="b"/> starts with the jimage magic in either byte order.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= HeaderSize && (BinaryPrimitives.ReadUInt32LittleEndian(b) == Magic || BinaryPrimitives.ReadUInt32BigEndian(b) == Magic);

    /// <summary>Parses the index of <paramref name="data"/>; throws <see cref="InvalidDataException"/> on a bad header or tables outside the file.</summary>
    public static JImageFile Read(byte[] data, CancellationToken ct = default) =>
        new(data, data.Length, (at, n) => data.AsSpan((int)at, n).ToArray(), ct);

    /// <summary>Reads the index of a seekable <paramref name="stream"/>, which must stay open while content is read; throws as <see cref="Read(byte[], CancellationToken)"/>.</summary>
    public static JImageFile Read(Stream stream, CancellationToken ct = default)
    {
        byte[] ReadAt(long at, int n)
        {
            var b = new byte[n];
            stream.Position = at;
            stream.ReadExactly(b);
            return b;
        }
        long length = stream.Length;
        if (length < HeaderSize) throw new InvalidDataException("not a jimage: shorter than its header");
        var header = ReadAt(0, HeaderSize);
        if (!Looks(header)) throw new InvalidDataException("not a jimage: the magic 0xCAFEDADA is missing");
        bool big = BinaryPrimitives.ReadUInt32LittleEndian(header) != Magic;
        uint U(int at) => big ? BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(at));
        long index = HeaderSize + 8L * U(16) + U(20) + U(24);
        if (index > length || index > int.MaxValue)
            throw new InvalidDataException($"the index ({index:N0} bytes) runs past the file ({length:N0} bytes)");
        return new(ReadAt(0, (int)index), length, ReadAt, ct);
    }

    private JImageFile(byte[] data, long length, Func<long, int, byte[]> readAt, CancellationToken ct)
    {
        _data = data;
        _length = length;
        _readAt = readAt;
        if (!Looks(data)) throw new InvalidDataException("not a jimage: the magic 0xCAFEDADA is missing");
        BigEndian = BinaryPrimitives.ReadUInt32LittleEndian(data) != Magic;
        uint version = U32(4);
        (Major, Minor) = ((int)(version >> 16), (int)(version & 0xFFFF));
        if (Major != 1) throw new InvalidDataException($"jimage format {Major}.{Minor} is not read (1.0 and 1.1 are)");
        if (Minor > 1) Notes.Add($"jimage format 1.{Minor} is newer than 1.1; attributes added after 1.1 are reported, not read.");
        uint resourceCount = U32(12), table = U32(16), locations = U32(20), strings = U32(24);
        long index = HeaderSize + 8L * table + locations + strings;
        if (table > int.MaxValue / 8 || index > data.Length)
            throw new InvalidDataException($"the index ({index:N0} bytes for {table:N0} entries) runs past the file ({length:N0} bytes)");
        TableLength = (int)table;
        IndexSize = index;
        _redirect = HeaderSize;
        _offsets = _redirect + 4 * TableLength;
        _locations = _offsets + 4 * TableLength;
        _locationsSize = (int)locations;
        _strings = _locations + _locationsSize;
        _stringsSize = (int)strings;
        if (resourceCount != table) Notes.Add($"The header counts {resourceCount:N0} resources and {table:N0} table entries.");

        int bad = 0, unknownKinds = 0, misplaced = 0, directories = 0;
        for (int i = 0; i < TableLength; i++)
        {
            if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            int location = (int)U32(_offsets + 4 * i);
            if (location == 0) continue;
            if (location < 0 || location >= _locationsSize) { if (bad++ < 3) Notes.Add($"Table entry {i:N0}: location 0x{location:X} lies outside the locations."); continue; }
            var a = Attributes(location, ref unknownKinds);
            if (a == null) { if (bad++ < 3) Notes.Add($"Table entry {i:N0}: its attributes run past the locations."); continue; }
            var module = Text((int)a[Module]);
            if (module.Length == 0 || module is "modules" or "packages") { directories++; continue; }
            var path = (a[Parent] != 0 ? Text((int)a[Parent]) + "/" : "") + Text((int)a[Base]) + (a[Extension] != 0 ? "." + Text((int)a[Extension]) : "");
            // The runtime finds a resource by the hash of its full name; one the hash does not lead to is unreachable.
            if (IndexOf(FullName(a)) != i) misplaced++;
            Resources.Add(new Resource(module, path, a[Offset], a[Compressed], a[Uncompressed], location));
        }
        Directories = directories;
        if (bad > 3) Notes.Add($"{bad - 3:N0} more table entries are unreadable.");
        if (unknownKinds > 0) Notes.Add($"{unknownKinds:N0} location attributes have a kind after 1.1; their values are skipped.");
        if (misplaced > 0) Notes.Add($"{misplaced:N0} resources are not found by the hash of their name: the runtime does not load them.");
    }

    /// <summary>The decompressed bytes of <paramref name="r"/>; throws <see cref="InvalidDataException"/> when out of range, too large or unsupported.</summary>
    public byte[] Content(Resource r, long maxBytes)
    {
        long stored = r.CompressedSize == 0 ? r.Size : r.CompressedSize;
        long at = IndexSize + r.Offset;
        if (r.Offset < 0 || stored < 0 || at > _length || stored > _length - at)
            throw new InvalidDataException($"its {stored:N0} bytes at 0x{at:X} lie outside the file");
        if (r.Size > maxBytes || stored > maxBytes) throw new InvalidDataException($"its {Math.Max(r.Size, stored):N0} bytes are over the {maxBytes:N0}-byte limit");
        var content = _readAt(at, (int)stored);
        if (r.CompressedSize == 0) return content;
        // Compressions stack: each layer has its own header and leaves the bytes of the one below.
        for (int layer = 0; layer < MaxLayers; layer++)
        {
            if (Layer(content) is not var (size, decompressor)) return content;
            if (size < 0 || size > maxBytes) throw new InvalidDataException($"a layer declares {size:N0} bytes, over the {maxBytes:N0}-byte limit");
            content = decompressor switch
            {
                "zip" => Inflate(content, size),
                "compact-cp" => StringShared(content),
                _ => throw new InvalidDataException($"the {decompressor} decompressor is not supported (zip and compact-cp are)"),
            };
        }
        throw new InvalidDataException($"more than {MaxLayers} compression layers");
    }

    /// <summary>The decompressor of the outermost compression layer of <paramref name="r"/>; null when it is stored.</summary>
    public string? Compression(Resource r)
    {
        long at = IndexSize + r.Offset;
        if (r.CompressedSize < CompressedHeaderSize || r.Offset < 0 || at + CompressedHeaderSize > _length) return null;
        return Layer(_readAt(at, CompressedHeaderSize))?.Decompressor;
    }

    private (long Size, string Decompressor)? Layer(ReadOnlySpan<byte> b)
    {
        if (b.Length < CompressedHeaderSize || Read32(b) != CompressedMagic) return null;
        long size = BigEndian ? BinaryPrimitives.ReadInt64BigEndian(b[12..]) : BinaryPrimitives.ReadInt64LittleEndian(b[12..]);
        return (size, Text((int)Read32(b[20..])));
    }

    // The output grows with the inflated bytes, not the declared size, so a forged size allocates nothing.
    private static byte[] Inflate(byte[] content, long size)
    {
        using var z = new ZLibStream(new MemoryStream(content, CompressedHeaderSize, content.Length - CompressedHeaderSize), CompressionMode.Decompress);
        var output = new MemoryStream();
        var buffer = new byte[81920];
        int n;
        while (output.Length <= size && (n = z.Read(buffer, 0, (int)Math.Min(buffer.Length, size + 1 - output.Length))) > 0) output.Write(buffer, 0, n);
        if (output.Length != size) throw new InvalidDataException($"zip data gives {(output.Length > size ? "more than " : "")}{output.Length:N0} of {size:N0} bytes");
        return output.ToArray();
    }

    // Constant pool entry sizes after the tag (StringSharingDecompressor.java); 0: not a fixed-size entry.
    private static readonly int[] PoolSizes = [0, 0, 0, 4, 4, 8, 8, 2, 2, 4, 4, 4, 4, 0, 0, 3, 2, 4, 4, 2, 2];

    /// <summary>A class file whose constant pool strings compact-cp moved into the image's strings table, with them put back.</summary>
    private byte[] StringShared(byte[] content)
    {
        var input = new Reader(content, CompressedHeaderSize);
        var output = new MemoryStream(content.Length * 2);
        output.Write(input.Bytes(8));
        int count = input.U16();
        WriteU16(output, count);
        for (int i = 1; i < count; i++)
        {
            int tag = input.U8();
            switch (tag)
            {
                case 1:
                    output.WriteByte(1);
                    int length = input.U16();
                    WriteU16(output, length);
                    output.Write(input.Bytes(length));
                    break;
                case 23:
                    WriteUtf8(output, StringBytes(input.Index()));
                    break;
                case 25:
                    WriteUtf8(output, Descriptor(ref input));
                    break;
                default:
                    if (tag >= PoolSizes.Length || PoolSizes[tag] == 0) throw new InvalidDataException($"constant pool tag {tag} at entry {i} is unknown");
                    if (tag is 5 or 6) i++;
                    output.WriteByte((byte)tag);
                    output.Write(input.Bytes(PoolSizes[tag]));
                    break;
            }
        }
        output.Write(content.AsSpan(input.At));
        return output.ToArray();
    }

    /// <summary>A method or field descriptor: its shape from the strings table, each 'L' followed by a package and a class name by index.</summary>
    private byte[] Descriptor(ref Reader input)
    {
        var shape = StringBytes(input.Index());
        int length = input.Index();
        var flow = new Reader(input.Bytes(length).ToArray(), 0);
        var result = new List<byte>(shape.Length * 2);
        foreach (var c in shape)
        {
            result.Add(c);
            if (c != 'L') continue;
            var package = StringBytes(flow.Index());
            if (package.Length > 0) { result.AddRange(package); result.Add((byte)'/'); }
            result.AddRange(StringBytes(flow.Index()));
        }
        return [.. result];
    }

    private static void WriteUtf8(MemoryStream output, ReadOnlySpan<byte> text)
    {
        if (text.Length > ushort.MaxValue) throw new InvalidDataException($"a {text.Length:N0}-byte constant pool string is over 65,535 bytes");
        output.WriteByte(1);
        WriteU16(output, text.Length);
        output.Write(text);
    }

    private static void WriteU16(MemoryStream output, int value) { output.WriteByte((byte)(value >> 8)); output.WriteByte((byte)value); }

    /// <summary>Big-endian class file bytes and the compressed indexes of CompressIndexes.java.</summary>
    private struct Reader(byte[] data, int at)
    {
        public int At = at;

        public ReadOnlySpan<byte> Bytes(int n)
        {
            if (n < 0 || At + n > data.Length) throw new InvalidDataException("the class file ends early");
            var s = data.AsSpan(At, n);
            At += n;
            return s;
        }

        public int U8() => Bytes(1)[0];
        public int U16() => BinaryPrimitives.ReadUInt16BigEndian(Bytes(2));

        // A set top bit marks a 1-3 byte value whose length is in bits 5-6; otherwise the value is 4 bytes.
        public int Index()
        {
            int header = U8();
            bool small = (header & 0x80) != 0;
            int size = small ? (header >> 5) & 3 : 4;
            if (size == 0) throw new InvalidDataException("a compressed index has no length");
            int value = small ? header & 0x1F : header;
            for (int i = 1; i < size; i++) value = (value << 8) | U8();
            return value;
        }
    }

    private long[]? Attributes(int at, ref int unknownKinds)
    {
        var a = new long[Kinds];
        int end = _locations + _locationsSize;
        for (int p = _locations + at; p < end;)
        {
            int data = _data[p++];
            if (data <= 7) return a;
            int kind = data >> 3, length = (data & 7) + 1;
            if (p + length > end) return null;
            long value = 0;
            for (int j = 0; j < length; j++) value = (value << 8) | _data[p++];
            if (kind < Kinds) a[kind] = value;
            else unknownKinds++;
        }
        return null;
    }

    /// <summary>The modified UTF-8 bytes of the null-terminated string at <paramref name="offset"/> in the strings table.</summary>
    private ReadOnlySpan<byte> StringBytes(int offset)
    {
        if (offset < 0 || offset >= _stringsSize) throw new InvalidDataException($"string offset 0x{offset:X} lies outside the strings table");
        var s = _data.AsSpan(_strings + offset, _stringsSize - offset);
        int nul = s.IndexOf((byte)0);
        return nul < 0 ? s : s[..nul];
    }

    private string Text(int offset) => offset < 0 || offset >= _stringsSize ? $"<string 0x{offset:X}>" : ModifiedUtf8(StringBytes(offset));

    private byte[] FullName(long[] a)
    {
        var name = new List<byte> { (byte)'/' };
        name.AddRange(StringBytes((int)a[Module]));
        name.Add((byte)'/');
        if (a[Parent] != 0) { name.AddRange(StringBytes((int)a[Parent])); name.Add((byte)'/'); }
        name.AddRange(StringBytes((int)a[Base]));
        if (a[Extension] != 0) { name.Add((byte)'.'); name.AddRange(StringBytes((int)a[Extension])); }
        return [.. name];
    }

    // The perfect hash of PerfectHashBuilder: a negative redirect is the index, a positive one the seed that finds it.
    private int IndexOf(ReadOnlySpan<byte> name)
    {
        int redirect = (int)U32(_redirect + 4 * (int)(Hash(name, HashMultiplier) % (uint)TableLength));
        if (redirect < 0) return -1 - redirect;
        return redirect > 0 ? (int)(Hash(name, (uint)redirect) % (uint)TableLength) : -1;
    }

    // Over modified UTF-8 bytes, as ImageStringsReader hashes the characters of a name.
    private static uint Hash(ReadOnlySpan<byte> name, uint seed)
    {
        foreach (var b in name) seed = (seed * HashMultiplier) ^ b;
        return seed & 0x7FFFFFFF;
    }

    /// <summary>Decodes modified UTF-8: C0 80 is NUL and characters outside the BMP are two encoded surrogates.</summary>
    internal static string ModifiedUtf8(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        for (int i = 0; i < b.Length;)
        {
            int c = b[i];
            if (c < 0x80) { sb.Append((char)c); i++; }
            else if ((c & 0xE0) == 0xC0 && i + 1 < b.Length) { sb.Append((char)(((c & 0x1F) << 6) | (b[i + 1] & 0x3F))); i += 2; }
            else if ((c & 0xF0) == 0xE0 && i + 2 < b.Length) { sb.Append((char)(((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F))); i += 3; }
            else { sb.Append('�'); i++; }
        }
        return sb.ToString();
    }

    private uint U32(int at) => Read32(_data.AsSpan(at));
    private uint Read32(ReadOnlySpan<byte> b) => BigEndian ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);

    /// <summary>A runtime image as a container: every resource as module/path, the selected ones extracted.</summary>
    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(() => Read(data, ct), name, allFiles, limits, ct);

    /// <summary>As <see cref="Open(byte[], string, bool, AnalysisLimits, CancellationToken)"/>, over a seekable stream: only the index and the extracted resources are held.</summary>
    public static ContainerContents Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(() => Read(stream, ct), name, allFiles, limits, ct);

    private static ContainerContents Open(Func<JImageFile> read, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        JImageFile image;
        try { image = read(); }
        catch (Exception e) when (e is InvalidDataException or EndOfStreamException) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: {e.Message}."); }
        var notes = new List<string>(image.Notes);
        var entries = new List<ContainerEntry>(image.Resources.Count);
        var items = new List<ExtractedItem>();
        var compression = new Dictionary<string, int>(StringComparer.Ordinal);
        int failed = 0;
        long total = 0;
        bool stopped = false;
        foreach (var r in image.Resources)
        {
            ct.ThrowIfCancellationRequested();
            var path = r.Module + "/" + r.Path;
            var layer = image.Compression(r);
            if (layer != null) compression[layer] = compression.GetValueOrDefault(layer) + 1;
            entries.Add(new ContainerEntry(path, r.Size, layer != null ? $"{layer}, {r.CompressedSize:N0} bytes stored" : null));
            if (stopped || !(allFiles || Containers.IsInteresting(path))) continue;
            if (items.Count >= limits.MaxItems || total + r.Size > limits.MaxTotalBytes)
            {
                notes.Add($"Stopped after {items.Count:N0} files ({total:N0} bytes): the extraction limit was reached.");
                stopped = true;
                continue;
            }
            total += r.Size;
            try { items.Add(new ExtractedItem(path, image.Content(r, limits.MaxItemBytes), "jimage resource")); }
            catch (InvalidDataException e) { if (failed++ < 3) notes.Add($"{path}: not extracted: {e.Message}."); }
        }
        if (failed > 3) notes.Add($"{failed - 3:N0} more resources are not extracted.");
        int modules = image.Resources.Select(r => r.Module).Distinct(StringComparer.Ordinal).Count();
        notes.Insert(0, $"Java runtime image (jimage {image.Major}.{image.Minor}, {(image.BigEndian ? "big" : "little")}-endian): " +
                        $"{image.Resources.Count:N0} resources in {modules:N0} module{(modules == 1 ? "" : "s")}, {image.Directories:N0} directory entries" +
                        (compression.Count > 0 ? "; compressed: " + string.Join(", ", compression.OrderByDescending(c => c.Value).Select(c => $"{c.Value:N0} {c.Key}")) : "") + ".");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }
}
