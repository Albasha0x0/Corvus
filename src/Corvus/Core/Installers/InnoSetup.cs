using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core.Archives;
using Corvus.Core.Disks;
using SharpCompress.Compressors.LZMA;

namespace Corvus.Core.Installers;

/// <summary>
/// Inno Setup installers (data formats 5.5 to 7.1; before 6.3 the Unicode builds): the loader's offset table (resource RCDATA 11111) locates setup-0,
/// whose compressed blocks hold the header, the entries up to the file list, and the file locations; setup-1 holds the
/// file data in chunks. Files are listed under their destination names ({app}\...) and checked against their SHA-1 or SHA-256.
/// </summary>
internal sealed class InnoSetupReader : IContainerReader
{
    private const string OffsetTableType = "#10";
    private const uint OffsetTableId = 11111;
    private static readonly byte[] OffsetTableMagic = [(byte)'r', (byte)'D', (byte)'l', (byte)'P', (byte)'t', (byte)'S', 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A];
    private const string SetupIdPrefix = "Inno Setup Setup Data (";
    private const int HeadBytes = 1 << 20;
    private const int MaxBlock = 256 << 20;
    private const int ChunkBytes = 4096;
    private static readonly byte[] ChunkMagic = "zlb\x1a"u8.ToArray();
    private static readonly string[] Methods = ["stored", "zlib", "bzip2", "LZMA", "LZMA2"];
    private const byte UninstallerFileType = 1;

    public string Kind => "inno";

    public bool Accepts(ReadOnlySpan<byte> data, string name)
    {
        var head = data[..Math.Min(data.Length, HeadBytes)].ToArray();
        return OffsetTable(head, InstallerPe.Of(head)) != null;
    }

    private sealed record Offsets(long Setup0, long Setup1);

    /// <summary>The loader's offset table: version 1 (32-bit offsets, before 6.5) or 2.</summary>
    private static Offsets? OffsetTable(byte[] head, InstallerPe.Read read)
    {
        if (PeImage.TryParse(head) is not { } pe || pe.IsDotNet(head)) return null;
        if (InstallerPe.Resource(pe, head, read, OffsetTableType, OffsetTableId) is not { Size: >= 44 } r || read(r.Offset, Math.Min(r.Size, 64)) is not { } t) return null;
        if (!t.AsSpan(0, 12).SequenceEqual(OffsetTableMagic)) return null;
        return BinaryPrimitives.ReadUInt32LittleEndian(t.AsSpan(12)) switch
        {
            1 => new Offsets(BinaryPrimitives.ReadUInt32LittleEndian(t.AsSpan(32)), BinaryPrimitives.ReadUInt32LittleEndian(t.AsSpan(36))),
            2 when t.Length >= 64 => new Offsets(BinaryPrimitives.ReadInt64LittleEndian(t.AsSpan(40)), BinaryPrimitives.ReadInt64LittleEndian(t.AsSpan(48))),
            _ => null,
        };
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct)!;

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(stream);
        var offsets = OffsetTable(read(0, (int)Math.Min(stream.Length, HeadBytes))!, read) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: no Inno Setup offset table.");
        var id = read(offsets.Setup0, 64) is { } idBytes ? Encoding.ASCII.GetString(idBytes).TrimEnd('\0') : throw new ToolError(ErrorCode.MalformedInput, $"{name}: setup-0 is past the end of the file.");
        var version = id.StartsWith(SetupIdPrefix, StringComparison.Ordinal) && id.EndsWith(')') ? id[SetupIdPrefix.Length..^1].Replace(") (u", " (u)") : null;
        var layout = Layouts.FirstOrDefault(l => l.Id == version)
            ?? throw new ToolError(ErrorCode.Unsupported, $"{name}: Inno Setup data \"{id}\" is not a format this reader knows (5.5 to 7.1 are; before 6.3 the Unicode builds).");

        Setup setup;
        try { setup = ReadSetup(stream, read, offsets.Setup0 + 64, layout, name); }
        catch (Exception ex) when (Damaged(ex)) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: the Inno Setup data does not decode: {ex.Message}"); }

        var notes = new List<string>
        {
            $"Inno Setup installer (data {version}){(setup.App.Name.Length > 0 ? $" {setup.App.Name}" : "")}{(setup.App.Version.Length > 0 ? $" {setup.App.Version}" : "")}" +
            $"{(setup.App.Publisher.Length > 0 ? $" by {setup.App.Publisher}" : "")}: {setup.Files.Count} file(s) in {setup.Locations.Count} data block(s), {Method(setup.Compression)}.",
        };
        if (setup.EncryptedFiles) notes.Add("The files are encrypted with a password: listed, not extracted.");

        var bytes = new Dictionary<int, byte[]>();
        if (offsets.Setup1 == 0) notes.Add("The file data is in separate setup-*.bin files (disk spanning): listed, not extracted.");
        else
        {
            try { Extract(stream, offsets.Setup1, setup, layout, limits, bytes, notes, ct); }
            catch (Exception ex) when (Damaged(ex)) { notes.Add($"{name}: the file data stops decoding: {ex.Message}"); }
        }

        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        foreach (var f in setup.Files)
        {
            if (f.Uninstaller)
                entries.Add(new ContainerEntry(f.Path, 0, "uninstaller written at install time (the setup program itself)"));
            else if (f.Location < 0 || f.Location >= setup.Locations.Count)
                entries.Add(new ContainerEntry(f.Path, f.ExternalSize, "not in the installer (an external or downloaded file)"));
            else if (bytes.TryGetValue(f.Location, out var data))
                ArchiveItems.Take(items, entries, $"Inno Setup file ({Method(setup.Compression)})", f.Path, data, allFiles, limits, ref total);
            else
                entries.Add(new ContainerEntry(f.Path, setup.Locations[f.Location].Size, "not extracted"));
        }
        if (!allFiles && entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents("Inno Setup installer", items, notes) { Entries = entries };
    }

    private static string Method(int m) => m >= 0 && m < Methods.Length ? Methods[m] : $"method {m}";

    /// <summary>Decoder failures on damaged data (the decoders throw a range of exception types).</summary>
    private static bool Damaged(Exception ex) => ex is not (OperationCanceledException or ToolError or OutOfMemoryException);

    private sealed record App(string Name, string Version, string Publisher);
    private sealed record SetupFile(string Path, int Location, long ExternalSize, bool Uninstaller);
    private sealed record Location(int FirstSlice, int LastSlice, long Start, long Suboffset, long Size, long CompressedSize, byte[] Hash, bool CallOptimized, bool Encrypted, bool Compressed);
    private sealed record Setup(App App, List<SetupFile> Files, List<Location> Locations, int Compression, bool EncryptedFiles);

    private static Setup ReadSetup(Stream stream, InstallerPe.Read read, long at, Layout layout, string name)
    {
        bool encryptedFiles = false;
        if (layout.EncryptionHeader > 0)
        {
            var e = read(at, 4 + layout.EncryptionHeader) ?? throw new EndOfStreamException("the encryption header is cut short");
            // EncryptionUse: 0 none, 1 files, 2 everything (setup-0 too)
            if (e[4] == 2) throw new ToolError(ErrorCode.Unsupported, $"{name}: the Inno Setup data is encrypted with a password.");
            encryptedFiles = e[4] == 1;
            at += 4 + layout.EncryptionHeader;
        }
        var (first, next) = Block(stream, read, at, layout);
        var r = new RecordReader(first);
        var (headerStrings, header) = r.Record(layout.Header);
        int Count(int offset) => BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(offset)) is var n and >= 0 ? n : throw new InvalidDataException("negative entry count");
        var files = new List<SetupFile>();
        for (int i = 0; i < layout.Entries.Length; i++)
        {
            bool fileList = i == layout.Entries.Length - 1;
            for (int n = Count(layout.Counts[i]); n > 0; n--)
            {
                var (strings, fixedPart) = r.Record(layout.Entries[i]);
                if (fileList)
                    files.Add(new SetupFile(strings[1].Replace('\\', '/'), BinaryPrimitives.ReadInt32LittleEndian(fixedPart.AsSpan(layout.FileLocation)),
                        BinaryPrimitives.ReadInt64LittleEndian(fixedPart.AsSpan(layout.ExternalSize)), fixedPart[layout.FileType] == UninstallerFileType));
            }
        }

        var (second, _) = Block(stream, read, next, layout);
        var l = layout.Location;
        int count = Count(layout.FileLocations);
        if ((long)count * l.Size > second.Length) throw new InvalidDataException("the file locations are cut short");
        var locations = new List<Location>(count);
        for (int i = 0; i < count; i++)
        {
            var e = second.AsSpan(i * l.Size, l.Size);
            long start = l.StartOffsetBytes == 8 ? BinaryPrimitives.ReadInt64LittleEndian(e[l.StartOffset..]) : BinaryPrimitives.ReadUInt32LittleEndian(e[l.StartOffset..]);
            ulong flags = 0;
            for (int b = l.Flags; b < l.Size; b++) flags |= (ulong)e[b] << (8 * (b - l.Flags));
            locations.Add(new Location(BinaryPrimitives.ReadInt32LittleEndian(e), BinaryPrimitives.ReadInt32LittleEndian(e[4..]), start,
                BinaryPrimitives.ReadInt64LittleEndian(e[l.ChunkSuboffset..]), BinaryPrimitives.ReadInt64LittleEndian(e[l.OriginalSize..]),
                BinaryPrimitives.ReadInt64LittleEndian(e[l.ChunkCompressedSize..]), e.Slice(l.Hash, l.HashBytes).ToArray(),
                (flags >> l.CallOptimized & 1) != 0, (flags >> l.ChunkEncrypted & 1) != 0, (flags >> l.ChunkCompressed & 1) != 0));
            encryptedFiles |= locations[^1].Encrypted;
        }
        return new Setup(new App(headerStrings[0], headerStrings[9], headerStrings[4]), files, locations, header[layout.CompressMethod], encryptedFiles);
    }

    /// <summary>A compressed block: a CRC-checked header (stored size, compressed flag), then 4 KiB chunks each after its CRC-32.</summary>
    private static (byte[] Data, long Next) Block(Stream stream, InstallerPe.Read read, long at, Layout layout)
    {
        int headerSize = layout.StoredSizeBytes + 1;
        var h = read(at, 4 + headerSize) ?? throw new EndOfStreamException("a compressed block header is cut short");
        if (BinaryPrimitives.ReadUInt32LittleEndian(h) != Crc32.HashToUInt32(h.AsSpan(4))) throw new InvalidDataException("a compressed block header fails its CRC");
        long stored = layout.StoredSizeBytes == 8 ? BinaryPrimitives.ReadInt64LittleEndian(h.AsSpan(4)) : BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(4));
        bool compressed = h[4 + layout.StoredSizeBytes] != 0;
        long start = at + 4 + headerSize;
        if (stored < 0 || stored > MaxBlock || start + stored > stream.Length) throw new InvalidDataException("a compressed block runs past the file or the size limit");
        var raw = new MemoryStream((int)stored);
        for (long p = start, end = start + stored; p < end;)
        {
            int n = (int)Math.Min(ChunkBytes, end - p - 4);
            if (n <= 0) throw new InvalidDataException("a block chunk is cut short");
            var c = read(p, 4 + n)!;
            if (BinaryPrimitives.ReadUInt32LittleEndian(c) != Crc32.HashToUInt32(c.AsSpan(4))) throw new InvalidDataException("a block chunk fails its CRC");
            raw.Write(c, 4, n);
            p += 4 + n;
        }
        if (!compressed) return (raw.ToArray(), start + stored);
        raw.Position = 0;
        var props = new byte[5];
        raw.ReadExactly(props);
        using var lzma = LzmaStream.Create(props, raw, raw.Length - 5, -1, leaveOpen: false);
        return (ReadAll(lzma, MaxBlock), start + stored);
    }

    /// <summary>Everything a decoder yields, up to <paramref name="max"/> bytes.</summary>
    private static byte[] ReadAll(Stream s, long max)
    {
        var output = new MemoryStream();
        var buffer = new byte[1 << 16];
        int n;
        while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            output.Write(buffer, 0, n);
            if (output.Length > max) throw new InvalidDataException("a block decodes past the size limit");
        }
        return output.ToArray();
    }

    /// <summary>Strings (length in bytes, then UTF-16 or ANSI bytes) and the record's fixed part.</summary>
    private sealed class RecordReader(byte[] data)
    {
        private int _at;

        public (string[] Strings, byte[] Fixed) Record(Rec rec)
        {
            var strings = new string[rec.Strings];
            for (int i = 0; i < rec.Strings; i++) strings[i] = Encoding.Unicode.GetString(Take(Length()));
            for (int i = 0; i < rec.AnsiStrings; i++) Take(Length());
            return (strings, Take(rec.Fixed).ToArray());
        }

        private int Length() => BinaryPrimitives.ReadInt32LittleEndian(Take(4)) is var n and >= 0 ? n : throw new InvalidDataException("negative string length");

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n > data.Length - _at) throw new InvalidDataException("a record runs past its block");
            var s = data.AsSpan(_at, n);
            _at += n;
            return s;
        }
    }

    /// <summary>Each chunk of setup-1 decoded once, front to back; its files cut out at their suboffsets and checked by their hash.</summary>
    private static void Extract(Stream stream, long setup1, Setup setup, Layout layout, AnalysisLimits limits, Dictionary<int, byte[]> bytes, List<string> notes, CancellationToken ct)
    {
        int mismatched = 0, skipped = 0;
        foreach (var chunk in Enumerable.Range(0, setup.Locations.Count).GroupBy(i => (setup.Locations[i].FirstSlice, setup.Locations[i].Start)).OrderBy(g => g.Key.Start))
        {
            ct.ThrowIfCancellationRequested();
            var first = setup.Locations[chunk.First()];
            if (first.Encrypted || first.FirstSlice != 0 || first.LastSlice != 0) { skipped += chunk.Count(); continue; }
            long at = setup1 + first.Start;
            var magic = new byte[4];
            stream.Position = at;
            if (stream.Read(magic) != 4 || !magic.AsSpan().SequenceEqual(ChunkMagic)) throw new InvalidDataException($"no chunk at setup-1 offset {first.Start:N0}");
            if (first.CompressedSize < 0 || at + 4 + first.CompressedSize > stream.Length) throw new InvalidDataException($"the chunk at setup-1 offset {first.Start:N0} runs past the file");
            using var decoded = Decoder(first.Compressed ? setup.Compression : 0, new SubStream(stream, at + 4, first.CompressedSize), first.CompressedSize);
            long position = 0;
            var skip = new byte[1 << 16];
            foreach (var index in chunk.OrderBy(i => setup.Locations[i].Suboffset))
            {
                var loc = setup.Locations[index];
                if (loc.Suboffset < position || loc.Size < 0) { skipped++; continue; }
                for (long left = loc.Suboffset - position; left > 0;)
                {
                    int n = decoded.Read(skip, 0, (int)Math.Min(left, skip.Length));
                    if (n == 0) throw new EndOfStreamException($"the chunk at setup-1 offset {first.Start:N0} ends early");
                    left -= n;
                }
                position = loc.Suboffset;
                if (loc.Size > limits.MaxItemBytes) { skipped++; continue; }
                var data = new byte[loc.Size];
                decoded.ReadExactly(data);
                position += loc.Size;
                if (loc.CallOptimized) TransformCallInstructions(data);
                if (!(loc.Hash.Length == 20 ? SHA1.HashData(data) : SHA256.HashData(data)).AsSpan().SequenceEqual(loc.Hash)) mismatched++;
                bytes[index] = data;
            }
        }
        if (mismatched > 0) notes.Add($"{mismatched} file(s) differ from their stored hash.");
        if (skipped > 0) notes.Add($"{skipped} data block(s) not extracted (encrypted, on another disk, or over the item limit).");
    }

    /// <summary>A chunk decoder: LZMA (5 property bytes), LZMA2 (1), zlib, bzip2, or stored.</summary>
    private static Stream Decoder(int method, Stream input, long size)
    {
        switch (method)
        {
            case 0: return input;
            case 1: return new ZLibStream(input, CompressionMode.Decompress);
            case 2: return SharpCompress.Compressors.BZip2.BZip2Stream.Create(input, SharpCompress.Compressors.CompressionMode.Decompress, false, false, false);
            case 3 or 4:
                var props = new byte[method == 3 ? 5 : 1];
                input.ReadExactly(props);
                return LzmaStream.Create(props, input, size - props.Length, -1, null, isLzma2: method == 4, leaveOpen: false);
            default: throw new NotSupportedException($"compression method {method}");
        }
    }

    /// <summary>Undoes the compiler's CALL/JMP address transform (version 3), in the 64 KiB buffers the compiler used.</summary>
    private static void TransformCallInstructions(byte[] data)
    {
        for (int start = 0; start < data.Length; start += 1 << 16)
        {
            var p = data.AsSpan(start, Math.Min(1 << 16, data.Length - start));
            for (int i = 0; i < p.Length - 4;)
            {
                if (p[i] is not (0xE8 or 0xE9)) { i++; continue; }
                i++;
                if (p[i + 3] is 0x00 or 0xFF)
                {
                    uint addr = (uint)(start + i + 4) & 0xFFFFFF;
                    uint rel = (uint)(p[i] | p[i + 1] << 8 | p[i + 2] << 16) - addr;
                    if ((rel & 0x800000) != 0) p[i + 3] = (byte)~p[i + 3];
                    p[i] = (byte)rel;
                    p[i + 1] = (byte)(rel >> 8);
                    p[i + 2] = (byte)(rel >> 16);
                }
                i += 4;
            }
        }
    }

    /// <summary>Strings (UTF-16, ANSI) and fixed bytes of one packed record.</summary>
    private readonly record struct Rec(int Strings, int AnsiStrings, int Fixed);

    /// <summary>File location field offsets and the bit positions of its flags; the hash is SHA-1 (20 bytes, before 6.4) or SHA-256.</summary>
    private sealed record LocationLayout(int Size, int StartOffset, int StartOffsetBytes, int ChunkSuboffset, int OriginalSize, int ChunkCompressedSize,
        int Hash, int Flags, int CallOptimized, int ChunkEncrypted, int ChunkCompressed, int HashBytes = 32);

    /// <summary>
    /// One data format: the encryption header size (0: none), the block stored-size width, the header record, the entry
    /// records up to and including the file entries, their count fields in the header, and the file entry and location fields.
    /// </summary>
    private sealed record Layout(string Id, int EncryptionHeader, int StoredSizeBytes, Rec Header, Rec[] Entries, int[] Counts, int FileLocations,
        int CompressMethod, int FileLocation, int ExternalSize, int FileType, LocationLayout Location);

    /// <summary>Computed from each format's Shared.Struct.pas (Struct.pas before 6.4; packed records; strings are stored apart from the fixed part).</summary>
    private static readonly Layout[] Layouts =
    [
        new("5.5.0 (u)", 0, 4, new(27, 4, 160), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 141, 20, 28, 42,
            new(74, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("5.5.6 (u)", 0, 4, new(28, 4, 160), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 141, 20, 28, 42,
            new(74, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("5.5.7 (u)", 0, 4, new(28, 4, 157), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 138, 20, 28, 42,
            new(74, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("6.0.0 (u)", 0, 4, new(30, 4, 167), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 148, 20, 28, 42,
            new(74, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("6.1.0 (u)", 0, 4, new(30, 4, 167), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 148, 20, 28, 42,
            new(74, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("6.3.0", 0, 4, new(32, 4, 166), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 148, 20, 28, 42,
            new(75, 8, 4, 12, 20, 28, 36, 72, 4, 6, 7, 20)),
        new("6.4.0.1", 0, 4, new(32, 4, 177), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 160, 20, 28, 42,
            new(87, 8, 4, 12, 20, 28, 36, 84, 4, 6, 7)),
        new("6.4.2", 0, 4, new(33, 4, 177), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 160, 20, 28, 42,
            new(87, 8, 4, 12, 20, 28, 36, 84, 4, 6, 7)),
        new("6.4.3", 0, 4, new(33, 4, 177), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(10, 0, 43)],
            [0, 4, 8, 12, 16, 20, 24, 28], 32, 160, 20, 28, 42,
            new(85, 8, 4, 12, 20, 28, 36, 84, 2, 3, 4)),
        new("6.5.0", 49, 4, new(34, 4, 133), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(3, 0, 0), new(15, 1, 77)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 116, 53, 61, 76,
            new(85, 8, 4, 12, 20, 28, 36, 84, 2, 3, 4)),
        new("6.5.2", 49, 4, new(34, 4, 141), [new(6, 4, 21), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(3, 0, 0), new(15, 1, 77)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 124, 53, 61, 76,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
        new("6.6.0", 49, 4, new(34, 4, 149), [new(4, 4, 19), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(3, 0, 0), new(15, 1, 77)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 132, 53, 61, 76,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
        new("6.6.1", 49, 4, new(34, 4, 150), [new(4, 4, 19), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 42), new(6, 0, 26), new(7, 0, 27), new(3, 0, 0), new(15, 1, 77)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 133, 53, 61, 76,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
        new("6.7.0", 49, 8, new(39, 4, 162), [new(4, 4, 19), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 39), new(6, 0, 23), new(7, 0, 27), new(3, 0, 0), new(15, 1, 80)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 143, 53, 61, 79,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
        new("7.0.0.1", 49, 8, new(39, 4, 162), [new(4, 4, 19), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 39), new(6, 0, 23), new(7, 0, 27), new(3, 0, 0), new(15, 1, 80)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 143, 53, 61, 79,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
        new("7.0.0.3", 49, 8, new(39, 4, 166), [new(4, 4, 19), new(2, 0, 4), new(0, 1, 0), new(4, 0, 30), new(5, 0, 39), new(6, 0, 23), new(7, 0, 27), new(3, 0, 0), new(15, 1, 81)],
            [0, 4, 8, 12, 16, 20, 24, 28, 32], 36, 147, 53, 61, 80,
            new(89, 8, 8, 16, 24, 32, 40, 88, 2, 3, 4)),
    ];
}
