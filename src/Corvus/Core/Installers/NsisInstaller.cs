using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core.Archives;
using Corvus.Core.Disks;
using SharpCompress.Compressors.LZMA;

namespace Corvus.Core.Installers;

/// <summary>
/// Nullsoft (NSIS) installers: a native stub, then at a 512-byte boundary the first header and the data, either one solid
/// stream or one block per file (LZMA, deflate, bzip2 or stored). The header's script is walked for File and
/// WriteUninstaller instructions, so files are listed under their install paths ($INSTDIR dropped), as 7-Zip lists them.
/// </summary>
internal sealed class NsisInstallerReader : IContainerReader
{
    private const uint Signature = 0xDEADBEEF;
    private const int FirstHeaderBytes = 28;
    private const int HeadBytes = 1 << 20;
    private const int MaxHeader = 64 << 20;
    private const uint Compressed = 0x80000000;

    public string Kind => "nsis";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => data.StartsWith("MZ"u8) && FirstHeader(data[..Math.Min(data.Length, HeadBytes)]) != null;

    private sealed record First(long Offset, uint Flags, int HeaderSize, long DataSize);

    /// <summary>The first header: flags, 0xDEADBEEF, "NullsoftInst", header size and data size, at a 512-byte boundary.</summary>
    private static First? FirstHeader(ReadOnlySpan<byte> head)
    {
        for (int at = 512; at + FirstHeaderBytes <= head.Length; at += 512)
            if (BinaryPrimitives.ReadUInt32LittleEndian(head[(at + 4)..]) == Signature && head.Slice(at + 8, 12).SequenceEqual("NullsoftInst"u8))
            {
                int header = BinaryPrimitives.ReadInt32LittleEndian(head[(at + 20)..]);
                long data = BinaryPrimitives.ReadUInt32LittleEndian(head[(at + 24)..]);
                return header > 0 && data > FirstHeaderBytes ? new First(at, BinaryPrimitives.ReadUInt32LittleEndian(head[at..]), header, data) : null;
            }
        return null;
    }

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Open(new MemoryStream(data, writable: false), name, allFiles, limits, ct)!;

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(stream);
        var first = FirstHeader(read(0, (int)Math.Min(stream.Length, HeadBytes))!) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: no NSIS first header.");
        if (first.HeaderSize > MaxHeader) throw new ToolError(ErrorCode.LimitExceeded, $"{name}: the NSIS header is {first.HeaderSize:N0} bytes, over {MaxHeader:N0}.");
        long body = first.Offset + FirstHeaderBytes, bodySize = Math.Min(first.DataSize - FirstHeaderBytes, stream.Length - body);
        var sig = (bodySize >= 16 ? read(body, 16) : null) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: the NSIS data is cut short.");
        var codec = Method(sig);
        var notes = new List<string>();
        if (codec is Codec.X86Filter) throw new ToolError(ErrorCode.Unsupported, $"{name}: the NSIS data uses the x86 branch filter, which is not decoded.");
        if (codec is Codec.Bzip2 || codec is Codec.Deflate && NonSolid(sig, bodySize, first.HeaderSize) && Method(sig.AsSpan(4)) is Codec.Bzip2)
            throw new ToolError(ErrorCode.Unsupported, $"{name}: the NSIS data is bzip2 in NSIS's variant without block checksums, which is not decoded.");

        Data source;
        byte[]? header;
        try
        {
            if (codec is Codec.Lzma || !NonSolid(sig, bodySize, first.HeaderSize))
            {
                source = new SolidData(Decoder(codec, new SubStream(stream, body, bodySize), bodySize));
                header = source.Block(0, MaxHeader, out _);
            }
            else
            {
                var b = new BlockData(stream, read, body, bodySize, 0);
                header = b.Block(0, MaxHeader, out _);
                source = new BlockData(stream, read, body, bodySize, b.End);
            }
        }
        catch (Exception ex) when (Damaged(ex)) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: the NSIS header does not decode: {ex.Message}"); }
        var script = (header != null ? Script.Parse(header) : null) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: the NSIS header is not one this reader knows.");

        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var bytes = new Dictionary<uint, (byte[]? Data, long Size)>();
        int unreadable = 0;
        long total = 0;
        try
        {
            foreach (var offset in script.Files.Select(f => f.Offset).Distinct().Order())
            {
                ct.ThrowIfCancellationRequested();
                var data = source.Block(offset, limits.MaxItemBytes, out var size);
                bytes[offset] = (data, size);
            }
        }
        catch (Exception ex) when (Damaged(ex))
        {
            notes.Add($"{name}: the NSIS data stops decoding: {ex.Message}");
        }
        if (source is BlockData { Last: not Codec.Stored } blocks) codec = blocks.Last;
        bool solid = source is SolidData;
        foreach (var f in script.Files)
        {
            var (data, size) = bytes.GetValueOrDefault(f.Offset, (null, -1));
            if (f.Uninstaller) { entries.Add(new ContainerEntry(f.Path, 0, $"uninstaller written at install time from the installer stub and a {Math.Max(size, 0):N0}-byte data block")); continue; }
            if (data == null)
            {
                entries.Add(new ContainerEntry(f.Path, Math.Max(size, 0), size > limits.MaxItemBytes ? "over the item limit" : "not decoded"));
                unreadable++;
                continue;
            }
            ArchiveItems.Take(items, entries, $"NSIS file ({codec}{(solid ? ", solid" : "")})", f.Path, data, allFiles, limits, ref total);
        }
        notes.Insert(0, $"NSIS installer{((first.Flags & 1) != 0 ? " (uninstaller)" : "")}, {(script.Unicode ? "Unicode" : "ANSI")} strings: {codec}" +
                        $"{(solid ? " solid" : "")}, header of {first.HeaderSize:N0} bytes, {script.Files.Count(f => !f.Uninstaller)} file(s)" +
                        $"{(script.Files.Any(f => f.Uninstaller) ? ", an uninstaller" : "")}.");
        if (unreadable > 0) notes.Add($"{unreadable} file(s) listed but not decoded.");
        if (!allFiles && entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not binaries or packages; allFiles extracts every file).");
        return new ContainerContents("NSIS installer", items, notes) { Entries = entries };
    }

    /// <summary>Decoder failures on damaged data (the decoders throw a range of exception types).</summary>
    private static bool Damaged(Exception ex) => ex is not (OperationCanceledException or ToolError or OutOfMemoryException);

    private enum Codec { Stored, Lzma, Deflate, Bzip2, X86Filter }

    /// <summary>LZMA: property byte 0x5D and a power-of-two dictionary (after a filter byte of 0 or 1); NSIS bzip2: 0x31, then a small byte.</summary>
    private static Codec Method(ReadOnlySpan<byte> b)
    {
        static bool Lzma(ReadOnlySpan<byte> p) => p.Length >= 5 && p[0] == 0x5D && BinaryPrimitives.ReadUInt32LittleEndian(p[1..]) is var d && d >= 1 << 12 && (d & (d - 1)) == 0;
        if (Lzma(b)) return Codec.Lzma;
        if (b.Length >= 6 && b[0] is 0 or 1 && Lzma(b[1..])) return b[0] == 0 ? Codec.Lzma : Codec.X86Filter;
        return b.Length >= 2 && b[0] == 0x31 && b[1] < 14 ? Codec.Bzip2 : Codec.Deflate;
    }

    /// <summary>Per-file blocks: the first dword is the header block's length, compressed (top bit) or the header's own size.</summary>
    private static bool NonSolid(ReadOnlySpan<byte> sig, long bodySize, int headerSize)
    {
        uint n = BinaryPrimitives.ReadUInt32LittleEndian(sig);
        return (n & Compressed) != 0 ? (n & ~Compressed) + 4L <= bodySize : n == headerSize;
    }

    /// <summary>A decoding stream; LZMA's property bytes (and a zero filter byte) and bzip2's missing stream header handled.</summary>
    private static Stream Decoder(Codec codec, Stream input, long size)
    {
        switch (codec)
        {
            case Codec.Lzma:
                if (input.ReadByte() is var f and not 0x5D) { if (f != 0) throw new InvalidDataException("bad LZMA filter byte"); size--; }
                else input.Position = 0;
                var props = new byte[5];
                input.ReadExactly(props);
                return LzmaStream.Create(props, input, size - 5, -1, leaveOpen: false);
            case Codec.Deflate:
                return new DeflateStream(input, CompressionMode.Decompress);
            case Codec.Stored:
                return input;
            default:
                throw new NotSupportedException($"{codec} blocks are not decoded");
        }
    }

    private abstract class Data
    {
        /// <summary>The block at <paramref name="offset"/>; null (with its size) when it is over <paramref name="max"/>.</summary>
        public abstract byte[]? Block(uint offset, long max, out long size);
    }

    /// <summary>One stream holding the header block and then the file blocks, each a length dword and its bytes; read forward only.</summary>
    private sealed class SolidData(Stream decoded) : Data
    {
        private long _position;
        private readonly byte[] _skip = new byte[1 << 16];
        private bool _headerRead;
        private long _origin;

        public override byte[]? Block(uint offset, long max, out long size)
        {
            long at = _headerRead ? _origin + offset : 0;
            if (at < _position) throw new InvalidDataException($"block {offset} overlaps the one before it");
            for (long left = at - _position; left > 0;)
            {
                int n = decoded.Read(_skip, 0, (int)Math.Min(left, _skip.Length));
                if (n == 0) throw new EndOfStreamException($"the solid stream ends before block {offset}");
                left -= n;
            }
            var length = new byte[4];
            decoded.ReadExactly(length);
            size = BinaryPrimitives.ReadUInt32LittleEndian(length);
            _position = at + 4 + size;
            if (!_headerRead) { _headerRead = true; _origin = _position; }
            // read in pieces: a damaged length does not allocate before the data is there
            var output = size > max ? null : new MemoryStream();
            for (long left = size; left > 0;)
            {
                int n = decoded.Read(_skip, 0, (int)Math.Min(left, _skip.Length));
                if (n == 0) throw new EndOfStreamException($"the solid stream ends inside block {offset}");
                output?.Write(_skip, 0, n);
                left -= n;
            }
            return output?.ToArray();
        }
    }

    /// <summary>Blocks of their own at an origin after the header block: a length dword, top bit set when compressed.</summary>
    private sealed class BlockData(Stream stream, InstallerPe.Read read, long body, long bodySize, long origin) : Data
    {
        public Codec Last { get; private set; } = Codec.Stored;
        /// <summary>The offset after the last block read.</summary>
        public long End { get; private set; }

        public override byte[]? Block(uint offset, long max, out long size)
        {
            long at = origin + offset;
            uint n = read(body + at, 4) is { } length ? BinaryPrimitives.ReadUInt32LittleEndian(length) : throw new EndOfStreamException($"block {offset} is past the data");
            long stored = n & ~Compressed;
            if (at + 4 + stored > bodySize) throw new EndOfStreamException($"block {offset} runs past the data");
            End = at + 4 + stored;
            if ((n & Compressed) == 0)
            {
                size = stored;
                return stored > max ? null : read(body + at + 4, (int)stored);
            }
            var sig = read(body + at + 4, (int)Math.Min(stored, 16))!;
            Last = Method(sig);
            if (Last == Codec.X86Filter) throw new NotSupportedException("the x86 branch filter is not decoded");
            using var decoder = Decoder(Last, new SubStream(stream, body + at + 4, stored), stored);
            var output = new MemoryStream();
            var buffer = new byte[1 << 16];
            int r;
            while ((r = decoder.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, r);
                if (output.Length > max) { size = output.Length; return null; }
            }
            size = output.Length;
            return output.ToArray();
        }
    }

    private sealed record ScriptFile(string Path, uint Offset, bool Uninstaller);

    /// <summary>The header's entries and strings: the files the script extracts, under their install paths.</summary>
    private sealed record Script(List<ScriptFile> Files, bool Unicode)
    {
        private const int Blocks = 8, EntriesBlock = 2, StringsBlock = 3, EntryBytes = 28;
        private const int CreateDir = 11, ExtractFile = 20, AssignVar = 25, WriteUninstaller = 62, OutDirVariable = 31;

        private static readonly string[] Variables =
        [
            "$0", "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$R0", "$R1", "$R2", "$R3", "$R4", "$R5", "$R6", "$R7", "$R8", "$R9",
            "$CMDLINE", "$INSTDIR", "$OUTDIR", "$EXEDIR", "$LANGUAGE", "$TEMP", "$PLUGINSDIR", "$EXEPATH", "$EXEFILE", "$HWNDPARENT", "$_CLICK", "$_OUTDIR",
        ];

        /// <summary>Shell folder names by CSIDL, as 7-Zip names them.</summary>
        private static readonly string?[] ShellFolders =
        [
            "DESKTOP", "INTERNET", "SMPROGRAMS", "CONTROLS", "PRINTERS", "DOCUMENTS", "FAVORITES", "SMSTARTUP", "RECENT", "SENDTO",
            "BITBUCKET", "STARTMENU", null, "MUSIC", "VIDEOS", null, "DESKTOP", "DRIVES", "NETWORK", "NETHOOD",
            "FONTS", "TEMPLATES", "STARTMENU", "SMPROGRAMS", "SMSTARTUP", "DESKTOP", "APPDATA", "PRINTHOOD", "LOCALAPPDATA", "ALTSTARTUP",
            "ALTSTARTUP", "FAVORITES", "INTERNET_CACHE", "COOKIES", "HISTORY", "APPDATA", "WINDIR", "SYSDIR", "PROGRAMFILES", "PICTURES",
            "PROFILE", "SYSTEMX86", "PROGRAMFILESX86", "COMMONFILES", "COMMONFILESX86", "TEMPLATES", "DOCUMENTS", "ADMINTOOLS", "ADMINTOOLS", "CONNECTIONS",
            null, null, "MUSIC", "PICTURES", "VIDEO", "RESOURCES", "RESOURCES_LOCALIZED", "COMMON_OEM_LINKS", "CDBURN_AREA", null,
            "COMPUTERSNEARME",
        ];

        public static Script? Parse(byte[] h)
        {
            // A 64-bit build writes each block header as a UINT_PTR offset and an int count: 12 bytes, not 8.
            if ((Layout(h, 8) ?? Layout(h, 12)) is not var (offsets, counts)) return null;
            uint entries = offsets[EntriesBlock], count = counts[EntriesBlock], strings = offsets[StringsBlock];
            if (entries > h.Length || count > (h.Length - entries) / EntryBytes || strings >= h.Length) return null;
            var table = h.AsSpan((int)strings, (int)(Math.Min(offsets[StringsBlock + 1], (uint)h.Length) is var end && end > strings ? end - strings : h.Length - strings));
            bool unicode = IsUnicode(table);
            // NSIS 3 codes strings with 1-4 in both builds; NSIS 2 (ANSI only) with 252-255
            var reader = new Strings(h, (int)strings, unicode, unicode || table.IndexOfAnyInRange((byte)1, (byte)4) >= 0);

            var files = new List<ScriptFile>();
            var seen = new HashSet<(string, uint)>();
            // File /r saves the output folder in $_OUTDIR (StrCpy $_OUTDIR $OUTDIR) and sets subfolders from it
            string outDir = "$INSTDIR", savedOutDir = "$INSTDIR";
            string Expand(string path) => path.StartsWith("$_OUTDIR", StringComparison.Ordinal) ? savedOutDir + path[8..] : path;
            for (int k = 0; k < count; k++)
            {
                int Parm(int i) => BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan((int)entries + k * EntryBytes + 4 + i * 4));
                switch (BinaryPrimitives.ReadInt32LittleEndian(h.AsSpan((int)entries + k * EntryBytes)))
                {
                    case CreateDir when Parm(1) != 0:
                        outDir = Expand(reader.Get(Parm(0)));
                        break;
                    case AssignVar when Parm(0) == OutDirVariable:
                        savedOutDir = Expand(reader.Get(Parm(1)).Replace("$OUTDIR", outDir, StringComparison.Ordinal));
                        break;
                    case ExtractFile:
                        var path = InstallPath(outDir, Expand(reader.Get(Parm(1))));
                        if (seen.Add((path, (uint)Parm(2)))) files.Add(new ScriptFile(path, (uint)Parm(2), false));
                        break;
                    case WriteUninstaller:
                        files.Add(new ScriptFile(InstallPath(outDir, reader.Get(Parm(0))), (uint)Parm(1), true));
                        break;
                }
            }
            return new Script(files, unicode);
        }

        /// <summary>
        /// The block offsets and counts with <paramref name="size"/>-byte block headers; null unless the pages, sections,
        /// entries, strings and language tables blocks lie in order inside the header.
        /// </summary>
        private static (uint[] Offsets, uint[] Counts)? Layout(byte[] h, int size)
        {
            if (h.Length < 4 + Blocks * size) return null;
            var offsets = new uint[Blocks];
            var counts = new uint[Blocks];
            for (int i = 0; i < Blocks; i++)
            {
                var b = h.AsSpan(4 + i * size);
                ulong offset = size == 8 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b);
                if (offset > (ulong)h.Length) return null;
                offsets[i] = (uint)offset;
                counts[i] = BinaryPrimitives.ReadUInt32LittleEndian(b[(size - 4)..]);
            }
            for (int i = 1; i <= StringsBlock + 1; i++)
                if (offsets[i] != 0 && offsets[i - 1] > offsets[i]) return null;
            return offsets[EntriesBlock] >= 4 + Blocks * size ? (offsets, counts) : null;
        }

        /// <summary>Relative names join the output folder; $INSTDIR\ is dropped and separators become '/'.</summary>
        private static string InstallPath(string outDir, string name)
        {
            var path = name.StartsWith('$') || name.Contains(':') || name.StartsWith(@"\\", StringComparison.Ordinal) ? name : outDir.TrimEnd('\\') + "\\" + name;
            if (path.StartsWith(@"$INSTDIR\", StringComparison.OrdinalIgnoreCase)) path = path[9..];
            return path.Replace('\\', '/');
        }

        /// <summary>UTF-16 strings leave every second byte of ASCII text zero.</summary>
        private static bool IsUnicode(ReadOnlySpan<byte> s)
        {
            int n = Math.Min(s.Length, 1024) & ~1, zeros = 0;
            for (int i = 1; i < n; i += 2) if (s[i] == 0) zeros++;
            return n > 0 && zeros * 4 > n / 2 * 3;
        }

        /// <summary>Strings with their codes expanded: variables, shell folders and language strings by name.</summary>
        private sealed class Strings(byte[] h, int start, bool unicode, bool nsis3)
        {
            private const int MaxLength = 4096;
            private int Lang => nsis3 ? 1 : 255;
            private int Shell => nsis3 ? 2 : 254;
            private int Var => nsis3 ? 3 : 253;
            private int Skip => nsis3 ? 4 : 252;

            public string Get(int index, int depth = 0)
            {
                if (index < 0) return $"$(LSTR_{-(index + 1)})";
                var s = new StringBuilder();
                int p = start + (unicode ? 2 * index : index);
                while (s.Length < MaxLength)
                {
                    int c = Char(ref p);
                    if (c <= 0) break;
                    if (c == Lang || c == Var || c == Shell)
                    {
                        if (!Pair(ref p, out int lo, out int hi)) break;
                        int n = ((hi & 0x7F) << 7) | (lo & 0x7F);
                        if (c == Var) s.Append(n < Variables.Length ? Variables[n] : $"$_{n - Variables.Length}_");
                        else if (c == Lang) s.Append($"$(LSTR_{n})");
                        else s.Append(ShellFolder(lo, hi, depth));
                    }
                    else if (c == Skip) { int next = Char(ref p); if (next <= 0) break; s.Append((char)next); }
                    else s.Append((char)c);
                }
                return s.ToString();
            }

            private int Char(ref int p)
            {
                if (p < 0 || p + (unicode ? 2 : 1) > h.Length) return -1;
                int c = unicode ? BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(p)) : h[p];
                p += unicode ? 2 : 1;
                return c;
            }

            private bool Pair(ref int p, out int lo, out int hi)
            {
                lo = hi = 0;
                if (p + 2 > h.Length) return false;
                lo = h[p]; hi = h[p + 1];
                p += 2;
                return true;
            }

            /// <summary>A CSIDL pair (current user, all users), or with 0x80 a registry value under CurrentVersion (0x40: 64-bit view).</summary>
            private string ShellFolder(int first, int second, int depth)
            {
                if ((first & 0x80) != 0)
                {
                    var value = depth == 0 ? Get(first & 0x3F, depth + 1) : "";
                    var folder = value switch { "ProgramFilesDir" => "$PROGRAMFILES", "CommonFilesDir" => "$COMMONFILES", _ => $"$_REG({value})" };
                    return (first & 0x40) != 0 ? folder + "64" : folder;
                }
                var name = (first < ShellFolders.Length ? ShellFolders[first] : null) ?? (second < ShellFolders.Length ? ShellFolders[second] : null);
                return name != null ? "$" + name : $"$SHELL({first},{second})";
            }
        }
    }
}
