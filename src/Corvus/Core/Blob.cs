using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Corvus.Core;

/// <summary>Size limits for everything decoded, decompressed or extracted (they bound decompression bombs).</summary>
public sealed record AnalysisLimits
{
    public static readonly AnalysisLimits Default = new();

    /// <summary>Largest single decoded / decompressed / extracted item.</summary>
    public long MaxItemBytes { get; init; } = 512L * 1024 * 1024;
    /// <summary>Largest total of everything extracted by one operation.</summary>
    public long MaxTotalBytes { get; init; } = 4L * 1024 * 1024 * 1024;
    /// <summary>Most items extracted by one operation.</summary>
    public int MaxItems { get; init; } = 20_000;
    /// <summary>Nesting depth for containers inside containers / encodings inside encodings.</summary>
    public int MaxDepth { get; init; } = 4;

    /// <summary>The current call's counter, the same for every copy of these limits; null outside a call.</summary>
    public Spent? Spent => Core.Spent.Current;
}

/// <summary>Byte-level helpers: file-type identification, entropy, hashes, bounded decompression, carving.</summary>
public static class Blob
{
    /// <summary>A short type name from magic bytes: "pe", "zip", "gzip", "elf", ... or "text" / "data".</summary>
    public static string Identify(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 2 && b[0] == 'M' && b[1] == 'Z')
        {
            var pe = PeImage.TryParse(b);
            if (pe != null) return pe.IsDotNet(b) ? ".NET assembly" : pe.IsNativeAot(b) ? "NativeAOT executable" : "native PE";
        }
        if (StartsWith(b, "PK\x03\x04"u8) || StartsWith(b, "PK\x05\x06"u8)) return "zip";
        // JDK module: a 4-byte header, then a zip whose offsets start after it.
        if (StartsWith(b, "JM\x01\x00PK"u8)) return "jmod";
        if (StartsWith(b, [0x1F, 0x8B])) return "gzip";
        if (b.Length >= 2 && b[0] == 0x78 && (b[1] is 0x01 or 0x5E or 0x9C or 0xDA)) return "zlib";
        if (StartsWith(b, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7z";
        if (StartsWith(b, "Rar!"u8)) return "rar";
        if (StartsWith(b, "MSCF"u8)) return "cab";
        if (StartsWith(b, "%PDF"u8)) return "pdf";
        if (StartsWith(b, [0x89, (byte)'P', (byte)'N', (byte)'G'])) return "png";
        if (StartsWith(b, [0xFF, 0xD8, 0xFF])) return "jpeg";
        if (StartsWith(b, "GIF8"u8)) return "gif";
        if (StartsWith(b, [0x00, 0x00, 0x01, 0x00])) return "ico";
        if (StartsWith(b, [0x7F, (byte)'E', (byte)'L', (byte)'F'])) return "elf";
        if (Native.NativeImageLoader.Detect(b) is Native.NativeFileKind.MachO or Native.NativeFileKind.MachOFat) return "mach-o";
        if (StartsWith(b, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return "ole (msi/doc/xls)";
        if (StartsWith(b, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return "lnk shortcut";
        if (StartsWith(b, "XALZ"u8)) return "xalz (Xamarin LZ4)";
        if (StartsWith(b, "XAZS"u8)) return "xazs (.NET for Android Zstandard)";
        if (StartsWith(b, "XABA"u8)) return "xaba (Xamarin assembly store)";
        if (StartsWith(b, [0xCE, 0xCA, 0xEF, 0xBE])) return ".resources";
        if (StartsWith(b, "BSJB"u8)) return "portable pdb";
        if (StartsWith(b, "\0asm"u8)) return "wasm";
        if (StartsWith(b, "WbIL"u8)) return "webcil";
        if (StartsWith(b, "Microsoft C/C++ MSF 7.00"u8)) return "pdb";
        if (AsarArchive.Looks(b)) return "asar";
        if (Hermes.HermesFile.Looks(b)) return "hermes bytecode";
        if (WebPlayerData.Looks(b)) return "webdata";
        if (GodotPack.Looks(b)) return "godotpck";
        if (JImage.JImageFile.Looks(b)) return "jimage";
        if (Firmware.Esp32.Esp32Flash.Find(b) != null) return "esp32 flash";
        if (Firmware.Esp32.Esp32PartitionTable.Is(b)) return "esp32 partition table";
        if (Firmware.Esp32.Esp32Nvs.Looks(b)) return "esp32 nvs";
        if (Firmware.InesRom.Looks(b)) return "ines rom";
        if (Archives.QtResources.Looks(b)) return "qt resources";
        if (Flash.SwfFile.Looks(b)) return "flash swf";
        if (Registry.RegistryHive.Looks(b)) return "registry hive";
        if (Pri.PriFile.Looks(b)) return "package resource index";
        // A pak is known by its footer, so only a whole file matches.
        if (UnrealPak.Looks(b)) return "unreal pak";
        if (UnrealIoStore.Looks(b)) return "unreal utoc";
        if (GameMakerData.Looks(b)) return "gamemaker data";
        if (Lua.LuaBytecode.Looks(b)) return "lua bytecode";
        if (Lua.LuaJitBytecode.Looks(b)) return "luajit bytecode";
        if (AutoIt.AutoItScript.Looks(b)) return "autoit script";
        if (Models.Gguf.Looks(b)) return "gguf";
        if (Models.Safetensors.Looks(b, long.MaxValue)) return "safetensors";
        if (Models.PickleScan.Looks(b)) return "pickle";
        if (Models.OnnxModel.Looks(b)) return "onnx";
        if (StartsWith(b, "PYZ\0"u8) && b.Length >= 12 && Python.PyVersion.FromMagic(b[4..]) != null) return "pyinstaller pyz";
        if (Python.PyVersion.LooksLikePyc(b)) return "python bytecode";
        if (LooksLikeText(b)) return "text";
        return "data";
    }

    public static bool StartsWith(ReadOnlySpan<byte> b, ReadOnlySpan<byte> magic) => b.Length >= magic.Length && b[..magic.Length].SequenceEqual(magic);

    /// <summary>Image formats: reported but not decoded further.</summary>
    public static bool IsMedia(string kind) => kind is "png" or "jpeg" or "gif" or "ico";

    /// <summary>Checks a 4 KB prefix: no NUL, at most 5% control bytes, and either 90%+ printable ASCII or valid UTF-8.</summary>
    public static bool LooksLikeText(ReadOnlySpan<byte> b)
    {
        if (b.Length == 0) return false;
        var sample = b[..Math.Min(b.Length, 4096)];
        if (StartsWith(sample, [0xEF, 0xBB, 0xBF])) sample = sample[3..];
        if (sample.Length == 0) return false;
        int printable = 0, ascii = 0;
        foreach (var c in sample)
        {
            if (c == 0) return false;
            if (c is 9 or 10 or 13 || (c >= 32 && c != 127)) printable++;
            if (c is 9 or 10 or 13 || (c >= 32 && c < 127)) ascii++;
        }
        if (printable < sample.Length * 0.95) return false;
        if (ascii >= sample.Length * 0.9) return true;
        // Drop a trailing incomplete UTF-8 sequence before validating.
        int end = sample.Length;
        for (int i = 1; i <= 3 && i <= sample.Length; i++)
        {
            byte c = sample[sample.Length - i];
            if ((c & 0xC0) == 0xC0) { int need = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : 2; if (need > i) end = sample.Length - i; break; }
            if ((c & 0x80) == 0) break;
        }
        return System.Text.Unicode.Utf8.IsValid(sample[..end]);
    }

    /// <summary>Shannon entropy in bits per byte (0..8); above ~7.5 means compressed or encrypted.</summary>
    public static double Entropy(ReadOnlySpan<byte> b)
    {
        if (b.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var x in b) counts[x]++;
        double e = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = (double)c / b.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    public static string Sha256(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(SHA256.HashData(b));
    public static string Sha1(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(SHA1.HashData(b));
    public static string Md5(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(MD5.HashData(b));

    /// <summary>Decompresses gzip / zlib / raw deflate within the limit; null if the data is not valid for the format.</summary>
    public static byte[]? TryDecompress(ReadOnlySpan<byte> data, string format, long maxBytes)
    {
        try
        {
            using var input = new MemoryStream(data.ToArray(), writable: false);
            using Stream z = format switch
            {
                "gzip" => new GZipStream(input, CompressionMode.Decompress),
                "zlib" => new ZLibStream(input, CompressionMode.Decompress),
                "deflate" => new DeflateStream(input, CompressionMode.Decompress),
                _ => throw new ArgumentException(format),
            };
            return ReadBounded(z, maxBytes);
        }
        catch (InvalidDataException) { return null; }
        catch (IOException) { return null; }
    }

    /// <summary>Reads a stream to the end, failing (null) instead of exceeding <paramref name="maxBytes"/>.</summary>
    public static byte[]? ReadBounded(Stream s, long maxBytes)
    {
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        var spent = Spent.Current;
        int n;
        while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            spent?.Step();
            if (output.Length + n > maxBytes) return null;
            output.Write(buffer, 0, n);
        }
        return output.ToArray();
    }

    /// <summary>Xamarin "XALZ" LZ4-compressed assembly: magic, descriptor index, uncompressed size, LZ4 block.</summary>
    public static byte[]? TryXalz(ReadOnlySpan<byte> data, long maxBytes)
    {
        if (!StartsWith(data, "XALZ"u8) || data.Length < 12) return null;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
        // LZ4 expands at most ~255x; a larger claimed size is a corrupt header.
        if (size == 0 || size > maxBytes || size > (long)(data.Length - 12) * 255) return null;
        var output = new byte[size];
        int written = K4os.Compression.LZ4.LZ4Codec.Decode(data[12..], output);
        return written == size ? output : null;
    }

    /// <summary>.NET for Android "XAZS" Zstandard-compressed assembly: the XALZ header with a Zstandard frame.</summary>
    public static byte[]? TryXazs(ReadOnlySpan<byte> data, long maxBytes)
    {
        if (!StartsWith(data, "XAZS"u8) || data.Length < 12) return null;
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
        if (size == 0 || size > maxBytes) return null;
        var output = new byte[size];
        try
        {
            using var zstd = new ZstdSharp.Decompressor();
            return zstd.Unwrap(data[12..], output) == size ? output : null;
        }
        catch (ZstdSharp.ZstdException) { return null; }
    }

    /// <summary>An XALZ or XAZS assembly decompressed, null for other data or a corrupt one; Kind is "lz4", "zstd" or null.</summary>
    public static (byte[]? Bytes, string? Kind) TryDecompressAssembly(ReadOnlySpan<byte> data, long maxBytes) =>
        StartsWith(data, "XALZ"u8) ? (TryXalz(data, maxBytes), "lz4") : StartsWith(data, "XAZS"u8) ? (TryXazs(data, maxBytes), "zstd") : (null, null);

    public sealed record Carved(int Offset, int Length, bool IsDotNet);

    /// <summary>Finds PE images embedded anywhere in <paramref name="data"/> (validated headers; overlays excluded).</summary>
    public static List<Carved> CarvePe(ReadOnlySpan<byte> data, int maxResults = 10_000)
    {
        var found = new List<Carved>();
        int i = 0;
        while (found.Count < maxResults)
        {
            int at = data[i..].IndexOf("MZ"u8);
            if (at < 0) break;
            at += i;
            var pe = PeImage.TryParse(data, at);
            if (pe != null && pe.EndOfImage <= data.Length - at && pe.EndOfImage > 0)
            {
                found.Add(new Carved(at, (int)pe.EndOfImage, pe.IsDotNet(data)));
                // Nested images are found by analyzing the container.
                i = at + (int)pe.EndOfImage;
            }
            else
            {
                i = at + 1;
            }
            if (i >= data.Length) break;
        }
        return found;
    }

    /// <summary>Offsets of every occurrence of <paramref name="magic"/>.</summary>
    public static List<int> FindAll(ReadOnlySpan<byte> data, ReadOnlySpan<byte> magic, int maxResults = 100_000)
    {
        var found = new List<int>();
        int i = 0;
        while (found.Count < maxResults && i < data.Length)
        {
            int at = data[i..].IndexOf(magic);
            if (at < 0) break;
            found.Add(i + at);
            i += at + 1;
        }
        return found;
    }

    private static readonly HashSet<string> RunnableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".lnk", ".msi", ".msp", ".cpl", ".jar", ".reg", ".sh", ".py", ".appref-ms", ".application", ".gadget",
    };

    // Explorer reads these when it lists or previews a folder, or hands them to
    // a host on open, so a file is parsed without being run.
    private static readonly HashSet<string> ShellParsedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".url", ".scf", ".library-ms", ".search-ms", ".searchConnector-ms", ".settingcontent-ms", ".chm", ".msc", ".xll",
        ".wsc", ".inf", ".appinstaller",
    };

    /// <summary>True for a file name the Windows shell parses from a folder or on open: shortcuts, search and library descriptions, desktop.ini, help files, snap-ins, add-ins, setup information.</summary>
    public static bool IsShellParsed(string fileName) =>
        ShellParsedExtensions.Contains(Path.GetExtension(fileName)) || fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);

    /// <summary>A relative path that cannot escape the output directory; runnable and shell-parsed names get ".bin", ".dll" is kept.</summary>
    public static string SafeRelativePath(string name, string fallback, int maxParts = 8)
    {
        var invalid = Path.GetInvalidFileNameChars().Concat(['<', '>', ':', '"', '|', '?', '*']).ToHashSet();
        var parts = name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p != "." && p != ".." && !p.EndsWith(':'))
            .Select(p => new string(p.Select(c => invalid.Contains(c) || char.IsControl(c) ? '_' : c).ToArray()).Trim(' ', '.'))
            .Where(p => p.Length > 0)
            .Select(p => p.Length > 120 ? p[..120] : p)
            .ToList();
        if (parts.Count == 0) parts.Add(fallback);
        var file = parts[^1];
        if (RunnableExtensions.Contains(Path.GetExtension(file)) || IsShellParsed(file)) parts[^1] = file + ".bin";
        for (int i = 0; i < parts.Count; i++)
            if (SafeFile.IsReservedName(parts[i])) parts[i] = "_" + parts[i];
        if (parts.Count > maxParts) parts = [.. parts.Take(maxParts - 1), parts[^1]];
        return Path.Combine([.. parts]);
    }

    /// <summary>The path without the ".bin" added to a runnable extension; null when it has none.</summary>
    public static string? WithoutRunnableSuffix(string path) =>
        path.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) && RunnableExtensions.Contains(Path.GetExtension(path[..^4])) ? path[..^4] : null;

    /// <summary>Full path of <paramref name="relative"/> under <paramref name="root"/>; throws if it would escape it, lexically or through a link.</summary>
    public static string UnderRoot(string root, string relative) => SafeFile.UnderRoot(root, relative);

    /// <summary>Whether the file holds <paramref name="bytes"/>; reads with full sharing, since a concurrent writer may hold a handle.</summary>
    private static bool SameContent(string path, ReadOnlySpan<byte> bytes)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length != bytes.Length) return false;
            var existing = new byte[bytes.Length];
            stream.ReadExactly(existing);
            return existing.AsSpan().SequenceEqual(bytes);
        }
        catch (FileNotFoundException) { return false; }
    }

    /// <summary>
    /// Writes an extracted file to a unique path under root, not flushed to disk, marked as from the Internet zone on
    /// Windows through <paramref name="zone"/> (a mark of its own when null); never overwrites a different file.
    /// <paramref name="names"/> keeps one extraction's numbering, so a repeated name costs one write; null: none kept.
    /// </summary>
    public static string WriteUnique(string root, string relative, ReadOnlySpan<byte> bytes, ZoneMark? zone = null, UniqueNames? names = null)
    {
        zone ??= new ZoneMark();
        var wanted = UnderRoot(root, relative);
        var dir = Path.GetDirectoryName(wanted)!;
        var stem = Path.GetFileNameWithoutExtension(wanted);
        var ext = Path.GetExtension(wanted);
        int k = 1;
        List<(int Length, string Path)>? written = null;
        if (names != null && names.ByName.TryGetValue(wanted, out var seen))
        {
            foreach (var (length, file) in seen.Written)
                if (length == bytes.Length && SameContent(file, bytes)) return zone.Mark(file);
            (k, written) = seen;
        }
        for (; ; k++)
        {
            var path = k == 1 ? wanted : Path.Combine(dir, $"{stem}_{k}{ext}");
            string? done = null;
            // A name a regular file holds costs a length check, not a guarded
            // write; links and folders still meet the guard.
            var taken = new FileInfo(path);
            if (taken.Exists && taken.LinkTarget == null)
            {
                if (SameContent(path, bytes)) done = path;
            }
            else
            {
                try { done = SafeFile.WriteUnderRoot(root, Path.GetRelativePath(root, path), bytes, overwrite: false, flush: false); }
                catch (ToolError ex) when (ex.Code == ErrorCode.Conflict)
                {
                    if (SameContent(path, bytes)) done = path;
                }
            }
            if (done == null) continue;
            if (names != null)
            {
                written ??= [];
                written.Add((bytes.Length, done));
                names.ByName[wanted] = (k + 1, written);
            }
            return zone.Mark(done);
        }
    }

    /// <summary>The name of the alternate data stream Windows reads a file's security zone from.</summary>
    public const string ZoneStream = "Zone.Identifier";
}

/// <summary>One extraction's numbered names: the next number to try and the files written for each wanted path.</summary>
public sealed class UniqueNames
{
    internal readonly Dictionary<string, (int Next, List<(int Length, string Path)> Written)> ByName =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
}

/// <summary>Marks one extraction's files as from the Internet zone (ZoneId=3) on Windows and keeps the first failure.</summary>
public sealed class ZoneMark
{
    private readonly Action<string> _write;
    private string? _problem;

    /// <summary>A mark that writes the zone stream; <paramref name="write"/> replaces the write of a stream path.</summary>
    public ZoneMark(Action<string>? write = null) =>
        _write = write ?? (stream => File.WriteAllText(stream, "[ZoneTransfer]\r\nZoneId=3\r\n"));

    /// <summary>The note an extraction adds when a file was left unmarked, from the first failure; null when none failed.</summary>
    public string? Note => _problem == null ? null : $"files not marked as from the internet zone: {_problem}";

    /// <summary>Writes the zone stream of <paramref name="path"/> on Windows and returns the path; a failure is kept for <see cref="Note"/>.</summary>
    public string Mark(string path)
    {
        if (!OperatingSystem.IsWindows()) return path;
        try { _write(path + ":" + Blob.ZoneStream); }
        // A volume without alternate data streams (FAT, some shares) refuses
        // the write; the file stays unmarked and the note says so.
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            Interlocked.CompareExchange(ref _problem, ex.Message, null);
        }
        return path;
    }
}
