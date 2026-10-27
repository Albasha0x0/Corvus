using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Corvus.Core.Mobile;

namespace Corvus.Core;

/// <summary>Electron binary facts read statically: fuses, Electron, Chromium and Node versions, and declared ASAR header hashes.</summary>
public static class Electron
{
    public static ReadOnlySpan<byte> FuseSentinel => "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"u8;

    /// <summary>Wire version 1 fuse order (@electron/fuses FuseV1Options); later indices are reported as fuse_&lt;n&gt;.</summary>
    public static readonly string[] FuseNames =
    [
        "RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnvironmentVariable", "EnableNodeCliInspectArguments",
        "EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot", "GrantFileProtocolExtraPrivileges",
        "WasmTrapHandlers",
    ];

    public sealed record Fuse(int Index, string Name, string State);

    /// <summary>A header hash the app declares for an archive: where it was found, the archive it names and the value.</summary>
    public sealed record DeclaredHash(string Source, string File, string Algorithm, string Hash);

    /// <summary>What a scan of an Electron binary found; Evidence quotes the strings the versions came from.</summary>
    public sealed record BinaryFacts(string Path, string? ElectronVersion, string? ChromiumVersion, string? NodeVersion, IReadOnlyList<string> Evidence,
        int? FuseWireVersion, IReadOnlyList<Fuse> Fuses, int Sentinels)
    {
        public bool IsElectron => Sentinels > 0 || ElectronVersion != null;
    }

    private const int Window = 4 * 1024 * 1024, Overlap = 512, MaxHits = 64;

    /// <summary>Scans a binary in 4 MiB windows for the fuse sentinel and the version strings; nothing is mapped or executed.</summary>
    public static BinaryFacts Scan(Stream stream, string path, CancellationToken ct = default)
    {
        var buffer = new byte[Window + Overlap];
        string? electron = null, chromium = null, node = null;
        var evidence = new List<string>();
        int sentinels = 0, hits = 0;
        int? wire = null;
        var fuses = new List<Fuse>();
        int carried = 0;
        stream.Position = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int filled = carried + stream.ReadAtLeast(buffer.AsSpan(carried), buffer.Length - carried, throwOnEndOfStream: false);
            bool end = filled < buffer.Length;
            var span = buffer.AsSpan(0, filled);
            // A match starting in the overlap is seen in the next window.
            int limit = end ? filled : filled - Overlap;
            for (int at = 0; (at = IndexFrom(span, FuseSentinel, at, limit)) >= 0; at++)
            {
                if (sentinels++ > 0) continue;
                var tail = span[(at + FuseSentinel.Length)..];
                if (tail.Length < 2) continue;
                wire = tail[0];
                // Another wire version is reported, not guessed.
                if (wire != 1) continue;
                int count = Math.Min(tail[1], tail.Length - 2);
                for (int i = 0; i < count; i++)
                    fuses.Add(new Fuse(i, i < FuseNames.Length ? FuseNames[i] : $"fuse_{i}", tail[2 + i] switch
                    {
                        (byte)'0' => "disabled",
                        (byte)'1' => "enabled",
                        (byte)'r' => "removed",
                        var b => $"unknown (0x{b:X2})",
                    }));
            }
            if (electron == null)
                for (int at = 0; hits < MaxHits && (at = IndexFrom(span, " Electron/"u8, at, limit)) >= 0; at++, hits++)
                {
                    var version = VersionAt(span, at + 10);
                    if (version == null) continue;
                    electron = version;
                    // The user agent template: "Chrome/<chromium> Electron/<electron>".
                    int chrome = span[Math.Max(0, at - 40)..at].LastIndexOf("Chrome/"u8);
                    if (chrome >= 0)
                    {
                        int start = Math.Max(0, at - 40) + chrome;
                        chromium = VersionAt(span, start + 7);
                        evidence.Add(Encoding.ASCII.GetString(span[start..(at + 10 + version.Length)]));
                    }
                    else evidence.Add("Electron/" + version);
                    break;
                }
            if (node == null)
                for (int at = 0; hits < MaxHits && (at = IndexFrom(span, "node-v"u8, at, limit)) >= 0; at++, hits++)
                {
                    var version = VersionAt(span, at + 6, suffix: false);
                    if (version == null || !span[(at + 6 + version.Length)..].StartsWith("-headers"u8)) continue;
                    node = version;
                    evidence.Add($"node-v{version}-headers");
                    break;
                }
            if (end) break;
            buffer.AsSpan(filled - Overlap, Overlap).CopyTo(buffer);
            carried = Overlap;
        }
        return new BinaryFacts(path, electron, chromium, node, evidence, wire, fuses, sentinels);
    }

    private static int IndexFrom(ReadOnlySpan<byte> span, ReadOnlySpan<byte> needle, int from, int limit)
    {
        if (from >= limit) return -1;
        int i = span[from..].IndexOf(needle);
        return i < 0 || from + i >= limit ? -1 : from + i;
    }

    /// <summary>"1.2.3" or (with <paramref name="suffix"/>) "1.2.3-beta.4" at <paramref name="at"/>; null unless it has at least two dots.</summary>
    private static string? VersionAt(ReadOnlySpan<byte> span, int at, bool suffix = true)
    {
        int end = at, dots = 0;
        while (end < span.Length && end - at < 40 && (char.IsAsciiDigit((char)span[end]) || span[end] == '.'
                   || (suffix && end > at && dots >= 2 && (char.IsAsciiLetterOrDigit((char)span[end]) || span[end] == '-'))))
        {
            if (span[end] == '.') dots++;
            end++;
        }
        return dots >= 2 && end > at && char.IsAsciiDigit((char)span[at]) ? Encoding.ASCII.GetString(span[at..end]).TrimEnd('.', '-') : null;
    }

    /// <summary>The app folder of an archive and its likely main executables, largest first, helpers and uninstallers skipped.</summary>
    public static (string? Root, List<string> Executables) LayoutOf(string archivePath)
    {
        var resources = Path.GetDirectoryName(Path.GetFullPath(archivePath));
        var root = resources == null ? null : Path.GetDirectoryName(resources);
        var found = new List<string>();
        if (root == null) return (null, found);
        try
        {
            if (Path.GetFileName(resources!).Equals("Resources", StringComparison.Ordinal) && Path.GetFileName(root).Equals("Contents", StringComparison.Ordinal))
            {
                var framework = Path.Combine(root, "Frameworks", "Electron Framework.framework");
                foreach (var candidate in new[] { Path.Combine(framework, "Electron Framework"), Path.Combine(framework, "Versions", "A", "Electron Framework") })
                    if (File.Exists(candidate)) { found.Add(candidate); break; }
                return (root, found);
            }
            if (!Directory.Exists(root)) return (root, found);
            foreach (var file in Directory.EnumerateFiles(root))
            {
                var name = Path.GetFileName(file);
                if (name.StartsWith("Uninstall", StringComparison.OrdinalIgnoreCase) || name.Equals("elevate.exe", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("Update.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("squirrel.exe", StringComparison.OrdinalIgnoreCase)) continue;
                var ext = Path.GetExtension(name);
                if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) || (ext.Length == 0 && Magic(file, "\x7F" + "ELF"))) found.Add(file);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        found.Sort((a, b) => Size(b).CompareTo(Size(a)));
        return (root, found);
    }

    private static long Size(string file)
    {
        try { return new FileInfo(file).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }

    private static bool Magic(string file, string magic)
    {
        // A FIFO beside the archive (the runtime's debug pipes in /tmp) would block the open.
        if (!InputFiles.IsRegularOrUnknown(file)) return false;
        try
        {
            using var f = File.OpenRead(file);
            Span<byte> head = stackalloc byte[4];
            return f.ReadAtLeast(head, 4, throwOnEndOfStream: false) == 4 && Encoding.Latin1.GetString(head) == magic;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>The header hash the app declares for the archive (PE resource or Info.plist); null when it declares none.</summary>
    public static DeclaredHash? DeclaredFor(string archivePath)
    {
        var full = Path.GetFullPath(archivePath);
        var (root, executables) = LayoutOf(full);
        if (root == null) return null;
        var plist = Path.Combine(root, "Info.plist");
        IEnumerable<DeclaredHash> declared = File.Exists(plist) && Path.GetFileName(root) == "Contents"
            ? PlistHashes(plist)
            : executables.Where(e => e.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).SelectMany(ResourceHashes);
        var relative = Path.GetRelativePath(root, full).Replace('\\', '/');
        return declared.FirstOrDefault(d => d.File.Replace('\\', '/').Equals(relative, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The INTEGRITY/ELECTRONASAR resource of a Windows executable: [{"file", "alg", "value"}].</summary>
    public static List<DeclaredHash> ResourceHashes(string executable)
    {
        try
        {
            using var f = File.OpenRead(executable);
            var json = IntegrityResource(f);
            return json == null ? [] : ParseResource(json, $"{Path.GetFileName(executable)} resource INTEGRITY/ELECTRONASAR");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    internal static List<DeclaredHash> ParseResource(byte[] json, string source)
    {
        var result = new List<DeclaredHash>();
        try
        {
            using var doc = JsonDocument.Parse(json.AsMemory().TrimEnd((byte)0));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return result;
            foreach (var item in doc.RootElement.EnumerateArray())
                if (item.ValueKind == JsonValueKind.Object && Str(item, "file") is { } file && Str(item, "value") is { } hash)
                    result.Add(new DeclaredHash(source, file, Str(item, "alg") ?? "SHA256", hash));
        }
        // InvalidOperationException: invalid UTF-8 in a string.
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { }
        return result;

        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    /// <summary>Info.plist ElectronAsarIntegrity: {"Resources/app.asar": {"algorithm", "hash"}}.</summary>
    public static List<DeclaredHash> PlistHashes(string infoPlist)
    {
        var result = new List<DeclaredHash>();
        byte[] bytes;
        try
        {
            if (new FileInfo(infoPlist).Length > 16 * 1024 * 1024) return result;
            bytes = File.ReadAllBytes(infoPlist);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return result; }
        if (Plist.Read(bytes).Root is not PlistDict root || root["ElectronAsarIntegrity"] is not PlistDict integrity) return result;
        foreach (var (file, value) in integrity.Entries)
            if (value is PlistDict d && d["hash"] is PlistString hash)
                result.Add(new DeclaredHash("Info.plist ElectronAsarIntegrity", file, (d["algorithm"] as PlistString)?.Value ?? "SHA256", hash.Value));
        return result;
    }

    /// <summary>The INTEGRITY/ELECTRONASAR resource, read from the resource section only; null when absent or malformed.</summary>
    public static byte[]? IntegrityResource(Stream s)
    {
        const int MaxSection = 64 * 1024 * 1024;
        var head = new byte[(int)Math.Min(s.Length, 64 * 1024)];
        s.Position = 0;
        s.ReadExactly(head);
        if (head.Length < 0x40 || head[0] != 'M' || head[1] != 'Z') return null;
        int pe = BinaryPrimitives.ReadInt32LittleEndian(head.AsSpan(0x3C));
        if (pe < 0 || pe > head.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(pe)) != 0x4550) return null;
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(pe + 6)), optSize = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(pe + 20));
        int opt = pe + 24;
        if (opt + 2 > head.Length) return null;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(opt));
        int dirs = opt + (magic == 0x20B ? 112 : 96);
        if (magic is not (0x10B or 0x20B) || dirs + 3 * 8 > head.Length || dirs + 3 * 8 > opt + optSize) return null;
        uint rsrc = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(dirs + 16));
        if (rsrc == 0) return null;
        for (int i = 0, at = opt + optSize; i < sections && at + 40 <= head.Length; i++, at += 40)
        {
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(at + 12)), raw = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(at + 16)),
                ptr = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(at + 20));
            if (rsrc < va || rsrc >= va + raw) continue;
            if (raw > MaxSection || ptr + (long)raw > s.Length) return null;
            var section = new byte[raw];
            s.Position = ptr;
            s.ReadExactly(section);
            return FindResource(section, va, (int)(rsrc - va));
        }
        return null;
    }

    private static byte[]? FindResource(byte[] section, uint sectionVa, int root)
    {
        // Type, then name, then language, then the data entry.
        int? type = Child(root, "INTEGRITY"), item = type is { } t ? Child(t, "ELECTRONASAR") : null, language = item is { } n ? Child(n, null) : null;
        if (language is not { } data || data + 16 > section.Length) return null;
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(section.AsSpan(data)), size = BinaryPrimitives.ReadUInt32LittleEndian(section.AsSpan(data + 4));
        long at = (long)rva - sectionVa;
        return at < 0 || size > 1024 * 1024 || at + size > section.Length ? null : section.AsSpan((int)at, (int)size).ToArray();

        int? Child(int dir, string? name)
        {
            if (dir < 0 || dir + 16 > section.Length) return null;
            int count = BinaryPrimitives.ReadUInt16LittleEndian(section.AsSpan(dir + 12)) + BinaryPrimitives.ReadUInt16LittleEndian(section.AsSpan(dir + 14));
            for (int i = 0; i < count && i < 4096; i++)
            {
                int e = dir + 16 + i * 8;
                if (e + 8 > section.Length) return null;
                uint id = BinaryPrimitives.ReadUInt32LittleEndian(section.AsSpan(e)), target = BinaryPrimitives.ReadUInt32LittleEndian(section.AsSpan(e + 4));
                if (name != null)
                {
                    if ((id & 0x80000000) == 0) continue;
                    int str = root + (int)(id & 0x7FFFFFFF);
                    if (str < 0 || str + 2 > section.Length) continue;
                    int len = BinaryPrimitives.ReadUInt16LittleEndian(section.AsSpan(str));
                    if (str + 2 + len * 2 > section.Length || !Encoding.Unicode.GetString(section, str + 2, len * 2).Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                }
                return root + (int)(target & 0x7FFFFFFF);
            }
            return null;
        }
    }
}
