using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core.Installers;

namespace Corvus.Core.Python;

/// <summary>A PyInstaller program's CArchive and PYZ archive; --key builds (3.x to 5.x) decrypt with the stored key.</summary>
/// <remarks>Extracted .pyc files get back the header PyInstaller 5.3+ strips.</remarks>
public static class PyInstallerArchive
{
    public const string Kind = "PyInstaller executable";
    private static readonly byte[] Cookie = [(byte)'M', (byte)'E', (byte)'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E];
    private const int Cookie20 = 24, Cookie21 = 24 + 64;
    /// <summary>The cookie is looked for in this many bytes at the end (a signature or ELF section table may follow it).</summary>
    private const int CookieWindow = 16 << 20;
    private const int MaxToc = 64 << 20, MaxPyzToc = 64 << 20, MaxEntryName = 4096;
    private const int CryptBlock = 16;

    /// <summary>The bootloader's own marker: every PyInstaller bootloader names the _MEIPASS variable.</summary>
    public static bool HasBootloader(ReadOnlySpan<byte> head) => head.IndexOf("_MEIPASS"u8) >= 0;

    /// <summary>The offset of the last valid cookie, or -1.</summary>
    internal static long FindCookie(InstallerPe.Read read, long length)
    {
        long from = Math.Max(0, length - CookieWindow);
        var tail = read(from, (int)(length - from));
        if (tail == null) return -1;
        var span = tail.AsSpan();
        while (span.Length > 0)
        {
            int at = span.LastIndexOf(Cookie);
            if (at < 0) return -1;
            if (Layout(read, from + at, length) != null) return from + at;
            span = span[..at];
        }
        return -1;
    }

    private sealed record ArchiveLayout(long Start, long Toc, int TocLength, int PyVersion, string? Library, int CookieSize);

    private static ArchiveLayout? Layout(InstallerPe.Read read, long cookie, long length)
    {
        if (read(cookie, Cookie20) is not { } c) return null;
        uint package = BinaryPrimitives.ReadUInt32BigEndian(c.AsSpan(8));
        uint toc = BinaryPrimitives.ReadUInt32BigEndian(c.AsSpan(12));
        int tocLength = BinaryPrimitives.ReadInt32BigEndian(c.AsSpan(16));
        int pyver = BinaryPrimitives.ReadInt32BigEndian(c.AsSpan(20));
        var lib = read(cookie + Cookie20, 64);
        bool v21 = lib != null && Encoding.ASCII.GetString(lib).Contains("python", StringComparison.OrdinalIgnoreCase);
        int size = v21 ? Cookie21 : Cookie20;
        long start = cookie + size - package;
        if (package < size || start < 0 || tocLength < 0 || tocLength > MaxToc || toc > package || start + toc + tocLength > cookie || pyver is < 10 or > 999) return null;
        string? library = v21 ? Encoding.ASCII.GetString(lib!).Split('\0')[0] : null;
        return new ArchiveLayout(start, start + toc, tocLength, pyver, library, size);
    }

    /// <summary>The program in the file read by <paramref name="read"/>; null when no cookie is found.</summary>
    internal static FrozenApp? Read(InstallerPe.Read read, long length, string name, AnalysisLimits limits, CancellationToken ct)
    {
        long cookie = FindCookie(read, length);
        if (cookie < 0) return null;
        var layout = Layout(read, cookie, length)!;
        var app = new FrozenApp("PyInstaller", Kind);
        (int, int) version = layout.PyVersion >= 100 ? (layout.PyVersion / 100, layout.PyVersion % 100) : (layout.PyVersion / 10, layout.PyVersion % 10);
        app.Version = version;
        app.VersionSource = layout.Library is { Length: > 0 } lib ? lib : "archive cookie";
        var toc = read(layout.Toc, layout.TocLength) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: the PyInstaller table of contents runs past the file.");
        app.Notes.Add($"CArchive {(layout.CookieSize == Cookie21 ? "2.1+" : "2.0")} at 0x{layout.Start:X}, {length - layout.Start:N0} bytes.");

        var entries = new List<(string Name, long Position, uint Stored, uint Size, bool Compressed, char Type)>();
        for (int at = 0; at + 18 <= toc.Length;)
        {
            ct.ThrowIfCancellationRequested();
            int entrySize = BinaryPrimitives.ReadInt32BigEndian(toc.AsSpan(at));
            if (entrySize < 18 || entrySize > toc.Length - at || entrySize > 18 + MaxEntryName) { app.Notes.Add($"The table of contents is damaged after {entries.Count:N0} entries."); break; }
            uint position = BinaryPrimitives.ReadUInt32BigEndian(toc.AsSpan(at + 4)), stored = BinaryPrimitives.ReadUInt32BigEndian(toc.AsSpan(at + 8)),
                size = BinaryPrimitives.ReadUInt32BigEndian(toc.AsSpan(at + 12));
            var entryName = Encoding.UTF8.GetString(toc, at + 18, entrySize - 18).TrimEnd('\0').Replace('\\', '/').TrimStart('/');
            entries.Add((entryName, layout.Start + position, stored, size, toc[at + 16] != 0, (char)toc[at + 17]));
            at += entrySize;
        }

        byte[]? Raw((string Name, long Position, uint Stored, uint Size, bool Compressed, char Type) e)
        {
            if (e.Stored > limits.MaxItemBytes || e.Position + e.Stored > length || read(e.Position, (int)e.Stored) is not { } stored) return null;
            return e.Compressed ? Blob.TryDecompress(stored, "zlib", limits.MaxItemBytes) : stored;
        }

        // The .pyc magic: the PYZ header's, an intact module header (before 5.3), or the version's final release.
        byte[]? magic = null;
        var pyzEntries = entries.Where(e => e.Type is 'z').ToList();
        var pyzData = new Dictionary<string, byte[]?>();
        foreach (var z in pyzEntries)
        {
            var data = pyzData[z.Name] = Raw(z);
            if (data is { Length: >= 12 } && data.AsSpan().StartsWith("PYZ\0"u8)) magic ??= data[4..8];
        }
        if (magic == null)
            foreach (var m in entries.Where(e => e.Type is 'm' or 'M'))
                if (Raw(m) is { Length: >= 4 } b && b[2] == '\r' && b[3] == '\n') { magic = b[..4]; break; }
        if (magic != null && PyVersion.FromMagic(magic) is { } fromMagic && fromMagic != version)
            app.Notes.Add($"The cookie names Python {PyVersion.Label(version)}; the .pyc magic {PyVersion.Magic(magic)} is Python {PyVersion.Label(fromMagic)}.");
        magic ??= PyVersion.MagicOf(version);

        byte[]? Pyc(byte[]? code) => code == null ? null
            // The header is still there before 5.3.
            : code.Length >= 4 && code[2] == '\r' && code[3] == '\n' ? code
            : magic == null ? code : PyVersion.WithHeader(magic, version, code);

        string? key = Key(entries.Where(e => e.Name == "pyimod00_crypto_key" && e.Type is 'm' or 'M').Select(e => Raw(e)).FirstOrDefault(), version);
        foreach (var e in entries)
        {
            var entry = e;
            switch (e.Type)
            {
                case 's':
                    bool boot = e.Name.StartsWith("pyiboot", StringComparison.Ordinal) || e.Name.StartsWith("pyi_rth_", StringComparison.Ordinal);
                    if (!boot) app.EntryScripts.Add(e.Name);
                    app.Entries.Add(new FrozenEntry(e.Name + ".pyc", e.Size, boot ? FrozenApp.Bootstrap : FrozenApp.Script, () => Pyc(Raw(entry))));
                    break;
                case 'm' or 'M':
                    app.Entries.Add(new FrozenEntry(e.Name + ".pyc", e.Size, e.Name.StartsWith("pyimod", StringComparison.Ordinal) ? FrozenApp.Bootstrap
                        : e.Type == 'M' ? FrozenApp.Package : FrozenApp.Module, () => Pyc(Raw(entry))));
                    break;
                case 'z':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, FrozenApp.Archive, () => pyzData[entry.Name]));
                    if (pyzData[e.Name] is { } pyz) Pyz(app, pyz, e.Name + "_extracted/", version, magic, key, limits, ct);
                    else app.Notes.Add($"{e.Name}: unreadable PYZ archive.");
                    break;
                case 'b':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, FrozenApp.BinaryRole(e.Name), () => Raw(entry)));
                    break;
                case 'Z':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, "zip", () => Raw(entry)));
                    break;
                case 'o':
                    app.Entries.Add(new FrozenEntry(e.Name, 0, "runtime option"));
                    break;
                case 'd':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, "dependency (a file of another program in the build)"));
                    break;
                case 'n':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, "link"));
                    break;
                case 'l':
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, "splash screen", () => Raw(entry)));
                    break;
                default:
                    app.Entries.Add(new FrozenEntry(e.Name, e.Size, FrozenApp.Data, () => Raw(entry)));
                    break;
            }
        }
        if (key != null) app.Notes.Add($"Built with --key: the PYZ modules are AES-encrypted with key '{key}' (from pyimod00_crypto_key); extracted .pyc files are decrypted.");
        var contents = entries.FirstOrDefault(e => e.Type == 'o' && e.Name.StartsWith("pyi-contents-directory ", StringComparison.Ordinal)).Name;
        if (contents != null && !app.Entries.Any(e => e.Role == FrozenApp.Runtime)) app.Notes.Add($"One-folder build: the runtime, native modules and data files sit in the {contents["pyi-contents-directory ".Length..]} folder beside the executable.");
        return app;
    }

    /// <summary>A PYZ archive on its own (extracted from a program): its modules with their headers rebuilt.</summary>
    public static ContainerContents OpenPyz(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        ReadPyz(data, name, limits, ct).ToContainer(allFiles, limits, ct);

    public static FrozenApp ReadPyz(byte[] data, string name, AnalysisLimits limits, CancellationToken ct)
    {
        var app = new FrozenApp("PyInstaller PYZ archive", "PyInstaller PYZ archive");
        if (data.Length >= 12 && PyVersion.FromMagic(data.AsSpan(4)) is { } version)
        {
            app.Version = version;
            app.VersionSource = $".pyc magic {PyVersion.Magic(data.AsSpan(4))}";
            Pyz(app, data, "", version, data[4..8], null, limits, ct);
        }
        else app.Notes.Add($"{name}: the PYZ header names no known Python version.");
        return app;
    }

    /// <summary>The modules of a PYZ archive: "PYZ\0", the .pyc magic, the table of contents' offset, then zlib-compressed code objects.</summary>
    private static void Pyz(FrozenApp app, byte[] pyz, string prefix, (int, int) version, byte[]? magic, string? key, AnalysisLimits limits, CancellationToken ct)
    {
        if (pyz.Length < 12 || !pyz.AsSpan().StartsWith("PYZ\0"u8)) { app.Notes.Add($"{prefix.TrimEnd('/')}: not a PYZ archive."); return; }
        var pyzMagic = pyz[4..8];
        var pyzVersion = PyVersion.FromMagic(pyzMagic) ?? version;
        foreach (var (name, type, data) in PyzEntries(pyz, pyzVersion, app.Notes, ct))
        {
            var path = prefix + (type == 2 ? name : name.Replace('.', '/') + (type == 1 ? "/__init__.pyc" : ".pyc"));
            var role = type switch { 1 => FrozenApp.Package, 2 => FrozenApp.Data, 3 => "namespace package", _ => FrozenApp.Module };
            var stored = data;
            app.Entries.Add(new FrozenEntry(path, data.Length, key != null && type != 2 ? FrozenApp.Encrypted : role, () =>
            {
                var plain = Blob.TryDecompress(stored, "zlib", limits.MaxItemBytes) ?? (key != null ? Decrypt(stored, key, limits) : null);
                return plain == null ? null : type == 2 ? plain : PyVersion.WithHeader(pyzMagic, pyzVersion, plain);
            }));
        }
    }

    /// <summary>Each PYZ entry: name, type (0 module, 1 package, 2 data, 3 namespace package) and its stored bytes.</summary>
    internal static IEnumerable<(string Name, int Type, byte[] Data)> PyzEntries(byte[] pyz, (int, int) version, List<string> notes, CancellationToken ct)
    {
        uint tocAt = BinaryPrimitives.ReadUInt32BigEndian(pyz.AsSpan(8));
        if (tocAt >= pyz.Length || pyz.Length - tocAt > MaxPyzToc) { notes.Add("The PYZ table of contents lies outside the archive."); yield break; }
        var toc = PyMarshal.TryRead(pyz, version, out var error, (int)tocAt);
        IEnumerable<object> rows = toc switch
        {
            PySequence { Kind: '[' or '(' } list => list.Items,
            PyDict dict => dict.Items.Select(kv => (object)new PySequence('(', [kv.Key, kv.Value])),
            _ => [],
        };
        if (toc == null) notes.Add($"The PYZ table of contents is unreadable ({error}).");
        int bad = 0;
        foreach (var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            if (row is not PySequence { Items: [var n, PySequence { Items: [var t, var p, var l] }] } || ToLong(t) is not { } type || ToLong(p) is not { } pos || ToLong(l) is not { } len
                || pos < 0 || len < 0 || pos > pyz.Length - len)
            {
                bad++;
                continue;
            }
            yield return (PyMarshal.Str(n), (int)type, pyz.AsSpan((int)pos, (int)len).ToArray());
        }
        if (bad > 0) notes.Add($"{bad} PYZ entr(ies) unreadable or outside the archive.");
    }

    private static long? ToLong(object o) => o switch { long l => l, bool b => b ? 1 : 0, _ => null };

    /// <summary>The key string of pyimod00_crypto_key ("key = '...'"), normalized as the bootloader does: cut or zero-filled to 16 characters.</summary>
    internal static string? Key(byte[]? pyc, (int, int) version)
    {
        if (pyc == null) return null;
        int start = pyc.Length >= 4 && pyc[2] == '\r' && pyc[3] == '\n' ? PyVersion.HeaderLength(version) : 0;
        if (PyMarshal.TryRead(pyc, version, out _, start) is not PyCode code || code.Consts.OfType<string>().FirstOrDefault() is not { } key) return null;
        return key.Length > CryptBlock ? key[..CryptBlock] : key.PadLeft(CryptBlock, '0');
    }

    /// <summary>An encrypted PYZ entry (a 16-byte IV, then the cipher text) decrypted and decompressed: AES-CTR (4.x, 5.x) or AES-CFB (3.x).</summary>
    internal static byte[]? Decrypt(byte[] data, string key, AnalysisLimits limits)
    {
        if (data.Length <= CryptBlock) return null;
        using var aes = Aes.Create();
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length != CryptBlock) return null;
        aes.Key = keyBytes;
        var iv = data[..CryptBlock];
        var body = data.AsSpan(CryptBlock);
        if (Blob.TryDecompress(Ctr(aes, iv, body), "zlib", limits.MaxItemBytes) is { } ctr) return ctr;
        foreach (int feedback in body.Length % CryptBlock == 0 ? new[] { 8, 128 } : [8])
            if (Blob.TryDecompress(aes.DecryptCfb(body, iv, PaddingMode.None, feedback), "zlib", limits.MaxItemBytes) is { } cfb) return cfb;
        return null;
    }

    /// <summary>AES-CTR as tiny-AES-c runs it: the 16-byte counter starts at the IV and counts up big-endian.</summary>
    internal static byte[] Ctr(Aes aes, byte[] iv, ReadOnlySpan<byte> body)
    {
        var counter = (byte[])iv.Clone();
        var output = new byte[body.Length];
        var block = new byte[CryptBlock];
        for (int at = 0; at < body.Length; at += CryptBlock)
        {
            aes.EncryptEcb(counter, block, PaddingMode.None);
            for (int i = 0; i < CryptBlock && at + i < body.Length; i++) output[at + i] = (byte)(body[at + i] ^ block[i]);
            for (int i = CryptBlock - 1; i >= 0 && ++counter[i] == 0; i--) { }
        }
        return output;
    }
}
