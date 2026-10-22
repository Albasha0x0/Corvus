using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core.Installers;

namespace Corvus.Core.Python;

/// <summary>
/// Frozen Python programs read as containers: PyInstaller (<see cref="PyInstallerArchive"/>), py2exe (the PYTHONSCRIPT
/// resource and the library zip in the executable or beside it), cx_Freeze (the launcher and lib/library.zip beside it),
/// Nuitka (the onefile payload; standalone code is compiled to native code) and a library zip of .pyc files on its own.
/// Files beside the executable are read only when its location on disk is known.
/// </summary>
public static class FrozenPython
{
    private const int MaxScanned = 20_000;
    /// <summary>Markers are looked for in this many leading bytes (a streamed file's head).</summary>
    private const int MarkerBytes = 1 << 20;

    /// <summary>Whether <paramref name="head"/> (a file's first bytes) is the executable of a frozen Python program a stream can open: PyInstaller or Nuitka onefile.</summary>
    public static bool LooksStreamable(ReadOnlySpan<byte> head)
    {
        var kind = Blob.Identify(head);
        if (kind is not ("native PE" or "elf" or "mach-o")) return false;
        var marker = head[..Math.Min(head.Length, MarkerBytes)];
        return PyInstallerArchive.HasBootloader(marker) || NuitkaPayload(marker) >= 0 || NuitkaResource(head) != null;
    }

    /// <summary>The program in <paramref name="data"/> (a whole file), or null when it is none; <paramref name="location"/> is its path on disk.</summary>
    public static FrozenApp? Read(byte[] data, string name, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(data);
        var kind = Blob.Identify(data);
        if (kind is not ("native PE" or "elf" or "mach-o" or "data")) return null;
        if (PyInstallerArchive.Read(read, data.Length, name, limits, ct) is { } pyinstaller) return Beside(pyinstaller, location);
        if (kind == "data") return null;
        var pe = PeImage.TryParse(data);
        if (pe != null && Py2exe(data, pe, name, location, limits, ct) is { } py2exe) return py2exe;
        if (Nuitka(read, data.Length, data, name, allFiles, limits, ct) is { } nuitka) return nuitka;
        if (data.AsSpan().IndexOf("cx_Freeze: "u8) >= 0) return CxFreeze(data, pe, name, location, limits, ct);
        if (data.AsSpan().IndexOf("nuitka_module_loader"u8) >= 0) return NuitkaStandalone(data, location);
        return null;
    }

    /// <summary>The same from a stream: PyInstaller and Nuitka onefile, whose archives travel in the executable.</summary>
    public static FrozenApp? Read(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(stream);
        if (PyInstallerArchive.Read(read, stream.Length, name, limits, ct) is { } pyinstaller) return pyinstaller;
        var head = read(0, (int)Math.Min(stream.Length, MarkerBytes))!;
        return Nuitka(read, stream.Length, head, name, allFiles, limits, ct);
    }

    public static ContainerContents? Open(byte[] data, string name, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(data, name, location, allFiles, limits, ct)?.ToContainer(allFiles, limits, ct);

    // ---- py2exe ----

    /// <summary>
    /// py2exe: the PYTHONSCRIPT resource (0x78563412, optimize, unbuffered, the code's length, the library zip's name, then
    /// a marshalled list of code objects: the boot scripts and the program's script last); the library zip is the one named,
    /// beside the executable, or appended to it when the name is empty.
    /// </summary>
    private static FrozenApp? Py2exe(byte[] data, PeImage pe, string name, string? location, AnalysisLimits limits, CancellationToken ct)
    {
        var read = InstallerPe.Of(data);
        if (InstallerPe.Resource(pe, data, read, "PYTHONSCRIPT", 1) is not var (offset, size) || size < 17 || offset + size > data.Length) return null;
        var script = data.AsSpan((int)offset, size);
        if (BinaryPrimitives.ReadUInt32LittleEndian(script) != 0x78563412) return null;
        int codeLength = BinaryPrimitives.ReadInt32LittleEndian(script[12..]);
        int nameEnd = script[16..].IndexOf((byte)0);
        if (nameEnd < 0 || codeLength < 0 || 16 + nameEnd + 1 + codeLength > script.Length) throw new ToolError(ErrorCode.MalformedInput, $"{name}: damaged py2exe PYTHONSCRIPT resource.");
        var zipName = Encoding.Latin1.GetString(script.Slice(16, nameEnd));
        var code = script.Slice(16 + nameEnd + 1, codeLength).ToArray();
        var app = new FrozenApp("py2exe", "py2exe executable");
        app.Notes.Add($"PYTHONSCRIPT resource: {codeLength:N0} bytes of code, optimize level {BinaryPrimitives.ReadInt32LittleEndian(script[4..])}.");

        // the library zip: appended to the executable, or the file named beside it
        byte[]? zip = null;
        string zipPath = zipName;
        if (zipName.Length == 0 || zipName.Equals(Path.GetFileName(location ?? name), StringComparison.OrdinalIgnoreCase))
        {
            zip = ZipAfter(data, pe.EndOfImage);
            zipPath = Path.GetFileName(name);
            if (zip == null) app.Notes.Add("No library zip after the image.");
        }
        else if (location != null && Directory.GetParent(Path.GetFullPath(location)) is { } dir && SafeFile(dir.FullName, zipName) is { } file && Bounded(file, limits) is { } beside)
            zip = beside;
        else app.Notes.Add($"The library zip {zipName} sits beside the executable{(location == null ? "; it is read when the executable is opened from its folder" : " and was not found")}.");
        byte[]? magic = zip != null ? Library(app, zip, zipPath + "_extracted/", limits, ct) : null;
        Beside(app, location);
        if (magic != null && PyVersion.FromMagic(magic) is { } v) Version(app, v, $".pyc magic {PyVersion.Magic(magic)}");

        // the scripts: the list's code objects, each saved as its own .pyc
        (int, int)[] versions = app.Version is { } known ? [known] : [.. Enumerable.Range(0, 15).Select(m => (3, 14 - m)), (2, 7)];
        foreach (var version in versions)
        {
            if (PyMarshal.TryRead(code, version, out _) is not PySequence { Items: var scripts } || scripts.Any(s => s is not PyCode)) continue;
            if (app.Version == null) Version(app, version, "PYTHONSCRIPT code layout");
            var pycMagic = magic ?? PyVersion.MagicOf(version)!;
            foreach (var (s, i) in scripts.Cast<PyCode>().Select((s, i) => (s, i)))
            {
                // "<bootstrap2>", "<boot hacks>": names py2exe gives its own code, made file names
                var stem = Regex.Replace(Path.GetFileNameWithoutExtension(s.Filename.Replace('\\', '/').Split('/')[^1]), "[^A-Za-z0-9_.-]+", "_").Trim('_');
                bool main = i == scripts.Length - 1;
                if (main) app.EntryScripts.Add(stem);
                var one = s;
                app.Entries.Insert(i, new FrozenEntry($"{(stem.Length > 0 ? stem : $"script_{i}")}.pyc", 0, main ? FrozenApp.Script : FrozenApp.Bootstrap,
                    () => PyVersion.WithHeader(pycMagic, version, PyMarshalWriter.Write(one, version))));
            }
            return app;
        }
        app.Notes.Add("The PYTHONSCRIPT code is no list of code objects of a known Python version.");
        return app;
    }

    // ---- cx_Freeze ----

    /// <summary>cx_Freeze: a launcher naming cx_Freeze, its modules in lib/library.zip (6+; lib/library.dat names it) or library.zip beside it, or a zip appended to it.</summary>
    private static FrozenApp CxFreeze(byte[] data, PeImage? pe, string name, string? location, AnalysisLimits limits, CancellationToken ct)
    {
        var app = new FrozenApp("cx_Freeze", "cx_Freeze executable");
        string? dir = location != null ? Path.GetDirectoryName(Path.GetFullPath(location)) : null;
        byte[]? magic = null;
        string? found = null;
        if (dir != null)
        {
            string? named = SafeFile(dir, "lib/library.dat") is { } dat && new FileInfo(dat).Length < 1024 ? File.ReadAllText(dat).Trim('\0', ' ', '\r', '\n') : null;
            foreach (var candidate in new[] { named != null ? "lib/" + named : null, "lib/library.zip", "library.zip", Path.GetFileNameWithoutExtension(location!) + ".zip" })
                if (candidate != null && SafeFile(dir, candidate) is { } file && Bounded(file, limits) is { } bytes)
                {
                    found = candidate;
                    magic = Library(app, bytes, candidate + "_extracted/", limits, ct);
                    break;
                }
        }
        if (found == null && ZipAfter(data, pe?.EndOfImage ?? data.Length) is { } appended)
        {
            found = Path.GetFileName(name);
            magic = Library(app, appended, found + "_extracted/", limits, ct);
        }
        if (found == null) app.Notes.Add($"The modules sit in lib/library.zip beside the launcher{(location == null ? "; it is read when the launcher is opened from its folder" : " and it was not found")}.");
        Beside(app, location);
        if (magic != null && PyVersion.FromMagic(magic) is { } v) Version(app, v, $".pyc magic {PyVersion.Magic(magic)}");
        // __main__<name>__ runs the program's script (one per executable: the launcher's own name first); __startup__ and __init__<name> start it
        var own = "__main__" + Regex.Replace(Path.GetFileNameWithoutExtension(location ?? name).ToLowerInvariant(), "[^a-z0-9]", "_");
        var top = (found ?? "") + "_extracted/";
        for (int i = 0; i < app.Entries.Count; i++)
        {
            var e = app.Entries[i];
            if (e.Role != FrozenApp.Module || !e.Path.StartsWith(top, StringComparison.Ordinal) || e.Path[top.Length..].Contains('/')) continue;
            var module = Path.GetFileNameWithoutExtension(e.Path);
            if (module.StartsWith("__main__", StringComparison.Ordinal) || module.EndsWith("__main__", StringComparison.Ordinal))
            {
                app.EntryScripts.Insert(module.TrimEnd('_') == own.TrimEnd('_') ? 0 : app.EntryScripts.Count, module);
                app.Entries[i] = e with { Role = FrozenApp.Script };
            }
            else if (module is "__startup__" or "BUILD_CONSTANTS" || module.StartsWith("__init__", StringComparison.Ordinal))
                app.Entries[i] = e with { Role = FrozenApp.Bootstrap };
        }
        return app;
    }

    // ---- Nuitka ----

    private static readonly byte[] Zstd = [0x28, 0xB5, 0x2F, 0xFD];

    /// <summary>Where a Nuitka onefile payload ("KA", then 'Y' for a Zstandard stream or 'X' for stored files) starts in <paramref name="data"/>, or -1.</summary>
    private static int NuitkaPayload(ReadOnlySpan<byte> data)
    {
        for (int from = 0; from < data.Length;)
        {
            int at = data[from..].IndexOf("KA"u8);
            if (at < 0) return -1;
            at += from;
            if (at + 3 + 4 <= data.Length && data[at + 2] == 'Y' && data.Slice(at + 3, 4).SequenceEqual(Zstd)) return at;
            from = at + 1;
        }
        return -1;
    }

    /// <summary>A Windows onefile keeps its payload in RCDATA resource 27.</summary>
    private static (long Offset, int Size)? NuitkaResource(ReadOnlySpan<byte> head) =>
        PeImage.TryParse(head) is { } pe && InstallerPe.Resource(pe, head, InstallerPe.Of(head.ToArray()), "#10", 27) is var (at, size)
        && at + 3 <= head.Length && head[(int)at] == 'K' && head[(int)at + 1] == 'A' ? (at, size) : null;

    private static FrozenApp? Nuitka(InstallerPe.Read read, long length, ReadOnlySpan<byte> data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        long start = NuitkaPayload(data);
        long end = length;
        if (NuitkaResource(data) is var (at, size)) (start, end) = (at, at + size);
        if (start < 0 || read(start + 2, 1) is not [var mode] || mode is not ((byte)'X' or (byte)'Y')) return null;
        var app = new FrozenApp("Nuitka", "Nuitka onefile executable") { Compiled = true };
        using var payload = new RangeStream(read, start + 3, end - start - 3);
        Stream files = mode == 'Y' ? new ZstdSharp.DecompressionStream(payload) : payload;
        app.Notes.Add($"Onefile payload at 0x{start:X} ({(mode == 'Y' ? "Zstandard" : "stored")}). The program's own modules are compiled to native code in the main binary: there is no bytecode to read.");
        try
        {
            using var buffered = new BufferedStream(files, 1 << 16);
            NuitkaFiles(app, buffered, allFiles, limits, ct);
        }
        catch (Exception ex) when (ex is ZstdSharp.ZstdException or IOException or InvalidDataException)
        {
            app.Notes.Add($"The payload ends early after {app.Entries.Count:N0} files ({ex.Message}).");
        }
        finally { files.Dispose(); }
        if (app.Version == null) app.Notes.Add("No Python version found in the payload.");
        return app;
    }

    /// <summary>
    /// Each payload file: its name (UTF-16 on Windows, else UTF-8, zero-terminated), on newer builds a flags byte, the size
    /// (8 bytes), on builds with checksums a CRC-32, then the data; an empty name ends the list. The layout is fixed from the
    /// first file, the main binary, whose data must start with an executable header.
    /// </summary>
    private static void NuitkaFiles(FrozenApp app, Stream s, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var probe = new byte[4096];
        int got = s.ReadAtLeast(probe, probe.Length, throwOnEndOfStream: false);
        var first = probe.AsSpan(0, got);
        (bool Wide, bool Flags, bool Crc)? layout = null;
        foreach (bool wide in new[] { false, true })
        {
            int nameEnd = wide ? WideEnd(first) : first.IndexOf((byte)0);
            if (nameEnd <= 0) continue;
            int after = nameEnd + (wide ? 2 : 1);
            foreach (var (flags, crc) in new[] { (true, false), (false, false), (false, true), (true, true) })
            {
                int data = after + (flags ? 1 : 0) + 8 + (crc ? 4 : 0);
                if (data + 4 <= first.Length && IsExecutable(first[data..])) { layout = (wide, flags, crc); break; }
            }
            if (layout != null) break;
        }
        if (layout is not var (isWide, hasFlags, hasCrc)) { app.Notes.Add("The payload's file list has an unknown layout."); return; }
        var input = new ConcatStream(probe.AsMemory(0, got), s);
        var versions = new Dictionary<(int, int), int>();
        long total = 0;
        for (int i = 0; i < limits.MaxItems; i++)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = isWide ? ReadWide(input) : ReadNarrow(input);
            if (fileName == null || fileName.Length == 0) return;
            if (hasFlags) Exactly(input, 1);
            long size = BinaryPrimitives.ReadInt64LittleEndian(Exactly(input, 8));
            if (hasCrc) Exactly(input, 4);
            if (size < 0) throw new IOException($"negative size for {fileName}");
            var path = fileName.Replace('\\', '/');
            var role = i == 0 ? "main binary (compiled program)" : FrozenApp.BinaryRole(path);
            if (PyVersion.FromLibraryName(path) is { } lib) Version(app, lib, Path.GetFileName(path), replace: true); // the runtime outranks the paths in the main binary
            // The dependencies view reads names and versions from the metadata and the runtime, so both are kept.
            bool metadata = FrozenApp.IsPackageMetadata(path) && size <= MaxMetadata || role == FrozenApp.Runtime;
            bool keep = size <= limits.MaxItemBytes && total + size <= limits.MaxTotalBytes && (i == 0 || allFiles || Containers.IsInteresting(path) || metadata);
            byte[]? bytes = keep ? UpTo(input, size) : null;
            if (!keep) Skip(input, size);
            if (i == 0 && bytes != null)
            {
                var text = Encoding.Latin1.GetString(bytes);
                foreach (Match m in PythonPath.Matches(text))
                    versions[(m.Groups[1].Value[0] - '0', int.Parse(m.Groups[2].Value))] = versions.GetValueOrDefault((m.Groups[1].Value[0] - '0', int.Parse(m.Groups[2].Value))) + 1;
                if (app.Version == null && versions.Count > 0) Version(app, versions.MaxBy(kv => kv.Value).Key, "the main binary's library paths");
                NuitkaModules(app, text);
                if (!(allFiles || Containers.IsInteresting(path))) bytes = null;
            }
            if (bytes != null) total += bytes.Length;
            var kept = bytes;
            app.Entries.Add(new FrozenEntry(path, size, role, kept == null ? null : () => kept));
        }
    }

    /// <summary>A distribution's metadata file is kept up to this size.</summary>
    private const int MaxMetadata = 1 << 20;

    // Nuitka's constants blob is a chain of sections, one per compiled module: its name, a zero byte, the data's
    // length (4 bytes, little-endian), then the data, which ends with '.' and holds the string "<module NAME>"; a
    // module-level "__version__ = '1.2'" keeps the value just before the name.
    private static readonly Regex NuitkaModule = new(@"u<module ([A-Za-z_][\w.]{0,200})>\x00", RegexOptions.CultureInvariant);
    private static readonly Regex NuitkaVersion = new(@"u(\d{1,9}(?:\.\d{1,9}){0,5}(?:[-_.]?(?:a|b|rc|c|post|dev)\d{0,9}){0,3}(?:\+[A-Za-z0-9.]{1,64})?)\x00a__version__\x00",
        RegexOptions.CultureInvariant);
    /// <summary>A section's header is looked for this many times, and this many bytes before the marker at most.</summary>
    private const int MaxSectionLookups = 64, MaxSectionBytes = 16 << 20;

    /// <summary>The modules a Nuitka binary's constants name, with the __version__ string in each one's own section.</summary>
    private static void NuitkaModules(FrozenApp app, string binary)
    {
        foreach (Match m in NuitkaModule.Matches(binary))
        {
            var name = m.Groups[1].Value;
            if (app.CompiledModules.Any(c => c.Module == name)) continue;
            string? version = null;
            if (NuitkaSection(binary, name, m.Index) is var (start, length))
                version = NuitkaVersion.Match(binary, start, length) is { Success: true } v ? v.Groups[1].Value : null;
            app.CompiledModules.Add((name, version));
        }
    }

    /// <summary>The data of the constants section named <paramref name="name"/> that holds <paramref name="marker"/>, or null.</summary>
    private static (int Start, int Length)? NuitkaSection(string binary, string name, int marker)
    {
        var key = name + "\0";
        int floor = Math.Max(0, marker - MaxSectionBytes);
        for (int at = marker, i = 0; i < MaxSectionLookups && at > floor; i++)
        {
            int header = binary.LastIndexOf(key, at - 1, at - floor, StringComparison.Ordinal);
            if (header < 0) return null;
            at = header;
            int data = header + key.Length + 4;
            if (header > 0 && binary[header - 1] is not ('\0' or '.') || data > binary.Length) continue;
            long length = binary[data - 4] | (long)binary[data - 3] << 8 | (long)binary[data - 2] << 16 | (long)binary[data - 1] << 24;
            if (length > 0 && data + length <= binary.Length && binary[data + (int)length - 1] == '.' && marker < data + length) return (data, (int)length);
        }
        return null;
    }

    private static readonly Regex PythonPath = new(@"python([23])\.(\d{1,2})(?=[/\\\x00])", RegexOptions.CultureInvariant);

    private static bool IsExecutable(ReadOnlySpan<byte> b) =>
        Blob.StartsWith(b, "MZ"u8) || Blob.StartsWith(b, [0x7F, (byte)'E', (byte)'L', (byte)'F']) || Blob.StartsWith(b, [0xCF, 0xFA, 0xED, 0xFE]) || Blob.StartsWith(b, [0xCA, 0xFE, 0xBA, 0xBE]);

    private static int WideEnd(ReadOnlySpan<byte> b)
    {
        for (int i = 0; i + 1 < b.Length; i += 2)
            if (b[i] == 0 && b[i + 1] == 0) return i;
        return -1;
    }

    private static string? ReadNarrow(Stream s)
    {
        var bytes = new List<byte>();
        for (int b; (b = s.ReadByte()) > 0;)
            if (bytes.Count < 4096) bytes.Add((byte)b);
            else throw new IOException("a file name runs past 4,096 bytes");
        return Encoding.UTF8.GetString([.. bytes]);
    }

    private static string? ReadWide(Stream s)
    {
        var sb = new StringBuilder();
        while (true)
        {
            int lo = s.ReadByte(), hi = s.ReadByte();
            if (lo < 0 || hi < 0) return null;
            if (lo == 0 && hi == 0) return sb.ToString();
            if (sb.Length >= 2048) throw new IOException("a file name runs past 2,048 characters");
            sb.Append((char)(lo | hi << 8));
        }
    }

    private static byte[] Exactly(Stream s, int n)
    {
        var b = new byte[n];
        s.ReadExactly(b);
        return b;
    }

    /// <summary>Exactly <paramref name="n"/> bytes, buffered as they arrive so a damaged size does not allocate up front.</summary>
    private static byte[] UpTo(Stream s, long n)
    {
        using var output = new MemoryStream();
        var buffer = new byte[1 << 16];
        while (output.Length < n)
        {
            int got = s.Read(buffer, 0, (int)Math.Min(buffer.Length, n - output.Length));
            if (got <= 0) throw new EndOfStreamException();
            output.Write(buffer, 0, got);
        }
        return output.ToArray();
    }

    private static void Skip(Stream s, long n)
    {
        var buffer = new byte[1 << 16];
        while (n > 0)
        {
            int got = s.Read(buffer, 0, (int)Math.Min(buffer.Length, n));
            if (got <= 0) throw new EndOfStreamException();
            n -= got;
        }
    }

    /// <summary>A Nuitka standalone program: compiled to native code, with its extension modules and data beside it.</summary>
    private static FrozenApp NuitkaStandalone(byte[] data, string? location)
    {
        var app = new FrozenApp("Nuitka", "Nuitka standalone executable") { Compiled = true };
        app.Notes.Add("Nuitka compiled the program's modules to native code in this executable: there is no bytecode to read; disassemble or decompile_native reads the code.");
        var versions = PythonPath.Matches(Encoding.Latin1.GetString(data)).GroupBy(m => (m.Groups[1].Value[0] - '0', int.Parse(m.Groups[2].Value))).MaxBy(g => g.Count());
        if (versions != null) Version(app, versions.Key, "the executable's library paths");
        NuitkaModules(app, Encoding.Latin1.GetString(data));
        Beside(app, location);
        return app;
    }

    // ---- shared ----

    /// <summary>
    /// A zip of .pyc modules on its own (a cx_Freeze or py2exe library, an embeddable distribution's pythonXY.zip), or null
    /// when fewer than half of its files are compiled modules.
    /// </summary>
    public static ContainerContents? OpenLibraryZip(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        ReadLibraryZip(data, limits, ct)?.ToContainer(allFiles, limits, ct);

    public static FrozenApp? ReadLibraryZip(byte[] data, AnalysisLimits limits, CancellationToken ct)
    {
        List<string> names;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read);
            names = [.. zip.Entries.Where(e => !e.FullName.EndsWith('/')).Select(e => e.FullName)];
        }
        catch (InvalidDataException) { return null; }
        int pyc = names.Count(n => FrozenApp.ModuleOf(n) != null);
        if (pyc == 0 || pyc * 2 < names.Count) return null;
        var app = new FrozenApp("Python library zip", "Python library zip");
        if (Library(app, data, "", limits, ct) is { } magic && PyVersion.FromMagic(magic) is { } v) Version(app, v, $".pyc magic {PyVersion.Magic(magic)}");
        foreach (var e in app.Entries.Where(e => Path.GetFileName(e.Path) is var f && (f.StartsWith("__main__", StringComparison.Ordinal) || f.EndsWith("__main__.pyc", StringComparison.Ordinal)) && !e.Path.Contains('/')))
            app.EntryScripts.Add(Path.GetFileNameWithoutExtension(e.Path));
        return app;
    }

    /// <summary>The files of a library zip as entries under <paramref name="prefix"/>; the first .pyc magic, or null.</summary>
    private static byte[]? Library(FrozenApp app, byte[] data, string prefix, AnalysisLimits limits, CancellationToken ct)
    {
        ZipArchive zip;
        // left open: the entries' loaders read from it
        try { zip = new ZipArchive(new MemoryStream(data, writable: false), ZipArchiveMode.Read); _ = zip.Entries; }
        catch (InvalidDataException ex) { app.Notes.Add($"{prefix.TrimEnd('/')}: unreadable library zip ({ex.Message})."); return null; }
        byte[]? magic = null;
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (e.FullName.EndsWith('/')) continue;
            var entry = e;
            byte[]? Load()
            {
                try
                {
                    using var s = entry.Open();
                    return Blob.ReadBounded(s, limits.MaxItemBytes);
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException) { return null; }
            }
            var module = FrozenApp.ModuleOf(e.FullName);
            if (module != null && magic == null && Load() is { Length: >= 4 } head && PyVersion.FromMagic(head) != null) magic = head[..4];
            var role = module is { Package: true } ? FrozenApp.Package : module != null ? FrozenApp.Module : FrozenApp.BinaryRole(e.FullName);
            app.Entries.Add(new FrozenEntry(prefix + e.FullName, e.Length, role, Load));
        }
        return magic;
    }

    /// <summary>A zip appended after <paramref name="end"/> (an image's end), or null.</summary>
    private static byte[]? ZipAfter(byte[] data, long end)
    {
        if (end <= 0 || end >= data.Length) return null;
        int at = data.AsSpan((int)end).IndexOf("PK\x03\x04"u8);
        if (at < 0) return null;
        var zip = data.AsSpan((int)end + at).ToArray();
        try
        {
            using var archive = new ZipArchive(new MemoryStream(zip, writable: false), ZipArchiveMode.Read);
            return archive.Entries.Count > 0 ? zip : null;
        }
        catch (InvalidDataException) { return null; }
    }

    /// <summary>
    /// The runtime library, native modules and distribution metadata beside the executable, and the .pyc modules under its
    /// lib folder, listed as files on disk (not extracted: they are already files).
    /// </summary>
    private static FrozenApp Beside(FrozenApp app, string? location)
    {
        if (location == null || Path.GetDirectoryName(Path.GetFullPath(location)) is not { } dir || !Directory.Exists(dir)) return app;
        var listed = app.Entries.Select(e => e.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        int scanned = 0;
        IEnumerable<string> Files(string folder, SearchOption option)
        {
            try { return Directory.EnumerateFiles(folder, "*", new EnumerationOptions { RecurseSubdirectories = option == SearchOption.AllDirectories, IgnoreInaccessible = true }); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
        }
        var lib = Path.Combine(dir, "lib");
        var internals = app.Freezer == "PyInstaller" ? Path.Combine(dir, "_internal") : null;
        var files = Files(dir, SearchOption.TopDirectoryOnly)
            .Concat(Directory.Exists(lib) ? Files(lib, SearchOption.AllDirectories) : [])
            .Concat(internals != null && Directory.Exists(internals) ? Files(internals, SearchOption.AllDirectories) : []);
        foreach (var file in files)
        {
            if (++scanned > MaxScanned) { app.Notes.Add($"Stopped listing the files beside the executable after {MaxScanned:N0}."); break; }
            var relative = Path.GetRelativePath(dir, file).Replace('\\', '/');
            if (listed.Contains(relative)) continue;
            var role = PyVersion.FromLibraryName(relative) != null ? FrozenApp.Runtime : FrozenApp.BinaryRole(relative) == FrozenApp.Native ? FrozenApp.Native
                : FrozenApp.ModuleOf(relative) is { } m && relative.StartsWith("lib/", StringComparison.Ordinal) ? m.Package ? FrozenApp.Package : FrozenApp.Module
                : FrozenApp.IsPackageMetadata(relative) ? FrozenApp.Data : null;
            if (role == null) continue;
            if (role == FrozenApp.Runtime && PyVersion.FromLibraryName(relative) is { } v) Version(app, v, relative.Split('/')[^1], replace: app.VersionSource is null or "PYTHONSCRIPT code layout");
            long size = 0;
            try { size = new FileInfo(file).Length; }
            catch (IOException) { }
            app.Entries.Add(new FrozenEntry(relative, size, role + " (beside the executable)"));
        }
        return app;
    }

    private static void Version(FrozenApp app, (int, int) version, string source, bool replace = false)
    {
        if (app.Version != null && !replace) return;
        app.Version = version;
        app.VersionSource = source;
    }

    /// <summary>A library zip beside the executable, or null when it is over the item limit.</summary>
    private static byte[]? Bounded(string file, AnalysisLimits limits) => new FileInfo(file).Length <= limits.MaxItemBytes ? File.ReadAllBytes(file) : null;

    /// <summary>A file under <paramref name="dir"/> named by the program (no rooted path, no "..")); null when absent.</summary>
    private static string? SafeFile(string dir, string relative)
    {
        if (Path.IsPathRooted(relative) || relative.Replace('\\', '/').Split('/').Contains("..")) return null;
        var full = Path.Combine(dir, relative);
        return File.Exists(full) ? full : null;
    }

    /// <summary>A forward-only stream over a range read through a <see cref="InstallerPe.Read"/>.</summary>
    private sealed class RangeStream(InstallerPe.Read read, long start, long length) : Stream
    {
        private long _at;
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = (int)Math.Min(count, length - _at);
            if (n <= 0) return 0;
            var b = read(start + _at, n) ?? throw new EndOfStreamException();
            b.CopyTo(buffer, offset);
            _at += n;
            return n;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _at; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Bytes already read, then the rest of a stream.</summary>
    private sealed class ConcatStream(ReadOnlyMemory<byte> first, Stream rest) : Stream
    {
        private ReadOnlyMemory<byte> _first = first;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_first.Length == 0) return rest.Read(buffer, offset, count);
            int n = Math.Min(count, _first.Length);
            _first[..n].CopyTo(buffer.AsMemory(offset));
            _first = _first[n..];
            return n;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
