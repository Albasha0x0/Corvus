using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Core.Archives;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Qt resource collections: binary .rcc files and the collections rcc compiles into a program.</summary>
public sealed class QtResourceTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static ContainerContents Open(byte[] bytes, string name = "app.rcc") => Containers.Open(bytes, name, AnalysisLimits.Default, default, allFiles: true);

    private static string Text(ContainerContents c, string path) => Encoding.UTF8.GetString(c.Items.Single(i => i.Name == path).Bytes);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void A_collection_lists_its_files_with_locales_and_times(int version)
    {
        var c = Open(QtResourceSamples.Rcc(QtResourceSamples.Sample, version));
        Assert.Equal(QtResources.Kind, c.Kind);
        Assert.Equal($"Qt resource collection, format version {version}: 6 file(s).", c.Notes[0]);
        Assert.Equal(
        [
            "app/data/table.json", "app/empty.txt", "app/icons/a.bin", "app/icons/small/b.txt", "app/readme (language 85, territory 84).txt", "app/readme.txt",
        ], c.Entries!.Select(e => e.Path).Order(StringComparer.Ordinal));
        Assert.Equal("bonjour", Text(c, "app/readme (language 85, territory 84).txt"));
        Assert.Equal(string.Concat(Enumerable.Repeat("hello resource\n", 200)), Text(c, "app/readme.txt"));
        Assert.Equal(256, c.Items.Single(i => i.Name == "app/icons/a.bin").Bytes.Length);
        Assert.Empty(c.Items.Single(i => i.Name == "app/empty.txt").Bytes);
        var readme = c.Entries!.Single(e => e.Path == "app/readme.txt");
        Assert.Equal(3000, readme.Size);
        Assert.Equal(version >= 2 ? "zlib, modified 2025-10-09 08:53:20 UTC" : "zlib", readme.Detail);
    }

    [Fact]
    public void Zstd_files_expand()
    {
        var c = Open(QtResourceSamples.Rcc(QtResourceSamples.Sample));
        Assert.Equal(string.Concat(Enumerable.Repeat("{\"k\":1}", 100)), Text(c, "app/data/table.json"));
        Assert.StartsWith("zstd", c.Entries!.Single(e => e.Path == "app/data/table.json").Detail);
    }

    /// <summary>
    /// A PE image holding three collections: the sample (version 2), a one-file version 1 one, and a one-file one no code
    /// loads; the code loads the first two as their qRegisterResourceData calls do.
    /// </summary>
    private static (byte[] Image, byte[] Arrays) Program()
    {
        var one = new[] { new QtResourceSamples.File("images/logo.png", [0x89, 0x50, 0x4E, 0x47, 1, 2, 3]) };
        var unloaded = new[] { new QtResourceSamples.File("unused/a.txt", [1, 2, 3, 4]) };
        var (arrays, at) = QtResourceSamples.Embed((QtResourceSamples.Sample, 2), (one, 1), (unloaded, 2));
        var pe = new PeBuilder();
        var rdata = pe.Add(".rdata", arrays, 0x40000040);
        // The qRegisterResourceData calls of the first two collections: lea rdx, [tree]; lea r8, [names]; lea r9, [data].
        pe.Add(".text", rva =>
        {
            var code = new List<byte>();
            foreach (var (data, names, tree) in at.Take(2))
                foreach (var (prefix, target) in new[] { ((byte[])[0x48, 0x8D, 0x15], tree), ([0x4C, 0x8D, 0x05], names), ([0x4C, 0x8D, 0x0D], data) })
                {
                    code.AddRange(prefix);
                    code.AddRange(BitConverter.GetBytes((int)(rdata.Rva + target - (rva + code.Count + 4))));
                }
            code.Add(0xC3);
            return [.. code];
        }, 0x60000020);
        return (pe.Build(), arrays);
    }

    [Fact]
    public void Collections_compiled_into_an_image_are_found_by_their_structure()
    {
        var (image, arrays) = Program();
        var c = Open(image, "app.exe");
        Assert.True(c.Kind == QtResources.Kind, string.Join("; ", c.Notes));
        Assert.StartsWith("2 Qt resource collection(s) compiled into the image", c.Notes[0]);
        Assert.EndsWith(": 7 file(s).", c.Notes[0]);
        Assert.Equal([0x89, 0x50, 0x4E, 0x47, 1, 2, 3], c.Items.Single(i => i.Name == "images/logo.png").Bytes);
        Assert.Equal("small", Text(c, "app/icons/small/b.txt"));
        // A one-file collection no code loads could be a file's own size field; it is not taken.
        Assert.DoesNotContain(c.Entries!, e => e.Path == "unused/a.txt");

        var noise = new byte[1 << 20];
        new Random(3).NextBytes(noise);
        Assert.Empty(QtResources.Embedded(noise, default));
        Assert.Equal(3, QtResources.Embedded(arrays, default).Count);
    }

    [Fact]
    public void A_damaged_collection_keeps_its_readable_files_and_notes_the_rest()
    {
        var bytes = QtResourceSamples.Rcc(QtResourceSamples.Sample);
        var header = QtResources.Header(bytes, "x");
        // The first name's hash no longer matches its text.
        bytes[header.Names + 2] ^= 0xFF;
        var c = Open(bytes);
        Assert.Contains("tree node 1: its name fails Qt's hash; skipped", c.Notes);
        Assert.Empty(c.Entries!);

        var broken = QtResourceSamples.Rcc(QtResourceSamples.Sample);
        var e = QtResources.Entries(broken, QtResources.Header(broken, "x"), [], default).Single(e => e.Path == "app/readme.txt" && e.IsDefaultLocale);
        // The zlib stream of readme.txt is cut to its first bytes.
        broken.AsSpan(e.DataAt + 10, (int)e.Stored - 10).Clear();
        var damaged = Open(broken);
        Assert.Contains(damaged.Notes, n => n.Contains("app/readme.txt does not expand as zlib"));
        Assert.Equal(5, damaged.Items.Count);

        var truncated = QtResourceSamples.Rcc(QtResourceSamples.Sample)[..30];
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Open(truncated)).Code);
    }

    [Fact]
    [FuzzEntry(typeof(QtResources), typeof(QtResourceReader))]
    public void Fuzzed_collections_never_throw()
    {
        foreach (var sample in new[] { QtResourceSamples.Rcc(QtResourceSamples.Sample, 1), QtResourceSamples.Rcc(QtResourceSamples.Sample) })
        {
            var failures = FormatFuzz.Run(sample, b =>
            {
                try { new QtResourceReader().Open(b, "fuzz.rcc", true, new AnalysisLimits { MaxItemBytes = 1 << 20 }, default); }
                catch (ToolError e) when (e.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { }
                QtResources.Embedded(b, default);
            }, 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    [Fact]
    [FuzzEntry(typeof(CodeReferences))]
    public void Fuzzed_program_images_never_throw()
    {
        var failures = FormatFuzz.Run(Program().Image, b => QtResources.Embedded(b, default), 100);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>
    /// What Qt (CORVUS_QT_PYTHON, a Python with PySide6) reads: each .rcc registered with QResource::registerResource, or
    /// the collections of the PySide6 modules it loads; every file QDirIterator lists under ":/", and each queried path
    /// in its locale with its SHA-256, modification time and storage.
    /// </summary>
    private JsonElement Qt(IEnumerable<string> rcc, IEnumerable<(string Path, int Language, int Territory)> queries, bool modules = false)
    {
        var script = _dir.File("oracle.py");
        File.WriteAllText(script, """
            import sys, json, hashlib, ctypes, ctypes.wintypes as w
            from PySide6.QtCore import QResource, QDirIterator, QLocale
            req = json.load(sys.stdin)
            if req["modules"]:
                import PySide6.QtGui, PySide6.QtWidgets, PySide6.QtNetwork, PySide6.QtSvg
            def listed():
                it = QDirIterator(":/", QDirIterator.Subdirectories)
                found = set()
                while it.hasNext():
                    p = it.next()
                    if it.fileInfo().isFile(): found.add(p[2:])
                return found
            # Qt's own collections are listed before any file is registered.
            before = listed() if req["rcc"] else set()
            for f in req["rcc"]:
                assert QResource.registerResource(f), f
            files = sorted(listed() - before)
            out = []
            for q in req["queries"]:
                loc = QLocale.c() if q[1] in (0, 1) and q[2] == 0 else QLocale(QLocale.Language(q[1]), QLocale.Country(q[2]))
                r = QResource(":/" + q[0], loc)
                d = bytes(r.uncompressedData()) if r.isValid() else None
                m = r.lastModified()
                out.append([hashlib.sha256(d).hexdigest() if d is not None else None, m.toMSecsSinceEpoch() if m.isValid() else 0, r.compressionAlgorithm().name])
            mods = []
            if req["modules"]:
                k = ctypes.WinDLL("kernel32"); h = (w.HMODULE * 4096)(); n = w.DWORD()
                k.GetCurrentProcess.restype = w.HANDLE
                k.K32EnumProcessModules.argtypes = [w.HANDLE, ctypes.POINTER(w.HMODULE), w.DWORD, ctypes.POINTER(w.DWORD)]
                k.GetModuleFileNameW.argtypes = [w.HMODULE, w.LPWSTR, w.DWORD]
                assert k.K32EnumProcessModules(k.GetCurrentProcess(), h, ctypes.sizeof(h), ctypes.byref(n))
                for i in range(n.value // ctypes.sizeof(w.HMODULE)):
                    b = ctypes.create_unicode_buffer(1024); k.GetModuleFileNameW(h[i], b, 1024); mods.append(b.value)
            json.dump({"files": files, "data": out, "modules": mods}, sys.stdout)
            """);
        var psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("CORVUS_QT_PYTHON")!) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add("-I");
        psi.ArgumentList.Add(script);
        psi.Environment["QT_QPA_PLATFORM"] = "offscreen";
        using var p = Process.Start(psi)!;
        p.StandardInput.Write(JsonSerializer.Serialize(new { rcc, queries = queries.Select(q => new object[] { q.Path, q.Language, q.Territory }), modules }));
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        Assert.True(p.WaitForExit(300_000), "the Qt reader did not exit");
        Assert.True(p.ExitCode == 0, stderr.Result);
        return JsonDocument.Parse(stdout.Result).RootElement;
    }

    /// <summary>Compares the files read here with what Qt reads: the listed paths, then content, time and storage per file and locale.</summary>
    private int Compare(List<(QtResources.Entry Entry, byte[] Content)> ours, JsonElement qt, List<string> mismatches, string label, string? skip = null)
    {
        var listed = qt.GetProperty("files").EnumerateArray().Select(f => f.GetString()!).Where(f => f != skip).ToHashSet(StringComparer.Ordinal);
        var paths = ours.Select(o => o.Entry.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var missing in listed.Except(paths).Take(10)) mismatches.Add($"{label}: Qt lists {missing}, not read here");
        foreach (var extra in paths.Except(listed).Take(10)) mismatches.Add($"{label}: {extra} read here, not listed by Qt");
        var data = qt.GetProperty("data").EnumerateArray().ToList();
        for (int i = 0; i < ours.Count; i++)
        {
            var (e, content) = ours[i];
            var row = data[i];
            string algorithm = e.Compression switch { "zlib" => "ZlibCompression", "zstd" => "ZstdCompression", _ => "NoCompression" };
            var mine = (Convert.ToHexStringLower(SHA256.HashData(content)), e.Modified is { } m ? (long)(m - DateTime.UnixEpoch).TotalMilliseconds : 0L, algorithm);
            var theirs = (row[0].GetString(), row[1].GetInt64(), row[2].GetString());
            if (mine != theirs) mismatches.Add($"{label}: {QtResources.ItemPath(e)}: {mine} here, {theirs} in Qt");
        }
        return ours.Count;
    }

    private static List<(QtResources.Entry, byte[])> Read(byte[] bytes, IEnumerable<QtResources.Collection> collections, List<string> notes)
    {
        var all = new List<(QtResources.Entry, byte[])>();
        var seen = new HashSet<(string, int, int)>();
        foreach (var c in collections)
            foreach (var e in QtResources.Entries(bytes, c, notes, default))
                if (seen.Add((e.Path, e.Language, e.Territory))) all.Add((e, QtResources.Content(bytes, e, AnalysisLimits.Default.MaxItemBytes, "x")));
        return all;
    }

    private void Check(string path, List<string> mismatches, ref int compared)
    {
        var bytes = File.ReadAllBytes(path);
        var notes = new List<string>();
        var ours = Read(bytes, [QtResources.Header(bytes, path)], notes);
        mismatches.AddRange(notes.Select(n => $"{Path.GetFileName(path)}: {n}"));
        compared += Compare(ours, Qt([path], ours.Select(o => (o.Item1.Path, o.Item1.Language, o.Item1.Territory))), mismatches, Path.GetFileName(path));
    }

    // Collections built here without zstd (the PySide6 build reads zlib only) and the same tree built by Qt's rcc
    // (PySide6/rcc) in every format version, compressed and not.
    [RequiresRealDataFact("CORVUS_QT_PYTHON")]
    [Trait("Speed", "Slow")]
    public void Collections_read_as_qt_reads_them()
    {
        var files = QtResourceSamples.Sample.Where(f => f.Compression != "zstd").ToList();
        var mismatches = new List<string>();
        int compared = 0;
        foreach (int version in (int[])[1, 2, 3])
        {
            var built = _dir.File($"built{version}.rcc");
            File.WriteAllBytes(built, QtResourceSamples.Rcc(files, version));
            Check(built, mismatches, ref compared);
        }
        var src = Path.Combine(_dir.Path, "src");
        Directory.CreateDirectory(Path.Combine(src, "icons", "small"));
        File.WriteAllText(Path.Combine(src, "readme.txt"), string.Concat(Enumerable.Repeat("hello resource\n", 200)));
        File.WriteAllBytes(Path.Combine(src, "icons", "a.bin"), [.. Enumerable.Range(0, 256).Select(i => (byte)i)]);
        File.WriteAllText(Path.Combine(src, "icons", "small", "b.txt"), "small");
        File.WriteAllText(Path.Combine(src, "fr.txt"), "bonjour");
        File.WriteAllText(Path.Combine(src, "empty.txt"), "");
        File.WriteAllText(Path.Combine(src, "app.qrc"), """
            <RCC>
              <qresource prefix="/app"><file>readme.txt</file><file>icons/a.bin</file><file alias="b.txt">icons/small/b.txt</file><file>empty.txt</file></qresource>
              <qresource prefix="/app" lang="fr_FR"><file alias="readme.txt">fr.txt</file></qresource>
            </RCC>
            """);
        var rcc = Path.Combine(Path.GetDirectoryName(Environment.GetEnvironmentVariable("CORVUS_QT_PYTHON")!)!, "..", "Lib", "site-packages", "PySide6", "rcc.exe");
        foreach (var (version, options) in new[] { (1, ""), (2, ""), (3, ""), (3, "--no-compress") })
        {
            var outPath = _dir.File($"rcc{version}{options}.rcc");
            var psi = new ProcessStartInfo(rcc) { WorkingDirectory = src, UseShellExecute = false, RedirectStandardError = true };
            foreach (var a in new[] { "--binary", "--format-version", version.ToString(), "app.qrc", "-o", outPath }.Concat(options.Length > 0 ? [options] : []))
                psi.ArgumentList.Add(a);
            using (var p = Process.Start(psi)!) { p.WaitForExit(60_000); Assert.True(p.ExitCode == 0, p.StandardError.ReadToEnd()); }
            Check(outPath, mismatches, ref compared);
        }
        output.WriteLine($"{compared} files compared");
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches.Take(40)));
    }

    // The PySide6 modules (Qt 6 DLLs and Python extension modules) Qt has loaded register their compiled-in
    // collections; those found here in the same files must be the ones Qt lists.
    [RequiresRealDataFact("CORVUS_QT_PYTHON")]
    [Trait("Speed", "Slow")]
    public void Collections_compiled_into_qt_modules_read_as_qt_registers_them()
    {
        var loaded = Qt([], [], modules: true);
        var modules = loaded.GetProperty("modules").EnumerateArray().Select(m => m.GetString()!)
            .Where(m => m.Contains(Path.DirectorySeparatorChar + "PySide6" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || m.Contains(Path.DirectorySeparatorChar + "shiboken6" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)).ToList();
        var ours = new List<(QtResources.Entry, byte[])>();
        var notes = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var module in modules)
        {
            var bytes = File.ReadAllBytes(module);
            var found = QtResources.Embedded(bytes, default);
            if (found.Count > 0) output.WriteLine($"{Path.GetFileName(module)}: {found.Count} collection(s)");
            foreach (var r in Read(bytes, found, notes))
                if (seen.Add(r.Item1.Path)) ours.Add(r);
        }
        // PySide6 registers qt/etc/qt.conf at run time with its install prefix; the module holds only a template.
        const string runTime = "qt/etc/qt.conf";
        ours.RemoveAll(o => o.Item1.Path == runTime);
        var mismatches = notes.ToList();
        int compared = Compare(ours, Qt([], ours.Select(o => (o.Item1.Path, o.Item1.Language, o.Item1.Territory)), modules: true), mismatches, "modules", runTime);
        output.WriteLine($"{modules.Count} modules, {compared} files compared");
        Assert.True(compared > 100, $"only {compared} files found");
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches.Take(40)));
    }

    // CORVUS_QT_RESOURCES: .rcc files compared with Qt (CORVUS_QT_PYTHON), and program images (any other file) whose
    // compiled-in collections must be found and expand without a note.
    [RequiresRealDataFact("CORVUS_QT_RESOURCES", "CORVUS_QT_PYTHON")]
    [Trait("Speed", "Slow")]
    public void Real_collections_read_as_qt_reads_them()
    {
        var mismatches = new List<string>();
        int compared = 0, images = 0;
        foreach (var path in Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_QT_RESOURCES")!, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (path.EndsWith(".rcc", StringComparison.OrdinalIgnoreCase)) { Check(path, mismatches, ref compared); continue; }
            var bytes = File.ReadAllBytes(path);
            var clock = Stopwatch.StartNew();
            var found = QtResources.Embedded(bytes, default);
            var notes = new List<string>();
            var files = found.Count > 0 ? Read(bytes, found, notes) : [];
            output.WriteLine($"{Path.GetFileName(path)}: {found.Count} collection(s), {files.Count} file(s), {clock.Elapsed.TotalSeconds:0.00} s: " +
                string.Join(", ", files.Take(4).Select(f => $"{f.Item1.Path} ({f.Item2.Length:N0} bytes)")));
            if (found.Count == 0) mismatches.Add($"{Path.GetFileName(path)}: no collection found");
            mismatches.AddRange(notes.Select(n => $"{Path.GetFileName(path)}: {n}"));
            images++;
        }
        output.WriteLine($"{compared} .rcc files compared, {images} images read");
        Assert.True(compared + images > 0, "nothing read");
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches.Take(40)));
    }
}
