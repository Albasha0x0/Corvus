using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Python;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;

namespace Corvus.Tests;

/// <summary>Frozen Python programs built at test time for each freezer: PyInstaller, py2exe, cx_Freeze, Nuitka, and their archives.</summary>
public sealed class FrozenPythonTests : IDisposable
{
    private static readonly (int, int) V312 = (3, 12);
    private static readonly byte[] Magic312 = PyVersion.MagicOf(V312)!;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A module code object of Python 3.12, marshalled (no .pyc header).</summary>
    internal static byte[] Code(string filename, params object[] consts) => PyMarshalWriter.Write(new PyCode
    {
        Code = [0x97, 0x00, 0x79, 0x00], Consts = [.. consts, PySingleton.None], Filename = filename, Name = "<module>", QualName = "<module>", FirstLineNo = 1,
    }, V312);

    private static byte[] Zlib(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return ms.ToArray();
    }

    /// <summary>A PYZ archive: header, the entries (zlib, then AES-CTR with a 16-byte IV when <paramref name="key"/> is set), then the marshalled table of contents.</summary>
    internal static byte[] Pyz(string? key, params (string Name, int Type, byte[] Code)[] modules)
    {
        using var ms = new MemoryStream();
        ms.Write("PYZ\0"u8);
        ms.Write(Magic312);
        // Table of contents offset, patched below; padding.
        ms.Write(new byte[8]);
        var toc = new List<object>();
        foreach (var (name, type, code) in modules)
        {
            var stored = Zlib(code);
            if (key != null)
            {
                using var aes = Aes.Create();
                aes.Key = Encoding.UTF8.GetBytes(key);
                var iv = RandomNumberGenerator.GetBytes(16);
                stored = [.. iv, .. PyInstallerArchive.Ctr(aes, iv, stored)];
            }
            toc.Add(new PySequence('(', [name, new PySequence('(', [(long)type, ms.Length, (long)stored.Length])]));
            ms.Write(stored);
        }
        long tocAt = ms.Length;
        ms.Write(PyMarshalWriter.Write(new PySequence('[', [.. toc]), V312));
        var bytes = ms.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), (uint)tocAt);
        return bytes;
    }

    /// <summary>A CArchive: the entries' data, the table of contents, then the 2.1+ cookie naming Python 3.12.</summary>
    internal static byte[] CArchive(params (string Name, char Type, byte[] Data, bool Compress)[] entries)
    {
        using var ms = new MemoryStream();
        using var toc = new MemoryStream();
        foreach (var (name, type, data, compress) in entries)
        {
            var stored = compress ? Zlib(data) : data;
            var nameBytes = Encoding.UTF8.GetBytes(name + "\0");
            int size = 18 + nameBytes.Length;
            var row = new byte[size];
            BinaryPrimitives.WriteInt32BigEndian(row, size);
            BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(4), (uint)ms.Length);
            BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(8), (uint)stored.Length);
            BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(12), (uint)data.Length);
            row[16] = (byte)(compress ? 1 : 0);
            row[17] = (byte)type;
            nameBytes.CopyTo(row, 18);
            toc.Write(row);
            ms.Write(stored);
        }
        long tocAt = ms.Length;
        ms.Write(toc.ToArray());
        var cookie = new byte[88];
        "MEI\x0c\x0b\x0a\x0b\x0e"u8.CopyTo(cookie);
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(8), (uint)(ms.Length + 88));
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(12), (uint)tocAt);
        BinaryPrimitives.WriteInt32BigEndian(cookie.AsSpan(16), (int)toc.Length);
        BinaryPrimitives.WriteInt32BigEndian(cookie.AsSpan(20), 312);
        "python312.dll"u8.CopyTo(cookie.AsSpan(24));
        ms.Write(cookie);
        return ms.ToArray();
    }

    /// <summary>A native launcher: a PE whose data section holds <paramref name="marker"/>, followed by <paramref name="overlay"/>.</summary>
    internal static byte[] Launcher(string marker, byte[] overlay)
    {
        var pe = new PeBuilder();
        pe.Add(".text", [0xC3], 0x60000020);
        pe.Add(".rdata", Encoding.ASCII.GetBytes(marker + "\0"));
        pe.Overlay = overlay;
        return pe.Build();
    }

    internal static byte[] PyInstallerSample(string? key = null)
    {
        var modules = new List<(string, char, byte[], bool)>
        {
            ("pyimod01_archive", 'm', Code("pyimod01_archive.py"), true),
            ("pyiboot01_bootstrap", 's', Code("pyiboot01_bootstrap.py"), true),
            ("app", 's', Code("app.py", "hello"), true),
            ("python312.dll", 'b', [(byte)'M', (byte)'Z', 0, 0], true),
            ("_ssl.pyd", 'b', [(byte)'M', (byte)'Z', 1, 1], false),
            ("certifi\\cacert.pem", 'x', "-----BEGIN CERTIFICATE-----"u8.ToArray(), true),
            ("pyi-contents-directory _internal", 'o', [], false),
            ("PYZ-00.pyz", 'z', Pyz(key, ("json", 1, Code("json/__init__.py")), ("json.decoder", 0, Code("json/decoder.py", 42L))), false),
        };
        if (key != null) modules.Insert(0, ("pyimod00_crypto_key", 'm', Code("pyimod00_crypto_key.py", key), true));
        return Launcher("_MEIPASS", CArchive([.. modules]));
    }

    private static string Roles(ContainerContents c) => string.Join("; ", c.Entries!.Select(e => $"{e.Path}={e.Detail}"));

    [Fact]
    public void A_PyInstaller_program_lists_every_file_with_its_role_and_rebuilds_the_pyc_headers()
    {
        var c = Containers.Open(PyInstallerSample(), "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(PyInstallerArchive.Kind, c.Kind);
        Assert.StartsWith("PyInstaller: Python 3.12 (python312.dll); entry app;", c.Notes[0]);
        Assert.Equal("pyimod01_archive.pyc=bootstrap script; pyiboot01_bootstrap.pyc=bootstrap script; app.pyc=entry script; python312.dll=Python runtime; " +
            "_ssl.pyd=native module; certifi/cacert.pem=data; pyi-contents-directory _internal=runtime option; PYZ-00.pyz=module archive; " +
            "PYZ-00.pyz_extracted/json/__init__.pyc=package; PYZ-00.pyz_extracted/json/decoder.pyc=module", Roles(c));
        var app = c.Items.Single(i => i.Name == "app.pyc").Bytes;
        Assert.Equal([.. Magic312, .. new byte[12], .. Code("app.py", "hello")], app);
        var decoder = c.Items.Single(i => i.Name == "PYZ-00.pyz_extracted/json/decoder.pyc").Bytes;
        Assert.True(PyVersion.LooksLikePyc(decoder));
        Assert.Equal(Code("json/decoder.py", 42L), decoder[16..]);
        // The runtime travels in the archive: onefile.
        Assert.DoesNotContain(c.Notes, n => n.StartsWith("One-folder", StringComparison.Ordinal));
    }

    [Fact]
    public void A_PyInstaller_build_made_with_a_key_is_decrypted_with_the_key_it_carries()
    {
        var c = Containers.Open(PyInstallerSample(key: "0123456789abcdef"), "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(c.Notes, n => n.Contains("key '0123456789abcdef'", StringComparison.Ordinal));
        Assert.Equal("encrypted module", c.Entries!.Single(e => e.Path.EndsWith("decoder.pyc", StringComparison.Ordinal)).Detail);
        Assert.Equal(Code("json/decoder.py", 42L), c.Items.Single(i => i.Name.EndsWith("decoder.pyc", StringComparison.Ordinal)).Bytes[16..]);
    }

    [Fact]
    public void The_stream_path_reads_the_same_program()
    {
        var bytes = PyInstallerSample();
        // The head: headers and sections, not the archive.
        var reader = Containers.ReaderFor(bytes.AsSpan(0, 0x800), "app.exe");
        Assert.IsType<FrozenPythonReader>(reader);
        var streamed = reader!.Open(new MemoryStream(bytes), "app.exe", allFiles: false, AnalysisLimits.Default, default)!;
        Assert.Equal(Roles(Containers.Open(bytes, "app.exe", AnalysisLimits.Default, default)), Roles(streamed));
    }

    [Fact]
    public void A_launcher_without_its_archive_says_so()
    {
        var c = Containers.Open(Launcher("_MEIPASS", []), "app.exe", AnalysisLimits.Default, default);
        Assert.Equal("none", c.Kind);
        Assert.Contains("without its archive", c.Notes[0]);
    }

    [Fact]
    public void A_PYZ_archive_and_a_library_zip_open_on_their_own()
    {
        var pyz = Containers.Open(Pyz(null, ("os", 0, Code("os.py"))), "PYZ-00.pyz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("PyInstaller PYZ archive", pyz.Kind);
        Assert.Equal("os.pyc=module", Roles(pyz));
        var zip = Containers.Open(ContainerFixtures.Zip(("os.pyc", PyVersion.WithHeader(Magic312, V312, Code("os.py"))), ("pkg/__init__.pyc", PyVersion.WithHeader(Magic312, V312, Code("pkg/__init__.py"))),
            ("pkg/data.txt", "x"u8.ToArray())), "python312.zip", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Python library zip", zip.Kind);
        Assert.StartsWith("Python library zip: Python 3.12 (.pyc magic 3531)", zip.Notes[0]);
        Assert.Equal("os.pyc=module; pkg/__init__.pyc=package; pkg/data.txt=data", Roles(zip));
        Assert.Equal(3, zip.Items.Count);
    }

    [Fact]
    public void A_zipapp_names_its_interpreter_entry_module_and_bundled_packages()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "import pkg\n"u8.ToArray()), ("pkg/__init__.py", "x = 1\n"u8.ToArray()), ("pkg/data.txt", "x"u8.ToArray()));
        var app = Containers.Open([.. "#!/usr/bin/env python3.11\n"u8.ToArray(), .. zip], "tool.pyz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Python zipapp", app.Kind);
        Assert.StartsWith("Python zipapp: Python 3.11 (the interpreter line); entry __main__", app.Notes[0]);
        Assert.Equal("__main__.py=entry script; pkg/__init__.py=package; pkg/data.txt=data", Roles(app));
    }

    [Fact]
    public void A_shiv_zipapp_reports_the_entry_point_its_environment_file_names()
    {
        var env = Encoding.UTF8.GetBytes("{\"entry_point\":\"tool.cli:main\",\"root\":\"~/.shiv\"}");
        var app = Containers.Open(ContainerFixtures.Zip(("__main__.py", "pass\n"u8.ToArray()), ("environment.json", env)), "tool.pyz", AnalysisLimits.Default, default);
        Assert.Contains("Built by shiv; entry point tool.cli:main.", app.Notes);
    }

    [Fact]
    public void A_zipapp_of_compiled_modules_is_a_zipapp_not_a_library_zip()
    {
        var zip = ContainerFixtures.Zip(("__main__.pyc", PyVersion.WithHeader(Magic312, V312, Code("__main__.py"))), ("pkg/__init__.pyc", PyVersion.WithHeader(Magic312, V312, Code("pkg/__init__.py"))));
        var app = Containers.Open(zip, "tool.pyz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Python zipapp", app.Kind);
        Assert.Equal("__main__.pyc=entry script; pkg/__init__.pyc=package", Roles(app));
    }

    [Fact]
    public void A_shebang_zipapp_loads_entries_with_relative_and_absolute_offsets()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "import pkg\n"u8.ToArray()), ("pkg/__init__.py", "x = 1\n"u8.ToArray()));
        byte[] line = "#!/usr/bin/env python3.11\n"u8.ToArray();
        var relative = Containers.Open([.. line, .. zip], "a.pyz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("x = 1\n", Encoding.ASCII.GetString(relative.Items.Single(i => i.Name == "pkg/__init__.py").Bytes));
        // Absolute offsets: the central directory is shifted by the line length.
        var shifted = ShiftOffsets([.. line, .. zip], line.Length);
        var absolute = Containers.Open(shifted, "b.pyz", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("x = 1\n", Encoding.ASCII.GetString(absolute.Items.Single(i => i.Name == "pkg/__init__.py").Bytes));
    }

    /// <summary>Adds <paramref name="by"/> to every local header offset in the central directory and to the directory offset.</summary>
    private static byte[] ShiftOffsets(byte[] data, int by)
    {
        var d = (byte[])data.Clone();
        int eocd = d.AsSpan().LastIndexOf("PK"u8);
        int dir = BitConverter.ToInt32(d, eocd + 16);
        BitConverter.GetBytes(dir + by).CopyTo(d, eocd + 16);
        int count = BitConverter.ToUInt16(d, eocd + 10);
        int p = dir + by;
        for (int i = 0; i < count; i++)
        {
            BitConverter.GetBytes(BitConverter.ToInt32(d, p + 42) + by).CopyTo(d, p + 42);
            p += 46 + BitConverter.ToUInt16(d, p + 28) + BitConverter.ToUInt16(d, p + 30) + BitConverter.ToUInt16(d, p + 32);
        }
        return d;
    }

    [Fact]
    public void A_pex_zipapp_reports_its_entry_point_and_distribution_count()
    {
        var info = Encoding.UTF8.GetBytes("{\"entry_point\":\"tool:main\",\"distributions\":{\"a-1.whl\":\"x\",\"b-2.whl\":\"y\"}}");
        var app = Containers.Open(ContainerFixtures.Zip(("__main__.py", "pass\n"u8.ToArray()), ("PEX-INFO", info)), "tool.pex", AnalysisLimits.Default, default);
        Assert.Contains("Built by pex; entry point tool:main; 2 bundled distributions.", app.Notes);
    }

    [Fact]
    public void A_malformed_environment_file_is_named_as_invalid_JSON()
    {
        var app = Containers.Open(ContainerFixtures.Zip(("__main__.py", "pass\n"u8.ToArray()), ("environment.json", "{"u8.ToArray())), "tool.pyz", AnalysisLimits.Default, default);
        Assert.Contains("shiv: the metadata file is not valid JSON.", app.Notes);
    }

    [Fact]
    public void An_interpreter_line_without_a_minor_version_gives_no_version()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "pass\n"u8.ToArray()));
        var app = Containers.Open([.. "#!/usr/bin/python3\n"u8.ToArray(), .. zip], "a.pyz", AnalysisLimits.Default, default);
        Assert.Equal("Python zipapp", app.Kind);
        Assert.DoesNotContain("Python 3", app.Notes[0]);
    }

    [Fact]
    public void A_shebang_file_without_an_archive_after_it_is_no_zipapp()
    {
        var app = Containers.Open("#!/usr/bin/env python3\nprint(1)\n"u8.ToArray(), "a.pyz", AnalysisLimits.Default, default);
        Assert.NotEqual("Python zipapp", app.Kind);
    }

    [Fact]
    public void A_zip_without_a_root_main_is_no_zipapp()
    {
        var zip = ContainerFixtures.Zip(("pkg/__main__.py", "pass\n"u8.ToArray()));
        Assert.NotEqual("Python zipapp", Containers.Open(zip, "a.zip", AnalysisLimits.Default, default).Kind);
    }

    [Fact]
    public void A_py2exe_program_saves_each_script_as_a_pyc_and_reads_the_library_zip_it_carries()
    {
        var scripts = PyMarshalWriter.Write(new PySequence('[', [
            PyMarshal.Read(Code("<bootstrap2>"), V312), PyMarshal.Read(Code("boot_common.py"), V312), PyMarshal.Read(Code("C:\\src\\app.py", "main"), V312)]), V312);
        var resource = new MemoryStream();
        var w = new BinaryWriter(resource);
        w.Write(0x78563412);
        w.Write(2); // optimize
        w.Write(0);
        w.Write(scripts.Length);
        w.Write((byte)0); // no zip name: the library zip is appended to the executable
        w.Write(scripts);
        var zip = ContainerFixtures.Zip(("app_helpers.pyc", PyVersion.WithHeader(Magic312, V312, Code("app_helpers.py"))));
        var exe = InstallerStubTests.Stub("PYTHONSCRIPT", 1, resource.ToArray(), zip);
        var c = Containers.Open(exe, "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("py2exe executable", c.Kind);
        Assert.StartsWith("py2exe: Python 3.12 (.pyc magic 3531); entry app;", c.Notes[0]);
        Assert.Equal("bootstrap2.pyc=bootstrap script; boot_common.pyc=bootstrap script; app.pyc=entry script; app.exe_extracted/app_helpers.pyc=module", Roles(c));
        var app = c.Items.Single(i => i.Name == "app.pyc").Bytes;
        Assert.Equal(Magic312, app[..4]);
        Assert.Equal("main", Assert.IsType<PyCode>(PyMarshal.Read(app, V312, 16)).Consts[0]);
    }

    [Fact]
    public void A_cx_Freeze_program_reads_lib_library_zip_and_the_files_beside_the_launcher()
    {
        var dir = Directory.CreateDirectory(Path.Combine(_dir.Path, "My App")).FullName;
        Directory.CreateDirectory(Path.Combine(dir, "lib", "mypkg"));
        File.WriteAllBytes(Path.Combine(dir, "lib", "library.zip"), ContainerFixtures.Zip(
            ("__main__my_app__.pyc", PyVersion.WithHeader(Magic312, V312, Code("main.py"))), ("__startup__.pyc", PyVersion.WithHeader(Magic312, V312, Code("__startup__.py"))),
            ("os.pyc", PyVersion.WithHeader(Magic312, V312, Code("os.py")))));
        File.WriteAllBytes(Path.Combine(dir, "lib", "mypkg", "__init__.pyc"), PyVersion.WithHeader(Magic312, V312, Code("mypkg/__init__.py")));
        File.WriteAllBytes(Path.Combine(dir, "lib", "_socket.cp312-win_amd64.pyd"), [1]);
        File.WriteAllBytes(Path.Combine(dir, "python312.dll"), [1]);
        var exe = Path.Combine(dir, "My App.exe");
        File.WriteAllBytes(exe, Launcher("cx_Freeze: Python error in main script", []));
        var c = Containers.Open(File.ReadAllBytes(exe), "My App.exe", AnalysisLimits.Default, default, exe, allFiles: true);
        Assert.Equal("cx_Freeze executable", c.Kind);
        Assert.StartsWith("cx_Freeze: Python 3.12 (python312.dll); entry __main__my_app__;", c.Notes[0]);
        var roles = Roles(c);
        Assert.Contains("lib/library.zip_extracted/__main__my_app__.pyc=entry script; lib/library.zip_extracted/__startup__.pyc=bootstrap script; lib/library.zip_extracted/os.pyc=module", roles);
        Assert.Contains("python312.dll=Python runtime (beside the executable)", roles);
        Assert.Contains("lib/_socket.cp312-win_amd64.pyd=native module (beside the executable)", roles);
        Assert.Contains("lib/mypkg/__init__.pyc=package (beside the executable)", roles);
        // The files beside it are listed, not copied.
        Assert.Equal(3, c.Items.Count);
    }

    /// <summary>A Nuitka onefile payload: "KAY", then one Zstandard stream of (name, flags, size, data) records ending in an empty name.</summary>
    internal static byte[] NuitkaPayload()
    {
        using var files = new MemoryStream();
        void File(string name, byte[] data)
        {
            files.Write(Encoding.UTF8.GetBytes(name + "\0"));
            files.WriteByte(0);
            files.Write(BitConverter.GetBytes((long)data.Length));
            files.Write(data);
        }
        File("app.bin", [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);
        File("libpython3.12.so.1.0", [0x7F, (byte)'E', (byte)'L', (byte)'F']);
        File("_ssl.so", [0x7F, (byte)'E', (byte)'L', (byte)'F']);
        File("certifi/cacert.pem", "pem"u8.ToArray());
        files.WriteByte(0);
        using var zstd = new ZstdSharp.Compressor();
        return [.. "KAY"u8, .. zstd.Wrap(files.ToArray())];
    }

    [Fact]
    public void A_Nuitka_onefile_program_lists_its_payload_and_says_the_code_is_compiled()
    {
        var c = Containers.Open(Launcher("NUITKA_ONEFILE_PARENT", NuitkaPayload()), "app.exe", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Nuitka onefile executable", c.Kind);
        Assert.StartsWith("Nuitka: Python 3.12 (libpython3.12.so.1.0);", c.Notes[0]);
        Assert.Contains(c.Notes, n => n.Contains("compiled to native code", StringComparison.Ordinal));
        Assert.Equal("app.bin=main binary (compiled program); libpython3.12.so.1.0=Python runtime; _ssl.so=native module; certifi/cacert.pem=data", Roles(c));
        Assert.Equal("pem", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "certifi/cacert.pem").Bytes));
    }

    [Fact]
    public void The_python_view_names_a_zipapp_with_its_interpreter_and_source_modules()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "import pkg\n"u8.ToArray()), ("pkg/__init__.py", "x = 1\n"u8.ToArray()));
        byte[] bytes = [.. "#!/usr/bin/env python3.11\n"u8.ToArray(), .. zip];
        var path = Path.Combine(_dir.Path, "tool.pyz");
        File.WriteAllBytes(path, bytes);
        var facts = Assert.IsType<PythonFileView.Facts>(new PythonFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)!.Detail);
        Assert.Equal(("Python zipapp", "3.11", "the interpreter line"), (facts.Freezer, facts.PythonVersion, facts.VersionSource));
        Assert.Equal(["__main__", "pkg"], facts.ModuleNames);
        Assert.Equal(1, facts.Packages);
    }

    [Fact]
    public void The_python_view_reads_a_plain_zip_zipapp_of_source_modules()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "import pkg\n"u8.ToArray()), ("pkg/__init__.py", "x = 1\n"u8.ToArray()));
        var facts = Assert.IsType<PythonFileView.Facts>(new PythonFileView().Inspect(new FileInput("tool.pyz", zip, Blob.Identify(zip)), default)!.Detail);
        Assert.Equal(("Python zipapp", null), (facts.Freezer, facts.PythonVersion));
        Assert.Equal(["__main__", "pkg"], facts.ModuleNames);
    }

    [Fact]
    public void The_python_view_leaves_the_version_unknown_for_an_interpreter_line_without_one()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "x = 1\n"u8.ToArray()));
        byte[] bytes = [.. "#!/usr/bin/python\n"u8.ToArray(), .. zip];
        var facts = Assert.IsType<PythonFileView.Facts>(new PythonFileView().Inspect(new FileInput("tool.pyz", bytes, Blob.Identify(bytes)), default)!.Detail);
        Assert.Null(facts.PythonVersion);
    }

    [Fact]
    public void The_python_view_skips_a_script_with_an_interpreter_line_and_no_archive()
    {
        byte[] bytes = "#!/bin/sh\necho hello\n"u8.ToArray();
        Assert.Null(new PythonFileView().Inspect(new FileInput("run.sh", bytes, Blob.Identify(bytes)), default));
    }

    [Fact]
    public void The_python_view_skips_a_truncated_archive_behind_an_interpreter_line()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "x = 1\n"u8.ToArray()));
        byte[] bytes = [.. "#!/usr/bin/env python3\n"u8.ToArray(), .. zip[..(zip.Length / 2)]];
        Assert.Null(new PythonFileView().Inspect(new FileInput("tool.pyz", bytes, Blob.Identify(bytes)), default));
    }

    [Fact]
    public void The_python_view_falls_back_to_the_library_reader_when_the_root_main_does_not_open()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "x = 1\n"u8.ToArray()), ("lib/m.pyc", PyVersion.WithHeader(Magic312, V312, Code("m.py"))));
        // The entry data follows a 30-byte header and an 11-byte name; block
        // type 3 is reserved.
        zip[30 + 11] |= 0x06;
        var facts = Assert.IsType<PythonFileView.Facts>(new PythonFileView().Inspect(new FileInput("lib.zip", zip, Blob.Identify(zip)), default)?.Detail);
        Assert.NotEqual("Python zipapp", facts.Freezer);
    }

    [Fact]
    public void The_dependencies_view_names_the_top_level_packages_of_a_source_zipapp()
    {
        var zip = ContainerFixtures.Zip(("__main__.py", "import pkg\n"u8.ToArray()), ("pkg/__init__.py", "x = 1\n"u8.ToArray()));
        var input = new FileInput("tool.pyz", zip, Blob.Identify(zip));
        var view = new PythonFileView().Inspect(input, default)!;
        var facts = DependencyInventory.Of(input, [], [], new Dictionary<string, FileView> { ["python"] = view }, default)!;
        Assert.Contains(facts.All, c => c.Name == "pkg");
    }

    [Fact]
    public void The_dependencies_view_ignores_a_source_file_that_is_not_a_module()
    {
        var app = new FrozenApp("Python zipapp", "Python zipapp");
        app.Entries.Add(new FrozenEntry("share/helper.py", 1, FrozenApp.Data));
        app.Entries.Add(new FrozenEntry("pkg/__init__.py", 1, FrozenApp.Package));
        var detail = new PythonFileView.Facts("Python zipapp", null, null, [], 0, 1, 0, [], [], 1, false, [], []) { App = app };
        var input = new FileInput("tool.pyz", [], "zip");
        var facts = DependencyInventory.Of(input, [], [], new Dictionary<string, FileView> { ["python"] = new FileView(detail, []) }, default)!;
        Assert.Equal(["pkg"], facts.All.Select(c => c.Name));
    }

    [Fact]
    public void The_python_view_skips_a_zip_without_a_root_main_or_compiled_modules()
    {
        var zip = ContainerFixtures.Zip(("pkg/__init__.py", "x = 1\n"u8.ToArray()));
        Assert.Null(new PythonFileView().Inspect(new FileInput("a.zip", zip, Blob.Identify(zip)), default));
    }

    [Fact]
    public void The_python_view_summarizes_the_program()
    {
        var path = Path.Combine(_dir.Path, "app.exe");
        var bytes = PyInstallerSample();
        File.WriteAllBytes(path, bytes);
        var view = new PythonFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)!;
        var facts = Assert.IsType<PythonFileView.Facts>(view.Detail);
        Assert.Equal(("PyInstaller", "3.12", "python312.dll"), (facts.Freezer, facts.PythonVersion, facts.VersionSource));
        Assert.Equal(["app"], facts.EntryScripts);
        Assert.Equal(["app", "json", "json.decoder"], facts.ModuleNames);
        Assert.Equal(["_ssl.pyd"], facts.NativeModules);
        Assert.Equal(["python312.dll"], facts.Runtime);
        Assert.Equal(1, facts.DataFiles);
    }

    /// <summary>marshal.dumps(compile("def f(a, b=2):\n    return a + b\nx = 1\n", "app.py", "exec")) from CPython 2.7, 3.8, 3.11 and 3.13: one sample per code layout.</summary>
    public static TheoryData<int, int, string> CPythonCode => new()
    {
        { 2, 7, "630000000000000000020000004000000073160000006400006401008401005a00006402005a01006403005328040000006902000000630200000002000000020000004300000073080000007c00007c0100175328010000004e280000000028020000007401000000617401000000622800000000280000000073060000006170702e7079740100000066010000007302000000000169010000004e2802000000520200000074010000007828000000002800000000280000000073060000006170702e707974080000003c6d6f64756c653e0100000073020000000c02" },
        { 3, 8, "e3000000000000000000000000000000000300000040000000731200000064056401640284015a0064035a01640453002906e9020000006302000000000000000000000002000000020000004300000073080000007c007c011700530029014ea9002902da0161da016272020000007202000000fa066170702e7079da016601000000730200000000017206000000e9010000004e2901720100000029027206000000da01787202000000720200000072020000007205000000da083c6d6f64756c653e0100000073020000000a02" },
        { 3, 11, "e30000000000000000000000000200000000000000f31200000097006404640184015a0064025a01640353002905e902000000630200000000000000000000000200000003000000f30c00000097007c007c017a000000530029014ea9002902da0161da016273020000002020fa066170702e7079da0166720800000001000000730b0000008000d80b0c88718935804cf300000000e9010000004e2901720200000029027208000000da0178720400000072090000007207000000fa083c6d6f64756c653e720c000000010000007322000000f003010101f002010111f000010111f000010111f000010111e004058001800180017209000000" },
        { 3, 13, "e30000000000000000000000000200000000000000f3120000009500530453011a006a0172005302720167032905e902000000630200000000000000000000000200000003000000f30a000000950058012d000000240029014ea9002902da0161da016273020000002020da066170702e7079da016672080000000100000073090000008000d80b0c8935804cf300000000e9010000004e2901720200000029027208000000da0178720400000072090000007207000000da083c6d6f64756c653e720c00000001000000730f000000f003010101f402010111e0040581017209000000" },
    };

    [Theory]
    [MemberData(nameof(CPythonCode))]
    public void Code_objects_of_each_layout_read_and_write_back(int major, int minor, string hex)
    {
        var data = Convert.FromHexString(hex);
        var module = Assert.IsType<PyCode>(PyMarshal.Read(data, (major, minor), 0, out int end));
        Assert.Equal(data.Length, end);
        Assert.Equal(("<module>", "app.py"), (module.Name, module.Filename));
        var f = Assert.Single(module.Consts.OfType<PyCode>());
        Assert.Equal(("f", 2), (f.Name, f.ArgCount));
        Assert.Equal(["a", "b"], ((major, minor) is (3, >= 11) ? f.LocalsPlusNames : f.VarNames).Select(PyMarshal.Str));
        // Written without back references, read again: the same objects.
        var again = Assert.IsType<PyCode>(PyMarshal.Read(PyMarshalWriter.Write(module, (major, minor)), (major, minor)));
        Assert.Equal(PyMarshalWriter.Write(module, (major, minor)), PyMarshalWriter.Write(again, (major, minor)));
    }

    [Fact]
    [FuzzEntry(typeof(PyMarshal))]
    public void Fuzzed_marshal_data_never_throws_past_a_tool_error()
    {
        var failures = new List<string>();
        foreach (var (major, minor, hex) in CPythonCode.Select(r => ((int)r[0], (int)r[1], (string)r[2])))
            failures.AddRange(FormatFuzz.Run(Convert.FromHexString(hex), b => PyMarshal.TryRead(b, (major, minor), out _), 400));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    [Fact]
    [FuzzEntry(typeof(FrozenPython), typeof(PyInstallerArchive), typeof(FrozenPythonReader), typeof(PythonFileView))]
    public void Fuzzed_frozen_programs_never_throw_past_a_tool_error()
    {
        var failures = new List<string>();
        var path = Path.Combine(_dir.Path, "fuzz.exe");
        foreach (var seed in new[] { PyInstallerSample(), PyInstallerSample("0123456789abcdef"), Launcher("NUITKA_ONEFILE_PARENT", NuitkaPayload()), Pyz(null, ("os", 0, Code("os.py"))) })
            failures.AddRange(FormatFuzz.Run(seed, b =>
            {
                try
                {
                    Containers.Open(b, "fuzz.exe", AnalysisLimits.Default, default, allFiles: true);
                    new FrozenPythonReader().Open(new MemoryStream(b), "fuzz.exe", allFiles: true, AnalysisLimits.Default, default);
                    File.WriteAllBytes(path, b);
                    new PythonFileView().Inspect(new FileInput(path, b, Blob.Identify(b)), default);
                }
                catch (ToolError) { }
            }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
