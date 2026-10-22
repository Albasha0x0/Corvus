using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Python;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;

namespace Corvus.Tests;

/// <summary>view=dependencies on frozen Python programs built at test time: PyInstaller, py2exe and Nuitka onefile.</summary>
public sealed class PythonDependencyTests : IDisposable
{
    private static readonly (int, int) V312 = (3, 12);
    private static readonly byte[] Magic312 = PyVersion.MagicOf(V312)!;
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>A 3.12 module that runs "__version__ = <paramref name="version"/>" (RESUME, LOAD_CONST, STORE_NAME, RETURN_CONST).</summary>
    private static byte[] VersionModule(string filename, string version) => PyMarshalWriter.Write(new PyCode
    {
        Code = [0x97, 0x00, 0x64, 0x00, 0x5A, 0x00, 0x79, 0x01], Consts = [version, PySingleton.None], Names = ["__version__"], Filename = filename,
        Name = "<module>", QualName = "<module>", FirstLineNo = 1,
    }, V312);

    private static byte[] Pyc(byte[] code) => PyVersion.WithHeader(Magic312, V312, code);

    /// <summary>A runtime library that names its full version only as a string.</summary>
    private static readonly byte[] Runtime = [(byte)'M', (byte)'Z', 0, 0, .. "\03.12.4\0"u8];

    private DependencyFacts Facts(string name, byte[] bytes, out string path)
    {
        path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        var summary = new InspectionService(_workspace).Summarize(null, path, default);
        return Assert.IsType<DependencyFacts>(summary.Views["dependencies"].Detail);
    }

    private static DependencyComponent Named(DependencyFacts facts, string name) => facts.All.Single(c => c.Name == name);

    [Fact]
    public void A_PyInstaller_program_names_packages_by_import_name_with_the_version_their_modules_bind()
    {
        var exe = FrozenPythonTests.Launcher("_MEIPASS", FrozenPythonTests.CArchive(
            ("pyimod01_archive", 'm', FrozenPythonTests.Code("pyimod01_archive.py"), true),
            ("app", 's', FrozenPythonTests.Code("app.py"), true),
            ("python312.dll", 'b', Runtime, true),
            ("mylib/_speedups.cp312-win_amd64.pyd", 'b', [(byte)'M', (byte)'Z'], false),
            ("PYZ-00.pyz", 'z', FrozenPythonTests.Pyz(null,
                ("json", 1, FrozenPythonTests.Code("json/__init__.py")),
                ("requests", 1, FrozenPythonTests.Code("requests/__init__.py")),
                ("requests.__version__", 0, VersionModule("requests/__version__.py", "2.31.0")),
                ("mylib", 1, FrozenPythonTests.Code("mylib/__init__.py"))), false)));
        var facts = Facts("app.exe", exe, out _);
        Assert.Equal(("app", "application"), (facts.Subject!.Name, facts.Subject.Type));
        Assert.Equal(["python", "mylib", "requests"], facts.All.Select(c => c.Name));
        var python = Named(facts, "python");
        Assert.Equal(("3.12.4", "pkg:generic/python@3.12.4", "framework"), (python.Version, python.Purl, python.Type));
        var requests = Named(facts, "requests");
        Assert.Equal(("2.31.0", "pkg:pypi/requests@2.31.0", 0.6), (requests.Version, requests.Purl, requests.Confidence));
        Assert.Contains("__version__ in module requests.__version__", requests.Source);
        // No metadata and no __version__: the package is listed with its version unknown and where it was found.
        var mylib = Named(facts, "mylib");
        Assert.Equal((null, null, false), (mylib.Version, mylib.Purl, mylib.VersionKnown));
        Assert.Equal(["mylib/_speedups.cp312-win_amd64.pyd", "PYZ-00.pyz_extracted/mylib/__init__.pyc"], mylib.Locations);
        Assert.Contains(facts.Notes, n => n.Contains("1 Python package(s) are named by import name only", StringComparison.Ordinal));
    }

    [Fact]
    public void A_one_folder_build_reads_the_metadata_and_runtime_beside_the_executable()
    {
        var internals = Directory.CreateDirectory(Path.Combine(_dir.Path, "_internal", "requests-2.31.0.dist-info")).Parent!.FullName;
        File.WriteAllText(Path.Combine(internals, "requests-2.31.0.dist-info", "METADATA"), "Name: requests\nVersion: 2.31.0\n");
        File.WriteAllBytes(Path.Combine(internals, "python312.dll"), Runtime);
        var exe = FrozenPythonTests.Launcher("_MEIPASS", FrozenPythonTests.CArchive(
            ("app", 's', FrozenPythonTests.Code("app.py"), true),
            ("pyi-contents-directory _internal", 'o', [], false),
            ("PYZ-00.pyz", 'z', FrozenPythonTests.Pyz(null, ("requests", 1, FrozenPythonTests.Code("requests/__init__.py"))), false)));
        var facts = Facts("app.exe", exe, out _);
        Assert.Equal([("python", "3.12.4"), ("requests", "2.31.0")], facts.All.Select(c => (c.Name, c.Version)));
        Assert.Equal(["_internal/requests-2.31.0.dist-info/METADATA", "PYZ-00.pyz_extracted/requests/__init__.pyc"], Named(facts, "requests").Locations);
        Assert.Equal(["_internal/python312.dll"], Named(facts, "python").Locations);
    }

    [Fact]
    public void A_py2exe_library_zip_names_distributions_from_their_metadata_with_their_requirements()
    {
        var zip = ContainerFixtures.Zip(
            ("requests-2.31.0.dist-info/METADATA", Encoding.UTF8.GetBytes(
                "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nRequires-Dist: urllib3 (<3,>=1.21.1)\nRequires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'\n\nRequires-Dist: not a header\n")),
            ("requests-2.31.0.dist-info/top_level.txt", "requests\n"u8.ToArray()),
            ("urllib3-2.0.7.dist-info/METADATA", "Metadata-Version: 2.1\r\nName: urllib3\r\nVersion: 2.0.7\r\n"u8.ToArray()),
            ("requests/__init__.pyc", Pyc(FrozenPythonTests.Code("requests/__init__.py"))),
            ("urllib3/__init__.pyc", Pyc(FrozenPythonTests.Code("urllib3/__init__.py"))),
            ("yaml/__init__.pyc", Pyc(FrozenPythonTests.Code("yaml/__init__.py"))),
            ("encodings/__init__.pyc", Pyc(FrozenPythonTests.Code("encodings/__init__.py"))));
        var scripts = PyMarshalWriter.Write(new PySequence('[', [PyMarshal.Read(FrozenPythonTests.Code("boot_common.py"), V312),
            PyMarshal.Read(FrozenPythonTests.Code("app.py"), V312)]), V312);
        var resource = new MemoryStream();
        var w = new BinaryWriter(resource);
        w.Write(0x78563412);
        w.Write(0);
        w.Write(0);
        w.Write(scripts.Length);
        w.Write((byte)0);
        w.Write(scripts);
        var facts = Facts("app.exe", InstallerStubTests.Stub("PYTHONSCRIPT", 1, resource.ToArray(), zip), out _);
        Assert.Equal(["python", "requests", "urllib3", "PyYAML"], facts.All.Select(c => c.Name));
        var requests = Named(facts, "requests");
        Assert.Equal(("pkg:pypi/requests@2.31.0", 1.0), (requests.Purl, requests.Confidence));
        Assert.Equal(["app.exe_extracted/requests-2.31.0.dist-info/METADATA", "app.exe_extracted/requests/__init__.pyc"], requests.Locations);
        // The extra's requirement is not one the program needs.
        Assert.Equal([Named(facts, "urllib3").Ref], facts.Edges.Single(e => e.From == requests.Ref).To);
        Assert.Equal((null, null), (Named(facts, "PyYAML").Version, Named(facts, "PyYAML").Purl));
        // The runtime is not in the program: only the .pyc magic names the version.
        Assert.Equal(("3.12", null), (Named(facts, "python").Version, Named(facts, "python").Purl));
    }

    /// <summary>A Nuitka onefile payload whose main binary holds one constants section per module and a bundled distribution's metadata.</summary>
    private static byte[] NuitkaProgram()
    {
        using var binary = new MemoryStream();
        binary.Write([0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);
        void Section(string module, string constants)
        {
            var data = Encoding.Latin1.GetBytes($"\u0002\0u<module {module}>\0{constants}.");
            binary.Write(Encoding.ASCII.GetBytes(module + "\0"));
            binary.Write(BitConverter.GetBytes(data.Length));
            binary.Write(data);
        }
        Section("requests", "afrom\0");
        Section("requests.__version__", "u2.31.0\0a__version__\0");
        // A __version__ that is not the package's: the next section's value must not be read for this one.
        Section("idna", "acore\0");
        Section("idna.idnadata", "u15.1.0\0a__version__\0");
        using var files = new MemoryStream();
        void File(string name, byte[] data)
        {
            files.Write(Encoding.UTF8.GetBytes(name + "\0"));
            files.WriteByte(0);
            files.Write(BitConverter.GetBytes((long)data.Length));
            files.Write(data);
        }
        File("app.bin", binary.ToArray());
        File("libpython3.12.so.1.0", [0x7F, (byte)'E', (byte)'L', (byte)'F', .. "\03.12.4\0"u8]);
        File("certifi-2023.11.17.dist-info/METADATA", "Name: certifi\nVersion: 2023.11.17\n"u8.ToArray());
        File("certifi/cacert.pem", "pem"u8.ToArray());
        files.WriteByte(0);
        using var zstd = new ZstdSharp.Compressor();
        return FrozenPythonTests.Launcher("NUITKA_ONEFILE_PARENT", [.. "KAY"u8, .. zstd.Wrap(files.ToArray())]);
    }

    [Fact]
    public void A_Nuitka_program_names_compiled_packages_from_its_constants_and_bundled_metadata()
    {
        var facts = Facts("app.exe", NuitkaProgram(), out _);
        Assert.Equal([("python", "3.12.4"), ("certifi", "2023.11.17"), ("idna", null), ("requests", "2.31.0")], facts.All.Select(c => (c.Name, c.Version)));
        Assert.Equal("pkg:pypi/certifi@2023.11.17", Named(facts, "certifi").Purl);
        Assert.Equal("pkg:pypi/requests@2.31.0", Named(facts, "requests").Purl);
        Assert.Equal(["app.bin (compiled module idna)"], Named(facts, "idna").Locations);
    }

    [Fact]
    public void A_frozen_programs_sbom_validates_and_carries_the_pypi_purls()
    {
        var facts = Facts("app.exe", NuitkaProgram(), out var path);
        var bom = CycloneDx.Write(facts, path, new string('0', 64), "1.0.0", DateTimeOffset.UnixEpoch, Guid.Empty);
        DependencyInventoryTests.AssertValid(bom);
        Assert.Contains("\"purl\": \"pkg:pypi/requests@2.31.0\"", Encoding.UTF8.GetString(bom));
    }

    [Fact]
    public void PyPI_purls_carry_the_normalized_distribution_name()
    {
        Assert.Equal("pkg:pypi/charset-normalizer@3.3.2", Purl.PyPI("Charset_Normalizer", "3.3.2"));
        Assert.Equal("pkg:pypi/zope-interface@6.0%2Blocal", Purl.PyPI("zope..interface", "6.0+local"));
    }
}
