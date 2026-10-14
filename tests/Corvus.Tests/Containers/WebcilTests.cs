using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>
/// Blazor WebAssembly's _framework folder holds Webcil (.wasm) assemblies; loading it said "Loaded 0 assemblies" and
/// nothing else. Folder and file loads now say why, and the container tools convert Webcil to a PE that loads.
/// </summary>
public sealed class WebcilTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    /// <summary>The fixture assembly as the Blazor build ships it: Webcil header and sections in a .wasm data segment.</summary>
    internal static byte[] ToWasm(byte[] pe)
    {
        using var reader = new PEReader(new MemoryStream(pe));
        var sections = reader.PEHeaders.SectionHeaders;
        var cli = reader.PEHeaders.PEHeader!.CorHeaderTableDirectory;
        int dataAt = 28 + sections.Length * 16;
        var webcil = new List<byte>();
        var header = new byte[dataAt];
        "WbIL"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8), (ushort)sections.Length);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), cli.RelativeVirtualAddress);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(16), cli.Size);
        int raw = dataAt;
        for (int i = 0; i < sections.Length; i++)
        {
            var s = header.AsSpan(28 + i * 16);
            BinaryPrimitives.WriteInt32LittleEndian(s, sections[i].VirtualSize);
            BinaryPrimitives.WriteInt32LittleEndian(s[4..], sections[i].VirtualAddress);
            BinaryPrimitives.WriteInt32LittleEndian(s[8..], sections[i].SizeOfRawData);
            BinaryPrimitives.WriteInt32LittleEndian(s[12..], raw);
            raw += sections[i].SizeOfRawData;
        }
        webcil.AddRange(header);
        foreach (var s in sections) webcil.AddRange(pe.AsSpan(s.PointerToRawData, s.SizeOfRawData).ToArray());

        var segments = new List<byte>();
        segments.AddRange(Uleb(2));
        segments.Add(1); segments.AddRange(Uleb(4)); segments.AddRange(BitConverter.GetBytes(webcil.Count));
        segments.Add(1); segments.AddRange(Uleb(webcil.Count)); segments.AddRange(webcil);
        var wasm = new List<byte>("\0asm"u8.ToArray()) { 1, 0, 0, 0 };
        wasm.Add(11); wasm.AddRange(Uleb(segments.Count)); wasm.AddRange(segments);
        return [.. wasm];
    }

    private static IEnumerable<byte> Uleb(int value)
    {
        do
        {
            byte b = (byte)(value & 0x7F);
            value >>= 7;
            yield return value != 0 ? (byte)(b | 0x80) : b;
        } while (value != 0);
    }

    /// <summary>A Blazor app's assembly (it has Main) converted as a DLL exported as OutputType Library with a StartupObject: CS2017.</summary>
    [Fact]
    public void AnAssemblyWithAnEntryPointConvertsToAnExe()
    {
        var exe = Roslyn.Compile("App", "public static class Program { public static void Main() { } }",
            new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.ConsoleApplication), []);
        foreach (var (image, isDll) in new[] { (exe, false), (File.ReadAllBytes(Env.FixturePath), true) })
        {
            var pe = Assert.Single(Containers.Open(ToWasm(image), "x.wasm", AnalysisLimits.Default, default).Items).Bytes;
            using var reader = new PEReader(new MemoryStream(pe));
            Assert.Equal(isDll, reader.PEHeaders.IsDll);
        }
    }

    [Fact]
    public void WebcilConvertsToAPeThatLoadsAndFolderLoadsSayWhyNothingLoaded()
    {
        var wasm = ToWasm(File.ReadAllBytes(Env.FixturePath));
        var framework = Path.Combine(_dir.Path, "wwwroot", "_framework");
        Directory.CreateDirectory(framework);
        var file = Path.Combine(framework, "TestFixture.abc123.wasm");
        File.WriteAllBytes(file, wasm);

        var contents = Containers.Open(wasm, file, AnalysisLimits.Default, default);
        Assert.Equal("Webcil", contents.Kind);
        var pe = Assert.Single(contents.Items);
        Assert.Equal("TestFixture.dll", pe.Name); // the assembly name, not the fingerprinted file name, so references resolve
        Assert.Equal(".NET assembly", Blob.Identify(pe.Bytes));
        var dll = Path.Combine(_dir.Path, "TestFixture.dll");
        File.WriteAllBytes(dll, pe.Bytes);
        using (var env = new Env(dll))
            Assert.Contains("class Account", env.Decompile("Fixture.Model.Account"));

        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var error = Assert.Throws<ToolError>(() => workspace.LoadAny(file));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("Webcil", error.Message);
        Assert.Contains("unpack_container", error.Remediation);

        var report = workspace.LoadDirectory(framework, recursive: false);
        Assert.Empty(report.Loaded);
        var text = Corvus.Tools.WorkspaceTools.FormatLoad(workspace, framework, report);
        Assert.Contains("Loaded 0 assemblies", text);
        Assert.Contains("1 .NET assemblies here are Webcil", text);
        Assert.Contains("not read directly yet (planned)", text);
        Assert.Contains("1 .NET assemblies here are Webcil", Corvus.Tools.WorkspaceTools.FormatLoad(workspace, Path.Combine(_dir.Path, "wwwroot"), report));
        Assert.Null(Webcil.FolderHint(_dir.Path + Path.DirectorySeparatorChar + "missing"));
        // A path spelled with '/' gives a hint with one kind of separator.
        var hint = Webcil.FolderHint(_dir.Path.Replace('\\', '/') + "/wwwroot")!;
        Assert.Contains($"Folder: {framework}", hint);
    }

    /// <summary>
    /// unpack_container refused the _framework folder and a second .wasm into the same output folder, so an app's assemblies
    /// could not be unpacked where they resolve each other; and a patched assembly could only be saved as a PE.
    /// </summary>
    [Fact]
    public void AFrameworkFolderUnpacksInOneGoAndPatchesSaveBackAsWebcil()
    {
        var lib = ReferenceResolutionTests.Compile("Lib", "namespace L { public class Marker { public static int V() { return 1; } } }");
        var app = ReferenceResolutionTests.Compile("App", "namespace A { public static class Run { public static int Go() { return L.Marker.V(); } } }", lib);
        var framework = Path.Combine(_dir.Path, "site", "_framework");
        Directory.CreateDirectory(framework);
        File.WriteAllBytes(Path.Combine(framework, "Lib.k2j4h5.wasm"), ToWasm(lib));
        File.WriteAllBytes(Path.Combine(framework, "App.x7y8z9.wasm"), ToWasm(app));
        File.WriteAllBytes(Path.Combine(framework, "dotnet.native.wasm"), [0, (byte)'a', (byte)'s', (byte)'m', 1, 0, 0, 0]);

        using var env = new Env();
        var unpacker = new UnpackService(env.Workspace);
        var listed = unpacker.List(Path.Combine(_dir.Path, "site"), AnalysisLimits.Default, default);
        Assert.Equal(["App.dll", "Lib.dll"], listed.Assemblies.Select(a => a.Path).Order());
        var output = Path.Combine(_dir.Path, "out");
        var report = unpacker.Unpack(framework, output, load: true, AnalysisLimits.Default, default);
        Assert.Equal(2, report.Files.Count(f => f.LoadedAs != null));
        Assert.Equal(output, unpacker.Unpack(framework, output, load: false, AnalysisLimits.Default, default).OutputDirectory); // a repeat reuses it

        var go = env.One("A.Run::Go");
        Assert.NotNull(env.Workspace.LocateReference("Lib", null, null, go.Assembly.FilePath, netFramework: false)?.Loaded);
        Assert.Contains("Marker.V()", env.Decompiler.DecompileMembers(go.Assembly, [go.Member], default));
        env.Edit(() => env.Edits.StubMethod(go, "42"));
        var saved = Path.Combine(_dir.Path, "App.patched.wasm");
        var result = env.Workspace.Read(() => env.Edits.Save(go.Assembly, saved, overwrite: false));
        Assert.Contains("Written as Webcil", result);

        var wasm = File.ReadAllBytes(saved);
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(Webcil.Payload(wasm)!.Value, out var payload));
        Assert.Equal(0, payload.Offset % 4); // the loader reads the payload as aligned data
        using var reloaded = new Env(SaveAsDll(Webcil.ToPe(wasm)!));
        Assert.Contains("return 42;", reloaded.Decompile("A.Run::Go"));
    }

    /// <summary>
    /// A _framework folder with stale fingerprinted copies of one assembly from earlier publishes took the first by file name;
    /// the copy the boot manifest lists is the one the app loads.
    /// </summary>
    [Theory]
    [InlineData("net9")]
    [InlineData("net8")]
    [InlineData("net10")]
    [InlineData("none")]
    public void StaleFingerprintedCopiesYieldToTheOneTheBootManifestLists(string manifest)
    {
        var stale = ToWasm(ReferenceResolutionTests.Compile("Lib", "namespace L { public class Marker { public static int V() { return 1; } } }"));
        var current = ToWasm(ReferenceResolutionTests.Compile("Lib", "namespace L { public class Marker { public static int V() { return 2; } } }"));
        var framework = Path.Combine(_dir.Path, manifest, "_framework");
        Directory.CreateDirectory(framework);
        File.WriteAllBytes(Path.Combine(framework, "Lib.aaaa1111.wasm"), stale);
        File.WriteAllBytes(Path.Combine(framework, "Lib.zzzz9999.wasm"), current);
        File.WriteAllBytes(Path.Combine(framework, "Lib.mmmm5555.wasm"), stale);
        switch (manifest)
        {
            case "net9":
                File.WriteAllText(Path.Combine(framework, "blazor.boot.json"),
                    """{ "mainAssemblyName": "Lib", "resources": { "fingerprinting": { "Lib.zzzz9999.wasm": "Lib.wasm" }, "assembly": { "Lib.wasm": "sha256-x" } } }""");
                break;
            case "net8": // logical names; the copy is identified by its integrity value
                File.WriteAllText(Path.Combine(framework, "blazor.boot.json"),
                    $$"""{ "mainAssemblyName": "Lib", "resources": { "assembly": { "Lib.wasm": "{{Webcil.Integrity(current)}}" } } }""");
                break;
            case "net10":
                File.WriteAllText(Path.Combine(framework, "dotnet.native.q1w2e3.js"), "var x = 1;");
                File.WriteAllText(Path.Combine(framework, "dotnet.k9j8h7.js"),
                    """var a=1;/*json-start*/{ "mainAssemblyName": "Lib", "resources": { "assembly": [ { "virtualPath": "Lib.wasm", "name": "Lib.zzzz9999.wasm", "hash": "sha256-x" } ] } }/*json-end*/;var b=2;""");
                break;
        }

        using var env = new Env();
        var listed = new UnpackService(env.Workspace).List(framework, AnalysisLimits.Default, default);
        var lib = Assert.Single(listed.Assemblies);
        if (manifest == "none")
        {
            Assert.Equal("Lib.aaaa1111.wasm", lib.Origin);
            Assert.Contains(listed.Notes, n => n.Contains("the first one found is used", StringComparison.Ordinal));
        }
        else
        {
            Assert.Equal("Lib.zzzz9999.wasm", lib.Origin);
            Assert.Contains(listed.Notes, n => n.Contains("Lib.zzzz9999.wasm, which the boot manifest lists, is used", StringComparison.Ordinal));
        }
    }

    private string SaveAsDll(byte[] pe)
    {
        var path = Path.Combine(_dir.Path, "reloaded", "App.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, pe);
        return path;
    }
}
