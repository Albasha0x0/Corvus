using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

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
        Assert.Equal("TestFixture.abc123.dll", pe.Name);
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
        var text = NetDecompilerMcp.Tools.WorkspaceTools.FormatLoad(workspace, framework, report);
        Assert.Contains("Loaded 0 assemblies", text);
        Assert.Contains("1 .NET assemblies here are Webcil", text);
        Assert.Contains("not read directly yet (planned)", text);
        Assert.Contains("1 .NET assemblies here are Webcil", NetDecompilerMcp.Tools.WorkspaceTools.FormatLoad(workspace, Path.Combine(_dir.Path, "wwwroot"), report));
        Assert.Null(Webcil.FolderHint(_dir.Path + Path.DirectorySeparatorChar + "missing"));
    }
}
