using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Corvus.Tests;

/// <summary>A metadata type's stream field is named at its +0x48 offset.</summary>
public sealed class AotFieldOffsetTests : IDisposable
{
    private const string Source = """
        using System;
        namespace Il2CppDummyDll
        {
            public class FieldOffsetAttribute : Attribute { public string Offset; }
            public class AddressAttribute : Attribute { public string RVA; public string Offset; public string VA; }
        }
        namespace Fixture.Native
        {
            using Il2CppDummyDll;
            public class StreamHost
            {
                [FieldOffset(Offset = "0x48")] public object mReadMemStream;
                [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")]
                public void Read() { }
            }
        }
        """;

    private const string ScriptJson = """
        {
          "ScriptMethod": [ { "Address": 4096, "Name": "Fixture.Native.StreamHost$$Read" } ],
          "ScriptMetadata": [ { "Address": 20480, "Name": "Fixture.Native.StreamHost_TypeInfo", "Signature": "Fixture_Native_StreamHost_c*" } ]
        }
        """;

    private readonly TempDir _dir = new();
    private readonly Env _env;
    private readonly NativeCodeService _code;
    private readonly NativeTypeCatalog _catalog;
    private readonly LoadedNative _native;
    private NativeTypeCatalog.Context? _context;

    public AotFieldOffsetTests()
    {
        var dump = Path.Combine(_dir.Path, "dump");
        var dummies = Path.Combine(dump, "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, "Fixture.dll");
        File.WriteAllBytes(dll, Roslyn.Compile("Fixture", Source, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)));
        File.WriteAllText(Path.Combine(dump, "script.json"), ScriptJson);
        File.WriteAllText(Path.Combine(dump, "stringliteral.json"), "[]");

        var b = new PeBuilder { ImageBase = 0x180000000 };
        var code = Enumerable.Repeat((byte)0xCC, 0x200).ToArray();
        b.EntryPoint = b.Add(".text", code, 0x60000020).Rva;
        b.Add(".data", new byte[0x100], 0xC0000040).Rva = 0x5000;
        var binary = Path.Combine(dump, "GameAssembly.dll");
        File.WriteAllBytes(binary, b.Build());

        _env = new Env(dll);
        _code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
        _native = _env.Workspace.LoadAny(binary).Native!;
        _catalog = new NativeTypeCatalog(_env.Workspace, _code);
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private async Task<NativeTypeView> Applied()
    {
        var index = await _code.Index(_native, null, default);
        new AotNativeNames(_env.AotMetadata, _env.AotNavigator, _code).Apply(_native, index, _env.Workspace.Assemblies, default);
        _context = await _catalog.Open(_native, new HashSet<string> { NativeTypeCatalog.Metadata }, null, false, default);
        return (await _catalog.Find(_context, "Fixture.Native.StreamHost", 0, 10, default)).View!();
    }

    [Fact]
    public async Task The_stream_field_resolves_only_at_its_0x48_offset()
    {
        var view = await Applied();
        Assert.Equal("mReadMemStream", Assert.Single(NativeTypeCatalog.Paths(_context!, view, 0x48, default)).Path);
        Assert.Empty(NativeTypeCatalog.Paths(_context!, view, 0x40, default));
        Assert.Empty(NativeTypeCatalog.Paths(_context!, view, 0x58, default));
        Assert.Empty(NativeTypeCatalog.Paths(_context!, view, 0x1000, default));
    }
}
