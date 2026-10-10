using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Il2Cpp names on a native binary: a synthetic dump (the fixture's dummy NativeThing::First at 0x1000 and ::Second
/// at 0x1100, script.json with instantiations and metadata slots, stringliteral.json) beside a small x64
/// GameAssembly.dll whose code sits at those addresses and loads the literal slots.
/// </summary>
public sealed class Il2CppNativeNamesTests : IDisposable
{
    private const string ScriptJson = """
        {
          "ScriptMethod": [
            { "Address": 4096, "Name": "Fixture.Native.NativeThing$$First" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Second" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Shared<object>" },
            { "Address": 4608, "Name": "Fixture.Native.NativeThing$$Shared<int>" },
            { "Address": 4608, "Name": "System.Collections.Generic.List<int>$$Add" },
            { "Address": 4864, "Name": "Fixture.Native.NativeThing$$Shared<uint>" }
          ],
          "ScriptMetadata": [
            { "Address": 20480, "Name": "Fixture.Native.NativeThing_TypeInfo", "Signature": "Fixture_Native_NativeThing_c*" },
            { "Address": 20488, "Name": "Fixture.Native.NativeThing_var", "Signature": "Il2CppType*" }
          ],
          "ScriptMetadataMethod": [
            { "Address": 20496, "Name": "Method$Fixture.Native.NativeThing.First()", "MethodAddress": 4096 },
            { "Address": 20504, "Name": "Method$Fixture.Native.NativeThing.Shared<int>()", "MethodAddress": 4608 },
            { "Address": 20512, "Name": "Method$Fixture.Native.NativeThing.Second()", "MethodAddress": 4352 }
          ],
          "Addresses": [ 4096, 4352, 4608, 4864, 4928, 8192 ]
        }
        """;

    private const string StringLiterals = """
        [
          { "value": "hello il2cpp", "address": "0x5040" },
          { "value": "second \"quoted\"", "address": "0x5048" }
        ]
        """;

    private readonly TempDir _dir = new();
    private readonly Env _env;
    private readonly NativeCodeService _code;
    private readonly Il2CppNativeNames _names;
    private readonly string _binary;

    public Il2CppNativeNamesTests()
    {
        (var dll, _binary) = CreateDump(_dir);
        _env = new Env(dll);
        _code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
        _names = new Il2CppNativeNames(_env.Il2Cpp, _env.Il2CppNavigator, _code);
    }

    /// <summary>Writes dump/DummyDll/TestFixture.dll, dump/script.json, dump/stringliteral.json and dump/GameAssembly.dll.</summary>
    internal static (string DummyDll, string GameAssembly) CreateDump(TempDir dir)
    {
        var dump = Path.Combine(dir.Path, "dump");
        var dummies = Path.Combine(dump, "DummyDll");
        Directory.CreateDirectory(dummies);
        var dll = Path.Combine(dummies, Path.GetFileName(Env.FixturePath));
        File.Copy(Env.FixturePath, dll);
        File.WriteAllText(Path.Combine(dump, "script.json"), ScriptJson);
        File.WriteAllText(Path.Combine(dump, "stringliteral.json"), StringLiterals);
        var binary = Path.Combine(dump, "GameAssembly.dll");
        File.WriteAllBytes(binary, GameAssembly());
        return (dll, binary);
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    /// <summary>
    /// .text at 0x1000: First loads the literal slot 0x5040 and calls Second (0x1100), which calls 0x1200; 0x1200 loads
    /// the slot 0x5048; 0x1300 and 0x1340 return. .data at 0x5000 holds the metadata, MethodInfo and literal slots.
    /// </summary>
    internal static byte[] GameAssembly()
    {
        var b = new PeBuilder { ImageBase = 0x180000000 };
        var code = Enumerable.Repeat((byte)0xCC, 0x400).ToArray();
        void Put(uint rva, params byte[] bytes) => bytes.CopyTo(code, (int)(rva - 0x1000));
        static byte[] Rel(uint from, uint to) => BitConverter.GetBytes((int)(to - from));
        Put(0x1000, [0x48, 0x8B, 0x0D, .. Rel(0x1007, 0x5040)]);     // mov rcx, [rip+slot]
        Put(0x1007, [0xE8, .. Rel(0x100C, 0x1100), 0xC3]);          // call Second; ret
        Put(0x1100, [0xE8, .. Rel(0x1105, 0x1200), 0xC3]);          // call 0x1200; ret
        Put(0x1200, [0x48, 0x8B, 0x0D, .. Rel(0x1207, 0x5048), 0xC3]);
        Put(0x1300, 0xC3);
        Put(0x1340, 0xC3);
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        var data = b.Add(".data", new byte[0x100], 0xC0000040);
        data.Rva = 0x5000;
        return b.Build();
    }

    private async Task<(LoadedNative Native, NativeCodeIndex Index)> Open()
    {
        var native = _env.Workspace.LoadAny(_binary).Native!;
        return (native, await _code.Index(native, null, default));
    }

    [Fact]
    public void IdentifiersAreValidNames()
    {
        Assert.Equal("Fixture_Native_NativeThing__First", Il2CppNativeNames.Identifier("Fixture.Native.NativeThing$$First"));
        Assert.Equal("System_Collections_Generic_Dictionary_string_int__Add", Il2CppNativeNames.Identifier("System.Collections.Generic.Dictionary<string, int>$$Add"));
        Assert.Equal("List_int", Il2CppNativeNames.Identifier("List<int>"));
        Assert.Equal("_c__DisplayClass1_0___Run_b__0", Il2CppNativeNames.Identifier("<>c__DisplayClass1_0$$<Run>b__0"));
        Assert.Equal("Method_Ns_Type_M", Il2CppNativeNames.Identifier("Method$Ns.Type.M"));
        Assert.Equal("_1abc", Il2CppNativeNames.Identifier("1abc"));
        Assert.Equal("Au4E2DB", Il2CppNativeNames.Identifier("A中B"));
        // C identifiers: IDA's x86/x64 name characters are letters, digits and '_' (it rewrites '$')
        foreach (var name in new[] { "Fixture.Native.NativeThing$$First", "<>c$$<M>b__0_0", "x.y<z>[]", "\u0001", "a$b@c" })
            Assert.Matches("^[A-Za-z_][A-Za-z0-9_]*$", Il2CppNativeNames.Identifier(name));
    }

    [Fact]
    public async Task NamesFunctionsSlotsAndStringsAndRanksBelowUserNames()
    {
        var (native, index) = await Open();
        var report = _names.Apply(native, index, _env.Workspace.Assemblies, default);
        Assert.Equal((4, 2, 2, 2), (report.Functions, report.SharedFunctions, report.SharedExtraMethods, report.UnnamedStarts));
        Assert.Equal((2, 2, 3, 0), (report.Strings, report.MetadataSlots, report.MethodInfoSlots, report.Suffixed));

        Assert.Equal("Fixture_Native_NativeThing__First", index.NameAt(0x1000));
        Assert.Equal("Fixture_Native_NativeThing__Shared_int", index.NameAt(0x1200));
        Assert.Equal("Fixture_Native_NativeThing_TypeInfo", index.NameAt(0x5000));
        Assert.Equal("Method_Fixture_Native_NativeThing_Second", index.NameAt(0x5020));
        Assert.Equal("StringLiteral_1", index.NameAt(0x5048));
        Assert.Equal("Fixture.Native.NativeThing::First()", index.CommentFor(0x1000));
        Assert.StartsWith("Fixture.Native.NativeThing::Second()\nshared code, also: Fixture.Native.NativeThing::Shared<object>", index.CommentFor(0x1100));
        Assert.Equal("\"second \\\"quoted\\\"\"", index.CommentFor(0x5048));
        Assert.Equal(0x5048u, index.AddressOfName("StringLiteral_1"));

        var tools = new NativeCodeTools(_env.Workspace, _code, _env.Pager);
        var list = await tools.ListFunctions(native.Id);
        Assert.Contains("Fixture_Native_NativeThing__First", list);
        var disasm = await tools.Disassemble(native.Id, "Fixture_Native_NativeThing__First");
        Assert.Contains("; Fixture.Native.NativeThing::First()", disasm);
        Assert.Contains("StringLiteral_0", disasm);
        Assert.Contains("; \"hello il2cpp\"", disasm);
        Assert.Contains("call   Fixture_Native_NativeThing__Second", disasm);
        Assert.Contains("Fixture_Native_NativeThing__First:\n", disasm.Replace("\r", ""));
        Assert.Contains("Fixture_Native_NativeThing__Shared_int+0x0", await tools.FindXrefs(native.Id, "StringLiteral_1"));
        var strings = await tools.SearchNativeStrings(native.Id, "il2cpp");
        Assert.Contains("il2cpp \"hello il2cpp\"  slot StringLiteral_0, 1 refs, first in Fixture_Native_NativeThing__First", strings);
        Assert.Contains("Fixture_Native_NativeThing__Second", await tools.NativeCallTree(native.Id, "0x1000"));

        var resolved = await new NativeTools(_env.Workspace, _env.Pager, _code).ResolveAddress(native.Id, "0x180001204");
        Assert.Contains("in il2cpp function Fixture_Native_NativeThing__Shared_int (rva 0x1200", resolved);
        Assert.Contains("find_method_by_address 0x1200", resolved);

        // user > il2cpp, and clearing the user name falls back to the il2cpp name
        var edits = new NativeEditService(_env.Workspace, _code);
        edits.Rename(native, index, 0x1000, "MyFirst", false);
        Assert.Equal("MyFirst", index.NameAt(0x1000));
        Assert.Equal(1, _names.Apply(native, index, _env.Workspace.Assemblies, default).UserNamesKept);
        Assert.Equal("MyFirst", index.NameAt(0x1000));
        edits.ClearName(native, index, 0x1000);
        Assert.Equal("Fixture_Native_NativeThing__First", index.NameAt(0x1000));

        // the layer survives a rebuilt index (patching) and is removed as a group
        native.ReplaceImage(native.Image);
        var rebuilt = await _code.Index(native, null, default);
        Assert.NotSame(index, rebuilt);
        Assert.Equal("StringLiteral_0", rebuilt.NameAt(0x5040));
        Assert.Equal(11, _names.Clear(native, rebuilt));
        Assert.Null(rebuilt.NameAt(0x5040));
        Assert.Equal("sub_1000", rebuilt.NameAt(0x1000));
        Assert.Null(_names.Clear(native, rebuilt));
    }

    [Fact]
    public async Task ToolReportsCountsAndRefusesAForeignBinary()
    {
        var (native, _) = await Open();
        var tools = new Il2CppNativeTools(_env.Workspace, _code, _names);
        var text = await tools.ApplyIl2CppNames(native.Id);
        Assert.Contains("functions named: 4", text);
        Assert.Contains("shared code: 2 functions hold 2 more methods", text);
        Assert.Contains("string literals: 2; metadata slots: 2; MethodInfo slots: 3", text);
        Assert.Contains("misses: 2 function start(s) without a method", text);
        Assert.Contains("removed 11 il2cpp names", await tools.ApplyIl2CppNames(native.Id, clear: true));

        var other = _dir.File("other.dll");
        var b = new PeBuilder { ImageBase = 0x180000000 };
        b.Add(".data", new byte[0x100]);
        File.WriteAllBytes(other, b.Build());
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.ApplyIl2CppNames(other));
        Assert.Contains("the dump was not made from this binary", e.Message);
    }

    [Fact]
    public async Task PushSendsEverythingOnceThenOnlyChanges()
    {
        var (native, index) = await Open();
        _names.Apply(native, index, _env.Workspace.Assemblies, default);
        var push = new NativeNamePush(_code);
        var session = new RecordingSession();
        var first = await push.EnsureAsync(native, session, default);
        Assert.Equal(11, first!.Sent);
        Assert.Equal(11, session.Items.Count);
        Assert.Contains(session.Items, i => i is { Rva: 0x1000, Name: "Fixture_Native_NativeThing__First", MakeFunction: true });
        Assert.Contains(session.Items, i => i is { Rva: 0x5040, Name: "StringLiteral_0", Comment: "\"hello il2cpp\"", MakeFunction: false });
        Assert.Equal(first.Stamp, session.Stamp);
        Assert.Null(await push.EnsureAsync(native, session, default)); // nothing changed

        session.Items.Clear();
        new NativeEditService(_env.Workspace, _code).Rename(native, index, 0x1100, "MySecond", false);
        var second = await push.EnsureAsync(native, session, default);
        Assert.Equal(1, second!.Sent);
        Assert.Equal(new NativeNameItem(0x1100, "MySecond", null, false), Assert.Single(session.Items));

        session.Items.Clear();
        _names.Clear(native, index);
        var third = await push.EnsureAsync(native, session, default);
        Assert.Equal((11, 10), (third!.Sent, third.Removed)); // the user name stays
        Assert.Contains(session.Items, i => i is { Rva: 0x5040, Name: "", Comment: "" });

        // a new session on a database that already holds the set skips the push
        var reopened = new RecordingSession { Stamp = session.Stamp };
        Assert.True((await push.EnsureAsync(native, reopened, default))!.AlreadyInDatabase);
        Assert.Empty(reopened.Items);
    }

    [Fact]
    public async Task PushLeavesPdbAddressesToTheEngine()
    {
        var (native, _) = await Open();
        var layers = new[]
        {
            new NativeNameLayers.Layer(NativeNameSource.Il2Cpp, new Dictionary<uint, string> { [0x1000] = "A", [0x1100] = "B" }, new Dictionary<uint, string>(), "t"),
            new NativeNameLayers.Layer(NativeNameSource.Pdb, new Dictionary<uint, string> { [0x1000] = "Bar::Foo", [0x1200] = "Baz" }, new Dictionary<uint, string>(), "t"),
        };
        var effective = NativeNamePush.Effective(null, layers, native.Image);
        Assert.Equal([0x1100u], effective.Keys);
        Assert.Equal("B", effective[0x1100].Name);
    }

    /// <summary>An engine session that records the names pushed into it.</summary>
    private sealed class RecordingSession : INativeDecompilerSession
    {
        public List<NativeNameItem> Items { get; } = [];
        public string? Stamp { get; set; }

        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default)
        {
            Items.AddRange(items);
            if (stampKey != null) Stamp = stamp;
            return Task.FromResult(new NameBatchResult(items.Count(i => i.Name != null), 0, items.Count(i => i.Comment != null), 0, TimeSpan.Zero, []));
        }

        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult(Stamp);

        public string ProviderId => "test";
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0x180000000;
        public bool ReusedDatabase => false;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => false;
        public bool IsOpen => true;
        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
