using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Il2Cpp string literals from a synthetic dump: the fixture's stand-in dummy types (NativeThing::First at RVA 0x1000,
/// ::Second at 0x1100) copied into dump/DummyDll, script.json and stringliteral.json in dump/, and a small x64
/// GameAssembly.dll whose code loads the literal slots.
/// </summary>
public sealed class Il2CppStringTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly string _dump;
    private readonly string _dummyDir;

    // Literal slots in .data (RVA 0x3000).
    private const uint SlotHello = 0x3000, SlotQuote = 0x3008, SlotOther = 0x3010, SlotUnused = 0x3018;

    private readonly ITestOutputHelper _output;

    public Il2CppStringTests(ITestOutputHelper output)
    {
        _output = output;
        _dump = Path.Combine(_dir.Path, "dump");
        _dummyDir = Path.Combine(_dump, "DummyDll");
        Directory.CreateDirectory(_dummyDir);
        File.Copy(Env.FixturePath, Path.Combine(_dummyDir, Path.GetFileName(Env.FixturePath)));
    }

    public void Dispose() => _dir.Dispose();

    private const string ScriptJson = """
        {
          "ScriptMethod": [
            { "Address": 4096, "Name": "Fixture.Native.NativeThing$$First", "Signature": "void Fixture_Native_NativeThing__First (Fixture_Native_NativeThing_o* __this, const MethodInfo* method);", "TypeSignature": "vii" },
            { "Address": 4352, "Name": "Fixture.Native.NativeThing$$Second", "Signature": "void S ();", "TypeSignature": "vii" },
            { "Address": 4608, "Name": "Fixture.Native.NativeThing$$Shared<int>", "Signature": "int32_t Fixture_Native_NativeThing__Shared_int_ (int32_t value, const MethodInfo* method);", "TypeSignature": "iii" },
            { "Address": 4608, "Name": "Fixture.Native.NativeThing$$Shared<uint>", "Signature": "uint32_t X ();", "TypeSignature": "iii" },
            { "Address": 631462417553368870, "Name": "Bogus$$Address", "Signature": "", "TypeSignature": "v" }
          ],
          "ScriptString": [ { "Address": 12288, "Value": "hello \u0001world" } ],
          "ScriptMetadata": [ { "Address": 20480, "Name": "Fixture.Native.NativeThing_TypeInfo", "Signature": "Fixture_Native_NativeThing_c*" } ],
          "ScriptMetadataMethod": [ { "Address": 20488, "Name": "Method$Fixture.Native.NativeThing.First()", "MethodAddress": 4096 } ],
          "Addresses": [ 4096, 4352, 4608, 4864, 8192 ]
        }
        """;

    private void WriteDump(bool binary = true, bool script = true)
    {
        if (script) File.WriteAllText(Path.Combine(_dump, "script.json"), ScriptJson);
        // With a byte order mark, as some tools write it.
        File.WriteAllText(Path.Combine(_dump, "stringliteral.json"), $$"""
            [
              { "value": "hello \u0001world", "address": "0x{{SlotHello:X}}" },
              { "value": "say \"hi\"", "address": "0x{{SlotQuote:X}}" },
              { "value": "other hello", "address": "0x{{SlotOther:X}}" },
              { "value": "unused hello", "address": "0x{{SlotUnused:X}}" }
            ]
            """, new UTF8Encoding(true));
        if (binary) File.WriteAllBytes(Path.Combine(_dump, "GameAssembly.dll"), BuildImage());
    }

    /// <summary>
    /// An x64 PE image: .text at RVA 0x1000 with RIP-relative loads of the literal slots, .data at RVA 0x3000.
    /// First (0x1000) loads "hello" and the quote; Second (0x1100) loads "hello"; Shared&lt;int&gt; (0x1200, script.json
    /// name only) loads the quote twice; an unnamed function (0x1300) loads "other".
    /// </summary>
    internal static byte[] BuildImage()
    {
        var code = new byte[0x400];
        void Load(int at, byte rex, byte opcode, byte modrm, uint target)
        {
            code[at] = rex; code[at + 1] = opcode; code[at + 2] = modrm;
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at + 3), (int)(target - (0x1000u + (uint)at + 7)));
        }
        Load(0x000, 0x48, 0x8D, 0x0D, SlotHello);   // lea rcx, [rip+..]
        Load(0x010, 0x4C, 0x8B, 0x05, SlotQuote);   // mov r8, [rip+..]
        Load(0x020, 0x48, 0x8B, 0x05, 0x3004);      // not a slot
        Load(0x030, 0x48, 0x8B, 0x45, SlotHello);   // [rbp+disp8]: not RIP-relative
        Load(0x100, 0x48, 0x8D, 0x15, SlotHello);   // lea rdx
        Load(0x200, 0x48, 0x8B, 0x05, SlotQuote);   // mov rax
        Load(0x210, 0x49, 0x8B, 0x0D, SlotQuote);   // mov rcx (REX.WB)
        Load(0x300, 0x4D, 0x8D, 0x05, SlotOther);   // lea r8 (REX.WRB)
        return Pe64([(".text", 0x1000, code, 0x60000020), (".data", 0x3000, new byte[0x200], 0xC0000040)]);
    }

    /// <summary>A minimal PE32+ (x64) file with the given sections; raw data starts at 0x200, aligned to 0x200.</summary>
    internal static byte[] Pe64(IReadOnlyList<(string Name, uint Rva, byte[] Data, uint Characteristics)> sections)
    {
        const int fileAlign = 0x200;
        var raw = new List<(int Offset, int Size)>();
        int at = fileAlign;
        foreach (var s in sections) { int size = (s.Data.Length + fileAlign - 1) / fileAlign * fileAlign; raw.Add((at, size)); at += size; }
        var image = new byte[at];
        var w = image.AsSpan();
        w[0] = (byte)'M'; w[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(w[0x3C..], 0x40);
        int pe = 0x40;
        "PE\0\0"u8.CopyTo(w[pe..]);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(pe + 4)..], 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(pe + 6)..], (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(pe + 20)..], 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(pe + 22)..], 0x2022);
        int opt = pe + 24;
        BinaryPrimitives.WriteUInt16LittleEndian(w[opt..], 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(w[(opt + 24)..], 0x180000000);
        BinaryPrimitives.WriteUInt32LittleEndian(w[(opt + 32)..], 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(w[(opt + 36)..], fileAlign);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(opt + 48)..], 6);
        uint end = sections.Max(s => s.Rva + (uint)s.Data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(w[(opt + 56)..], (end + 0xFFF) & ~0xFFFu);
        BinaryPrimitives.WriteUInt32LittleEndian(w[(opt + 60)..], fileAlign);
        BinaryPrimitives.WriteUInt16LittleEndian(w[(opt + 68)..], 2);
        BinaryPrimitives.WriteUInt32LittleEndian(w[(opt + 108)..], 16);
        int sh = opt + 0xF0;
        for (int i = 0; i < sections.Count; i++, sh += 40)
        {
            var s = sections[i];
            Encoding.ASCII.GetBytes(s.Name).CopyTo(w[sh..]);
            BinaryPrimitives.WriteUInt32LittleEndian(w[(sh + 8)..], (uint)s.Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(w[(sh + 12)..], s.Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(w[(sh + 16)..], (uint)raw[i].Size);
            BinaryPrimitives.WriteUInt32LittleEndian(w[(sh + 20)..], (uint)raw[i].Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(w[(sh + 36)..], s.Characteristics);
            s.Data.CopyTo(w[raw[i].Offset..]);
        }
        return image;
    }

    private Env LoadDummy() => new(Path.Combine(_dummyDir, Path.GetFileName(Env.FixturePath)));

    private static (SearchTools Search, Il2CppTools Il2Cpp, Il2CppStringService Strings) Tools(Env env)
    {
        var strings = new Il2CppStringService(env.Workspace, env.Il2Cpp);
        return (new SearchTools(env.Workspace, env.Search, env.Il2Cpp, strings, env.Pager),
                new Il2CppTools(env.Workspace, env.Il2Cpp, new Il2CppExporter(env.Il2Cpp), strings, env.Pager), strings);
    }

    [Fact]
    public void ReadsEverySectionOfScriptJson()
    {
        WriteDump(binary: false);
        var path = Path.Combine(_dump, "script.json");
        var methods = new List<(ScriptMethod Method, long Offset)>();
        var strings = new List<ScriptString>();
        var metadata = new List<ScriptMetadata>();
        var metadataMethods = new List<ScriptMetadataMethod>();
        var addresses = new List<ulong>();
        new ScriptJsonReader
        {
            Method = (m, o) => methods.Add((m, o)), String = strings.Add, Metadata = metadata.Add, MetadataMethod = metadataMethods.Add, Address = addresses.Add,
        }.Read(path);

        Assert.Equal(5, methods.Count);
        Assert.Equal(new ScriptMethod(4096, "Fixture.Native.NativeThing$$First",
            "void Fixture_Native_NativeThing__First (Fixture_Native_NativeThing_o* __this, const MethodInfo* method);", "vii"), methods[0].Method);
        Assert.Equal(631462417553368870UL, methods[4].Method.Address);
        Assert.Equal(new ScriptString(12288, "hello \u0001world"), Assert.Single(strings));
        Assert.Equal(new ScriptMetadata(20480, "Fixture.Native.NativeThing_TypeInfo", "Fixture_Native_NativeThing_c*"), Assert.Single(metadata));
        Assert.Equal(new ScriptMetadataMethod(20488, "Method$Fixture.Native.NativeThing.First()", 4096), Assert.Single(metadataMethods));
        Assert.Equal([4096UL, 4352, 4608, 4864, 8192], addresses);

        // Offsets lead back to the same records.
        using var file = File.OpenHandle(path);
        foreach (var (m, offset) in methods) Assert.Equal(m, ScriptJsonReader.ReadMethodAt(file, offset));

        // Only subscribed sections are materialized; signatures can be skipped.
        var names = new List<ScriptMethod>();
        new ScriptJsonReader { Method = (m, _) => names.Add(m), MethodSignatures = false }.Read(path);
        Assert.All(names, m => Assert.Null(m.Signature));

        var literals = ScriptJsonReader.ReadStringLiterals(WriteLiteralsOnly());
        Assert.Equal(["hello \u0001world", "say \"hi\"", "other hello", "unused hello"], literals.Select(l => l.Value));
        Assert.Equal([SlotHello, SlotQuote, SlotOther, SlotUnused], literals.Select(l => (uint)l.Address));
    }

    private string WriteLiteralsOnly()
    {
        WriteDump(binary: false, script: false);
        return Path.Combine(_dump, "stringliteral.json");
    }

    /// <summary>Records across buffer refills, and a single token larger than the read buffer.</summary>
    [Fact]
    public void StreamsFilesLargerThanTheBuffer()
    {
        var path = _dir.File("big.json");
        var longName = new string('n', 3 << 20);
        using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
        {
            w.Write("{\"ScriptMethod\":[");
            for (int i = 0; i < 40_000; i++)
                w.Write($"{(i > 0 ? "," : "")}{{\"Address\":{i + 1},\"Name\":\"{(i == 20_000 ? longName : $"T$$M{i}")}\",\"Signature\":\"s\\u00e9{i}\",\"TypeSignature\":\"v\"}}");
            w.Write("],\"Addresses\":[");
            w.Write(string.Join(",", Enumerable.Range(1, 40_000)));
            w.Write("]}");
        }
        var methods = new List<(ScriptMethod, long)>();
        int addresses = 0;
        new ScriptJsonReader { Method = (m, o) => methods.Add((m, o)), Address = _ => addresses++ }.Read(path);
        Assert.Equal(40_000, methods.Count);
        Assert.Equal(40_000, addresses);
        Assert.Equal(longName, methods[20_000].Item1.Name);
        Assert.Equal("s\u00e939999", methods[^1].Item1.Signature);
        using var file = File.OpenHandle(path);
        Assert.Equal(methods[39_999].Item1, ScriptJsonReader.ReadMethodAt(file, methods[39_999].Item2));
        Assert.Equal(longName, ScriptJsonReader.ReadMethodAt(file, methods[20_000].Item2).Name);

        var script = Il2CppScript.Load(path);
        Assert.Equal(40_000, script.FunctionStarts.Length);
        Assert.Equal("T$$M41", Assert.Single(script.MethodsAt(42)).Name);
    }

    [Fact]
    public void LocatesDumpFilesAndKeepsAScriptIndex()
    {
        Assert.Null(Il2CppDumpFiles.Locate(_dummyDir));
        WriteDump();
        var files = Il2CppDumpFiles.Locate(_dummyDir)!;
        Assert.Equal(Path.GetFullPath(_dump), files.Directory);
        Assert.NotNull(files.ScriptJson);
        Assert.NotNull(files.StringLiteralJson);
        Assert.Equal(Path.Combine(Path.GetFullPath(_dump), "GameAssembly.dll"), files.GameAssembly);

        var script = Il2CppScript.Load(files.ScriptJson!);
        Assert.Equal([0x1000u, 0x1100, 0x1200, 0x1300, 0x2000], script.FunctionStarts);
        Assert.Equal(4, script.MethodCount);
        Assert.Equal(1, script.DroppedAddresses); // beyond 32 bits
        Assert.Equal(["Fixture.Native.NativeThing$$Shared<int>", "Fixture.Native.NativeThing$$Shared<uint>"], script.MethodsAt(0x1200).Select(m => m.Name));
        Assert.StartsWith("int32_t", script.MethodsAt(0x1200)[0].Signature);
        Assert.Empty(script.MethodsAt(0x1300));
        Assert.Equal(0x1100u, script.FunctionContaining(0x10FF + 2));
        Assert.Null(script.FunctionContaining(0xFFF));
        Assert.Null(script.FunctionContaining(0x2000 + (uint)Il2CppService.MaxFunctionSpan));
    }

    [Fact]
    public void FindsRipRelativeLoadsInX64Code()
    {
        var path = _dir.File("GameAssembly.dll");
        File.WriteAllBytes(path, BuildImage());
        var sections = NativeCodeScanner.Sections(path);
        Assert.Equal([".text", ".data"], sections.Select(s => s.Name));
        Assert.True(sections[0].Executable);
        var found = new List<(uint Site, uint Target)>();
        NativeCodeScanner.FindRipRelative(path, sections, 0x3000, 0x3018, (s, t) => found.Add((s, t)), default);
        Assert.Equal([(0x1000u, SlotHello), (0x1010, SlotQuote), (0x1020, 0x3004), (0x1100, SlotHello), (0x1200, SlotQuote), (0x1210, SlotQuote), (0x1300, SlotOther)], found);

        File.WriteAllBytes(path, [.. File.ReadAllBytes(path).Select((b, i) => i == 0x44 ? (byte)0x4C : i == 0x45 ? (byte)0x01 : b)]); // machine i386
        Assert.Contains("only x64", Assert.Throws<ToolError>(() => NativeCodeScanner.Sections(path)).Message);
    }

    [Fact]
    public async Task SearchStringsListsLiteralsAndTheMethodsLoadingThem()
    {
        WriteDump();
        using var env = LoadDummy();
        var (search, il2cpp, strings) = Tools(env);

        var text = await search.SearchStrings("hello");
        Assert.StartsWith("3 occurrences (0 in IL and constants, 3 Il2Cpp string literals):", text);
        Assert.Contains("4 literals from", text);
        Assert.Contains("6 loads of 3 literals in 4 functions", text);
        Assert.Contains("""
              "hello \u0001world"
                  Il2Cpp literal, slot RVA 0x3000; loaded by 2 functions:
                  in Fixture.Native.NativeThing::First()  RVA 0x1000  [TestFixture] 0x
            """.Replace("\r\n", "\n").Replace("\n", Environment.NewLine), text);
        Assert.Contains("in Fixture.Native.NativeThing::Second()  RVA 0x1100  [TestFixture]", text);
        Assert.Contains("""
              "other hello"
                  Il2Cpp literal, slot RVA 0x3010; loaded by 1 function:
                  in function at RVA 0x1300 (no method name in the dump)
            """.Replace("\r\n", "\n").Replace("\n", Environment.NewLine), text);
        Assert.Contains("\"unused hello\"" + Environment.NewLine + "      Il2Cpp literal, slot RVA 0x3018; no code loads it", text);

        var quote = await search.SearchStrings("say*");
        Assert.Contains("in Fixture.Native.NativeThing::First()  RVA 0x1000  [TestFixture]", quote);
        Assert.Contains("Fixture.Native.NativeThing$$Shared<int>  RVA 0x1200 x2 (script.json; no dummy method starts here) and 1 more names sharing this code", quote);

        // Paging over literals, and the per-literal cap.
        var page = await search.SearchStrings("hello", limit: 1, offset: 1, usesPerLiteral: 0);
        Assert.Contains("(showing 2-2)", page);
        Assert.Contains("\"other hello\"", page);
        Assert.DoesNotContain("\"hello", page);
        Assert.Contains("… 1 more functions", page);
        Assert.Contains("[More: call again with offset=2]", page);

        // The method's literals, and a literal slot address.
        var info = await il2cpp.GetIl2CppInfo("Fixture.Native.NativeThing::First");
        Assert.Contains("string literals loaded by its native code: 2", info);
        Assert.Contains("\"hello \\u0001world\"  slot RVA 0x3000", info);
        Assert.Contains("\"say \\\"hi\\\"\"  slot RVA 0x3008", info);
        Assert.Contains("string literal slot: \"other hello\"", await il2cpp.FindMethodByAddress("0x3010"));
        Assert.Contains("exact start: Fixture.Native.NativeThing::First()", await il2cpp.FindMethodByAddress("0x1000"));

        var dump = Assert.Single(env.Workspace.Read(() => strings.DumpsFor(env.Workspace.Assemblies))).Dump;
        Assert.Equal([(1, 2)], strings.LiteralsUsedBy(dump, 0x1200));
    }

    [Fact]
    public async Task WithoutTheBinaryOnlyTheLiteralIndexIsAvailable()
    {
        WriteDump(binary: false);
        using var env = LoadDummy();
        var (search, il2cpp, _) = Tools(env);
        var text = await search.SearchStrings("hello");
        Assert.Contains("code references unknown: no GameAssembly.dll next to the dump", text);
        Assert.Contains("Il2Cpp literal, slot RVA 0x3000" + Environment.NewLine, text);
        Assert.Contains("string literals: unknown (no GameAssembly.dll next to the dump)", await il2cpp.GetIl2CppInfo("Fixture.Native.NativeThing::First"));
    }

    [Fact]
    public async Task ScopeLimitsLiteralsToTheirUsers()
    {
        WriteDump();
        using var env = LoadDummy();
        // A second copy of the dummy set: the scope then holds only some of the dump's assemblies.
        var other = Path.Combine(_dummyDir, "Other.dll");
        File.Copy(Env.FixturePath, other);
        env.Workspace.Load(other);
        var (search, _, _) = Tools(env);
        var all = await search.SearchStrings("hello");
        Assert.Contains("3 Il2Cpp string literals", all);
        Assert.Contains("[TestFixture#2]", all);
        var one = await search.SearchStrings("hello", assembly: "TestFixture");
        Assert.Contains("1 Il2Cpp string literal)", one); // the unused literal and the unnamed function's are left out
        Assert.DoesNotContain("other hello", one);
    }

    [Fact]
    public async Task DummyDllsWithoutDumpFilesGetAHint()
    {
        using var env = LoadDummy();
        var (search, _, _) = Tools(env);
        Assert.Contains("put the dump's stringliteral.json", await search.SearchStrings("hello"));
        using var managed = new Env(Env.ConsumerPath);
        Assert.Equal("No string literals match 'zzz-none'.", await Tools(managed).Search.SearchStrings("zzz-none"));
    }

    /// <summary>
    /// A real Il2CppDumper dump (NDM_IL2CPP_STRINGS_DIR: a DummyDll folder with stringliteral.json / script.json beside
    /// it, and optionally GameAssembly.dll): literal and reference counts, timings and retained memory.
    /// </summary>
    [RequiresRealDataFact(RealData.Il2CppStringsDir)]
    [Trait("Speed", "Slow")]
    public void RealDump()
    {
        var output = _output;
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(RealData.Path(RealData.Il2CppStringsDir), false);
        var il2cpp = new Il2CppService(ws);
        var sw = Stopwatch.StartNew();
        ws.Read(() => ws.Assemblies.Sum(a => il2cpp.GetIndex(a).Count));
        output.WriteLine($"dummy address index: {sw.ElapsedMilliseconds} ms");

        var strings = new Il2CppStringService(ws, il2cpp);
        long before = GC.GetTotalMemory(true);
        sw.Restart();
        var dump = Assert.Single(ws.Read(() => strings.DumpsFor(ws.Assemblies))).Dump;
        int literals = dump.Values.Length;
        output.WriteLine($"{literals} literals ({dump.Values.Distinct().Count()} distinct) in {dump.LiteralLoadTime.TotalMilliseconds:F0} ms");
        Assert.True(literals > 0);
        var refs = dump.References;
        output.WriteLine($"script.json: {dump.Script?.FunctionStarts.Length} function starts, {dump.Script?.MethodCount} methods in {dump.Script?.LoadTime.TotalMilliseconds:F0} ms");
        output.WriteLine($"index built in {sw.ElapsedMilliseconds} ms, retained {(GC.GetTotalMemory(true) - before) / (1 << 20)} MB");
        if (refs != null)
        {
            sw.Restart();
            var methods = ws.Read(() => strings.MethodsByRva(dump));
            output.WriteLine($"function -> method map: {methods.Count} methods in {sw.ElapsedMilliseconds} ms, retained {(GC.GetTotalMemory(true) - before) / (1 << 20)} MB in all");
            sw.Restart();
            int withMethod = 0, scriptOnly = 0;
            var matches = ws.Read(() => strings.Search(_ => true, ws.Assemblies, default));
            foreach (var m in matches)
            {
                if (m.Uses!.Any(u => u.Methods.Count > 0)) withMethod++;
                else if (m.Uses!.Any(u => dump.Script!.MethodsAt(u.Function).Count > 0)) scriptOnly++;
            }
            output.WriteLine($"all literals with their users in {sw.ElapsedMilliseconds} ms");
            output.WriteLine($"references (script.json and scan) {refs.ScanTime.TotalMilliseconds:F0} ms: {refs.Sites.Length} loads of {refs.ReferencedLiterals} literals ({100.0 * refs.ReferencedLiterals / literals:F1}%) in {refs.Functions} functions");
            output.WriteLine($"literals with a dummy-DLL method: {withMethod} ({100.0 * withMethod / literals:F1}%); only script.json names: {scriptOnly}");
            Assert.True(refs.ReferencedLiterals > literals / 2);
        }
        else output.WriteLine($"no code references: {dump.ReferenceProblem}");
        GC.KeepAlive(dump);
    }
}
