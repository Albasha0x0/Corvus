using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Native.Code;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>get_native_type over the PDB fixture (<see cref="PdbTypeFixture"/>), a synthetic RTTI image and an Il2Cpp dump.</summary>
public sealed class NativeTypeInfoTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly TempDir _dir = new();
    private readonly Env _env = new();
    private readonly NativeCodeService _code;
    private readonly NativeTypeInfoTools _tools;
    private readonly string _image;

    public NativeTypeInfoTests(ITestOutputHelper output)
    {
        _output = output;
        _code = new NativeCodeService(_env.Workspace, _env.Options, null, new AnnotationStore(_dir.File("ann")));
        _ = new PdbService(_code); // reads the PDB beside the image during the index build
        _tools = new NativeTypeInfoTools(_env.Workspace, _code);
        _image = PdbTypeFixture.Image(_dir);
    }

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    private async Task<(string Text, NativeTypeInfoTools.NativeTypeReport Report)> Get(string? name = null, string? id = null, string? address = null, string? at = null,
        int depth = 0, string? format = null, int offset = 0, int limit = 200, string? source = null)
    {
        var collector = StructuredOutput.Begin();
        var text = await _tools.GetNativeType(_image, name, id, address, at, depth, source, format, offset, limit);
        _output.WriteLine(text);
        return (text, Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(collector.Value));
    }

    private static string Row(NativeTypeField f) => $"+0x{f.Offset:X} {f.Size} {f.Name} {f.Type} {f.Kind}";

    [Fact]
    public async Task Struct_by_name_with_padding_alignment_and_ids()
    {
        var (text, r) = await Get("Player");
        var t = r.Type!;
        Assert.Equal(("struct", "Player", "pdb", 0x40L, 8L, false), (t.Kind, t.Name, t.Source, t.Size, t.Alignment, t.Packed));
        Assert.Equal(["+0x0 12 header Header member", "+0xC 12 pos Vec member", "+0x18 12 val Value member", "+0x24 16 scores int[4] member",
            "+0x34 4 <padding 0> unsigned char[4] padding", "+0x38 8 next Player * member"], t.Fields.Select(Row));
        Assert.Equal(t.Id, t.Fields[5].TypeId is { } next ? (await Get(id: next)).Report.Type!.Referenced : null); // the pointer leads back to Player
        Assert.Contains("Fields (6; offset  size  name  type  [id]):", text);

        // case-insensitive, and ids drill down
        Assert.Equal(t.Id, (await Get("player")).Report.Type!.Id);
        var header = (await Get(id: t.Fields[0].TypeId)).Report.Type!;
        Assert.Equal(["+0x0 2 magic unsigned short member", "+0x2 1 version unsigned char member", "+0x3 1 <padding 0> unsigned char[1] padding",
            "+0x4 4 kind Color member", "+0x8 4 urgent unsigned int member", "+0x8 4 retries unsigned int member"], header.Fields.Select(Row));
        Assert.Equal([(0, 1), (1, 3)], header.Fields.Where(f => f.BitSize != null).Select(f => (f.BitOffset!.Value, f.BitSize!.Value)));
    }

    [Fact]
    public async Task Names_resolve_exactly_or_list_candidates_or_report_ambiguity()
    {
        var (text, r) = await Get("lay");
        Assert.Null(r.Type);
        Assert.Equal(["pdb:PPlayer", r.Candidates.Single(c => c.Name == "Player").Id], r.Candidates.Select(c => c.Id).Order().Reverse());
        Assert.Contains("2 type(s) contain 'lay'", text);

        var e = await Assert.ThrowsAsync<ToolError>(() => Get("Dup"));
        Assert.Equal(ErrorCode.Ambiguous, e.Code);
        Assert.Matches(@"2 types are named 'Dup': pdb:0x[0-9A-F]+ \(struct, 4 bytes, pdb\); pdb:0x[0-9A-F]+ \(struct, 8 bytes, pdb\)", e.Message);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Get("NoSuchType"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Get("Player", id: "pdb:0x1001"))).Code);

        var opaque = (await Get("Opaque")).Report.Type!;
        Assert.True(opaque.ForwardOnly);
        Assert.Contains(opaque.Notes, n => n.Contains("forward declaration", StringComparison.Ordinal));

        // a typedef of a pointer, and one whose name is its tag's is the struct itself
        var pplayer = (await Get("PPlayer")).Report.Type!;
        Assert.Equal(("typedef", 8L), (pplayer.Kind, pplayer.Size));
        Assert.Equal("Player *", (await Get(id: pplayer.Referenced)).Report.Type!.Name);
    }

    [Fact]
    public async Task Field_paths_descend_through_arrays_unions_bit_fields_and_pointers()
    {
        Assert.Equal(["scores[3]"], (await Get("Player", at: "0x30")).Report.Paths.Select(p => p.Path));
        Assert.Equal(["val.i", "val.f", "val.v.x"], (await Get("Player", at: "0x18")).Report.Paths.Select(p => p.Path));
        var game = (await Get("Game", at: "0xD8")).Report;
        var y = Assert.Single(game.Paths);
        Assert.Equal(("players[3].pos.y", "float", 0xD8L, 0L), (y.Path, y.Type, y.Offset, y.Remainder));
        Assert.Equal(["header.urgent (bits 0..0)", "header.retries (bits 1..3)"], (await Get("Player", at: "0x8")).Report.Paths.Select(p => p.Path));
        Assert.Equal(["<padding 0>"], (await Get("Player", at: "0x35")).Report.Paths.Select(p => p.Path));
        // [[p+38h]+0Ch]: through the next pointer
        Assert.Equal(["next->pos.x"], (await Get("Player", at: "0x38.0xC")).Report.Paths.Select(p => p.Path));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Get("Player", at: "0x24.0x0"))).Code);
    }

    /// <summary>Writes little-endian values into the fixture image at RVAs of its .data section, before the image loads.</summary>
    private void Patch(params (uint Rva, byte[] Bytes)[] writes)
    {
        var bytes = File.ReadAllBytes(_image);
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
        {
            var data = pe.PEHeaders.SectionHeaders.First(s => s.Name == ".data");
            foreach (var (rva, value) in writes) value.CopyTo(bytes, data.PointerToRawData + (int)(rva - (uint)data.VirtualAddress));
        }
        File.WriteAllBytes(_image, bytes);
    }

    [Fact]
    public async Task Read_gives_field_values_from_the_image_bytes()
    {
        const uint player = PdbTypeFixture.GameRva + 8;
        Patch((PdbTypeFixture.GameRva, BitConverter.GetBytes(3)), (player, BitConverter.GetBytes((ushort)0x5A4D)), (player + 2, [7]),
            (player + 4, BitConverter.GetBytes(3)), (player + 8, BitConverter.GetBytes(0b1011u)), (player + 0xC, BitConverter.GetBytes(1.5f)),
            (player + 0x24, [.. BitConverter.GetBytes(10), .. BitConverter.GetBytes(-2), .. BitConverter.GetBytes(30), .. BitConverter.GetBytes(40)]),
            (player + 0x38, BitConverter.GetBytes(0x140000000UL + PdbTypeFixture.GameRva)));
        // pointer values are named from the code index once it is built (a read does not wait for it)
        await _code.Index(_env.Workspace.LoadAny(_image).Native!, null, default);

        var collector = StructuredOutput.Begin();
        var text = await _tools.GetNativeType(_image, name: "Player", address: $"rva:0x{player:X}", depth: 2, read: true);
        _output.WriteLine(text);
        var r = Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(collector.Value);
        string Value(string field) => r.Type!.Fields.Single(f => f.Name == field).Value!;
        Assert.Equal($"0x{0x140000000 + player:X}", r.ReadAddress);
        Assert.Equal("23117 (0x5A4D)", Value("header.magic"));
        Assert.Equal("7", Value("header.version"));
        Assert.Equal("Red | Green (3)", Value("header.kind"));
        Assert.Equal(("1", "5"), (Value("header.urgent"), Value("header.retries")));
        Assert.Equal("1.5", Value("pos.x"));
        Assert.Equal("{10, -2, 30, 40}", Value("scores"));
        Assert.Equal("0x140003010 (g_Game)", Value("next"));
        Assert.Contains("pos.x  float  = 1.5", text);

        // a typed address reads its owner from the start; a plain name needs an address
        Assert.Null((await Get(address: "g_Game")).Report.Type!.Fields.Single(f => f.Name == "count").Value);
        var owner = StructuredOutput.Begin();
        await _tools.GetNativeType(_image, address: $"rva:0x{player:X}", read: true);
        var game = Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(owner.Value);
        Assert.Equal(("0x140003010", "3"), (game.ReadAddress, game.Type!.Fields.Single(f => f.Name == "count").Value));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.GetNativeType(_image, name: "Player", read: true))).Code);
        var color = StructuredOutput.Begin();
        await _tools.GetNativeType(_image, name: "Color", address: $"rva:0x{player + 4:X}", read: true);
        Assert.Equal("Red | Green (3)", Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(color.Value).Value);

        // read_bytes type= reads scalars and strings without a type source
        var tools = new NativeTools(_env.Workspace, _env.Pager, _code);
        var ints = await tools.ReadBytes(_image, $"rva:0x{player + 0x24:X}", length: 4, type: "i32");
        _output.WriteLine(ints);
        Assert.Contains("4 x i32", ints);
        Assert.Contains($"{0x140000000 + player + 0x28:X}  -2", ints);
        Assert.Contains("1.5", await tools.ReadBytes(_image, $"rva:0x{player + 0xC:X}", type: "float"));
        Assert.Contains("0x140003010 (g_Game)", await tools.ReadBytes(_image, $"rva:0x{player + 0x38:X}", type: "Player *"));
        Assert.Contains("\"MZ", await tools.ReadBytes(_image, "rva:0x0", type: "string"));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.ReadBytes(_image, "rva:0x0", type: "Player"))).Code);
    }

    [Fact]
    public async Task List_globals_merges_pdb_data_user_names_and_user_types()
    {
        var tools = new NativeCodeTools(_env.Workspace, _code, _env.Pager);
        await tools.ListGlobals(_image); // loads the image and its PDB
        var native = _env.Workspace.Read(() => _env.Workspace.Natives[0]);
        _code.Annotations(native).SetName(0x3150, "sample_flag");
        _code.Annotations(native).ChangeUserTypes(l => l.WithType(0x3150, "int").WithAnalysis(new(0x3160, "data", null, "dword[2]")));
        var collector = StructuredOutput.Begin();
        var text = await tools.ListGlobals(_image);
        _output.WriteLine(text);
        var list = Assert.IsType<GlobalList>(collector.Value);
        var game = Assert.Single(list.Items, g => g.Name == "g_Game");
        Assert.Equal(("0x140003010", "Game", 0x108L, ".data", "pdb"), (game.Address, game.Type, game.Size, game.Section, string.Join(",", game.Sources)));
        var flag = Assert.Single(list.Items, g => g.Address == "0x140003150");
        Assert.Equal(("sample_flag", "int", "user"), (flag.Name, flag.Type, string.Join(",", flag.Sources)));
        Assert.Contains(list.Items, g => g.Address == "0x140003160" && g.Type == "dword[2]");
        // code is not a global
        Assert.DoesNotContain(list.Items, g => g.Section == ".text");

        var filtered = StructuredOutput.Begin();
        await tools.ListGlobals(_image, filter: "sample", section: ".DATA");
        Assert.Equal(["sample_flag"], Assert.IsType<GlobalList>(filtered.Value).Items.Select(g => g.Name));
    }

    [Fact]
    public async Task Typed_address_inside_a_global_gives_the_field_path()
    {
        var (text, r) = await Get(address: $"0x{0x140000000 + PdbTypeFixture.GameRva + 0xD8:X}");
        Assert.Equal(("g_Game", "0x140003010", "Game"), (r.Owner, r.OwnerAddress, r.Type!.Name));
        Assert.Equal("players[3].pos.y", Assert.Single(r.Paths).Path);
        Assert.Contains("is in g_Game (starts at 0x140003010)", text);
        Assert.Equal(1, r.Type.GlobalsOfType);
        Assert.Equal(["g_Game at 0x140003010"], r.Type.Globals);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Get(address: "rva:0x1000"))).Code);

        var resolve = new NativeTools(_env.Workspace, _env.Pager, _code);
        var inside = await resolve.ResolveAddress(_image, $"rva:0x{PdbTypeFixture.GameRva + 0xDA:X}");
        _output.WriteLine(inside);
        Assert.Contains("typed data: g_Game+0xDA = g_Game.players[3].pos.y (float, +0x2 into it)", inside);
        Assert.Contains("typed data: g_Game = g_Game.count (int)", await resolve.ResolveAddress(_image, "g_Game"));
        Assert.DoesNotContain("typed data", await resolve.ResolveAddress(_image, $"rva:0x{PdbTypeFixture.GameRva + 0x108:X}"));
    }

    [Fact]
    public async Task Enums_functions_classes_and_formats()
    {
        var color = (await Get("Color")).Report.Type!;
        Assert.Equal(["Red=0x1", "Green=0x2", "Blue=0x4"], color.Enumerators.Select(e => $"{e.Name}={e.Hex}"));
        Assert.True(color.FlagsLike);
        Assert.True(NativeTypeCatalog.FlagsLike([0, 1, 2, 4, 6]));
        Assert.False(NativeTypeCatalog.FlagsLike([0, 1, 2, 3]));
        Assert.False(NativeTypeCatalog.FlagsLike([1, 2, 3, 4]));
        Assert.False(NativeTypeCatalog.FlagsLike([1, 2, 5]));

        var proc = (await Get(id: "pdb:0x1001")).Report.Type!;
        Assert.Equal("function", proc.Kind);
        Assert.Equal(("int", "__cdecl", "Player *, int"), (proc.Function!.Return, proc.Function.Convention, string.Join(", ", proc.Function.Parameters.Select(p => p.Type))));

        var derived = (await Get("Derived")).Report.Type!;
        Assert.Equal(("class", "Base", 0L), (derived.Kind, Assert.Single(derived.Bases).Name, derived.Bases[0].Offset));
        Assert.Equal("base", derived.Fields[0].Kind);
        Assert.Equal(["+0x0 8 __vftable void * vfptr", "+0x8 4 a int member", "+0xC 4 <padding 0> unsigned char[4] padding"],
            (await Get("Base")).Report.Type!.Fields.Select(Row));
        Assert.Contains("static", (await Get("Game")).Report.Type!.Fields.Select(f => f.Kind));

        var (c, _) = await Get("Player", format: "c");
        Assert.Contains("struct Player // 0x40 bytes\n{\n  /* +0x0 */ Header header;\n", c);
        Assert.Contains("  /* +0x24 */ int scores[4];\n", c);
    }

    [Fact]
    public async Task Depth_expands_by_value_members_and_fields_page()
    {
        var player = (await Get("Player", depth: 1)).Report.Type!;
        Assert.Contains("header.magic", player.Fields.Select(f => f.Name));
        Assert.Contains(player.Fields, f => f is { Name: "val.v", Offset: 0x18 });
        Assert.DoesNotContain(player.Fields, f => f.Name.StartsWith("next.", StringComparison.Ordinal)); // pointers are not followed
        Assert.DoesNotContain(player.Fields, f => f.Name.StartsWith("val.v.", StringComparison.Ordinal)); // one level only
        var game = (await Get("Game", depth: 2)).Report;
        Assert.Contains(game.Type!.Fields, f => f is { Name: "players[0].pos.y", Offset: 0x18 });
        Assert.Contains(game.Type.Notes, n => n.Contains("element [0]", StringComparison.Ordinal));

        var page = (await Get("Player", offset: 2, limit: 2)).Report;
        Assert.Equal(["val", "scores"], page.Type!.Fields.Select(f => f.Name));
        Assert.Equal((6, true, 2), (page.Type.TotalFields, page.Truncated, page.Offset));
    }

    [Fact]
    public async Task Source_filters_and_engine_needs_one()
    {
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Get("Player", source: "rtti"))).Code);
        Assert.Equal("pdb", (await Get("Player", source: "pdb")).Report.Type!.Source);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => Get("Player", source: "engine"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => Get("Player", source: "nope"))).Code);
    }

    /// <summary>Compilands repeat a type under their own unique names: identical layouts are one candidate, different ones stay ambiguous.</summary>
    [Fact]
    public async Task Identical_definitions_from_other_compilands_collapse()
    {
        var t = new TpiBuilder();
        foreach (var unique in new[] { "?A0x1", "?A0x2", "?A0x3" })
            t.Struct("Lambda", t.FieldList(TpiBuilder.Member(0x74, 0, "captured")), 4, unique: unique);
        t.Struct("Pair", t.FieldList(TpiBuilder.Member(0x74, 0, "a")), 4, unique: "?A0x4");
        t.Struct("Pair", t.FieldList(TpiBuilder.Member(0x74, 0, "b")), 4, unique: "?A0x5");
        var msf = PdbBuilder.Sample().Msf();
        msf.Streams[2] = t.Build();
        File.WriteAllBytes(_dir.File("dups.pdb"), msf.Build());
        var pdb = Corvus.Native.Pdb.PdbFile.Open(_dir.File("dups.pdb"));
        var native = _env.Workspace.LoadAny(_image).Native!;
        var c = new NativeTypeCatalog.Context
        {
            Native = native, PdbFile = pdb, Model = Corvus.Native.Pdb.PdbTypeModel.Of(pdb, 8), Sources = new HashSet<string> { NativeTypeCatalog.Pdb },
        };
        var catalog = new NativeTypeCatalog(_env.Workspace);
        var lambda = (await catalog.Find(c, "Lambda", 0, 10, default)).View!();
        Assert.Contains("2 identical definition(s) from other compilands: pdb:0x", Assert.Single(lambda.Notes, n => n.Contains("identical", StringComparison.Ordinal)));
        Assert.Equal(ErrorCode.Ambiguous, (await Assert.ThrowsAsync<ToolError>(() => catalog.Find(c, "Pair", 0, 10, default))).Code);
    }

    /// <summary>RTTI classes of the synthetic image: bases with offsets, vftables with named slots, and a slot address typed.</summary>
    [Fact]
    public async Task Rtti_classes_and_vftable_addresses()
    {
        var (image, vftables) = VirtualCallTests.Synthetic();
        var native = new Corvus.Core.LoadedNative("synthetic", "synthetic", image);
        var catalog = new NativeTypeCatalog(_env.Workspace);
        var c = new NativeTypeCatalog.Context { Native = native, Index = NativeCodeIndex.Build(image), Sources = new HashSet<string> { NativeTypeCatalog.Rtti } };
        var found = await catalog.Find(c, "Multi", 0, 10, default);
        var multi = found.View!();
        Assert.Equal(("class", "rtti", -1L), (multi.Kind, multi.Source, multi.Size));
        Assert.Equal(["Base@0", "Second@8"], multi.Bases.Select(b => $"{b.Name}@{b.Offset}"));
        Assert.All(multi.Bases, b => Assert.StartsWith("rtti:0x", b.Id));
        Assert.Equal([(0L, 2), (8L, 1)], multi.Vftables.Select(v => (v.SubobjectOffset, v.Slots)));
        Assert.Equal(["0 +0x0", "1 +0x8"], multi.Vftables[0].Entries.Select(e => $"{e.Index} +0x{e.Offset:X}"));
        Assert.Equal(["+0x0 8 __vftable vfptr", "+0x8 8 __vftable vfptr"], multi.Fields.Select(f => $"+0x{f.Offset:X} {f.Size} {f.Name} {f.Kind}"));
        Assert.Equal(multi.Id, (await catalog.Get(c, multi.Id, default)).Id);

        var typed = catalog.AtAddress(c, vftables["Multi"] + 8, default)!;
        Assert.Equal("Multi", typed.Type.Name);
        Assert.Contains("slot 1 ->", typed.Note);
        Assert.Null(catalog.AtAddress(c, 0x1000, default));
    }

    /// <summary>Il2Cpp layouts after the names are applied: the object header, dumped offsets, statics, and the metadata slot typed.</summary>
    [Fact]
    public async Task Il2cpp_layouts_after_apply()
    {
        var (dll, binary) = Il2CppNativeNamesTests.CreateDump(_dir);
        using var env = new Env(dll);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann2")));
        var native = env.Workspace.LoadAny(binary).Native!;
        new Il2CppNativeNames(env.Il2Cpp, env.Il2CppNavigator, code).Apply(native, await code.Index(native, null, default), env.Workspace.Assemblies, default);
        var catalog = new NativeTypeCatalog(env.Workspace, code);
        var c = await catalog.Open(native, new HashSet<string> { NativeTypeCatalog.Il2Cpp }, null, false, default);
        var view = (await catalog.Find(c, "Fixture.Native.NativeThing", 0, 10, default)).View!();
        Assert.Equal(("il2cpp:Fixture.Native.NativeThing", "class", "il2cpp"), (view.Id, view.Kind, view.Source));
        Assert.Equal(["+0x0 klass header", "+0x8 monitor header", "+0x10 Counter member"], view.Fields.Select(f => $"+0x{f.Offset:X} {f.Name} {f.Kind}"));
        Assert.Equal("Counter", Assert.Single(NativeTypeCatalog.Paths(c, view, 0x12, default)).Path);
        Assert.Equal(view.Id, (await catalog.Find(c, "NativeThing", 0, 10, default)).View!().Id); // the short name

        var typed = catalog.AtAddress(c, 0x5000, default)!;
        Assert.Equal(("Fixture.Native.NativeThing", "Fixture.Native.NativeThing_TypeInfo"), (typed.Type.Name, typed.Owner));
    }
}

/// <summary>get_native_type on an MSVC-built image with its PDB (<see cref="PdbIdaTypesTests.Source"/>).</summary>
[Trait("Speed", "Slow")]
public sealed class NativeTypeInfoMsvcTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public async Task Compiler_layouts_match_the_source()
    {
        if (PdbIdaTypesTests.Build(_dir) is not { } built) { output.WriteLine("no MSVC build tools"); return; }
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(_dir.File("ann")));
        _ = new PdbService(code);
        var tools = new NativeTypeInfoTools(env.Workspace, code);
        var collector = StructuredOutput.Begin();
        var text = await tools.GetNativeType(built.Exe, "Packet", at: "0x24", depth: 1);
        output.WriteLine(text);
        var report = Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(collector.Value);
        var packet = report.Type!;
        Assert.Equal(0x38L, packet.Size);
        Assert.Contains(packet.Fields, f => f is { Name: "header.retries", Offset: 8, BitSize: 3, BitOffset: 1 });
        Assert.Contains(packet.Fields, f => f is { Name: "sender_name", Offset: 0x18, Type: "char[16]" });
        Assert.Contains(packet.Fields, f => f is { Name: "checksum", Offset: 0x30, Type: "int (__cdecl *)(const Packet *)" });
        Assert.Equal("sender_name[12]", Assert.Single(report.Paths).Path);
        var kind = (await tools.GetNativeType(built.Exe, "PacketKind"));
        Assert.Contains("0x7  7  PK_BYE", kind);
        Assert.Contains("[pdb:", await tools.GetNativeType(built.Exe, "PPacket"));
    }
}

/// <summary>get_native_type reading the engine's types: a struct declared in IDA, by source=engine and by auto once the analysis is complete.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeTypeInfoIdaTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [IdaFact]
    public async Task Declared_struct_reads_back_with_offsets()
    {
        var image = NativeIdaProviderTests.System64;
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new Corvus.Native.Providers.Ida.IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var user = new NativeUserTypePush(code);
        workspace.LoadAny(image);
        await new NativeTypeTools(workspace, engines, user, code).DeclareNativeTypes(image, "struct SampleTyped { int length; struct { short a, b; } pair; char data[16]; };");
        var tools = new NativeTypeInfoTools(workspace, code, engines, user);

        var collector = StructuredOutput.Begin();
        var text = await tools.GetNativeType(image, "SampleTyped", source: "engine", at: "0x6");
        output.WriteLine(text);
        var report = Assert.IsType<NativeTypeInfoTools.NativeTypeReport>(collector.Value);
        Assert.Equal(("ida:SampleTyped", "ida", 24L), (report.Type!.Id, report.Type.Source, report.Type.Size));
        Assert.Equal(["+0x0 length", "+0x4 pair", "+0x8 data"], report.Type.Fields.Select(f => $"+0x{f.Offset:X} {f.Name}"));
        Assert.Equal("pair", Assert.Single(report.Paths).Path);
        // auto reads the engine once its analysis is complete, for names the other sources lack
        Assert.Contains("[ida:SampleTyped, ida]", await tools.GetNativeType(image, "SampleTyped"));
        Assert.Contains("ida:SampleTyped", await tools.GetNativeType(image, "mpleTyp", source: "engine"));
    }
}
