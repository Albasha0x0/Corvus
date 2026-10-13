using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The user's types in IDA through the tools, on a real system DLL: applied, shown in pseudocode, replayed after a worker
/// restart, pushed into a new database from the sidecar, and kept over recovered types.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeIdaTypeTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private static string Image => NativeIdaProviderTests.System64;

    internal sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeAnalysisTools Analysis, NativeTypeTools Types,
        NativeCodeTools CodeTools, EngineScriptTools Scripts)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public async Task<IdaSession> Session() => (IdaSession)await Engines.Session(Native, null, null, default);
    }

    /// <summary>A server on <paramref name="cache"/> (its IDA databases) and the shared annotation sidecars.</summary>
    private Rig Setup(string cache, bool scripting = false, string annotations = "annotations")
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false, IdaScripting = scripting };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File(annotations)));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File(cache) }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        var types = new NativeTypePush();
        var user = new NativeUserTypePush(code);
        workspace.LoadAny(Image);
        return new Rig(workspace, code, engines, new NativeAnalysisTools(workspace, engines, pager, names, code, types, user),
            new NativeTypeTools(workspace, engines, user, code, names, types), new NativeCodeTools(workspace, code, pager, null, engines, names, types, user),
            new EngineScriptTools(workspace, engines, options, code, names, types, user));
    }

    [IdaFact]
    public async Task Prototype_and_global_type_apply_replay_after_a_restart_and_reach_a_new_database()
    {
        var rig = Setup("cache-a");
        var prototype = "int __fastcall CheckSumMappedFile(void *base, unsigned int length, unsigned int *headerSum, unsigned int *checkSum)";
        output.WriteLine(await rig.Types.SetNativeType(Image, Function, prototype));
        var text = await rig.Analysis.DecompileNative(Image, Function);
        output.WriteLine(text);
        Assert.Contains("unsigned int *headerSum", text);

        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data");
        var global = await rig.Types.SetNativeType(Image, $"rva:0x{data.Rva:X}", "unsigned int[4]");
        Assert.Contains("unsigned int[4]", global);
        var bad = await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeType(Image, Function, "int f(no_such_type_t *p)"));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Types.Count);

        // the edits are journaled: a worker killed before any save replays them
        var session = await rig.Session();
        await WorkerKill.KillAsync(session);
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        Assert.Contains("headerSum", (await session.DecompileAsync(rva)).Text);

        // another database (another IDA cache) gets them from the sidecar
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
        var fresh = Setup("cache-b");
        var again = await EngineMeta.WithPushes(() => fresh.Analysis.DecompileNative(Image, Function));
        Assert.Contains("user types: pushed 2 item(s)", again);
        Assert.Contains("unsigned int *headerSum", again);

        // clearing restores IDA's own type
        await fresh.Types.SetNativeType(Image, Function, "");
        Assert.DoesNotContain("headerSum", await fresh.Analysis.DecompileNative(Image, Function));
        Assert.Single(fresh.Code.Annotations(fresh.Native).UserTypes.Types);
    }

    /// <summary>The first local the pseudocode declares with a decompiler-made name (v8: "unsigned int v8; // esi").</summary>
    private static string FirstDefaultLocal(string pseudocode) =>
        System.Text.RegularExpressions.Regex.Match(pseudocode, @"^\s+[\w ]+?\*?\b(v\d+); //", System.Text.RegularExpressions.RegexOptions.Multiline) is { Success: true } m
            ? m.Groups[1].Value : throw new Xunit.Sdk.XunitException("no vN local in\n" + pseudocode);

    [IdaFact]
    public async Task Locals_rename_and_retype_stay_one_edit_and_reach_a_new_database()
    {
        var rig = Setup("cache-l");
        var local = FirstDefaultLocal(await rig.Analysis.DecompileNative(Image, Function));
        output.WriteLine(await rig.Types.SetNativeLocal(Image, Function, local, newName: "sample_count", type: "unsigned __int64"));
        var text = await rig.Analysis.DecompileNative(Image, Function);
        output.WriteLine(text);
        Assert.Contains("unsigned __int64 sample_count", text);
        // named by its new name: the same edit
        await rig.Types.SetNativeLocal(Image, Function, "sample_count", newName: "sample_total");
        var edit = Assert.Single(Assert.Single(rig.Code.Annotations(rig.Native).UserTypes.Locals).Value);
        Assert.Equal((local, "sample_total", "unsigned __int64"), (edit.Local, edit.Name, edit.Type));

        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(Image, Function, "no_such_local", newName: "x"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(Image, Function, "sample_total", newName: "bad name"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(Image, Function, "sample_total"))).Code);

        // journaled: a killed worker replays the edits
        var session = await rig.Session();
        await WorkerKill.KillAsync(session);
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        Assert.Contains("sample_total", (await session.DecompileAsync(rva)).Text);

        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
        var fresh = Setup("cache-m");
        var again = await fresh.Analysis.DecompileNative(Image, Function);
        Assert.Contains("unsigned __int64 sample_total", again);
    }

    [IdaFact]
    public async Task Stack_frame_lists_members_and_locals_and_stack_edits_persist()
    {
        var rig = Setup("cache-s");
        var view = await rig.Types.GetNativeFrame(Image, Function, locals: true);
        output.WriteLine(view);
        Assert.Contains("__return_address", view);
        Assert.Contains("special", view);
        var session = await rig.Session();
        var frame = await session.GetFrameAsync(rig.Native.Image.Exports.First(e => e.Name == Function).Rva);
        var member = frame.Members.First(m => m.Kind == "local" && m.Size >= 4);
        Assert.Contains(frame.Members, m => m.Kind == "special" && m.Offset == frame.ReturnAddressOffset);

        output.WriteLine(await rig.Types.SetNativeStackVar(Image, Function, member.Name, newName: "sample_slot", type: "int"));
        output.WriteLine(await rig.Types.SetNativeStackVar(Image, Function, $"0x{member.Offset:X}", newName: "sample_slot2"));
        var after = await session.GetFrameAsync(frame.StartRva);
        Assert.Equal(("sample_slot2", "int", 4), after.Members.Single(m => m.Offset == member.Offset) is var x ? (x.Name, x.Type, x.Size) : default);
        var edit = Assert.Single(Assert.Single(rig.Code.Annotations(rig.Native).UserTypes.StackVars).Value);
        Assert.Equal((member.Offset, "sample_slot2", "int"), (edit.Offset, edit.Name, edit.Type));
        var special = await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeStackVar(Image, Function, "__return_address", newName: "ret"));
        Assert.Equal(ErrorCode.InvalidArgument, special.Code);

        // a decompiler local addressed by its stack offset
        if (frame.Locals.FirstOrDefault(l => l.Stack != null) is { } stackLocal)
        {
            await rig.Types.SetNativeLocal(Image, Function, $"stack:0x{stackLocal.Stack:X}", newName: "sample_onstack");
            Assert.Contains("sample_onstack", await rig.Analysis.DecompileNative(Image, Function));
        }

        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
        var fresh = Setup("cache-t");
        Assert.Contains("sample_slot2  int  4", await fresh.Types.GetNativeFrame(Image, Function, locals: true));
    }

    [IdaFact]
    public async Task Declared_types_list_win_over_recovered_types_and_reach_a_new_database()
    {
        var rig = Setup("cache-d");
        var declared = await rig.Types.DeclareNativeTypes(Image, "struct SamplePacket { int length; char data[16]; };\nenum SampleKind { SampleA = 1, SampleB = 2 };");
        output.WriteLine(declared);
        Assert.Contains("SamplePacket", declared);
        Assert.Contains("SampleKind", declared);
        var bad = await Assert.ThrowsAsync<ToolError>(() => rig.Types.DeclareNativeTypes(Image, "struct SampleBad { unknown_t x; };"));
        output.WriteLine(bad.Message);
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Contains("unknown_t", bad.Message);
        Assert.Single(rig.Code.Annotations(rig.Native).UserTypes.Declarations);

        var list = await rig.Types.ListNativeTypes(Image, filter: "sample");
        output.WriteLine(list);
        Assert.Contains("struct SamplePacket  20 bytes  2 members", list);
        Assert.Contains("enum SampleKind", list);
        Assert.DoesNotContain("SampleBad", await rig.Types.ListNativeTypes(Image, filter: "sample", kind: "struct"));
        var detail = await rig.Types.ListNativeTypes(Image, name: "SamplePacket");
        output.WriteLine(detail);
        Assert.Contains("+0x4  data  char[16]  16", detail);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.ListNativeTypes(Image, name: "NoSuchSampleType"))).Code);
        // declared with the database's packing, as a replay declares it: the pointer is 8-aligned
        await rig.Types.DeclareNativeTypes(Image, "struct SampleAligned { short tag; void *next; };");
        var aligned = await rig.Types.ListNativeTypes(Image, name: "SampleAligned");
        output.WriteLine(aligned);
        Assert.Contains("struct SampleAligned, 16 bytes", aligned);
        Assert.Contains("+0x8  next  void *  8", aligned);

        // the declared type is usable, and a recovered type of the same name does not replace it
        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data");
        Assert.Contains("SamplePacket", await rig.Types.SetNativeType(Image, $"rva:0x{data.Rva:X}", "SamplePacket"));
        var session = await rig.Session();
        await session.ApplyTypesAsync(new NativeTypeBatch("struct SamplePacket { char replaced; };", [], [], [], 8));
        Assert.Contains(session.GetTypeAsync("SamplePacket").Result.Members, m => m.Name == "length");

        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
        var fresh = Setup("cache-e");
        Assert.Contains("+0x4  data  char[16]  16", await fresh.Types.ListNativeTypes(Image, name: "SamplePacket"));
    }

    /// <summary>get_native_type through IDA: bit fields with their bits, member comments, the type's alignment and packing.</summary>
    [IdaFact]
    public async Task Engine_type_details_show_bit_fields_comments_and_alignment()
    {
        var rig = Setup("cache-details");
        output.WriteLine(await rig.Types.DeclareNativeTypes(Image, "struct SampleBits { unsigned int lo : 3; unsigned int hi : 5; int whole; }; " +
                                                                  "struct __attribute__((packed)) SamplePacked { char c; int i; };", engine: "ida"));
        var session = await rig.Session();
        var script = await session.RunScriptAsync("import ida_typeinf as ti\nt = ti.tinfo_t()\nt.get_named_type(None, 'SampleBits')\n" +
                                                  "u = ti.udm_t()\nu.name = 'whole'\nidx = t.find_udm(u, ti.STRMEM_NAME)\nt.set_udm_cmt(idx, 'the whole count')\n");
        Assert.Null(script.Error);
        var tools = new NativeTypeInfoTools(rig.Workspace, rig.Code, rig.Engines);
        var bits = await tools.GetNativeType(Image, name: "SampleBits", source: "engine");
        output.WriteLine(bits);
        Assert.Contains("align 4", bits);
        Assert.Matches(@"\+0x0\s+4\s+lo : 3 \(bit 0\)", bits);
        Assert.Matches(@"\+0x0\s+4\s+hi : 5 \(bit 3\)", bits);
        Assert.Contains("// the whole count", bits);
        var packed = await tools.GetNativeType(Image, name: "SamplePacked", source: "engine");
        output.WriteLine(packed);
        Assert.Contains("packed", packed);
    }

    [IdaFact]
    public async Task Struct_member_references_come_from_typed_operands_and_pseudocode()
    {
        var rig = Setup("cache-f");
        var text = await rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64::OptionalHeader", engine: "ida");
        output.WriteLine(text);
        Assert.Contains("References to member _IMAGE_NT_HEADERS64::OptionalHeader (+0x18", text);
        Assert.Matches(@"0x[0-9A-F]+  (read|address|write)  CheckSumMappedFile\+0x[0-9A-F]+", text);
        // by offset: the member covering it
        Assert.Contains("_IMAGE_NT_HEADERS64::OptionalHeader", await rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64+0x20", engine: "ida"));
        // a miss points at the engine's types, not at the function list
        var member = await Assert.ThrowsAsync<ToolError>(() => rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64::NoSuchMember", engine: "ida"));
        Assert.Equal(ErrorCode.NotFound, member.Code);
        Assert.Contains("OptionalHeader", member.Message);
        Assert.Equal("list_native_types name=_IMAGE_NT_HEADERS64 lists its members with offsets; pass Type::member or Type+offset", member.Remediation);
        var type = await Assert.ThrowsAsync<ToolError>(() => rig.CodeTools.FindXrefs(Image, "std::NoSuchType::member", engine: "ida"));
        Assert.Equal(ErrorCode.NotFound, type.Code);
        Assert.StartsWith("list_native_types filter=NoSuchType kind=struct", type.Remediation);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64::Signature", engine: "ours"))).Code);
        // scope=all: every function's pseudocode, continued by calling again until complete; the typed scan's uses are among them
        string all = "";
        for (int call = 0; call < 40 && !all.Contains("; complete", StringComparison.Ordinal); call++)
            all = await rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64::OptionalHeader", engine: "ida", scope: "all", limit: 5000);
        output.WriteLine(all.Split('\n')[1]);
        Assert.Contains("pseudocode of all functions scanned: ", all);
        Assert.Contains("; complete", all);
        static HashSet<string> Rows(string t) => t.Split('\n').Where(l => l.StartsWith("0x", StringComparison.Ordinal)).Select(l => l.Trim()).ToHashSet();
        Assert.Subset(Rows(all), Rows(text));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.CodeTools.FindXrefs(Image, "_IMAGE_NT_HEADERS64::OptionalHeader", engine: "ida", scope: "some"))).Code);
        // an ordinary name still resolves as an address
        Assert.Contains("References to", await rig.CodeTools.FindXrefs(Image, Function));
    }

    [IdaFact]
    public async Task Python_runs_in_the_worker_only_when_allowed_and_refreshes_cached_pseudocode()
    {
        var off = Setup("cache-p");
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => off.Scripts.IdaPython(Image, "1 + 1"))).Code);
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();

        var rig = Setup("cache-q", scripting: true);
        var count = await rig.Scripts.IdaPython(Image, "len(list(idautils.Functions()))");
        output.WriteLine(count);
        Assert.True(int.Parse(count.Split("Result: ")[1].Split('\n')[0]) > 50, count);
        await rig.Scripts.IdaPython(Image, "x = 20\nprint('set', x)");
        Assert.Contains("Result: 42", await rig.Scripts.IdaPython(Image, "x * 2 + 2"));
        var raised = await Assert.ThrowsAsync<ToolError>(() => rig.Scripts.IdaPython(Image, "1 / 0"));
        Assert.Contains("ZeroDivisionError", raised.Message);
        Assert.Contains("ZeroDivisionError", await rig.Scripts.IdaPython(Image, "1 / 0", allowError: true));
        Assert.Contains("NameError", await rig.Scripts.IdaPython(Image, "x", reset: true, allowError: true));
        var printed = await rig.Scripts.IdaPython(Image, "print('hello from ida')");
        Assert.Contains("stdout:\nhello from ida", printed);
        // a script file, the database saved afterwards
        var script = _dir.File("script.py");
        File.WriteAllText(script, "print('y' * 500)\n7 * 6");
        var printedFile = await rig.Scripts.IdaPython(Image, file: script);
        Assert.Contains("Result: 42", printedFile);
        Assert.Contains(new string('y', 500), printedFile);
        var database = Directory.EnumerateFiles(_dir.File("cache-q"), "*.i64", SearchOption.AllDirectories).Single();
        var before = File.GetLastWriteTimeUtc(database);
        await Task.Delay(1100);
        Assert.Contains("Database saved.", await rig.Scripts.IdaPython(Image, "1", persist: true));
        Assert.True(File.GetLastWriteTimeUtc(database) > before);

        // a script's change shows in the next decompilation (the cached text is made again)
        Assert.DoesNotContain("scriptedBase", await rig.Analysis.DecompileNative(Image, Function));
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        await rig.Scripts.IdaPython(Image, $"idc.SetType(base + 0x{rva:X}, 'int __fastcall f(void *scriptedBase, unsigned int n, unsigned int *a, unsigned int *b)')");
        Assert.Contains("scriptedBase", await rig.Analysis.DecompileNative(Image, Function));
    }

    [IdaFact]
    public async Task Database_export_writes_a_copy_and_the_worker_keeps_its_own()
    {
        var rig = Setup("cache-e");
        await rig.Types.DeclareNativeTypes(Image, "struct SampleShipped { int a; };");
        var export = new EngineExportTools(rig.Workspace, rig.Engines, rig.Code);
        var target = _dir.File("out/copy");
        var (_, call) = await EngineMeta.Run(() => export.ExportEngineDatabase(Image, target));
        var r = Assert.IsType<EngineExportTools.DatabaseExport>(call.Record);
        output.WriteLine($"{r.Path} {r.Bytes}");
        Assert.Equal(Path.GetFullPath(target + ".i64"), r.Path);
        Assert.True(new FileInfo(r.Path).Length > 1000 && r.Bytes == new FileInfo(r.Path).Length);
        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => export.ExportEngineDatabase(Image, r.Path))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => export.ExportEngineDatabase(Image, _dir.File("x.idb")))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => export.ExportEngineDatabase(Image, _dir.File("y.i64"), engine: "ghidra"))).Code); // Ghidra writes .gzf

        // the worker still saves to its own database, not to the copy
        var session = await rig.Session();
        var own = session.DatabasePath;
        var copyTime = File.GetLastWriteTimeUtc(r.Path);
        await Task.Delay(1100);
        await session.SaveAsync();
        Assert.Equal(own, session.DatabasePath);
        Assert.Equal(copyTime, File.GetLastWriteTimeUtc(r.Path));
        Assert.Contains(r.Path, await export.ExportEngineDatabase(Image, r.Path, overwrite: true));
        Assert.Empty(Directory.EnumerateFiles(Path.GetDirectoryName(r.Path)!, "*.tmp"));

        // a path past IDA's 259 characters is written through a short one and moved, or refused before IDA works
        var deep = Path.Combine(_dir.File("long"), new string('d', 120), new string('e', 120), "copy.i64");
        Assert.True(deep.Length > 300);
        try
        {
            Assert.Contains(deep, await export.ExportEngineDatabase(Image, deep));
            Assert.True(new FileInfo(deep).Length > 1000);
        }
        catch (ToolError e)
        {
            Assert.Equal(ErrorCode.IoError, e.Code);
            Assert.Contains("characters", e.Message);
        }
        Assert.Contains((await session.GetTypeAsync("SampleShipped")).Members, m => m.Name == "a");
    }

    [IdaFact]
    public async Task Exported_IDA_script_applies_every_user_type_to_another_database()
    {
        var rig = Setup("cache-x");
        var local = FirstDefaultLocal(await rig.Analysis.DecompileNative(Image, Function));
        await rig.Types.DeclareNativeTypes(Image, "struct SampleExported { int a; int b; };");
        await rig.Types.SetNativeType(Image, Function, "int __fastcall CheckSumMappedFile(void *exportedBase, unsigned int n, unsigned int *a, unsigned int *b)");
        await rig.Types.SetNativeLocal(Image, Function, local, newName: "sample_exported_local");
        var frame = await (await rig.Session()).GetFrameAsync(rig.Native.Image.Exports.First(e => e.Name == Function).Rva);
        var member = frame.Members.First(m => m.Kind == "local");
        await rig.Types.SetNativeStackVar(Image, Function, member.Name, newName: "sample_exported_slot", type: "int");
        var script = _dir.File("apply.py");
        File.WriteAllText(script, Native.Annotations.AnnotationExport.Render(rig.Code.Annotations(rig.Native), Native.Annotations.AnnotationExport.Format.Ida));
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();

        // another database without the sidecar: the script alone brings the edits
        var other = Setup("cache-y", scripting: true, annotations: "other-annotations");
        var run = await other.Scripts.IdaPython(Image, $"exec(open({System.Text.Json.JsonSerializer.Serialize(script)}).read())");
        output.WriteLine(run);
        Assert.DoesNotContain("not applied", run);
        Assert.Contains("4 user type(s)", run);
        var text = await other.Analysis.DecompileNative(Image, Function);
        Assert.Contains("exportedBase", text);
        Assert.Contains("sample_exported_local", text);
        var session = await other.Session();
        Assert.Contains((await session.GetFrameAsync(frame.StartRva)).Members, m => m.Name == "sample_exported_slot" && m.Type == "int");
        Assert.Contains((await session.GetTypeAsync("SampleExported")).Members, m => m.Name == "b");
    }

    [IdaFact]
    public async Task Recovered_types_never_replace_user_types()
    {
        var rig = Setup("cache-c");
        var session = await rig.Session();
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        var user = await session.ApplyUserTypesAsync(new NativeUserTypeBatch([], [new NativePrototype(rva, "int __fastcall f(void *userBase, int userLength)")], [], []));
        Assert.True(user.Items[0].Applied, user.Items[0].Error);
        var pushed = await session.ApplyTypesAsync(new NativeTypeBatch(null, [new NativePrototype(rva, "int __fastcall f(char *pushedBase)")], [], [], 8));
        Assert.Equal(0, pushed.Typed);
        var text = (await session.DecompileAsync(rva)).Text;
        Assert.Contains("userBase", text);
        Assert.DoesNotContain("pushedBase", text);
    }

    [IdaFact]
    public async Task A_class_push_decompiles_nothing_and_methods_sent_alone_are_typed_by_decompiling()
    {
        var rig = Setup("cache-d");
        var session = await rig.Session();
        var functions = (await session.ListFunctionsAsync()).Where(f => (f.Flags & (NativeFunctionFlags.Thunk | NativeFunctionFlags.Library)) == 0).Take(150).ToList();
        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name.Contains("data")).Rva;
        var owners = functions.Select(f => new NativeMethodOwner(f.StartRva, "SampleLazy")).ToList();
        var push = await session.ApplyTypesAsync(new NativeTypeBatch(null, [],
            [new NativeClassType("SampleLazy", [new NativeVftableType(0, data, functions.Take(2).Select(f => f.StartRva).ToList())], [])], owners, 8));
        output.WriteLine($"push: {push.MethodsTyped} typed, skips {string.Join(", ", push.MethodSkips.Select(kv => $"{kv.Key} {kv.Value}"))}, {push.Elapsed.TotalSeconds:0.00} s");
        Assert.False(push.MethodSkips.ContainsKey("no_type")); // no decompilation tried
        var alone = await session.ApplyTypesAsync(new NativeTypeBatch(null, [], [], owners, 8));
        output.WriteLine($"alone: {alone.MethodsTyped} typed, skips {string.Join(", ", alone.MethodSkips.Select(kv => $"{kv.Key} {kv.Value}"))}");
        Assert.False(alone.MethodSkips.ContainsKey("deferred"));
        Assert.Equal(push.MethodSkips.GetValueOrDefault("deferred"), alone.MethodsTyped + alone.MethodSkips.GetValueOrDefault("no_type") + alone.MethodSkips.GetValueOrDefault("no_arguments")
                                                                       + alone.MethodSkips.GetValueOrDefault("rejected"));
    }
}
