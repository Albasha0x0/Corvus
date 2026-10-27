using System.Text.Json;
using Corvus.Native.Annotations;

namespace Corvus.Tests;

/// <summary>Annotation sidecars: an unusable sidecar is never silently replaced; writes are atomic and concurrent writers never tear the file.</summary>
public class AnnotationStoreTests : IDisposable
{
    private const string Sha = "ab12";
    private readonly TempDir _dir = new();
    private readonly List<string> _notices = [];
    public void Dispose() => _dir.Dispose();

    private string Root => _dir.File("ann");
    private string Sidecar => Path.Combine(Root, Sha + ".json");

    private NativeAnnotations Open(AnnotationStore? store = null) =>
        new(store ?? new AnnotationStore(Root), _dir.File("image.dll"), Sha, 0x180000000, n => { lock (_notices) _notices.Add(n); });

    private void WriteSidecar(string text)
    {
        Directory.CreateDirectory(Root);
        File.WriteAllText(Sidecar, text);
    }

    private static JsonElement Parse(string file) => JsonDocument.Parse(File.ReadAllText(file)).RootElement;

    [Fact]
    public void Corrupt_sidecar_is_moved_aside_and_reported()
    {
        WriteSidecar("{ \"names\": { \"1000\": \"Kept\" ");
        var ann = Open();
        var notice = Assert.Single(_notices);
        Assert.Contains("moved to", notice);
        Assert.Null(ann.WriteBlocked);

        ann.SetName(0x2000, "Fresh");
        var aside = Assert.Single(Directory.GetFiles(Root, Sha + ".json.corrupt-*"));
        Assert.Equal("{ \"names\": { \"1000\": \"Kept\" ", File.ReadAllText(aside));
        Assert.Contains(aside, notice);
        Assert.Equal("Fresh", Parse(Sidecar).GetProperty("names").GetProperty("2000").GetString());
    }

    [Fact]
    public void Locked_sidecar_is_left_untouched_and_writes_are_blocked()
    {
        WriteSidecar("{\"sha256\":\"ab12\",\"names\":{\"1000\":\"Original\"},\"comments\":{}}");
        var before = File.ReadAllBytes(Sidecar);
        NativeAnnotations ann;
        using (new FileStream(Sidecar, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            ann = Open();
            ann.SetName(0x3000, "InMemory");
        }
        Assert.Equal("InMemory", ann.NameAt(0x3000));
        Assert.Single(_notices);
        if (OperatingSystem.IsWindows())
        {
            Assert.NotNull(ann.WriteBlocked);
            Assert.Contains("left untouched", _notices[0]);
            Assert.Equal(before, File.ReadAllBytes(Sidecar));
        }
        else
        {
            // POSIX locks do not stop a rename: the sidecar is moved aside intact instead.
            var kept = Directory.GetFiles(Root, Sha + ".json*").Select(File.ReadAllBytes);
            Assert.Contains(kept, b => b.AsSpan().SequenceEqual(before));
        }
    }

    [Fact]
    public void Sidecar_without_format_version_loads_and_is_rewritten_with_it()
    {
        WriteSidecar("{\"path\":\"x\",\"sha256\":\"ab12\",\"imageBase\":0,\"names\":{\"1000\":\"Legacy\"},\"comments\":{\"1000\":\"note\"}}");
        var ann = Open();
        Assert.Empty(_notices);
        Assert.Equal("Legacy", ann.NameAt(0x1000));
        Assert.Equal("note", ann.CommentAt(0x1000));
        ann.SetComment(0x1000, "changed");
        var doc = Parse(Sidecar);
        Assert.Equal(1, doc.GetProperty("formatVersion").GetInt32());
        Assert.Equal("Legacy", doc.GetProperty("names").GetProperty("1000").GetString());
    }

    [Fact]
    public void User_types_round_trip_as_version_2_and_without_them_the_file_stays_version_1()
    {
        var ann = Open();
        ann.ChangeUserTypes(l => l.WithDeclarations("struct S { int a; };").WithType(0x1000, "int __fastcall f(S *s)")
            .WithLocal(new(0x1000, "v3", null, "count", null)).WithLocal(new(0x1000, "count", 0x28, null, "unsigned int"))
            .WithStackVar(new(0x1000, 0x20, "buffer", "char[16]")));
        Assert.Equal(2, Parse(Sidecar).GetProperty("formatVersion").GetInt32());

        var again = Open().UserTypes;
        Assert.Equal(["struct S { int a; };"], again.Declarations);
        Assert.Equal("int __fastcall f(S *s)", again.Types[0x1000]);
        // The second edit names the variable by its new name: one edit, identity kept.
        Assert.Equal(new Corvus.Native.Providers.NativeLocalEdit(0x1000, "v3", 0x28, "count", "unsigned int"), Assert.Single(again.Locals[0x1000]));
        Assert.Equal(new Corvus.Native.Providers.NativeStackVarEdit(0x1000, 0x20, "buffer", "char[16]"), Assert.Single(again.StackVars[0x1000]));
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);

        ann.ChangeUserTypes(_ => UserTypeLayer.Empty);
        ann.SetName(0x1000, "kept");
        Assert.Equal(1, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
        Assert.False(Parse(Sidecar).TryGetProperty("locals", out _));
    }

    [Fact]
    public void Header_declares_types_prototypes_by_current_name_and_globals()
    {
        var ann = Open();
        ann.SetName(0x1000, "Parse");
        ann.SetName(0x3000, "Untyped");
        ann.ChangeUserTypes(l => l.WithDeclarations("struct S { int a; }").WithType(0x1000, "int __fastcall old(S *s)").WithType(0x2000, "void __cdecl(int)")
            .WithType(0x5000, "S *").WithType(0x6000, "int[4]").WithType(0x7000, "void (*)(int)"));
        var names = new Dictionary<uint, string> { [0x1000] = "Parse", [0x2000] = "ns::Init", [0x3000] = "Untyped" };
        var header = AnnotationHeader.Render(ann, r => names.GetValueOrDefault(r), r => r is 0x1000 or 0x2000 or 0x3000);
        Assert.Contains("#pragma once", header);
        Assert.Contains("struct S { int a; };", header);
        Assert.Contains("int __fastcall Parse(S *s); // rva 0x1000", header);
        Assert.Contains("void __cdecl ns__Init(int); // rva 0x2000", header);
        Assert.Contains("// Untyped: rva 0x3000, no prototype set", header);
        Assert.Contains("extern S * g_5000; // rva 0x5000", header);
        Assert.Contains("extern int g_6000[4];", header);
        Assert.Contains("extern void (*g_7000)(int);", header);
        Assert.Equal("int f(int)", AnnotationHeader.Prototype("int(int)", "f"));
        Assert.Equal("unsigned int f(void)", AnnotationHeader.Prototype("unsigned int(void)", "f"));
        Assert.Equal("char * f(void)", AnnotationHeader.Prototype("char *(void)", "f"));
        Assert.Null(AnnotationHeader.Prototype("int", "f"));
        Assert.Equal(AnnotationExport.Format.Header, AnnotationExport.ParseFormat("header"));
    }

    [Fact]
    public void Cleared_locals_and_stack_members_leave_the_layer_and_the_sidecar()
    {
        var ann = Open();
        ann.ChangeUserTypes(l => l.WithLocal(new(0x1000, "v3", 0x28, "count", null)).WithLocal(new(0x1000, "v4", null, "size", "int"))
            .WithStackVar(new(0x1000, 0x20, "buffer", "char[16]")));
        var layer = ann.UserTypes;
        // Found by its first name, by the name it got and by stack offset.
        var count = layer.LocalEdit(0x1000, "count", null)!;
        Assert.Same(count, layer.LocalEdit(0x1000, "v3", null));
        Assert.Same(count, layer.LocalEdit(0x1000, "other", 0x28));
        Assert.Null(layer.LocalEdit(0x2000, "count", null));
        ann.ChangeUserTypes(l => l.WithoutLocal(count).WithoutStackVar(0x1000, 0x20).WithoutStackVar(0x1000, 0x99));
        var again = Open().UserTypes;
        Assert.Equal("size", Assert.Single(again.Locals[0x1000]).Name);
        Assert.Empty(again.StackVars);
        ann.ChangeUserTypes(l => l.WithoutLocal(l.LocalEdit(0x1000, "size", null)!));
        Assert.Empty(Open().UserTypes.Locals);
    }

    [Fact]
    public void Export_carries_user_types_in_the_IDA_script_and_JSON()
    {
        var ann = Open();
        ann.SetName(0x1000, "Parse");
        ann.ChangeUserTypes(l => l.WithDeclarations("struct S { int a; };").WithType(0x1000, "int __fastcall Parse(S *s)")
            .WithLocal(new(0x1000, "v3", 0x28, "count", null)).WithStackVar(new(0x1000, 0x20, null, "char[16]")));
        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.Contains("apply_declare(\"struct S { int a; };\")", ida);
        Assert.Contains("apply_type(0x1000, \"int __fastcall Parse(S *s)\")", ida);
        Assert.Contains("apply_stack(0x1000, 32, None, \"char[16]\")", ida);
        Assert.Contains("apply_local(0x1000, \"v3\", 40, \"count\", None)", ida);
        Assert.Contains("1 name(s), 0 comment(s), 0 pseudocode comment(s) and 4 user type(s)", ida);
        var python = Corvus.Native.Providers.PythonLocator.Find([], []);
        if (python != null)
        {
            var script = _dir.File("apply.py");
            File.WriteAllText(script, ida);
            var check = Corvus.Native.Providers.PythonLocator.RunCapture(python.Executable,
                ["-I", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", script], TimeSpan.FromSeconds(30));
            Assert.True(check.ExitCode == 0, check.Stderr);
        }

        var json = JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement;
        Assert.Equal("struct S { int a; };", json.GetProperty("declarations")[0].GetString());
        Assert.Equal("count", json.GetProperty("locals")[0].GetProperty("name").GetString());
        Assert.Equal(32, json.GetProperty("stackVars")[0].GetProperty("offset").GetInt32());
        Assert.Contains("IDA and JSON exports only", AnnotationExport.Render(ann, AnnotationExport.Format.Ghidra));
    }

    [Fact]
    public void Analysis_edits_keep_their_order_as_version_3_merge_across_writers_and_export()
    {
        var a = Open();
        a.ChangeUserTypes(l => l.WithType(0x5000, "int[4]").WithAnalysis(new(0x4000, "function", 0x4100, null)).WithAnalysis(new(0x5000, "data", null, "dword[8]"))
            .WithAnalysis(new(0x4000, "undefine", null, null)));
        // The later edit at 0x4000 replaced the earlier one and moved to the end; data at 0x5000 dropped the global's user type.
        Assert.Equal([0x5000u, 0x4000u], a.UserTypes.Analysis.Select(x => x.Rva));
        Assert.Empty(a.UserTypes.Types);
        Assert.Equal(3, Parse(Sidecar).GetProperty("formatVersion").GetInt32());

        var b = Open();
        b.ChangeUserTypes(l => l.WithAnalysis(new(0x6000, "code", 0x6010, null)));
        a.ChangeUserTypes(l => l.WithAnalysis(new(0x7000, "data", 0x7010, "string")));
        var merged = Open().UserTypes;
        Assert.Equal([0x5000u, 0x4000u, 0x7000u, 0x6000u], merged.Analysis.Select(x => x.Rva));
        Assert.Equal(new Corvus.Native.Providers.NativeAnalysisEdit(0x7000, "data", 0x7010, "string"), merged.Analysis[2]);
        Assert.Equal(4, merged.Count);

        var ida = AnnotationExport.Render(a, AnnotationExport.Format.Ida);
        Assert.Contains("apply_analysis(0x5000, \"data\", None, \"dword[8]\")", ida);
        Assert.Contains("apply_analysis(0x6000, \"code\", 0x6010, None)", ida);
        Assert.True(ida.IndexOf("apply_analysis(0x4000", StringComparison.Ordinal) < ida.IndexOf("apply_analysis(0x7000", StringComparison.Ordinal));
        var python = Corvus.Native.Providers.PythonLocator.Find([], []);
        if (python != null)
        {
            var script = _dir.File("analysis.py");
            File.WriteAllText(script, ida);
            var check = Corvus.Native.Providers.PythonLocator.RunCapture(python.Executable,
                ["-I", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", script], TimeSpan.FromSeconds(30));
            Assert.True(check.ExitCode == 0, check.Stderr);
        }
        var json = JsonDocument.Parse(AnnotationExport.Render(a, AnnotationExport.Format.Json)).RootElement;
        Assert.Equal("undefine", json.GetProperty("analysis")[1].GetProperty("kind").GetString());

        // Without analysis edits the file is version 2 again, which older builds read.
        a.ChangeUserTypes(_ => UserTypeLayer.Empty.WithType(0x1000, "int"));
        Assert.Equal(2, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
    }

    [Fact]
    public void Operand_formats_round_trip_default_removes_them_and_export()
    {
        var ann = Open();
        ann.ChangeUserTypes(l => l.WithOperand(new(0x1010, 1, "enum", "Magic")).WithOperand(new(0x1010, 0, "hex", null)).WithOperand(new(0x1020, 1, "struct", "Hdr+0x8")));
        ann.ChangeUserTypes(l => l.WithOperand(new(0x1010, 0, "default", null)));
        var again = Open().UserTypes;
        Assert.Equal([(0x1010u, 1), (0x1020u, 1)], again.Operands.Keys.Order());
        Assert.Equal(new Corvus.Native.Providers.NativeOperandEdit(0x1020, 1, "struct", "Hdr+0x8"), again.Operands[(0x1020, 1)]);
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);
        Assert.Equal(3, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
        var batch = again.ToBatch();
        Assert.Equal(2, batch.Operands.Count);
        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.Contains("apply_operand(0x1010, 1, \"enum\", \"Magic\")", ida);
        Assert.Contains("apply_operand(0x1020, 1, \"struct\", \"Hdr+0x8\")", ida);
        var python = Corvus.Native.Providers.PythonLocator.Find([], []);
        if (python != null)
        {
            var script = _dir.File("operands.py");
            File.WriteAllText(script, ida);
            var check = Corvus.Native.Providers.PythonLocator.RunCapture(python.Executable,
                ["-I", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", script], TimeSpan.FromSeconds(30));
            Assert.True(check.ExitCode == 0, check.Stderr);
        }
        Assert.Equal("struct", JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement.GetProperty("operands")[1].GetProperty("display").GetString());
    }

    [Fact]
    public void Enum_members_and_stack_deletes_round_trip_and_export()
    {
        var ann = Open();
        ann.ChangeUserTypes(l => l.WithEnumMember(new("Color", "Red", 1)).WithEnumMember(new("Color", "Gone", null)).WithEnumMember(new("Color", "Red", 0x10))
            .WithStackVar(new(0x2000, 0x20, "buf", "char[8]")).WithStackVar(new(0x2000, 0x20, null, null) { Delete = true }).WithStackVar(new(0x2000, 0x28, "kept", "int")));
        var again = Open().UserTypes;
        Assert.Equal(new Corvus.Native.Providers.NativeEnumMemberEdit("Color", "Red", 0x10), again.EnumMembers[("Color", "Red")]);
        Assert.Null(again.EnumMembers[("Color", "Gone")].Value);
        // A deletion replaced the earlier edit at that offset.
        Assert.Equal([true, false], again.StackVars[0x2000].Select(s => s.Delete));
        Assert.Equal(ann.UserTypes.Stamp, again.Stamp);
        Assert.Equal(3, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
        // An edit after the deletion replaces it again.
        Assert.False(again.WithStackVar(new(0x2000, 0x20, "back", "int")).StackVars[0x2000][0].Delete);

        var ida = AnnotationExport.Render(ann, AnnotationExport.Format.Ida);
        Assert.Contains("apply_enum(\"Color\", \"Gone\", None)", ida);
        Assert.Contains("apply_enum(\"Color\", \"Red\", 16)", ida);
        Assert.Contains("apply_stack_delete(0x2000, 32)", ida);
        Assert.DoesNotContain("apply_stack(0x2000, 32,", ida);
        var python = Corvus.Native.Providers.PythonLocator.Find([], []);
        if (python != null)
        {
            var script = _dir.File("enums.py");
            File.WriteAllText(script, ida);
            var check = Corvus.Native.Providers.PythonLocator.RunCapture(python.Executable,
                ["-I", "-c", "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')", script], TimeSpan.FromSeconds(30));
            Assert.True(check.ExitCode == 0, check.Stderr);
        }
        var json = JsonDocument.Parse(AnnotationExport.Render(ann, AnnotationExport.Format.Json)).RootElement;
        Assert.Equal("Red", json.GetProperty("enumMembers")[1].GetProperty("member").GetString());
        Assert.True(json.GetProperty("stackVars")[0].GetProperty("delete").GetBoolean());
    }

    [Fact]
    public void Newer_format_version_is_left_untouched()
    {
        var text = "{\"formatVersion\":99,\"sha256\":\"ab12\",\"names\":{\"1000\":\"Future\"},\"comments\":{}}";
        WriteSidecar(text);
        var ann = Open();
        Assert.NotNull(ann.WriteBlocked);
        ann.SetName(0x1000, "Mine");
        Assert.Equal(text, File.ReadAllText(Sidecar));
    }

    [Fact]
    public async Task Concurrent_writers_never_tear_the_file_and_keep_each_others_entries()
    {
        var a = Open(new AnnotationStore(Root));
        var b = Open(new AnnotationStore(Root));
        using var stop = new CancellationTokenSource();
        int reads = 0;
        // Its own thread: a pool task can wait longer than the whole test for a pool thread while other tests hold them.
        var reader = Task.Factory.StartNew(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var fs = new FileStream(Sidecar, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    JsonDocument.Parse(fs).Dispose(); // a torn file would throw here
                    Interlocked.Increment(ref reads);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { }
                Thread.Sleep(1); // an open reader blocks a rename over the file on Windows; real readers are occasional
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        Parallel.Invoke(
            () => { for (uint i = 0; i < 20; i++) a.SetName(0x1000 + i * 16, $"A_{i}"); },
            () => { for (uint i = 0; i < 20; i++) b.SetName(0x8000 + i * 16, $"B_{i}"); });
        a.SetComment(0x1000, "last");
        SpinWait.SpinUntil(() => Volatile.Read(ref reads) > 0, TimeSpan.FromSeconds(30)); // the reader may start late on a busy machine
        stop.Cancel();
        await reader;

        Assert.True(_notices.Count == 0, string.Join('\n', _notices));
        Assert.True(Volatile.Read(ref reads) > 0);
        var names = Parse(Sidecar).GetProperty("names");
        for (uint i = 0; i < 20; i++)
        {
            Assert.Equal($"A_{i}", names.GetProperty((0x1000 + i * 16).ToString("x")).GetString());
            Assert.Equal($"B_{i}", names.GetProperty((0x8000 + i * 16).ToString("x")).GetString());
        }
        Assert.Equal(40, a.NameCount); // a's last save took in b's names
        Assert.Empty(Directory.GetFiles(Root, "*.tmp"));
        Assert.Empty(Directory.GetFiles(Root, "*.corrupt-*"));
        if (OperatingSystem.IsWindows()) Assert.Empty(Directory.GetFiles(Root, "*.lock")); // kept on Unix by design
    }

    [Fact]
    public void Interleaved_writers_both_survive_and_refresh_brings_the_other_sides_names()
    {
        var a = Open();
        var b = Open();
        var seen = new List<(uint, string?)>();
        b.MergedFromDisk += (names, _) => seen.AddRange(names);
        a.SetName(0x1000, "FromA");
        b.SetName(0x2000, "FromB");
        Assert.Equal("FromA", b.NameAt(0x1000)); // b's save merged a's name in
        Assert.Contains((0x1000u, (string?)"FromA"), seen);
        Assert.Null(a.NameAt(0x2000));
        a.Refresh();
        Assert.Equal("FromB", a.NameAt(0x2000));
        a.SetComment(0x2000, "seen by a");
        b.Refresh();
        Assert.Equal("seen by a", b.CommentAt(0x2000));
        Assert.Empty(_notices);
        Assert.True(Parse(Sidecar).GetProperty("revision").GetUInt64() >= 3);
    }

    [Fact]
    public void Same_address_different_names_is_a_conflict_and_the_other_name_is_kept_as_a_comment()
    {
        var a = Open();
        var b = Open();
        a.SetName(0x1000, "AName");
        b.SetName(0x1000, "BName");
        Assert.Equal("BName", b.NameAt(0x1000));
        Assert.Contains("[conflict] another process named this 'AName'", b.CommentAt(0x1000));
        var notice = Assert.Single(_notices);
        Assert.Contains("conflict", notice);
        Assert.Contains("AName", notice);
        Assert.Contains("[conflict]", Parse(Sidecar).GetProperty("comments").GetProperty("1000").GetString());
    }

    [Fact]
    public void Removal_in_one_addition_in_the_other_both_persist_and_a_removal_loses_to_a_concurrent_change()
    {
        var a = Open();
        a.SetName(0x1000, "Shared");
        a.SetName(0x3000, "Renamed");
        var b = Open();
        a.SetName(0x1000, null);
        b.SetName(0x2000, "Added");
        var names = Parse(Sidecar).GetProperty("names");
        Assert.False(names.TryGetProperty("1000", out _));
        Assert.Equal("Added", names.GetProperty("2000").GetString());

        a.SetName(0x3000, "RenamedAgain");
        b.SetName(0x3000, null); // b never saw the rename: its removal loses
        Assert.Equal("RenamedAgain", Parse(Sidecar).GetProperty("names").GetProperty("3000").GetString());
        Assert.Equal("RenamedAgain", b.NameAt(0x3000));
    }

    [Fact]
    public void User_types_from_two_writers_are_merged()
    {
        var a = Open();
        var b = Open();
        a.ChangeUserTypes(l => l.WithDeclarations("struct A { int x; };").WithType(0x1000, "int f(A *a)"));
        b.ChangeUserTypes(l => l.WithDeclarations("struct B { int y; };").WithLocal(new(0x2000, "v1", null, "count", null)).WithStackVar(new(0x2000, 8, "buf", "char[8]")));
        var merged = Open().UserTypes;
        Assert.Equal(["struct A { int x; };", "struct B { int y; };"], merged.Declarations);
        Assert.Equal("int f(A *a)", merged.Types[0x1000]);
        Assert.Equal("count", Assert.Single(merged.Locals[0x2000]).Name);
        Assert.Equal("buf", Assert.Single(merged.StackVars[0x2000]).Name);
        Assert.Equal(merged.Stamp, b.UserTypes.Stamp);
        Assert.Equal(2, Parse(Sidecar).GetProperty("formatVersion").GetInt32());
    }

    [Fact]
    public void Whole_document_write_by_an_older_build_is_merged_as_a_change()
    {
        var a = Open();
        a.SetName(0x1000, "Mine");
        // An older build rewrites the whole file without a revision and without a's name.
        WriteSidecar("{\"formatVersion\":1,\"sha256\":\"ab12\",\"names\":{\"2000\":\"Old\"},\"comments\":{}}");
        a.SetName(0x3000, "Next");
        var names = Parse(Sidecar).GetProperty("names");
        Assert.Equal("Old", names.GetProperty("2000").GetString());
        Assert.Equal("Next", names.GetProperty("3000").GetString());
        Assert.False(names.TryGetProperty("1000", out _)); // removed by that writer, not changed here since
    }

    [Fact]
    public void Held_lock_times_out_keeps_the_change_in_memory_and_the_next_save_writes_it()
    {
        var a = Open(new AnnotationStore(Root) { LockTimeout = TimeSpan.FromMilliseconds(200) });
        a.SetName(0x1000, "Before");
        using (new FileStream(Sidecar + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            a.SetName(0x2000, "WhileLocked");
            Assert.Equal("WhileLocked", a.NameAt(0x2000));
        }
        var notice = Assert.Single(_notices);
        Assert.Contains("could not be saved", notice);
        Assert.Contains("timed out", notice);
        Assert.False(Parse(Sidecar).GetProperty("names").TryGetProperty("2000", out _));
        a.SetComment(0x1000, "after");
        Assert.Equal("WhileLocked", Parse(Sidecar).GetProperty("names").GetProperty("2000").GetString());
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task Two_processes_saving_names_concurrently_keep_all_of_them()
    {
        const int PerSide = 500;
        var image = McpProtocolTests.NativeSample(_dir);
        var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(image)));
        // Any address inside the image takes a name.
        const uint Start = 0x200;
        Assert.True(Corvus.Services.NativeCodeScanner.Sections(image).Max(s => s.Rva + s.VirtualSize) > Start + 2 * PerSide);
        await using var server = await ModelContextProtocol.Client.McpClient.CreateAsync(new ModelContextProtocol.Client.StdioClientTransport(new()
        {
            Name = "corvus",
            Command = "dotnet",
            Arguments = [typeof(Corvus.Core.AssemblyWorkspace).Assembly.Location],
            EnvironmentVariables = new Dictionary<string, string?> { ["CORVUS_ANNOTATIONS_DIR"] = Root, ["PATH"] = Tools.CmdPath() },
            ShutdownTimeout = TimeSpan.FromMilliseconds(200),
        }));
        Assert.True((await server.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = image })).IsError != true);
        var here = new NativeAnnotations(new AnnotationStore(Root), image, sha, 0, n => { lock (_notices) _notices.Add(n); });

        var remote = Task.Run(async () =>
        {
            for (uint i = 0; i < PerSide; i++)
            {
                var r = await server.CallToolAsync("rename_native", new Dictionary<string, object?>
                { ["dryRun"] = false,
                    ["image"] = "native.dll", ["address"] = $"rva:0x{Start + i * 2:X}", ["name"] = $"Remote_{i}",
                });
                Assert.True(r.IsError != true, string.Join("\n", r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(c => c.Text)));
            }
        });
        var local = Task.Run(() => { for (uint i = 0; i < PerSide; i++) here.SetName(Start + i * 2 + 1, $"Local_{i}"); });
        await Task.WhenAll(remote, local);

        Assert.True(_notices.Count == 0, string.Join('\n', _notices));
        var names = Parse(Path.Combine(Root, sha + ".json")).GetProperty("names");
        for (uint i = 0; i < PerSide; i++)
        {
            Assert.Equal($"Remote_{i}", names.GetProperty((Start + i * 2).ToString("x")).GetString());
            Assert.Equal($"Local_{i}", names.GetProperty((Start + i * 2 + 1).ToString("x")).GetString());
        }
        // The server's copy converged too: its export carries the names saved by this process.
        var output = _dir.File("export.json");
        var export = await server.CallToolAsync("export_native_annotations", new Dictionary<string, object?> { ["image"] = "native.dll", ["outputPath"] = output, ["format"] = "json" });
        Assert.True(export.IsError != true);
        Assert.Contains($"Local_{PerSide - 1}", File.ReadAllText(output));
    }
}
