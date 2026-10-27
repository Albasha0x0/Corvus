using Corvus.Core;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>symbolize_stack_text over each documented shape, against the fixture assembly and synth.dll.</summary>
public sealed class StackTextTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    private readonly StackTextService _service;
    private readonly LoadedAssembly _fixture;
    private readonly uint _stamp;

    public StackTextTests()
    {
        var synth = _dir.File("synth.dll");
        File.WriteAllBytes(synth, SyntheticCrash.FileImage());
        _stamp = PeFile.Open(synth).Coff.TimeDateStamp;
        _ws.LoadAny(synth);
        _fixture = _ws.Load(Env.FixturePath);
        var code = new NativeCodeService(_ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Native.Annotations.AnnotationStore(_dir.File("ann")));
        _service = new StackTextService(_ws, code);
    }

    public void Dispose()
    {
        _ws.Dispose();
        _dir.Dispose();
    }

    private Task<StackTextService.SymbolizedStack> Run(string text, string format = "auto", string? moduleBases = null) =>
        _service.Symbolize(text, null, format, null, moduleBases, 0, 200, default);

    [Trait("Smoke", "push")]
    [Fact]
    public async Task Dotnet_exception_text_keeps_the_inner_chain()
    {
        var r = await Run("""
            Unhandled exception. System.InvalidOperationException: outer failure
             ---> System.ArgumentException: bad amount (Parameter 'amount')
               at Fixture.Model.Account.Charge(Int32 amount) in C:\src\Model.cs:line 40
               --- End of inner exception stack trace ---
               at Fixture.Model.Account.Charge(Int32 amount, String source) in C:\src\Model.cs:line 47
               at Program.Main(String[] args)
            """);
        Assert.Equal("dotnet", r.Format);
        Assert.Equal("System.InvalidOperationException", r.Exception!.Type);
        Assert.Equal("outer failure", r.Exception.Message);
        Assert.Equal("System.ArgumentException", Assert.Single(r.Exception.Inner).Type);
        Assert.Equal(3, r.Total);
        var inner = r.Items[0];
        Assert.Equal(1, inner.Exception);
        Assert.Equal(_fixture.Id, inner.Assembly);
        Assert.Contains("Charge(int)", inner.Resolved);
        Assert.Equal("unknown", inner.BuildCheck);
        Assert.Contains("no MVID", inner.BuildDetail);
        Assert.StartsWith($"decompile_member assembly={_fixture.Id} member=0x06", inner.NextStep);
        var outer = r.Items[1];
        Assert.Equal(0, outer.Exception);
        Assert.Contains("Charge(int, string)", outer.Resolved);
        Assert.NotEqual(inner.Token, outer.Token);
        // Program is not loaded.
        Assert.Null(r.Items[2].Assembly);
        Assert.Equal(0, r.UnrecognizedLines);
    }

    [Fact]
    public async Task Mono_frames_are_matched_by_module_MVID()
    {
        var mvid = _fixture.Module.Mvid!.Value;
        var other = Guid.NewGuid();
        var unknown = Guid.NewGuid();
        var r = await Run($"""
            NullReferenceException: Object reference not set to an instance of an object
              at Fixture.Model.Account.Charge (System.Int32 amount) [0x0001a] in <{mvid:N}>:0
              at Fixture.Model.Account.Charge (System.Int32 amount, System.String source) [0x00002] in <{other:N}>:0
              at App.Player.Update () [0x00000] in <{unknown:N}>:0
              at (wrapper runtime-invoke) object.runtime_invoke_void (object,intptr,intptr,intptr)
            """);
        Assert.Equal("mono", r.Format);
        Assert.Equal("NullReferenceException", r.Exception!.Type);
        Assert.Equal("match", r.Items[0].BuildCheck);
        Assert.Equal(0x1a, r.Items[0].IlOffset);
        Assert.Equal(_fixture.Id, r.Items[0].Assembly);
        Assert.Equal("mismatch", r.Items[1].BuildCheck);
        Assert.Contains(other.ToString("D"), r.Items[1].BuildDetail);
        Assert.Null(r.Items[2].Resolved);
        Assert.Contains(r.ModulesMissing, m => m.Module.Contains(unknown.ToString("D"), StringComparison.Ordinal) && m.Module.Contains("App.Player", StringComparison.Ordinal));
        Assert.Contains("wrapper", r.Items[3].BuildDetail);
    }

    [Fact]
    public async Task A_Mono_backtrace_uses_the_module_list_for_load_addresses()
    {
        var r = await Run("""
            ========== OUTPUTTING STACK TRACE ==================
            0x00007FF610001005 (synth) Crash
            0x00007FF610001055 (synth) (function-name not available)
            0x00007FFB22221234 (UnityPlayer) [C:\build\Runtime\Main.cpp:42] PlayerMain
            0x0000020012345678 (Mono JIT Code) [Player.cs:12] Fixture.Model.Account:Charge (int)
            ========== END OF STACKTRACE ===========
            C:\App\synth.dll:synth.dll (00007FF610000000), size: 20480 (result: 0), SymType: '-exported-', PDB: '', fileVersion: 1.2.3.4
            C:\App\UnityPlayer.dll:UnityPlayer.dll (00007FFB22220000), size: 1048576 (result: 0), SymType: '-exported-', PDB: '', fileVersion: 2022.3.1.0
            """);
        Assert.Equal("mono", r.Format);
        var crash = r.Items[0];
        Assert.Equal("0x1005", crash.Offset);
        Assert.Equal("Crash+0x5", crash.Resolved);
        // The text's own name agrees.
        Assert.Equal("match", crash.BuildCheck);
        Assert.Equal("synth.dll", crash.Image);
        Assert.StartsWith("decompile_native image=synth.dll address=0x1005", crash.NextStep);
        Assert.StartsWith("Outer+0x", r.Items[1].Resolved);
        var player = Assert.Single(r.ModulesMissing);
        Assert.Equal("UnityPlayer", player.Module);
        Assert.Equal("2022.3.1.0", player.Version);
        Assert.Equal(_fixture.Id, r.Items[3].Assembly);
        // The two banner lines.
        Assert.Equal(2, r.UnrecognizedLines);
    }

    /// <summary>compact folds a run of matching native frames of one image into one row that keeps their names; offset and total count rows.</summary>
    [Fact]
    public async Task Compact_folds_matching_frames_of_one_image()
    {
        const string text = """
            ========== OUTPUTTING STACK TRACE ==================
            0x00007FF610001005 (synth) Crash
            0x00007FF610001006 (synth) Crash
            0x00007FF610001007 (synth) Crash
            0x00007FFB22221234 (UnityPlayer) PlayerMain
            ========== END OF STACKTRACE ===========
            C:\App\synth.dll:synth.dll (00007FF610000000), size: 20480 (result: 0), SymType: '-exported-', PDB: '', fileVersion: 1.2.3.4
            """;
        var full = await _service.Symbolize(text, null, "auto", null, null, 0, 50, false, default);
        Assert.Equal((4, 4), (full.Frames, full.Total));
        var compact = await _service.Symbolize(text, null, "auto", null, null, 0, 50, true, default);
        Assert.Equal((4, 2), (compact.Frames, compact.Total));
        Assert.Equal(["Crash+0x6", "Crash+0x7"], compact.Items[0].Folded);
        Assert.Equal(3, compact.Items[1].Index);
        var second = await _service.Symbolize(text, null, "auto", null, null, 1, 50, true, default);
        Assert.Equal(3, Assert.Single(second.Items).Index);
    }

    /// <summary>An Android tombstone backtrace: frames resolve in the loaded .so whose GNU build id the line names; another build id is another build.</summary>
    [Fact]
    public async Task Android_tombstone_frames_resolve_by_build_id()
    {
        byte[] id = [0x3c, 0x5c, 0x01, 0x9f, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x12, 0x34];
        var so = _dir.File("libapp.so");
        File.WriteAllBytes(so, new NativeFormats.ElfWriter { BuildId = id, Symbols = [new("Crash", NativeFormats.ElfWriter.TextRva, 8)] }.Build());
        var image = _ws.LoadAny(so).Native!;
        var hex = Convert.ToHexStringLower(id);
        var r = await Run($"""
            *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
            ABI: 'arm64'
            signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000010
            backtrace:
                  #00 pc 0000000000001004  /data/app/~~abc==/com.example-1/lib/arm64/libapp.so (Crash+4) (BuildId: {hex})
                  #01 pc 0000000000001004  /data/app/~~abc==/com.example-1/lib/arm64/libapp.so (BuildId: deadbeef)
                  #02 pc 000000000004f1a4  /apex/com.android.runtime/lib64/bionic/libc.so (abort+164) (BuildId: 0f00ba44)
            """);
        Assert.Equal("android", r.Format);
        Assert.Equal(3, r.Total);
        var crash = r.Items[0];
        Assert.Equal(("libapp.so", "0x1004", "Crash+0x4", image.Id, "match"), (crash.Module, crash.Offset, crash.Resolved, crash.Image, crash.BuildCheck));
        Assert.Equal("mismatch", r.Items[1].BuildCheck);
        Assert.Contains("deadbeef", r.Items[1].BuildDetail);
        var libc = Assert.Single(r.ModulesMissing);
        Assert.Equal("libc.so", libc.Module);
        Assert.Contains("BuildId 0f00ba44", r.Items[2].NextStep);
    }

    [Fact]
    public void An_android_symbol_that_starts_like_a_build_id_stays_the_symbol()
    {
        var frames = StackTextFormats.Parse("""
            #00 pc 0000000000001004  /system/lib64/libapp.so (Build+4) (BuildId: 0f00ba44)
            #01 pc 0000000000001008  /system/lib64/libapp.so (BuildIdTable+8)
            #02 pc 000000000000100c  /system/lib64/libapp.so (BuildId: 0f00ba44)
            """, "android").Frames;
        Assert.Equal([("Build", 4ul, "0f00ba44"), ("BuildIdTable", 8ul, null), (null, null, "0f00ba44")],
            frames.Select(f => (f.Symbol, f.SymbolOffset, f.BuildId)));
    }

    /// <summary>AOT builds print an all-zero MVID: no build identity, so the frame is matched by name and its build is unknown.</summary>
    [Fact]
    public async Task An_AOT_zero_MVID_is_unknown_not_another_build()
    {
        var r = await Run("""
            NullReferenceException: Object reference not set to an instance of an object.
              at Fixture.Model.Account.Charge (System.Int32 amount) [0x00000] in <00000000000000000000000000000000>:0
            """);
        var f = Assert.Single(r.Items);
        Assert.Equal((_fixture.Id, "unknown"), (f.Assembly, f.BuildCheck));
        Assert.Empty(r.ModulesMissing);
    }

    /// <summary>The runtime writes "Crash!!!" before every crash report: a banner, not a module!function frame.</summary>
    [Fact]
    public async Task The_crash_banner_is_not_a_frame()
    {
        var r = await Run("""
            Crash!!!
            0x00007FF610001005 (synth) Crash
            C:\App\synth.dll:synth.dll (00007FF610000000), size: 20480 (result: 0), SymType: '-exported-', PDB: '', fileVersion: 1.2.3.4
            """);
        Assert.Equal("Crash+0x5", Assert.Single(r.Items).Resolved);
        Assert.Empty(r.ModulesMissing);
        Assert.Equal(["Crash!!!"], r.UnrecognizedSample);
    }

    /// <summary>The fixture carries dummy-assembly [Address] attributes (NativeThing::First at 0x1000, ::Second at 0x1100): GameAssembly frames get their names.</summary>
    [Fact]
    public async Task AOT_frames_are_named_through_the_dummy_assemblies()
    {
        using var env = new Env();
        var binary = _dir.File("GameAssembly.dll");
        File.WriteAllBytes(binary, AotStringTests.Pe64([(".text", 0x1000, new byte[0x400], 0x60000020)]));
        env.Workspace.LoadAny(binary);
        var service = new StackTextService(env.Workspace, null, env.AotNavigator);
        var r = await service.Symbolize("""
            0x00007FFB00001105 (GameAssembly) (function-name not available)
            Fixture.Native.NativeThing:First ()
            C:\App\GameAssembly.dll:GameAssembly.dll (00007FFB00000000), size: 8192 (result: 0), fileVersion: 0.0.0.0
            """, null, null, null, null, 0, 50, default);
        var native = r.Items[0];
        Assert.Equal("metadata", native.Source);
        Assert.Contains("NativeThing", native.Resolved);
        Assert.Contains("Second", native.Resolved);
        Assert.EndsWith("+0x5", native.Resolved);
        var managed = r.Items[1];
        Assert.Equal("aot", managed.Kind);
        Assert.StartsWith($"get_method_addresses assembly={env.Fixture.Id} symbol=0x06", managed.NextStep);
    }

    /// <summary>Runtime code after the last method (::Second at 0x1100) is a function of its own, not Second plus an offset.</summary>
    [Fact]
    public async Task Code_between_AOT_methods_is_not_named_after_the_method_below()
    {
        using var env = new Env();
        var binary = _dir.File("GameAssembly.dll");
        var text = Enumerable.Repeat((byte)0xCC, 0x400).ToArray();
        new byte[] { 0xE8, 0xFB, 0x00, 0x00, 0x00, 0xC3 }.CopyTo(text, 0x100); // Second: call 0x1200; ret
        new byte[] { 0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3 }.CopyTo(text, 0x200); // the runtime's function
        var pe = new PeBuilder { EntryPoint = 0x1100, ImageBase = 0x180000000 };
        pe.Add(".text", text, 0x60000020);
        File.WriteAllBytes(binary, pe.Build());
        env.Workspace.LoadAny(binary);
        var service = new StackTextService(env.Workspace, new NativeCodeService(env.Workspace, new ServerOptions()), env.AotNavigator);
        var r = await service.Symbolize("""
            0x00007FFB00001205 (GameAssembly) (function-name not available)
            0x00007FFB00001105 (GameAssembly) (function-name not available)
            C:\App\GameAssembly.dll:GameAssembly.dll (00007FFB00000000), size: 8192 (result: 0), fileVersion: 0.0.0.0
            """, null, null, null, null, 0, 50, default);
        Assert.DoesNotContain("Second", r.Items[0].Resolved);
        Assert.Contains("Second", r.Items[1].Resolved);
    }

    /// <summary>Android tombstones name libil2cpp.so: its frames get the metadata names too, not only GameAssembly's.</summary>
    [Fact]
    public async Task Android_tombstone_frames_in_libil2cpp_are_named_through_the_dummy_assemblies()
    {
        using var env = new Env();
        var binary = _dir.File("libil2cpp.so");
        File.WriteAllBytes(binary, AotStringTests.Pe64([(".text", 0x1000, new byte[0x400], 0x60000020)]));
        env.Workspace.LoadAny(binary);
        var service = new StackTextService(env.Workspace, null, env.AotNavigator);
        var r = await service.Symbolize("""
            backtrace:
                  #00 pc 0000000000001105  /data/app/~~x==/com.example.app-1/lib/arm64/libil2cpp.so
            """, null, null, null, null, 0, 50, default);
        var native = Assert.Single(r.Items);
        Assert.Equal("metadata", native.Source);
        Assert.Contains("Second", native.Resolved);
        Assert.EndsWith("+0x5", native.Resolved);
    }

    [Fact]
    public async Task WER_report_compares_the_faulting_module_timestamp()
    {
        string Report(uint stamp) => $"""
            Version=1
            EventType=APPCRASH
            Sig[0].Name=Application Name
            Sig[0].Value=app.exe
            Sig[3].Name=Fault Module Name
            Sig[3].Value=synth.dll
            Sig[4].Name=Fault Module Version
            Sig[4].Value=1.2.3.4
            Sig[5].Name=Fault Module Timestamp
            Sig[5].Value={stamp:x8}
            Sig[6].Name=Exception Code
            Sig[6].Value=c0000005
            Sig[7].Name=Exception Offset
            Sig[7].Value=0000000000001005
            """;
        var same = await Run(Report(_stamp));
        Assert.Equal("wer", same.Format);
        Assert.Equal("0xC0000005", same.Exception!.Code);
        Assert.Equal("EXCEPTION_ACCESS_VIOLATION", same.Exception.Name);
        var f = Assert.Single(same.Items);
        Assert.Equal("Crash+0x5", f.Resolved);
        Assert.Equal("match", f.BuildCheck);

        var other = await Run(Report(_stamp + 1));
        Assert.Equal("mismatch", other.Items[0].BuildCheck);
        Assert.Contains($"0x{_stamp + 1:X8}", other.Items[0].BuildDetail);
    }

    [Fact]
    public async Task Event_log_text_is_read_like_WER()
    {
        var r = await Run($"""
            Faulting application name: app.exe, version: 1.0.0.0, time stamp: 0x65000000
            Faulting module name: synth.dll, version: 1.2.3.4, time stamp: 0x{_stamp:x8}
            Exception code: 0xc0000005
            Fault offset: 0x0000000000001085
            Faulting process id: 0x1a2b
            Faulting module path: C:\App\synth.dll
            """, "eventlog");
        Assert.Equal("eventlog", r.Format);
        Assert.Equal("0xC0000005", r.Exception!.Code);
        Assert.Equal("Big+0x5", r.Items.Single().Resolved);
        Assert.Equal("match", r.Items[0].BuildCheck);
    }

    [Fact]
    public async Task Debugger_frames_are_checked_against_our_functions()
    {
        var r = await Run("""
            00 000000e0`00010000 00007ff6`10001005 synth!Crash+0x5
            01 000000e0`00010030 00007ff6`10001055 synth!Outer+0x500
            02 synth+0x1080
            03 kernel32!BaseThreadInitThunk+0x14
            0x7FF610001020
            """, "windbg", "synth.dll=0x7FF610000000");
        Assert.Equal("Crash+0x5", r.Items[0].Resolved);
        Assert.Equal("match", r.Items[0].BuildCheck);
        Assert.Equal("mismatch", r.Items[1].BuildCheck); // past the end of Outer
        Assert.Equal("Big", r.Items[2].Resolved);
        Assert.Equal("kernel32", Assert.Single(r.ModulesMissing).Module);
        Assert.Equal("Outer", r.Items[4].Resolved); // absolute address through moduleBases
    }

    [Fact]
    public async Task Unrecognized_text_is_counted_not_dropped()
    {
        var r = await Run("hello\nworld\n\nnothing here\n4 5 6\nmore\nlines");
        Assert.Equal(0, r.Total);
        Assert.Equal(6, r.UnrecognizedLines);
        Assert.Equal(5, r.UnrecognizedSample.Count);
        Assert.Equal("none", r.Format);
        Assert.Contains(r.Notes, n => n.StartsWith("No stack frame was recognized", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Arguments_are_checked()
    {
        async Task<ErrorCode> Code(Func<Task> call) => (await Assert.ThrowsAsync<ToolError>(call)).Code;
        Assert.Equal(ErrorCode.InvalidArgument, await Code(() => _service.Symbolize(null, null, null, null, null, 0, 10, default)));
        Assert.Equal(ErrorCode.InvalidArgument, await Code(() => _service.Symbolize("x", _dir.File("a.log"), null, null, null, 0, 10, default)));
        Assert.Equal(ErrorCode.InvalidArgument, await Code(() => _service.Symbolize("x", null, "gdb", null, null, 0, 10, default)));
        Assert.Equal(ErrorCode.InvalidArgument, await Code(() => _service.Symbolize("x", null, null, null, "synth.dll:1000", 0, 10, default)));
        Assert.Equal(ErrorCode.LimitExceeded, await Code(() => _service.Symbolize(new string('a', StackTextService.MaxTextChars + 1), null, null, null, null, 0, 10, default)));
        Assert.Equal(ErrorCode.NotFound, await Code(() => _service.Symbolize("x", null, null, "missing.dll", null, 0, 10, default)));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Large_logs_are_read_from_their_end()
    {
        var log = _dir.File("Player.log");
        using (var w = new StreamWriter(log))
        {
            var filler = new string('x', 1000);
            for (int i = 0; i < 9000; i++) w.WriteLine(filler);
            w.WriteLine("0x00007FF610001005 (synth) Crash");
            w.WriteLine(@"C:\App\synth.dll:synth.dll (00007FF610000000), size: 20480 (result: 0)");
        }
        var r = await _service.Symbolize(null, log, null, null, null, 0, 10, default);
        Assert.Equal("Crash+0x5", Assert.Single(r.Items).Resolved);
        Assert.Contains(r.Notes, n => n.Contains("last 8 MiB", StringComparison.Ordinal));
    }
}
