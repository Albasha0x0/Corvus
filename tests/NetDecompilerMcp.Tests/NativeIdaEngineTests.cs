using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The native code tools on top of the IDA session: architectures the built-in analysis does not decode.</summary>
public sealed class NativeIdaEngineTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeAnalysisTools Analysis, NativeEngineService Engines);

    private Rig Setup(IdaProviderOptions? ida = null, bool prewarm = false, Native.Providers.Ghidra.GhidraProviderOptions? ghidra = null)
    {
        var options = new ServerOptions { TimeoutSeconds = 120, BackgroundIndexing = false, Prewarm = prewarm ? EngineMode.Ida : null };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(ida ?? new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options, ghidra);
        _owned.Add(engines);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, pager, null, engines, names), new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush()), engines);
    }

    /// <summary>A MIPS ELF shared object: the built-in analysis only lists its function symbol.</summary>
    private string SyntheticMips()
    {
        var w = new NativeFormats.ElfWriter { Is64 = false, Machine = NativeFormats.ElfWriter.EmMips, Text = [0, 0, 0, 0, 0x08, 0x00, 0xE0, 0x03, 0, 0, 0, 0] }; // nop; jr ra; nop
        w.Symbols.Add(new NativeFormats.ElfWriter.Symbol("f", NativeFormats.ElfWriter.TextRva, 12));
        var path = _dir.File("mips.so");
        File.WriteAllBytes(path, w.Build());
        return path;
    }

    [WindowsFact]
    public async Task Undecoded_architecture_without_IDA_is_unsupported_with_remediation()
    {
        var tools = Setup(new IdaProviderOptions { InstallDirectory = _dir.File("no-ida-here"), CacheRoot = _dir.File("cache") },
            ghidra: new() { InstallDirectory = _dir.File("no-ghidra-here"), CacheRoot = _dir.File("cache") }).Tools;
        var path = SyntheticMips();
        foreach (var call in new Func<Task<string>>[] { () => tools.Disassemble(path, "rva:0x1000"), () => tools.GetCfg(path, "rva:0x1000") })
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains("Mips", e.Message);
            Assert.Contains("IDA", e.Remediation);
            Assert.Contains("NDM_GHIDRA_DIR", e.Remediation);
        }
        // list_functions still answers from the declared starts.
        Assert.Contains("1 function", await tools.ListFunctions(path));
    }

    /// <summary>A small ARM64 PE on this machine (the .NET host packs ship some), or null.</summary>
    internal static string? FindArm64Image()
    {
        var roots = new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }
            .Select(Environment.GetFolderPath).Where(r => r.Length > 0 && Directory.Exists(r)).Distinct().ToList();
        foreach (var root in roots)
        {
            var packs = Path.Combine(root, "dotnet", "packs");
            if (!Directory.Exists(packs)) continue;
            foreach (var dir in Directory.EnumerateDirectories(packs, "*win-arm64*"))
                foreach (var file in SafeFiles(dir, "nethost.dll"))
                    if (IsArm64(file)) return file;
        }
        int seen = 0;
        foreach (var root in roots)
            foreach (var file in SafeFiles(root, "*.dll"))
            {
                if (++seen > 50_000) return null;
                if (file.Contains("arm64", StringComparison.OrdinalIgnoreCase) && new FileInfo(file).Length is > 40_000 and < 2_000_000 && IsArm64(file)) return file;
            }
        return null;
    }

    private static IEnumerable<string> SafeFiles(string root, string pattern)
    {
        try { return Directory.EnumerateFiles(root, pattern, new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static bool IsArm64(string file)
    {
        try
        {
            var pe = PeFile.Open(file);
            return pe.Arch == Native.NativeArch.Arm64 && pe.Exports.Count > 0 && !pe.IsDotNet;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError) { return false; }
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Arm64_code_tools_answer_through_IDA()
    {
        var path = FindArm64Image();
        if (path == null) { output.WriteLine("no ARM64 image found on this machine"); return; }
        output.WriteLine(path);
        var (workspace, _, tools, _, _) = Setup();
        var clock = Stopwatch.StartNew();
        var list = await tools.ListFunctions(path, limit: 5000, engine: "ida");
        output.WriteLine($"list_functions {clock.Elapsed.TotalSeconds:0.0} s (includes IDA analysis)\n{string.Join('\n', list.Split('\n').Take(12))}");
        Assert.Contains(NativeEngineCode.Via("ida"), list);
        var id = workspace.Read(() => workspace.Natives[0].Id);
        var pe = workspace.Read(() => workspace.Natives[0].Image);
        var export = pe.Exports.First(e => e.Rva != 0 && e.Name != null && pe.SectionAt(e.Rva) is { IsExecutable: true });
        var declared = int.Parse(list.Split(':')[1].Trim().Split(' ')[0]);
        Assert.True(declared > 10, list[..200]);

        clock.Restart();
        var asm = await tools.Disassemble(id, export.Name!, engine: "ida");
        output.WriteLine($"disassemble {export.Name}: {clock.ElapsedMilliseconds} ms\n{string.Join('\n', asm.Split('\n').Take(10))}");
        Assert.Contains(NativeEngineCode.Via("ida"), asm);
        Assert.Contains($"{pe.ImageBase + export.Rva:X}", asm);
        Assert.Matches(@"(?m)^  [0-9A-F]+  [0-9A-F]{8} +\S", asm); // ARM64: 4-byte instructions

        var linear = await tools.Disassemble(id, export.Name!, function: false, maxInstructions: 5, engine: "ida");
        Assert.Equal(5, linear.Split('\n').Count(l => l.StartsWith("  ", StringComparison.Ordinal)));

        var cfg = await tools.GetCfg(id, export.Name!, engine: "ida");
        output.WriteLine(cfg);
        Assert.Contains(NativeEngineCode.Via("ida"), cfg);
        Assert.Matches(@"insn  (Return|Jump|ConditionalJump|FallThrough|TailCall|NoReturnCall|IndirectJump|Switch)", cfg);

        var callees = await tools.NativeCallTree(id, export.Name!, depth: 2, engine: "ida");
        output.WriteLine(callees);
        Assert.Contains(NativeEngineCode.Via("ida"), callees);

        // References to some function that is called: callers in the tree match find_xrefs.
        var called = list.Split('\n').Select(l => System.Text.RegularExpressions.Regex.Match(l, @"^\s*(0x[0-9A-F]+) .*; (\d+) refs\)\s*$"))
            .Where(m => m.Success && int.Parse(m.Groups[2].Value) > 1).Select(m => m.Groups[1].Value).FirstOrDefault();
        Assert.NotNull(called);
        var xrefs = await tools.FindXrefs(id, called!, engine: "ida");
        output.WriteLine(string.Join('\n', xrefs.Split('\n').Take(8)));
        Assert.Contains(NativeEngineCode.Via("ida"), xrefs);
        Assert.Matches(@"(?m)^\s*0x[0-9A-F]+  Call ", xrefs);
        var callers = await tools.NativeCallTree(id, called!, direction: "callers", depth: 1, engine: "ida");
        Assert.True(callers.Split('\n').Length > 2, callers);
    }

    /// <summary>
    /// Patches go into the open database (no new auto-analysis) and undo reverts them; compared with analyzing the
    /// patched bytes from scratch (the fallback when the database cannot take a patch set).
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Patched_bytes_decompile_from_the_open_database_and_undo_reverts_them()
    {
        var dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dbghelp.dll");
        const string Export = "SymGetOptions";
        if (!File.Exists(dll)) return;
        var rig = Setup();
        var clock = Stopwatch.StartNew();
        var original = await rig.Analysis.DecompileNative(dll, Export);
        var open = clock.Elapsed;
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        Assert.DoesNotContain("return 0x5A17;", original);
        var edits = new NativeEditService(rig.Workspace, rig.Code);

        async Task Patch()
        {
            var index = await rig.Code.Index(native, null, default);
            var rva = index.AddressOfName(Export) ?? native.Image.Exports.First(e => e.Name == Export).Rva;
            edits.ApplyPatch(native, index, edits.PreparePatch(index, rva, [0xB8, 0x17, 0x5A, 0x00, 0x00, 0xC3], false, "return 0x5A17"), dryRun: false);
        }

        await Patch();
        clock.Restart();
        var patched = await rig.Analysis.DecompileNative(native.Id, Export);
        var inDatabase = clock.Elapsed;
        output.WriteLine(patched);
        Assert.Contains("return 23063;", patched.Replace("0x5A17", "23063"));
        Assert.Contains("applied in the database", patched);
        Assert.False(rig.Engines.ServesPatchedCopy(native, "ida"));
        var sync = rig.Engines.LastPatchSync(native, "ida")!;
        output.WriteLine($"sync: {sync}");
        Assert.True(sync.Complete);

        edits.Undo(native, null);
        clock.Restart();
        var undone = await rig.Analysis.DecompileNative(native.Id, Export);
        var undoTime = clock.Elapsed;
        Assert.Equal(Body(original), Body(undone));
        Assert.True(rig.Engines.LastPatchSync(native, "ida")!.Reverted > 0);
        // the tool may answer from its page cache (same bytes as the original): ask the database itself
        var session = await rig.Engines.Session(native, null, null, default);
        var fresh = await session.DecompileAsync(native.Image.Exports.First(e => e.Name == Export).Rva);
        Assert.DoesNotContain("23063", fresh.Text);
        Assert.DoesNotContain("5A17", fresh.Text);

        // The same patch analyzed from scratch: what every patch cost without applying it to the database.
        rig.Engines.PatchInDatabase = false;
        await Patch();
        clock.Restart();
        var reanalyzed = await rig.Analysis.DecompileNative(native.Id, Export);
        var fromScratch = clock.Elapsed;
        Assert.Contains("analyzed as a patched copy", reanalyzed);
        Assert.True(rig.Engines.ServesPatchedCopy(native, "ida"));
        Assert.Contains("return 23063;", reanalyzed.Replace("0x5A17", "23063"));
        output.WriteLine($"{Path.GetFileName(dll)} ({new FileInfo(dll).Length:N0} bytes): first open {open.TotalSeconds:0.0} s; decompile after a patch: " +
                         $"{inDatabase.TotalSeconds:0.00} s applied in the database (sync {sync.Elapsed.TotalSeconds:0.00} s, {sync.Functions} function(s) reanalyzed) " +
                         $"vs {fromScratch.TotalSeconds:0.0} s re-analyzing the patched copy; after undo {undoTime.TotalSeconds:0.00} s");

        static string Body(string text) => string.Join('\n', text.Split('\n').Where(l => !l.StartsWith("//", StringComparison.Ordinal)));
    }

    [Fact]
    public void Prewarm_is_off_by_default_and_turned_on_by_option()
    {
        Assert.Null(new ServerOptions().Prewarm);
        Assert.Equal(EngineMode.Ida, ServerOptions.Parse(["--ida-prewarm"]).Prewarm);
        using var engines = new NativeEngineService();
        Assert.False(engines.Prewarming.Enabled);
    }

    /// <summary>
    /// With prewarming on, loading native images queues their IDA analysis (one at a time, visible in the status); the
    /// first decompile_native then finds the session open; unloading a queued or running image cancels its work.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Prewarm_analyzes_loaded_images_one_at_a_time_and_unload_cancels()
    {
        string Sys(string name) => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
        var rig = Setup(prewarm: true);
        var clock = Stopwatch.StartNew();
        var first = rig.Workspace.LoadAny(Sys("imagehlp.dll")).Native!;
        var second = rig.Workspace.LoadAny(Sys("version.dll")).Native!;
        var big = rig.Workspace.LoadAny(Sys("dbghelp.dll")).Native!;
        var seen = new List<string>();
        while (rig.Engines.Prewarming is { Done: < 2 } p && clock.Elapsed < TimeSpan.FromMinutes(5))
        {
            seen.Add($"{p.Running ?? "-"}/{p.Queued}");
            Assert.True(p.Queued + (p.Running != null ? 1 : 0) + p.Done <= 3);
            await Task.Delay(100);
        }
        var warmed = clock.Elapsed;
        Assert.Contains(seen, s => s.StartsWith(first.Id, StringComparison.Ordinal) && s.EndsWith("/2", StringComparison.Ordinal)); // one runs, two wait
        // dbghelp runs now: unloading it cancels its analysis
        while (rig.Engines.Prewarming.Running != big.Id && clock.Elapsed < TimeSpan.FromMinutes(5)) await Task.Delay(50);
        var cancel = Stopwatch.StartNew();
        rig.Workspace.UnloadNative(big);
        while (rig.Engines.Prewarming is { Cancelled: 0 } && cancel.Elapsed < TimeSpan.FromSeconds(30)) await Task.Delay(50);
        var status = rig.Engines.Prewarming;
        output.WriteLine($"prewarmed 2 images in {warmed.TotalSeconds:0.0} s; dbghelp cancelled {cancel.ElapsedMilliseconds} ms after unload; {status}");
        Assert.Equal(1, status.Cancelled);
        Assert.Equal(2, status.Done);
        Assert.Null(status.Running);

        clock.Restart();
        var text = await rig.Analysis.DecompileNative(first.Id, "CheckSumMappedFile");
        output.WriteLine($"first decompile_native after prewarm: {clock.ElapsedMilliseconds} ms");
        Assert.Contains("CheckSumMappedFile", text);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20));
    }

    /// <summary>The Il2Cpp header and method prototypes reach the pseudocode, persist in the database and are not pushed again.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Il2Cpp_types_reach_the_pseudocode_and_persist()
    {
        var (dll, binary) = Il2CppNativeNamesTests.CreateDump(_dir);
        using var env = new Env(dll);
        var code = new NativeCodeService(env.Workspace, env.Options, null, new Native.Annotations.AnnotationStore(_dir.File("ann")));
        var native = env.Workspace.LoadAny(binary).Native!;
        var index = await code.Index(native, null, default);
        new Il2CppNativeNames(env.Il2Cpp, env.Il2CppNavigator, code).Apply(native, index, env.Workspace.Assemblies, default);
        var batch = NativeTypePush.Build(native, Il2CppNativeNames.Of(native), null, default);
        output.WriteLine($"{batch.Prototypes.Count} prototypes, header {batch.Declarations!.Length:N0} chars\n{string.Join('\n', batch.Prototypes.Select(p => $"0x{p.Rva:X} {p.Declaration}"))}");
        Assert.Contains(batch.Prototypes, p => p.Rva == 0x1000 && p.Declaration.Contains("struct Fixture_Native_NativeThing* __this"));

        using var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = _dir.File("cache") });
        var offline = new Native.Providers.NativeOpenOptions { Symbols = Native.Providers.SymbolMode.Off };
        var types = new NativeTypePush();
        await using (var session = await provider.OpenAsync(binary, null, offline))
        {
            await new NativeNamePush(code).EnsureAsync(native, session, default);
            var pushed = await types.EnsureAsync(native, session, default);
            output.WriteLine(NativeTypePush.Describe(pushed));
            Assert.NotNull(pushed!.Totals);
            Assert.Equal(0, pushed.Totals!.TypeFailures);
            Assert.Equal(batch.Prototypes.Count, pushed.Totals.Typed);
            var text = (await session.DecompileAsync(0x1000)).Text;
            output.WriteLine(text);
            Assert.Contains("Fixture_Native_NativeThing *this", text);
            Assert.Contains("method", text);
            Assert.Null(await types.EnsureAsync(native, session, default)); // nothing changed
        }
        await using (var session = await provider.OpenAsync(binary, null, offline))
        {
            Assert.True((await types.EnsureAsync(native, session, default))!.AlreadyInDatabase);
            Assert.Contains("Fixture_Native_NativeThing *this", (await session.DecompileAsync(0x1000)).Text);
        }
    }

    private const string ClassesSource = """
        #include <stdio.h>
        struct Shape { virtual ~Shape() {} virtual int Area() const = 0; virtual const char* Name() const { return "shape"; } int id = 7; };
        struct Rect : Shape
        {
            int w, h;
            Rect(int a, int b) : w(a), h(b) {}
            int Area() const override { return w * h + id; }
            const char* Name() const override { return "rect"; }
            virtual int Twice() const { return Area() * 2 + (int)Name()[0]; }
        };
        struct Printer { virtual void Print(const Shape& s) { printf("%s %d\n", s.Name(), s.Area()); } virtual ~Printer() {} };
        struct Both : Rect, Printer
        {
            Both() : Rect(2, 3) {}
            void Print(const Shape& s) override { printf("both %d %d\n", s.Area(), Twice()); }
        };
        int main(int argc, char**)
        {
            Shape* s = argc > 1 ? (Shape*)new Rect(argc, 4) : (Shape*)new Both();
            Printer* p = new Both();
            p->Print(*s);
            int r = ((Rect*)s)->Twice();
            delete s;
            delete p;
            return r;
        }
        """;

    /// <summary>MSVC RTTI classes become vftable and class structs; a class's own virtual methods get it as the type of this.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Rtti_class_types_reach_the_pseudocode()
    {
        var path = CallArgumentTests.BuildSample(_dir, "x64", ClassesSource, "classes", "/MD /TP /EHsc");
        if (path == null) { output.WriteLine("no MSVC build tools"); return; }
        var rig = Setup();
        var text = await rig.Analysis.DecompileNative(path, "rva:0x" + PeFile.Open(path).EntryPointRva.ToString("X"));
        output.WriteLine(text.Split('\n')[0] + "\n" + text.Split('\n')[1]);
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var rtti = native.GetAnalysis(n => Native.Msvc.MsvcRtti.Analyze(n.Image));
        var rect = rtti.Classes.Single(c => c.Name == "Rect");
        var batch = NativeTypePush.Build(native, null, rtti, default);
        output.WriteLine($"{batch.Classes.Count} classes, {batch.Methods.Count} methods owned: " +
                         string.Join(", ", batch.Classes.Select(c => $"{c.Name}[{string.Join("/", c.Vftables.Select(v => $"+{v.Offset:X}:{v.Slots.Count}"))}]" +
                                                                         (c.Bases.Count > 0 ? " bases " + string.Join(",", c.Bases.Select(b => $"{b.Name}@{b.Offset:X}")) : ""))));
        Assert.Contains(batch.Classes, c => c.Name == "Both" && c.Bases.Any(b => b.Name == "Printer" && b.Offset > 0));

        Assert.Contains("// types: pushed", text);

        // Rect::Twice (Rect's last slot) is inherited by Both at offset 0: it is Rect's method
        var twice = rect.Vtables.Single(v => v.Offset == 0).SlotRvas[^1];
        Assert.Contains(batch.Methods, m => m.Rva == twice && m.Class == "Rect");
        var decompiled = await rig.Analysis.DecompileNative(native.Id, $"rva:0x{twice:X}");
        output.WriteLine(decompiled);
        Assert.Contains("Rect *this", decompiled);
        Assert.Contains("__vftable->", decompiled);

        // a system DLL with many classes: how much is typed and what the push costs
        var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "msvcp_win.dll");
        if (!File.Exists(system)) return;
        var clock = Stopwatch.StartNew();
        var head = await rig.Analysis.DecompileNative(system, "rva:0x" + PeFile.Open(system).EntryPointRva.ToString("X"));
        output.WriteLine($"msvcp_win.dll first decompile_native {clock.Elapsed.TotalSeconds:0.0} s: {head.Split('\n').First(l => l.Contains("types:"))}");
    }

    /// <summary>The protocol sample (no RTTI, no Il2Cpp): decompile_native with every push enabled.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Synthetic_sample_decompiles_with_name_and_type_pushes()
    {
        var rig = Setup();
        var text = await rig.Analysis.DecompileNative(McpProtocolTests.NativeSample(_dir), "First");
        output.WriteLine(text);
        Assert.Contains("First", text);

        // A patch that ends the function (ret -> nop) and its undo: the function comes back with the original bytes.
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var index = await rig.Code.Index(native, null, default);
        var edits = new NativeEditService(rig.Workspace, rig.Code);
        edits.ApplyPatch(native, index, edits.PreparePatch(index, 0x1000, [0x90], false, "nop"), dryRun: false);
        try { output.WriteLine(await rig.Analysis.DecompileNative(native.Id, "rva:0x1000")); }
        catch (ToolError e) { output.WriteLine(e.Render("decompile_native")); }
        edits.Undo(native, null);
        var session = await rig.Engines.Session(native, null, null, default);
        Assert.Equal(0x1000u, (await session.DecompileAsync(0x1000)).StartRva);
    }

    private const string StaticSource = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        static int cmp(const void* a, const void* b) { return *(const int*)a - *(const int*)b; }
        int main(int argc, char** argv)
        {
            int v[64];
            char buf[128];
            for (int i = 0; i < 64; i++) v[i] = rand();
            qsort(v, 64, sizeof(int), cmp);
            snprintf(buf, sizeof buf, "%s %d", argv[0], v[0]);
            char* copy = _strdup(buf);
            printf("%s %zu\n", copy, strlen(copy));
            free(copy);
            FILE* f = fopen("x.txt", "r");
            if (f) fclose(f);
            return (int)strtol(argv[argc - 1], NULL, 10);
        }
        """;

    /// <summary>
    /// A statically linked (/MT) MSVC build: the CRT functions IDA recognizes become the ida name layer once a session is
    /// open (list_functions alone does not start IDA for x64), flagged library; user names still win.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Library_functions_IDA_recognizes_name_a_static_MSVC_build()
    {
        var path = CallArgumentTests.BuildSample(_dir, "x64", StaticSource, "static", "/MT");
        if (path == null) { output.WriteLine("no MSVC build tools"); return; }
        var rig = Setup();
        var before = await rig.Tools.ListFunctions(path, limit: 5000);
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        Assert.Null(rig.Engines.LibraryNames(native));
        Assert.DoesNotContain("[library", before);

        var clock = Stopwatch.StartNew();
        await rig.Analysis.DecompileNative(native.Id, $"rva:0x{native.Image.EntryPointRva:X}");
        var imported = await rig.Engines.LibraryNames(native)!;
        var opened = clock.Elapsed;
        // the built-in listing with the ida name layer (auto would now answer from IDA: its analysis is complete)
        var after = await rig.Tools.ListFunctions(native.Id, limit: 5000, engine: "ours");
        var rows = after.Split('\n').Where(l => l.StartsWith("  0x", StringComparison.Ordinal)).ToList();
        var library = rows.Where(r => r.Contains("library") && r.Contains(", ida;")).ToList();
        output.WriteLine($"{Path.GetFileName(path)} ({new FileInfo(path).Length:N0} bytes): {rows.Count} functions, {imported} library names from IDA, " +
                         $"{library.Count} of the listed functions named by them ({100.0 * library.Count / rows.Count:0.0}%); IDA open + import {opened.TotalSeconds:0.0} s");
        output.WriteLine(string.Join('\n', library.Take(15)));
        Assert.True(imported >= 50, $"{imported} library names");
        Assert.True(library.Count >= 50);
        Assert.Contains(library, r => r.Contains("qsort") || r.Contains("strtol") || r.Contains("_strdup") || r.Contains("memset"));
        Assert.DoesNotContain(rows, r => r.Contains("unknown_libname_"));

        // A user name wins over the library name.
        var index = await rig.Code.Index(native, null, default);
        var first = index.Functions.First(f => EngineLibraryNames.IsLibrary(index, f.Start));
        new NativeEditService(rig.Workspace, rig.Code).Rename(native, index, first.Start, "MyLibraryFunction", false);
        Assert.Contains("MyLibraryFunction  [library", await rig.Tools.ListFunctions(native.Id, filter: "MyLibraryFunction", engine: "ours"));
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Signatures_at_every_reference_take_IDAs_references_too()
    {
        var rig = Setup();
        var path = NativeIdaProviderTests.System64;
        var diff = new NativeDiffTools(rig.Workspace, rig.Code, rig.Engines);
        // the function CheckSumMappedFile calls most often (ChkSum, twice), with its call sites as the references
        var session = await rig.Engines.Session(rig.Workspace.LoadAny(path).Native!, null, null, default);
        var calls = (await session.GetXrefsFromAsync(NativeIdaProviderTests.ExportRva(path, "CheckSumMappedFile"), true))
            .Where(x => x.Kind == Native.Providers.NativeXrefKind.Call).GroupBy(x => x.ToRva).OrderByDescending(g => g.Count()).First();
        var target = $"rva:0x{calls.Key:X}";
        var ours = await diff.MakeCodePattern(path, target, anchor: "xrefs", engine: "ours");
        var ida = await diff.MakeCodePattern(path, target, anchor: "xrefs", engine: "ida");
        output.WriteLine($"ours: {ours.Note}\nida: {ida.Note}");
        foreach (var r in ida.References!) output.WriteLine($"  {r.Pattern}  at {r.ReferenceAddress} ({r.Source}) {r.Note}");
        Assert.Equal("ida", ida.Engine);
        Assert.NotEmpty(ida.References!);
        Assert.True(ida.References!.Count >= ours.References!.Count);
        Assert.All(ida.References!, r => Assert.True(r.OperandKind != null, r.Note));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => diff.MakeCodePattern(path, target, anchor: "xrefs", maxPatterns: 0))).Code);
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Function_diff_pseudocode_shows_the_changed_constant()
    {
        var (workspace, code, _, _, engines) = Setup();
        code.SymbolStarts = (_, _) => [0x1000u, 0x1040u];
        var oldPath = _dir.File("old.dll");
        var newPath = _dir.File("new.dll");
        File.WriteAllBytes(oldPath, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 1));
        File.WriteAllBytes(newPath, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 7));
        var tools = new NativeDiffTools(workspace, code, engines);
        var report = await tools.DiffFunction(oldPath, newPath, "rva:0x1040", view: "pseudocode", context: 1);
        output.WriteLine(report.Unified);
        Assert.Equal("pseudocode", report.View);
        Assert.True(report.Removed >= 1 && report.Added >= 1, report.Summary);
        Assert.Matches(@"(?m)^-.*(35|0x23)", report.Unified!);
        Assert.Matches(@"(?m)^\+.*(41|0x29)", report.Unified!);
        var asm = await tools.DiffFunction(oldPath, newPath, "rva:0x1040");
        Assert.Equal(1, asm.Changed);
    }

    /// <summary>Our switch cases (values per target, default) against IDA's: x64 switches of a system DLL, ARM64 jump tables.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public Task Switch_cases_agree_with_IDA() =>
        SwitchesAgree(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "kernel32.dll"));

    [Trait("Speed", "Slow")]
    [IdaFact]
    public Task Arm64_switch_cases_agree_with_IDA() => SwitchesAgree(NativeFormats.NativeFixtures.WinArm64DbgShim);

    private async Task SwitchesAgree(string path)
    {
        var rig = Setup();
        await rig.Tools.ListFunctions(path, engine: "ours");
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var index = await rig.Code.Index(native, null, default);
        var functions = index.Functions.Where(f => index.RefsFrom(f).Any(x => x.Kind == Native.Code.XrefKind.JumpTable)).Take(12).ToList();
        Assert.NotEmpty(functions);
        int compared = 0, agreed = 0;
        foreach (var f in functions)
        {
            var at = $"rva:0x{f.Start:X}";
            var collector = Mcp.StructuredOutput.Begin();
            await rig.Tools.GetCfg(path, at, engine: "ours");
            var ours = Assert.IsType<CfgReport>(collector.Value);
            collector = Mcp.StructuredOutput.Begin();
            await rig.Tools.GetCfg(path, at, engine: "ida");
            var ida = Assert.IsType<CfgReport>(collector.Value);
            foreach (var sw in ours.Switches)
            {
                if (ida.Switches.FirstOrDefault(s => s.Jump == sw.Jump) is not { } other) { output.WriteLine($"{f.Name}: IDA has no switch at {sw.Jump}"); continue; }
                compared++;
                string Key(CfgSwitch s) => string.Join("; ", s.Cases.OrderBy(c => c.Target).Select(c => $"{c.Target}={string.Join(",", c.Values)}")) + $" default {s.Default}";
                if (Key(sw) == Key(other)) agreed++;
                else output.WriteLine($"{f.Name} {sw.Jump}:\n  ours {Key(sw)}\n  ida  {Key(other)}");
            }
        }
        output.WriteLine($"{agreed} of {compared} switches agree");
        Assert.True(compared > 0);
        Assert.True(agreed * 10 >= compared * 9, $"{agreed} of {compared} switches agree");
    }
}
