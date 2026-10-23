using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The engine read views against a real Ghidra, on a copy of a system DLL analyzed once for the class.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeGhidraViewTests(ITestOutputHelper output, GhidraCacheFixture shared) : IClassFixture<GhidraCacheFixture>
{
    private const string Export = "CheckSumMappedFile";
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };

    private async Task<GhidraSession> Open() => (GhidraSession)await shared.Provider.OpenAsync(shared.Sample, null, Offline);

    [GhidraFact]
    public async Task Image_info_is_the_engine_view_of_the_image()
    {
        await using var s = await Open();
        var info = await s.GetEngineInfoAsync();
        output.WriteLine($"{info.Version} {info.Language} {info.Compiler} {info.Format} {info.Functions} functions, {info.ExternalFunctions} external, " +
                         $"{info.Blocks.Count} blocks, analysis {info.Analysis}");
        Assert.StartsWith("12.", info.Version);
        Assert.Equal("x86:LE:64:default", info.Language);
        Assert.Equal("windows", info.Compiler);
        Assert.Contains("Portable Executable", info.Format);
        Assert.Equal((8, "little"), (info.PointerSize, info.Endian));
        Assert.Equal(s.FunctionCount, info.Functions);
        Assert.True(info.ExternalFunctions > 10);
        Assert.Equal(AnalysisCache.HashFile(shared.Sample), info.Sha256);
        Assert.Contains(info.Blocks, b => b.Name == ".text" && b.Permissions == "r-x" && b.Initialized && b.Start == s.ImageBase + 0x1000);
        Assert.NotEmpty(info.EntryPoints);
        Assert.Contains(NativeIdaProviderTests.ExportRva(shared.Sample, Export), info.EntryPoints);
        Assert.Equal("complete", info.Analysis);
    }

    [GhidraFact]
    public async Task Defined_data_lists_typed_items_with_values_and_strings()
    {
        await using var s = await Open();
        var data = await s.ListDataAsync(100_000);
        output.WriteLine($"{data.Total} items; " + string.Join("; ", data.Items.Take(8).Select(d => $"0x{d.Rva:X} {d.Size} {d.Type} {d.Label} = {d.Value}")));
        Assert.True(data.Total > 200, $"{data.Total} items");
        Assert.Equal(data.Total, data.Items.Count);
        Assert.True(data.Items.Zip(data.Items.Skip(1)).All(p => p.First.Rva < p.Second.Rva));
        Assert.Contains(data.Items, d => d.IsString && d.Value != null && d.Size > 1);
        Assert.Contains(data.Items, d => d.Label != null && d.Type.Length > 0);
        Assert.Equal(5, (await s.ListDataAsync(5)).Items.Count);
    }

    [GhidraFact]
    public async Task Defined_strings_include_unreferenced_ones()
    {
        await using var s = await Open();
        var strings = await s.ListStringsAsync(100_000);
        output.WriteLine($"{strings.Count} strings; " + string.Join("; ", strings.Take(6).Select(x => $"0x{x.Rva:X} {x.Type} {x.Text}")));
        Assert.True(strings.Count > 20);
        Assert.Contains(strings, x => x.Type == "unicode" && x.Text.Length > 2);
        Assert.Contains(strings, x => x.Text == Export);
    }

    [GhidraFact]
    public async Task Namespaces_list_cpp_classes_with_functions_and_vftables_and_the_libraries()
    {
        var dll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "msvcp_win.dll");
        if (!File.Exists(dll)) return;
        await using var s = await shared.Provider.OpenAsync(shared.Copy(dll), null, Offline);
        var list = await s.ListNamespacesAsync();
        var classes = list.Where(n => n.Kind == "class").ToList();
        output.WriteLine($"{classes.Count} classes, {list.Count(n => n.Kind == "library")} libraries; " +
                         string.Join("; ", classes.Where(c => c.Vftable != null).Take(6).Select(c => $"{c.Name} {c.Functions} 0x{c.Vftable:X}")));
        Assert.True(classes.Count > 10);
        Assert.Contains(classes, c => c.Name.StartsWith("std::", StringComparison.Ordinal) && c.Functions > 0);
        Assert.Contains(classes, c => c.Vftable != null);
        Assert.Contains(list, n => n.Kind == "library");
        Assert.Equal(list.Select(n => n.Name).Order(StringComparer.Ordinal), list.Select(n => n.Name));
    }

    [GhidraFact]
    public async Task Scripts_print_commit_and_save_and_a_failing_one_rolls_back()
    {
        await using var s = await Open();
        var label = "sample_script_" + Guid.NewGuid().ToString("N")[..8];
        string Body(string action) => "import ghidra.program.model.symbol.SourceType;\n" +
            $"var a = currentProgram.getImageBase().add(0x{NativeIdaProviderTests.ExportRva(shared.Sample, Export):X});\n" + action;
        var ok = await s.RunJavaAsync(Body($"createLabel(a, \"{label}\", false, SourceType.USER_DEFINED);\nprintln(\"functions \" + currentProgram.getFunctionManager().getFunctionCount());"), 120);
        output.WriteLine($"stdout: {ok.Stdout}\nstderr: {ok.Stderr}\nerror: {ok.Error}");
        Assert.Null(ok.Error);
        Assert.Contains($"functions {s.FunctionCount}", ok.Stdout);
        Assert.Equal(0, s.UnsavedCount);
        var find = Body($"println(\"labels \" + currentProgram.getSymbolTable().getSymbols(\"{label}\").hasNext());");
        Assert.Contains("labels true", (await s.RunJavaAsync(find, 60)).Stdout);

        var failed = await s.RunJavaAsync(Body($"createLabel(a, \"{label}_x\", false, SourceType.USER_DEFINED);\nthrow new IllegalStateException(\"stop\");"), 60);
        Assert.Contains("IllegalStateException: stop", failed.Error);
        Assert.Contains("labels false", (await s.RunJavaAsync(find.Replace(label, label + "_x"), 60)).Stdout);

        var broken = await s.RunJavaAsync("int x = ;", 60);
        Assert.StartsWith("compile:", broken.Error);
        var slow = await s.RunJavaAsync("while (true) { monitor.checkCancelled(); Thread.sleep(50); }", 2);
        Assert.Contains("cancelled or ran past", slow.Error);
        var cleanup = await s.RunJavaAsync(Body($"for (var x : currentProgram.getSymbolTable().getSymbols(\"{label}\")) x.delete();"), 60);
        Assert.Null(cleanup.Error);
    }

    [GhidraFact]
    public async Task Field_xrefs_find_member_accesses_through_a_typed_parameter()
    {
        using var dir = new TempDir();
        using var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.File("cache") });
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = (GhidraSession)await provider.OpenAsync(path, null, Offline);
        var typed = await s.ApplyUserTypesAsync(new NativeUserTypeBatch(["struct SampleDos { unsigned short e_magic; char pad[0x3a]; int e_lfanew; };"],
            [new NativePrototype(rva, "void * __fastcall SampleCheck(struct SampleDos *image, unsigned int size, unsigned int *header, unsigned int *sum)")], [], []));
        Assert.True(typed.Items[0].Applied, typed.Items[0].Error);
        output.WriteLine((await s.DecompileAsync(rva)).Text);
        var r = await s.GetFieldXrefsAsync(["SampleMissing", "SampleDos"], "pad", null, [], 60);
        output.WriteLine($"{r.Type}::{r.Member} +0x{r.Offset:X} {r.MemberType} {r.Size}: {r.Scanned}/{r.Candidates} scanned; " +
                         string.Join(", ", r.Accesses.Select(a => $"0x{a.Rva:X} {a.Kind} in 0x{a.FunctionRva:X}")));
        Assert.Equal(("SampleDos", "pad", 2, 0x3A, "char[58]"), (r.Type, r.Member, r.Offset, r.Size, r.MemberType));
        Assert.True(r.DecompilerAvailable);
        Assert.True(r.Scanned >= 1);
        Assert.Contains(r.Accesses, a => a.FunctionRva == rva && a.Kind == "read");
        Assert.Equal("e_lfanew", (await s.GetFieldXrefsAsync(["SampleDos"], null, 0x3D, [], 60)).Member);
        // every function from the typed one on: more candidates, the typed function's access among the uses
        var all = await s.GetFieldXrefsAsync(["SampleDos"], "pad", null, [], 30, allFrom: rva);
        Assert.True(all.Candidates > r.Candidates, $"{all.Candidates} candidates");
        Assert.Contains(all.Accesses, a => a.FunctionRva == rva && a.Kind == "read");
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFieldXrefsAsync(["SampleDos"], "nope", null, [], 10))).Code);
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFieldXrefsAsync(["SampleNone"], "x", null, [], 10))).Code);
    }

    [GhidraFact]
    public async Task The_program_exports_as_a_packed_archive_outside_the_project()
    {
        await using var s = await Open();
        using var dir = new TempDir();
        var projectFiles = Directory.GetFiles(s.ProjectDirectory, "*", SearchOption.AllDirectories).Length;
        var (path, bytes) = await s.ExportPackedAsync(dir.File("copy.gzf"));
        output.WriteLine($"{path}: {bytes:N0} bytes");
        Assert.Equal(dir.File("copy.gzf"), path);
        Assert.True(bytes > 10_000 && new FileInfo(path).Length == bytes);
        Assert.Equal(projectFiles, Directory.GetFiles(s.ProjectDirectory, "*", SearchOption.AllDirectories).Length);
        Assert.NotEmpty(await s.ListFunctionsAsync());
    }

    /// <summary>The background function pass builds the function table after the open; listings come from it until the program changes.</summary>
    [GhidraFact]
    public async Task The_function_pass_serves_listings_until_the_program_changes()
    {
        await using var s = await Open();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        (bool Ready, int Functions) table;
        while (!(table = await s.FunctionTableAsync()).Ready && clock.Elapsed < TimeSpan.FromSeconds(120)) await Task.Delay(200);
        output.WriteLine($"function table: {table.Functions} functions after {clock.Elapsed.TotalSeconds:0.0} s");
        Assert.True(table.Ready);
        var listed = await s.ListFunctionsAsync(withReferences: true);
        Assert.Equal(table.Functions, listed.Count);
        Assert.Contains(listed, f => f.References > 0);
        Assert.Equal(listed.Select(f => f.StartRva), (await s.ListFunctionsAsync()).Select(f => f.StartRva));
        // a change (a label) makes the table stale: the live listing serves
        var rva = NativeIdaProviderTests.ExportRva(shared.Sample, Export);
        await s.RunJavaAsync($"createLabel(toAddr(0x{s.ImageBase + rva + 1:X}L), \"sample_pass_label\", false, ghidra.program.model.symbol.SourceType.USER_DEFINED);", 60);
        Assert.False((await s.FunctionTableAsync()).Ready);
        Assert.Equal(listed.Count, (await s.ListFunctionsAsync()).Count);
        await s.RunJavaAsync("for (var x : currentProgram.getSymbolTable().getSymbols(\"sample_pass_label\")) x.delete();", 60);
    }

    [GhidraFact]
    public async Task The_program_types_export_as_a_header_and_an_archive()
    {
        await using var s = await Open();
        var declared = await s.ApplyUserTypesAsync(new NativeUserTypeBatch(["struct SampleExported { int len; char tag[4]; struct SampleExported *next; };"], [], [], []));
        Assert.Equal(0, declared.DeclarationErrors);
        using var dir = new TempDir();
        var (header, headerBytes, count) = await s.ExportTypesAsync(dir.File("types.h"), "h");
        var text = File.ReadAllText(header);
        output.WriteLine($"{count} types, {headerBytes:N0} bytes");
        Assert.Contains("struct SampleExported {", text);
        Assert.Contains("char tag[4];", text);
        var (archive, archiveBytes, archived) = await s.ExportTypesAsync(dir.File("types.gdt"), "gdt");
        Assert.Equal(count, archived);
        Assert.True(archiveBytes > 1000 && new FileInfo(archive).Length == archiveBytes);
    }

    [GhidraFact]
    public async Task Function_record_has_prototype_convention_storage_and_thunk_target()
    {
        await using var s = await Open();
        var rva = NativeIdaProviderTests.ExportRva(shared.Sample, Export);
        var r = await s.GetFunctionRecordAsync(rva + 2);
        output.WriteLine(string.Join("\n", Corvus.Tools.NativeEngineCode.RecordLines(r, x => $"0x{x:X}")));
        Assert.Equal(rva, r.Start);
        Assert.Contains(Export, r.Prototype);
        Assert.Equal("__fastcall", r.CallingConvention);
        Assert.NotNull(r.SignatureSource);
        Assert.Equal(4, r.Parameters.Count);
        Assert.Equal("RCX:8", r.Parameters[0].Storage);
        Assert.Contains(r.Ranges, x => x.Start == rva && x.End > rva);
        var thunk = (await s.ListFunctionsAsync()).First(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        var t = await s.GetFunctionRecordAsync(thunk.StartRva);
        output.WriteLine($"{t.Name} -> {t.ThunkTargetName}");
        Assert.NotNull(t.ThunkTargetName);
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFunctionRecordAsync(0x10))).Code);
    }
}

/// <summary>The engine read views against a real IDA (idalib), on a system DLL analyzed once for the class.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeIdaViewTests(ITestOutputHelper output, IdaCacheFixture shared) : IClassFixture<IdaCacheFixture>
{
    private const string Export = "CheckSumMappedFile";

    [IdaFact]
    public async Task Image_info_is_the_engine_view_of_the_image()
    {
        var s = await shared.Session;
        var info = await s.GetEngineInfoAsync();
        output.WriteLine($"{info.Version} {info.Language} {info.Compiler} {info.Format} {info.Functions} functions, {info.ExternalFunctions} external, " +
                         $"{info.Blocks.Count} blocks, analysis {info.Analysis}");
        Assert.StartsWith("9.", info.Version);
        Assert.Equal("metapc:LE:64", info.Language);
        Assert.Equal("pe", info.Format);
        Assert.Equal((8, "little"), (info.PointerSize, info.Endian));
        Assert.True(info.Functions > 100);
        Assert.True(info.ExternalFunctions > 10);
        Assert.Equal(AnalysisCache.HashFile(NativeIdaProviderTests.System64), info.Sha256);
        Assert.Contains(info.Blocks, b => b.Name == ".text" && b.Permissions.StartsWith('r') && b.Initialized);
        Assert.Contains(NativeIdaProviderTests.ExportRva(NativeIdaProviderTests.System64, Export), info.EntryPoints);
        Assert.Equal("complete", info.Analysis);
    }

    [IdaFact]
    public async Task Defined_data_lists_typed_items_with_values_and_strings()
    {
        var s = await shared.Session;
        var data = await s.ListDataAsync(100_000);
        output.WriteLine($"{data.Total} items; " + string.Join("; ", data.Items.Take(8).Select(d => $"0x{d.Rva:X} {d.Size} {d.Type} {d.Label} = {d.Value}")));
        Assert.True(data.Total > 200, $"{data.Total} items");
        Assert.True(data.Items.Zip(data.Items.Skip(1)).All(p => p.First.Rva < p.Second.Rva));
        Assert.Contains(data.Items, d => d.IsString && d.Value != null && d.Size > 1);
        Assert.Contains(data.Items, d => d.Label != null && d.Type.Length > 0);
        Assert.Equal(5, (await s.ListDataAsync(5)).Items.Count);
    }

    [IdaFact]
    public async Task Defined_strings_include_unreferenced_ones()
    {
        var s = await shared.Session;
        var strings = await s.ListStringsAsync(100_000);
        output.WriteLine($"{strings.Count} strings; " + string.Join("; ", strings.Take(6).Select(x => $"0x{x.Rva:X} {x.Type} {x.Text}")));
        Assert.True(strings.Count > 20);
        Assert.Contains(strings, x => x.Type == "C_16" && x.Text.Length > 2);
        Assert.Contains(strings, x => x.Type == "C" && x.Text == Export);
    }

    [IdaFact]
    public async Task Function_record_has_prototype_convention_storage_and_thunk_target()
    {
        var s = await shared.Session;
        var rva = NativeIdaProviderTests.ExportRva(NativeIdaProviderTests.System64, Export);
        var r = await s.GetFunctionRecordAsync(rva + 2);
        output.WriteLine(string.Join("\n", Corvus.Tools.NativeEngineCode.RecordLines(r, x => $"0x{x:X}")));
        Assert.Equal(rva, r.Start);
        Assert.Contains(Export, r.Prototype);
        Assert.Contains(r.CallingConvention, new[] { "__fastcall", "__stdcall" }); // IDA keeps the x64 type library's __stdcall
        Assert.Equal(4, r.Parameters.Count);
        Assert.Equal("rcx", r.Parameters[0].Storage);
        Assert.Contains(r.Ranges, x => x.Start == rva && x.End > rva);
        var thunk = (await s.ListFunctionsAsync()).First(f => f.Flags.HasFlag(NativeFunctionFlags.Thunk));
        var t = await s.GetFunctionRecordAsync(thunk.StartRva);
        output.WriteLine($"{t.Name} -> {t.ThunkTargetName}");
        Assert.NotNull(t.ThunkTargetName);
        Assert.Equal(Core.ErrorCode.NotFound, (await Assert.ThrowsAsync<Core.ToolError>(() => s.GetFunctionRecordAsync(0x10))).Code);
    }
}