using Corvus.Core;
using Corvus.Core.WebAssembly;
using Corvus.Native;
using Corvus.Native.Code;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A WebAssembly module as a loaded image: the format registry, the code index, WAT and lifted views through the native tools.</summary>
public sealed class WasmCodeTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void The_format_registry_opens_a_module_as_an_image()
    {
        var path = Save("names.wasm", WasmFixtures.Valid().Single(f => f.Name == "names").Bytes);
        Assert.Equal(NativeFileKind.Wasm, NativeImageLoader.DetectFile(path));
        var image = Assert.IsType<WasmImage>(NativeImageLoader.Open(path));
        Assert.Equal((ImageFormat.Wasm, NativeArch.Wasm), (image.Format, image.Arch));
        Assert.Equal(["log", "add(int, long)", "dup", "dup", "café"], image.FunctionNames);
        Assert.Equal("env", Assert.Single(image.Imports).Module);
        Assert.Contains(image.Sections, s => s.Name == "code" && s.IsExecutable);
        Assert.Equal(NativeImageLoader.Providers.Select(p => p.Kind), [NativeFileKind.Pe, NativeFileKind.Elf, NativeFileKind.MachO, NativeFileKind.MachOFat, NativeFileKind.Wasm]);
    }

    [Fact]
    public void Index_holds_calls_imports_globals_indirect_edges_and_data_strings()
    {
        var path = Save("names.wasm", WasmFixtures.Valid().Single(f => f.Name == "names").Bytes);
        var image = (WasmImage)NativeImageLoader.Open(path);
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(CodeSupport.Bytecode, index.Support);
        var add = index.Functions.Single(f => f.Name == "add(int, long)");
        Assert.Equal("log", Assert.Single(index.Callees(add)).Import!.Name);
        var dup = index.Functions.First(f => f.Name == "dup");
        Assert.Equal(add.Start, Assert.Single(index.Callees(dup)).Target);
        Assert.Contains(index.RefsFrom(dup), x => x.Kind == XrefKind.Write && x.To == image.GlobalAddress(1));
        // call_indirect of type 1 reaches the table's functions of that type (dup and dup.1 are in the element segment)
        var cafe = index.Functions.Single(f => f.Name == "café");
        Assert.Equal(2, index.Callees(cafe).Count(c => c.Kind == XrefKind.VirtualPossible));
    }

    [Fact]
    public async Task Native_tools_give_wat_lifted_code_and_references()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var path = WasmTextTests.DotnetNative("10.0.11");
        await h.WorkspaceTools.LoadAssembly(path);
        var id = h.Workspace.Read(() => h.Workspace.FindNative(path))!.Id;
        Assert.Contains("malloc", await h.CodeTools.ListFunctions(id, filter: "malloc"));
        var wat = await h.CodeTools.Disassemble(id, "malloc");
        Assert.Contains(";; malloc: function", wat);
        Assert.Contains("  (func (;", wat);
        var lifted = await h.Analysis.DecompileNative(id, "malloc");
        Assert.Contains("// malloc: function", lifted);
        Assert.Contains("malloc(i32 p0)", lifted);
        Assert.Contains("malloc", await h.CodeTools.NativeCallTree(id, "malloc", direction: "callers", depth: 1));
        Assert.Contains("Call", await h.CodeTools.FindXrefs(id, "malloc"));
        output.WriteLine(lifted.Length > 3000 ? lifted[..3000] : lifted);
    }

    [Fact]
    public async Task Cfg_and_instructions_of_a_function()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var path = Save("control.wasm", WasmFixtures.Valid().Single(f => f.Name == "control").Bytes);
        await h.WorkspaceTools.LoadAssembly(path);
        var cfg = await h.CodeTools.GetCfg("control.wasm", "func_0");
        Assert.Contains("ConditionalJump", cfg);
        var inspected = await h.CodeTools.InspectInstruction("control.wasm", "func_0", limit: 4);
        Assert.Contains("block", inspected);
        Assert.Contains("local.get 0", inspected);
        Assert.Matches(@"br_if 1\n +operand stack: by its immediates; flow conditional_jump to label 1", inspected.Replace("\r\n", "\n"));
    }

    [Fact]
    public void Fuzzed_modules_never_throw_in_the_index_graph_and_lifter()
    {
        var seed = WasmFixtures.Valid().Single(f => f.Name == "control").Bytes;
        var failures = FormatFuzz.Run(seed, b =>
        {
            if (!WasmBinary.Looks(b)) return;
            var image = new WasmImage(b, "m.wasm");
            var index = NativeCodeIndex.Build(image);
            foreach (var f in index.Functions)
            {
                index.GetGraph(f);
                WasmDecompiler.Function(image.Module, image.FunctionAt(f.Start)!.Value, i => $"f{i}", image.Memory);
            }
        }, 2000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    /// <summary>A module of <paramref name="functions"/> functions, each a chain of loads, calls, call_indirect and global updates.</summary>
    internal static byte[] Large(int functions)
    {
        var b = new WasmModuleBuilder();
        uint t = b.Type([WasmType.I32], [WasmType.I32]);
        b.Memory(16);
        b.Table(WasmType.FuncRef, 1000);
        b.Global(WasmType.I32, true, new WasmAsm().I32(0).Bytes);
        b.Data(1024, "a string the code points at\0"u8.ToArray());
        b.Element(0, [.. Enumerable.Range(0, 1000).Select(i => (uint)i)]);
        for (int f = 0; f < functions; f++)
        {
            var a = new WasmAsm();
            for (int r = 0; r < 13; r++)
                a.Op(0x20).U(0).I32(1024).Op(0x6A).Op(0x28, 2, 4).Op(0x10).U((ulong)((f + r + 1) % functions)).I32(7).Op(0x11).U(t).U(0)
                    .Op(0x23).U(0).Op(0x6A).Op(0x24).U(0);
            b.Func(t, a.Op(0x20).U(0).Bytes);
        }
        return b.Build();
    }

    /// <summary>Every native tool on a real Emscripten module answers without an unexpected exception.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task Every_native_tool_answers_on_a_real_module()
    {
        using var h = new NativeToolHarness();
        await h.Exercise(WasmTextTests.DotnetNative("10.0.11"));
        foreach (var c in h.Calls.Where(c => c.Failed || c.Error != null)) output.WriteLine(c.ToString());
        output.WriteLine($"{h.Calls.Count} calls, {h.Calls.Count(c => c.Error != null)} typed errors");
        Assert.DoesNotContain(h.Calls, c => c.Failed);
        // the code tools answer: list, disassemble (WAT), references and call trees
        Assert.DoesNotContain(h.Calls, c => c.Tool is "list_functions" or "disassemble" or "find_xrefs" or "native_call_tree" or "search_native_strings" && c.Error == ErrorCode.Unsupported);
    }
}

/// <summary>Index time of a Unity-WebGL-size module, measured without other tests running.</summary>
[Collection(nameof(SerialTimingTests))]
public sealed class WasmIndexSpeedTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void Sixty_megabyte_module_is_indexed_in_five_seconds()
    {
        var bytes = WasmCodeTests.Large(210_000);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var image = new WasmImage(bytes, "large.wasm");
        var index = NativeCodeIndex.Build(image);
        clock.Stop();
        output.WriteLine($"{bytes.Length:N0} bytes, {index.Functions.Count:N0} functions, {index.Stats.Instructions:N0} instructions, {index.Stats.Xrefs:N0} references, " +
                         $"{index.VirtualEdges.Count:N0} call_indirect edges: {clock.Elapsed.TotalSeconds:F2} s");
        Assert.True(bytes.Length >= 60_000_000, $"{bytes.Length:N0} bytes");
        Assert.Equal(210_000, index.Functions.Count);
        PerfBudget.Check(clock.Elapsed < TimeSpan.FromSeconds(5), $"{clock.Elapsed.TotalSeconds:F2} s", output);
    }
}
