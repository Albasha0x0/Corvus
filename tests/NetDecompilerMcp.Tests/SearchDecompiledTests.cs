using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>search_decompiled over a scripted engine: hits in address order, the cursor across budgets, lanes in parallel, the pseudocode cache.</summary>
public sealed class SearchDecompiledTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (NativeSearchDecompiledTools Tools, ScriptedEngine Engine, LoadedNative Native) Setup(Action<ScriptedEngine> script)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine { Clock = new ManualClock() };
        script(engine);
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return (new NativeSearchDecompiledTools(workspace, engines, new OutputPager(options), time: engine.Clock), engine, native);
    }

    /// <summary>40 functions; every third calls memcpy (once, or twice in every ninth); f_11 is a thunk; f_20 fails to decompile.</summary>
    private static void Forty(ScriptedEngine e)
    {
        for (uint i = 0; i < 40; i++)
        {
            var lines = new List<string> { $"int f_{i}(void)", "{" };
            if (i % 3 == 0) lines.Add("  memcpy(dst, src, n);");
            if (i % 9 == 0) lines.Add("  MemCpy(a, b, 4);");
            lines.Add("  return 0;");
            lines.Add("}");
            e.Add(0x1000 + i * 0x10, 0x10, $"f_{i}", i == 11 ? NativeFunctionFlags.Thunk : NativeFunctionFlags.None, [.. lines]);
        }
        e.Failing.Add(0x1000 + 20 * 0x10);
    }


    [Fact]
    public async Task Hits_come_in_address_order_with_line_numbers()
    {
        var (tools, engine, native) = Setup(Forty);
        var collector = StructuredOutput.Begin();
        var text = await tools.SearchDecompiled(native.Id, "memcpy\\(");
        var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        Assert.Equal(39, report.Functions); // the thunk is left out
        Assert.Null(report.Cursor);
        Assert.Equal(1, report.Failed);
        Assert.Contains("1 function did not decompile", text);
        Assert.Contains("f_20: failed: decompilation failed", text);
        // case-insensitive: memcpy and MemCpy; f_0, f_9, f_18, f_27, f_36 have both
        Assert.Equal(14 + 5, report.Hits.Count);
        Assert.Equal(report.Hits.OrderBy(h => h.Function, StringComparer.Ordinal).ThenBy(h => h.Line).Select(h => (h.Function, h.Line)), report.Hits.Select(h => (h.Function, h.Line)));
        var first = report.Hits[0];
        Assert.Equal(("f_0", 3, "memcpy(dst, src, n);"), (first.Name, first.Line, first.Text));
        Assert.Contains("0x140001000  f_0:3  memcpy(dst, src, n);", text);
        Assert.Contains("Every function in scope was searched.", text);
    }

    [Fact]
    public async Task The_filter_narrows_the_scope_and_exact_case_is_inline()
    {
        var (tools, _, native) = Setup(Forty);
        var collector = StructuredOutput.Begin();
        await tools.SearchDecompiled(native.Id, "(?-i)MemCpy", filter: "/^f_[0-9]$/");
        var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        Assert.Equal(10, report.Functions);
        Assert.Equal(["f_0", "f_9"], report.Hits.Select(h => h.Name));
    }

    [Fact]
    public async Task The_hit_limit_stops_after_a_whole_function_and_the_cursor_continues()
    {
        var (tools, _, native) = Setup(Forty);
        var all = new List<NativeSearchDecompiledTools.DecompiledHit>();
        int? cursor = 0;
        int calls = 0;
        while (cursor is { } c)
        {
            var collector = StructuredOutput.Begin();
            var text = await tools.SearchDecompiled(native.Id, "memcpy", cursor: c, limit: 4);
            var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
            Assert.True(report.Hits.Count <= 5, text); // the last function's hits are kept whole
            if (report.Cursor != null)
            {
                Assert.Equal("hits", report.StoppedBy);
                Assert.Contains($"cursor={report.Cursor}", text);
            }
            all.AddRange(report.Hits);
            cursor = report.Cursor;
            Assert.True(++calls < 20);
        }
        var collectorAll = StructuredOutput.Begin();
        await tools.SearchDecompiled(native.Id, "memcpy");
        var whole = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collectorAll.Value);
        Assert.Equal(whole.Hits, all);
    }

    [Fact]
    public async Task MaxFunctions_and_the_time_budget_end_with_a_cursor()
    {
        var (tools, engine, native) = Setup(e =>
        {
            Forty(e);
            e.Slow[0x1000 + 30 * 0x10] = 5;
        });
        var collector = StructuredOutput.Begin();
        await tools.SearchDecompiled(native.Id, "memcpy", maxFunctions: 10);
        var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        Assert.Equal((10, 10, "functions"), (report.Searched, report.Cursor!.Value, report.StoppedBy));

        collector = StructuredOutput.Begin();
        var text = await tools.SearchDecompiled(native.Id, "memcpy", cursor: 10, seconds: 1);
        report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        Assert.Equal("time", report.StoppedBy);
        Assert.Equal(30, report.Cursor!.Value); // f_30 used the whole second and is a timeout failure; f_31 (index 30, after the thunk) is next
        Assert.Contains("f_30: timeout", text);
        Assert.Contains("seconds=1 used", text);
    }

    [Fact]
    public async Task Requests_fill_the_decompiler_pool_and_a_second_search_reuses_the_pseudocode()
    {
        var (tools, engine, native) = Setup(e =>
        {
            Forty(e);
            e.Lanes = 3;
        });
        var text = await tools.SearchDecompiled(native.Id, "return");
        Assert.Contains("(requests of 24 over a decompiler pool of 3)", text);
        Assert.Equal([24, 15], engine.Batches);
        int decompiled = engine.Decompiles;
        Assert.Equal(38, decompiled);
        await tools.SearchDecompiled(native.Id, "memcpy");
        Assert.Equal(decompiled, engine.Decompiles);
    }

    [Fact]
    public async Task Bad_arguments_fail_before_the_engine()
    {
        var (tools, engine, native) = Setup(Forty);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.SearchDecompiled(native.Id, "("))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.SearchDecompiled(native.Id, "x", cursor: 500))).Code);
        Assert.Equal(0, engine.Decompiles);
    }
}
