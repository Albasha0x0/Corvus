using System.Reflection;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A page of a node and edge result keeps edges between its own nodes and names the cut ends as pending.</summary>
public sealed class GraphPagingTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static void Call(List<byte> code, int at, int target)
    {
        code.Add(0xE8);
        code.AddRange(BitConverter.GetBytes(target - (at + 5)));
    }

    /// <summary>
    /// A function of eight conditional blocks, and a root calling three functions that each call one leaf:
    /// both are larger than a page of two.
    /// </summary>
    private string Image()
    {
        var code = new List<byte>();
        for (int i = 0; i < 8; i++) code.AddRange([0x85, 0xC0, 0x74, 0x00]);
        code.Add(0xC3);
        while (code.Count < 0x40) code.Add(0xCC);
        // Root at +0x40 calls +0x60, +0x70 and +0x80; each of those calls the leaf at +0x90.
        int root = 0x1040;
        code.AddRange([0x48, 0x83, 0xEC, 0x28]);
        for (int i = 0; i < 3; i++) Call(code, 0x1000 + code.Count, 0x1060 + 0x10 * i);
        code.AddRange([0x48, 0x83, 0xC4, 0x28, 0xC3]);
        Assert.True(code.Count <= 0x60 && root == 0x1040);
        while (code.Count < 0x60) code.Add(0xCC);
        for (int i = 0; i < 3; i++)
        {
            Call(code, 0x1000 + code.Count, 0x1090);
            code.Add(0xC3);
            while (code.Count < 0x70 + 0x10 * i) code.Add(0xCC);
        }
        code.Add(0xC3);
        var b = new PeBuilder { EntryPoint = 0x1000 };
        b.Add(".text", [.. code], 0x60000020);
        var path = _dir.File("graph.dll");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    private NativeCodeTools Tools(AssemblyWorkspace ws, ServerOptions options) => new(ws, new NativeCodeService(ws, options), new OutputPager(options));

    // Regression: a page of trace_native_values named a node it did not return.
    [Fact]
    public async Task A_cfg_page_names_a_successor_block_on_another_page_as_pending()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var tools = Tools(ws, options);
        var path = Image();
        bool cut = false;
        for (int offset = 0; offset < 8; offset += 2)
        {
            var collector = ToolOutput.Collect();
            var text = await tools.GetCfg(path, "0x140001000", offset: offset, limit: 2);
            var report = Assert.IsType<CfgReport>(collector.Value);
            var starts = report.Items.Select(b => b.Start).ToHashSet();
            var all = report.Items.SelectMany(b => b.Successors.Select(s => (b.Start, s.To))).ToList();
            foreach (var (from, to) in all.Where(e => !starts.Contains(e.To)))
                Assert.Contains(report.PendingEdges, p => p.From == from && p.To == to);
            foreach (var p in report.PendingEdges)
            {
                Assert.DoesNotContain(p.To, starts);
                Assert.Contains($"off page: {p.To}", text);
            }
            cut |= report.PendingEdges.Count > 0;
        }
        Assert.True(cut);
    }

    [Fact]
    public async Task A_call_tree_page_names_a_parent_on_another_page_as_pending()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var tools = Tools(ws, options);
        var path = Image();
        bool cut = false;
        for (int offset = 0; offset < 7; offset += 2)
        {
            var collector = ToolOutput.Collect();
            await tools.NativeCallTree(path, "0x140001040", offset: offset, limit: 2, depth: 3);
            var report = Assert.IsType<NativeCallTreeResult>(collector.Value);
            var ids = report.Items.Select(n => n.Id).ToHashSet();
            foreach (var n in report.Items.Where(n => n.Parent is { } p && !ids.Contains(p)))
                Assert.Contains(report.PendingParents ?? [], p => p.Node == n.Parent);
            foreach (var p in report.PendingParents ?? [])
                Assert.DoesNotContain(p.Node, ids);
            cut |= report.PendingParents is { Count: > 0 };
        }
        Assert.True(cut);
    }

    [Fact]
    public void The_path_and_tree_rows_of_the_managed_tools_hold_no_node_ids()
    {
        foreach (var type in new[] { typeof(CallTreeRow), typeof(PathStepEntry), typeof(CallPathEntry) })
            Assert.DoesNotContain(type.GetProperties(BindingFlags.Public | BindingFlags.Instance),
                p => p.Name is "Id" or "Parent" or "From" or "To");
    }
}
