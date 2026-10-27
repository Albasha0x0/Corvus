using System.Text.Json;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>native_call_tree records and the shared <see cref="NativeTreeNode"/> row.</summary>
public class NativeCallTreeTests
{
    [Fact]
    public void Tree_nodes_serialize_compact_with_camel_case_fields()
    {
        var root = new NativeTreeNode(0, null, 0, "main", "0x401000", null, null, null);
        var child = new NativeTreeNode(1, 0, 1, "kernel32.dll!CreateFileW", "0x402000", "lib.dll", "import", ["more"]) { Note = "KERNELBASE.dll!CreateFileW" };
        var json = JsonSerializer.Serialize(new[] { root, child }, ToolOutput.Json);
        Assert.Equal("""[{"id":0,"depth":0,"name":"main","address":"0x401000"},{"id":1,"parent":0,"depth":1,"name":"kernel32.dll!CreateFileW","address":"0x402000","image":"lib.dll","edge":"import","flags":["more"],"note":"KERNELBASE.dll!CreateFileW"}]""", json);
    }

    private static readonly string Kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    private static async Task<(string Text, NativeCallTreeResult Record)> Tree(NativeCodeTools tools, string function, int depth = 3, int offset = 0, int limit = 200,
        string direction = "callees")
    {
        var collector = ToolOutput.Collect();
        var text = await tools.NativeCallTree("kernel32.dll", function, direction, depth, maxNodes: 2000, offset: offset, limit: limit);
        return (text, Assert.IsType<NativeCallTreeResult>(collector.Value));
    }

    [WindowsFact]
    public async Task Tree_rows_page_in_tree_order_and_the_frontier_reexpands()
    {
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options);
        var tools = new NativeCodeTools(env.Workspace, code, env.Pager);
        var index = await code.Index(env.Workspace.LoadAny(Kernel32).Native!, null, default);
        // A function with a few levels of callees.
        var root = index.Functions.Where(f => index.Callees(f).Count(c => c.Function != null) is >= 3 and <= 12).OrderBy(f => f.Start).First();
        string at = $"rva:0x{root.Start:X}";

        var (text, full) = await Tree(tools, at);
        Assert.Equal(full.Total, full.Items.Count);
        Assert.Equal(Enumerable.Range(0, full.Total), full.Items.Select(n => n.Id));
        Assert.Null(full.Items[0].Parent);
        Assert.All(full.Items.Skip(1), n => Assert.Equal(full.Items[n.Parent!.Value].Depth + 1, n.Depth));
        Assert.Contains($"{full.Total} nodes", text);

        // A walk by pages of 3 gives the same rows.
        var walked = new List<NativeTreeNode>();
        for (int offset = 0; offset < full.Total; offset += 3)
        {
            var page = (await Tree(tools, at, offset: offset, limit: 3)).Record;
            walked.AddRange(page.Items);
            // A page names its own unexpanded nodes only (a whole tree's frontier can be thousands).
            Assert.All(page.Frontier ?? [], f => Assert.Contains(page.Items, n => n.Address == f));
        }
        Assert.Equal(JsonSerializer.Serialize(full.Items, ToolOutput.Json), JsonSerializer.Serialize(walked, ToolOutput.Json));

        // Depth 1 leaves its children on the frontier; expanding each frontier node gives the depth-2 nodes of the full tree.
        var shallow = (await Tree(tools, at, depth: 1)).Record;
        Assert.NotNull(shallow.Frontier);
        var below = new HashSet<string>();
        foreach (var f in shallow.Frontier!)
            foreach (var n in (await Tree(tools, f, depth: 1)).Record.Items.Where(n => n.Depth == 1))
                below.Add(n.Name);
        Assert.Subset(below, full.Items.Where(n => n.Depth == 2).Select(n => n.Name).ToHashSet());

        // direction=both: the root, then callers and callees by call site
        var both = (await Tree(tools, at, direction: "both")).Record;
        Assert.Equal("both", both.Direction);
        Assert.All(both.Items.Skip(1), n => Assert.Matches("^0x[0-9A-F]+$", n.Site!));
        Assert.Contains(both.Items, n => n.Flags?[0] == "callee");
    }
}
