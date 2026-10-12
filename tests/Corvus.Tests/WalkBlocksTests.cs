using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>The compact blocks the virtual call flow walks are the blocks and successors of the function's graph.</summary>
public class WalkBlocksTests
{
    [Fact]
    public void Blocks_and_successors_equal_the_graph_of_every_function()
    {
        var index = NativeCodeIndex.Build(NativeImageLoader.Open(NativeFixtures.LinuxX64DbgShim), new CodeIndexOptions { ResolveVirtualCalls = false });
        var walker = index.NewWalker()!;
        var blocks = new BlockList();
        int checkedBlocks = 0;
        foreach (var f in index.Functions)
        {
            var graph = index.GetGraph(f);
            walker.WalkBlocks(f.Start, NativeCodeIndex.ChunkRoots(f), blocks, default);
            Assert.Equal(graph.Blocks.Count, blocks.Count);
            var starts = graph.Blocks.Select(b => b.Start).ToList();
            for (int i = 0; i < blocks.Count; i++)
            {
                var b = graph.Blocks[i];
                Assert.Equal((b.Start, b.End), (blocks.Starts[i], blocks.Ends[i]));
                // successors inside the function, tail calls left out, each once in edge order
                var expected = b.Successors.Where(e => e.Kind != EdgeKind.TailCall).Select(e => starts.IndexOf(e.To)).Where(t => t >= 0).Distinct().ToArray();
                Assert.Equal(expected, blocks.Successors(i).ToArray());
                checkedBlocks++;
            }
        }
        Assert.True(checkedBlocks > 1000, $"{checkedBlocks} blocks");
    }
}
