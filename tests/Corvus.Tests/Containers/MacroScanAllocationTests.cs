using Corvus.Core.Documents;
using Xunit.Abstractions;
using static Corvus.Tests.DocumentFixtures;

namespace Corvus.Tests;

/// <summary>
/// What reading a small compound document allocates, measured in a process of
/// its own so it is the first read.
/// </summary>
public sealed class MacroScanAllocationTests(ITestOutputHelper output)
{
    // The first read builds the macro rules: 274 MB on 18797c94, 11 MB after.
    private const long FirstReadBound = 32 << 20;
    private const long LaterReadBound = 512 << 10;

    [Fact]
    public void The_first_read_of_a_small_compound_document_allocates_under_its_bound()
    {
        if (ChildTest.Rerun(this, output)) return;
        var data = Compound([("WordDocument", new byte[600]), .. VbaStreams("Macros/", ("Module1", "standard", "Sub AutoOpen()\r\n  Shell \"calc\"\r\nEnd Sub\r\n"))]);
        long Read()
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            Assert.NotNull(OfficeDocument.FromCompound(CompoundFile.Read(data, "a.doc"), default));
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }
        long first = Read(), second = Read();
        output.WriteLine($"first read {first:N0} bytes, second {second:N0} bytes");
        Assert.True(first < FirstReadBound, $"first read allocated {first:N0} bytes, bound {FirstReadBound:N0}");
        Assert.True(second < LaterReadBound, $"second read allocated {second:N0} bytes, bound {LaterReadBound:N0}");
    }
}
