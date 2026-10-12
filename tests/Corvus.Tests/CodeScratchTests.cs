using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>Scratch structures of the code analysis: the constant-time scratch set and the code bitmap.</summary>
public class CodeScratchTests
{
    [Fact]
    public void Scratch_set_grows_keeps_insertion_order_and_empties()
    {
        var set = new ScratchSet();
        var values = Enumerable.Range(0, 5000).Select(i => (uint)(i * 16 + 0x401000)).ToArray();
        foreach (uint v in values) Assert.True(set.Add(v));
        Assert.False(set.Add(values[123]));
        Assert.Equal(values, set.Items);
        Assert.All(values, v => Assert.True(set.Contains(v)));
        Assert.False(set.Contains(0x401008));
        set.Clear();
        Assert.Equal(0, set.Count);
        Assert.False(set.Contains(values[0]));
        Assert.True(set.Add(values[0]));
        Assert.Equal([values[0]], set.Items);
    }

    [Fact]
    public void Bitmap_ranges_cross_words()
    {
        var bits = new CodeBitmap(256);
        bits.SetRange(60, 70);
        bits.SetRange(-3, 5);
        bits.SetRange(192, 64);
        for (long i = 0; i < 256; i++)
            Assert.Equal(i is >= 60 and < 130 or < 2 or >= 192, bits[i]);
    }

    [Fact]
    public void Bitmap_finds_the_next_clear_bit_across_words()
    {
        var bits = new CodeBitmap(256);
        bits.SetRange(10, 150);
        Assert.Equal(5, bits.NextClear(5, 256));
        Assert.Equal(160, bits.NextClear(10, 256));
        Assert.Equal(100, bits.NextClear(70, 100));
        bits.SetRange(160, 96);
        Assert.Equal(256, bits.NextClear(10, 256));
    }
}
