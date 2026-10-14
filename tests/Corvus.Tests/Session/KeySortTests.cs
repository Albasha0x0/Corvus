using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>Bucketed parallel key sorts give the order a serial sort gives, ties ordered by the caller.</summary>
public class KeySortTests
{
    [Fact]
    public void Parallel_sort_with_ordered_ties_equals_the_serial_sort()
    {
        var random = new Random(7);
        int n = 300_000;
        var keys = new ulong[n];
        var items = new int[n];
        for (int i = 0; i < n; i++)
        {
            // many equal keys, and a wide spread
            keys[i] = (ulong)random.Next(0, 50_000) << 32 | (uint)random.Next(0, 4);
            items[i] = i;
        }
        var serialKeys = (ulong[])keys.Clone();
        var serialItems = (int[])items.Clone();
        KeySort.Sort(ref serialKeys, ref serialItems, n, 1);
        KeySort.OrderTies(serialKeys, serialItems, n);
        KeySort.Sort(ref keys, ref items, n, 8);
        KeySort.OrderTies(keys, items, n);
        Assert.Equal(serialKeys, keys);
        Assert.Equal(serialItems, items);
        for (int i = 1; i < n; i++) Assert.True(keys[i - 1] < keys[i] || keys[i - 1] == keys[i] && items[i - 1] < items[i]);
    }

    [Fact]
    public void Owner_map_gives_overlapping_code_to_the_lowest_function()
    {
        // function 0: [10, 20) and [40, 50); function 1: [15, 30); function 2: [40, 45)
        ulong Key(uint start, int f) => (ulong)start << 32 | (uint)f;
        var (starts, ends, owners) = KeySort.OwnerMap([Key(10, 0), Key(40, 0), Key(15, 1), Key(40, 2)], [20, 50, 30, 45], 1);
        Assert.Equal([10u, 20u, 40u], starts);
        Assert.Equal([20u, 30u, 50u], ends);
        Assert.Equal([0, 1, 0], owners);
    }
}
