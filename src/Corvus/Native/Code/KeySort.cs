using System.Numerics;

namespace Corvus.Native.Code;

/// <summary>Parallel bucket sort of key / item arrays; equal keys end unordered (see <see cref="OrderTies"/>).</summary>
internal static class KeySort
{
    private const int ParallelMin = 1 << 16;
    private const int BucketBits = 12;

    /// <summary>Sorts the first <paramref name="count"/> items by key; may replace both arrays by sorted copies of the same length.</summary>
    public static void Sort<T>(ref ulong[] keys, ref T[] items, int count, int parallelism)
    {
        if (parallelism <= 0) parallelism = Environment.ProcessorCount;
        if (parallelism == 1 || count < ParallelMin)
        {
            Array.Sort(keys, items, 0, count);
            return;
        }
        ulong min = ulong.MaxValue, max = 0;
        for (int i = 0; i < count; i++)
        {
            if (keys[i] < min) min = keys[i];
            if (keys[i] > max) max = keys[i];
        }
        if (min == max) return;
        int shift = Math.Max(0, 64 - BitOperations.LeadingZeroCount(max - min) - BucketBits);
        var starts = new int[(1 << BucketBits) + 1];
        for (int i = 0; i < count; i++) starts[(int)((keys[i] - min) >> shift) + 1]++;
        for (int b = 0; b < 1 << BucketBits; b++) starts[b + 1] += starts[b];
        var next = (int[])starts.Clone();
        var sortedKeys = new ulong[keys.Length];
        var sortedItems = new T[items.Length];
        for (int i = 0; i < count; i++)
        {
            int at = next[(int)((keys[i] - min) >> shift)]++;
            sortedKeys[at] = keys[i];
            sortedItems[at] = items[i];
        }
        Parallel.For(0, 1 << BucketBits, new ParallelOptions { MaxDegreeOfParallelism = parallelism }, b =>
        {
            int n = starts[b + 1] - starts[b];
            if (n > 1) Array.Sort(sortedKeys, sortedItems, starts[b], n);
        });
        keys = sortedKeys;
        items = sortedItems;
    }

    /// <summary>Orders the items of each run of equal keys by <paramref name="comparer"/> (sorted keys).</summary>
    public static void OrderTies<T>(ulong[] keys, T[] items, int count, IComparer<T>? comparer = null)
    {
        for (int i = 0; i < count;)
        {
            int j = i + 1;
            while (j < count && keys[j] == keys[i]) j++;
            if (j - i > 1) Array.Sort(items, i, j - i, comparer);
            i = j;
        }
    }

    /// <summary>Non-overlapping owner map of code ranges by start; on overlap the lowest function index wins.</summary>
    /// <param name="keys">Start &lt;&lt; 32 | function index.</param>
    /// <param name="ends">Exclusive ends.</param>
    public static (uint[] Starts, uint[] Ends, int[] Functions) OwnerMap(ulong[] keys, uint[] ends, int parallelism)
    {
        Sort(ref keys, ref ends, keys.Length, parallelism);
        var os = new uint[keys.Length];
        var oe = new uint[keys.Length];
        var of = new int[keys.Length];
        int n = 0;
        uint covered = 0;
        for (int i = 0; i < keys.Length; i++)
        {
            uint s = Math.Max((uint)(keys[i] >> 32), covered), e = ends[i];
            if (s >= e) continue;
            os[n] = s; oe[n] = e; of[n] = (int)(uint)keys[i];
            n++;
            covered = e;
        }
        return (os[..n], oe[..n], of[..n]);
    }
}
