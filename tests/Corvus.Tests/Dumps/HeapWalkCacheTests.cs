using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>dump_heap paging over a fake heap walk that counts its calls.</summary>
public sealed class HeapWalkCacheTests
{
    private static HeapWalk Fake(int objects) => new([], [.. Enumerable.Range(0, objects).Select(i => new HeapObject(0x1000UL + (ulong)i * 16, "T", 24, null))],
        objects, objects, false);

    [Fact]
    public void Two_object_offsets_of_one_dump_walk_the_heap_once()
    {
        using var service = new MinidumpService();
        int walks = 0;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { walks++; return Fake(10); }

        var first = service.HeapOf("d1", Walk, a => $"0x{a:X}", "", false, null, 0, 0, 4, 1000, [], default, keep: true);
        var second = service.HeapOf("d1", Walk, a => $"0x{a:X}", "", false, null, 0, 4, 4, 1000, [], default, keep: true);

        Assert.Equal(1, walks);
        Assert.Equal(["0x1000", "0x1010", "0x1020", "0x1030"], first.Items.Select(r => r.Address));
        Assert.Equal(["0x1040", "0x1050", "0x1060", "0x1070"], second.Items.Select(r => r.Address));
    }

    [Fact]
    public void A_running_program_is_walked_on_every_call()
    {
        using var service = new MinidumpService();
        int walks = 0;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { walks++; return Fake(3); }

        service.HeapOf("s1", Walk, a => $"0x{a:X}", "", false, null, 0, 0, 2, 1000, [], default);
        service.HeapOf("s1", Walk, a => $"0x{a:X}", "", false, null, 0, 2, 2, 1000, [], default);

        Assert.Equal(2, walks);
    }

    private static string Hex(ulong a) => $"0x{a:X}";

    [Fact]
    public void A_page_past_the_kept_cap_names_the_limit()
    {
        using var service = new MinidumpService();
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) =>
            new([], [.. Enumerable.Range(0, Math.Min(take, 5)).Select(i => new HeapObject(0x1000UL + (ulong)i, "T", 24, null))], 150_000, 150_000, false);

        var r = service.HeapOf("d1", Walk, Hex, "", false, null, 0, 99_998, 10, 1000, [], default, keep: true);

        Assert.Contains(r.Notes, n => n.Contains("Only the first 100000 matching objects", StringComparison.Ordinal) && !n.Contains("MaxCachedHeapObjects", StringComparison.Ordinal));
    }

    [Fact]
    public void A_different_type_walks_again()
    {
        using var service = new MinidumpService();
        int walks = 0;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { walks++; return Fake(3); }

        service.HeapOf("d1", Walk, Hex, "", false, "A", 0, 0, 2, 1000, [], default, keep: true);
        service.HeapOf("d1", Walk, Hex, "", false, "B", 0, 0, 2, 1000, [], default, keep: true);
        service.HeapOf("d1", Walk, Hex, "", false, "A", 0, 2, 2, 1000, [], default, keep: true);

        Assert.Equal(2, walks);
    }

    [Fact]
    public void Stats_mode_asks_for_no_objects()
    {
        using var service = new MinidumpService();
        int taken = -1;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { taken = take; return Fake(3); }

        service.HeapOf("d1", Walk, Hex, "", true, null, 0, 0, 2, 1000, [], default, keep: true);

        Assert.Equal(0, taken);
    }

    [Fact]
    public void The_oldest_walk_is_dropped_after_four()
    {
        using var service = new MinidumpService();
        int walks = 0;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { walks++; return Fake(3); }

        foreach (var id in new[] { "a", "b", "c", "d", "e" }) service.HeapOf(id, Walk, Hex, "", false, null, 0, 0, 2, 1000, [], default, keep: true);
        service.HeapOf("e", Walk, Hex, "", false, null, 0, 0, 2, 1000, [], default, keep: true);
        Assert.Equal(5, walks);
        service.HeapOf("a", Walk, Hex, "", false, null, 0, 0, 2, 1000, [], default, keep: true);
        Assert.Equal(6, walks);
    }

    [Fact]
    public void A_replaced_file_walks_again()
    {
        using var service = new MinidumpService();
        int walks = 0;
        HeapWalk Walk(string? t, ulong m, long max, int from, int take, CancellationToken ct) { walks++; return Fake(3); }

        service.HeapOf("d1", Walk, Hex, "", false, null, 0, 0, 2, 1000, [], default, keep: true, version: "10:1");
        service.HeapOf("d1", Walk, Hex, "", false, null, 0, 0, 2, 1000, [], default, keep: true, version: "12:2");

        Assert.Equal(2, walks);
    }

    [Fact]
    public void A_page_past_the_end_of_the_walk_is_empty()
    {
        using var service = new MinidumpService();

        var r = service.HeapOf("d1", (t, m, max, from, take, ct) => Fake(3), Hex, "", false, null, 0, 10, 4, 1000, [], default, keep: true);

        Assert.Empty(r.Items);
    }
}
