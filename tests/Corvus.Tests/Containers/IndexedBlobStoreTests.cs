using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Packages built here: an offset and size index followed by blobs of text and of pseudo-random bytes.</summary>
public sealed class IndexedBlobStoreTests
{
    private static byte[] Text(int n) => Enumerable.Range(0, n).Select(i => (byte)('a' + i % 3)).ToArray();

    private static byte[] Noise(int n)
    {
        var bytes = new byte[n];
        new Random(7).NextBytes(bytes);
        return bytes;
    }

    private static byte[] Store(int truncate = 0, params byte[][] blobs)
    {
        int indexEnd = 4 + 8 * blobs.Length;
        var index = new byte[indexEnd];
        BinaryPrimitives.WriteUInt32LittleEndian(index, (uint)blobs.Length);
        int at = indexEnd;
        for (int i = 0; i < blobs.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(index.AsSpan(4 + 8 * i), (uint)at);
            BinaryPrimitives.WriteUInt32LittleEndian(index.AsSpan(8 + 8 * i), (uint)blobs[i].Length);
            at += blobs[i].Length;
        }
        byte[] all = [.. index, .. blobs.SelectMany(b => b)];
        return all[..(all.Length - truncate)];
    }

    private static ContainerContents Open(byte[] data) => Containers.Open(data, "package.bin", AnalysisLimits.Default, default);

    [Fact]
    public void An_index_plus_blob_store_lists_each_entry_with_size_and_entropy()
    {
        var contents = Open(Store(0, Text(400), Noise(600), Text(200)));
        Assert.Equal("indexed blob store", contents.Kind);
        Assert.Equal([400L, 600, 200], contents.Entries!.Select(e => e.Size));
        Assert.Contains("entropy 1.", contents.Entries![0].Detail);
        Assert.Contains("compressed or encrypted", contents.Entries![1].Detail);
        Assert.DoesNotContain("compressed", contents.Entries![2].Detail);
        Assert.Equal(3, contents.Items.Count);
    }

    [Fact]
    public void The_store_notes_name_entry_sizes_entropy_and_the_next_calls()
    {
        var contents = Open(Store(0, Text(400), Noise(600), Text(200)));
        Assert.Contains(contents.Notes, n => n.Contains("3 entries, 1 of 3 measured above entropy 7.5") && n.Contains("entry_0000 400 bytes, entropy ") && n.Contains("entry_0001 600 bytes, entropy 7.") && n.Contains("entry_0002 200 bytes, entropy "));
        Assert.Contains(contents.Notes, n => n.Contains("list_assemblies on this file") && n.Contains("unpack_container on this file"));
    }

    [Fact]
    public void A_truncated_store_notes_the_entries_with_unknown_entropy()
    {
        var contents = Open(Store(100, Text(300), Text(300), Text(300)));
        Assert.Contains(contents.Notes, n => n.Contains("0 of 2 measured") && n.Contains("1 with unknown entropy") && n.Contains("entry_0002 300 bytes, entropy unknown"));
    }

    [Fact]
    public void Entries_past_the_extraction_limit_are_noted_with_unknown_entropy()
    {
        var limits = AnalysisLimits.Default with { MaxItems = 2 };
        var contents = Containers.Open(Store(0, Text(100), Text(100), Text(100), Text(100)), "package.bin", limits, default);
        Assert.Contains(contents.Notes, n => n.Contains("0 of 2 measured") && n.Contains("2 with unknown entropy") && n.Contains("entry_0003 100 bytes, entropy unknown"));
    }

    [Fact]
    public async Task The_summary_reply_carries_the_entry_and_next_call_notes()
    {
        using var dir = new TempDir();
        var file = dir.File("package.bin");
        File.WriteAllBytes(file, Store(0, Text(400), Noise(600), Text(200)));
        using var workspace = new AssemblyWorkspace();
        var tools = new Corvus.Tools.InspectionTools(new Corvus.Services.Analysis.InspectionService(workspace), workspace);
        var text = await tools.SummarizeFile(path: file);
        Assert.Contains("Note: 3 entries, 1 of 3 measured", text);
        Assert.Contains("list_assemblies on this file", text);
    }

    [Fact]
    public async Task The_overview_of_a_truncated_store_keeps_the_leading_notes()
    {
        using var dir = new TempDir();
        var file = dir.File("package.bin");
        File.WriteAllBytes(file, Store(50, [.. Enumerable.Range(0, 20).Select(_ => Text(100))]));
        using var workspace = new AssemblyWorkspace();
        var tools = new Corvus.Tools.InspectionTools(new Corvus.Services.Analysis.InspectionService(workspace), workspace);
        var text = await tools.SummarizeFile(path: file);
        Assert.Contains("Note: 20 entries", text);
        Assert.Contains("list_assemblies on this file", text);
    }

    [Fact]
    public void A_store_with_more_than_eight_entries_names_the_count_listed()
    {
        var contents = Open(Store(0, [.. Enumerable.Range(0, 10).Select(_ => Text(100))]));
        Assert.Contains(contents.Notes, n => n.Contains("8 of 10 entries"));
    }

    [Fact]
    public void An_entry_past_the_end_of_a_truncated_store_is_reported_as_damaged()
    {
        var contents = Open(Store(100, Text(300), Text(300), Text(300)));
        Assert.Equal("indexed blob store", contents.Kind);
        Assert.Contains("damaged", contents.Entries![2].Detail);
        Assert.Equal(2, contents.Items.Count);
        Assert.Contains(contents.Notes, n => n.Contains("unknown contents"));
    }

    [Fact]
    public void A_record_starting_inside_the_index_is_not_taken_as_a_store()
    {
        var data = Store(0, Text(300), Text(300), Text(300));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4 + 8), 40);
        Assert.NotEqual("indexed blob store", Open(data).Kind);
    }

    [Fact]
    public void A_record_starting_one_byte_before_the_previous_blob_ends_is_not_taken_as_a_store()
    {
        var data = Store(0, Text(300), Text(300), Text(300));
        uint first = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4 + 8), first + 299);
        Assert.NotEqual("indexed blob store", Open(data).Kind);
    }

    [Fact]
    public void A_first_blob_sixteen_bytes_past_the_index_is_not_taken_as_a_store()
    {
        var data = Store(0, Text(300), Text(300), Text(300));
        uint first = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), first + 16);
        Assert.NotEqual("indexed blob store", Open(data).Kind);
    }

    [Fact]
    public void Blobs_spanning_under_three_quarters_of_the_file_are_not_taken_as_a_store()
    {
        var data = Store(0, Text(100), Text(100));
        data = [.. data, .. new byte[400]];
        Assert.NotEqual("indexed blob store", Open(data).Kind);
    }

    [Fact]
    public void A_two_record_store_with_a_truncated_last_record_is_recognized()
    {
        var contents = Open(Store(50, Text(300), Text(300)));
        Assert.Equal("indexed blob store", contents.Kind);
        Assert.Contains("damaged", contents.Entries![1].Detail);
    }

    [Fact]
    public void Trailing_bytes_after_the_blobs_are_reported_as_belonging_to_no_entry()
    {
        var data = Store(0, Text(300), Text(300), Text(300));
        data = [.. data, .. new byte[40]];
        Assert.Contains(Open(data).Notes, n => n.Contains("belong to no entry"));
    }

    // Forty bytes are inserted after the first blob and later offsets move past them.
    [Fact]
    public void A_gap_between_blobs_is_reported_as_belonging_to_no_entry()
    {
        var data = Store(0, Text(300), Text(300), Text(300));
        int firstEnd = 4 + 24 + 300;
        data = [.. data[..firstEnd], .. new byte[40], .. data[firstEnd..]];
        for (int i = 1; i < 3; i++)
        {
            var at = data.AsSpan(4 + 8 * i);
            BinaryPrimitives.WriteUInt32LittleEndian(at, BinaryPrimitives.ReadUInt32LittleEndian(at) + 40);
        }
        var contents = Open(data);
        Assert.Equal("indexed blob store", contents.Kind);
        Assert.Contains(contents.Notes, n => n.Contains("belong to no entry"));
    }

    [Fact]
    public void A_zero_size_record_is_listed_as_an_empty_entry()
    {
        var contents = Open(Store(0, Text(300), Array.Empty<byte>(), Text(300)));
        Assert.Equal("indexed blob store", contents.Kind);
        Assert.Equal(0L, contents.Entries![1].Size);
    }

    [Fact]
    public void The_item_limit_lists_every_entry_and_extracts_up_to_the_limit()
    {
        var limits = AnalysisLimits.Default with { MaxItems = 1 };
        var contents = Containers.Open(Store(0, Text(300), Text(300), Text(300)), "package.bin", limits, default);
        Assert.Equal(3, contents.Entries!.Count);
        Assert.Single(contents.Items);
        Assert.Contains(contents.Notes, n => n.Contains("extraction limit"));
    }

    [Fact]
    public void The_total_byte_limit_lists_every_entry_and_extracts_up_to_the_limit()
    {
        var limits = AnalysisLimits.Default with { MaxTotalBytes = 500 };
        var contents = Containers.Open(Store(0, Text(300), Text(300), Text(300)), "package.bin", limits, default);
        Assert.Equal(3, contents.Entries!.Count);
        Assert.Single(contents.Items);
    }

    [Fact]
    public void A_cancelled_open_throws_instead_of_returning_a_partial_listing()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() =>
            Containers.Open(Store(0, Text(300), Text(300), Text(300)), "package.bin", AnalysisLimits.Default, cts.Token));
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.IndexedBlobStoreReader))]
    public void Fuzzed_index_plus_blob_stores_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Store(0, Text(40), Noise(64), Text(24)), b => { try { Open(b); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
