using System.Buffers.Binary;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Containers built here: a marker, a payload length, then pseudo-random 8-byte blocks.</summary>
public sealed class TransformedBlockContainerTests
{
    internal static byte[] Container(int payload, uint? declared = null, int truncate = 0, int trailing = 0)
    {
        var bytes = new byte[8 + payload + trailing];
        new Random(3).NextBytes(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), declared ?? (uint)payload);
        return bytes[..(bytes.Length - truncate)];
    }

    private static ContainerContents Open(byte[] data, string name = "a.luae") => Containers.Open(data, name, AnalysisLimits.Default, default);

    [Fact]
    public void A_marked_file_lists_its_payload_with_blocks_and_entropy()
    {
        var contents = Open(Container(2048));
        Assert.Equal("transformed block container", contents.Kind);
        var entry = Assert.Single(contents.Entries!);
        Assert.Equal(2048, entry.Size);
        Assert.Contains("256 blocks", entry.Detail);
        Assert.Contains("entropy 7.", entry.Detail);
        Assert.Single(contents.Items);
    }

    [Theory]
    [InlineData("a.jsone")]
    [InlineData("a.PBE")]
    public void Each_listed_extension_is_read(string name) =>
        Assert.Equal("transformed block container", Open(Container(64), name).Kind);

    [Fact]
    public void The_notes_name_the_unknown_decode_and_the_next_call()
    {
        var contents = Open(Container(64));
        Assert.Contains(contents.Notes, n => n.Contains("decoded content is unknown"));
        Assert.Contains(contents.Notes, n => n.Contains("unpack_container on this file"));
    }

    [Fact]
    public void A_truncated_payload_is_listed_as_damaged_with_the_bytes_present()
    {
        var contents = Open(Container(256, truncate: 100));
        Assert.Contains("damaged", contents.Entries!.Single().Detail);
        Assert.Contains(contents.Notes, n => n.Contains("only 152 of 256 bytes"));
        var item = Assert.Single(contents.Items);
        Assert.Equal(152, item.Bytes.Length);
        Assert.Contains("partial", item.Origin);
        Assert.Contains(contents.Notes, n => n.Contains("writes the present payload (152 bytes)"));
    }

    [Fact]
    public void A_header_only_file_is_reported_truncated_without_an_item()
    {
        var contents = Open(Container(0, declared: 64));
        Assert.Contains("damaged", contents.Entries!.Single().Detail);
        Assert.Contains(contents.Notes, n => n.Contains("only 0 of 64 bytes"));
        Assert.Empty(contents.Items);
        Assert.DoesNotContain(contents.Notes, n => n.Contains("unpack_container"));
    }

    [Fact]
    public void A_minimal_one_block_file_lists_its_payload()
    {
        var contents = Open(Container(8));
        Assert.Equal(8, contents.Entries!.Single().Size);
        Assert.Single(contents.Items);
    }

    [Fact]
    public void A_zero_declared_length_is_not_taken()
    {
        Assert.NotEqual("transformed block container", Open(Container(64, declared: 0)).Kind);
    }

    [Fact]
    public void A_payload_over_the_item_limit_names_the_variable_and_extracts_nothing()
    {
        var limits = new AnalysisLimits { MaxItemBytes = 16 };
        var contents = Containers.Open(Container(64), "a.luae", limits, default);
        Assert.Empty(contents.Items);
        Assert.Contains(contents.Notes, n => n.Contains(AnalysisLimits.RaiseVariable) && n.Contains("16"));
    }

    [Fact]
    public void Bytes_after_the_payload_are_named_as_unowned()
    {
        var contents = Open(Container(64, trailing: 5));
        Assert.Contains(contents.Notes, n => n.Contains("5 bytes after the payload"));
    }

    [Fact]
    public void A_length_off_the_block_size_is_not_taken()
    {
        Assert.NotEqual("transformed block container", Open(Container(64, declared: 63)).Kind);
    }

    [Fact]
    public void A_file_without_a_listed_extension_is_not_taken()
    {
        Assert.NotEqual("transformed block container", Open(Container(64), "a.bin").Kind);
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.TransformedBlockContainerReader))]
    public void Fuzzed_transformed_block_containers_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Container(256), b => { try { Containers.Open(b, "x.luae", AnalysisLimits.Default, default); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
