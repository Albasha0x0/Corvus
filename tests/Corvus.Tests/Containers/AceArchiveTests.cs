using System.Buffers.Binary;
using System.IO.Hashing;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>ACE archives built here from a main header and file headers; no compressed data is needed to list them.</summary>
public sealed class AceArchiveTests
{
    private static byte[] Block(byte[] body, bool badCrc = false)
    {
        var block = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(block, (ushort)(Crc32.HashToUInt32(body) ^ (badCrc ? 1u : 0u)));
        BinaryPrimitives.WriteUInt16LittleEndian(block.AsSpan(2), (ushort)body.Length);
        body.CopyTo(block, 4);
        return block;
    }

    private static byte[] Main() => Block([0, 0, 0, .. "**ACE**"u8, 20, 20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    private static byte[] File(string name, int size, byte[] packed, ushort flags = 0, uint attr = 0x20, byte tech = 1)
    {
        var body = new byte[31 + name.Length];
        body[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(1), (ushort)(flags | 1));
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(3), (uint)packed.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(7), (uint)size);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(15), attr);
        body[23] = tech;
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(29), (ushort)name.Length);
        Encoding.Latin1.GetBytes(name, body.AsSpan(31));
        return [.. Block(body), .. packed];
    }

    [Fact]
    public void An_ace_archive_lists_its_files_from_the_headers_and_labels_each_state()
    {
        byte[] ace = [.. Main(), .. File("docs\\a.txt", 100, [1, 2, 3]), .. File("sub", 0, [], attr: 0x10),
            .. File("secret.bin", 50, [9, 9], flags: 0x4000 | 0x2000, tech: 0)];
        var c = Containers.Open(ace, "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("ace", c.Kind);
        Assert.Empty(c.Items);
        Assert.Equal(["docs/a.txt", "secret.bin"], c.Entries!.Select(e => e.Path));
        Assert.Equal(100, c.Entries![0].Size);
        Assert.Equal("compressed; data not read", c.Entries[0].Detail);
        Assert.Equal("stored; data not read; encrypted; continues in the next volume", c.Entries[1].Detail);
        Assert.Contains("ace: 1 folder entries not listed", c.Notes);
    }

    [Fact]
    public void A_damaged_file_header_keeps_the_entries_before_it_and_is_labelled()
    {
        byte[] ace = [.. Main(), .. File("a.txt", 4, [1]), .. File("b.txt", 4, [1]).Take(10)];
        var c = Containers.Open(ace, "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["a.txt"], c.Entries!.Select(e => e.Path));
        Assert.Contains(c.Notes, n => n.Contains("later entries are unknown"));
    }

    [Fact]
    public void A_header_checksum_that_does_not_hold_is_named_on_the_entry()
    {
        var bad = File("a.txt", 4, [1]);
        bad[0] ^= 1;
        var c = Containers.Open([.. Main(), .. bad], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains("header checksum does not hold", c.Entries!.Single().Detail);
    }

    [Fact]
    public void An_archive_with_only_a_main_header_reports_no_file_entries()
    {
        var c = Containers.Open(Main(), "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Empty(c.Entries!);
        Assert.Contains("ace: no file entries in the headers read", c.Notes);
    }

    [Fact]
    public void A_file_continuing_from_the_previous_volume_is_labelled()
    {
        var c = Containers.Open([.. Main(), .. File("a.bin", 4, [1], flags: 0x1000)], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains("continues from the previous volume", c.Entries!.Single().Detail);
    }

    [Fact]
    public void A_packed_size_past_the_end_of_the_data_is_reported_as_partial()
    {
        var cut = File("b.txt", 4, [1, 2, 3, 4]);
        var c = Containers.Open([.. Main(), .. File("a.txt", 4, [1]), .. cut.Take(cut.Length - 2)], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["a.txt", "b.txt"], c.Entries!.Select(e => e.Path));
        Assert.Contains(c.Notes, n => n.Contains("data ends inside the last packed size") && n.Contains("later entries are unknown"));
    }

    [Fact]
    public void Trailing_bytes_shorter_than_a_block_header_are_reported_as_partial()
    {
        var c = Containers.Open([.. Main(), .. File("a.txt", 4, [1]), 1, 2], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(c.Notes, n => n.Contains("2 trailing bytes") && n.Contains("later entries are unknown"));
    }

    [Fact]
    public void A_file_header_shorter_than_the_fixed_fields_is_counted_and_labelled()
    {
        var shortBody = new byte[] { 1, 0, 0, 0, 0 };
        var c = Containers.Open([.. Main(), .. Block(shortBody), .. File("a.txt", 4, [1])], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["a.txt"], c.Entries!.Select(e => e.Path));
        Assert.Contains(c.Notes, n => n.Contains("header shorter than a file header"));
    }

    [Fact]
    public void Listing_past_the_item_limit_names_the_limit_and_keeps_the_listed_entries()
    {
        var limits = AnalysisLimits.Default with { MaxItems = 1 };
        var c = Containers.Open([.. Main(), .. File("a.txt", 4, [1]), .. File("b.txt", 4, [1])], "x.ace", limits, default, allFiles: true);
        Assert.Equal(["a.txt"], c.Entries!.Select(e => e.Path));
        Assert.Contains(c.Notes, n => n.Contains("item count limit: 1-file") && n.Contains("later entries are unknown"));
    }

    [Fact]
    public void A_name_with_high_bytes_is_labelled_as_an_unrecorded_code_page()
    {
        var file = File("a_\u00E9.txt", 4, [1]);
        var c = Containers.Open([.. Main(), .. file], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Contains(c.Notes, n => n.Contains("unrecorded code page"));
    }

    [Fact]
    public void A_main_header_that_runs_past_the_end_is_refused_as_malformed()
    {
        var ex = Assert.Throws<ToolError>(() => Containers.Open(Main().Take(20).ToArray(), "x.ace", AnalysisLimits.Default, default, allFiles: true));
        Assert.Equal(ErrorCode.MalformedInput, ex.Code);
    }

    [Fact]
    public void Path_traversal_in_an_entry_name_is_reported_through_the_name_issues()
    {
        var c = Containers.Open([.. Main(), .. File("..\\evil.txt", 4, [1])], "x.ace", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("../evil.txt", c.Entries!.Single().Path);
        Assert.NotEmpty(c.Names!);
    }

    [Fact]
    public void The_container_listing_tool_path_lists_ace_entries()
    {
        using var dir = new TempDir();
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var path = dir.File("x.ace");
        System.IO.File.WriteAllBytes(path, [.. Main(), .. File("a.txt", 4, [1])]);
        var listing = new UnpackService(workspace).List(path, AnalysisLimits.Default, default);
        Assert.Equal("ace", listing.Container);
        Assert.Equal("a.txt", listing.Files!.Single().Path);
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.AceReader))]
    public void Fuzzed_ace_archives_never_throw_unexpectedly()
    {
        byte[] seed = [.. Main(), .. File("docs\\a.txt", 100, [1, 2, 3]), .. File("sub", 0, [], attr: 0x10)];
        var failures = FormatFuzz.Run(seed, b => { try { Containers.Open(b, "x.ace", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
