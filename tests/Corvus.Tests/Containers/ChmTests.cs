using System.Text;
using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Tests;

/// <summary>Builds compiled help images: stored files and LZX stored blocks.</summary>
public sealed class ChmTests
{
    private const string Lzx = "::DataSpace/Storage/MSCompressed/";
    private const string ResetName = Lzx + "Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";
    private const int Frame = 0x8000;

    internal static byte[] Page(int length, byte seed)
    {
        var b = new byte[length];
        for (int i = 0; i < length; i++) b[i] = (byte)('a' + (i * 7 + seed) % 26);
        return b;
    }

    private static byte[] U32(uint v) => BitConverter.GetBytes(v);
    private static byte[] U64(ulong v) => BitConverter.GetBytes(v);

    private static byte[] Number(long v)
    {
        var parts = new List<byte> { (byte)(v & 0x7F) };
        for (v >>= 7; v > 0; v >>= 7) parts.Insert(0, (byte)(0x80 | (v & 0x7F)));
        return [.. parts];
    }

    // One LZX segment holding its bytes as a single stored block.
    private static byte[] StoredSegment(byte[] bytes)
    {
        uint head = (3u << 28) | ((uint)bytes.Length << 4);
        return [.. BitConverter.GetBytes((ushort)(head >> 16)), .. BitConverter.GetBytes((ushort)head), .. U32(1), .. U32(1), .. U32(1), .. bytes, .. bytes.Length % 2 == 1 ? new byte[1] : []];
    }

    /// <summary>A help image: stored files in section 0 and compressed files in section 1; the reset table can be left out.</summary>
    internal static byte[] Chm((string Name, byte[] Data)[] stored, (string Name, byte[] Data)[] compressed, bool resetTable = true, string? badName = null, int version = 3, int corruptSegment = -1)
    {
        var section0 = new List<byte>();
        var listing = new List<(string Name, int Section, long Offset, long Length)>();
        foreach (var (name, data) in stored)
        {
            listing.Add((name, 0, section0.Count, data.Length));
            section0.AddRange(data);
        }
        var plain = new List<byte>();
        foreach (var (name, data) in compressed)
        {
            listing.Add((name, 1, plain.Count, data.Length));
            plain.AddRange(data);
        }
        if (compressed.Length > 0)
        {
            var packed = new List<byte>();
            var offsets = new List<ulong>();
            int frames = (plain.Count + Frame - 1) / Frame;
            for (int f = 0; f < frames; f += 2)
            {
                var segment = plain.Skip(f * Frame).Take(2 * Frame).ToArray();
                for (int k = f; k < Math.Min(f + 2, frames); k++) offsets.Add((ulong)packed.Count);
                packed.AddRange(f / 2 == corruptSegment ? new byte[] { 0xFF, 0xFF, 0xFF, 0xFF } : StoredSegment(segment));
            }
            void Put(string name, byte[] data)
            {
                listing.Add((name, 0, section0.Count, data.Length));
                section0.AddRange(data);
            }
            Put(Lzx + "Content", [.. packed]);
            Put(Lzx + "ControlData", [.. U32(6), .. "LZXC"u8, .. U32(2), .. U32(2), .. U32(2), .. U32(0), .. U32(0)]);
            if (resetTable) Put(ResetName, [.. U32(2), .. U32((uint)offsets.Count), .. U32(8), .. U32(0x28), .. U64((ulong)plain.Count), .. U64((ulong)packed.Count), .. U64(Frame), .. offsets.SelectMany(o => U64(o))]);
        }
        if (badName != null) listing.Add((badName, 0, 0, 1));
        var entries = listing.SelectMany(e => (byte[])[.. Number(Encoding.UTF8.GetByteCount(e.Name)), .. Encoding.UTF8.GetBytes(e.Name), .. Number(e.Section), .. Number(e.Offset), .. Number(e.Length)]).ToArray();
        const int chunk = 0x1000;
        var list = new byte[chunk];
        "PMGL"u8.CopyTo(list);
        BitConverter.GetBytes((uint)(chunk - 0x14 - entries.Length)).CopyTo(list, 4);
        BitConverter.GetBytes(-1).CopyTo(list, 12);
        BitConverter.GetBytes(-1).CopyTo(list, 16);
        entries.CopyTo(list, 0x14);
        var dir = new byte[0x54 + chunk];
        "ITSP"u8.CopyTo(dir);
        BitConverter.GetBytes(1).CopyTo(dir, 4);
        BitConverter.GetBytes(0x54).CopyTo(dir, 8);
        BitConverter.GetBytes(chunk).CopyTo(dir, 0x10);
        BitConverter.GetBytes(1).CopyTo(dir, 0x2C);
        list.CopyTo(dir, 0x54);
        var header = new byte[0x60];
        "ITSF"u8.CopyTo(header);
        BitConverter.GetBytes(version).CopyTo(header, 4);
        BitConverter.GetBytes(0x60).CopyTo(header, 8);
        BitConverter.GetBytes(0x60UL).CopyTo(header, 0x48);
        BitConverter.GetBytes((ulong)dir.Length).CopyTo(header, 0x50);
        if (version == 3) BitConverter.GetBytes((ulong)(0x60 + dir.Length)).CopyTo(header, 0x58);
        return [.. header, .. dir, .. section0];
    }

    private static ContainerContents Open(byte[] data, bool allFiles = false, AnalysisLimits? limits = null, CancellationToken ct = default) =>
        Containers.Open(data, "help.chm", limits ?? AnalysisLimits.Default, ct, allFiles: allFiles);

    [Fact]
    public void Stored_and_compressed_pages_are_extracted_across_a_reset_boundary()
    {
        var big = Page(100_000, 3);
        var small = Page(300, 9);
        var c = Open(Chm([("/index.htm", "<html></html>"u8.ToArray())], [("/big.htm", big), ("/pages/small.js", small)]));
        Assert.Equal("chm", c.Kind);
        Assert.Equal(big, c.Items.Single(i => i.Name == "big.htm").Bytes);
        Assert.Equal(small, c.Items.Single(i => i.Name == "pages/small.js").Bytes);
        Assert.Equal("<html></html>"u8.ToArray(), c.Items.Single(i => i.Name == "index.htm").Bytes);
        var entries = c.Entries!;
        Assert.Equal("LZX:16", entries.Single(e => e.Path == "big.htm").Detail);
        Assert.Equal("stored", entries.Single(e => e.Path == "index.htm").Detail);
        Assert.Contains(entries, e => e.Path.StartsWith("::DataSpace", StringComparison.Ordinal) && e.Detail!.Contains("format stream", StringComparison.Ordinal));
    }

    [Fact]
    public void Files_that_are_not_pages_or_binaries_are_extracted_only_with_allFiles()
    {
        var image = Chm([("/style.css", "p{}"u8.ToArray()), ("/a.htm", "<p>"u8.ToArray())], []);
        var some = Open(image);
        Assert.Equal(["a.htm"], some.Items.Select(i => i.Name));
        Assert.Contains(some.Notes, n => n.Contains("allFiles", StringComparison.Ordinal));
        Assert.Contains(Open(image, allFiles: true).Items, i => i.Name == "style.css");
    }

    [Fact]
    public void A_missing_reset_table_leaves_stored_files_readable_and_names_the_compressed_ones()
    {
        var c = Open(Chm([("/index.htm", "<p>"u8.ToArray())], [("/big.htm", Page(70_000, 1))], resetTable: false));
        Assert.Equal(["index.htm"], c.Items.Select(i => i.Name));
        Assert.Contains(c.Entries!, e => e.Path == "big.htm" && e.Detail == "unreadable");
        Assert.Contains(c.Notes, n => n.StartsWith("big.htm: ", StringComparison.Ordinal) && n.Contains("reset table", StringComparison.Ordinal));
    }

    [Fact]
    public void A_file_with_a_path_that_climbs_out_is_listed_and_not_extracted()
    {
        var c = Open(Chm([("/index.htm", "<p>"u8.ToArray())], [], badName: "/../x.htm"));
        Assert.DoesNotContain(c.Items, i => i.Name.Contains("..", StringComparison.Ordinal));
        Assert.Contains(c.Entries!, e => e.Path == "../x.htm" && e.Detail!.Contains("unsafe name", StringComparison.Ordinal));
        Assert.Contains(c.Notes, n => n.Contains("unsafe names", StringComparison.Ordinal));
    }

    [Fact]
    public void A_file_past_the_end_of_the_image_is_counted_and_its_neighbours_are_kept()
    {
        var image = Chm([("/index.htm", "<p>"u8.ToArray())], []);
        var cut = image[..^1];
        var c = Open(cut);
        Assert.Contains(c.Entries!, e => e.Path == "index.htm" && e.Detail == "stored, unreadable");
        Assert.Contains(c.Notes, n => n.StartsWith("index.htm: ", StringComparison.Ordinal));
    }

    [Fact]
    public void A_corrupt_segment_leaves_the_neighbouring_segments_readable()
    {
        var a = Page(2 * Frame, 1);
        var b = Page(2 * Frame, 2);
        var c = Page(2 * Frame, 3);
        var open = Open(Chm([], [("/a.htm", a), ("/b.htm", b), ("/c.htm", c)], corruptSegment: 1));
        Assert.Equal(a, open.Items.Single(i => i.Name == "a.htm").Bytes);
        Assert.Equal(c, open.Items.Single(i => i.Name == "c.htm").Bytes);
        Assert.Contains(open.Entries!, e => e.Path == "b.htm" && e.Detail!.EndsWith("unreadable", StringComparison.Ordinal));
        Assert.Contains(open.Notes, n => n.StartsWith("b.htm: ", StringComparison.Ordinal));
    }

    [Fact]
    public void The_item_limit_applies_to_the_file_and_not_to_the_segment_that_holds_it()
    {
        var image = Chm([], [("/small.htm", Page(300, 1)), ("/big.htm", Page(5_000, 2)), ("/pad.htm", Page(2 * Frame, 3))]);
        var c = Open(image, limits: AnalysisLimits.Default with { MaxItemBytes = 1_000 });
        Assert.Equal(300, c.Items.Single(i => i.Name == "small.htm").Bytes.Length);
        Assert.Contains(c.Entries!, e => e.Path == "big.htm" && e.Detail!.EndsWith("over limit", StringComparison.Ordinal));
        Assert.Contains(c.Notes, n => n.StartsWith("big.htm: ", StringComparison.Ordinal) && n.Contains(AnalysisLimits.RaiseVariable, StringComparison.Ordinal));
    }

    [Fact]
    public void A_segment_over_the_total_limit_is_labelled_over_limit_not_unreadable()
    {
        var c = Open(Chm([], [("/a.htm", Page(2 * Frame, 1))]), limits: AnalysisLimits.Default with { MaxTotalBytes = 1_000 });
        Assert.Contains(c.Entries!, e => e.Path == "a.htm" && e.Detail!.EndsWith("over limit", StringComparison.Ordinal));
        Assert.Empty(c.Items);
    }

    [Fact]
    public void The_item_count_limit_keeps_the_listing_complete()
    {
        var c = Open(Chm([("/a.htm", "<p>"u8.ToArray()), ("/b.htm", "<p>"u8.ToArray())], []), limits: AnalysisLimits.Default with { MaxItems = 1 });
        Assert.Single(c.Items);
        Assert.Contains(c.Entries!, e => e.Path == "a.htm");
        Assert.Contains(c.Entries!, e => e.Path == "b.htm");
    }

    [Fact]
    public void A_cancelled_read_throws_cancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Open(Chm([("/a.htm", "<p>"u8.ToArray())], []), ct: cts.Token));
    }

    [Fact]
    public void A_damaged_directory_chunk_is_named_and_the_image_still_opens()
    {
        var image = Chm([("/a.htm", "<p>"u8.ToArray())], []);
        BitConverter.GetBytes(0xFFFFFFu).CopyTo(image, 0x60 + 0x54 + 4);
        var c = Open(image);
        Assert.Contains(c.Notes, n => n.StartsWith("directory chunk 0: ", StringComparison.Ordinal));
    }

    [Fact]
    public void A_version_2_header_starts_the_content_after_the_directory()
    {
        var c = Open(Chm([("/a.htm", "<p>"u8.ToArray())], [("/b.htm", Page(500, 4))], version: 2));
        Assert.Equal(Page(500, 4), c.Items.Single(i => i.Name == "b.htm").Bytes);
        Assert.Equal("<p>"u8.ToArray(), c.Items.Single(i => i.Name == "a.htm").Bytes);
    }

    [Fact]
    public void An_image_cut_inside_the_directory_is_refused_as_malformed()
    {
        var image = Chm([("/a.htm", "<p>"u8.ToArray())], []);
        var ex = Assert.Throws<ToolError>(() => ChmFile.Read(image[..(0x60 + 0x20)], "help.chm", default));
        Assert.Equal(ErrorCode.MalformedInput, ex.Code);
        Assert.Contains("runs past the file", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_directory_without_an_itsp_header_is_named()
    {
        var image = Chm([("/a.htm", "<p>"u8.ToArray())], []);
        image[0x60] = (byte)'X';
        var ex = Assert.Throws<ToolError>(() => ChmFile.Read(image, "help.chm", default));
        Assert.Contains("no ITSP header", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_header_shorter_than_the_fixed_size_is_not_a_help_image()
    {
        var image = Chm([], []);
        Assert.False(ChmFile.Looks(image.AsSpan(0, 0x5F)));
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => ChmFile.Read(image[..0x5F], "help.chm", default)).Code);
    }

    [Fact]
    public void An_image_with_no_files_lists_nothing_and_extracts_nothing()
    {
        var c = Open(Chm([], []), allFiles: true);
        Assert.Empty(c.Items);
        Assert.Empty(c.Entries!);
    }

    [Fact]
    [FuzzEntry(typeof(ChmReader), typeof(ChmFile))]
    public void Fuzzed_help_images_never_throw_past_a_tool_error()
    {
        var seed = Chm([("/index.htm", "<p>"u8.ToArray())], [("/big.htm", Page(70_000, 5))]);
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { Open(b, allFiles: true); } catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
