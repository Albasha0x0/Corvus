using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Node;

namespace Corvus.Tests;

/// <summary>Node SEA, pkg, nexe, Bun and Deno executables built at test time around an ELF header.</summary>
public sealed class NodeBundleTests
{
    private const string Fuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

    private static byte[] Image(params byte[][] parts) => [0x7F, (byte)'E', (byte)'L', (byte)'F', .. new byte[60], .. parts.SelectMany(p => p)];

    private static ContainerContents Open(byte[] image) => Containers.Open(image, "app", AnalysisLimits.Default, default, allFiles: true);

    private static string Text(ContainerContents c, string name) => Encoding.UTF8.GetString(c.Items.Single(i => i.Name == name).Bytes);

    private static byte[] U64(ulong v) { var b = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); return b; }

    private static byte[] Str(string s) => [.. U64((ulong)Encoding.UTF8.GetByteCount(s)), .. Encoding.UTF8.GetBytes(s)];

    private static byte[] SeaBlob(uint flags, params byte[][] fields) => [0x20, 0xDA, 0x43, 0x01, .. BitConverter.GetBytes(flags), .. fields.SelectMany(f => f)];

    private static byte[] SeaImage(uint flags, params byte[][] fields) => Image(Encoding.ASCII.GetBytes(Fuse + ":1"), SeaBlob(flags, fields));

    private static byte[] PkgImage(byte[] payload, string table, string? prelude = null)
    {
        var text = Encoding.UTF8.GetBytes(prelude ?? "boot\n})(require, " + table + ", \"/snapshot/app/index.js\", {}, {})");
        string Head(int pos) => $"PAYLOAD_POSITION = '{pos,-8}';PAYLOAD_SIZE = '{payload.Length,-8}';PRELUDE_POSITION = '{pos + payload.Length,-8}';PRELUDE_SIZE = '{text.Length,-8}';";
        // The numbers are file offsets into the image, written at a fixed width.
        int pos = 64 + Head(0).Length;
        return Image(Encoding.ASCII.GetBytes(Head(pos)), payload, text);
    }

    private static byte[] Gzip(byte[] bytes)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.SmallestSize)) gz.Write(bytes);
        return ms.ToArray();
    }

    private static byte[] NexeTrailer(double code, double resources)
    {
        var trailer = new byte[32];
        "<nexe~~sentinel>"u8.CopyTo(trailer);
        BinaryPrimitives.WriteDoubleLittleEndian(trailer.AsSpan(16), code);
        BinaryPrimitives.WriteDoubleLittleEndian(trailer.AsSpan(24), resources);
        return trailer;
    }

    [Fact]
    public void A_sea_blob_yields_its_main_script_and_assets()
    {
        var blob = SeaBlob(8, Str("main.js"), Str("console.log(1)"), U64(1), Str("logo.txt"), Str("pixels"));
        var c = Open(Image(Encoding.ASCII.GetBytes(Fuse + ":1"), new byte[16], blob));
        Assert.Equal("Node SEA executable", c.Kind);
        Assert.Equal("console.log(1)", Text(c, "sea-main.js"));
        Assert.Equal("pixels", Text(c, "assets/logo.txt"));
    }

    [Fact]
    public void A_truncated_sea_blob_keeps_the_entries_before_the_cut()
    {
        var c = Open(SeaImage(8, Str("main.js"), Str("run()"), U64(2), Str("a.txt"), Str("one"), Str("b.txt")));
        Assert.Equal("one", Text(c, "assets/a.txt"));
        Assert.Contains(c.Notes, n => n.Contains("ends inside the asset 2 of 2"));
    }

    [Fact]
    public void A_sea_code_cache_is_listed_beside_the_main_script()
    {
        var c = Open(SeaImage(4, Str("main.js"), Str("run()"), Str("cache")));
        Assert.Equal("run()", Text(c, "sea-main.js"));
        Assert.Equal("cache", Text(c, "sea-code-cache.bin"));
    }

    [Fact]
    public void A_sea_startup_snapshot_replaces_the_main_script_item()
    {
        var c = Open(SeaImage(2, Str("main.js"), Str("snap")));
        Assert.Equal("snap", Text(c, "sea-snapshot.bin"));
        Assert.Contains(c.Notes, n => n.Contains("startup snapshot"));
    }

    [Fact]
    public void Sea_execution_arguments_are_named_in_a_note()
    {
        var c = Open(SeaImage(16, Str("main.js"), Str("run()"), U64(2), Str("--a"), Str("--b")));
        Assert.Contains(c.Notes, n => n.Contains("execution arguments: --a --b"));
    }

    [Fact]
    public void A_sea_blob_cut_inside_the_main_script_names_the_offset()
    {
        var c = Open(SeaImage(0, Str("main.js"), U64(50), "abc"u8.ToArray()));
        Assert.Contains(c.Notes, n => n.Contains("ends inside the main script at offset 0x"));
    }

    [Fact]
    public void A_sea_blob_cut_inside_the_main_code_path_names_the_offset()
    {
        var c = Open(SeaImage(0, U64(20), "main"u8.ToArray()));
        Assert.Contains(c.Notes, n => n.Contains("ends inside the main code path at offset 0x"));
    }

    [Fact]
    public void A_runtime_with_an_unset_fuse_is_named_as_holding_no_application()
    {
        var c = Open(Image(Encoding.ASCII.GetBytes(Fuse + ":0")));
        Assert.Empty(c.Items);
        Assert.Contains(c.Notes, n => n.Contains("fuse is not set"));
    }

    [Fact]
    public void A_set_fuse_with_no_blob_is_reported_as_unknown()
    {
        var c = Open(Image(Encoding.ASCII.GetBytes(Fuse + ":1")));
        Assert.Contains(c.Notes, n => n.Contains("fuse is set but no valid blob"));
    }

    [Fact]
    public void An_image_with_no_marker_is_kind_none_with_the_scan_size()
    {
        var image = Image(new byte[40]);
        var c = NodeBundle.Open(image, AnalysisLimits.Default, default);
        Assert.Equal("none", c.Kind);
        Assert.Contains(c.Notes, n => n.Contains($"scanned {image.Length:N0} bytes"));
    }

    [Fact]
    public void A_cancelled_token_stops_the_extraction()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var image = SeaImage(0, Str("main.js"), Str("run()"));
        Assert.Throws<OperationCanceledException>(() => NodeBundle.Open(image, AnalysisLimits.Default, cts.Token));
    }

    [Fact]
    public void The_item_limit_lists_later_entries_without_extracting_them()
    {
        var image = SeaImage(8, Str("main.js"), Str("run()"), U64(2), Str("a"), Str("1"), Str("b"), Str("2"));
        var c = NodeBundle.Open(image, new AnalysisLimits { MaxItems = 1 }, default);
        Assert.Single(c.Items);
        Assert.Equal(3, c.Entries!.Count);
        Assert.Contains(c.Notes, n => n.StartsWith("Stopped: the extraction limit"));
    }

    [Fact]
    public void Entries_whose_paths_collapse_to_one_are_renamed_and_noted()
    {
        var c = Open(SeaImage(8, Str("main.js"), Str("run()"), U64(2), Str("$x"), Str("1"), Str("x"), Str("2")));
        Assert.Equal("1", Text(c, "assets/x"));
        Assert.Equal("2", Text(c, "assets/x-2"));
        Assert.Contains(c.Notes, n => n.Contains("map to assets/x"));
    }

    [Fact]
    public void A_pkg_prelude_maps_snapshot_files_into_the_payload()
    {
        var payload = Encoding.UTF8.GetBytes("console.log('hi')");
        var c = Open(PkgImage(payload, "{\"/snapshot/app/index.js\":{\"1\":[0," + payload.Length + "]}}"));
        Assert.Equal("pkg executable", c.Kind);
        Assert.Equal("console.log('hi')", Text(c, "snapshot/app/index.js"));
        Assert.Contains(c.Notes, n => n.Contains("entry /snapshot/app/index.js"));
    }

    [Fact]
    public void A_pkg_blob_part_is_a_code_cache_and_a_content_part_is_the_file()
    {
        var c = Open(PkgImage("abcde"u8.ToArray(), "{\"/a.js\":{\"1\":[0,3],\"0\":[3,2]}}"));
        Assert.Equal("abc", Text(c, "a.js"));
        Assert.Equal("de", Text(c, "a.js.v8cache"));
        Assert.Equal("pkg V8 code cache", c.Items.Single(i => i.Name == "a.js.v8cache").Origin);
    }

    [Fact]
    public void A_gzip_compressed_pkg_file_is_expanded()
    {
        var packed = Gzip("hello"u8.ToArray());
        var c = Open(PkgImage(packed, "{\"/a.js\":{\"1\":[0," + packed.Length + "]}}"));
        Assert.Equal("hello", Text(c, "a.js"));
    }

    [Fact]
    public void A_gzip_expansion_past_the_total_limit_keeps_the_compressed_bytes()
    {
        var packed = Gzip(new byte[2_000_000]);
        var image = PkgImage(packed, "{\"/a.js\":{\"1\":[0," + packed.Length + "]}}");
        var c = NodeBundle.Open(image, new AnalysisLimits { MaxTotalBytes = 100_000 }, default);
        Assert.Equal(packed.Length, c.Items.Single().Bytes.Length);
        Assert.Contains(c.Notes, n => n.Contains("expansion of /a.js stopped at"));
    }

    [Fact]
    public void A_pkg_entry_outside_the_payload_is_counted_and_not_extracted()
    {
        var c = Open(PkgImage("abc"u8.ToArray(), "{\"/a.js\":{\"1\":[0,999999]},\"/b.js\":{\"1\":[0,3]}}"));
        Assert.Equal("abc", Text(c, "b.js"));
        Assert.Contains(c.Notes, n => n.Contains("1 entries lie outside the payload"));
    }

    [Fact]
    public void An_unparsable_pkg_table_keeps_the_prelude_text()
    {
        var c = Open(PkgImage("abc"u8.ToArray(), "", "boot\n})(require, {not json"));
        Assert.Contains("not json", Text(c, "pkg-prelude.js"));
        Assert.Contains(c.Notes, n => n.Contains("file table could not be parsed"));
    }

    [Fact]
    public void A_nexe_trailer_yields_the_bundle_and_its_resources()
    {
        var code = Encoding.UTF8.GetBytes("process.__nexe = {\"resources\":{\"./a.txt\":[0,3]}};\nrun();");
        var resources = "abc"u8.ToArray();
        var c = Open(Image(new byte[32], code, resources, NexeTrailer(code.Length, resources.Length)));
        Assert.Equal("nexe executable", c.Kind);
        Assert.EndsWith("run();", Text(c, "nexe-bundle.js"));
        Assert.Equal("abc", Text(c, "resources/a.txt"));
    }

    [Fact]
    public void A_nexe_trailer_length_outside_the_image_is_reported_and_nothing_is_extracted()
    {
        var c = Open(Image(new byte[32], NexeTrailer(1e6, 0)));
        Assert.Empty(c.Items);
        Assert.Contains(c.Notes, n => n.Contains("do not fit"));
    }

    [Fact]
    public void A_nexe_bundle_without_a_settings_object_reports_the_resources_as_unknown()
    {
        var code = "run();"u8.ToArray();
        var c = Open(Image(new byte[32], code, NexeTrailer(code.Length, 0)));
        Assert.Contains(c.Notes, n => n.Contains("settings object was not found") && n.Contains("unknown"));
    }

    [Fact]
    public void A_bun_module_table_yields_sources_and_names_the_entry()
    {
        var data = new List<byte>();
        (uint, uint) Put(string s) { var at = (uint)data.Count; data.AddRange(Encoding.UTF8.GetBytes(s)); return (at, (uint)Encoding.UTF8.GetByteCount(s)); }
        var name = Put("/$bunfs/root/app.js");
        var source = Put("export {}");
        var table = (uint)data.Count;
        foreach (var v in new[] { name.Item1, name.Item2, source.Item1, source.Item2, 0u, 0u, 0u, 0u, 0u })
            data.AddRange(BitConverter.GetBytes(v));
        var offsets = new List<byte>();
        offsets.AddRange(U64((ulong)data.Count));
        offsets.AddRange(BitConverter.GetBytes(table));
        offsets.AddRange(BitConverter.GetBytes(36u));
        offsets.AddRange(BitConverter.GetBytes(0u));
        offsets.AddRange(new byte[12]);
        var c = Open(Image([.. data, .. offsets, .. "\n---- Bun! ----\n"u8.ToArray()]));
        Assert.Equal("Bun executable", c.Kind);
        Assert.Equal("export {}", Text(c, "bunfs/root/app.js"));
        Assert.Contains(c.Notes, n => n.Contains("entry /$bunfs/root/app.js"));
    }

    [Fact]
    public void A_bun_trailer_with_no_known_table_layout_reports_the_module_list_as_unknown()
    {
        var c = Open(Image(new byte[64], "\n---- Bun! ----\n"u8.ToArray()));
        Assert.Contains(c.Notes, n => n.Contains("matches no known layout"));
    }

    [Fact]
    public void A_bun_trailer_before_the_end_of_the_image_is_not_a_bun_payload()
    {
        Assert.False(NodeBundle.Accepts(Image("\n---- Bun! ----\n"u8.ToArray(), new byte[40])));
    }

    [Fact]
    public void A_deno_trailer_with_an_unknown_field_count_reports_the_layout_as_not_decoded()
    {
        var trailer = new List<byte>("d3n0l4nd"u8.ToArray());
        for (int i = 0; i < 3; i++) trailer.AddRange(new byte[] { 0, 0, 0, 0, 0, 0, 0, (byte)i });
        var c = Open(Image(new byte[64], [.. trailer]));
        Assert.Empty(c.Items);
        Assert.Contains(c.Notes, n => n.Contains("3 offsets") && n.Contains("not decoded"));
    }

    [Fact]
    public void A_deno_trailer_yields_the_module_archive_and_metadata()
    {
        var archive = "ESZIP"u8.ToArray();
        var meta = "{\"entrypoint\":\"file:///main.ts\"}"u8.ToArray();
        int baseAt = 64;
        var trailer = new List<byte>("d3n0l4nd"u8.ToArray());
        foreach (var v in new[] { baseAt, baseAt + archive.Length })
        {
            var b = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(b, (ulong)v);
            trailer.AddRange(b);
        }
        var c = Open(Image(archive, meta, [.. trailer]));
        Assert.Equal("Deno executable", c.Kind);
        Assert.Equal("ESZIP", Text(c, "deno-modules.eszip"));
        Assert.Contains("main.ts", Text(c, "deno-metadata.json"));
    }

    [Fact]
    [FuzzEntry(typeof(NodeBundle), typeof(NodeBundleReader))]
    public void Fuzzed_node_executables_never_throw_unexpectedly()
    {
        var seed = Image(Encoding.ASCII.GetBytes(Fuse + ":1"), new byte[16], SeaBlob(8, Str("main.js"), Str("console.log(1)"), U64(1), Str("logo.txt"), Str("pixels")));
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { NodeBundle.Open(b, AnalysisLimits.Default, default); } catch (ToolError) { }
            try { Containers.Open(b, "app", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
