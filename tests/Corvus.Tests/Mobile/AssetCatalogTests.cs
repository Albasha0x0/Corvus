using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Core.Mobile;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Compiled asset catalogs (Assets.car): renditions, bitmaps, cropped images, original data, colors.</summary>
public sealed class AssetCatalogTests(ITestOutputHelper output)
{
    // A 3x2 image, premultiplied RGBA, with an opaque, a transparent and a translucent pixel; every pixel's chroma
    // is even so the default deepmap-2 method stores it exactly.
    private static readonly byte[] Premultiplied = [40, 60, 100, 255, 50, 50, 50, 255, 0, 0, 0, 0, 40, 100, 200, 255, 16, 32, 64, 128, 40, 140, 240, 255];
    private static readonly byte[] Straight = [40, 60, 100, 255, 50, 50, 50, 255, 0, 0, 0, 0, 40, 100, 200, 255, 31, 63, 127, 128, 40, 140, 240, 255];
    private static readonly byte[] Notes = "{\"notes\":1}"u8.ToArray();

    private static byte[] Bgra(byte[] rgba)
    {
        var bgra = (byte[])rgba.Clone();
        for (int i = 0; i < bgra.Length; i += 4) (bgra[i], bgra[i + 2]) = (bgra[i + 2], bgra[i]);
        return bgra;
    }

    private static AssetCatalogWriter Catalog()
    {
        var bgra = Bgra(Premultiplied);
        return new AssetCatalogWriter()
            .Facet("Icon", 1).Facet("Badge", 3).Facet("Gray", 4).Facet("Manual", 5).Facet("Notes", 6).Facet("Accent", 7).Facet("Banner", 8)
            .Appearance("NSAppearanceNameDarkAqua", 1)
            .Rendition([1, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(0, bgra))
            .Rendition([2, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 200, AssetCatalogWriter.Celm(4, AssetCatalogWriter.Lzfse(bgra)))
            .Rendition([2, 0, 1, 1], "icon.png", 12, "ARGB", 3, 2, 200, AssetCatalogWriter.Celm(2, AssetCatalogWriter.Kcbc(bgra, 12, 1, AssetCatalogWriter.Gzip)))
            .Rendition([3, 1, 1, 0], "icon.png", 12, "ARGB", 3, 2, 300, AssetCatalogWriter.Celm(4, AssetCatalogWriter.Kcbc(bgra, 12, 1, AssetCatalogWriter.Lzfse)))
            .Rendition([2, 2, 1, 0], "icon.png", 12, "ARGB", 3, 2, 200, AssetCatalogWriter.Celm(11, AssetCatalogWriter.DeepmapRaw(3, 2, bgra)))
            .Rendition([1, 7, 1, 0], "icon.png", 12, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(11, AssetCatalogWriter.DeepmapDefault(3, 2, bgra, [2, 3])))
            .Rendition([2, 7, 1, 0], "icon.png", 12, "ARGB", 3, 2, 200, AssetCatalogWriter.Celm(11, AssetCatalogWriter.DeepmapLossless(3, 2, bgra, 12)))
            .Rendition([1, 3, 1, 0], "icon.png", 12, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(11, AssetCatalogWriter.DeepmapPalette(3, 2, bgra)))
            .Rendition([1, 5, 1, 0], "icon.png", 12, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(11, AssetCatalogWriter.Kcbc(bgra, 12, 1, rows => AssetCatalogWriter.DeepmapDefault(3, 1, rows, [0]))))
            .Rendition([1, 0, 2, 0], "ZZZZPackedAsset-1.0.0-gamut0", 1004, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(0, bgra))
            .Rendition([1, 0, 3, 0], "badge.png", 1003, "ARGB", 2, 1, 100, [], AssetCatalogWriter.Link(1, 0, 2, 1, [1, 0, 2, 0]))
            .Rendition([1, 0, 4, 0], "gray.png", 12, "GA8 ", 2, 1, 100, AssetCatalogWriter.Celm(0, [100, 255, 60, 128]))
            .Rendition([1, 0, 5, 0], "manual.pdf", 1000, "PDF ", 0, 0, 100, AssetCatalogWriter.Rawd("%PDF-1.4 manual"u8.ToArray()))
            .Rendition([1, 0, 6, 0], "notes.json", 1000, "DATA", 0, 0, 100, AssetCatalogWriter.Rawd(AssetCatalogWriter.Lzfse(Notes)))
            .Rendition([1, 0, 7, 0], "Accent", 1009, "", 0, 0, 100, AssetCatalogWriter.Color(1, 1, 0.5, 0.25, 1))
            .Rendition([1, 0, 8, 0], "Banner", 1021, "", 0, 0, 100, AssetCatalogWriter.Gradient(2));
    }

    [Fact]
    public void A_catalog_lists_each_rendition_and_extracts_bitmaps_crops_and_originals()
    {
        var c = Containers.Open(Catalog().Build(), "Assets.car", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("asset catalog", c.Kind);
        Assert.Equal(["asset catalog: 16 renditions of 7 assets for ios 17.0; Xcode 26.0 (17A000) via AssetCatalogAgent"], c.Notes);
        var details = c.Entries!.ToDictionary(e => e.Path, e => e.Detail);
        Assert.Equal("image 3x2 @2x, zip", details["Icon/icon~DarkAqua@2x.png"]);
        Assert.Equal("internal reference 2x1 @1x, cropped from a packed image", details["Badge/badge@1x.png"]);
        Assert.Equal("data, PDF data", details["Manual/manual.pdf"]);
        Assert.Equal("color sRGB 1 0.5 0.25 1", details["Accent/Accent"]);
        Assert.Equal("gradient, 2 stops", details["Banner/Banner"]);
        var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
        foreach (var path in new[] { "Icon/icon@1x.png", "Icon/icon@2x.png", "Icon/icon~DarkAqua@2x.png", "Icon/icon~iphone@3x.png", "Icon/icon~ipad@2x.png",
            "Icon/icon~mac@1x.png", "Icon/icon~mac@2x.png", "Icon/icon~tv@1x.png", "Icon/icon~watch@1x.png", "ZZZZPackedAsset-1.0.0-gamut0/ZZZZPackedAsset-1.0.0-gamut0@1x.png" })
        {
            var (w, h, rgba) = PngPixels.Read(items[path]);
            Assert.True((3, 2) == (w, h) && rgba.SequenceEqual(Straight), path);
        }
        AssertPng(items["Badge/badge@1x.png"], 2, 1, Straight[16..]);
        AssertPng(items["Gray/gray@1x.png"], 2, 1, [100, 100, 100, 255, 119, 119, 119, 128]);
        Assert.Equal("%PDF-1.4 manual"u8.ToArray(), items["Manual/manual.pdf"]);
        Assert.Equal(Notes, items["Notes/notes.json"]);
        Assert.Equal(14, c.Items.Count);
    }

    private static void AssertPng(byte[] png, int width, int height, byte[] pixels)
    {
        var (w, h, rgba) = PngPixels.Read(png);
        Assert.Equal((width, height), (w, h));
        Assert.Equal(pixels, rgba);
    }

    [Fact]
    public void Without_all_files_a_catalog_extracts_only_original_data()
    {
        var c = Containers.Open(Catalog().Build(), "Assets.car", AnalysisLimits.Default, default, allFiles: false);
        Assert.Equal(16, c.Entries!.Count);
        Assert.Equal(["Manual/manual.pdf", "Notes/notes.json"], c.Items.Select(i => i.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Compressions_not_read_and_damaged_bitmaps_are_named_per_rendition_and_counted()
    {
        var bgra = Bgra(Premultiplied);
        var data = new AssetCatalogWriter().Facet("Icon", 1).Declared(9)
            .Rendition([1, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 100, AssetCatalogWriter.Celm(7, bgra))
            .Rendition([2, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 200, AssetCatalogWriter.Celm(0, bgra[..10]))
            .Rendition([3, 0, 1, 0], "icon.png", 12, "RGBW", 3, 2, 300, AssetCatalogWriter.Celm(0, bgra))
            .Rendition([4, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 400, AssetCatalogWriter.Celm(0, bgra))
            .Rendition([4, 0, 1, 0], "icon.png", 12, "ARGB", 3, 2, 400, AssetCatalogWriter.Celm(0, bgra))
            .Build();
        var c = Containers.Open(data, "Assets.car", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(
        [
            "asset catalog: 5 renditions of 1 assets for ios 17.0; Xcode 26.0 (17A000) via AssetCatalogAgent",
            "the header declares 9 renditions; the tree holds 5",
            "renditions not decoded: astc compression (1), pixel format RGBW (1)",
            "1 renditions unreadable (see their entries)",
        ], c.Notes);
        Assert.Equal("image 3x2 @1x, astc; not decoded", c.Entries![0].Detail);
        Assert.StartsWith("image 3x2 @2x, uncompressed; unreadable: 10 bytes for 2 rows", c.Entries[1].Detail);
        Assert.Equal(["Icon/icon@4x.png", "Icon/icon@4x-2.png"], c.Items.Select(i => i.Name));
    }

    [Fact]
    public void A_damaged_catalog_is_refused_as_malformed_input()
    {
        var bad = Catalog().Build();
        // The RENDITIONS variable names a block past the index.
        int vars = (int)BinaryPrimitives.ReadUInt32BigEndian(bad.AsSpan(24));
        int count = (int)BinaryPrimitives.ReadUInt32BigEndian(bad.AsSpan(vars));
        for (int i = 0, p = vars + 4; i < count; i++, p += 5 + bad[p + 4])
            if (Encoding.ASCII.GetString(bad, p + 5, bad[p + 4]) == "RENDITIONS") BinaryPrimitives.WriteUInt32BigEndian(bad.AsSpan(p), 0xFFFF);
        var error = Assert.Throws<ToolError>(() => Containers.Open(bad, "Assets.car", AnalysisLimits.Default, default, allFiles: true));
        Assert.Contains("not a readable asset catalog: block 65535 is not in the index", error.Message);
    }

    [Fact]
    [FuzzEntry(typeof(AssetCatalogReader))]
    public void Fuzzed_catalogs_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Catalog().Build(), b => { try { Containers.Open(b, "Assets.car", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void A_PNG_holds_the_pixels_it_was_written_with()
    {
        var rgba = Enumerable.Range(0, 4 * 5 * 3).Select(i => (byte)(i * 37)).ToArray();
        AssertPng(PngWriter.Rgba(5, 3, rgba), 5, 3, rgba);
    }

    // The reference writes each format's files and manifest to its own folder; the tests compare decoded pixels, so a
    // PNG's encoding may differ while its pixels match.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_ASSET_CATALOG_DIR", "CORVUS_ASSET_CATALOG_READER")]
    public void Real_catalogs_hold_the_renditions_bitmaps_and_originals_carfile_go_reads()
    {
        var tool = ExternalTools.Locate(ExternalTools.AssetCatalogReader)!.Value.Path;
        var files = Directory.GetFiles(RealData.Path("CORVUS_ASSET_CATALOG_DIR"), "*.car").Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        using var dir = new TempDir();
        var problems = new List<string>();
        int bitmaps = 0, crops = 0, originals = 0, wide = 0;
        foreach (var file in files)
        {
            string name = Path.GetFileName(file);
            var data = File.ReadAllBytes(file);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var contents = Containers.Open(data, name, AnalysisLimits.Default, default, allFiles: true);
            output.WriteLine($"{name}: {contents.Entries!.Count} entries, {contents.Items.Count} items in {sw.ElapsedMilliseconds} ms; {string.Join(" | ", contents.Notes)}");
            Assert.Equal("asset catalog", contents.Kind);
            // RGBW (wide color) pixels are named, not decoded: no vendor source fixes their scale.
            foreach (var note in contents.Notes.Where(n => n.Contains("not decoded", StringComparison.Ordinal) || n.Contains("unreadable", StringComparison.Ordinal)))
                if (note != "renditions not decoded: pixel format RGBW (1)") problems.Add($"{name}: {note}");

            var catalog = new AssetCatalog(data);
            var listed = Reference(tool, "json", file, dir.File(name + ".json"), "catalog.json").GetProperty("renditions").EnumerateArray().ToList();
            if (listed.Count != catalog.Renditions.Count || contents.Entries.Count != listed.Count) problems.Add($"{name}: {catalog.Renditions.Count} renditions, {contents.Entries.Count} entries, the reference lists {listed.Count}");
            foreach (var (theirs, ours) in listed.Zip(catalog.Renditions))
            {
                var csi = theirs.GetProperty("csi");
                var payload = csi.GetProperty("payload");
                var expected = (theirs.TryGetProperty("asset_name", out var a) ? a.GetString() : null, csi.GetProperty("name").GetString(), csi.GetProperty("layout").GetInt32(),
                    csi.GetProperty("width").GetInt32(), csi.GetProperty("height").GetInt32(), payload.TryGetProperty("tag", out var t) ? t.GetString() : "");
                if (expected != (ours.Asset, ours.Name, ours.Layout, ours.Width, ours.Height, ours.Tag)) problems.Add($"{name}: rendition {ours.Index} is {(ours.Asset, ours.Name, ours.Layout, ours.Width, ours.Height, ours.Tag)}, the reference reads {expected}");
            }

            var packed = new Dictionary<int, byte[]?>();
            foreach (var format in new[] { "png", "resources" })
            {
                string folder = dir.File($"{name}.{format}");
                foreach (var f in Reference(tool, format, file, folder, "manifest.json").GetProperty("files").EnumerateArray())
                {
                    int index = f.GetProperty("index").GetInt32();
                    string mode = f.TryGetProperty("mode", out var m) ? m.GetString()! : "bitmap", path = Path.Combine(folder, f.GetProperty("file").GetString()!);
                    var r = catalog.Renditions[index];
                    if (r.PixelFormat == "RGBW") { wide++; continue; }
                    if (mode is "bitmap" or "cropped from packed image")
                    {
                        var (w, h, rgba) = PngPixels.Read(File.ReadAllBytes(path));
                        byte[] mine;
                        try { mine = AssetCatalogReader.Pixels(catalog, r, packed, 1L << 30); }
                        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException) { problems.Add($"{name}: rendition {index} ({mode}): {ex.Message}"); continue; }
                        PngWriter.Unpremultiply(mine);
                        if ((w, h) != (r.Width, r.Height) || !mine.AsSpan().SequenceEqual(rgba)) problems.Add($"{name}: rendition {index} ({mode}, {r.Name}) differs");
                        if (mode == "bitmap") bitmaps++; else crops++;
                    }
                    else if (mode is "copied original payload" or "decoded original payload")
                    {
                        var mine = Corvus.Core.Firmware.Lzfse.Looks(r.Payload) ? AssetCatalogBitmap.Lzfse(r.Payload, 1L << 30) : r.Payload;
                        if (!mine.AsSpan().SequenceEqual(File.ReadAllBytes(path))) problems.Add($"{name}: rendition {index} ({mode}, {r.Name}) differs");
                        originals++;
                    }
                }
            }
        }
        output.WriteLine($"{files.Count} catalogs: {bitmaps} bitmaps, {crops} cropped images, {originals} originals compared; {wide} RGBW bitmaps not compared");
        foreach (var p in problems.Take(60)) output.WriteLine(p);
        Assert.Empty(problems);
    }

    private static JsonElement Reference(string tool, string format, string file, string folder, string result)
    {
        var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.AssetCatalogReader, format, ("file", file), ("output", folder)), TimeSpan.FromMinutes(5), 1 << 16, default);
        Assert.True(run.ExitCode == 0, $"{format}: {run.Text}");
        return JsonDocument.Parse(File.ReadAllBytes(Path.Combine(folder, result))).RootElement.Clone();
    }
}
