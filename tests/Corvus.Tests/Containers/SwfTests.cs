using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Flash;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Flash SWF files: tags, ActionScript 3 blocks, images, sounds and binary data.</summary>
public sealed partial class SwfTests(ITestOutputHelper output)
{
    private static ContainerContents Open(byte[] bytes, string name = "app.swf") => Containers.Open(bytes, name, AnalysisLimits.Default, default, allFiles: true);

    private static byte[] Item(ContainerContents c, string path) => c.Items.Single(i => i.Name == path).Bytes;

    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];

    /// <summary>One tag of each kind the reader extracts, a sprite, and the names SymbolClass and ExportAssets give.</summary>
    private static byte[] Sample(char compression) => SwfSamples.File(compression, 32, 2,
        SwfSamples.Tag(69, SwfSamples.U32(0x08)),
        SwfSamples.Tag(77, Encoding.UTF8.GetBytes("<rdf:RDF/>\0")),
        SwfSamples.Tag(9, [0xFF, 0x80, 0x00]),
        // A 2x1 DefineBitsLossless2 of premultiplied ARGB: opaque red, half-transparent white.
        SwfSamples.Tag(36, [.. SwfSamples.U16(1), 5, .. SwfSamples.U16(2), .. SwfSamples.U16(1), .. SwfSamples.Z(0xFF, 0xFF, 0, 0, 0x80, 0x80, 0x80, 0x80)]),
        // A 3x1 colormapped DefineBitsLossless: two colors, rows padded to 4 bytes.
        SwfSamples.Tag(20, [.. SwfSamples.U16(2), 3, .. SwfSamples.U16(3), .. SwfSamples.U16(1), 1, .. SwfSamples.Z(0, 0, 255, 0, 255, 0, 1, 0, 1, 0)]),
        SwfSamples.Tag(8, [0xFF, 0xD8, 0xFF, 0xDB, 0xAA, 0xFF, 0xD9]),
        SwfSamples.Tag(6, [.. SwfSamples.U16(3), 0xFF, 0xD8, 0xFF, 0xC0, 0xBB, 0xFF, 0xD9]),
        SwfSamples.Tag(21, [.. SwfSamples.U16(4), 0xFF, 0xD9, 0xFF, 0xD8, .. Png]),
        SwfSamples.Tag(35, [.. SwfSamples.U16(5), .. SwfSamples.U32(4), 0xFF, 0xD8, 0xFF, 0xD9, .. SwfSamples.Z(0x80)]),
        // 16-bit mono PCM at 22,050 Hz, two samples; and MP3 behind its seek count.
        SwfSamples.Tag(14, [.. SwfSamples.U16(6), 0x3A, .. SwfSamples.U32(2), 1, 0, 2, 0]),
        SwfSamples.Tag(14, [.. SwfSamples.U16(7), 0x2E, .. SwfSamples.U32(1152), 0, 0, 0xFF, 0xFB, 0x90]),
        SwfSamples.Tag(87, [.. SwfSamples.U16(8), 0, 0, 0, 0, .. Encoding.UTF8.GetBytes("payload")]),
        SwfSamples.Tag(39, [.. SwfSamples.U16(9), .. SwfSamples.U16(1), .. SwfSamples.Tag(12, [0x07, 0x00]), .. SwfSamples.Tag(1, []), .. SwfSamples.Tag(0, [])]),
        SwfSamples.Tag(59, [.. SwfSamples.U16(9), 0x06, 0x00]),
        SwfSamples.Tag(82, [.. SwfSamples.U32(1), .. Encoding.UTF8.GetBytes("frame1\0"), .. SwfSamples.Abc()], longForm: true),
        SwfSamples.Tag(56, [.. SwfSamples.U16(2), .. SwfSamples.U16(8), .. Encoding.UTF8.GetBytes("exported\0"), .. SwfSamples.U16(9), .. Encoding.UTF8.GetBytes("Clip\0")]),
        SwfSamples.Tag(76, [.. SwfSamples.U16(2), .. SwfSamples.U16(8), .. Encoding.UTF8.GetBytes("sample.Payload\0"), .. SwfSamples.U16(1), .. Encoding.UTF8.GetBytes("sample.Logo\0")]),
        SwfSamples.Tag(12, [0x00]),
        SwfSamples.Tag(1, []),
        SwfSamples.Tag(1, []));

    [Theory]
    [InlineData('F')]
    [InlineData('C')]
    [InlineData('Z')]
    public void A_file_lists_its_scripts_images_sounds_and_data(char compression)
    {
        var c = Open(Sample(compression));
        Assert.Equal(SwfReader.KindName, c.Kind);
        Assert.StartsWith("Flash SWF version 32, " + (compression == 'F' ? "uncompressed" : compression == 'C' ? "zlib-compressed" : "lzma-compressed") +
            ", 550x400 px, 24 fps, 2 frame(s); 24 tags (", c.Notes[0]);
        Assert.EndsWith("1 ActionScript 3 block(s), 3 ActionScript 1/2 action list(s).", c.Notes[0]);
        Assert.Equal(
        [
            "actions/Clip.init.bin", "actions/Clip/frame_1.bin", "actions/frame_1.bin", "binary/sample.Payload.bin", "images/character_2.png", "images/character_3.jpg",
            "images/character_4.png", "images/character_5.jpg", "images/sample.Logo.png", "metadata.xml", "scripts/frame1.abc", "scripts/frame1.classes.txt",
            "sounds/character_6.wav", "sounds/character_7.mp3",
        ], c.Entries!.Select(e => e.Path).Order(StringComparer.Ordinal));
        Assert.Equal("payload", Encoding.UTF8.GetString(Item(c, "binary/sample.Payload.bin")));
        Assert.Equal("<rdf:RDF/>", Encoding.UTF8.GetString(Item(c, "metadata.xml")));
        Assert.Equal([0xFF, 0xD8, 0xFF, 0xDB, 0xAA, 0xFF, 0xC0, 0xBB, 0xFF, 0xD9], Item(c, "images/character_3.jpg"));
        Assert.Equal(Png, Item(c, "images/character_4.png"));
        Assert.Equal("DefineBitsJPEG3, alpha channel stored apart (zlib), not applied", c.Entries!.Single(e => e.Path == "images/character_5.jpg").Detail);
        Assert.Equal([0xFF, 0xFB, 0x90], Item(c, "sounds/character_7.mp3"));
        var wav = Item(c, "sounds/character_6.wav");
        Assert.Equal("RIFF", Encoding.ASCII.GetString(wav, 0, 4));
        Assert.Equal(22050, BitConverter.ToInt32(wav, 24));
        Assert.Equal([1, 0, 2, 0], wav[44..]);
        Assert.Equal([0x07, 0x00], Item(c, "actions/Clip/frame_1.bin"));
        Assert.Equal([0x00], Item(c, "actions/frame_1.bin"));
        Assert.Equal([0x06, 0x00], Item(c, "actions/Clip.init.bin"));
        Assert.Equal("ABC 46.16, 2 classes, 7 methods, 7 method bodies", c.Entries!.Single(e => e.Path == "scripts/frame1.abc").Detail);
        Assert.Equal(
            "interface sample:IRunner\n" +
            "class sample:Runner extends flash.display:Sprite implements sample:IRunner\n" +
            "  static const :LIMIT\n" +
            "  slot :count\n" +
            "  slot private:secret\n" +
            "  method :run\n" +
            "  getter :size\n", Encoding.UTF8.GetString(Item(c, "scripts/frame1.classes.txt")));
    }

    [Fact]
    public void Lossless_bitmaps_become_straight_alpha_png()
    {
        var c = Open(Sample('C'));
        // Premultiplied (0x80, 0x80, 0x80, 0x80) is white at half alpha.
        Assert.Equal([0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x80], PngPixels(Item(c, "images/sample.Logo.png")));
        Assert.Equal([0, 255, 0, 255, 0, 0, 255, 255, 0, 255, 0, 255], PngPixels(Item(c, "images/character_2.png")));
    }

    /// <summary>The RGBA bytes of a PNG PngWriter wrote: one IDAT of unfiltered rows.</summary>
    private static byte[] PngPixels(byte[] png)
    {
        int at = png.AsSpan().IndexOf("IDAT"u8);
        int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(at - 4));
        using var z = new System.IO.Compression.ZLibStream(new MemoryStream(png, at + 4, length), System.IO.Compression.CompressionMode.Decompress);
        var rows = new MemoryStream();
        z.CopyTo(rows);
        int width = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16));
        return rows.ToArray().Where((_, i) => i % (width * 4 + 1) != 0).ToArray();
    }

    [Fact]
    public void A_cut_file_keeps_its_readable_tags_and_notes_the_rest()
    {
        var full = Sample('F');
        var cut = full[..(full.Length - 40)];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(cut.AsSpan(4), (uint)cut.Length);
        var c = Open(cut);
        Assert.Contains(c.Notes, n => n.Contains("runs past the end", StringComparison.Ordinal));
        Assert.Contains(c.Entries!, e => e.Path == "scripts/frame1.abc");

        var zlib = Sample('C');
        var c2 = Open(zlib[..(zlib.Length - 30)]);
        Assert.Contains(c2.Notes, n => n.Contains("of the", StringComparison.Ordinal) || n.Contains("stops expanding", StringComparison.Ordinal));

        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => SwfFile.Read([.. "CWS"u8, 10, 100, 0, 0, 0, 1, 2, 3], "x.swf", 1 << 20)).Code);
    }

    [Fact]
    public void A_damaged_script_block_is_kept_and_noted()
    {
        var abc = SwfSamples.Abc();
        var c = Open(SwfSamples.File('F', 10, 1, SwfSamples.Tag(72, abc.AsSpan(0, abc.Length / 2))));
        Assert.Equal("does not parse", c.Entries!.Single(e => e.Path == "scripts/block_0.abc").Detail);
        Assert.Contains(c.Notes, n => n.StartsWith("scripts/block_0.abc: ", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(SwfFile), typeof(SwfReader), typeof(AbcFile))]
    public void Fuzzed_files_never_throw()
    {
        var limits = new AnalysisLimits { MaxItemBytes = 1 << 20 };
        foreach (var sample in new[] { Sample('F'), Sample('C') })
        {
            var failures = FormatFuzz.Run(sample, b =>
            {
                try { new SwfReader().Open(b, "fuzz.swf", true, limits, default); }
                catch (ToolError e) when (e.Code is ErrorCode.MalformedInput or ErrorCode.LimitExceeded) { }
            }, 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
        var abcFailures = FormatFuzz.Run(SwfSamples.Abc(), b =>
        {
            try { AbcFile.Read(b); }
            catch (InvalidDataException) { }
        }, 200);
        Assert.True(abcFailures.Count == 0, string.Join("\n", abcFailures.Take(20)));
    }

    /// <summary>
    /// CORVUS_SWF_FILES (a folder of .swf files) compared with swfdump of the Apache Flex SDK (CORVUS_SWF_DUMP, swfdump.jar,
    /// run with java from JAVA_HOME or PATH): the tags in order, each sprite's tags, the binary data sizes, and per
    /// ActionScript 3 block the pool, method and class counts and every class with its base, interfaces and traits.
    /// </summary>
    [RequiresRealDataFact("CORVUS_SWF_FILES", "CORVUS_SWF_DUMP")]
    [Trait("Speed", "Slow")]
    public void Real_files_read_as_swfdump_reads_them()
    {
        var mismatches = new List<string>();
        int files = 0, classes = 0, tags = 0;
        foreach (var path in Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_SWF_FILES")!, "*.swf", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            string label = Path.GetFileName(path);
            var bytes = File.ReadAllBytes(path);
            var swf = SwfFile.Read(bytes, label, 1L << 30);
            mismatches.AddRange(swf.Notes.Select(n => $"{label}: {n}"));
            var dump = Dump(path, "-noglyphs");
            var mine = swf.Tags.Where(t => t.Sprite == 0 && t.Code != 0).Select(t => $"{t.Name}").ToList();
            var theirs = TopTag().Matches(dump).Select(m => m.Groups[1].Value == "ScalingGrid" ? "DefineScalingGrid" : m.Groups[1].Value).ToList();
            Compare(label, "tags", mine, theirs, mismatches);
            tags += mine.Count;
            var mineNested = swf.Tags.Where(t => t.Sprite != 0 && t.Code is not (0 or 1)).Select(t => t.Name).ToList();
            var theirsNested = SpriteBlock().Matches(dump).SelectMany(m => NestedTag().Matches(m.Groups[1].Value).Select(x => x.Groups[1].Value)).ToList();
            Compare(label, "sprite tags", mineNested, theirsNested, mismatches);
            var c = Open(bytes, label);
            // Past the summary, a note is a resource that did not read.
            mismatches.AddRange(c.Notes.Skip(1 + swf.Notes.Count).Select(n => $"{label}: {n}"));
            Compare(label, "binary data sizes",
                c.Entries!.Where(e => e.Detail == "DefineBinaryData").Select(e => e.Size.ToString()).Order().ToList(),
                BinaryLength().Matches(dump).Select(m => m.Groups[1].Value).Order().ToList(), mismatches);
            var blocks = Dump(path, "-abc").Split("<DoABC", StringSplitOptions.None).Skip(1).ToList();
            var abcs = swf.Tags.Where(t => t.Code is 72 or 82).Select(t =>
            {
                int at = t.Code == 82 ? t.At + 4 : t.At;
                if (t.Code == 82) SwfFile.String(swf.Body, at, t.At + t.Length, out at);
                return AbcFile.Read(swf.Body.AsSpan(at, t.At + t.Length - at));
            }).ToList();
            if (blocks.Count != abcs.Count) { mismatches.Add($"{label}: {abcs.Count} ABC blocks, swfdump {blocks.Count}"); continue; }
            for (int i = 0; i < abcs.Count; i++) classes += CompareAbc($"{label} block {i}", abcs[i], blocks[i], mismatches);
            files++;
        }
        output.WriteLine($"{files} files, {tags} tags, {classes} classes compared");
        Assert.True(files > 0, "no .swf files");
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches.Take(40)));
    }

    private static int CompareAbc(string label, AbcFile abc, string dump, List<string> mismatches)
    {
        var counts = new Dictionary<string, int>
        {
            ["Integer Constant Pool Entries"] = abc.Integers.Length, ["Unsigned Integer Constant Pool Entries"] = abc.Unsigned.Length,
            ["Floating Point Constant Pool Entries"] = abc.Doubles.Length, ["String Constant Pool Entries"] = abc.Strings.Length,
            ["Namespace Constant Pool Entries"] = abc.Namespaces, ["Namespace Set Constant Pool Entries"] = abc.NamespaceSets,
            ["MultiName Constant Pool Entries"] = abc.Multinames.Length, ["Method Entries"] = abc.Methods.Length, ["Metadata Entries"] = abc.Metadata,
            ["Instance Entries"] = abc.Classes.Count, ["Class Entries"] = abc.Classes.Count, ["Script Entries"] = abc.Scripts, ["Method Bodies"] = abc.Bodies.Count,
        };
        foreach (var (heading, count) in counts)
        {
            var m = Regex.Match(dump, $@"^\s+(\d+) {heading}?$", RegexOptions.Multiline);
            // swfdump prints a pool's count as stored; an empty pool is stored as 0 and still has entry 0.
            int theirs = m.Success ? int.Parse(m.Groups[1].Value) : -1;
            if (theirs != count && !(theirs == 0 && count == 1 && heading.Contains("Pool", StringComparison.Ordinal)))
                mismatches.Add($"{label}: {heading}: {count}, swfdump {theirs}");
        }
        var lines = dump.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        var theirsClasses = new List<string>();
        for (int i = 0; i < lines.Count; i++)
        {
            var header = InstanceHeader().Match(lines[i]);
            if (!header.Success) continue;
            var count = TraitCount().Match(lines[i + 1]);
            int n = count.Success ? int.Parse(count.Groups[1].Value) : 0;
            var interfaces = header.Groups[3].Success ? header.Groups[3].Value.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries) : [];
            theirsClasses.Add($"{header.Groups[1].Value} : {header.Groups[2].Value} : {string.Join(" ", interfaces)} : " +
                string.Join(" ", lines.Skip(i + 2).Take(n).Select(l => l.Trim())));
        }
        var mineClasses = abc.Classes.Select(c => $"{c.Name} : {c.Super} : {string.Join(" ", c.Interfaces)} : {string.Join(" ", c.Traits.Select(t => t.Name))}").ToList();
        Compare(label, "classes", mineClasses, theirsClasses, mismatches);
        return mineClasses.Count;
    }

    private static void Compare(string label, string what, List<string> mine, List<string> theirs, List<string> mismatches)
    {
        if (mine.SequenceEqual(theirs)) return;
        int i = 0;
        while (i < mine.Count && i < theirs.Count && mine[i] == theirs[i]) i++;
        mismatches.Add($"{label}: {what}: {mine.Count} vs swfdump {theirs.Count}; first difference at {i}: " +
            $"{(i < mine.Count ? mine[i] : "(end)")} | {(i < theirs.Count ? theirs[i] : "(end)")}");
    }

    private static string Dump(string path, string option)
    {
        string java = Environment.GetEnvironmentVariable("JAVA_HOME") is { Length: > 0 } home ? Path.Combine(home, "bin", "java") : "java";
        var info = new ProcessStartInfo(java) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "-jar", Environment.GetEnvironmentVariable("CORVUS_SWF_DUMP")!, option, path }) info.ArgumentList.Add(a);
        using var p = Process.Start(info)!;
        var stderr = p.StandardError.ReadToEndAsync();
        string text = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        _ = stderr.Result;
        return text;
    }

    [GeneratedRegex(@"^  <([A-Z]\w*)", RegexOptions.Multiline)]
    private static partial Regex TopTag();

    [GeneratedRegex(@"^  <DefineSprite [^\n]*\n(.*?)^  </DefineSprite>", RegexOptions.Multiline | RegexOptions.Singleline)]
    private static partial Regex SpriteBlock();

    [GeneratedRegex(@"^    <([A-Z]\w*)", RegexOptions.Multiline)]
    private static partial Regex NestedTag();

    [GeneratedRegex(@"<DefineBinaryData id='\d+' length='(\d+)'")]
    private static partial Regex BinaryLength();

    [GeneratedRegex(@"^\s+Instance Traits for: (\S+)(?: extends (\S+))?(?: implements\s+(.*?))?\s*$")]
    private static partial Regex InstanceHeader();

    [GeneratedRegex(@"^\s+(\d+) Traits Entries$")]
    private static partial Regex TraitCount();
}
