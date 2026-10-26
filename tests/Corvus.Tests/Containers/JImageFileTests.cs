using System.Buffers.Binary;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Core.JImage;

namespace Corvus.Tests;

/// <summary>Java runtime images (lib/modules): resources by module and their decompressed content, as jimage lists and extracts them.</summary>
public sealed class JImageFileTests : IDisposable
{
    private const string JImageTool = "CORVUS_JIMAGE";
    private const string JImageFiles = "CORVUS_JIMAGE_FILES";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void An_image_lists_its_resources_by_module_and_restores_their_content()
    {
        var (bytes, expected) = JImageSamples.Sample();
        Assert.Equal("jimage", Blob.Identify(bytes));
        var image = JImageFile.Read(bytes);
        Assert.Equal((1, 0, false, 3), (image.Major, image.Minor, image.BigEndian, image.Directories));
        Assert.Empty(image.Notes);
        Assert.Equal(expected.Select(e => $"{e.Module}/{e.Path}").Order(StringComparer.Ordinal),
            image.Resources.Select(r => $"{r.Module}/{r.Path}").Order(StringComparer.Ordinal));
        foreach (var e in expected)
        {
            var r = image.Resources.Single(r => r.Module == e.Module && r.Path == e.Path);
            Assert.Equal(e.Content.LongLength, r.Size);
            Assert.Equal(e.Content, image.Content(r, 1 << 20));
        }
        Assert.Equal(["compact-cp", "zip", "zip"], image.Resources.Select(image.Compression).OfType<string>().Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_compact_cp_class_gets_its_shared_strings_and_descriptors_back()
    {
        var w = new JImageSamples();
        var (original, shared) = w.SharedClass();
        var bytes = w.Build([new("m", "p", "C", "class", original) { Stored = shared }]);
        var image = JImageFile.Read(bytes);
        Assert.Equal(original, image.Content(image.Resources[0], 1 << 20));
        Assert.True(original.AsSpan().IndexOf("(Ljava/lang/String;ILjava/util/List;)V"u8) > 0);
    }

    [Fact]
    public void A_big_endian_image_of_format_1_1_reads_with_its_preview_attribute()
    {
        var (bytes, expected) = JImageSamples.Sample(bigEndian: true, minor: 1);
        Assert.Equal(JImageSamples.Magic, BinaryPrimitives.ReadUInt32BigEndian(bytes));
        var image = JImageFile.Read(bytes);
        Assert.Equal((1, 1, true), (image.Major, image.Minor, image.BigEndian));
        Assert.Empty(image.Notes);
        foreach (var e in expected) Assert.Equal(e.Content, image.Content(image.Resources.Single(r => r.Path == e.Path), 1 << 20));
    }

    [Fact]
    public void The_container_lists_module_paths_and_extracts_every_file_on_request()
    {
        var (bytes, expected) = JImageSamples.Sample();
        var listed = Containers.Open(bytes, "modules", new AnalysisLimits(), default);
        Assert.Equal(JImageFile.Kind, listed.Kind);
        Assert.Empty(listed.Items);
        Assert.Equal(expected.Count, listed.Entries!.Count);
        Assert.Equal("zip, ", listed.Entries.Single(e => e.Path == "app.core/com/example/data/notes.txt").Detail![..5]);
        Assert.StartsWith("Java runtime image (jimage 1.0, little-endian): 6 resources in 2 modules, 3 directory entries; compressed: 2 zip, 1 compact-cp.", listed.Notes[0]);

        var all = Containers.Open(bytes, "modules", new AnalysisLimits(), default, allFiles: true);
        Assert.Equal(expected.Select(e => (e.Module + "/" + e.Path, Convert.ToHexString(e.Content))).OrderBy(p => p.Item1, StringComparer.Ordinal),
            all.Items.Select(i => (i.Name, Convert.ToHexString(i.Bytes))).OrderBy(p => p.Name, StringComparer.Ordinal));

        var capped = Containers.Open(bytes, "modules", new AnalysisLimits { MaxItems = 2 }, default, allFiles: true);
        Assert.Equal(2, capped.Items.Count);
        Assert.Contains(capped.Notes, n => n.StartsWith("Stopped after 2 files (", StringComparison.Ordinal));
    }

    [Fact]
    public void A_stream_reads_as_the_bytes_do()
    {
        var (bytes, _) = JImageSamples.Sample();
        var path = _dir.File("modules");
        File.WriteAllBytes(path, bytes);
        var streamed = Containers.OpenStream(() => File.OpenRead(path), bytes.AsSpan(0, 64), "modules", new AnalysisLimits(), default)!;
        var held = Containers.Open(bytes, "modules", new AnalysisLimits(), default);
        Assert.Equal(held.Entries, streamed.Entries);
        Assert.Equal(held.Notes, streamed.Notes);
    }

    [Fact]
    public void A_resource_the_hash_does_not_reach_is_named_unreachable()
    {
        var (bytes, _) = JImageSamples.Sample();
        int count = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16));
        // Clearing every redirect leaves each resource listed by its offset and found by no lookup.
        bytes.AsSpan(28, 4 * count).Clear();
        var image = JImageFile.Read(bytes);
        Assert.Equal(6, image.Resources.Count);
        Assert.Contains("6 resources are not found by the hash of their name: the runtime does not load them.", image.Notes);
    }

    [Fact]
    public void A_file_that_is_no_image_is_refused_with_its_reason()
    {
        var (bytes, _) = JImageSamples.Sample();
        Assert.Contains("magic", Refused(bytes.AsSpan(4).ToArray()));
        var version = bytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(version.AsSpan(4), 2 << 16);
        Assert.Contains("format 2.0 is not read", Refused(version));
        Assert.Contains("runs past the file", Refused(bytes.AsSpan(0, 100).ToArray()));
        var e = Assert.Throws<ToolError>(() => Containers.Open(bytes.AsSpan(0, 100).ToArray(), "modules", new AnalysisLimits(), default));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);

        var w = new JImageSamples();
        var odd = w.Build([new("m", null, "x", null, [1, 2, 3]) { Stored = w.Layer("lz4", [9, 9], 3) }]);
        var image = JImageFile.Read(odd);
        Assert.Contains("the lz4 decompressor is not supported (zip and compact-cp are)", Assert.Throws<InvalidDataException>(() => image.Content(image.Resources[0], 1 << 20)).Message);
        var forged = w.Build([new("m", null, "y", null, new byte[16]) { Stored = w.Layer("zip", [0x78, 0x9C, 3, 0], 1L << 40) }]);
        var big = JImageFile.Read(forged);
        Assert.Contains("over the 1,048,576-byte limit", Assert.Throws<InvalidDataException>(() => big.Content(big.Resources[0], 1 << 20)).Message);
    }

    [Fact]
    [FuzzEntry(typeof(JImageFile))]
    public void Fuzzed_images_never_throw()
    {
        var (sample, _) = JImageSamples.Sample();
        var failures = FormatFuzz.Run(sample, b =>
        {
            JImageFile image;
            try { image = JImageFile.Read(b); }
            catch (InvalidDataException) { return; }
            foreach (var r in image.Resources)
            {
                try { image.Content(r, 1 << 20); }
                catch (InvalidDataException) { }
            }
            try { Containers.Open(b, "modules", new AnalysisLimits { MaxItemBytes = 1 << 20 }, default, allFiles: true); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
        }, 200);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // jimage (CORVUS_JIMAGE) lists and extracts each runtime image under CORVUS_JIMAGE_FILES; compared: the resource
    // names by module and every resource's bytes.
    [RequiresRealDataFact(JImageTool, JImageFiles)]
    [Trait("Speed", "Slow")]
    public void Real_images_list_and_extract_as_jimage_does()
    {
        var tool = Environment.GetEnvironmentVariable(JImageTool)!;
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable(JImageFiles)!, "*", SearchOption.AllDirectories)
            .Where(f => { try { using var s = File.OpenRead(f); var h = new byte[28]; return s.Read(h) == 28 && JImageFile.Looks(h); } catch (IOException) { return false; } })
            .ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var listing = Run(tool, "list", file);
            var expected = new List<string>();
            string? module = null;
            foreach (var line in listing.Split('\n').Select(l => l.TrimEnd('\r')))
            {
                if (line.StartsWith("Module: ", StringComparison.Ordinal)) module = line[8..];
                else if (module != null && line.StartsWith("    ", StringComparison.Ordinal)) expected.Add(module + "/" + line[4..]);
            }
            using var stream = File.OpenRead(file);
            var image = JImageFile.Read(stream);
            Assert.True(image.Notes.Count == 0, $"{file}: {string.Join("; ", image.Notes)}");
            Assert.Equal(expected.Order(StringComparer.Ordinal), image.Resources.Select(r => r.Module + "/" + r.Path).Order(StringComparer.Ordinal));

            var into = _dir.File("extract-" + Guid.NewGuid().ToString("N"));
            Run(tool, "extract", $"--dir={into}", file);
            foreach (var r in image.Resources)
            {
                var reference = File.ReadAllBytes(Path.Combine(into, r.Module, r.Path));
                Assert.True(reference.AsSpan().SequenceEqual(image.Content(r, 1L << 30)), $"{file}: {r.Module}/{r.Path} differs");
            }
            Directory.Delete(into, recursive: true);
        }
    }

    private static string Refused(byte[] b) => Assert.Throws<InvalidDataException>(() => JImageFile.Read(b)).Message;

    private static string Run(string tool, params string[] args)
    {
        var start = new ProcessStartInfo(tool) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"jimage {string.Join(' ', args)}: exit {p.ExitCode}: {error.Result}");
        return output.Result;
    }
}
