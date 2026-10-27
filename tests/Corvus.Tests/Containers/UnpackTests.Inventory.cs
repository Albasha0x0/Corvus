using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>unpack_container's inventory: every file paged, an honest result when nothing is extracted, and progress.</summary>
public partial class UnpackTests
{
    [Fact]
    public void Nothing_extracted_names_the_next_call_or_fails()
    {
        // Not a container at all, whatever its name says.
        var data = Save("blob.tar.xz", [0x4E, 0x4F, 0x54, 0x41, 0x52, 0x43, .. new byte[200]]);
        var ex = Assert.Throws<ToolError>(() => Unpack(data));
        Assert.Equal(ErrorCode.Unsupported, ex.Code);
        Assert.StartsWith($"summarize_file path={data}", ex.Remediation);
        // The hint names no format as unread: tar and gzip unpack.
        Assert.DoesNotContain("not read", ex.Remediation);
        using (var tar = new MemoryStream())
        {
            using (var w = new System.Formats.Tar.TarWriter(tar, System.Formats.Tar.TarEntryFormat.Ustar, leaveOpen: true))
                w.WriteEntry(new System.Formats.Tar.UstarTarEntry(System.Formats.Tar.TarEntryType.RegularFile, "lib/app.dll") { DataStream = File.OpenRead(Env.FixturePath) });
            Assert.NotEmpty(Unpack(Save("app.tar", tar.ToArray())).Files);
            var gz = new MemoryStream();
            using (var z = new System.IO.Compression.GZipStream(gz, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true)) z.Write(tar.ToArray());
            Assert.NotEmpty(Unpack(Save("app.tar.gz", gz.ToArray())).Files);
        }

        // A plain assembly and a native image: nothing bundled, the next call is load_assembly.
        var plain = Unpack(Env.FixturePath);
        Assert.Empty(plain.Files);
        Assert.Equal(("load_assembly", Env.FixturePath), (plain.Next!.Tool, plain.Next.Arguments["path"]));
        var native = McpProtocolTests.NativeSample(_dir);
        Assert.Equal(("load_assembly", native), (Unpack(native).Next!.Tool, Unpack(native).Next!.Arguments["path"]));

        // A package without assemblies.
        var empty = Save("empty.nupkg", ContainerFixtures.Zip(("x.nuspec", "<package/>"u8.ToArray()), ("build/x.targets", "<Project/>"u8.ToArray())));
        Assert.Equal("summarize_file", Unpack(empty).Next!.Tool);
        // Something extracted: no next.
        Assert.Null(Unpack(fx.Bundle).Next);
    }

    [Fact]
    public async Task Every_file_is_written_and_listed_in_pages()
    {
        var entries = Enumerable.Range(0, 7).Select(i => ($"lib/a{i}.dll", File.ReadAllBytes(Env.FixturePath).Concat(new byte[] { (byte)i }).ToArray()))
            .Append(("readme.txt", "hello"u8.ToArray())).ToArray();
        var zip = Save("many.zip", ContainerFixtures.Zip(entries));
        var tools = new UnpackTools(Unpacker);
        var output = _dir.File("many-out");
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var text = await tools.UnpackContainer(zip, output, extractOnly: true, offset: 0, limit: 3);
        var first = Assert.IsType<UnpackPage>(collector.Value);
        Assert.Equal((0, 3), (first.Offset, first.Items.Count));
        Assert.Contains("[More: offset=3]", text);
        Assert.Null(first.Next);
        // Relative to outputDirectory.
        Assert.All(first.Items, f => Assert.True(File.Exists(Path.Combine(first.OutputDirectory, f.Path)), f.Path));
        int total = first.Total;
        Assert.Equal(Directory.GetFiles(output, "*", SearchOption.AllDirectories).Count(f => !f.EndsWith(".corvus-unpack", StringComparison.Ordinal)), total);

        // The same unpack again pages on: the rows after the first page, the same total.
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.UnpackContainer(zip, output, extractOnly: true, offset: 3, limit: 100);
        var rest = Assert.IsType<UnpackPage>(collector.Value);
        Assert.Equal(total, rest.Total);
        Assert.Equal(total - 3, rest.Items.Count);
        Assert.Empty(first.Items.Select(f => f.Path).Intersect(rest.Items.Select(f => f.Path)));
    }

    [Fact]
    public void List_pages_union_to_the_total_without_duplicates()
    {
        // Satellites first in the zip: the listing order (app first, translations last) differs from the entry order.
        var fixture = File.ReadAllBytes(Env.FixturePath);
        var entries = Enumerable.Range(0, 6).Select(i => ($"fr/a{i}.resources.dll", fixture.Append((byte)i).ToArray()))
            .Concat(Enumerable.Range(0, 9).Select(i => ($"lib/b{i}.dll", fixture.Append((byte)(i + 10)).ToArray()))).ToArray();
        var zip = Save("pages.zip", ContainerFixtures.Zip(entries));
        var whole = Unpacker.List(zip, AnalysisLimits.Default, default).Assemblies.Select(a => a.Path).ToList();
        var walked = new List<string>();
        for (int offset = 0; offset < whole.Count; offset += 4)
            walked.AddRange(Unpacker.List(zip, AnalysisLimits.Default, default, offset: offset, limit: 4).Assemblies.Select(a => a.Path));
        Assert.Equal(15, whole.Count);
        // The first (whole) page and later pages share one order.
        Assert.Equal(whole, walked);
        Assert.StartsWith("lib/", whole[0]);
    }

    /// <summary>unpack_container loads what it extracts unless extractOnly.</summary>
    [Fact]
    public async Task Loads_by_default_extract_only_does_not()
    {
        var zip = Save("one.zip", ContainerFixtures.Zip(("lib/a.dll", File.ReadAllBytes(Env.FixturePath))));
        var tools = new UnpackTools(Unpacker);
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.UnpackContainer(zip, _dir.File("one-extract"), extractOnly: true);
        Assert.Null(Assert.Single(Assert.IsType<UnpackPage>(collector.Value).Items, f => f.Path.EndsWith("a.dll", StringComparison.Ordinal)).LoadedAs);
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.UnpackContainer(zip, _dir.File("one-load"));
        Assert.NotNull(Assert.Single(Assert.IsType<UnpackPage>(collector.Value).Items, f => f.Path.EndsWith("a.dll", StringComparison.Ordinal)).LoadedAs);
    }

    [Fact]
    public void Progress_names_the_phases()
    {
        var messages = new List<string>();
        Unpacker.Unpack(fx.Bundle, _dir.File("progress-out"), load: true, AnalysisLimits.Default, default, messages.Add);
        Assert.StartsWith("reading ", messages[0]);
    }
}
