using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>unpack_container's inventory: every file paged, an honest result when nothing is extracted, and progress.</summary>
public partial class UnpackTests
{
    [Fact]
    public void NothingExtracted_NamesTheNextCallOrFails()
    {
        // not a container at all, whatever its name says
        var data = Save("blob.tar.xz", [0x4E, 0x4F, 0x54, 0x41, 0x52, 0x43, .. new byte[200]]);
        var ex = Assert.Throws<ToolError>(() => Unpack(data));
        Assert.Equal(ErrorCode.Unsupported, ex.Code);
        Assert.StartsWith($"summarize_file path={data}", ex.Remediation);

        // a plain assembly and a native image: nothing bundled, the next call is load_assembly
        var plain = Unpack(Env.FixturePath);
        Assert.Empty(plain.Files);
        Assert.Equal(("load_assembly", Env.FixturePath), (plain.Next!.Tool, plain.Next.Arguments["path"]));
        var native = McpProtocolTests.NativeSample(_dir);
        Assert.Equal(("load_assembly", native), (Unpack(native).Next!.Tool, Unpack(native).Next!.Arguments["path"]));

        // a package without assemblies
        var empty = Save("empty.nupkg", ContainerFixtures.Zip(("x.nuspec", "<package/>"u8.ToArray()), ("build/x.targets", "<Project/>"u8.ToArray())));
        Assert.Equal("summarize_file", Unpack(empty).Next!.Tool);
        // something extracted: no next
        Assert.Null(Unpack(fx.Bundle).Next);
    }

    [Fact]
    public async Task EveryFileIsWrittenAndListedInPages()
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
        Assert.All(first.Items, f => Assert.True(File.Exists(Path.Combine(first.OutputDirectory, f.Path)), f.Path)); // relative to outputDirectory
        int total = first.Total;
        Assert.Equal(Directory.GetFiles(output, "*", SearchOption.AllDirectories).Count(f => !f.EndsWith(".corvus-unpack", StringComparison.Ordinal)), total);

        // the same unpack again pages on: the rows after the first page, the same total
        collector = Corvus.Mcp.ToolOutput.Collect();
        await tools.UnpackContainer(zip, output, extractOnly: true, offset: 3, limit: 100);
        var rest = Assert.IsType<UnpackPage>(collector.Value);
        Assert.Equal(total, rest.Total);
        Assert.Equal(total - 3, rest.Items.Count);
        Assert.Empty(first.Items.Select(f => f.Path).Intersect(rest.Items.Select(f => f.Path)));
    }

    [Fact]
    public void ListPages_UnionToTheTotalWithoutDuplicates()
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
        Assert.Equal(whole, walked); // the first (whole) page and later pages share one order
        Assert.StartsWith("lib/", whole[0]);
    }

    /// <summary>unpack_container loads what it extracts unless extractOnly (the default of the former load=true).</summary>
    [Fact]
    public async Task LoadsByDefault_ExtractOnlyDoesNot()
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
    public void ProgressNamesThePhases()
    {
        var messages = new List<string>();
        Unpacker.Unpack(fx.Bundle, _dir.File("progress-out"), load: true, AnalysisLimits.Default, default, messages.Add);
        Assert.StartsWith("reading ", messages[0]);
    }
}
