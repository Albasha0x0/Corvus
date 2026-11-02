using System.Text.Json.Nodes;

namespace Corvus.Tests;

/// <summary>batch --file --dump-modules takes the rebuild options of open_minidump.</summary>
public sealed class DumpModulesCliTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Dump()
    {
        var path = _dir.File("crash.dmp");
        File.WriteAllBytes(path, SyntheticCrash.Builder().Build());
        return path;
    }

    [Fact]
    public async Task The_dump_modules_option_writes_rebuilt_modules()
    {
        var folder = _dir.File("images");
        var (code, output, _) = await ToolCliTests.Run("batch", "--file", Dump(), "--dump-modules", folder,
            "--module", "synth.dll", "--layout", "mapped", "--imports", "keep", "--base", "preferred", "--json", "--no-index");
        Assert.True(code is 0, output);
        var written = Assert.Single(JsonNode.Parse(output)!["dumpModules"]!["written"]!.AsArray());
        Assert.Equal("synth.dll", (string?)written!["file"]);
        Assert.Equal(SyntheticCrash.Image().Length, new FileInfo(Path.Combine(folder, "synth.dll")).Length);
    }

    [Fact]
    public async Task An_unknown_layout_value_is_refused()
    {
        var folder = _dir.File("images");
        var (code, output, error) = await ToolCliTests.Run("batch", "--file", Dump(), "--dump-modules", folder,
            "--layout", "flat", "--json", "--no-index");
        Assert.Equal(2, code);
        Assert.Empty(output);
        Assert.Contains("layout", error);
        Assert.False(Directory.Exists(folder));
    }
}