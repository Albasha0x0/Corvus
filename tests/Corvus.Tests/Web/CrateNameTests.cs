using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>Crate names checked against the most downloaded crates.</summary>
public sealed class CrateNameTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Crate(string name)
    {
        var path = _dir.File($"{name}-0.1.0.crate");
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Fastest);
        using var tar = new TarWriter(gz, TarEntryFormat.Ustar);
        tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, $"{name}-0.1.0/Cargo.toml")
            { DataStream = new MemoryStream(Encoding.UTF8.GetBytes($"[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n")) });
        return path;
    }

    [Fact]
    public void A_crate_one_edit_from_a_popular_crate_is_a_review_finding()
    {
        var r = PackageReview.Review(Crate("serdee"), default)!;
        Assert.Contains(r.Findings, f => f is { Rule: "package/close-name", Level: "review", Category: "name" }
            && f.Detail.Contains("'serde'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_popular_crate_name_itself_raises_nothing()
    {
        Assert.DoesNotContain(PackageReview.Review(Crate("serde"), default)!.Findings, f => f.Rule == "package/close-name");
    }
}
