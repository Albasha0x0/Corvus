using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The review of an executable two archives deep.</summary>
public sealed class NestedExecutableTests
{
    private static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Zip(params (string Name, byte[] Data)[] entries) => ContainerFixtures.Zip(entries);

    private static InspectionService.FileSummary Summarize(string path)
    {
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        return new InspectionService(workspace).Summarize(null, path, default);
    }

    private static Finding[] Nested(byte[] file)
    {
        using var dir = new TempDir();
        var path = dir.File("outer.zip");
        File.WriteAllBytes(path, file);
        return [.. Summarize(path).Findings().Where(f => f.Rule == "archive/nested-executable")];
    }

    [Fact]
    public void An_executable_in_an_archive_inside_an_archive_is_a_review_finding()
    {
        var inner = Zip(("tool.exe", U("MZ")), ("readme.txt", U("x")));
        var f = Assert.Single(Nested(Zip(("inner.zip", inner))));
        Assert.Equal(FindingLevel.Review, f.Level);
        Assert.Contains("tool.exe", f.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void An_executable_in_an_archive_at_the_first_depth_is_not_reviewed()
    {
        Assert.Empty(Nested(Zip(("tool.exe", U("MZ")), ("readme.txt", U("x")))));
    }

    [Fact]
    public void A_document_in_an_archive_inside_an_archive_is_not_reviewed()
    {
        Assert.Empty(Nested(Zip(("inner.zip", Zip(("readme.txt", U("x")))))));
    }

    [Fact]
    public void A_library_in_a_package_inside_an_archive_is_not_reviewed()
    {
        var package = Zip(("Lib.nuspec", U("<package/>")), ("lib/net8.0/Lib.dll", ContainerFixtures.Module("Lib")));
        Assert.Empty(Nested(Zip(("Lib.1.0.0.nupkg", package))));
    }
}
