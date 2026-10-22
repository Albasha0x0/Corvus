using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Tests.NativeFormats;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;

namespace Corvus.Tests;

/// <summary>summarize_file view=dependencies on Go and Rust programs, and the CycloneDX file sbomPath writes.</summary>
public sealed class DependencyInventoryTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>Fails with the validator's messages unless <paramref name="bom"/> is a valid CycloneDX 1.6 JSON document.</summary>
    internal static void AssertValid(byte[] bom)
    {
        var result = CycloneDX.Json.Validator.Validate(Encoding.UTF8.GetString(bom), CycloneDX.SpecificationVersion.v1_6);
        Assert.True(result.Valid, string.Join("\n", result.Messages ?? []));
    }

    private static byte[] GoProgram() => new ElfWriter
    {
        Machine = ElfWriter.EmX64, Is64 = true, Type = 2, Base = 0x400000, Entry = ElfWriter.TextRva, Text = [0xC3],
        Hash = ElfWriter.HashKind.None, DataSectionName = ".go.buildinfo", Data = GoBuildInfoTests.Inline(),
    }.Build();

    private static byte[] RustProgram()
    {
        const string json = """
            {"packages":[
              {"name":"tool","version":"0.3.1","source":"local","dependencies":[1,2],"root":true},
              {"name":"serde","version":"1.0.210","source":"crates.io","dependencies":[]},
              {"name":"cc","version":"1.1.0","source":"crates.io","kind":"build"}
            ]}
            """;
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(Encoding.UTF8.GetBytes(json));
        return new ElfWriter { DataSectionName = ".dep-v0", Data = ms.ToArray() }.Build();
    }

    private (string Path, InspectionService.FileSummary Summary) Summarize(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return (path, new InspectionService(_workspace).Summarize(null, path, default));
    }

    private static DependencyFacts Facts(InspectionService.FileSummary s) => Assert.IsType<DependencyFacts>(s.Views["dependencies"].Detail);

    [Fact]
    public void Go_modules_are_named_with_golang_purls_and_the_standard_library()
    {
        var facts = Facts(Summarize("tool", GoProgram()).Summary);
        Assert.Equal(("example.com/tool", "v1.4.2", "pkg:golang/example.com/tool@v1.4.2"), (facts.Subject!.Name, facts.Subject.Version, facts.Subject.Purl));
        Assert.Equal(["pkg:golang/stdlib@1.22.5", "pkg:golang/golang.org/x/sys@v0.20.0", "pkg:golang/example.com/fork@v1.0.1"], facts.All.Select(c => c.Purl));
        // The replace directive names the module whose code was compiled.
        Assert.Contains("replaces example.com/old v1.0.0", facts.All[2].Source);
        Assert.Equal(3, Assert.Single(facts.Edges).To.Count);
    }

    [Fact]
    public void Crates_io_crates_get_cargo_purls_and_build_crates_are_excluded()
    {
        var facts = Facts(Summarize("tool", RustProgram()).Summary);
        Assert.Equal(("tool", "application"), (facts.Subject!.Name, facts.Subject.Type));
        Assert.Equal([("pkg:cargo/serde@1.0.210", null), ("pkg:cargo/cc@1.1.0", "excluded")], facts.All.Select(c => (c.Purl, c.Scope)));
        Assert.Equal(2, facts.Edges.Single(e => e.From == facts.Subject.Ref).To.Count);
    }

    [Fact]
    public void A_plain_assembly_with_nothing_bundled_has_no_dependencies_view()
    {
        Assert.False(new InspectionService(_workspace).Summarize(null, Env.FixturePath, default).Views.ContainsKey("dependencies"));
    }

    [Fact]
    public void Go_and_Rust_sboms_validate_against_the_CycloneDX_1_6_schema()
    {
        foreach (var (path, summary) in new[] { Summarize("go-tool", GoProgram()), Summarize("rust-tool", RustProgram()) })
            AssertValid(CycloneDx.Write(Facts(summary), path, summary.File.Sha256, "1.0.0", DateTimeOffset.UnixEpoch, Guid.Empty));
    }

    [Fact]
    public async Task The_sbom_path_refuses_an_existing_file_unless_overwrite_is_set()
    {
        var (path, _) = Summarize("rust-tool", RustProgram());
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace), _workspace);
        var sbom = _dir.File("tool.cdx.json");
        var text = await tools.SummarizeFile(path: path, view: "dependencies", sbomPath: sbom);
        Assert.Contains($"CycloneDX 1.6 SBOM written to {sbom}: 2 components, 2 with a package URL.", text);
        using (var doc = JsonDocument.Parse(File.ReadAllBytes(sbom)))
            Assert.Equal("tool", doc.RootElement.GetProperty("metadata").GetProperty("component").GetProperty("name").GetString());
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: path, sbomPath: sbom));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        Assert.Contains("SBOM written to", await tools.SummarizeFile(path: path, sbomPath: sbom, overwrite: true));
    }
}
