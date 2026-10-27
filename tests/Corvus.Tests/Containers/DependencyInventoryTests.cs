using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Services;
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
    public void An_AOT_build_names_the_runtime_with_its_class_libraries_and_leaves_package_versions_unknown()
    {
        AotMetadataOnly.AssemblyIdentity Id(string name, string version) => new(name, new Version(version), null);
        var facts = DependencyInventory.OfAotMetadata(
            [Id("mscorlib", "4.0.0.0"), Id("UnityEngine.CoreModule", "0.0.0.0"), Id("System.Core", "4.0.0.0"), Id("Assembly-CSharp", "0.0.0.0"),
             Id("Newtonsoft.Json", "13.0.0.0"), Id("Unity.TextMeshPro", "0.0.0.0")], "2022.3.62f1", "AOT metadata", "Cell App")!;
        Assert.Equal("Cell App", facts.Subject!.Name);
        Assert.Equal(["Assembly-CSharp.dll"], facts.Subject.Locations);
        var engine = facts.All[0];
        Assert.Equal(("Unity", "2022.3.62f1", "pkg:generic/unity@2022.3.62f1"), (engine.Name, engine.Version, engine.Purl));
        Assert.Equal(["mscorlib.dll", "UnityEngine.CoreModule.dll", "System.Core.dll"], engine.Locations);
        Assert.Equal([("Newtonsoft.Json", "13.0.0.0"), ("Unity.TextMeshPro", null)], facts.All.Skip(1).Select(c => (c.Name, c.AssemblyVersion)));
        Assert.All(facts.All.Skip(1), c => Assert.Equal((null, false, null), (c.Version, c.VersionKnown, c.Purl)));
        AssertValid(CycloneDx.Write(facts, "global-metadata.dat", new string('0', 64), "1.0.0", DateTimeOffset.UnixEpoch, Guid.Empty));
    }

    [Fact]
    public void An_AOT_build_without_a_runtime_version_reports_it_unknown()
    {
        var engine = DependencyInventory.OfAotMetadata([new("UnityEngine", new Version(0, 0, 0, 0), null)], null, "AOT metadata", null)!.All[0];
        Assert.Equal(("Unity", null, null), (engine.Name, engine.Version, engine.Purl));
    }

    /// <summary>A Windows AOT build folder, without its binary; null leaves a file out.</summary>
    private string AotBuild(string name, string? engineVersion, string? product)
    {
        var data = Path.Combine(_dir.File(name), "App_Data");
        var metadata = Path.Combine(data, "il2cpp_data", "Metadata", "global-metadata.dat");
        Directory.CreateDirectory(Path.GetDirectoryName(metadata)!);
        File.WriteAllBytes(metadata, new AotMetadataWriter().Assembly("Assembly-CSharp", "0.0.0.0").Assembly("mscorlib", "4.0.0.0", [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89])
            .Assembly("UnityEngine.CoreModule", "0.0.0.0").Assembly("Newtonsoft.Json", "13.0.0.0", [0x30, 0xAD, 0x4F, 0xE6, 0xB2, 0xA6, 0xAE, 0xED]).Build());
        // globalgamemanagers keeps the runtime version as a NUL-terminated string at offset 20.
        if (engineVersion != null) File.WriteAllBytes(Path.Combine(data, "globalgamemanagers"), [.. new byte[20], .. Encoding.ASCII.GetBytes(engineVersion), 0, .. new byte[64]]);
        if (product != null) File.WriteAllText(Path.Combine(data, "app.info"), $"Example Company\n{product}");
        return metadata;
    }

    [Fact]
    public void An_AOT_builds_metadata_lists_the_runtime_its_assemblies_and_the_product()
    {
        var path = AotBuild("app", "2021.3.45f1", "Cell App");
        var facts = Facts(new InspectionService(_workspace).Summarize(null, path, default, new FileViewOptions("dependencies")));
        Assert.Equal("Cell App", facts.Subject!.Name);
        Assert.Equal(["Assembly-CSharp.dll"], facts.Subject.Locations);
        var engine = facts.All[0];
        Assert.Equal(("Unity", "2021.3.45f1", "pkg:generic/unity@2021.3.45f1"), (engine.Name, engine.Version, engine.Purl));
        Assert.Equal(["mscorlib.dll", "UnityEngine.CoreModule.dll"], engine.Locations);
        var json = Assert.Single(facts.All.Skip(1));
        Assert.Equal(("Newtonsoft.Json", "13.0.0.0", null, null), (json.Name, json.AssemblyVersion, json.Version, json.Purl));
        Assert.Contains(facts.Sources, s => s.StartsWith("AOT metadata", StringComparison.Ordinal) && s.Contains("metadata v29", StringComparison.Ordinal));
    }

    [Fact]
    public void An_AOT_build_without_globalgamemanagers_reads_with_the_runtime_version_unknown()
    {
        var path = AotBuild("bare", null, null);
        var facts = Facts(new InspectionService(_workspace).Summarize(null, path, default, new FileViewOptions("dependencies")));
        var engine = facts.All[0];
        Assert.Equal(("Unity", null, null), (engine.Name, engine.Version, engine.Purl));
        Assert.Equal("Assembly-CSharp", facts.Subject!.Name);
        Assert.Contains(facts.Notes, n => n.Contains("engine version is unknown", StringComparison.Ordinal));
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
