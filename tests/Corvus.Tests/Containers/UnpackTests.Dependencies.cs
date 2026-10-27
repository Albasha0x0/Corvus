using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Analysis.Dependencies;

namespace Corvus.Tests;

/// <summary>summarize_file view=dependencies on .NET containers: deps.json, assembly metadata, the runtime, Costura.</summary>
public partial class UnpackTests
{
    private static string NewtonsoftJson => RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll");

    private static string HelloDepsJson()
    {
        var sha = File.ReadAllText(RealPackages.File("Newtonsoft.Json", "13.0.1", "newtonsoft.json.13.0.1.nupkg.sha512")).Trim();
        return """
            {"runtimeTarget":{"name":".NETCoreApp,Version=v10.0/win-x64"},
             "targets":{".NETCoreApp,Version=v10.0":{},".NETCoreApp,Version=v10.0/win-x64":{
               "Hello/1.0.0":{"dependencies":{"Newtonsoft.Json":"13.0.1","Analyzers.Only":"2.0.0"},"runtime":{"Hello.dll":{}}},
               "Newtonsoft.Json/13.0.1":{"runtime":{"lib/netstandard2.0/Newtonsoft.Json.dll":{"assemblyVersion":"13.0.0.0","fileVersion":"13.0.1.25517"}}},
               "Analyzers.Only/2.0.0":{}}},
             "libraries":{
               "Hello/1.0.0":{"type":"project","serviceable":false,"sha512":""},
               "Newtonsoft.Json/13.0.1":{"type":"package","serviceable":true,"sha512":"sha512-SHA","path":"newtonsoft.json/13.0.1"},
               "Analyzers.Only/2.0.0":{"type":"package","serviceable":true,"sha512":"","path":"analyzers.only/2.0.0"}}}
            """.Replace("sha512-SHA", "sha512-" + sha);
    }

    private string BundleOf(string name, params ContainerFixtures.BundleEntry[] entries) =>
        Save(name, ContainerFixtures.WithManifest(File.ReadAllBytes(fx.Bundle), entries));

    private DependencyFacts Dependencies(string path) =>
        Assert.IsType<DependencyFacts>(new InspectionService(_workspace).Summarize(null, path, default).Views["dependencies"].Detail);

    private string HelloBundleWithDepsJson() => BundleOf("Hello.exe",
        new("Hello.dll", File.ReadAllBytes(fx.HelloDll)),
        new("Newtonsoft.Json.dll", File.ReadAllBytes(NewtonsoftJson)),
        new("Hello.deps.json", System.Text.Encoding.UTF8.GetBytes(HelloDepsJson()), Type: 3));

    [Fact]
    public void A_bundled_deps_json_names_each_package_with_its_purl_hash_and_location()
    {
        var facts = Dependencies(HelloBundleWithDepsJson());
        Assert.Equal(("Hello", "1.0.0", "application"), (facts.Subject!.Name, facts.Subject.Version, facts.Subject.Type));
        var json = Assert.Single(facts.All, c => c.Name == "Newtonsoft.Json");
        Assert.Equal(("pkg:nuget/Newtonsoft.Json@13.0.1", 1.0, "manifest-analysis"), (json.Purl, json.Confidence, json.Technique));
        Assert.Equal(["Newtonsoft.Json.dll"], json.Locations);
        var sha = Convert.FromBase64String(File.ReadAllText(RealPackages.File("Newtonsoft.Json", "13.0.1", "newtonsoft.json.13.0.1.nupkg.sha512")).Trim());
        Assert.Equal(new ComponentHash("SHA-512", Convert.ToHexStringLower(sha)), Assert.Single(json.Hashes));
        Assert.Contains(json.Ref, Assert.Single(facts.Edges, e => e.From == facts.Subject.Ref).To);
        // The bundled copy is claimed by its package, not listed again from its metadata.
        Assert.DoesNotContain(facts.All, c => c.Technique == "binary-analysis");
    }

    [Fact]
    public void A_package_with_no_runtime_asset_below_it_is_excluded()
    {
        var facts = Dependencies(HelloBundleWithDepsJson());
        Assert.Equal("excluded", Assert.Single(facts.All, c => c.Name == "Analyzers.Only").Scope);
        Assert.Null(Assert.Single(facts.All, c => c.Name == "Newtonsoft.Json").Scope);
    }

    [Fact]
    public void A_bundle_without_deps_json_names_an_assembly_by_its_informational_version()
    {
        var facts = Dependencies(BundleOf("Hello.exe",
            new("Hello.dll", File.ReadAllBytes(fx.HelloDll)),
            new("Newtonsoft.Json.dll", File.ReadAllBytes(NewtonsoftJson))));
        Assert.Equal("Hello", facts.Subject!.Name);
        var json = Assert.Single(facts.All);
        Assert.Equal(("pkg:nuget/Newtonsoft.Json@13.0.1", 0.7, "binary-analysis"), (json.Purl, json.Confidence, json.Technique));
        Assert.Equal(new ComponentHash("SHA-256", Sha(NewtonsoftJson)), Assert.Single(json.Hashes));
    }

    [Fact]
    public void An_assembly_with_only_an_assembly_version_has_an_unknown_version_and_no_purl()
    {
        var facts = Dependencies(BundleOf("Hello.exe",
            new("Hello.dll", File.ReadAllBytes(fx.HelloDll)),
            new("Helper.dll", ContainerFixtures.Module("Helper", Array.Empty<(string, byte[])>()))));
        var helper = Assert.Single(facts.All);
        Assert.Equal(("Helper", (string?)null, false, (string?)null, "1.2.3.4"), (helper.Name, helper.Version, helper.VersionKnown, helper.Purl, helper.AssemblyVersion));
        Assert.Contains(facts.Notes, n => n.Contains("package version unknown, no package URL", StringComparison.Ordinal));
        using var bom = System.Text.Json.JsonDocument.Parse(CycloneDx.Write(facts, "Hello.exe", new string('0', 64), "1.0.0", DateTimeOffset.UnixEpoch, Guid.Empty));
        var properties = bom.RootElement.GetProperty("components")[0].GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString());
        Assert.Equal("unknown", properties["corvus:version"]);
    }

    [Fact]
    public void The_runtime_assemblies_roll_up_into_one_framework_component()
    {
        var runtime = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var facts = Dependencies(BundleOf("Hello.exe",
            new("Hello.dll", File.ReadAllBytes(fx.HelloDll)),
            new("System.Private.CoreLib.dll", File.ReadAllBytes(Path.Combine(runtime, "System.Private.CoreLib.dll"))),
            new("System.Runtime.dll", File.ReadAllBytes(Path.Combine(runtime, "System.Runtime.dll")))));
        var framework = Assert.Single(facts.All);
        Assert.Equal(("Microsoft.NETCore.App", "framework", null), (framework.Name, framework.Type, framework.Purl));
        Assert.StartsWith($"{Environment.Version.Major}.{Environment.Version.Minor}.", framework.Version);
        Assert.Equal(["System.Private.CoreLib.dll", "System.Runtime.dll"], framework.Locations);
    }

    [Fact]
    public void A_costura_embedded_assembly_is_named_with_its_location()
    {
        var host = ContainerFixtures.Module("CosturaHost", ("costura.newtonsoft.json.dll.compressed", ContainerFixtures.Deflate(File.ReadAllBytes(NewtonsoftJson))));
        var json = Assert.Single(Dependencies(Save("CosturaHost.exe", host)).All);
        Assert.Equal(("pkg:nuget/Newtonsoft.Json@13.0.1", "newtonsoft.json.dll"), (json.Purl, Assert.Single(json.Locations)));
    }

    [Fact]
    public void A_deps_json_beside_the_app_is_read()
    {
        var app = _dir.File("Hello.dll");
        File.Copy(fx.HelloDll, app);
        File.WriteAllText(_dir.File("Hello.deps.json"), HelloDepsJson());
        var facts = Dependencies(app);
        Assert.Equal("1.0.0", facts.Subject!.Version);
        Assert.Equal(1.0, Assert.Single(facts.All, c => c.Name == "Newtonsoft.Json").Confidence);
        Assert.Contains(facts.Sources, s => s.StartsWith("deps.json " + _dir.File("Hello.deps.json"), StringComparison.Ordinal));
    }

    [Fact]
    public void The_bundle_sbom_validates_against_the_CycloneDX_1_6_schema()
    {
        var path = HelloBundleWithDepsJson();
        var facts = Dependencies(path);
        DependencyInventoryTests.AssertValid(CycloneDx.Write(facts, path, Sha(path), "1.0.0", DateTimeOffset.UnixEpoch, Guid.Empty));
    }
}
