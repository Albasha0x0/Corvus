using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Installers;

namespace Corvus.Tests;

/// <summary>ClickOnce publish folders: the deployment manifest, the application manifest it names, and the files that one lists.</summary>
public sealed class ClickOnceTests
{
    private const string Head = """<?xml version="1.0" encoding="utf-8"?><asmv1:assembly manifestVersion="1.0" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">""";

    private static string Hash(byte[] bytes) =>
        $"""<hash><dsig:Transforms><dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" /></dsig:Transforms><dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256" /><dsig:DigestValue>{Convert.ToBase64String(SHA256.HashData(bytes))}</dsig:DigestValue></hash>""";

    /// <summary>The application manifest of App 1.0.0.0: App.exe (the entry point) and data.txt, whose listed digest is of other bytes.</summary>
    internal static byte[] AppManifest(byte[] exe) => Encoding.UTF8.GetBytes(Head +
        """<asmv1:assemblyIdentity name="App.exe" version="1.0.0.0" type="win32" /><application /><entryPoint><commandLine file="App.exe" parameters="" /></entryPoint>""" +
        """<trustInfo><security><applicationRequestMinimum><PermissionSet Unrestricted="true" ID="Custom" /></applicationRequestMinimum></security></trustInfo>""" +
        $"""<dependency><dependentAssembly dependencyType="install" codebase="App.exe" size="{exe.Length}"><assemblyIdentity name="App" version="1.0.0.0" />{Hash(exe)}</dependentAssembly></dependency>""" +
        $"""<file name="data.txt" size="5">{Hash("other"u8.ToArray())}</file></asmv1:assembly>""");

    internal static byte[] DeploymentManifest(byte[] app) => Encoding.UTF8.GetBytes(Head +
        """<asmv1:assemblyIdentity name="App.application" version="1.0.0.0" /><description asmv2:publisher="Sample" asmv2:product="App" xmlns="urn:schemas-microsoft-com:asm.v1" />""" +
        """<deployment install="true" mapFileExtensions="true" />""" +
        $"""<dependency><dependentAssembly dependencyType="install" codebase="Application Files\App_1_0_0_0\App.exe.manifest" size="{app.Length}"><assemblyIdentity name="App.exe" version="1.0.0.0" />{Hash(app)}</dependentAssembly></dependency></asmv1:assembly>""");

    [Fact]
    public void A_ClickOnce_publish_folder_extracts_the_files_its_manifests_list()
    {
        using var dir = new TempDir();
        var version = Directory.CreateDirectory(Path.Combine(dir.Path, "Application Files", "App_1_0_0_0")).FullName;
        Directory.CreateDirectory(Path.Combine(dir.Path, "Application Files", "App_0_9_0_0"));
        byte[] exe = [0x4D, 0x5A, 1, 2, 3];
        var app = AppManifest(exe);
        File.WriteAllBytes(Path.Combine(version, "App.exe.manifest"), app);
        File.WriteAllBytes(Path.Combine(version, "App.exe.deploy"), exe);
        File.WriteAllBytes(Path.Combine(version, "data.txt.deploy"), "hello"u8.ToArray());
        File.WriteAllBytes(Path.Combine(dir.Path, "App.application"), DeploymentManifest(app));

        var manifest = ClickOnceDeployment.Find(dir.Path);
        Assert.Equal(Path.Combine(dir.Path, "App.application"), manifest);
        var c = ClickOnceDeployment.Open(manifest!, AnalysisLimits.Default, default);
        Assert.Equal("ClickOnce deployment", c.Kind);
        Assert.Contains("ClickOnce deployment App 1.0.0.0 by Sample: 2 file(s) in Application Files/App_1_0_0_0, installed (available offline), entry point App.exe, full trust, unsigned.", c.Notes);
        Assert.Equal(exe, Assert.Single(c.Items, i => i.Name == "App.exe").Bytes);
        Assert.Contains(c.Entries!, e => e.Path == "App.exe" && e.Detail == "entry point");
        Assert.Contains(c.Entries!, e => e.Path == "data.txt" && e.Detail == "differs from its manifest digest");
        Assert.Contains("1 file(s) differ from their manifest digest or size.", c.Notes);
        Assert.Contains("Application Files also holds 1 other publish(es): App_0_9_0_0.", c.Notes);
    }

    // A fuzz input that took 28 s: 41,903 nested dependency elements.
    [Fact]
    public void A_manifest_nested_past_the_depth_limit_is_refused_in_bounded_time()
    {
        var data = Encoding.UTF8.GetBytes(Head + """<asmv1:assemblyIdentity name="App.application" version="1.0.0.0" /><deployment install="true" />"""
            + string.Concat(Enumerable.Repeat("<dependency>", 40_000)) + string.Concat(Enumerable.Repeat("</dependency>", 40_000)) + "</asmv1:assembly>");
        var cpu = ThreadCpuClock.Now();
        var e = Assert.Throws<ToolError>(() => Containers.Open(data, "App.application", AnalysisLimits.Default, default));
        Assert.True(ThreadCpuClock.Now() - cpu < TimeSpan.FromSeconds(2));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);
        Assert.Contains("deeper than 256 levels", e.Message);
    }

    [Fact]
    [FuzzEntry(typeof(ClickOnceManifestReader), typeof(ClickOnceManifest))]
    public void Fuzzed_ClickOnce_manifests_never_throw_past_a_tool_error()
    {
        var app = AppManifest([1, 2, 3]);
        foreach (var (seed, name) in new[] { (DeploymentManifest(app), "App.application"), (app, "App.exe.manifest") })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
            }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
