using System.Text.Json;
using dnlib.DotNet;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

/// <summary>ReadyToRun status, merged-assembly labels, and list_assemblies on container files.</summary>
public partial class UnpackTests
{
    // ------------------------------------------------------------------ merged-assembly fixtures

    private static TypeDefUser AddType(ModuleDefUser m, string ns, string name, bool compilerGenerated = false)
    {
        var t = new TypeDefUser(ns, name, m.CorLibTypes.Object.TypeDefOrRef) { Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed };
        if (compilerGenerated)
        {
            var attr = new TypeRefUser(m, "System.Runtime.CompilerServices", "CompilerGeneratedAttribute", m.CorLibTypes.AssemblyRef);
            t.CustomAttributes.Add(new CustomAttribute(new MemberRefUser(m, ".ctor", MethodSig.CreateInstance(m.CorLibTypes.Void), attr)));
        }
        m.Types.Add(t);
        return t;
    }

    /// <summary>
    /// What ILMerge leaves when inputs LibB, Contoso.Utils and Lib2 each had a clashing non-public type: the first input
    /// keeps "Helper" / "&lt;PrivateImplementationDetails&gt;", later ones get "Input.Name" (compiler-generated) or
    /// "Input&lt;key&gt;.Name" (the rest), in the same namespace.
    /// </summary>
    private static byte[] IlMerged() => ContainerFixtures.Module("IlMerged", m =>
    {
        AddType(m, "", "<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "LibB.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "Contoso.Utils.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "Lib2.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "App.Internal", "Helper");
        AddType(m, "App.Internal", "LibB7.Helper");
        AddType(m, "App.Internal", "Contoso.Utils12.Helper");
        AddType(m, "App.Internal", "Lib227.Helper"); // "Lib2" + key 27, not "Lib" + key 227
    });

    /// <summary>ILRepack's "ILRepack.List": a BinaryFormatter string[] (same bytes as ILRepack's StringArrayBinaryFormatter).</summary>
    private static byte[] RepackList(params string[] names)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms))
        {
            w.Write(new byte[] { 0x00, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0 });
            w.Write((byte)0x11);
            w.Write(1);
            w.Write(names.Length);
            int id = 2;
            foreach (var n in names)
            {
                w.Write((byte)0x06);
                w.Write(id++);
                w.Write(n);
            }
            w.Write((byte)0x0B);
        }
        return ms.ToArray();
    }

    private static byte[] Repacked() => ContainerFixtures.Module("Repacked", ("ILRepack.List", RepackList(
        "LibA, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
        "LibB, Version=2.0.0.0, Culture=neutral, PublicKeyToken=null",
        "Repacked, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null")));

    private static string? MergeNote(byte[] assembly)
    {
        using var module = ModuleDefMD.Load(assembly);
        return AssemblyTraits.MergeNote(module);
    }

    // ------------------------------------------------------------------ ReadyToRun

    [Fact]
    public void ReadyToRun_DetectedOnCrossgenOutput_NotOnIlOnlyAssemblies()
    {
        Assert.True(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(fx.ReadyToRunDll)));
        Assert.True(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(typeof(object).Assembly.Location))); // the shared framework ships R2R
        Assert.False(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(fx.HelloDll))); // same app, plain build
        Assert.False(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(Env.FixturePath)));
        Assert.False(AssemblyTraits.IsReadyToRun("not a PE file"u8));
    }

    [Fact]
    public void UnpackContainer_ReportsReadyToRunPerAssembly()
    {
        var r2r = Unpack(fx.ReadyToRunBundle);
        Assert.True(Entry(r2r, "Hello.dll").ReadyToRun);
        Assert.Null(Entry(r2r, "Hello.deps.json").ReadyToRun); // not an assembly

        var plain = Unpack(fx.Bundle);
        Assert.False(Entry(plain, "Hello.dll").ReadyToRun);
    }

    // ------------------------------------------------------------------ merged assemblies

    [Fact]
    public void IlMergeRenames_AreLabelledWithTheRecoveredInputs()
    {
        Assert.Equal("Merged assembly (ILMerge-style): at least 4 original modules (renamed types from Contoso.Utils, Lib2, LibB).", MergeNote(IlMerged()));
    }

    [Fact]
    public void IlRepackList_GivesTheExactInputs()
    {
        Assert.Equal("Merged by ILRepack from 3 assemblies: LibA, LibB, Repacked.", MergeNote(Repacked()));
        var corrupt = ContainerFixtures.Module("BadList", ("ILRepack.List", [0x00, 0x01, 0x02]));
        Assert.Equal("Merged by ILRepack (ILRepack.List resource present, but its list is unreadable).", MergeNote(corrupt));
    }

    [Fact]
    public void OldCompilerHelperClasses_FromSeveralModules_AreLabelled()
    {
        var two = ContainerFixtures.Module("OldMerged", m =>
        {
            AddType(m, "", "<PrivateImplementationDetails>{6F9619FF-8B86-D011-B42D-00C04FC964FF}", compilerGenerated: true);
            AddType(m, "", "<PrivateImplementationDetails>{0E984725-C51C-4BF4-9960-E1C80E27ABA0}", compilerGenerated: true);
        });
        Assert.Equal("Merged assembly (ILMerge-style): at least 2 original modules.", MergeNote(two));

        var one = ContainerFixtures.Module("OldSingle", m => AddType(m, "", "<PrivateImplementationDetails>{6F9619FF-8B86-D011-B42D-00C04FC964FF}", compilerGenerated: true));
        Assert.Null(MergeNote(one));
    }

    [Fact]
    public void UnmergedAssemblies_AreNotLabelled()
    {
        Assert.Null(MergeNote(System.IO.File.ReadAllBytes(Env.FixturePath)));
        // a dotted type name alone is not enough: the undotted original must be there too
        Assert.Null(MergeNote(ContainerFixtures.Module("Odd", m => AddType(m, "Ns", "Weird.Name"))));
        // every assembly of the shared framework (none of them merged): no false positives on real compiler output
        var framework = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var labelled = Directory.EnumerateFiles(framework, "*.dll")
            .Where(f => Blob.Identify(System.IO.File.ReadAllBytes(f)) == ".NET assembly")
            .Select(f => (File: Path.GetFileName(f), Note: MergeNote(System.IO.File.ReadAllBytes(f))))
            .Where(x => x.Note != null).ToList();
        Assert.True(labelled.Count == 0, string.Join("\n", labelled));
    }

    [Fact]
    public void UnpackContainer_LabelsMergedAssemblies()
    {
        var zip = ContainerFixtures.Zip(("IlMerged.dll", IlMerged()), ("Repacked.dll", Repacked()), ("TestFixture.dll", System.IO.File.ReadAllBytes(Env.FixturePath)));
        var r = Unpack(Save("merged.zip", zip));
        Assert.StartsWith("Merged assembly (ILMerge-style): at least 4", Entry(r, "IlMerged.dll").Merged);
        Assert.StartsWith("Merged by ILRepack from 3", Entry(r, "Repacked.dll").Merged);
        Assert.Null(Entry(r, "TestFixture.dll").Merged);
    }

    // ------------------------------------------------------------------ list_assemblies on a container (service)

    private UnpackService.ContainerListing List(string path) => Unpacker.List(path, AnalysisLimits.Default, default);

    [Fact]
    public void List_SingleFileBundle()
    {
        var l = List(fx.Bundle);
        Assert.Equal(".NET single-file bundle", l.Container);
        var hello = Assert.Single(l.Assemblies);
        Assert.Equal("Hello.dll", hello.Path);
        Assert.StartsWith("Hello, Version=", hello.Name);
        Assert.Equal(Sha(fx.HelloDll), hello.Sha256);
        Assert.False(hello.ReadyToRun);
        Assert.Empty(_workspace.Assemblies); // listing loads nothing

        Assert.True(Assert.Single(List(fx.ReadyToRunBundle).Assemblies).ReadyToRun);
    }

    [Fact]
    public void List_NuGetPackage()
    {
        var l = List(ContainerFixtures.NuGetPackage("dnlib"));
        Assert.Equal("NuGet package", l.Container);
        Assert.NotEmpty(l.Assemblies);
        Assert.All(l.Assemblies, a => Assert.StartsWith("dnlib, Version=", a.Name));
        Assert.All(l.Assemblies, a => Assert.Matches(@"^lib/[^/]+/dnlib\.dll$", a.Path));
    }

    [Fact]
    public void List_ApkStyleZip()
    {
        var l = List(Save("app.apk", BuildApk().Apk));
        Assert.Equal("Android package (Xamarin / MAUI)", l.Container);
        Assert.Equal(["StoreRaw", "StoreXalz", "TestFixture", "TestFixture.Consumer"], l.Assemblies.Select(a => a.Name!.Split(',')[0]).Order());
        Assert.Contains(l.Assemblies, a => a.Path == "assemblies/TestFixture.dll" && a.Origin.Contains("XALZ"));
    }

    [Fact]
    public void List_NestedAndCosturaAndMerged()
    {
        var host = ContainerFixtures.Module("CosturaHost", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(System.IO.File.ReadAllBytes(Env.FixturePath))));
        var l = List(Save("outer.zip", ContainerFixtures.Zip(("app/CosturaHost.exe", host), ("Repacked.dll", Repacked()))));
        Assert.Equal("zip archive", l.Container);
        Assert.Contains(l.Assemblies, a => a.Path == "app/CosturaHost.exe.bin" && a.Name!.StartsWith("CosturaHost,"));
        Assert.Contains(l.Assemblies, a => a.Path == "app/CosturaHost.exe_unpacked/testfixture.dll" && a.Name!.StartsWith("TestFixture,"));
        Assert.StartsWith("Merged by ILRepack", Assert.Single(l.Assemblies, a => a.Path == "Repacked.dll").Merged);
    }

    [Fact]
    public void List_PlainAssemblyListsItself_AndNonAssemblyListsNothing()
    {
        var l = List(Env.FixturePath);
        Assert.Equal("none (plain .NET assembly)", l.Container);
        var self = Assert.Single(l.Assemblies);
        Assert.Equal("TestFixture.dll", self.Path);
        Assert.Equal("the file itself", self.Origin);
        Assert.Empty(l.Notes);

        var text = List(Save("notes.txt", "just text"u8.ToArray()));
        Assert.Equal("none", text.Container);
        Assert.Empty(text.Assemblies);
        Assert.NotEmpty(text.Notes);
    }

    [Fact]
    public void List_CorruptContainers_GiveAClearError()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        Assert.Contains("corrupt zip", Assert.Throws<ToolError>(() => List(Save("cut.nupkg", nupkg[..(nupkg.Length / 2)]))).Message);

        var bundle = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bundle, bundle.Length - 6);
        Assert.Contains("Corrupt single-file bundle", Assert.Throws<ToolError>(() => List(Save("bad.exe", bundle))).Message);

        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => List(Save("bad.dll", [.. "XALZ"u8, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3]))).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => List(_dir.File("missing.apk"))).Message);
    }

    // ------------------------------------------------------------------ list_assemblies over MCP

    private static JsonElement Prop(JsonElement e, string name) =>
        e.EnumerateObject().First(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static bool Has(JsonElement e, string name) =>
        e.EnumerateObject().Any(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static JsonElement Structured(CallToolResult r) => JsonDocument.Parse(r.StructuredContent!.ToString()!).RootElement;

    [Fact]
    public async Task ListAssembliesTool_ReportsReadyToRunMergedAndContainers()
    {
        var merged = Save("IlMerged.dll", IlMerged());
        await using var client = await McpProtocolTests.StartServerAsync("--no-index", "--load", fx.ReadyToRunDll, "--load", Env.FixturePath, "--load", merged);

        // no path: the workspace, as before, with readyToRun / merged per assembly and no container section
        var state = Structured(await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>()));
        Assert.False(Has(state, "container"));
        var byId = Prop(state, "assemblies").EnumerateArray().ToDictionary(a => Prop(a, "id").GetString()!);
        Assert.True(Prop(byId["Hello"], "readyToRun").GetBoolean());
        Assert.False(Prop(byId["TestFixture"], "readyToRun").GetBoolean());
        Assert.False(Has(byId["TestFixture"], "merged"));
        Assert.StartsWith("Merged assembly (ILMerge-style)", Prop(byId["IlMerged"], "merged").GetString());

        // a container path: its managed assemblies, nothing loaded
        var withBundle = Structured(await client.CallToolAsync("list_assemblies", new Dictionary<string, object?> { ["path"] = fx.Bundle }));
        var container = Prop(withBundle, "container");
        Assert.Equal(".NET single-file bundle", Prop(container, "container").GetString());
        var hello = Assert.Single(Prop(container, "assemblies").EnumerateArray());
        Assert.Equal("Hello.dll", Prop(hello, "path").GetString());
        Assert.False(Prop(hello, "readyToRun").GetBoolean());
        Assert.Equal(3, Prop(withBundle, "assemblies").GetArrayLength());

        // a corrupt container: a tool error with the reason, and the server keeps serving
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var bad = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?> { ["path"] = Save("cut.nupkg", nupkg[..(nupkg.Length / 2)]) });
        Assert.True(bad.IsError);
        Assert.Contains("corrupt zip", string.Join("\n", bad.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        var after = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
        Assert.NotEqual(true, after.IsError);
    }
}
