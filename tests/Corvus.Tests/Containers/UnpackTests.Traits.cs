using System.Text.Json;
using dnlib.DotNet;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>ReadyToRun status, merged-assembly labels, and list_assemblies on container files.</summary>
public partial class UnpackTests
{
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

    /// <summary>ILMerge renames of clashing types: "Input.Name" for compiler-generated, "Input&lt;key&gt;.Name" otherwise.</summary>
    private static byte[] IlMerged() => ContainerFixtures.Module("IlMerged", m =>
    {
        AddType(m, "", "<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "LibB.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "Contoso.Utils.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "", "Lib2.<PrivateImplementationDetails>", compilerGenerated: true);
        AddType(m, "App.Internal", "Helper");
        AddType(m, "App.Internal", "LibB7.Helper");
        AddType(m, "App.Internal", "Contoso.Utils12.Helper");
        // "Lib2" + key 27, not "Lib" + key 227.
        AddType(m, "App.Internal", "Lib227.Helper");
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

    [Trait("Speed", "Slow")]
    [Fact]
    public void ReadyToRun_detected_on_crossgen_output_not_on_IL_only_assemblies()
    {
        Assert.True(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(fx.ReadyToRunDll)));
        Assert.True(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(typeof(object).Assembly.Location))); // the shared framework ships R2R
        Assert.False(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(fx.HelloDll))); // same app, plain build
        Assert.False(AssemblyTraits.IsReadyToRun(System.IO.File.ReadAllBytes(Env.FixturePath)));
        Assert.False(AssemblyTraits.IsReadyToRun("not a PE file"u8));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Unpack_container_reports_ReadyToRun_per_assembly()
    {
        var r2r = Unpack(fx.ReadyToRunBundle);
        Assert.True(Entry(r2r, "Hello.dll").ReadyToRun);
        // Not an assembly.
        Assert.Null(Entry(r2r, "Hello.deps.json").ReadyToRun);

        var plain = Unpack(fx.Bundle);
        Assert.False(Entry(plain, "Hello.dll").ReadyToRun);
    }

    [Fact]
    public void ILMerge_renames_are_labelled_with_the_recovered_inputs()
    {
        Assert.Equal("Merged assembly (ILMerge-style): at least 4 original modules (renamed types from Contoso.Utils, Lib2, LibB).", MergeNote(IlMerged()));
    }

    [Fact]
    public void ILRepack_list_gives_the_exact_inputs()
    {
        Assert.Equal("Merged by ILRepack from 3 assemblies: LibA, LibB, Repacked.", MergeNote(Repacked()));
        var corrupt = ContainerFixtures.Module("BadList", ("ILRepack.List", [0x00, 0x01, 0x02]));
        Assert.Equal("Merged by ILRepack; its ILRepack.List resource is unreadable.", MergeNote(corrupt));
    }

    [Fact]
    public void Old_compiler_helper_classes_from_several_modules_are_labelled()
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
    public void Unmerged_assemblies_are_not_labelled()
    {
        Assert.Null(MergeNote(System.IO.File.ReadAllBytes(Env.FixturePath)));
        // A dotted type name alone is not enough; the undotted original must exist too.
        Assert.Null(MergeNote(ContainerFixtures.Module("Odd", m => AddType(m, "Ns", "Weird.Name"))));
        // False-positive guard over the shared framework.
        var framework = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        var labelled = Directory.EnumerateFiles(framework, "*.dll")
            .Where(f => Blob.Identify(System.IO.File.ReadAllBytes(f)) == ".NET assembly")
            .Select(f => (File: Path.GetFileName(f), Note: MergeNote(System.IO.File.ReadAllBytes(f))))
            .Where(x => x.Note != null).ToList();
        Assert.True(labelled.Count == 0, string.Join("\n", labelled));
    }

    [Fact]
    public void Unpack_container_labels_merged_assemblies()
    {
        var zip = ContainerFixtures.Zip(("IlMerged.dll", IlMerged()), ("Repacked.dll", Repacked()), ("TestFixture.dll", System.IO.File.ReadAllBytes(Env.FixturePath)));
        var r = Unpack(Save("merged.zip", zip));
        Assert.StartsWith("Merged assembly (ILMerge-style): at least 4", Entry(r, "IlMerged.dll").Merged);
        Assert.StartsWith("Merged by ILRepack from 3", Entry(r, "Repacked.dll").Merged);
        Assert.Null(Entry(r, "TestFixture.dll").Merged);
    }

    private UnpackService.ContainerListing List(string path) => Unpacker.List(path, AnalysisLimits.Default, default);

    [Trait("Speed", "Slow")]
    [Fact]
    public void List_names_the_assembly_of_a_single_file_bundle_without_loading_it()
    {
        var l = List(fx.Bundle);
        Assert.Equal(".NET single-file bundle", l.Container);
        var hello = Assert.Single(l.Assemblies);
        Assert.Equal("Hello.dll", hello.Path);
        Assert.StartsWith("Hello, Version=", hello.Name);
        Assert.Equal(Sha(fx.HelloDll), hello.Sha256);
        Assert.False(hello.ReadyToRun);
        // Listing loads nothing.
        Assert.Empty(_workspace.Assemblies);

        Assert.True(Assert.Single(List(fx.ReadyToRunBundle).Assemblies).ReadyToRun);
    }

    [Fact]
    public void List_names_each_target_framework_copy_of_a_NuGet_package()
    {
        var l = List(ContainerFixtures.NuGetPackage("dnlib"));
        Assert.Equal("NuGet package", l.Container);
        Assert.NotEmpty(l.Assemblies);
        Assert.All(l.Assemblies, a => Assert.StartsWith("dnlib, Version=", a.Name));
        Assert.All(l.Assemblies, a => Assert.Matches(@"^lib/[^/]+/dnlib\.dll$", a.Path));
    }

    [Fact]
    public void List_names_the_assemblies_of_an_APK_with_their_origin()
    {
        var l = List(Save("app.apk", BuildApk().Apk));
        Assert.Equal("Android package (Xamarin / MAUI)", l.Container);
        Assert.Equal(["StoreRaw", "StoreXalz", "TestFixture", "TestFixture.Consumer"], l.Assemblies.Select(a => a.Name!.Split(',')[0]).Order());
        Assert.Contains(l.Assemblies, a => a.Path == "assemblies/TestFixture.dll" && a.Origin.Contains("XALZ"));
    }

    [Fact]
    public void List_names_nested_Costura_and_merged_assemblies()
    {
        var host = ContainerFixtures.Module("CosturaHost", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(System.IO.File.ReadAllBytes(Env.FixturePath))));
        var l = List(Save("outer.zip", ContainerFixtures.Zip(("app/CosturaHost.exe", host), ("Repacked.dll", Repacked()))));
        Assert.Equal("zip archive", l.Container);
        Assert.Contains(l.Assemblies, a => a.Path == "app/CosturaHost.exe.bin" && a.Name!.StartsWith("CosturaHost,"));
        Assert.Contains(l.Assemblies, a => a.Path == "app/CosturaHost.exe_unpacked/testfixture.dll" && a.Name!.StartsWith("TestFixture,"));
        Assert.StartsWith("Merged by ILRepack", Assert.Single(l.Assemblies, a => a.Path == "Repacked.dll").Merged);
    }

    [Fact]
    public void List_plain_assembly_lists_itself_and_non_assembly_lists_nothing()
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
    public void List_corrupt_containers_give_a_clear_error()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        Assert.Contains("corrupt zip", Assert.Throws<ToolError>(() => List(Save("cut.nupkg", nupkg[..20]))).Message);
        // Cut halfway: earlier entries are recovered from local headers.
        var half = List(Save("half.nupkg", nupkg[..(nupkg.Length / 2)]));
        Assert.Contains(half.Notes, n => n.StartsWith("Damaged zip"));

        var bundle = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bundle, bundle.Length - 6);
        Assert.Contains("Corrupt single-file bundle", Assert.Throws<ToolError>(() => List(Save("bad.exe", bundle))).Message);

        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => List(Save("bad.dll", [.. "XALZ"u8, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3]))).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => List(_dir.File("missing.apk"))).Message);
    }

    private static JsonElement Prop(JsonElement e, string name) =>
        e.EnumerateObject().First(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static bool Has(JsonElement e, string name) =>
        e.EnumerateObject().Any(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static JsonElement Structured(CallToolResult r) => JsonDocument.Parse(r.StructuredContent!.ToString()!).RootElement;

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task List_assemblies_tool_reports_ReadyToRun_merged_and_containers()
    {
        var merged = Save("IlMerged.dll", IlMerged());
        await using var client = await McpProtocolTests.StartServerAsync("--no-index", "--load", fx.ReadyToRunDll, "--load", Env.FixturePath, "--load", merged);

        // No path: the workspace, without a container (nulls are omitted).
        var stateResult = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
        await McpProtocolTests.AssertMatchesOutputSchema(client, "list_assemblies", stateResult);
        var state = Structured(stateResult);
        Assert.False(state.TryGetProperty("container", out _));
        var byId = Prop(state, "items").EnumerateArray().ToDictionary(a => Prop(a, "id").GetString()!);
        Assert.True(Prop(byId["Hello"], "readyToRun").GetBoolean());
        Assert.False(Has(byId["TestFixture"], "readyToRun"));
        Assert.False(byId["TestFixture"].TryGetProperty("merged", out _));
        Assert.StartsWith("Merged assembly (ILMerge-style)", Prop(byId["IlMerged"], "merged").GetString());

        // A container path lists its assemblies without loading them.
        var bundleResult = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?> { ["path"] = fx.Bundle });
        await McpProtocolTests.AssertMatchesOutputSchema(client, "list_assemblies", bundleResult);
        var withBundle = Structured(bundleResult);
        var container = Prop(withBundle, "container");
        Assert.Equal(".NET single-file bundle", Prop(container, "container").GetString());
        // With path, the rows are the container's.
        var hello = Assert.Single(Prop(withBundle, "items").EnumerateArray());
        Assert.Equal(("contained", "Hello.dll"), (Prop(hello, "kind").GetString(), Prop(hello, "path").GetString()));
        Assert.False(Has(hello, "readyToRun"));
        Assert.Equal(1, Prop(withBundle, "total").GetInt32());

        // A corrupt container gives a tool error; the server keeps serving.
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var bad = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?> { ["path"] = Save("cut.nupkg", nupkg[..20]) });
        Assert.True(bad.IsError);
        Assert.Contains("corrupt zip", string.Join("\n", bad.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        var after = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
        Assert.NotEqual(true, after.IsError);
    }
}
