using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;
using Xunit.Abstractions;
using T = NetDecompilerMcp.Tests.NativeAotTypeTests;

namespace NetDecompilerMcp.Tests;

/// <summary>The nativeaot name layer: priority among the sources, contents, auto-apply on index build, save and restore.</summary>
public class NativeAotNamesTests(ITestOutputHelper output)
{
    [Fact]
    public void Priority_NativeAotBelowPdbAboveIl2Cpp()
    {
        var names = new SourcedNames();
        names.SetName(0x10, "ida", NativeNameSource.Ida);
        names.SetName(0x10, "il2cpp", NativeNameSource.Il2Cpp);
        names.SetName(0x10, "aot", NativeNameSource.NativeAot);
        Assert.Equal(("aot", NativeNameSource.NativeAot), names.NameAt(0x10));
        names.SetName(0x10, "pdb", NativeNameSource.Pdb);
        Assert.Equal(("pdb", NativeNameSource.Pdb), names.NameAt(0x10));
        names.SetName(0x10, "mine", NativeNameSource.User);
        Assert.Equal(("mine", NativeNameSource.User), names.NameAt(0x10));
        names.SetComment(0x20, "il2cpp", NativeNameSource.Il2Cpp);
        names.SetComment(0x20, "aot", NativeNameSource.NativeAot);
        Assert.Equal(("aot", NativeNameSource.NativeAot), names.CommentAt(0x20));
        Assert.Equal([(0x10u, NativeNameSource.User)], names.AddressesOf("mine"));

        var layers = new NativeNameLayers();
        foreach (var source in new[] { NativeNameSource.Ida, NativeNameSource.NativeAot, NativeNameSource.Pdb, NativeNameSource.Il2Cpp })
            layers.Set(new NativeNameLayers.Layer(source, new Dictionary<uint, string>(), new Dictionary<uint, string>(), "x"), null);
        Assert.Equal([NativeNameSource.Pdb, NativeNameSource.NativeAot, NativeNameSource.Il2Cpp, NativeNameSource.Ida], layers.Layers.Select(l => l.Source));
        Assert.Equal(NativeNameSource.NativeAot, NativeNameSources.Parse("nativeaot"));
        Assert.Equal("nativeaot", NativeNameSource.NativeAot.Id());
    }

    /// <summary>The engine name push takes the nativeaot layer over il2cpp names and leaves addresses the PDB names to the engine.</summary>
    [Fact]
    public void Push_IncludesTheNativeAotLayer()
    {
        var image = T.Build(16).Aot.Image;
        NativeNameLayers.Layer L(NativeNameSource s, params (uint, string)[] names) =>
            new(s, names.ToDictionary(n => n.Item1, n => n.Item2), new Dictionary<uint, string> { [T.SpeakCode] = s.Id() }, s.Id());
        var layers = new NativeNameLayers();
        layers.Set(L(NativeNameSource.Il2Cpp, (T.SpeakCode, "low"), (T.HashCode, "il2cpp")), null);
        layers.Set(L(NativeNameSource.NativeAot, (T.SpeakCode, "Dog__Speak"), (T.EqualsCode, "Object__Equals")), null);
        layers.Set(L(NativeNameSource.Pdb, (T.EqualsCode, "pdb")), null);
        var effective = NativeNamePush.Effective(null, layers.Layers, image);
        Assert.Equal(new NativeNamePush.Entry("Dog__Speak", "nativeaot", true), effective[T.SpeakCode]);
        Assert.Equal("il2cpp", effective[T.HashCode].Name);
        Assert.False(effective.ContainsKey(T.EqualsCode));
    }

    [Fact]
    public void SavedLayer_RoundTripsTheNativeAotSource()
    {
        using var dir = new TempDir();
        var store = new AnnotationStore(dir.File("ann"));
        var layer = new NativeNameLayers.Layer(NativeNameSource.NativeAot, new Dictionary<uint, string> { [0x1010] = "A__B" }, new Dictionary<uint, string> { [0x1010] = "A::B()" },
            "NativeAOT metadata (.NET 10)", new ImportInfo(@"C:\x\app.exe", NativeAotNames.ReaderIdentity, DateTime.UtcNow, [0x1010]));
        Assert.Null(store.SaveLayer("cd34", @"C:\x\app.exe", layer));
        var back = store.LoadLayer("cd34", NativeNameSource.NativeAot)!;
        Assert.Equal(NativeNameSource.NativeAot, back.Source);
        Assert.Equal(layer.Names, back.Names);
        Assert.Equal(NativeAotNames.ReaderIdentity, back.Info!.SourceIdentity);
        Assert.EndsWith(".nativeaot.names", store.LayerFileFor("cd34", NativeNameSource.NativeAot), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData((ushort)9)]
    [InlineData((ushort)16)]
    public void Build_NamesBodiesSlotsMethodTablesAndFrozenObjects(ushort major)
    {
        var w = T.Build(major);
        var built = NativeAotNames.Build(w.Aot);
        var n = built.Names;
        Assert.Equal("Sample_Zoo_Dog__Speak", n[T.SpeakCode]);
        Assert.StartsWith("Sample.Zoo.Dog::Speak", built.Comments[T.SpeakCode], StringComparison.Ordinal);
        // System.Object introduces three unnamed slots; Dog overrides slot 0 with a named body and inherits the others.
        Assert.Equal(["System_Object__vslot0", "System_Object__vslot1", "System_Object__vslot2"], new[] { n[T.ToStringCode], n[T.EqualsCode], n[T.HashCode] });
        Assert.Equal("virtual slot 1 of System.Object", built.Comments[T.EqualsCode]);
        Assert.Equal("MT_System_Object", n[w.Object]);
        Assert.Equal("MT_Sample_Zoo_Box_Sample_Zoo_Dog", n[w.BoxOfDog]);
        Assert.Equal($"MT_{w.Speaker:X}", n[w.Speaker]);
        Assert.Contains("name from composition", built.Comments[w.BoxOfDog]);
        Assert.Equal(("str_0", "\"hi\""), (n[w.Text + 8], built.Comments[w.Text + 8]));
        Assert.Equal("frozen_0", n[w.Frozen + 8]);
        Assert.Equal("__ReadyToRunHeader", n[w.Aot.Header.Rva]);
        Assert.Equal([T.SpeakCode, T.ToStringCode, T.EqualsCode, T.HashCode], built.FunctionStarts);
        Assert.Equal((1, 3, 7, 1, 1), (built.Report.Functions, built.Report.VtableSlots, built.Report.MethodTables, built.Report.FrozenStrings, built.Report.FrozenObjects));
        Assert.Equal(n.Count, n.Values.Distinct().Count());
    }

    /// <summary>The index build names the image without a tool call; the layer is saved and a later load restores it instead of rebuilding.</summary>
    [Fact]
    public async Task AutoApply_OnIndexBuild_SavedAndRestored()
    {
        using var dir = new TempDir();
        var (path, _) = WriteImage(dir);
        var store = dir.File("ann");

        using (var env = new Env())
        {
            var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(store));
            var native = env.Workspace.LoadAny(path).Native!;
            var index = await code.Index(native, null, default);
            Assert.Equal(("Sample_Zoo_Dog__Speak", NativeNameSource.NativeAot), index.Sourced.NameAt(T.SpeakCode));
            Assert.NotNull(index.FunctionByStart(T.SpeakCode));
            var layer = NativeNameLayers.Of(native).Get(NativeNameSource.NativeAot)!;
            Assert.False(layer.Info!.Restored);
            Assert.Contains(".NET 10", layer.Origin);
        }
        using (var env = new Env())
        {
            var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(store));
            var native = env.Workspace.LoadAny(path).Native!;
            var index = await code.Index(native, null, default);
            Assert.True(NativeNameLayers.Of(native).Get(NativeNameSource.NativeAot)!.Info!.Restored);
            Assert.Equal("Sample_Zoo_Dog__Speak", index.Sourced.NameAt(T.SpeakCode)?.Name);
            Assert.NotNull(index.FunctionByStart(T.SpeakCode));
        }
    }

    [Fact]
    public async Task AutoApply_NotForOtherImages()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var path = dir.File("plain.dll");
        File.WriteAllBytes(path, new NativeAotBuilder().Build()); // a header without rows is no module header
        var native = env.Workspace.LoadAny(path).Native!;
        await code.Index(native, null, default);
        Assert.Null(NativeNameLayers.Of(native).Get(NativeNameSource.NativeAot));
        Assert.Null(NativeAotNames.View(native));
    }

    /// <summary>The synthetic image with Dog::Speak loading the frozen string "hi" (lea rcx, [rip+string]; ret), written to <paramref name="dir"/>.</summary>
    internal static (string Path, T.World World) WriteImage(TempDir dir, string name = "app.exe")
    {
        var w = T.Build(16);
        var pe = (PeFile)w.Aot.Image;
        var bytes = pe.FileBytes.ToArray();
        Assert.True(pe.TryRvaToFileOffset(T.SpeakCode, out long at));
        byte[] lea = [0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(lea.AsSpan(3), (int)(w.Text + 8 - (T.SpeakCode + 7)));
        lea.CopyTo(bytes, at);
        var path = dir.File(name);
        File.WriteAllBytes(path, bytes);
        return (path, w);
    }

    [Fact]
    public async Task SearchNativeStrings_ListsFrozenStringsByTheObject()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NetDecompilerMcp.Tools.NativeCodeTools(env.Workspace, code, new OutputPager(env.Options));
        var (path, _) = WriteImage(dir);
        var text = await tools.SearchNativeStrings(path, "hi");
        output.WriteLine(text);
        Assert.Contains("nativeaot \"hi\"  str_0, 1 refs, first in Sample_Zoo_Dog__Speak", text);
        Assert.DoesNotContain("L\"hi\"", text);
    }

    /// <summary>The production ilc binaries: most functions named right after load; logged as named / all index functions and / .pdata starts.</summary>
    [Theory]
    [Trait("Speed", "Slow")]
    [MemberData(nameof(NativeAotRealTests.Samples), MemberType = typeof(NativeAotRealTests))]
    public async Task Real_LoadNamesMostFunctions(string sample)
    {
        using var dir = new TempDir();
        using var env = new Env();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var native = env.Workspace.LoadAny(NativeAotRealTests.PathOf(sample)).Native!;
        var watch = Stopwatch.StartNew();
        var index = await code.Index(native, null, default);
        int named = index.Functions.Count(f => index.Sourced.NameAt(f.Start) is { Source: NativeNameSource.NativeAot });
        var pdata = native.Image.RuntimeFunctions.Select(f => f.BeginRva).ToHashSet();
        int pdataNamed = pdata.Count(r => index.Sourced.NameAt(r) is { Source: NativeNameSource.NativeAot });
        output.WriteLine($"{sample}: {named} of {index.Functions.Count} functions named ({100.0 * named / index.Functions.Count:0.0} %), " +
                         $"{pdataNamed} of {pdata.Count} .pdata starts ({100.0 * pdataNamed / pdata.Count:0.0} %) in {watch.Elapsed.TotalSeconds:0.0} s");
        Assert.True(pdataNamed > 0.75 * pdata.Count, $"{pdataNamed} of {pdata.Count}");
        Assert.Contains(index.Sourced.AddressesOf("ILCompiler_Program__Main"), a => a.Source == NativeNameSource.NativeAot);
        Assert.NotEmpty(index.Sourced.AddressesOf("MT_System_String"));
        var strings = NativeAotNames.View(native)!.Frozen.Objects.Where(o => o.Text != null).ToList();
        int referenced = strings.Count(o => index.CountRefsTo(o.Rva) > 0);
        output.WriteLine($"  {referenced} of {strings.Count} frozen strings referenced by code");
        if (sample.StartsWith("win-x64", StringComparison.Ordinal)) // the ARM64 index records no adrp/add data references yet
            Assert.True(referenced > strings.Count / 2, $"{referenced} of {strings.Count} frozen strings referenced");
    }
}
