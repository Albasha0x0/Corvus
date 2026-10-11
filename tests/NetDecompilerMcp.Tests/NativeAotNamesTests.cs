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
        Assert.Equal($"Sample_Zoo_Dog__MT_{w.Speaker:X}_slot1", n[T.SealedCode]);
        Assert.Equal($"Sample.Zoo.Dog implementation of MT_{w.Speaker:X} slot 1, vtable slot 3", built.Comments[T.SealedCode]);
        Assert.Equal([T.SpeakCode, T.ToStringCode, T.EqualsCode, T.HashCode, T.SealedCode], built.FunctionStarts);
        Assert.Equal((1, 3, 1, 7, 1, 1), (built.Report.Functions, built.Report.VtableSlots, built.Report.InterfaceSlots, built.Report.MethodTables, built.Report.FrozenStrings, built.Report.FrozenObjects));
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
        byte[] body =
        [
            0x48, 0x8B, 0xD9,             // mov rbx, rcx         this kept in rbx
            0x48, 0x8D, 0x0D, 0, 0, 0, 0, // lea rcx, [rip+"hi"]
            0x48, 0x8B, 0x03,             // mov rax, [rbx]       this's MethodTable
            0xFF, 0x50, 0x18,             // call [rax+18h]       slot 0
            0x48, 0x8B, 0x02,             // mov rax, [rdx]       a MethodTable of an unknown type
            0xFF, 0x50, 0x20,             // call [rax+20h]       slot 1
            0x48, 0x8B, 0x03,             // mov rax, [rbx]
            0x48, 0x8B, 0x40, 0x20,       // mov rax, [rax+20h]   slot 1 into rax
            0xFF, 0x15, 0, 0, 0, 0,       // call [rip+fptr]      a CFG dispatch call on rax
            0xC3,
        ];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(6), (int)(w.Text + 8 - (T.SpeakCode + 10)));
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(31), (int)(w.Object - (T.SpeakCode + 35)));
        body.CopyTo(bytes, at);
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

    [Fact]
    public async Task GetNativeAotInfo_Views()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NetDecompilerMcp.Tools.NativeTools(env.Workspace, new OutputPager(env.Options), code);
        var (path, w) = WriteImage(dir);
        var native = env.Workspace.LoadAny(path).Native!;
        await code.Index(native, null, default);

        var summary = await tools.GetNativeAotInfo(native.Id);
        output.WriteLine(summary);
        Assert.Contains("NativeAOT, .NET 10, ReadyToRun 16.0", summary);
        Assert.Contains("method tables: complete", summary);
        Assert.Contains("nativeaot name layer:", summary);
        Assert.Contains("list_functions: 5 of 6 functions carry a nativeaot name", summary);

        Assert.Contains("FrozenObjectRegion  [section]", await tools.GetNativeAotInfo(native.Id, "sections"));
        var types = await tools.GetNativeAotInfo(native.Id, "types", "zoo.dog");
        Assert.Contains("Sample.Zoo.Dog  [class]  name from vtable, base System.Object, 3 slots, 1 interfaces", types);
        Assert.Contains("Sample.Zoo.Dog[]  [array]  name from element, element Sample.Zoo.Dog", types);

        var obj = await tools.GetNativeAotInfo(native.Id, "type", "MT_System_Object");
        output.WriteLine(obj);
        Assert.Contains("[1] 0x140001070 System_Object__vslot1", obj);
        var dog = await tools.GetNativeAotInfo(native.Id, "type", $"0x{w.Dog:X}");
        Assert.Contains("base chain: System.Object", dog);
        Assert.Contains("[0] 0x140001010 Sample_Zoo_Dog__Speak", dog);
        Assert.Contains("[2] 0x140001080 System_Object__vslot2  (inherited)", dog);
        Assert.Contains($"interfaces (1): MT_{w.Speaker:X}", dog);
        Assert.Contains("interface methods implemented here (2, from the dispatch map):", dog);
        Assert.Contains($"MT_{w.Speaker:X} slot 1 -> [3, sealed] 0x140001090 Sample_Zoo_Dog__MT_{w.Speaker:X}_slot1", dog);

        Assert.Contains("Sample.Zoo.Dog::Speak", await tools.GetNativeAotInfo(native.Id, "methods", "speak"));
        Assert.Contains("hi  [string]  1 refs", await tools.GetNativeAotInfo(native.Id, "strings", "h"));

        var bad = await Assert.ThrowsAsync<ToolError>(() => tools.GetNativeAotInfo(native.Id, "nope"));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => tools.GetNativeAotInfo(native.Id, "type", "No.Such"))).Code);
        var plain = dir.File("plain.dll");
        File.WriteAllBytes(plain, new NativeAotBuilder().Build());
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => tools.GetNativeAotInfo(plain))).Code);
    }

    [Fact]
    public async Task Disassemble_RendersStringLiteralsAndVirtualCalls()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NetDecompilerMcp.Tools.NativeCodeTools(env.Workspace, code, new OutputPager(env.Options));
        var (path, _) = WriteImage(dir);
        var text = await tools.Disassemble(path, "Sample_Zoo_Dog__Speak");
        output.WriteLine(text);
        Assert.Contains("lea    rcx, [str_0]  ; \"hi\"\n", text.Replace("\r\n", "\n"));
        Assert.Contains("; virtual Sample.Zoo.Dog slot 0: Sample_Zoo_Dog__Speak (or an override)", text);
        Assert.Contains("; virtual call, vtable slot 1: System_Object__vslot1 or an override", text);
        Assert.Contains("; virtual Sample.Zoo.Dog slot 1: System_Object__vslot1 (or an override)", text);
    }

    [Fact]
    public async Task ResolveAddress_DescribesMethodTablesFrozenObjectsMethodsAndSections()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var code = new NativeCodeService(env.Workspace, env.Options, null, new AnnotationStore(dir.File("ann")));
        var tools = new NetDecompilerMcp.Tools.NativeTools(env.Workspace, new OutputPager(env.Options), code);
        var (path, w) = WriteImage(dir);
        var native = env.Workspace.LoadAny(path).Native!;
        await code.Index(native, null, default);
        string Hex(uint rva) => $"0x{rva:X}";

        var mt = await tools.ResolveAddress(native.Id, Hex(w.Dog));
        Assert.Contains("name MT_Sample_Zoo_Dog (nativeaot)", mt);
        Assert.Contains("NativeAOT MethodTable of Sample.Zoo.Dog (class, name from vtable)", mt);
        Assert.Contains("NativeAOT frozen String \"hi\"", await tools.ResolveAddress(native.Id, "str_0"));
        Assert.True(w.Aot.Names.MethodAt[T.SpeakCode].Name.HasThis);
        Assert.Contains($"inside the NativeAOT frozen String \"hi\" at rva {Hex(w.Text + 8)} (+0x4)", await tools.ResolveAddress(native.Id, Hex(w.Text + 12)));
        Assert.Contains("inside the NativeAOT frozen Sample.Zoo.Dog (32 bytes)", await tools.ResolveAddress(native.Id, Hex(w.Frozen)));
        Assert.Contains("NativeAOT method Sample.Zoo.Dog::Speak", await tools.ResolveAddress(native.Id, "Sample_Zoo_Dog__Speak"));
        Assert.Contains("NativeAOT module header, ReadyToRun 16.0", await tools.ResolveAddress(native.Id, "__ReadyToRunHeader"));
        Assert.Contains("in NativeAOT module section EmbeddedMetadata (+0x4)",
            await tools.ResolveAddress(native.Id, Hex(w.Aot.Header.Blob(Native.NativeAot.BlobId.EmbeddedMetadata)!.StartRva + 4)));
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
        // Disassembly comments over every named function: string literal loads and virtual calls (x64).
        int literals = 0, typed = 0, untyped = 0;
        foreach (var f in index.Functions.Where(f => index.Sourced.NameAt(f.Start) is { Source: NativeNameSource.NativeAot }))
            foreach (var c in NativeAotCode.Comments(native, index, f).Values)
                if (c.StartsWith('"')) literals++;
                else if (c.StartsWith("virtual call", StringComparison.Ordinal)) untyped++;
                else typed++;
        output.WriteLine($"  disassembly comments: {literals} string literals, {typed} virtual calls on this, {untyped} other virtual calls");
        if (native.Image.Arch == NetDecompilerMcp.Native.NativeArch.X64) Assert.True(literals > 1000 && typed > 100 && untyped > 1000);

        var strings = NativeAotNames.View(native)!.Frozen.Objects.Where(o => o.Text != null).ToList();
        int referenced = strings.Count(o => index.CountRefsTo(o.Rva) > 0);
        output.WriteLine($"  {referenced} of {strings.Count} frozen strings referenced by code");
        if (sample.StartsWith("win-x64", StringComparison.Ordinal)) // the ARM64 index records no adrp/add data references yet
            Assert.True(referenced > strings.Count / 2, $"{referenced} of {strings.Count} frozen strings referenced");
    }
}
