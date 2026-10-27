using Corvus.Core;
using Corvus.Native.NativeAot;
using Corvus.Native;

namespace Corvus.Tests;

/// <summary>NativeAOT recovery on the ILCompiler packs' own tools/ilc (.NET 8, 9, 10; x64, ARM64, x86, ARM); restored only with CORVUS_ALL_TESTS=1.</summary>
[Trait("Speed", "Slow")]
public class NativeAotRealTests
{
    public sealed record Sample(string Rid, string Version, string ReadyToRun, string Runtime, int DebugHeader, bool Dehydrated)
    {
        public override string ToString() => $"{Rid} {Version}";
        public bool IsPe => Rid.StartsWith("win-", StringComparison.Ordinal);
        public string Path => RealPackages.File($"runtime.{Rid}.Microsoft.DotNet.ILCompiler", Version, "tools", IsPe ? "ilc.exe" : "ilc");
    }

    private static readonly Sample[] All =
    [
        new("win-x64", "8.0.30", "9.1", ".NET 8", 3, true),
        new("win-x64", "9.0.19", "10.1", ".NET 9", 4, true),
        new("win-x64", "10.0.11", "16.0", ".NET 10", 5, false),
        new("win-arm64", "10.0.11", "16.0", ".NET 10", 5, false),
        new("win-x86", "10.0.11", "16.0", ".NET 10", 5, false),
        new("linux-arm", "10.0.11", "16.0", ".NET 10", 5, true),
        new("linux-x64", "10.0.11", "16.0", ".NET 10", 5, true),
        new("linux-arm64", "10.0.11", "16.0", ".NET 10", 5, true),
        new("osx-arm64", "10.0.11", "16.0", ".NET 10", 5, true),
    ];

    public static readonly TheoryData<string> Samples = new(All.Select(s => s.ToString()));

    private static readonly Dictionary<string, NativeAotImage> Opened = [];

    public static string PathOf(string name) => All.Single(x => x.ToString() == name).Path;

    private static (Sample, NativeAotImage) Open(string name)
    {
        var s = All.Single(x => x.ToString() == name);
        lock (Opened)
        {
            if (!Opened.TryGetValue(name, out var aot))
                Opened[name] = aot = NativeAotImage.Open(NativeImageLoader.Open(s.Path)) ?? throw new InvalidOperationException($"{s}: no NativeAOT header");
            return (s, aot);
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void The_header_gives_the_version_and_sections(string sample)
    {
        var (s, aot) = Open(sample);
        Assert.Single(aot.Headers);
        Assert.True(aot.Header.Relocated);
        Assert.Equal(s.ReadyToRun, aot.ReadyToRunVersion);
        Assert.Equal(s.Runtime, aot.Runtime);
        Assert.Equal(s.DebugHeader, aot.DebugHeaderMajor);
        Assert.Equal(s.Dehydrated, aot.Header.IsDehydrated);
        Assert.NotNull(aot.Header.Blob(BlobId.EmbeddedMetadata));
        Assert.NotNull(aot.Header.Section(SectionId.FrozenObjectRegion));

        if (s.IsPe) Assert.Equal("NativeAOT executable", Blob.Identify(File.ReadAllBytes(s.Path)));
        else
        {
            Assert.True(NativeAotLocator.HasMarkers(aot.Image));
            Assert.Equal("NativeAOT executable", Containers.Open(File.ReadAllBytes(s.Path), "ilc", AnalysisLimits.Default, default).Kind);
        }
    }

    /// <summary>Interface dispatch cells in every format: most carry the interface method's name and have implementations.</summary>
    [Theory]
    [MemberData(nameof(Samples))]
    public void Dispatch_cells_are_named_with_their_implementations(string sample)
    {
        var (_, aot) = Open(sample);
        var cells = aot.Dispatch.Cells;
        Assert.InRange(cells.Count, 4000, 9000);
        Assert.True(cells.Count(c => c.Method != null) > 0.95 * cells.Count);
        Assert.True(cells.Count(c => aot.Dispatch.Implementers(c.Interface, c.Slot).Count > 0) > 0.85 * cells.Count); // the rest: interfaces nothing implements here
        Assert.Contains(cells, c => c.Target == "System.Collections.IEnumerator::MoveNext");
    }

    /// <summary>32-bit images: 4-byte MethodTable pointers, frozen objects with 4-byte headers, ARM code pointers without the Thumb bit.</summary>
    [Theory]
    [InlineData("win-x86 10.0.11")]
    [InlineData("linux-arm 10.0.11")]
    public void A_32_bit_image_reads_like_a_64_bit_one(string sample)
    {
        var (_, aot) = Open(sample);
        Assert.False(aot.Image.Is64Bit);
        Assert.Equal(4, aot.Hydrated.PointerSize);
        var str = aot.Types.ByRva.Values.Single(t => t.Name == "System.String");
        Assert.Equal((14u, (ushort)2), (str.BaseSize, str.ComponentSize));
        Assert.Equal(12u, aot.Types.ByRva.Values.Single(t => t.Name == "System.Object").BaseSize);
        Assert.All(aot.Names.MethodAt.Keys.Take(5000), rva => Assert.True(aot.Image.SectionAt(rva) is { IsExecutable: true }));
        if (aot.Image.Arch == NativeArch.Arm) Assert.All(aot.Names.MethodAt.Keys, rva => Assert.Equal(0u, rva & 1));
        Assert.Contains(aot.Frozen.Objects, o => o.Text == "System.Private.CoreLib");
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Metadata_names_every_type_definition(string sample)
    {
        var (_, aot) = Open(sample);
        var md = Assert.IsType<NativeAotMetadata>(aot.Metadata);
        var types = md.TypeDefinitions();
        Assert.InRange(types.Count, 3000, 5000);
        var names = types.Select(t => md.FormatType(new MdHandle(MdRecord.TypeDefinition, t))).ToHashSet();
        Assert.DoesNotContain(names, n => n.Contains('?'));
        Assert.Contains("ILCompiler.Program", names);
        Assert.Contains("System.String", names);
        Assert.Contains("System.Collections.Generic.List`1+Enumerator", names);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Rehydration_expands_dehydrated_images(string sample)
    {
        var (s, aot) = Open(sample);
        var h = aot.Hydrated;
        Assert.Equal(s.Dehydrated ? NativeAotStage.Complete : NativeAotStage.Absent, h.Stage.Status);
        if (s.Dehydrated)
        {
            Assert.InRange(h.HydratedLength, 2_000_000, 4_000_000);
            Assert.NotNull(h.Sha256);
        }
        Assert.InRange(h.PointerSlots.Count, 100_000, 400_000);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Name_maps_name_most_functions(string sample)
    {
        var (_, aot) = Open(sample);
        var names = aot.Names;
        Assert.All(names.Stages, st => Assert.Equal(NativeAotStage.Complete, st.Status));
        var starts = aot.UnwindStarts();
        int covered = names.MethodAt.Keys.Count(starts.Contains);
        if (aot.Image.Arch == NativeArch.X86) Assert.Empty(starts); // x86 PE has no unwind table: no coverage to measure
        else Assert.True(covered > 0.65 * starts.Count, $"{covered} of {starts.Count} function starts named"); // the rest: runtime and C library code
        Assert.InRange(names.MethodAt.Count, 20_000, 40_000);
        Assert.Contains(names.Methods, m => m.Name.Short == "ILCompiler.Program::Main");
        Assert.Contains(names.Methods, m => m.Name.Full == "System.String::Concat(string, string)");
        Assert.InRange(names.TypeNames.Count, 2000, 5000);
        Assert.Contains("System.String", names.TypeNames.Values);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Method_tables_are_found_and_named(string sample)
    {
        var (_, aot) = Open(sample);
        var types = aot.Types;
        Assert.Equal(NativeAotStage.Complete, types.Stage.Status);
        Assert.InRange(types.ByRva.Count, 15_000, 30_000);
        int named = types.ByRva.Values.Count(t => t.NameOrigin != "generated");
        Assert.True(named > 0.99 * types.ByRva.Count, $"{named} of {types.ByRva.Count} named");
        Assert.All(aot.Names.TypeNames.Keys, mt => Assert.True(types.ByRva.ContainsKey(mt)));
        var names = types.ByRva.Values.Select(t => t.Name).ToHashSet();
        Assert.Contains("string[]", names);
        Assert.Contains("System.Collections.Generic.List<string>", names);
        var str = types.ByRva.Values.Single(t => t.Name == "System.String");
        Assert.Equal((NativeAotElementType.Class, (ushort)2), (str.ElementType, str.ComponentSize));
    }

    /// <summary>Dispatch maps: interface slots resolve to code, IEnumerator's slot 0 to MoveNext bodies.</summary>
    [Theory]
    [MemberData(nameof(Samples))]
    public void Dispatch_maps_resolve_interface_slots(string sample)
    {
        var (_, aot) = Open(sample);
        var types = aot.Types;
        var impls = types.ByRva.Values.Where(t => t.DispatchMap != 0).SelectMany(t => types.Implementations(t).Select(i => (Type: t, Impl: i))).ToList();
        Assert.InRange(impls.Count, 20_000, 40_000);
        Assert.True(impls.Count(i => i.Impl.Code != 0) > 0.9 * impls.Count);
        Assert.True(impls.Count(i => i.Impl.ImplSlot >= i.Type.Vtable.Count) > impls.Count / 2, "most implementations are in sealed vtables");
        var moveNext = impls.Where(i => i.Impl.InterfaceSlot == 0 && types.At(i.Impl.Interface)?.Name == "System.Collections.IEnumerator"
                                        && aot.Names.MethodAt.ContainsKey(i.Impl.Code)).Select(i => aot.Names.MethodAt[i.Impl.Code].Name.Name).ToList();
        Assert.True(moveNext.Count > 50 && moveNext.Count(n => n.EndsWith("MoveNext", StringComparison.Ordinal)) > 0.95 * moveNext.Count);
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void The_frozen_region_is_walked_to_the_end(string sample)
    {
        var (_, aot) = Open(sample);
        var frozen = aot.Frozen;
        Assert.Equal(NativeAotStage.Complete, frozen.Stage.Status);
        Assert.InRange(frozen.Objects.Count, 6000, 12000);
        Assert.InRange(frozen.StringCount, 4000, 8000);
        Assert.DoesNotContain(frozen.Objects, o => o.TypeName.StartsWith("MT_", StringComparison.Ordinal) && o.Text != null);
        Assert.Contains(frozen.Objects, o => o.Text == "System.Private.CoreLib");
    }
}
