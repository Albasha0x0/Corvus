using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.NativeAot;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// NativeAOT recovery on production binaries: tools/ilc.exe of the ILCompiler runtime packs is itself compiled with
/// NativeAOT (.NET 8, 9, 10; x64 and ARM64). Restored only for the full suite (NDM_ALL_TESTS=1).
/// </summary>
[Trait("Speed", "Slow")]
public class NativeAotRealTests
{
    public sealed record Sample(string Rid, string Version, string ReadyToRun, string Runtime, int DebugHeader, bool Dehydrated)
    {
        public override string ToString() => $"{Rid} {Version}";
        public string Path => RealPackages.File($"runtime.{Rid}.Microsoft.DotNet.ILCompiler", Version, "tools", "ilc.exe");
    }

    private static readonly Sample[] All =
    [
        new("win-x64", "8.0.30", "9.1", ".NET 8", 3, true),
        new("win-x64", "9.0.19", "10.1", ".NET 9", 4, true),
        new("win-x64", "10.0.11", "16.0", ".NET 10", 5, false),
        new("win-arm64", "10.0.11", "16.0", ".NET 10", 5, false),
    ];

    public static readonly TheoryData<string> Samples = new(All.Select(s => s.ToString()));

    private static readonly Dictionary<string, NativeAotImage> Opened = [];

    private static (Sample, NativeAotImage) Open(string name)
    {
        var s = All.Single(x => x.ToString() == name);
        lock (Opened)
        {
            if (!Opened.TryGetValue(name, out var aot))
                Opened[name] = aot = NativeAotImage.Open(PeFile.Open(s.Path)) ?? throw new InvalidOperationException($"{s}: no NativeAOT header");
            return (s, aot);
        }
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Header_VersionAndSections(string sample)
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

        var bytes = File.ReadAllBytes(s.Path);
        Assert.Equal("NativeAOT executable", Blob.Identify(bytes));
    }

    [Theory]
    [MemberData(nameof(Samples))]
    public void Metadata_AllTypeDefinitionsNamed(string sample)
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
}
