using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>Function discovery explores roots in parallel and commits them in queue order: the saved index is the same at any thread count.</summary>
[Collection(SweepCollection.Name)]
public class ParallelDiscoveryTests
{
    private static byte[] Payload(INativeImage image, CodeIndexOptions options)
    {
        var index = NativeCodeIndex.Build(image, options);
        var stream = new MemoryStream();
        using (var w = new PayloadWriter(b => stream.Write(b))) index.WritePayload(w, times: false);
        return stream.ToArray();
    }

    private static void AssertSame(byte[] serial, byte[] parallel, string what)
    {
        int at = serial.AsSpan().CommonPrefixLength(parallel);
        Assert.True(at == serial.Length && at == parallel.Length, $"{what}: payloads differ at byte {at} ({serial.Length} / {parallel.Length} bytes)");
    }

    public static readonly TheoryData<string> Small = new() { "linux-x64", "osx-arm64", "win-arm64", "linux-arm", "android-arm stripped" };

    /// <summary>Every queued root goes through the parallel path, so speculative runs and their commits are exercised.</summary>
    [Theory]
    [MemberData(nameof(Small))]
    public void Saved_index_is_the_same_at_one_and_four_threads(string build)
    {
        var image = build switch
        {
            "linux-x64" => NativeImageLoader.Open(NativeFixtures.LinuxX64DbgShim),
            "osx-arm64" => NativeImageLoader.Open(NativeFixtures.OsxArm64DbgShim),
            "linux-arm" => NativeImageLoader.Open(NativeFixtures.LinuxArmDbgShim),
            // ARM32 without symbols: states learned while exploring (speculative runs log their reads and hints)
            "android-arm stripped" => Stripped(NativeFixtures.AndroidArmTracing),
            _ => NativeImageLoader.Open(NativeFixtures.WinArm64DbgShim),
        };
        var serial = Payload(image, new CodeIndexOptions { MaxParallelism = 1 });
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 4, ParallelExploreMin = 1 }), build);
    }

    public static readonly TheoryData<string> Large = new() { "win-x64 10.0.11", "win-x86 10.0.11", "linux-x64 10.0.11", "osx-arm64 10.0.11", "libSkiaSharp", "libSkiaSharp arm stripped" };

    private static INativeImage Stripped(string path) => NativeImageLoader.FromBytes(Accuracy.ElfStrip.Strip(File.ReadAllBytes(path)), path);

    /// <summary>NativeAOT-compiled ilc and libSkiaSharp (C++, ARM64 virtual call shapes): one thread against eight, twice to vary the scheduling.</summary>
    [Theory]
    [MemberData(nameof(Large))]
    [Trait("Speed", "Slow")]
    public void Saved_index_of_a_large_image_is_the_same_at_one_and_eight_threads(string sample)
    {
        var image = sample switch
        {
            "libSkiaSharp" => NativeImageLoader.Open(NativeFixtures.OsxFatSkia),
            "libSkiaSharp arm stripped" => Stripped(RealPackages.File("SkiaSharp.NativeAssets.Linux", "3.119.4", "runtimes", "linux-arm", "native", "libSkiaSharp.so")),
            _ => NativeImageLoader.Open(NativeAotRealTests.PathOf(sample)),
        };
        var serial = Payload(image, new CodeIndexOptions { MaxParallelism = 1 });
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 8 }), sample);
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 8 }), sample + " (again)");
    }
}
