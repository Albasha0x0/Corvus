using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>Function discovery explores roots in parallel and commits them in queue order: the saved index is the same at any thread count.</summary>
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

    public static readonly TheoryData<string> Small = new() { "linux-x64", "osx-arm64", "win-arm64" };

    /// <summary>Every queued root goes through the parallel path, so speculative runs and their commits are exercised.</summary>
    [Theory]
    [MemberData(nameof(Small))]
    public void Saved_index_is_the_same_at_one_and_four_threads(string build)
    {
        var image = NativeImageLoader.Open(build switch
        {
            "linux-x64" => NativeFixtures.LinuxX64DbgShim,
            "osx-arm64" => NativeFixtures.OsxArm64DbgShim,
            _ => NativeFixtures.WinArm64DbgShim,
        });
        var serial = Payload(image, new CodeIndexOptions { MaxParallelism = 1 });
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 4, ParallelExploreMin = 1 }), build);
    }

    public static readonly TheoryData<string> Large = new() { "win-x64 10.0.11", "win-x86 10.0.11", "linux-x64 10.0.11", "osx-arm64 10.0.11" };

    /// <summary>NativeAOT-compiled ilc (tens of megabytes): one thread against eight, twice to vary the scheduling.</summary>
    [Theory]
    [MemberData(nameof(Large))]
    [Trait("Speed", "Slow")]
    public void Saved_index_of_a_large_image_is_the_same_at_one_and_eight_threads(string sample)
    {
        var image = NativeImageLoader.Open(NativeAotRealTests.PathOf(sample));
        var serial = Payload(image, new CodeIndexOptions { MaxParallelism = 1 });
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 8 }), sample);
        AssertSame(serial, Payload(image, new CodeIndexOptions { MaxParallelism = 8 }), sample + " (again)");
    }
}
