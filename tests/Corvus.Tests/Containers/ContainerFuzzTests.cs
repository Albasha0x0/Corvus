using System.Buffers.Binary;
using System.IO.Compression;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Quick fuzz entries of the built-in container formats, the light PE reader and the Authenticode reader.</summary>
public sealed class ContainerFuzzTests
{
    private static readonly byte[] Fixture = File.ReadAllBytes(Env.FixturePath);

    private static void Open(byte[] b, string name)
    {
        try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); }
        catch (ToolError) { }
    }

    /// <summary>zip, Costura, XALZ, Webcil and compressed Unity web data, each through the container dispatch.</summary>
    [Fact]
    [FuzzEntry(typeof(Containers))]
    public void Fuzzed_containers_never_throw_past_a_tool_error()
    {
        var unity = new MemoryStream();
        using (var gzip = new GZipStream(unity, CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write(UnityWebDataTests.Build(("Il2CppData/Metadata/global-metadata.dat", [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0]), ("data.unity3d", new byte[32])));
        var seeds = new (string Name, byte[] Bytes)[]
        {
            ("app.zip", ContainerFixtures.Zip(("lib/app.dll", Fixture), ("readme.txt", "hello"u8.ToArray()))),
            ("host.dll", ContainerFixtures.Module("Host", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(Fixture)))),
            ("app.dll", ContainerFixtures.Xalz(Fixture)),
            ("app.wasm", Webcil.FromPe(Fixture)),
            ("app.data.gz", unity.ToArray()),
        };
        var failures = new List<string>();
        foreach (var (name, bytes) in seeds)
            failures.AddRange(FormatFuzz.Run(bytes, b => Open(b, name), 300).Select(f => $"{name}: {f}"));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    [Fact]
    [FuzzEntry(typeof(UnityWebData))]
    public void Fuzzed_unity_web_data_never_throws_past_a_tool_error()
    {
        var seed = UnityWebDataTests.Build(("data.unity3d", "UnityFS\0\0\0\0"u8.ToArray()), ("Il2CppData/Metadata/global-metadata.dat", new byte[16]), ("../evil.txt", "x"u8.ToArray()));
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { UnityWebData.Open(b, "app.data", null, allFiles: true, AnalysisLimits.Default, default); }
            catch (ToolError) { }
        }, 1000);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    /// <summary>The header walk of a managed and a native image, and every query on what it read.</summary>
    [Fact]
    [FuzzEntry(typeof(PeImage))]
    public void Fuzzed_images_never_throw_in_the_header_reader()
    {
        static void Read(byte[] b)
        {
            if (PeImage.TryParse(b) is not { } pe) return;
            _ = (pe.IsDotNet(b), pe.CorFlags(b), pe.IsReadyToRun(b), pe.IsNativeAot(b), pe.Subsystem(b), pe.Exports(b).Count, pe.Overlaps.Count);
            for (int i = 0; i < pe.DataDirectoryCount && i < 16; i++) pe.MapRva(pe.Directory(b, i).Address);
            foreach (var s in pe.Sections) pe.RvaToOffset(s.VirtualAddress + s.VirtualSize / 2);
        }
        var failures = FormatFuzz.Run(Fixture, Read, 1000);
        failures.AddRange(FormatFuzz.Run(NativePeTests.KitchenSink(true), Read, 1000));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    /// <summary>The fixture with a real Authenticode signature appended: the security directory and the PKCS#7 blob damaged.</summary>
    [Fact]
    [FuzzEntry(typeof(Certificates))]
    public void Fuzzed_signatures_are_reported_not_thrown()
    {
        var failures = FormatFuzz.Run(SignedFixture(), b => Certificates.Read(b), 250);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    internal static byte[] SignedFixture()
    {
        var folder = Path.GetDirectoryName(ContainerFixtures.NuGetPackage("Microsoft.CodeAnalysis.Common"))!;
        var signed = File.ReadAllBytes(Directory.EnumerateFiles(Path.Combine(folder, "lib"), "Microsoft.CodeAnalysis.dll", SearchOption.AllDirectories).Order(StringComparer.Ordinal).First());
        var (offset, size) = PeImage.TryParse(signed)!.Directory(signed, PeImage.SecurityDirectory);
        Assert.True(size > 8, "the reference DLL is not signed");
        int at = (Fixture.Length + 7) & ~7;
        var seed = new byte[at + size];
        Fixture.CopyTo(seed, 0);
        Array.Copy(signed, offset, seed, at, size);
        int entry = PeImage.TryParse(Fixture)!.DirectoryEntryOffset(PeImage.SecurityDirectory);
        BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(entry), (uint)at);
        BinaryPrimitives.WriteUInt32LittleEndian(seed.AsSpan(entry + 4), size);
        Assert.True(Certificates.Read(seed).Signer != null, "the seed carries a readable signature");
        return seed;
    }
}
