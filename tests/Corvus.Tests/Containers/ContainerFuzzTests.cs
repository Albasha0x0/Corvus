using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Quick fuzz entries of the built-in container formats, the light PE reader and the Authenticode reader.</summary>
public sealed class ContainerFuzzTests
{
    private static readonly byte[] Fixture = File.ReadAllBytes(Env.FixturePath);

    private static void Open(byte[] b, string name)
    {
        using var _ = ContainerPassword.Enter("fuzz");
        try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); }
        catch (ToolError) { }
    }

    /// <summary>zip, Costura, XALZ, Webcil and compressed WebGL player data, each through the container dispatch.</summary>
    [Fact]
    [FuzzEntry(typeof(Containers))]
    public void Fuzzed_containers_never_throw_past_a_tool_error()
    {
        var webData = new MemoryStream();
        using (var gzip = new GZipStream(webData, CompressionLevel.Fastest, leaveOpen: true))
            gzip.Write(WebPlayerDataTests.Build(("Il2CppData/Metadata/global-metadata.dat", [0xAF, 0x1B, 0xB1, 0xFA, 29, 0, 0, 0]), ("data.unity3d", new byte[32])));
        var seeds = new (string Name, byte[] Bytes)[]
        {
            ("app.zip", ContainerFixtures.Zip(("lib/app.dll", Fixture), ("readme.txt", "hello"u8.ToArray()))),
            ("locked.zip", ArchivePasswordTests.Zip("fuzz", aes: true, ("lib/app.dll", Fixture))),
            ("crypto.zip", ArchivePasswordTests.Zip("fuzz", aes: false, ("lib/app.dll", Fixture))),
            ("host.dll", ContainerFixtures.Module("Host", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(Fixture)))),
            ("app.dll", ContainerFixtures.Xalz(Fixture)),
            ("app.wasm", Webcil.FromPe(Fixture)),
            ("app.data.gz", webData.ToArray()),
        };
        var failures = new List<string>();
        foreach (var (name, bytes) in seeds)
            failures.AddRange(FormatFuzz.Run(bytes, b => Open(b, name), 300).Select(f => $"{name}: {f}"));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    // Regression for 25559c18: a fuzz edit set a Costura host's
    // ManifestResource row count to 0x7FFFFFFF in a 148-byte tables stream.
    [Fact]
    public void A_host_whose_resource_rows_exceed_the_tables_stream_is_refused_without_a_large_allocation()
    {
        var host = ContainerFixtures.Module("Host", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(Fixture)));
        Assert.Contains(Containers.Open(host, "host.dll", AnalysisLimits.Default, default, allFiles: true).Items, i => i.Name.Contains("testfixture", StringComparison.OrdinalIgnoreCase));
        int rows;
        using (var pe = new PEReader(new MemoryStream(host)))
        {
            // The row counts end where the Module table starts.
            var md = pe.GetMetadataReader();
            int later = Enum.GetValues<TableIndex>().Count(t => t > TableIndex.ManifestResource && md.GetTableRowCount(t) > 0);
            rows = pe.PEHeaders.MetadataStartOffset + md.GetTableMetadataOffset(TableIndex.Module) - 4 * (later + 1);
        }
        BinaryPrimitives.WriteInt32LittleEndian(host.AsSpan(rows), int.MaxValue);
        var (offset, length) = MetadataSurvey.TablesStream(host)!.Value;
        Assert.Equal($"metadata table ManifestResource declares 16777215 rows; the tables stream holds {length} bytes", MetadataRows.Check(host.AsSpan(offset, length)));
        long before = GC.GetAllocatedBytesForCurrentThread();
        var opened = Containers.Open(host, "host.dll", AnalysisLimits.Default, default, allFiles: true);
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 32 << 20);
        Assert.DoesNotContain(opened.Items, i => i.Name.Contains("testfixture", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void The_full_set_runs_every_fuzz_entry_at_least_200_times_and_the_quick_set_25()
    {
        Assert.Equal((200, 200, 1000), (FormatFuzz.Iterations(100, full: true), FormatFuzz.Iterations(200, full: true), FormatFuzz.Iterations(1000, full: true)));
        Assert.Equal((25, 25, 100), (FormatFuzz.Iterations(100, full: false), FormatFuzz.Iterations(250, full: false), FormatFuzz.Iterations(1000, full: false)));
        Assert.Equal(10, FormatFuzz.Iterations(10, full: false));
    }

    [Fact]
    [FuzzEntry(typeof(WebPlayerData))]
    public void Fuzzed_WebGL_data_files_never_throw_past_a_tool_error()
    {
        var seed = WebPlayerDataTests.Build(("data.unity3d", "UnityFS\0\0\0\0"u8.ToArray()), ("Il2CppData/Metadata/global-metadata.dat", new byte[16]), ("../evil.txt", "x"u8.ToArray()));
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { WebPlayerData.Open(b, "app.data", null, allFiles: true, AnalysisLimits.Default, default); }
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
