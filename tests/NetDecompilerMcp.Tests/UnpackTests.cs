using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using dnlib.DotNet;
using K4os.Compression.LZ4;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Every container fixture is built at test time: hello-world single-file bundles from `dotnet publish`, NuGet packages
/// from the local package cache, Costura hosts and assembly stores written with dnlib, and APK-style zips.
/// </summary>
public sealed class ContainerFixtures : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Lazy<string> _compressedBundle;
    private readonly Lazy<string> _readyToRunBundle;
    private readonly Lazy<string> _readyToRunDll;

    public ContainerFixtures()
    {
        HelloProject = Path.Combine(_dir.Path, "hello");
        Directory.CreateDirectory(HelloProject);
        // Empty build props stop MSBuild from picking up a Directory.Build.props above the temp folder.
        File.WriteAllText(Path.Combine(HelloProject, "Directory.Build.props"), "<Project />");
        File.WriteAllText(Path.Combine(HelloProject, "Directory.Packages.props"), "<Project />");
        File.WriteAllText(Path.Combine(HelloProject, "Hello.csproj"), """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net10.0</TargetFramework>
                <ImplicitUsings>enable</ImplicitUsings>
              </PropertyGroup>
            </Project>
            """);
        File.WriteAllText(Path.Combine(HelloProject, "Program.cs"), """Console.WriteLine("Hello from a single-file bundle");""");
        Bundle = Publish("plain", "--self-contained", "false");
        _compressedBundle = new(() => Publish("compressed", "--self-contained", "true", "-p:EnableCompressionInSingleFile=true"));
        _readyToRunBundle = new(() => Publish("r2r-bundle", "--self-contained", "false", "-p:PublishReadyToRun=true"));
        _readyToRunDll = new(() => Path.Combine(Path.GetDirectoryName(
            Publish("r2r", "--self-contained", "false", "-p:PublishReadyToRun=true", "-p:PublishSingleFile=false"))!, "Hello.dll"));
    }

    public static string Rid => RuntimeInformation.RuntimeIdentifier;
    public string HelloProject { get; }
    /// <summary>Framework-dependent single-file bundle (entries stored uncompressed).</summary>
    public string Bundle { get; }
    /// <summary>Self-contained single-file bundle with compression (entries deflated); built on first use.</summary>
    public string CompressedBundle => _compressedBundle.Value;
    /// <summary>Single-file bundle whose Hello.dll was precompiled by crossgen2 (PublishReadyToRun).</summary>
    public string ReadyToRunBundle => _readyToRunBundle.Value;
    /// <summary>A ReadyToRun Hello.dll on its own (not bundled).</summary>
    public string ReadyToRunDll => _readyToRunDll.Value;
    /// <summary>The Hello.dll the bundler packed.</summary>
    public string HelloDll => Path.Combine(HelloProject, "bin", "Release", "net10.0", Rid, "Hello.dll");

    private string Publish(string name, params string[] args)
    {
        var output = Path.Combine(_dir.Path, name);
        var psi = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = HelloProject };
        foreach (var a in (string[])["publish", "-c", "Release", "-r", Rid, "-p:PublishSingleFile=true", "-o", output, .. args]) psi.ArgumentList.Add(a);
        foreach (var key in psi.Environment.Keys.Where(k => k.StartsWith("MSBuild", StringComparison.OrdinalIgnoreCase)).ToList()) psi.Environment.Remove(key);
        psi.Environment["DOTNET_NOLOGO"] = "1";
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        using var p = Process.Start(psi)!;
        var stderr = p.StandardError.ReadToEndAsync();
        var stdout = p.StandardOutput.ReadToEnd();
        Assert.True(p.WaitForExit(600_000), "dotnet publish timed out");
        Assert.True(p.ExitCode == 0, $"dotnet publish {name} failed:\n{stdout}{stderr.Result}");
        return Path.Combine(output, OperatingSystem.IsWindows() ? "Hello.exe" : "Hello");
    }

    public void Dispose() => _dir.Dispose();

    // ------------------------------------------------------------------ builders

    /// <summary>A .nupkg from the global packages folder (restore guarantees the server's own dependencies are there).</summary>
    public static string NuGetPackage(string id)
    {
        var root = Environment.GetEnvironmentVariable("NUGET_PACKAGES")
                   ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        // the newest version: the cache can hold older ones too
        var package = Directory.EnumerateDirectories(Path.Combine(root, id.ToLowerInvariant()))
            .OrderByDescending(d => Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : new Version())
            .SelectMany(d => Directory.EnumerateFiles(d, "*.nupkg"))
            .FirstOrDefault();
        Assert.True(package != null, $"{id} is not in the NuGet cache at {root}");
        return package!;
    }

    /// <summary>A tiny, distinct .NET assembly.</summary>
    public static byte[] Module(string name, params (string Name, byte[] Data)[] resources) => Module(name, module =>
    {
        foreach (var (resName, data) in resources)
            module.Resources.Add(new EmbeddedResource(resName, data));
    });

    /// <summary>A tiny .NET assembly with a Marker type; <paramref name="build"/> adds whatever else the test needs.</summary>
    public static byte[] Module(string name, Action<ModuleDefUser> build)
    {
        // fixed MVID: the same name gives the same bytes on every run, so fuzzing failures reproduce
        var mvid = new Guid(System.Security.Cryptography.MD5.HashData(Encoding.UTF8.GetBytes(name)));
        var module = new ModuleDefUser(name + ".dll", mvid) { Kind = ModuleKind.Dll };
        new AssemblyDefUser(name, new Version(1, 2, 3, 4)).Modules.Add(module);
        module.Types.Add(new TypeDefUser(name, "Marker", module.CorLibTypes.Object.TypeDefOrRef));
        build(module);
        using var ms = new MemoryStream();
        module.Write(ms);
        return ms.ToArray();
    }

    public static byte[] Deflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var z = new DeflateStream(ms, CompressionLevel.Optimal)) z.Write(data);
        return ms.ToArray();
    }

    /// <summary>Xamarin XALZ: "XALZ", descriptor index, uncompressed size, LZ4 block.</summary>
    public static byte[] Xalz(byte[] data, uint index = 0)
    {
        var block = new byte[LZ4Codec.MaximumOutputSize(data.Length)];
        int n = LZ4Codec.Encode(data, block);
        var result = new byte[12 + n];
        "XALZ"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), index);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), (uint)data.Length);
        block.AsSpan(0, n).CopyTo(result.AsSpan(12));
        return result;
    }

    public static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in entries)
            {
                var entry = zip.CreateEntry(name);
                entry.LastWriteTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero); // deterministic bytes
                using var s = entry.Open();
                s.Write(data);
            }
        return ms.ToArray();
    }

    /// <summary>"XABA" assembly store: a header, a raw PE image and an XALZ chunk.</summary>
    public static byte[] AssemblyStore(byte[] rawAssembly, byte[] xalzAssembly) =>
        [.. "XABA"u8, .. new byte[12], .. rawAssembly, .. new byte[16], .. Xalz(xalzAssembly)];

    private static readonly byte[] BundleSignature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    public sealed record BundleEntry(string Path, byte[]? Data, long Offset = 0, long Size = 0, long Compressed = 0, byte Type = 1);

    /// <summary>
    /// A real apphost bundle with extra payloads and a new v6 manifest appended, and the header-offset slot pointed at it.
    /// Entries with <see cref="BundleEntry.Data"/> get their data appended; the others keep the offsets/sizes given (to corrupt them).
    /// </summary>
    public static byte[] WithManifest(byte[] bundle, IEnumerable<BundleEntry> entries, int? count = null)
    {
        var list = entries.ToList();
        using var ms = new MemoryStream();
        ms.Write(bundle);
        var placed = list.Select(e =>
        {
            if (e.Data == null) return e;
            var at = ms.Position;
            ms.Write(e.Data);
            return e with { Offset = at, Size = e.Data.Length };
        }).ToList();
        long header = ms.Position;
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(6u);
            w.Write(0u);
            w.Write(count ?? placed.Count);
            w.Write("synthetic-bundle");
            w.Write(new byte[40]); // deps.json / runtimeconfig.json locations, flags
            foreach (var e in placed)
            {
                w.Write(e.Offset);
                w.Write(e.Size);
                w.Write(e.Compressed);
                w.Write(e.Type);
                w.Write(e.Path);
            }
        }
        var result = ms.ToArray();
        SetBundleHeaderOffset(result, header);
        return result;
    }

    public static void SetBundleHeaderOffset(byte[] bundle, long offset)
    {
        int sig = bundle.AsSpan().IndexOf(BundleSignature);
        Assert.True(sig >= 8, "bundle signature not found");
        BinaryPrimitives.WriteInt64LittleEndian(bundle.AsSpan(sig - 8), offset);
    }

    public static long GetBundleHeaderOffset(byte[] bundle) =>
        BinaryPrimitives.ReadInt64LittleEndian(bundle.AsSpan(bundle.AsSpan().IndexOf(BundleSignature) - 8));
}

public partial class UnpackTests(ContainerFixtures fx) : IClassFixture<ContainerFixtures>, IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());
    private UnpackService Unpacker => new(_workspace);

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private string Save(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private UnpackService.UnpackReport Unpack(string path, bool load = false, string? output = null) =>
        Unpacker.Unpack(path, output ?? _dir.File("out-" + Guid.NewGuid().ToString("N")[..8]), load, AnalysisLimits.Default, default);

    private static UnpackService.UnpackedFile Entry(UnpackService.UnpackReport r, string name) =>
        Assert.Single(r.Files, f => Path.GetFileName(f.Path).Equals(name, StringComparison.OrdinalIgnoreCase));

    private static string Sha(string path) => Blob.Sha256(System.IO.File.ReadAllBytes(path));

    // ------------------------------------------------------------------ single-file bundles

    [Fact]
    public void SingleFileBundle_ExtractsTheAppAndItsHostFiles()
    {
        var r = Unpack(fx.Bundle, load: true);

        Assert.Equal(".NET single-file bundle", r.Container);
        var hello = Entry(r, "Hello.dll");
        Assert.Equal(".NET assembly", hello.Kind);
        Assert.Equal(Sha(fx.HelloDll), hello.Sha256);
        Assert.StartsWith("bundle entry (assembly", hello.Origin);
        Assert.Equal("Hello", hello.LoadedAs);
        Assert.Contains("runtimeconfig.json", Entry(r, "Hello.runtimeconfig.json").Origin);
        Assert.Contains("deps.json", Entry(r, "Hello.deps.json").Origin);
        Assert.Contains(r.Notes, n => n.StartsWith("Single-file bundle v"));
        Assert.True(System.IO.File.ReadAllBytes(hello.Path).AsSpan().IndexOf(Encoding.Unicode.GetBytes("Hello from a single-file bundle")) > 0);
    }

    [Fact]
    public void CompressedSelfContainedBundle_InflatesEveryEntry()
    {
        var r = Unpack(fx.CompressedBundle);

        Assert.Equal(".NET single-file bundle", r.Container);
        Assert.Equal(Sha(fx.HelloDll), Entry(r, "Hello.dll").Sha256);
        var corelib = Entry(r, "System.Private.CoreLib.dll");
        Assert.Equal(".NET assembly", corelib.Kind);
        Assert.Contains("deflate", corelib.Origin);
        // the whole runtime is extracted; the report lists 100 (the app first) and counts the rest
        Assert.True(Directory.EnumerateFiles(r.OutputDirectory, "*.dll", SearchOption.AllDirectories).Count() > 100);
        Assert.Equal(UnpackService.MaxListed, r.Files.Count);
        Assert.Equal("Hello.dll", Path.GetFileName(r.Files.First(f => f.Kind == ".NET assembly").Path));
        Assert.Contains(r.Notes, n => n.Contains($"; {UnpackService.MaxListed} listed (the app's assemblies first"));
        Assert.DoesNotContain(r.Notes, n => n.StartsWith("Skipped"));
    }

    [Fact]
    public void UnpackingAgainReusesTheOutput_ButAnUnrelatedDirectoryIsRefused()
    {
        var output = _dir.File("reuse");
        var first = Unpack(fx.Bundle, output: output);
        var second = Unpack(fx.Bundle, output: output);
        Assert.Equal(first.Files.Select(f => f.Path), second.Files.Select(f => f.Path));

        var other = Save("other.nupkg", System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4")));
        Assert.Contains("not empty", Assert.Throws<ToolError>(() => Unpack(other, output: output)).Message);
    }

    // ------------------------------------------------------------------ NuGet

    [Theory]
    [InlineData("dnlib", "dnlib.dll")]
    [InlineData("K4os.Compression.LZ4", "K4os.Compression.LZ4.dll")]
    public void NuGetPackageFromTheLocalCache(string id, string dll)
    {
        var r = Unpack(ContainerFixtures.NuGetPackage(id), load: true);

        Assert.Equal("NuGet package", r.Container);
        var assemblies = r.Files.Where(f => Path.GetFileName(f.Path) == dll).ToList();
        Assert.NotEmpty(assemblies); // one per target framework
        Assert.All(assemblies, f => Assert.Equal(".NET assembly", f.Kind));
        Assert.All(assemblies, f => Assert.NotNull(f.LoadedAs));
        Assert.All(assemblies, f => Assert.Contains($"{Path.DirectorySeparatorChar}lib{Path.DirectorySeparatorChar}", f.Path));
        // the copy the test itself runs against came out of the same package
        var used = Path.Combine(AppContext.BaseDirectory, dll);
        Assert.Contains(assemblies, f => f.Sha256 == Sha(used));
    }

    [Fact]
    public void NestedPackages_AreOpenedIntoTheirOwnFolders()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var r = Unpack(Save("bundle.zip", ContainerFixtures.Zip(("packages/k4os.nupkg", nupkg))));

        Assert.Equal("zip archive", r.Container);
        Assert.Contains("packages/k4os.nupkg: NuGet package.", r.Notes);
        Assert.Contains(r.Files, f => f.Path.Contains("k4os.nupkg_unpacked") && f.Path.EndsWith("K4os.Compression.LZ4.dll"));
    }

    // ------------------------------------------------------------------ resource-embedded (Costura)

    [Fact]
    public void CosturaHost_ExtractsCompressedAndPlainEmbeddedAssemblies()
    {
        var fixture = System.IO.File.ReadAllBytes(Env.FixturePath);
        var consumer = System.IO.File.ReadAllBytes(Env.ConsumerPath);
        var host = ContainerFixtures.Module("CosturaHost",
            ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(fixture)),
            ("costura64.testfixture.consumer.dll", consumer),
            ("unrelated.txt", "not an assembly"u8.ToArray()));

        var r = Unpack(Save("CosturaHost.exe", host), load: true);

        Assert.Equal("Costura.Fody (embedded assemblies)", r.Container);
        Assert.Equal(3, r.Files.Count);
        // the host itself first: the app's own code, loaded with the embedded assemblies (its path is the source file)
        Assert.Equal((UnpackService.HostOrigin, "CosturaHost"), (r.Files[0].Origin, r.Files[0].LoadedAs));
        Assert.Equal(System.IO.Path.GetFileName(r.Source), System.IO.Path.GetFileName(r.Files[0].Path));
        var a = Entry(r, "testfixture.dll");
        Assert.Equal(Blob.Sha256(fixture), a.Sha256);
        Assert.Equal("Costura resource costura.testfixture.dll.compressed (deflate)", a.Origin);
        Assert.Equal("TestFixture", a.LoadedAs);
        Assert.Equal(Blob.Sha256(consumer), Entry(r, "testfixture.consumer.dll").Sha256);
    }

    [Fact]
    public void PlainAssembly_IsNotAContainer()
    {
        var r = Unpack(Env.FixturePath);
        Assert.Equal("none", r.Container);
        Assert.Empty(r.Files);
        Assert.Contains(r.Notes, n => n.Contains("plain .NET assembly"));
    }

    // ------------------------------------------------------------------ APK

    private static (byte[] Apk, byte[] StoreRaw, byte[] StoreXalz) BuildApk()
    {
        var storeRaw = ContainerFixtures.Module("StoreRaw");
        var storeXalz = ContainerFixtures.Module("StoreXalz");
        var store = ContainerFixtures.AssemblyStore(storeRaw, storeXalz);
        var apk = ContainerFixtures.Zip(
            ("AndroidManifest.xml", [0x03, 0x00, 0x08, 0x00]),
            ("assemblies/TestFixture.dll", ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath), 7)),
            ("assemblies/TestFixture.Consumer.dll", System.IO.File.ReadAllBytes(Env.ConsumerPath)),
            ("assemblies/assemblies.blob", store),
            ("lib/arm64-v8a/libassemblies.arm64-v8a.blob.so", store), // same store per ABI: extracted once
            ("res/drawable/icon.png", [0x89, (byte)'P', (byte)'N', (byte)'G']),
            ("classes.dex", "dex\n035"u8.ToArray()));
        return (apk, storeRaw, storeXalz);
    }

    [Fact]
    public void ApkStyleZip_DecodesXalzAndAssemblyStores()
    {
        var (apk, storeRaw, storeXalz) = BuildApk();
        var r = Unpack(Save("app.apk", apk), load: true);

        Assert.Equal("Android package (Xamarin / MAUI)", r.Container);
        var fixture = Entry(r, "TestFixture.dll");
        Assert.Equal(Sha(Env.FixturePath), fixture.Sha256);
        Assert.Contains("XALZ", fixture.Origin);
        Assert.Equal("TestFixture", fixture.LoadedAs);
        Assert.Equal(Sha(Env.ConsumerPath), Entry(r, "TestFixture.Consumer.dll").Sha256);

        var carved = Assert.Single(r.Files, f => f.Sha256 == Blob.Sha256(storeRaw));
        Assert.Contains("carved .NET image", carved.Origin);
        Assert.Equal("StoreRaw", carved.LoadedAs);
        var decoded = Assert.Single(r.Files, f => f.Sha256 == Blob.Sha256(storeXalz));
        Assert.Contains("XALZ (LZ4) chunk", decoded.Origin);

        Assert.DoesNotContain(r.Files, f => f.Path.EndsWith("icon.png") || f.Path.EndsWith("classes.dex"));
        Assert.Equal(4, r.Files.Count);
    }

    [Fact]
    public void StandaloneXalzFile_IsDecompressed()
    {
        var r = Unpack(Save("TestFixture.dll", ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath))));
        Assert.Equal("Xamarin XALZ", r.Container);
        Assert.Equal(Sha(Env.FixturePath), Assert.Single(r.Files).Sha256);
    }

    // ------------------------------------------------------------------ robustness: corrupt headers

    [Fact]
    public void Bundle_HeaderOffsetOutsideTheFile()
    {
        var bytes = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bytes, long.MaxValue - 4);
        Assert.Contains("outside the file", Assert.Throws<ToolError>(() => Unpack(Save("a.exe", bytes))).Message);
        ContainerFixtures.SetBundleHeaderOffset(bytes, -1);
        Assert.Contains("outside the file", Assert.Throws<ToolError>(() => Unpack(Save("b.exe", bytes))).Message);
    }

    [Fact]
    public void Bundle_ManifestTruncatedOrImplausible()
    {
        var bytes = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bytes, bytes.Length - 6);
        Assert.Contains("truncated", Assert.Throws<ToolError>(() => Unpack(Save("a.exe", bytes))).Message);

        var huge = ContainerFixtures.WithManifest(System.IO.File.ReadAllBytes(fx.Bundle), [], count: int.MaxValue);
        Assert.Contains("Corrupt single-file bundle header", Assert.Throws<ToolError>(() => Unpack(Save("b.exe", huge))).Message);

        var tooMany = ContainerFixtures.WithManifest(System.IO.File.ReadAllBytes(fx.Bundle), [new("x.dll", [1, 2, 3])], count: 50);
        Assert.Contains("truncated", Assert.Throws<ToolError>(() => Unpack(Save("c.exe", tooMany))).Message);
    }

    [Fact]
    public void Bundle_EntriesWithBadOffsetsSizesOrCompression_AreSkippedWithNotes()
    {
        var good = ContainerFixtures.Module("Good");
        var bytes = ContainerFixtures.WithManifest(System.IO.File.ReadAllBytes(fx.Bundle),
        [
            new("past-end.dll", null, Offset: 1L << 40, Size: 10),
            new("overflow.dll", null, Offset: long.MaxValue - 4, Size: 100),
            new("negative.dll", null, Offset: 0, Size: -5),
            new("bad-deflate.dll", null, Offset: 0x40, Size: 4096, Compressed: 64),
            new("good.dll", good),
        ]);

        var r = Unpack(Save("corrupt.exe", bytes));

        Assert.Equal(Blob.Sha256(good), Entry(r, "good.dll").Sha256);
        Assert.Single(r.Files);
        foreach (var name in new[] { "past-end.dll", "overflow.dll", "negative.dll", "bad-deflate.dll" })
            Assert.Contains(r.Notes, n => n.StartsWith($"Skipped {name}"));
    }

    [Fact]
    public void Pe_CorruptHeaders_FallBackToCarving()
    {
        var lfanew = System.IO.File.ReadAllBytes(Env.FixturePath);
        BinaryPrimitives.WriteInt32LittleEndian(lfanew.AsSpan(0x3C), int.MaxValue);
        Assert.Null(PeImage.TryParse(lfanew));
        Assert.Equal("none", Unpack(Save("lfanew.dll", lfanew)).Container);

        var sections = System.IO.File.ReadAllBytes(Env.FixturePath);
        int pe = BinaryPrimitives.ReadInt32LittleEndian(sections.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt16LittleEndian(sections.AsSpan(pe + 6), 0xFFFF);
        Assert.Null(PeImage.TryParse(sections));
        Assert.Equal("none", Unpack(Save("sections.dll", sections)).Container);
    }

    [Fact]
    public void Xalz_CorruptOrImplausibleSize()
    {
        var xalz = ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath));
        var wrongSize = xalz.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongSize.AsSpan(8), 123);
        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => Unpack(Save("a.dll", wrongSize))).Message);

        // a 400 MB claim from a 20-byte chunk is rejected before anything is allocated
        byte[] bomb = [.. "XALZ"u8, 0, 0, 0, 0, .. BitConverter.GetBytes(400u << 20), .. new byte[8]];
        Assert.Null(Blob.TryXalz(bomb, AnalysisLimits.Default.MaxItemBytes));
        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => Unpack(Save("b.dll", bomb))).Message);
    }

    [Fact]
    public void Zip_CorruptCentralDirectoryOrEntries()
    {
        var zip = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        int eocd = zip.AsSpan().LastIndexOf("PK\x05\x06"u8);
        var badDirectory = zip.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(badDirectory.AsSpan(eocd + 16), uint.MaxValue - 100); // central directory offset
        // the central directory lost: every entry is still read from its local header
        var recovered = Unpack(Save("a.nupkg", badDirectory));
        Assert.Contains(recovered.Notes, n => n.StartsWith("Damaged zip"));
        Assert.Contains(recovered.Files, f => f.Path.EndsWith("K4os.Compression.LZ4.dll"));

        // a stored entry's data overwritten: the CRC check fails for that entry only
        var apk = ContainerFixtures.Zip(("a.dll", ContainerFixtures.Module("A")), ("b.dll", ContainerFixtures.Module("B")));
        int local = apk.AsSpan().IndexOf("PK\x03\x04"u8);
        int dataStart = local + 30 + BinaryPrimitives.ReadUInt16LittleEndian(apk.AsSpan(local + 26)) + BinaryPrimitives.ReadUInt16LittleEndian(apk.AsSpan(local + 28));
        apk.AsSpan(dataStart, 32).Fill(0xAA);
        var r = Unpack(Save("b.zip", apk));
        Assert.Contains(r.Files, f => f.Path.EndsWith("b.dll"));
    }

    [Fact]
    public void Costura_BadDeflateResource_IsNoted()
    {
        var host = ContainerFixtures.Module("Host", ("costura.broken.dll.compressed", [0xFF, 0xFF, 0xFF, 0xFF, 0x00]));
        var r = Unpack(Save("host.exe", host));
        Assert.Equal(UnpackService.HostOrigin, Assert.Single(r.Files).Origin); // only the host: nothing could be extracted
        Assert.Contains(r.Notes, n => n.Contains("costura.broken.dll.compressed") && n.Contains("deflate"));
    }

    // ------------------------------------------------------------------ robustness: truncation and fuzzing

    /// <summary>Every fixture, cut short at many points and with random bytes flipped: only ToolError, nothing outside the output.</summary>
    private static readonly int FuzzCases = int.TryParse(Environment.GetEnvironmentVariable("NDM_FUZZ_CASES"), out var n) ? n : 40;

    [Fact]
    public void TruncatedAndFuzzedInputs_FailCleanly()
    {
        var host = ContainerFixtures.Module("Host", ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(System.IO.File.ReadAllBytes(Env.FixturePath))));
        var inputs = new Dictionary<string, byte[]>
        {
            ["bundle"] = System.IO.File.ReadAllBytes(fx.Bundle),
            ["nupkg"] = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4")),
            ["costura"] = host,
            ["apk"] = BuildApk().Apk,
            ["xalz"] = ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath)),
        };
        var random = new Random(1234);
        var failures = new List<string>();
        foreach (var (name, bytes) in inputs)
        {
            var cases = new List<(string, byte[])>();
            foreach (var cut in new[] { 0, 1, 2, 3, 12, 64, 0x3C, 0x100, bytes.Length / 4, bytes.Length / 2, bytes.Length * 3 / 4, bytes.Length - 22, bytes.Length - 1 })
                if (cut >= 0 && cut < bytes.Length) cases.Add(($"{name} cut at {cut}", bytes[..cut]));
            if (name == "bundle") // truncated inside the manifest
            {
                long header = ContainerFixtures.GetBundleHeaderOffset(bytes);
                foreach (var cut in new[] { header + 2, header + 20, header + 60, header + 100 })
                    if (cut < bytes.Length) cases.Add(($"bundle cut at manifest+{cut - header}", bytes[..(int)cut]));
            }
            for (int i = 0; i < FuzzCases; i++)
            {
                var mutated = bytes.ToArray();
                for (int k = 0; k < 1 + i % 8; k++)
                {
                    // half the flips land in the first 4 KB, where the headers are
                    int at = random.Next(2) == 0 ? random.Next(Math.Min(4096, mutated.Length)) : random.Next(mutated.Length);
                    mutated[at] = (byte)random.Next(256);
                }
                cases.Add(($"{name} fuzz #{i}", mutated));
            }

            foreach (var (label, data) in cases)
            {
                using var sandbox = new TempDir();
                var output = Path.Combine(sandbox.Path, "out");
                var input = Path.Combine(sandbox.Path, "input.bin");
                System.IO.File.WriteAllBytes(input, data);
                try
                {
                    using var ws = new AssemblyWorkspace(new ServerOptions());
                    new UnpackService(ws).Unpack(input, output, load: true, AnalysisLimits.Default, default);
                }
                catch (ToolError) { /* expected for corrupt input */ }
                catch (Exception ex)
                {
                    failures.Add($"{label}: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
                }
                try
                {
                    using var ws = new AssemblyWorkspace(new ServerOptions());
                    new UnpackService(ws).List(input, AnalysisLimits.Default, default); // list_assemblies on a container
                }
                catch (ToolError) { /* expected for corrupt input */ }
                catch (Exception ex)
                {
                    failures.Add($"{label} (list): {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
                }
                var strays = Directory.EnumerateFiles(sandbox.Path, "*", SearchOption.AllDirectories)
                    .Where(f => f != input && !f.StartsWith(output + Path.DirectorySeparatorChar)).ToList();
                if (strays.Count > 0) failures.Add($"{label}: wrote outside the output: {string.Join(", ", strays)}");
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    // ------------------------------------------------------------------ robustness: path traversal

    private static readonly string[] HostileNames =
    [
        "../evil1.dll",
        "../../../../../evil2.dll",
        @"..\..\..\evil3.dll",
        "/abs/evil4.dll",
        @"\\server\share\evil5.dll",
        "C:/Windows/evil6.dll",
        @"C:..\evil7.dll",
        "assemblies/../../../../evil8.dll",
        "a/./../b/../../../evil9.exe",
        "....//....//evil10.dll",
        "%2e%2e/evil11.dll",
        "CON.dll",
        "evil12.dll\0.txt",
    ];

    /// <summary>Unpacks into sandbox/1/2/3/4/5/out so that any escape of up to five levels lands inside the sandbox and is caught.</summary>
    private void AssertContained(byte[] container, string fileName, Action<UnpackService.UnpackReport>? check = null)
    {
        using var sandbox = new TempDir();
        var output = Path.Combine(sandbox.Path, "1", "2", "3", "4", "5", "out");
        var input = Path.Combine(sandbox.Path, fileName);
        System.IO.File.WriteAllBytes(input, container);

        var r = new UnpackService(_workspace).Unpack(input, output, load: false, AnalysisLimits.Default, default);

        var prefix = Path.GetFullPath(output) + Path.DirectorySeparatorChar;
        Assert.All(r.Files.Where(f => f.Origin != UnpackService.HostOrigin), f => Assert.StartsWith(prefix, f.Path)); // the host is the input itself
        var everything = Directory.EnumerateFiles(sandbox.Path, "*", SearchOption.AllDirectories).Where(f => f != input).ToList();
        Assert.All(everything, f => Assert.StartsWith(prefix, f));
        Assert.DoesNotContain(everything, f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)); // runnable extensions defanged
        Assert.False(System.IO.File.Exists(@"C:\Windows\evil6.dll"));
        check?.Invoke(r);
    }

    private static byte[] Payload(int i) => Encoding.UTF8.GetBytes($"payload {i}"); // distinct content, or duplicates are skipped

    [Fact]
    public void ZipEntries_WithTraversalNames_StayInsideTheOutput() =>
        AssertContained(ContainerFixtures.Zip([.. HostileNames.Select((n, i) => (n, Payload(i)))]), "hostile.zip", r =>
        {
            // archives only yield code entries: "evil12.dll\0.txt" is a .txt, the rest all come out
            Assert.Equal(HostileNames.Length - 1, r.Files.Count);
            Assert.DoesNotContain(r.Files, f => f.Path.Contains("evil12"));
            Assert.Contains(r.Files, f => f.Path.EndsWith("evil9.exe.bin"));
            Assert.Contains(r.Files, f => Path.GetFileName(f.Path) == "_CON.dll");
        });

    [Fact]
    public void BundleEntries_WithTraversalNames_StayInsideTheOutput() =>
        AssertContained(ContainerFixtures.WithManifest(System.IO.File.ReadAllBytes(fx.Bundle),
            HostileNames.Select((n, i) => new ContainerFixtures.BundleEntry(n, Payload(i)))), "hostile.exe",
            r => Assert.Equal(HostileNames.Length, r.Files.Count));

    [Fact]
    public void CosturaResources_WithTraversalNames_StayInsideTheOutput() =>
        AssertContained(ContainerFixtures.Module("Host", [.. HostileNames.Where(n => !n.Contains('\0')).Select((n, i) => ("costura." + n, Payload(i)))]), "hostile.dll",
            r => Assert.Equal(HostileNames.Length - 1 + 1, r.Files.Count)); // metadata strings cannot hold NUL; + the host itself

    [Fact]
    public void NestedContainers_WithTraversalNames_StayInsideTheOutput()
    {
        var inner = ContainerFixtures.Zip([.. HostileNames.Select((n, i) => (n, Payload(i)))]);
        var outer = ContainerFixtures.Zip(("../../../../inner.nupkg", inner), ("/abs/inner2.zip", ContainerFixtures.Zip(("../../deep.dll", Payload(99)))));
        AssertContained(outer, "outer.zip", r =>
        {
            // rooted names keep their nesting folder
            Assert.Contains(r.Files, f => f.Path.Contains("inner2.zip_unpacked") && f.Path.EndsWith("deep.dll"));
            Assert.Equal(2 + HostileNames.Length - 1 + 1, r.Files.Count);
        });
    }

    [Fact]
    public void FileAndDirectoryWithTheSameName_IsNotedNotFatal()
    {
        var zip = ContainerFixtures.Zip(("lib.dll", Payload(1)), ("lib.dll/inner.dll", Payload(2)));
        AssertContained(zip, "clash.zip", r =>
        {
            Assert.Single(r.Files);
            Assert.Contains(r.Notes, n => n.StartsWith("Could not write"));
        });
    }
}
