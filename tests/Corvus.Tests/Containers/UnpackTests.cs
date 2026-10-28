using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using dnlib.DotNet;
using K4os.Compression.LZ4;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Container fixtures built at test time: published bundles, cached NuGet packages, dnlib-written hosts and APKs.</summary>
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
        var (exitCode, log) = Tools.Dotnet(HelloProject, ["publish", "-c", "Release", "-r", Rid, "-p:PublishSingleFile=true", "-o", output, .. args]);
        Assert.True(exitCode == 0, $"dotnet publish {name} failed:\n{log}");
        return Path.Combine(output, OperatingSystem.IsWindows() ? "Hello.exe" : "Hello");
    }

    public void Dispose() => _dir.Dispose();

    /// <summary>A .nupkg from the global packages folder (restore guarantees the server's own dependencies are there).</summary>
    public static string NuGetPackage(string id)
    {
        var root = Environment.GetEnvironmentVariable("NUGET_PACKAGES")
                   ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
        // Newest version; the cache may hold several.
        var package = Directory.EnumerateDirectories(Path.Combine(root, id.ToLowerInvariant()))
            .OrderByDescending(d => Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : new Version())
            .SelectMany(d => Directory.EnumerateFiles(d, "*.nupkg"))
            .FirstOrDefault();
        Assert.True(package != null, $"{id} is not in the NuGet cache at {root}");
        return package!;
    }

    /// <summary>A minimal native (non-.NET) PE32+ DLL with one code section.</summary>
    public static byte[] NativeLibrary()
    {
        var blob = new System.Reflection.Metadata.BlobBuilder();
        new NativePe().Serialize(blob);
        return blob.ToArray();
    }

    private sealed class NativePe() : System.Reflection.PortableExecutable.PEBuilder(
        System.Reflection.PortableExecutable.PEHeaderBuilder.CreateLibraryHeader(), deterministicIdProvider: null)
    {
        protected override System.Collections.Immutable.ImmutableArray<Section> CreateSections() =>
            [new Section(".text", System.Reflection.PortableExecutable.SectionCharacteristics.ContainsCode |
                                  System.Reflection.PortableExecutable.SectionCharacteristics.MemExecute |
                                  System.Reflection.PortableExecutable.SectionCharacteristics.MemRead)];

        protected override System.Reflection.Metadata.BlobBuilder SerializeSection(string name, System.Reflection.PortableExecutable.SectionLocation location)
        {
            var section = new System.Reflection.Metadata.BlobBuilder();
            section.WriteBytes(0xC3, 16);
            return section;
        }

        protected override System.Reflection.PortableExecutable.PEDirectoriesBuilder GetDirectories() => new();
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
        // MVID derived from the name: deterministic bytes keep fuzz failures reproducible.
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
                // Deterministic bytes.
                entry.LastWriteTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
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

    /// <summary>Appends entries and a v6 manifest to a real bundle; entries without Data keep the given (corrupt) offsets.</summary>
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
            // deps.json / runtimeconfig.json locations, flags.
            w.Write(new byte[40]);
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

    [Fact]
    public void A_streamed_bundle_reads_its_manifest_and_entries_past_the_image()
    {
        InspectionService.FileSummary Summary(long streamAbove) => new InspectionService(_workspace) { StreamAbove = streamAbove }.Summarize(null, fx.Bundle, default);
        var whole = Summary(FileInput.StreamAbove);
        var streamed = Summary(64);
        Assert.Equal(".NET single-file bundle", streamed.Container);
        Assert.Equal(whole.Assemblies.Select(a => (a.Path, a.Sha256)), streamed.Assemblies.Select(a => (a.Path, a.Sha256)));
        Assert.Equal(whole.File.Type, streamed.File.Type);
        // The macOS bundler extends __LINKEDIT over the bundle (for code signing), so there it is part of the image.
        if (!OperatingSystem.IsMacOS())
            Assert.Contains(streamed.Notes, n => n.Contains("(an overlay) are not held", StringComparison.Ordinal));
    }

    [Fact]
    public void Blazor_folder_without_its_assemblies_is_not_found()
    {
        var app = Path.Combine(_dir.Path, "app");
        Directory.CreateDirectory(Path.Combine(app, "_framework"));
        File.WriteAllText(Path.Combine(app, "_framework", "blazor.boot.json"),
            """{ "resources": { "wasmNative": { "dotnet.native.wasm": "sha256-a" }, "assembly": { "App.wasm": "sha256-b", "Lib.wasm": "sha256-c" } } }""");
        foreach (var call in new Action[]
                 {
                     () => Unpacker.Unpack(app, null, load: false, AnalysisLimits.Default, default),
                     () => Unpacker.List(app, AnalysisLimits.Default, default),
                     () => Unpacker.Search(Path.Combine(app, "_framework"), "Main", SymbolKind.Type, 10, AnalysisLimits.Default, default),
                 })
        {
            var ex = Assert.Throws<ToolError>(call);
            Assert.Equal(ErrorCode.NotFound, ex.Code);
            Assert.Contains("lists 2 assemblies; none is present", ex.Message);
        }
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

    [Fact]
    public void Single_file_bundle_extracts_the_app_and_its_host_files()
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

    [Trait("Speed", "Slow")]
    [Fact]
    public void Compressed_self_contained_bundle_inflates_every_entry()
    {
        var r = Unpack(fx.CompressedBundle);

        Assert.Equal(".NET single-file bundle", r.Container);
        Assert.Equal(Sha(fx.HelloDll), Entry(r, "Hello.dll").Sha256);
        var corelib = Entry(r, "System.Private.CoreLib.dll");
        Assert.Equal(".NET assembly", corelib.Kind);
        Assert.Contains("deflate", corelib.Origin);
        // The whole runtime is extracted and every file is listed, app first (unpack_container pages them).
        var written = Directory.EnumerateFiles(r.OutputDirectory, "*", SearchOption.AllDirectories).Count(f => !f.EndsWith(".corvus-unpack", StringComparison.Ordinal));
        Assert.True(written > 100);
        Assert.Equal(written, r.Files.Count);
        Assert.Equal("Hello.dll", Path.GetFileName(r.Files.First(f => f.Kind == ".NET assembly").Path));
        Assert.DoesNotContain(r.Notes, n => n.StartsWith("Skipped"));
    }

    [Fact]
    public void Unpacking_again_reuses_the_output_but_an_unrelated_directory_is_refused()
    {
        var output = _dir.File("reuse");
        var first = Unpack(fx.Bundle, output: output);
        var second = Unpack(fx.Bundle, output: output);
        Assert.Equal(first.Files.Select(f => f.Path), second.Files.Select(f => f.Path));

        var other = Save("other.nupkg", System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4")));
        Assert.Contains("not empty", Assert.Throws<ToolError>(() => Unpack(other, output: output)).Message);
    }

    [Theory]
    [InlineData("dnlib", "dnlib.dll")]
    [InlineData("K4os.Compression.LZ4", "K4os.Compression.LZ4.dll")]
    public void A_NuGet_package_extracts_and_loads_each_target_framework_copy(string id, string dll)
    {
        var r = Unpack(ContainerFixtures.NuGetPackage(id), load: true);

        Assert.Equal("NuGet package", r.Container);
        var assemblies = r.Files.Where(f => Path.GetFileName(f.Path) == dll).ToList();
        // One per target framework.
        Assert.NotEmpty(assemblies);
        Assert.All(assemblies, f => Assert.Equal(".NET assembly", f.Kind));
        Assert.All(assemblies, f => Assert.NotNull(f.LoadedAs));
        Assert.All(assemblies, f => Assert.Contains($"{Path.DirectorySeparatorChar}lib{Path.DirectorySeparatorChar}", f.Path));
        // The copy this test runs against came from the same package.
        var used = Path.Combine(AppContext.BaseDirectory, dll);
        Assert.Contains(assemblies, f => f.Sha256 == Sha(used));
    }

    [Fact]
    public void Nested_packages_are_opened_into_their_own_folders()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var r = Unpack(Save("bundle.zip", ContainerFixtures.Zip(("packages/k4os.nupkg", nupkg))));

        Assert.Equal("zip archive", r.Container);
        Assert.Contains("packages/k4os.nupkg: NuGet package.", r.Notes);
        Assert.Contains(r.Files, f => f.Path.Contains("k4os.nupkg_unpacked") && f.Path.EndsWith("K4os.Compression.LZ4.dll"));
    }

    [Fact]
    public void Costura_host_extracts_compressed_and_plain_embedded_assemblies()
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
        // The host comes first and is loaded from the source file.
        Assert.Equal((UnpackService.HostOrigin, "CosturaHost"), (r.Files[0].Origin, r.Files[0].LoadedAs));
        Assert.Equal(System.IO.Path.GetFileName(r.Source), System.IO.Path.GetFileName(r.Files[0].Path));
        var a = Entry(r, "testfixture.dll");
        Assert.Equal(Blob.Sha256(fixture), a.Sha256);
        Assert.Equal("Costura resource costura.testfixture.dll.compressed (deflate)", a.Origin);
        Assert.Equal("TestFixture", a.LoadedAs);
        Assert.Equal(Blob.Sha256(consumer), Entry(r, "testfixture.consumer.dll").Sha256);
    }

    [Fact]
    public void Plain_assembly_is_not_a_container()
    {
        var r = Unpack(Env.FixturePath);
        Assert.Equal("none", r.Container);
        Assert.Empty(r.Files);
        Assert.Contains(r.Notes, n => n.Contains("plain .NET assembly"));
    }

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
    public void APK_style_zip_decodes_XALZ_and_assembly_stores()
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

        Assert.Contains(r.Files, f => f.Path.EndsWith("icon.png") && f.LoadedAs == null);
        Assert.Contains(r.Files, f => f.Path.EndsWith("classes.dex") && f.LoadedAs == null);
        Assert.Equal(7, r.Files.Count);
    }

    // Packages without .NET code: stub manifest and dex bytes beside a resource.
    [Theory]
    [InlineData("app.aab", "Android App Bundle (no .NET runtime or assemblies)", "BundleConfig.pb", "base/manifest/AndroidManifest.xml", "base/dex/classes.dex", "base/res/raw/notes.txt")]
    [InlineData("app.apk", "Android package (no .NET runtime or assemblies)", "AndroidManifest.xml", "classes.dex", "res/raw/notes.txt")]
    public void An_android_package_without_assemblies_writes_every_member(string name, string container, params string[] members)
    {
        var output = _dir.File("out-" + Path.GetFileNameWithoutExtension(name));
        var zip = ContainerFixtures.Zip([.. members.Select(m => (m, m.EndsWith(".dex") ? "dex\n035\0"u8.ToArray() : Encoding.UTF8.GetBytes(m)))]);
        var r = Unpack(Save(name, zip), output: output);

        Assert.Equal(container, r.Container);
        Assert.Equal(members.Order(), r.Files.Select(f => Path.GetRelativePath(output, f.Path).Replace('\\', '/')).Order());
    }

    [Fact]
    public void An_android_package_writes_each_member_whose_bytes_repeat()
    {
        var output = _dir.File("out-repeat");
        var dll = System.IO.File.ReadAllBytes(Env.ConsumerPath);
        var zip = ContainerFixtures.Zip(
            ("AndroidManifest.xml", [0x03, 0x00, 0x08, 0x00]),
            ("lib/x86/TestFixture.Consumer.dll", dll),
            ("lib/arm64-v8a/TestFixture.Consumer.dll", dll),
            ("res/raw/a.txt", "same"u8.ToArray()),
            ("res/raw/b.txt", "same"u8.ToArray()));
        var r = Unpack(Save("repeat.apk", zip), output: output, load: true);

        Assert.Equal(5, r.Files.Count);
        var loaded = r.Files.Where(f => f.Path.EndsWith(".dll")).Select(f => f.LoadedAs).ToList();
        Assert.Equal(2, loaded.Count);
        Assert.NotNull(loaded[0]);
        Assert.Equal(loaded[0], loaded[1]);
    }

    [Trait("Smoke", "push")]
    [Fact]
    public void Standalone_XALZ_file_is_decompressed()
    {
        var r = Unpack(Save("TestFixture.dll", ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath))));
        Assert.Equal("Xamarin XALZ", r.Container);
        Assert.Equal(Sha(Env.FixturePath), Assert.Single(r.Files).Sha256);
    }

    [Fact]
    public void A_bundle_header_offset_outside_the_file_is_refused()
    {
        var bytes = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bytes, long.MaxValue - 4);
        Assert.Contains("outside the file", Assert.Throws<ToolError>(() => Unpack(Save("a.exe", bytes))).Message);
        ContainerFixtures.SetBundleHeaderOffset(bytes, -1);
        Assert.Contains("outside the file", Assert.Throws<ToolError>(() => Unpack(Save("b.exe", bytes))).Message);
    }

    [Fact]
    public void A_truncated_or_implausible_bundle_manifest_is_refused()
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
    public void Bundle_entries_with_bad_offsets_sizes_or_compression_are_skipped_with_notes()
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
            Assert.Contains(r.Notes, n => n.StartsWith($"{name}: damaged (", StringComparison.Ordinal));
    }

    [Fact]
    public void PE_corrupt_headers_fall_back_to_carving()
    {
        var lfanew = System.IO.File.ReadAllBytes(Env.FixturePath);
        BinaryPrimitives.WriteInt32LittleEndian(lfanew.AsSpan(0x3C), int.MaxValue);
        Assert.Null(PeImage.TryParse(lfanew));
        // Not a container: nothing to unpack.
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Unpack(Save("lfanew.dll", lfanew))).Code);

        var sections = System.IO.File.ReadAllBytes(Env.FixturePath);
        int pe = BinaryPrimitives.ReadInt32LittleEndian(sections.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt16LittleEndian(sections.AsSpan(pe + 6), 0xFFFF);
        Assert.Null(PeImage.TryParse(sections));
        Assert.Equal(ErrorCode.Unsupported, Assert.Throws<ToolError>(() => Unpack(Save("sections.dll", sections))).Code);
    }

    [Fact]
    public void A_corrupt_or_implausible_XALZ_size_is_refused()
    {
        var xalz = ContainerFixtures.Xalz(System.IO.File.ReadAllBytes(Env.FixturePath));
        var wrongSize = xalz.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(wrongSize.AsSpan(8), 123);
        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => Unpack(Save("a.dll", wrongSize))).Message);

        // A 400 MB size claim in a 20-byte chunk is rejected before allocating.
        byte[] bomb = [.. "XALZ"u8, 0, 0, 0, 0, .. BitConverter.GetBytes(400u << 20), .. new byte[8]];
        Assert.Null(Blob.TryXalz(bomb, AnalysisLimits.Default.MaxItemBytes));
        Assert.Contains("corrupt XALZ", Assert.Throws<ToolError>(() => Unpack(Save("b.dll", bomb))).Message);
    }

    [Fact]
    public void A_zip_with_a_bad_central_directory_or_entry_keeps_the_readable_entries()
    {
        var zip = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        int eocd = zip.AsSpan().LastIndexOf("PK\x05\x06"u8);
        var badDirectory = zip.ToArray();
        // Central directory offset.
        BinaryPrimitives.WriteUInt32LittleEndian(badDirectory.AsSpan(eocd + 16), uint.MaxValue - 100);
        // Without a central directory, entries are read from local headers.
        var recovered = Unpack(Save("a.nupkg", badDirectory));
        Assert.Contains(recovered.Notes, n => n.StartsWith("Damaged zip"));
        Assert.Contains(recovered.Files, f => f.Path.EndsWith("K4os.Compression.LZ4.dll"));

        // Overwritten stored data fails the CRC for that entry only.
        var apk = ContainerFixtures.Zip(("a.dll", ContainerFixtures.Module("A")), ("b.dll", ContainerFixtures.Module("B")));
        int local = apk.AsSpan().IndexOf("PK\x03\x04"u8);
        int dataStart = local + 30 + BinaryPrimitives.ReadUInt16LittleEndian(apk.AsSpan(local + 26)) + BinaryPrimitives.ReadUInt16LittleEndian(apk.AsSpan(local + 28));
        apk.AsSpan(dataStart, 32).Fill(0xAA);
        var r = Unpack(Save("b.zip", apk));
        Assert.Contains(r.Files, f => f.Path.EndsWith("b.dll"));
    }

    [Fact]
    public void Costura_bad_deflate_resource_is_noted()
    {
        var host = ContainerFixtures.Module("Host", ("costura.broken.dll.compressed", [0xFF, 0xFF, 0xFF, 0xFF, 0x00]));
        var r = Unpack(Save("host.exe", host));
        // Only the host.
        Assert.Equal(UnpackService.HostOrigin, Assert.Single(r.Files).Origin);
        Assert.Contains(r.Notes, n => n.Contains("costura.broken.dll.compressed") && n.Contains("deflate"));
    }

    /// <summary>Fuzz iterations per fixture; override with CORVUS_FUZZ_CASES.</summary>
    private static readonly int FuzzCases = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_FUZZ_CASES"), out var n) ? n : 40;

    [Trait("Speed", "Slow")]
    [Fact]
    public void Truncated_and_fuzzed_inputs_fail_cleanly()
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
            // Truncated inside the manifest.
            if (name == "bundle")
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
                    // Half the mutations target the first 4 KB (headers).
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
                    // list_assemblies on a container.
                    new UnpackService(ws).List(input, AnalysisLimits.Default, default);
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

    private static readonly string[] EscapingNames =
    [
        "../outside1.dll",
        "../../../../../outside2.dll",
        @"..\..\..\outside3.dll",
        "/abs/outside4.dll",
        @"\\server\share\outside5.dll",
        "C:/Windows/outside6.dll",
        @"C:..\outside7.dll",
        "assemblies/../../../../outside8.dll",
        "a/./../b/../../../outside9.exe",
        "....//....//outside10.dll",
        "%2e%2e/outside11.dll",
        "CON.dll",
        "outside12.dll\0.txt",
    ];

    /// <summary>Unpacks five levels deep in a sandbox so escapes of up to five levels are caught.</summary>
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
        Assert.False(System.IO.File.Exists(@"C:\Windows\outside6.dll"));
        check?.Invoke(r);
    }

    // Distinct content, or duplicates are skipped.
    private static byte[] Content(int i) => Encoding.UTF8.GetBytes($"content {i}");

    [Fact]
    public void Zip_entries_with_traversal_names_stay_inside_the_output() =>
        AssertContained(ContainerFixtures.Zip([.. EscapingNames.Select((n, i) => (n, Content(i)))]), "escaping.zip", r =>
        {
            // An unpack takes every file of a plain zip; "outside12.dll\0.txt" is a .txt.
            Assert.Equal(EscapingNames.Length, r.Files.Count);
            Assert.DoesNotContain(r.Files, f => f.Path.Contains("outside12") && f.Path.EndsWith(".dll"));
            Assert.Contains(r.Files, f => f.Path.EndsWith("outside9.exe.bin"));
            Assert.Contains(r.Files, f => Path.GetFileName(f.Path) == "_CON.dll");
        });

    [Fact]
    public void Bundle_entries_with_traversal_names_stay_inside_the_output() =>
        AssertContained(ContainerFixtures.WithManifest(System.IO.File.ReadAllBytes(fx.Bundle),
            EscapingNames.Select((n, i) => new ContainerFixtures.BundleEntry(n, Content(i)))), "escaping.exe",
            r => Assert.Equal(EscapingNames.Length, r.Files.Count));

    [Fact]
    public void Costura_resources_with_traversal_names_stay_inside_the_output() =>
        AssertContained(ContainerFixtures.Module("Host", [.. EscapingNames.Where(n => !n.Contains('\0')).Select((n, i) => ("costura." + n, Content(i)))]), "escaping.dll",
            // Metadata strings cannot hold NUL; + the host itself.
            r => Assert.Equal(EscapingNames.Length - 1 + 1, r.Files.Count));

    [Fact]
    public void Nested_containers_with_traversal_names_stay_inside_the_output()
    {
        var inner = ContainerFixtures.Zip([.. EscapingNames.Select((n, i) => (n, Content(i)))]);
        var outer = ContainerFixtures.Zip(("../../../../inner.nupkg", inner), ("/abs/inner2.zip", ContainerFixtures.Zip(("../../deep.dll", Content(99)))));
        AssertContained(outer, "outer.zip", r =>
        {
            // Rooted names keep their nesting folder.
            Assert.Contains(r.Files, f => f.Path.Contains("inner2.zip_unpacked") && f.Path.EndsWith("deep.dll"));
            Assert.Equal(2 + EscapingNames.Length + 1, r.Files.Count);
        });
    }

    [Fact]
    public void Container_at_the_nesting_limit_is_noted()
    {
        var inner = ContainerFixtures.Zip(("b.zip", ContainerFixtures.Zip(("c.dll", Content(1)))));
        var path = Save("nested.zip", ContainerFixtures.Zip(("a.zip", inner)));
        var r = Unpacker.Unpack(path, _dir.File("nested-out"), load: false, AnalysisLimits.Default with { MaxDepth = 2 }, default);
        Assert.Contains("b.zip: a container 2 levels deep, not opened (the nesting limit).", r.Notes);
    }

    [Fact]
    public void File_and_directory_with_the_same_name_is_noted_not_fatal()
    {
        var zip = ContainerFixtures.Zip(("lib.dll", Content(1)), ("lib.dll/inner.dll", Content(2)));
        AssertContained(zip, "clash.zip", r =>
        {
            Assert.Single(r.Files);
            Assert.Contains(r.Notes, n => n.StartsWith("Could not write"));
        });
    }
}
