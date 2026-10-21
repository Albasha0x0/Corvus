using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Elf;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Il2Cpp builds for Android, iOS, macOS and Linux: the binary layout the reader uses on ELF and Mach-O (code and data
/// areas, Thumb pointers, memory images, encrypted and universal binaries) on real runtime libraries and synthetic images.
/// </summary>
public sealed class Il2CppMobileTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void ElfLayoutHasCodeAndDataAreasAndFileOffsets()
    {
        var bytes = File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim);
        var opened = Il2CppBinaryLayout.Open(bytes, "libdbgshim.so");
        var layout = opened.Layout;
        Assert.False(opened.MemoryImage);
        Assert.Equal((ImageFormat.Elf, NativeArch.Arm64, true, 0UL), (layout.Format, layout.Arch, layout.Is64, layout.ImageBase));
        Assert.False(layout.ThumbPointers);
        var text = Assert.Single(layout.Areas, a => a.Name == ".text");
        Assert.True(text.Executable && !text.InitializedData);
        Assert.True(layout.InCode(layout.ImageBase + text.Rva + 4));
        Assert.Contains(layout.Areas, a => a.Name.StartsWith(".data", StringComparison.Ordinal) && a.InitializedData);
        Assert.DoesNotContain(layout.Areas, a => (a.Name.StartsWith(".rela", StringComparison.Ordinal) || a.Name == ".dynsym") && a.InitializedData);
        var image = ElfFile.FromBytes(bytes);
        Assert.True(image.TryRvaToFileOffset(text.Rva + 8, out var offset));
        Assert.Equal((ulong)offset, layout.FileOffset(text.Rva + 8));
        Assert.Equal(image.BuildId, layout.BuildId);
    }

    [Fact]
    public void Arm32CodePointersLoseTheThumbBit()
    {
        var layout = Il2CppBinaryLayout.Open(File.ReadAllBytes(NativeFixtures.LinuxArmDbgShim), "libdbgshim.so").Layout;
        Assert.True(layout.ThumbPointers);
        var text = Assert.Single(layout.Areas, a => a.Name == ".text");
        ulong thumb = layout.ImageBase + text.Rva + 0x11;
        Assert.Equal(text.Rva + 0x10, layout.CodeRva(thumb));
        Assert.Equal(text.Rva + 0x11, layout.Rva(thumb)); // data pointers keep every bit
    }

    [Fact]
    public void ElfMemoryImageIsReadAtItsAddresses()
    {
        var file = File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim);
        var image = ElfFile.FromBytes(file);
        // The loaded-library layout: every PT_LOAD at its address, the file as long as the image.
        var dump = new byte[image.SizeOfImage];
        foreach (var s in image.LoadSegments)
            file.AsSpan((int)s.Offset, (int)s.FileSize).CopyTo(dump.AsSpan((int)(s.VirtualAddress - image.ImageBase)));
        var opened = Il2CppBinaryLayout.Open(dump, "libdbgshim.so");
        Assert.True(opened.MemoryImage);
        Assert.Contains("memory image", opened.Note);
        var text = Assert.Single(opened.Layout.Areas, a => a.Executable);
        Assert.True(image.TryRvaToFileOffset(text.Rva + 0x20, out var built));
        Assert.Equal((ulong)built, opened.Layout.FileOffset(text.Rva + 0x20)); // offsets in the file as built
        // The bytes handed to the library describe the image at its addresses and no longer name the file's sections.
        var normalized = ElfFile.FromBytes(opened.Bytes);
        Assert.All(normalized.LoadSegments, s => Assert.Equal(s.VirtualAddress - normalized.ImageBase, s.Offset));
        Assert.Empty(normalized.SectionHeaders);
        var expected = new byte[64];
        var actual = new byte[64];
        image.Read(text.Rva, expected);
        normalized.Read(text.Rva, actual);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MachOLayoutRefusesEncryptedCodeAndReadsTheChosenSlice()
    {
        var w = new MachOWriter { Encryption = (MachOWriter.TextOffset, 0x2000, 1) };
        var error = Assert.Throws<ToolError>(() => Il2CppBinaryLayout.Open(w.Build(), "UnityFramework"));
        Assert.Equal(ErrorCode.Unsupported, error.Code);
        Assert.Contains("encrypted_fairplay", error.Message);
        Assert.Contains("decrypted", error.Remediation);

        w.Encryption = null;
        var thin = w.Build();
        var fat = MachOWriter.Fat([(MachOWriter.CpuX64, 3, new MachOWriter { CpuType = MachOWriter.CpuX64 }.Build()), (MachOWriter.CpuArm64, 0, thin)]);
        var opened = Il2CppBinaryLayout.Open(fat, "GameAssembly.dylib", "arm64");
        Assert.Equal(thin, opened.Bytes);
        Assert.Equal((ImageFormat.MachO, NativeArch.Arm64), (opened.Layout.Format, opened.Layout.Arch));
        Assert.Contains("slice arm64", opened.Note);
        Assert.Contains(opened.Layout.Areas, a => a.Name.StartsWith("__TEXT", StringComparison.Ordinal) && a.Executable);
        Assert.All(opened.Layout.Areas.Where(a => a.InitializedData), a => Assert.StartsWith("__DATA", a.Name, StringComparison.Ordinal));

        var other = Assert.Throws<ToolError>(() => Il2CppBinaryLayout.Open([0xCA, 0xFE, 0xD0, 0x0D, 0, 0, 0, 0], "x.bin"));
        Assert.Contains("binary_format_unsupported", other.Message);
    }

    [Fact]
    public void MetadataVersionsUpToUnity6AreAccepted()
    {
        foreach (var version in new[] { 24, 31, 39 })
        {
            var path = _dir.File($"v{version}.dat");
            var bytes = new byte[0x100];
            BitConverter.TryWriteBytes(bytes.AsSpan(0), 0xFAB11BAF);
            BitConverter.TryWriteBytes(bytes.AsSpan(4), version);
            File.WriteAllBytes(path, bytes);
            Assert.Equal(version, Il2CppMetadataReader.CheckHeader(path));
        }
        output.WriteLine($"versions {Il2CppMetadataReader.MinVersion}-{Il2CppMetadataReader.MaxVersion}");
    }

    private static readonly byte[] MetadataBytes = [0xAF, 0x1B, 0xB1, 0xFA, 31, 0, 0, 0];

    private string Put(string relative, byte[]? bytes = null)
    {
        var path = _dir.File(relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes ?? [0x7F, 0x45, 0x4C, 0x46]);
        return path;
    }

    [Fact]
    public void GameFilesAreFoundInEveryPlatformLayout()
    {
        // Android, extracted: lib/<abi>/libil2cpp.so, assets/bin/Data/Managed/Metadata.
        var arm64 = Put("apk/lib/arm64-v8a/libil2cpp.so");
        var armv7 = Put("apk/lib/armeabi-v7a/libil2cpp.so");
        var metadata = Put("apk/assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes);
        foreach (var path in new[] { _dir.File("apk"), metadata, arm64 })
        {
            var files = Assert.IsType<Il2CppGameFiles>(Il2CppGameFiles.Find(path));
            Assert.Equal((arm64, metadata, "android"), (files.Binary, files.Metadata, files.Platform));
            Assert.EndsWith(Path.Combine("assets", "bin", "Data"), files.DataDirectory);
        }
        Assert.Equal(armv7, Il2CppGameFiles.Find(armv7)!.Binary);
        Assert.Equal(armv7, Il2CppGameFiles.Find(_dir.File("apk"), "armv7")!.Binary);
        var missing = Assert.Throws<ToolError>(() => Il2CppGameFiles.Find(_dir.File("apk"), "x86"));
        Assert.Equal(ErrorCode.NotFound, missing.Code);
        Assert.Contains("arm64-v8a", missing.Message);

        // iOS: Frameworks/UnityFramework.framework/UnityFramework, Data/Managed/Metadata; found inside a Payload folder too.
        var framework = Put("Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework");
        var iosMetadata = Put("Payload/Game.app/Data/Managed/Metadata/global-metadata.dat", MetadataBytes);
        foreach (var path in new[] { _dir.File("Payload"), _dir.File("Payload/Game.app"), iosMetadata, framework })
            Assert.Equal((framework, iosMetadata, "ios"), Il2CppGameFiles.Find(path) is { } f ? (f.Binary, f.Metadata, f.Platform) : default);
        var universal = Il2CppGameFiles.Find(_dir.File("Payload/Game.app"), "arm64")!;
        Assert.Equal("arm64", universal.Slice);

        // macOS .app and Linux.
        var dylib = Put("Mac.app/Contents/Frameworks/GameAssembly.dylib");
        var macMetadata = Put("Mac.app/Contents/Resources/Data/il2cpp_data/Metadata/global-metadata.dat", MetadataBytes);
        Assert.Equal((dylib, macMetadata, "macos"), Il2CppGameFiles.Find(macMetadata) is { } m ? (m.Binary, m.Metadata, m.Platform) : default);
        Assert.Equal(dylib, Il2CppGameFiles.Find(_dir.File("Mac.app"))!.Binary);
        var so = Put("linux/GameAssembly.so");
        var linuxMetadata = Put("linux/Game_Data/il2cpp_data/Metadata/global-metadata.dat", MetadataBytes);
        Assert.Equal((so, linuxMetadata, "linux"), Il2CppGameFiles.Find(linuxMetadata) is { } l ? (l.Binary, l.Metadata, l.Platform) : default);

        // Side by side.
        var lone = Put("flat/libil2cpp.so");
        Assert.Equal((lone, "android"), Il2CppGameFiles.Find(Put("flat/global-metadata.dat", MetadataBytes)) is { } s ? (s.Binary, s.Platform) : default);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => Il2CppGameFiles.Find(Put("half/assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes))).Code);
    }

    /// <summary>A zip of (path, bytes) entries.</summary>
    private static byte[] Zip(params (string Path, byte[] Bytes)[] entries)
    {
        using var stream = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(stream, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (path, bytes) in entries)
            {
                using var s = zip.CreateEntry(path).Open();
                s.Write(bytes);
            }
        return stream.ToArray();
    }

    [Fact]
    public void PackagesYieldTheirGameFiles()
    {
        var cache = _dir.File("cache");
        byte[] lib64 = [0x7F, 0x45, 0x4C, 0x46, 2], lib32 = [0x7F, 0x45, 0x4C, 0x46, 1];
        var bundle = new byte[0x20000];
        "UnityFS"u8.CopyTo(bundle);
        var apk = Zip(("lib/arm64-v8a/libil2cpp.so", lib64), ("lib/armeabi-v7a/libil2cpp.so", lib32), ("lib/arm64-v8a/libunity.so", [1]),
            ("assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes), ("assets/bin/Data/data.unity3d", bundle), ("classes.dex", [0]));
        var apkPath = Put("in/game.apk", apk);
        var root = Assert.IsType<string>(Il2CppPackages.Extract(apkPath, null, cache));
        var files = Il2CppGameFiles.Find(root)!;
        Assert.Equal(lib64, File.ReadAllBytes(files.Binary));
        Assert.Equal(MetadataBytes, File.ReadAllBytes(files.Metadata));
        Assert.Equal(0x10000, new FileInfo(Path.Combine(files.DataDirectory!, "data.unity3d")).Length); // the version header only
        Assert.True(File.Exists(Path.Combine(root, "lib", "arm64-v8a", "libunity.so"))); // the ABI's other libraries, for P/Invoke checks
        Assert.False(Directory.Exists(Path.Combine(root, "lib", "armeabi-v7a")));
        Assert.Equal(root, Il2CppPackages.Extract(apkPath, null, cache)); // cached
        var v7 = Il2CppPackages.Extract(apkPath, "armeabi-v7a", cache)!;
        Assert.Equal(lib32, File.ReadAllBytes(Il2CppGameFiles.Find(v7)!.Binary));
        Assert.Contains("ABIs:", Assert.Throws<ToolError>(() => Il2CppPackages.Extract(apkPath, "x86", cache)).Message);

        // Split set: metadata in the base APK, the library in its ABI split.
        var xapk = Put("in/game.xapk", Zip(("com.example.game.apk", Zip(("assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes), ("classes.dex", [0]))),
            ("config.armeabi_v7a.apk", Zip(("lib/armeabi-v7a/libil2cpp.so", lib32))), ("manifest.json", [0x7B, 0x7D])));
        var split = Il2CppGameFiles.Find(Il2CppPackages.Extract(xapk, null, cache)!)!;
        Assert.Equal(lib32, File.ReadAllBytes(split.Binary));
        Assert.Equal("android", split.Platform);

        var aab = Put("in/game.aab", Zip(("base/lib/arm64-v8a/libil2cpp.so", lib64), ("base/assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes)));
        Assert.Equal(lib64, File.ReadAllBytes(Il2CppGameFiles.Find(Il2CppPackages.Extract(aab, null, cache)!)!.Binary));
        // An app bundle saved as .apk is known by its content; the same bytes give the same answer under any name.
        byte[] bundleBytes = Zip(("BundleConfig.pb", [0]), ("base/manifest/AndroidManifest.xml", [0]), ("base/lib/arm64-v8a/libil2cpp.so", lib64),
            ("base/assets/bin/Data/Managed/Metadata/global-metadata.dat", MetadataBytes));
        foreach (var name in new[] { "in/bundle.apk", "in/bundle-copy.aab" })
            Assert.Equal(lib64, File.ReadAllBytes(Il2CppGameFiles.Find(Il2CppPackages.Extract(Put(name, bundleBytes), null, cache)!)!.Binary));

        var ipa = Put("in/game.ipa", Zip(("Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework", [0xCF, 0xFA, 0xED, 0xFE]),
            ("Payload/Game.app/Data/Managed/Metadata/global-metadata.dat", MetadataBytes), ("Payload/Game.app/Data/globalgamemanagers", [5])));
        var ios = Il2CppGameFiles.Find(Il2CppPackages.Extract(ipa, null, cache)!)!;
        Assert.Equal(("ios", "UnityFramework"), (ios.Platform, Path.GetFileName(ios.Binary)));
        Assert.True(File.Exists(Path.Combine(ios.DataDirectory!, "globalgamemanagers")));

        Assert.Null(Il2CppPackages.Extract(Put("in/plain.apk", Zip(("classes.dex", [0]))), null, cache));
    }

    [Fact]
    public async Task LoadAssemblyReadsAPackageAndReportsWhyNot()
    {
        var apk = Put("in/enc.apk", Zip(("lib/arm64-v8a/libil2cpp.so", File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim)),
            ("assets/bin/Data/Managed/Metadata/global-metadata.dat", [0xDE, 0xAD, 0xBE, 0xEF, 31, 0, 0, 0])));
        using var ws = new AssemblyWorkspace();
        var error = await Assert.ThrowsAsync<ToolError>(() => Tools(ws).LoadAssembly(apk));
        Assert.Contains("encrypted_or_transformed", error.Message);
        Assert.Empty(ws.Assemblies);
    }

    private static Corvus.Tools.WorkspaceTools Tools(AssemblyWorkspace ws)
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        var il2cpp = new Il2CppService(ws);
        return new Corvus.Tools.WorkspaceTools(ws, il2cpp, new IndexingService(ws, new CallGraphService(ws), options),
            new Corvus.Services.Analysis.UnpackService(ws));
    }

    [Fact]
    public void CacheTrimLeavesEntriesUsedRecentlyForOtherReaders()
    {
        var root = _dir.File("trim");
        string Entry(string name, TimeSpan age)
        {
            var dir = Directory.CreateDirectory(Path.Combine(root, name)).FullName;
            File.WriteAllText(Path.Combine(dir, Il2CppRawLoader.MarkerFileName), "{}");
            Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow - age);
            return dir;
        }
        var recent = Enumerable.Range(0, Il2CppRawLoader.MaxEntries + 2).Select(i => Entry($"recent{i}", TimeSpan.FromSeconds(i))).ToList();
        var old = Enumerable.Range(0, 2).Select(i => Entry($"old{i}", TimeSpan.FromHours(1 + i))).ToList();
        using var ws = new AssemblyWorkspace();
        new Il2CppRawLoader(ws).Trim(root, recent[0]);
        Assert.All(recent, d => Assert.True(Directory.Exists(d), d)); // beyond the limit, but maybe in use elsewhere
        Assert.All(old, d => Assert.False(Directory.Exists(d), d));
    }

    [Fact]
    public void PackageTrimLeavesExtractionsUsedRecentlyForOtherReaders()
    {
        var root = _dir.File("packages-trim");
        string Entry(string name, TimeSpan age)
        {
            var dir = Directory.CreateDirectory(Path.Combine(root, name)).FullName;
            File.WriteAllText(Path.Combine(dir, Il2CppPackages.MarkerFileName), "{}");
            Directory.SetLastWriteTimeUtc(dir, DateTime.UtcNow - age);
            return dir;
        }
        var recent = Enumerable.Range(0, Il2CppPackages.MaxPackages + 2).Select(i => Entry($"recent{i}", TimeSpan.FromSeconds(i))).ToList();
        var old = Enumerable.Range(0, 2).Select(i => Entry($"old{i}", TimeSpan.FromHours(1 + i))).ToList();
        Il2CppPackages.Trim(root, recent[0]);
        Assert.All(recent, d => Assert.True(Directory.Exists(d), d)); // beyond the limit, but a reader may still use its binary
        Assert.All(old, d => Assert.False(Directory.Exists(d), d));
    }

    [Fact]
    public void DumpsNameAnyGameBinaryAndMatchCopiesByIdentity()
    {
        // An Il2CppDumper dump beside libil2cpp.so.
        Put("dump/script.json", "{}"u8.ToArray());
        var lib = Put("dump/libil2cpp.so", File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim));
        Assert.Equal(lib, Il2CppDumpFiles.Locate(_dir.File("dump/DummyDll"))!.GameAssembly);

        // A built-in reader cache entry made from another copy of the same build: recognized by its build id.
        var entry = _dir.File("cache-entry");
        Directory.CreateDirectory(Path.Combine(entry, Il2CppRawLoader.DummyFolder));
        new Il2CppGameModel { BinaryPath = "x", MetadataPath = "y", MetadataVersion = 39, HeaderVersion = 39, UnityVersion = "6000.0.0f1", UnityVersionSource = "test", ImageBase = 0, MemoryImage = false }.Write(Path.Combine(entry, Il2CppGameModel.FileName));
        var image = ElfFile.FromBytes(File.ReadAllBytes(lib));
        var marker = new Il2CppRawLoader.Marker(_dir.File("elsewhere/libil2cpp.so"), "m", "-", "-", 2, "r", DateTime.UtcNow, BinaryIdentity: image.BuildId);
        File.WriteAllText(Path.Combine(entry, Il2CppRawLoader.MarkerFileName), System.Text.Json.JsonSerializer.Serialize(marker));
        var files = Il2CppDumpFiles.Locate(Path.Combine(entry, Il2CppRawLoader.DummyFolder))!;
        Assert.Null(files.GameAssembly); // the original copy is gone
        using var ws = new AssemblyWorkspace();
        Assert.True(files.Describes(ws.LoadAny(lib).Native!));
        Assert.False(files.Describes(ws.LoadAny(NativeFixtures.LinuxMuslArm64DbgShim).Native!));

        Assert.True(Il2CppBinaryLayout.IsArm32(NativeFixtures.LinuxArmDbgShim));
        Assert.False(Il2CppBinaryLayout.IsArm32(lib));
    }

    private const string MobileVariable = "CORVUS_IL2CPP_MOBILE";

    /// <summary>
    /// Real mobile games (CORVUS_IL2CPP_MOBILE: a folder of .apk / .xapk / .aab / .ipa packages and extracted game folders):
    /// each is loaded through load_assembly, every Android package once per ABI it ships, and the counts are reported.
    /// A build LibCpp2IL cannot read must fail with a reason code.
    /// </summary>
    [RequiresRealDataFact(MobileVariable)]
    [Trait("Speed", "Slow")]
    public async Task MobileGamesLoad()
    {
        var root = RealData.Path(MobileVariable);
        var inputs = Directory.EnumerateFiles(root).Where(Il2CppPackages.IsPackage).Concat(Directory.EnumerateDirectories(root)).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(inputs);
        int read = 0;
        foreach (var input in inputs)
            foreach (var abi in new string?[] { null, "armeabi-v7a" })
            {
                using var ws = new AssemblyWorkspace(new ServerOptions { WatchFiles = false });
                var watch = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    var text = await Tools(ws).LoadAssembly(input, slice: abi);
                    read++;
                    var model = Il2CppRawLoader.Model(Path.Combine(Path.GetDirectoryName(ws.Assemblies[0].FilePath)!, "..", Il2CppGameModel.FileName));
                    output.WriteLine($"{Path.GetFileName(input)} [{abi ?? "default"}] {watch.Elapsed.TotalSeconds:0.0} s: metadata v{model.HeaderVersion}, Unity {model.UnityVersion}, " +
                                     $"{model.Types} types, {model.MethodDefinitions} methods ({model.MethodsWithCode} with code), {model.Methods.Count} script methods, " +
                                     $"{ws.Assemblies.Count} dummy assemblies, native {ws.Natives.FirstOrDefault()?.Image.Arch}");
                    Assert.True(model.MethodsWithCode > 0);
                    Assert.Contains("Read Il2Cpp game", text);
                    Downstream(ws, model, abi);
                }
                catch (ToolError e)
                {
                    output.WriteLine($"{Path.GetFileName(input)} [{abi ?? "default"}] {watch.Elapsed.TotalSeconds:0.0} s: {e.Message}");
                    Assert.Matches("reason [a-z0-9_]+|no lib/", e.Message);
                }
            }
        Assert.True(read > 0);
    }

    /// <summary>apply_il2cpp_names on the loaded binary, find_method_by_address round trips (Thumb pointers on 32-bit ARM) and unity_overview.</summary>
    private void Downstream(AssemblyWorkspace ws, Il2CppGameModel model, string? abi)
    {
        var native = Assert.Single(ws.Natives);
        var il2cpp = new Il2CppService(ws);
        var navigator = new Il2CppNavigator(ws, il2cpp, new Il2CppStringService(ws, il2cpp));
        var code = new NativeCodeService(ws, new ServerOptions { BackgroundIndexing = false }, annotations: new Corvus.Native.Annotations.AnnotationStore(_dir.File($"ann-{Guid.NewGuid():N}")));
        bool thumb = native.Image.Arch == Corvus.Native.NativeArch.Arm;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        // The code index (ARM64 only; 32-bit ARM code is not decoded) shows how many method starts its own discovery found.
        var index = thumb ? null : code.Index(native, null, default).GetAwaiter().GetResult();
        if (index != null) output.WriteLine($"  code index: {index.Functions.Count} functions ({watch.Elapsed.TotalSeconds:0.0} s)");
        watch.Restart();
        var names = ws.Read(() => new Il2CppNativeNames(il2cpp, navigator, code).Apply(native, index, ws.Assemblies, default));
        output.WriteLine($"  apply_il2cpp_names: {names.Functions} functions ({names.FunctionsNotDiscovered} not discovered by the code index), {names.SharedFunctions} shared, " +
                         $"{names.MetadataSlots} metadata and {names.MethodInfoSlots} MethodInfo slots ({watch.Elapsed.TotalSeconds:0.0} s)");
        Assert.True(names.Functions > 0);

        var rng = new Random(11);
        var methods = ws.Assemblies.SelectMany(il2cpp.GetIndex).Where(e => e.Rva is > 0 and <= uint.MaxValue).ToList();
        int trips = 0, tried = Math.Min(300, methods.Count);
        foreach (var e in Enumerable.Range(0, tried).Select(_ => methods[rng.Next(methods.Count)]))
        {
            ulong address = model.ImageBase + e.Rva!.Value + (thumb ? 1UL : 0);
            if (ws.Read(() => navigator.Locate(address, "auto", ws.Assemblies)) is [{ Function.IsExactStart: true } r] && r.Methods.Any(m => m.Method == e.Method)) trips++;
        }
        output.WriteLine($"  find_method_by_address round trips{(thumb ? " (Thumb pointers)" : "")}: {trips}/{tried}");
        Assert.Equal(tried, trips);

        // P/Invoke declarations the dummy assemblies keep, checked against the game's own libraries.
        var verifier = new NativeImportVerifier(p => Corvus.Native.NativeImageLoader.Open(p), hostHasSystemDlls: false);
        var verdicts = ws.Read(() => ws.Assemblies.Select(a => verifier.Verify(a, default)).ToList());
        output.WriteLine($"  verify_native_imports ({verdicts.FirstOrDefault()?.Platform.Rid}): {verdicts.Sum(v => v.Checks.Count)} declarations " + string.Join(", ", verdicts.SelectMany(v => v.Checks)
            .GroupBy(c => $"{c.Status}/{c.Reason}").OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {g.Count()}")));
        Assert.All(verdicts, v => Assert.NotEqual("windows", v.Platform.Os));

        var root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(native.FilePath)!)!)!;
        var overview = Corvus.Services.Analysis.UnityOverview.Inspect(root, false, default);
        output.WriteLine($"  unity_overview: {overview.Platform} {overview.Architecture}, backend {overview.Backend.Kind}, metadata {overview.Backend.MetadataState}, next {string.Join(", ", overview.NextSteps.Select(s => s.Action))}");
        if (abi == null && overview.Platform == "android") Assert.Contains(overview.NextSteps, s => s.Action == "apply_il2cpp_names");
    }
}
