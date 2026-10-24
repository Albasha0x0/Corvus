using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Pe;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// The ClrMD side of dump analysis without a real runtime: the data reader over our minidump parser (read-only image
/// fallback, relocations, thread contexts), DAC signature checks and the DAC outcomes a dump without a usable DAC gets.
/// </summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class ManagedDumpTests
{
    private const ulong Preferred = 0x1_8000_0000, Loaded = 0x7FF6_2000_0000;

    /// <summary>A DLL with code, a read-only pointer (relocated), writable data and a base relocation for the pointer.</summary>
    private static (PeFile Pe, uint Text, uint Rdata, uint Data) Image()
    {
        var b = new PeBuilder { ImageBase = Preferred, Characteristics = 0x2022 };
        var text = b.Add(".text", Enumerable.Range(0, 0x40).Select(i => (byte)(0x90 + (i & 1))).ToArray(), 0x60000020);
        var rdata = b.Add(".rdata", rva =>
        {
            var d = new byte[0x20];
            BinaryPrimitives.WriteUInt64LittleEndian(d, Preferred + text.Rva);
            BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(8), 0x1122334455667788);
            return d;
        });
        var data = b.Add(".data", Enumerable.Repeat((byte)0xAB, 0x20).ToArray(), 0xC0000040);
        var reloc = b.Add(".reloc", _ =>
        {
            var r = new byte[12];
            BinaryPrimitives.WriteUInt32LittleEndian(r, rdata.Rva);
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(4), 12);
            BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(8), 0xA000); // DIR64 at offset 0
            return r;
        }, 0x42000040);
        b.Directories[PeDirectory.BaseRelocation] = (reloc.Rva, 12);
        return (PeFile.FromBytes(b.Build()), text.Rva, rdata.Rva, data.Rva);
    }

    private static MinidumpBuilder Dump(PeFile pe, ushort arch = 9, string module = @"Z:\app\native.dll")
    {
        var d = new MinidumpBuilder { ProcessorArchitecture = arch };
        d.Modules.Add(new MinidumpBuilder.Module(Loaded, pe.SizeOfImage, pe.Coff.TimeDateStamp, module));
        d.Memory.Add((0xE0_0000_0000, new byte[0x100]));
        d.Threads.Add(new MinidumpBuilder.Thread(7, 0xE0_0000_0000, MinidumpBuilder.ContextX64(Loaded + 0x1000, 0xE0_0000_0080)));
        return d;
    }

    [Fact]
    public void ReaderServesOnlyReadOnlyImagePartsAndRelocatesThem()
    {
        var (pe, text, rdata, data) = Image();
        var builder = Dump(pe);
        builder.Memory.Add((Loaded + text + 0x10, [1, 2, 3, 4])); // captured bytes win over the image
        using var reader = new DumpDataReader(MinidumpFile.FromBytes(builder.Build()), _ => pe);

        var header = new byte[2];
        Assert.Equal(2, reader.Read(Loaded, header));
        Assert.Equal("MZ"u8.ToArray(), header);

        Assert.True(reader.ReadPointer(Loaded + rdata, out var pointer));
        Assert.Equal(Loaded + text, pointer); // relocated from the preferred base
        Assert.Equal(0x1122334455667788UL, reader.Read<ulong>(Loaded + rdata + 8));

        var code = new byte[0x14];
        Assert.Equal(code.Length, reader.Read(Loaded + text, code));
        Assert.Equal(0x90, code[0]);
        Assert.Equal([1, 2, 3, 4], code[0x10..0x14]);

        Assert.Equal(0, reader.Read(Loaded + data, new byte[4])); // writable: never the initial values
        Assert.False(reader.Read(Loaded + data, out uint _));

        var context = new byte[0x4D0];
        Assert.True(reader.GetThreadContext(7, 0, context));
        Assert.Equal(Loaded + 0x1000, BinaryPrimitives.ReadUInt64LittleEndian(context.AsSpan(0xF8)));
        Assert.False(reader.GetThreadContext(8, 0, context));

        var module = Assert.Single(reader.EnumerateModules());
        Assert.Equal(Loaded, module.ImageBase);
        Assert.Equal((int)pe.SizeOfImage, module.IndexFileSize);
        Assert.Equal(Architecture.X64, reader.Architecture);
        Assert.Equal(8, reader.PointerSize);
    }

    [Fact]
    public void ModulesWithoutHeadersStillHaveTheirDumpRecord()
    {
        var (pe, _, _, _) = Image();
        using var reader = new DumpDataReader(MinidumpFile.FromBytes(Dump(pe).Build()), _ => null);
        var module = Assert.Single(reader.EnumerateModules());
        Assert.Equal(@"Z:\app\native.dll", module.FileName);
        Assert.Equal((int)pe.Coff.TimeDateStamp, module.IndexTimeStamp);
        Assert.Equal(new Version(1, 2, 3, 4), module.Version); // the builder's VS_FIXEDFILEINFO
    }

    [Fact]
    public void DacSignatureMustBeMicrosofts()
    {
        var (pe, _, _, _) = Image();
        using var dir = new TempDir();
        var unsigned = dir.File("unsigned.dll");
        File.WriteAllBytes(unsigned, pe.FileBytes.ToArray());
        Assert.StartsWith("no embedded signature", DacLocator.Verify(File.ReadAllBytes(unsigned), unsigned));

        var other = RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll");
        Assert.Contains("not Microsoft Corporation", DacLocator.Verify(File.ReadAllBytes(other), other));

        var microsoft = RealPackages.Lib("System.Text.Json", "10.0.1", "net10.0", "System.Text.Json.dll");
        var bytes = File.ReadAllBytes(microsoft);
        if (OperatingSystem.IsWindows()) Assert.Null(DacLocator.Verify(bytes, microsoft));
        var probe = PeFile.FromBytes(bytes);
        var codeAt = probe.Sections.First(s => s.IsExecutable).RawOffset + 0x100;
        bytes[codeAt] ^= 0xFF;
        Assert.Contains("changed after signing", DacLocator.Verify(bytes, microsoft));
    }

    [Fact]
    public void A_signer_without_the_code_signing_usage_is_refused()
    {
        using var key = System.Security.Cryptography.ECDsa.Create();
        System.Security.Cryptography.X509Certificates.X509Certificate2 Signer(params string[] usages)
        {
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Test, O=Microsoft Corporation", key,
                System.Security.Cryptography.HashAlgorithmName.SHA256);
            if (usages.Length > 0)
                request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
                    [.. usages.Select(u => new System.Security.Cryptography.Oid(u))], critical: false));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
        // Server authentication only.
        Assert.False(Certificates.AllowsCodeSigning(Signer("1.3.6.1.5.5.7.3.1")));
        Assert.False(Certificates.AllowsCodeSigning(Signer()));
        Assert.True(Certificates.AllowsCodeSigning(Signer("1.3.6.1.5.5.7.3.3")));
    }

    [Fact]
    public void An_installed_dac_passes_the_usage_and_revocation_checks()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dac = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "mscordaccore.dll");
        Assert.Null(DacLocator.Verify(File.ReadAllBytes(dac), dac, out var note));
        Assert.True(note == null || note.StartsWith("revocation not checked", StringComparison.Ordinal), note);
    }

    /// <summary>Windows' own files are signed through system catalogs, as the .NET Framework's DAC is.</summary>
    [Fact]
    public void CatalogSignedSystemFilesAreAccepted()
    {
        if (!OperatingSystem.IsWindows()) return;
        var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");
        var bytes = File.ReadAllBytes(system);
        Assert.Null(DacLocator.Verify(bytes, system));
        using var dir = new TempDir();
        var copy = dir.File("kernel32.dll");
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(copy, bytes);
        Assert.NotNull(DacLocator.Verify(bytes, copy)); // a changed copy is in no catalog
    }

    /// <summary>A Linux runtime's DAC on this host is the Windows-hosted one built for Linux targets, stored under libcoreclr.so's build id.</summary>
    [Fact]
    public void LinuxRuntimeDacIsKeyedByTheRuntimeBuildId()
    {
        var id = System.Collections.Immutable.ImmutableArray.Create<byte>(0x8A, 0x5D, 0x01);
        var libraries = new[]
        {
            new Microsoft.Diagnostics.Runtime.DebugLibraryInfo(Microsoft.Diagnostics.Runtime.DebugLibraryKind.Dac, "libmscordaccore.so", Architecture.X64, OSPlatform.Linux, Microsoft.Diagnostics.Runtime.SymbolProperties.Coreclr, id),
            new Microsoft.Diagnostics.Runtime.DebugLibraryInfo(Microsoft.Diagnostics.Runtime.DebugLibraryKind.Dac, "mscordaccore.dll", Architecture.X64, OSPlatform.Windows, Microsoft.Diagnostics.Runtime.SymbolProperties.Coreclr, id),
        };
        var key = Assert.Single(DacLocator.StoreKeys(libraries, Architecture.X64));
        Assert.Equal(("mscordaccore.dll", "elf-buildid-coreclr-8a5d01"), (key.Name, key.Key));
        Assert.Empty(DacLocator.StoreKeys(libraries, Architecture.Arm64));
        Assert.Equal(["mscordaccore.dll"], DacLocator.FileNames(Microsoft.Diagnostics.Runtime.ClrFlavor.Core, libraries));
    }

    /// <summary>A core holds no runtime version: it is read from libcoreclr.so on disk and must equal the DAC's file version.</summary>
    [Fact]
    public void CoreDacVersionMustMatchTheRuntimeFile()
    {
        Assert.Equal("10.0.1326.50504", ClrDecoder.RuntimeVersion("\0@(#)Version 10.0.1326.50504 @Commit: 4099f839\0"u8));
        Assert.Null(ClrDecoder.RuntimeVersion("no version here"u8));
        if (!OperatingSystem.IsWindows()) return;
        var dac = RealPackages.Lib("System.Text.Json", "10.0.1", "net10.0", "System.Text.Json.dll");
        var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(dac);
        var own = $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}.{info.FilePrivatePart}";
        Assert.Null(ClrDecoder.DacVersionProblem(dac, own));
        Assert.Null(ClrDecoder.DacVersionProblem(dac, null));
        Assert.Equal($"DAC version {own}, the runtime is 10.0.1326.50504", ClrDecoder.DacVersionProblem(dac, "10.0.1326.50504"));
    }

    /// <summary>A 32-bit dump goes to the 32-bit decoder after its DAC is looked for here; without the decoder it is a bitness mismatch.</summary>
    [Fact]
    public async Task ThirtyTwoBitDumpNeedsTheThirtyTwoBitDecoder()
    {
        var (pe, _, _, _) = Image();
        var bytes = Dump(pe, arch: 0, module: @"Z:\app\coreclr.dll").Build();
        async Task<DacState> Open(string? helper = null)
        {
            using var decoder = await ClrDecoder.Open(MinidumpFile.FromBytes(bytes), _ => null, [], new DacRequest { Decoder = helper }, default);
            Assert.NotNull(decoder);
            Assert.False(decoder.Loaded);
            return decoder.Dac;
        }
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal("host_unsupported", (await Open()).Status);
            return;
        }
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64) return;
        Assert.NotNull(ClrHelperClient.Locate()); // built beside the server (and these tests)
        Assert.NotEqual("bitness_mismatch", (await Open()).Status);
        var missing = await Open(Path.Combine(Path.GetTempPath(), "missing", ClrHelperClient.FileName));
        Assert.Equal("bitness_mismatch", missing.Status);
        Assert.Contains("not installed", missing.Detail);
    }

    /// <summary>A 64-bit tool's dump of a 32-bit process: the reason names the WoW64 dump, not a DAC that failed to load.</summary>
    [Fact]
    public async Task Wow64DumpOfA32BitRuntimeSaysHowToWriteADecodableDump()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (pe, _, _, _) = Image();
        var builder = Dump(pe, module: @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\clr.dll");
        builder.Modules.Add(new MinidumpBuilder.Module(0x7FFA_0000_0000, 0x10000, 0, @"C:\Windows\System32\wow64cpu.dll"));
        using var decoder = await ClrDecoder.Open(MinidumpFile.FromBytes(builder.Build()), _ => null, [], new DacRequest(), default);
        Assert.NotNull(decoder);
        Assert.Equal("bitness_mismatch", decoder.Dac.Status);
        Assert.Contains("WoW64", decoder.Dac.Detail);
    }

    [Fact]
    public async Task NoProcessRuntimeMeansNoDecoder()
    {
        var (pe, _, _, _) = Image();
        Assert.Null(await ClrDecoder.Open(MinidumpFile.FromBytes(Dump(pe).Build()), _ => pe, [], new DacRequest(), default));
        using var dir = new TempDir();
        var path = dir.File("native.dmp");
        File.WriteAllBytes(path, Dump(pe).Build());
        using var service = new MinidumpService();
        Assert.Null((await service.Summarize(path, null, default)).Managed);
        Assert.Null((await service.Stack(path, null, true, 16, 0, 16, null, default)).Managed);
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Object(path, "0x1000", 1, 10, 10, default));
        Assert.Contains("no .NET runtime", error.Message);
    }

    /// <summary>A managed library named Mono.* in a CoreCLR process does not make it a Mono process.</summary>
    [Fact]
    public void AManagedLibraryNamedMonoIsNotTheMonoRuntime()
    {
        var (pe, _, _, _) = Image();
        var builder = Dump(pe, module: @"Z:\app\Mono.Nat.dll");
        using (var dump = MinidumpFile.FromBytes(builder.Build()))
            Assert.False(MinidumpService.HostsClr(dump, out _));
        builder.Modules.Add(new MinidumpBuilder.Module(0x7FFA_0000_0000, 0x10000, 0, @"Z:\app\coreclr.dll"));
        using (var dump = MinidumpFile.FromBytes(builder.Build()))
        {
            Assert.True(MinidumpService.HostsClr(dump, out var runtime));
            Assert.Equal(".NET (CoreCLR)", runtime);
        }
    }

    /// <summary>A WoW64 process dumped by a 64-bit writer lists its own image twice: one module, no overlap issue.</summary>
    [Fact]
    public void AModuleListedTwiceIsOneModule()
    {
        var (pe, _, _, _) = Image();
        var builder = Dump(pe, module: @"Z:\app\client.exe");
        builder.Modules.Add(builder.Modules[0]);
        using var dump = MinidumpFile.FromBytes(builder.Build());
        Assert.Single(dump.Modules);
        Assert.Empty(dump.Issues);
    }

    /// <summary>JIT code in a Mono process points at the runtime's own report, not at a DAC Mono does not have.</summary>
    [Fact]
    public async Task JitCodeInAMonoProcessIsNotSentToADac()
    {
        var (pe, _, _, _) = Image();
        var builder = Dump(pe, module: @"Z:\app\MonoBleedingEdge\EmbedRuntime\mono-2.0-bdwgc.dll");
        const ulong Jit = 0xE1_0000_0000;
        builder.Memory.Add((Jit, new byte[0x100]));
        builder.Regions.Add(new MinidumpBuilder.Region(Jit, 0x1000, 0x20));
        builder.Threads[0] = new MinidumpBuilder.Thread(7, 0xE0_0000_0000, MinidumpBuilder.ContextX64(Jit + 0x10, 0xE0_0000_0080));
        using var dir = new TempDir();
        var path = dir.File("mono.dmp");
        File.WriteAllBytes(path, builder.Build());
        using var service = new MinidumpService();
        var top = (await service.Stack(path, null, true, 4, 0, 4, null, default)).Items[0];
        Assert.Equal("managed", top.Kind);
        Assert.Contains("Mono has no DAC", top.Note);
        Assert.DoesNotContain("downloadDac", top.Note);
    }

    [Theory]
    [InlineData("System.String", "System.String", true)]
    [InlineData("System.String", "system.string", true)]
    [InlineData("System.String[]", "System.String", false)]
    [InlineData("System.Collections.Generic.List<System.Int32>", "System.Collections.Generic.List*", true)]
    [InlineData("Probe.Program", "*.Prog?am", true)]
    [InlineData("Probe.Program", "*Exception", false)]
    [InlineData("A", "**", true)]
    public void TypeFilterIsWildcardOrExact(string name, string pattern, bool expected) => Assert.Equal(expected, Wildcard.Matches(name, pattern));

    /// <summary>A CoreCLR module whose build is nowhere on this machine: not found locally, a refused download offline, a rejected unsigned DAC.</summary>
    [Fact]
    public async Task UnknownRuntimeBuildReportsWhyNoDacLoaded()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64) return;
        var (pe, _, _, _) = Image();
        using var dir = new TempDir();
        var path = dir.File("clr.dmp");
        File.WriteAllBytes(path, Dump(pe, module: @"Z:\nowhere\coreclr.dll").Build());
        using var service = new MinidumpService();

        var summary = await service.Summarize(path, null, default);
        var managed = Assert.IsType<MinidumpService.ManagedSummary>(summary.Managed);
        Assert.Equal("not_found", managed.Dac.Status);
        Assert.Contains("downloadDac=true", managed.Dac.Detail);
        Assert.Null(managed.Heap);
        var stack = await service.Stack(path, null, true, 32, 0, 32, null, default);
        Assert.Equal("not_found", stack.Managed);
        Assert.Contains(stack.Notes, n => n.StartsWith("Managed frames are identified, not decoded", StringComparison.Ordinal));
        Assert.Equal("off", (await service.Stack(path, null, true, 32, 0, 32, null, false, default)).Managed);

        var unsigned = dir.File("mscordaccore.dll");
        File.WriteAllBytes(unsigned, pe.FileBytes.ToArray());
        summary = await service.Summarize(path, null, new DacRequest(unsigned), default);
        Assert.Equal("signature_invalid", summary.Managed!.Dac.Status);
        Assert.Contains("no embedded signature", summary.Managed.Dac.Detail);
        summary = await service.Summarize(path, null, new DacRequest(dir.Path), default); // the folder works too
        Assert.Equal("signature_invalid", summary.Managed!.Dac.Status);
        await Assert.ThrowsAsync<ToolError>(() => service.Summarize(path, null, new DacRequest(dir.File("missing.dll")), default));

        var noDac = await Assert.ThrowsAsync<ToolError>(() => service.Heap(path, "stats", null, 0, 0, 50, 100, default));
        Assert.Equal(ErrorCode.Unsupported, noDac.Code);
        Assert.Contains("DAC is not loaded", noDac.Message);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => service.Heap(path, "tree", null, 0, 0, 50, 100, default))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => service.Object(path, "nowhere", 1, 10, 10, default))).Code);

        using (new EnvironmentScope().Set(ReferencePacks.OfflineVariable, "1"))
        {
            summary = await service.Summarize(path, null, new DacRequest(Download: true), default);
            Assert.Equal("download_refused_offline", summary.Managed!.Dac.Status);
        }
    }

    [Fact]
    public async Task Offline_and_the_symbol_cache_set_in_one_flow_are_not_seen_in_another()
    {
        var cache = Path.Combine(Path.GetTempPath(), "corvus-flow-cache");
        using var scope = new EnvironmentScope().Set(ReferencePacks.OfflineVariable, "1").Set(Native.Pdb.PdbLocator.CacheVariable, cache);
        Assert.True(ReferencePacks.Offline);
        Assert.Equal(cache, Native.Pdb.PdbLocator.DownloadCache);
        Task<(bool, string)> other;
        // A flow started without this one's context reads the values the run started with.
        using (ExecutionContext.SuppressFlow())
            other = Task.Run(() => (ReferencePacks.Offline, Native.Pdb.PdbLocator.DownloadCache));
        var (offline, downloadCache) = await other;
        Assert.Equal(EnvironmentScope.AtStart.GetValueOrDefault(ReferencePacks.OfflineVariable) is "1" or "true", offline);
        Assert.NotEqual(cache, downloadCache);
    }

    /// <summary>
    /// A scan from JIT code that finds the return address an inlined P/Invoke's frame record keeps on the stack gives no
    /// second frame for a managed frame the runtime named; two runtime frames at one return address (recursion) both stay.
    /// </summary>
    [Fact]
    public void A_scanned_copy_of_a_named_return_address_is_not_a_second_frame()
    {
        const ulong api = 0x7FF9_1DBC_7887, readAllBytes = 0x7FF7_A3FF_ABF6, readOnce = 0x7FF7_A3FF_A93A;
        WalkFrame Native(ulong ip, ulong sp, string method) => new(ip, sp, method, method == FrameMethod.Scan, true, null);
        ManagedFrame Clr(ulong ip, ulong sp, string name) => new(ip, sp, true, name, 0x06000001, 0, null, null, null);
        var merged = MinidumpService.Merge(
            [Native(api, 0x1D0, FrameMethod.UnwindInfo), Native(readAllBytes, 0x230, FrameMethod.UnwindInfo), Native(readAllBytes, 0x300, FrameMethod.Scan), Native(readOnce, 0x3F0, FrameMethod.Scan)],
            [Clr(readAllBytes, 0x230, "File.ReadAllBytes"), Clr(readOnce, 0x3F0, "Readers.ReadOnce")]);
        Assert.Equal([api, readAllBytes, readOnce], merged.Select(f => f.Managed?.Ip ?? f.Native!.Ip));
        Assert.Equal([null, "File.ReadAllBytes", "Readers.ReadOnce"], merged.Select(f => f.Managed?.Name));

        var recursive = MinidumpService.Merge(
            [Native(readOnce, 0x100, FrameMethod.UnwindInfo), Native(readOnce, 0x180, FrameMethod.Scan)],
            [Clr(readOnce, 0x100, "Readers.ReadOnce"), Clr(readOnce, 0x180, "Readers.ReadOnce")]);
        Assert.Equal(2, recursive.Count(f => f.Managed != null));
    }

    /// <summary>A single-file app links the runtime into its executable, which exports DotNetRuntimeInfo; an apphost does not.</summary>
    [WindowsHostPackFact]
    public void A_single_file_host_is_the_runtime_module()
    {
        foreach (var (file, hosts) in new[] { ("singlefilehost.exe", true), ("apphost.exe", false) })
        {
            var memory = new ImageMemory(SyntheticCrashX86.Mapped(File.ReadAllBytes(WindowsHostPackFactAttribute.File(file)!)), @"C:\app\app.exe");
            Assert.Equal(hosts, ClrDecoder.RuntimeModule(memory) != null);
            Assert.Equal(hosts, MinidumpService.HostsClr(memory, out var runtime));
            Assert.Equal(hosts ? ".NET (CoreCLR, single-file)" : null, runtime);
        }
    }

    /// <summary>One image mapped at <see cref="Loaded"/>, as a process holding only its executable.</summary>
    private sealed class ImageMemory(byte[] image, string path) : IProcessMemory
    {
        private readonly DumpModule _module = new(Loaded, (uint)image.Length, 0, 0, path, null, null, null);
        public Corvus.Native.NativeArch Arch => Corvus.Native.NativeArch.X64;
        public bool Is64Bit => true;
        public string Identity => path;
        public IReadOnlyList<DumpModule> Modules => [_module];
        public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];

        public int ReadMemory(ulong address, Span<byte> destination)
        {
            if (!_module.Contains(address)) return 0;
            var from = image.AsSpan((int)(address - Loaded));
            int n = Math.Min(from.Length, destination.Length);
            from[..n].CopyTo(destination);
            return n;
        }

        public DumpModule? ModuleAt(ulong address) => _module.Contains(address) ? _module : null;
        public DumpMemoryRegion? RegionAt(ulong address) => null;
        public ulong ReadableExtent(ulong start, ulong size) => 0;
    }
}

/// <summary>Runs when the SDK holds the Windows x64 apphost pack (apphost.exe and singlefilehost.exe).</summary>
public sealed class WindowsHostPackFactAttribute : FactAttribute
{
    public WindowsHostPackFactAttribute()
    {
        if (File("singlefilehost.exe") == null || File("apphost.exe") == null) Skip = "The SDK has no Microsoft.NETCore.App.Host.win-x64 pack.";
    }

    /// <summary>A file of the newest Windows x64 apphost pack; null without one.</summary>
    public static string? File(string name)
    {
        var root = new DirectoryInfo(RuntimeEnvironment.GetRuntimeDirectory());
        while (root != null && !Directory.Exists(Path.Combine(root.FullName, "packs"))) root = root.Parent;
        var pack = root == null ? null : new DirectoryInfo(Path.Combine(root.FullName, "packs", "Microsoft.NETCore.App.Host.win-x64"));
        return pack is { Exists: true }
            ? pack.EnumerateDirectories().OrderByDescending(d => d.Name).Select(d => Path.Combine(d.FullName, "runtimes", "win-x64", "native", name)).FirstOrDefault(System.IO.File.Exists)
            : null;
    }
}
