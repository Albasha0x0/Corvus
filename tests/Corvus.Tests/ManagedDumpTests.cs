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

    /// <summary>A 32-bit dump goes to the 32-bit decoder after its DAC is looked for here; without the decoder it is a bitness mismatch.</summary>
    [Fact]
    public async Task ThirtyTwoBitDumpNeedsTheThirtyTwoBitDecoder()
    {
        var (pe, _, _, _) = Image();
        var bytes = Dump(pe, arch: 0, module: @"Z:\app\coreclr.dll").Build();
        async Task<DacState> Open()
        {
            using var decoder = await ClrDecoder.Open(MinidumpFile.FromBytes(bytes), _ => null, [], new DacRequest(), default);
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
        using (new EnvironmentScope().Set(ClrHelperClient.PathVariable, Path.Combine(Path.GetTempPath(), "missing", ClrHelperClient.FileName)))
        {
            var missing = await Open();
            Assert.Equal("bitness_mismatch", missing.Status);
            Assert.Contains("not installed", missing.Detail);
        }
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
        var service = new MinidumpService();
        Assert.Null((await service.Summarize(path, null, 0, 50, 0, 50, default)).Managed);
        Assert.Null((await service.Stack(path, null, true, 16, 0, 16, null, default)).Managed);
        var error = await Assert.ThrowsAsync<ToolError>(() => service.Object(path, "0x1000", 1, 10, 10, default));
        Assert.Contains("no .NET runtime", error.Message);
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
        var service = new MinidumpService();

        var summary = await service.Summarize(path, null, 0, 50, 0, 50, default);
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
        summary = await service.Summarize(path, null, 0, 50, 0, 50, new DacRequest(unsigned), default);
        Assert.Equal("signature_invalid", summary.Managed!.Dac.Status);
        Assert.Contains("no embedded signature", summary.Managed.Dac.Detail);
        summary = await service.Summarize(path, null, 0, 50, 0, 50, new DacRequest(dir.Path), default); // the folder works too
        Assert.Equal("signature_invalid", summary.Managed!.Dac.Status);
        await Assert.ThrowsAsync<ToolError>(() => service.Summarize(path, null, 0, 50, 0, 50, new DacRequest(dir.File("missing.dll")), default));

        var noDac = await Assert.ThrowsAsync<ToolError>(() => service.Heap(path, "stats", null, 0, 0, 50, 100, default));
        Assert.Equal(ErrorCode.Unsupported, noDac.Code);
        Assert.Contains("DAC is not loaded", noDac.Message);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => service.Heap(path, "tree", null, 0, 0, 50, 100, default))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => service.Object(path, "nowhere", 1, 10, 10, default))).Code);

        var previous = Environment.GetEnvironmentVariable("CORVUS_OFFLINE");
        Environment.SetEnvironmentVariable("CORVUS_OFFLINE", "1");
        try
        {
            summary = await service.Summarize(path, null, 0, 50, 0, 50, new DacRequest(Download: true), default);
            Assert.Equal("download_refused_offline", summary.Managed!.Dac.Status);
        }
        finally { Environment.SetEnvironmentVariable("CORVUS_OFFLINE", previous); }
    }
}
