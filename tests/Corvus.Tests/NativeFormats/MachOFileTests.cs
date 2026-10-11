using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.MachO;
using Xunit.Abstractions;
using static Corvus.Tests.NativeFormats.FormatWriterTests;

namespace Corvus.Tests.NativeFormats;

public sealed class MachOFileTests(ITestOutputHelper output)
{
    private static MachOFile Parse(MachOWriter w, string? slice = null) => MachOFile.FromBytes(w.Build(), "sample.dylib", slice);

    private static ulong Word(INativeImage image, uint rva)
    {
        var b = new byte[8];
        Assert.Equal(image.Is64Bit ? 8 : 4, image.Read(rva, b.AsSpan(0, image.Is64Bit ? 8 : 4)));
        return image.Is64Bit ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    [Fact]
    public void Dylib_ImageModel()
    {
        var w = SampleMachO();
        var m = Parse(w);
        INativeImage image = m;
        Assert.Equal(ImageFormat.MachO, image.Format);
        Assert.Equal(NativeArch.Arm64, image.Arch);
        Assert.True(image.Is64Bit && image.IsDll);
        Assert.Equal(0UL, image.ImageBase);
        Assert.Equal("arm64", image.MachineName);
        Assert.Empty(image.Issues);
        Assert.Equal(["/usr/lib/libSystem.B.dylib", "@rpath/libweak.dylib"], image.Dependencies);
        Assert.Equal("@rpath/libtest.dylib", m.InstallName);
        Assert.Equal(["@loader_path"], m.Rpaths);
        Assert.Equal("aabbccdd000102030405060708090a0b", image.BuildId);
        Assert.Equal(("macos", "11.0"), (m.BuildVersion!.PlatformName, MachONames.Version(m.BuildVersion.MinOs)));

        var text = Assert.Single(image.Sections, s => s.Name == "__TEXT,__text");
        Assert.True(text.IsExecutable);
        Assert.Equal(MachOWriter.TextOffset, text.Rva);
        Assert.False(Assert.Single(image.Sections, s => s.Name == "__DATA_CONST,__const").IsExecutable);
        Assert.Contains(image.Sections, s => s.Name == "__LINKEDIT");
        Assert.Equal("__DATA,__data", image.SectionAt(MachOWriter.DataOffset + 8)?.Name);

        Assert.Equal([("_sample_init", MachOWriter.TextOffset, (string?)null), ("_sample_resolved", MachOWriter.TextOffset, null), ("_sample_run", MachOWriter.TextOffset + 4, null)],
            image.Exports.Select(e => (e.Name!, e.Rva, e.ForwardedTo)));
        var resolved = Assert.Single(m.ExportTrie, e => e.Name == "_sample_resolved");
        Assert.True(resolved.IsStubAndResolver);
        Assert.Equal(MachOWriter.TextOffset + 4UL, resolved.Resolver);

        Assert.Contains(image.Symbols, s => s.Name == "_local" && s.Binding == ImageSymbolBinding.Local && s.Kind == ImageSymbolKind.Function);
        Assert.Contains(image.Symbols, s => s.Name == "_sample_run" && s.Binding == ImageSymbolBinding.Global && s.Section == "__TEXT,__text");
        Assert.Equal([MachOWriter.TextOffset, MachOWriter.TextOffset + 4], m.FunctionStarts);
        Assert.Contains(new DeclaredFunction(MachOWriter.TextOffset, 4, DeclaredSource.FunctionStarts), image.DeclaredFunctions);
        Assert.Equal(new MachODataInCode(MachOWriter.TextOffset + 4, 4, 1), Assert.Single(m.DataInCode));

        // Chained fixups: rebases hold their targets, binds read 0; Resolve tells which symbol a slot binds to.
        var bind = Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.GotOffset));
        Assert.Equal(("_malloc", 1, "/usr/lib/libSystem.B.dylib", false), (bind.Symbol, bind.Ordinal, bind.Dylib, bind.Weak));
        Assert.True(Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.DataOffset)).Weak);
        Assert.Equal(MachOWriter.TextOffset + 4UL, Assert.IsType<MachOFixup.Rebase>(m.Fixups.Resolve(MachOWriter.ConstOffset + 8)).TargetVm);
        Assert.Null(m.Fixups.Resolve(MachOWriter.ConstOffset + 16));
        Assert.Equal((ushort)6, m.Fixups.PointerFormat);
        Assert.Equal(0UL, Word(image, MachOWriter.GotOffset));
        Assert.Equal(MachOWriter.TextOffset + 4UL, Word(image, MachOWriter.ConstOffset + 8));
        Assert.Equal(MachOWriter.DataOffset, Word(image, MachOWriter.DataOffset + 0x1800));
        Assert.Equal([MachOWriter.ConstOffset, MachOWriter.ConstOffset + 8, MachOWriter.DataOffset + 0x1800], image.RelocationRvas);
        Assert.Equal([("/usr/lib/libSystem.B.dylib", "_malloc", MachOWriter.GotOffset), ("@rpath/libweak.dylib", "_weak_fn", MachOWriter.DataOffset)],
            image.Imports.Select(i => (i.Module, i.Name!, i.SlotRva)));
    }

    /// <summary>Every chained pointer format decodes to the rebase targets and binds the writer chained.</summary>
    [Theory]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(6, true)]
    [InlineData(7, true)]
    [InlineData(8, true)]
    [InlineData(9, true)]
    [InlineData(10, true)]
    [InlineData(11, true)]
    [InlineData(12, true)]
    [InlineData(3, false)]
    [InlineData(4, false)]
    [InlineData(5, false)]
    public void ChainedPointerFormats(int format, bool is64)
    {
        bool binds = format is not (4 or 5 or 8 or 11);
        var w = new MachOWriter
        {
            Is64 = is64,
            CpuType = is64 ? MachOWriter.CpuArm64 : MachOWriter.CpuArm,
            CpuSubType = format is 1 or 9 or 12 ? 2u : is64 ? 0u : 9u,
            ChainedFormat = (ushort)format,
            Dylibs = [("/usr/lib/libSystem.B.dylib", 0xC)],
            Imports = binds ? [new(1, "_malloc"), new(-2, "_flat")] : [],
        };
        int ptr = is64 ? 8 : 4;
        var fixups = new List<MachOWriter.Fixup>
        {
            new(MachOWriter.ConstOffset, Target: MachOWriter.TextOffset),
            new(MachOWriter.ConstOffset + (uint)ptr, Target: MachOWriter.TextOffset + 0x10, High8: format is 1 or 2 or 6 or 9 or 12 ? (byte)0x80 : (byte)0),
            new(MachOWriter.DataOffset + 0x200, Target: MachOWriter.DataOffset), // past the 32-bit chain reach: a second chain start on the page
        };
        if (binds) fixups.AddRange([new(MachOWriter.GotOffset, Import: 0), new(MachOWriter.GotOffset + (uint)ptr, Import: 1, Addend: 3)]);
        if (format is 1 or 7 or 9 or 10 or 12)
            fixups.AddRange([new(MachOWriter.ConstOffset + 0x20, Target: MachOWriter.TextOffset + 8, Auth: true, Diversity: 0x1234, Key: 2), new(MachOWriter.GotOffset + 0x10, Import: 0, Auth: true, AddrDiv: true)]);
        w.Fixups = fixups;
        var m = Parse(w);
        Assert.Empty(m.Issues);
        Assert.Equal(fixups.Count, m.Fixups.All.Count);
        foreach (var f in fixups)
        {
            var got = m.Fixups.Resolve(m.ImageBase + f.Offset);
            if (f.Import >= 0)
            {
                var b = Assert.IsType<MachOFixup.Bind>(got);
                Assert.Equal((w.Imports[f.Import].Name, f.Import == 0 ? 1 : -2, f.Auth ? 0 : f.Addend, f.Auth), (b.Symbol, b.Ordinal, b.Addend, b.Authenticated));
                Assert.Equal(0UL, Word(m, f.Offset));
            }
            else
            {
                var r = Assert.IsType<MachOFixup.Rebase>(got);
                ulong expected = (m.ImageBase + f.Target) | ((ulong)f.High8 << 56);
                Assert.Equal((expected, f.Auth), (r.TargetVm, r.Authenticated));
                Assert.Equal(is64 ? expected : expected & 0xFFFFFFFF, Word(m, f.Offset));
            }
        }
        Assert.Equal(binds ? "flat-namespace" : null, m.Imports.FirstOrDefault(i => i.Name == "_flat")?.Module);
    }

    [Theory]
    [InlineData(2u, false)]
    [InlineData(3u, true)]
    public void ChainedImportFormats_AddendsAndCompressedNames(uint importsFormat, bool compress)
    {
        var w = SampleMachO();
        w.ImportsFormat = importsFormat;
        w.CompressSymbols = compress;
        w.Imports = [new(1, "_malloc", Addend: 16), new(2, "_weak_fn", Weak: true, Addend: -8)];
        var m = Parse(w);
        Assert.Empty(m.Issues);
        Assert.Equal(("_malloc", 16L), Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.GotOffset)) is var b ? (b.Symbol, b.Addend) : default);
        Assert.Equal(-8L, Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.DataOffset)).Addend);
    }

    [Fact]
    public void Executable_PageZeroAndEntryPoint()
    {
        var w = new MachOWriter { FileType = 2, InstallName = null, MainOffset = MachOWriter.TextOffset + 4, ChainedFormat = 6, Fixups = [new(MachOWriter.ConstOffset, Target: MachOWriter.TextOffset)] };
        var m = Parse(w);
        Assert.Equal(0x1_0000_0000UL, m.ImageBase);
        Assert.False(m.IsDll);
        Assert.Equal(MachOWriter.TextOffset + 4, m.EntryPointRva);
        Assert.DoesNotContain(m.Sections, s => s.Name.Contains("PAGEZERO", StringComparison.Ordinal));
        Assert.Equal(0x1_0000_0000UL + MachOWriter.TextOffset, Word(m, MachOWriter.ConstOffset));
        Assert.Empty(m.Issues);

        // LC_UNIXTHREAD names the entry by its program counter.
        var thread = new ByteWriter();
        thread.U32(0x5); thread.U32(16 + 68 * 4); thread.U32(6); thread.U32(68);
        for (int i = 0; i < 68; i++) thread.U32(0);
        var bytes = thread.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16 + 256), 0x1_0000_0000UL + MachOWriter.TextOffset);
        var t = new MachOWriter { FileType = 2, InstallName = null, ExtraCommands = [bytes, UnknownCommand()] };
        var tm = Parse(t);
        Assert.Equal(MachOWriter.TextOffset, tm.EntryPointRva);
        Assert.Contains(tm.LoadCommands, c => c.Command == 0x7777 && c.GetType() == typeof(MachOLoadCommand));
    }

    private static byte[] UnknownCommand()
    {
        var c = new ByteWriter();
        c.U32(0x7777); c.U32(16); c.U64(42);
        return c.ToArray();
    }

    [Fact]
    public void DyldInfo_OpcodesIncludingThreadedBinds()
    {
        var w = new MachOWriter { Dylibs = [("/usr/lib/libSystem.B.dylib", 0xC), ("/usr/lib/libc++.1.dylib", 0xC)], StubSymbols = ["_free"], ExportsInDyldInfo = true,
            Exports = [new("_api", MachOWriter.TextOffset)] };
        var constBytes = new byte[0x100];
        BinaryPrimitives.WriteUInt64LittleEndian(constBytes, MachOWriter.TextOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(constBytes.AsSpan(8), MachOWriter.TextOffset + 4);
        w.Const = constBytes;
        var rebase = new ByteWriter();
        rebase.U8(0x11); rebase.U8(0x21); rebase.Uleb(0x800); rebase.U8(0x52); rebase.U8(0x00);
        w.RebaseOpcodes = rebase.ToArray();
        var bindOps = new ByteWriter();
        bindOps.U8(0x11); bindOps.U8(0x40); bindOps.CString("_malloc"); bindOps.U8(0x51); bindOps.U8(0x71); bindOps.Uleb(0); bindOps.U8(0x90);
        bindOps.U8(0x3E); bindOps.U8(0x40); bindOps.CString("_flat_sym"); bindOps.U8(0x90); bindOps.U8(0x00);
        w.BindOpcodes = bindOps.ToArray();
        var lazy = new ByteWriter();
        lazy.U8(0x72); lazy.Uleb(0x1000); lazy.U8(0x12); lazy.U8(0x40); lazy.CString("_free"); lazy.U8(0x90); lazy.U8(0x00);
        w.LazyBindOpcodes = lazy.ToArray();
        var weakOps = new ByteWriter();
        weakOps.U8(0x40); weakOps.CString("__ZdlPv"); weakOps.U8(0x51); weakOps.U8(0x72); weakOps.Uleb(0x10); weakOps.U8(0x90); weakOps.U8(0x00);
        w.WeakBindOpcodes = weakOps.ToArray();
        var m = Parse(w);
        Assert.Empty(m.Issues);
        Assert.Equal("dyld info", m.Fixups.Source);
        Assert.Equal(MachOWriter.TextOffset + 4UL, Assert.IsType<MachOFixup.Rebase>(m.Fixups.Resolve(MachOWriter.ConstOffset + 8)).TargetVm);
        Assert.Equal((-2, "flat-namespace"), Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.GotOffset + 8)) is var f ? (f.Ordinal, f.Dylib) : default);
        var lazyBind = Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(MachOWriter.LazyPointersOffset));
        Assert.Equal(("_free", "/usr/lib/libc++.1.dylib", true), (lazyBind.Symbol, lazyBind.Dylib, lazyBind.Lazy));
        Assert.Equal("__ZdlPv", Assert.Single(m.Fixups.WeakBinds).Symbol);
        Assert.Contains(m.Imports, i => i.Name == "_free" && i.IsDelayLoad && i.SlotRva == MachOWriter.LazyPointersOffset);
        Assert.Equal(0UL, Word(m, MachOWriter.GotOffset));
        Assert.Equal([(MachOWriter.StubsOffset, "_free")], m.Stubs);
        Assert.Equal("_api", Assert.Single(m.Exports).Name);

        // Threaded binds: DO_BIND fills an ordinal table, THREADED_APPLY walks an arm64e chain.
        var t = new MachOWriter { Dylibs = [("/usr/lib/libSystem.B.dylib", 0xC)] };
        var chain = new byte[0x100];
        BinaryPrimitives.WriteUInt64LittleEndian(chain, 0UL | (1UL << 51) | (1UL << 62));
        BinaryPrimitives.WriteUInt64LittleEndian(chain.AsSpan(8), MachOWriter.TextOffset);
        t.Const = chain;
        var threaded = new ByteWriter();
        threaded.U8(0xD0); threaded.Uleb(1); threaded.U8(0x11); threaded.U8(0x40); threaded.CString("_malloc"); threaded.U8(0x90);
        threaded.U8(0x71); threaded.Uleb(0x800); threaded.U8(0xD1); threaded.U8(0x00);
        t.BindOpcodes = threaded.ToArray();
        var tm = Parse(t);
        Assert.Empty(tm.Issues);
        Assert.Equal("threaded", tm.Fixups.Source);
        Assert.Equal("_malloc", Assert.IsType<MachOFixup.Bind>(tm.Fixups.Resolve(MachOWriter.ConstOffset)).Symbol);
        Assert.Equal(MachOWriter.TextOffset, Word(tm, MachOWriter.ConstOffset + 8));
        Assert.Equal(0UL, Word(tm, MachOWriter.ConstOffset));
    }

    [Fact]
    public void Fat_SlicesAreNamedPerSubtypeAndSelected()
    {
        var arm64 = SampleMachO().Build();
        var arm64e = new MachOWriter { CpuSubType = 0x80000002, InstallName = "@rpath/e.dylib" }.Build();
        var x64 = new MachOWriter { CpuType = MachOWriter.CpuX64, CpuSubType = 3, InstallName = "@rpath/x.dylib" }.Build();
        foreach (bool fat64 in new[] { false, true })
        {
            var fat = MachOWriter.Fat([(MachOWriter.CpuX64, 3, x64), (MachOWriter.CpuArm64, 0, arm64), (MachOWriter.CpuArm64, 0x80000002, arm64e)], fat64);
            Assert.Equal(NativeFileKind.MachOFat, NativeImageLoader.Detect(fat));
            var slices = MachOFat.Read(fat);
            Assert.Equal(["x86_64", "arm64", "arm64e"], slices.Select(s => s.Name));
            Assert.Equal("arm64e", MachOFat.Select(slices, null).Name);
            Assert.Equal("arm64", MachOFat.Select(slices, "arm64").Name);
            Assert.Equal("x86_64", MachOFat.Select(slices, "0").Name);
            Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => MachOFat.Select(slices, "armv7")).Code);
            var m = MachOFile.FromBytes(fat, "fat.dylib", "arm64");
            Assert.Equal("arm64", m.Slice!.Name);
            Assert.Equal(3, m.Slices.Count);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(arm64)), m.Sha256);
            Assert.Equal("@rpath/e.dylib", MachOFile.FromBytes(fat).InstallName);
        }
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => MachOFile.FromBytes(arm64, "", "arm64")).Code);
    }

    [Fact]
    public void Encryption_CompactUnwindAndEhFrame()
    {
        var w = SampleMachO();
        w.Encryption = (MachOWriter.TextOffset, 0x2000, 1);
        w.Text = new byte[0x40];
        w.CompactUnwind = [(MachOWriter.TextOffset + 0x10, 0x04000000), (MachOWriter.TextOffset + 0x20, 0), (MachOWriter.TextOffset + 0x30, 0x02000000)];
        w.EhFdes = [(MachOWriter.TextOffset + 0x24, 8)];
        var m = Parse(w);
        Assert.Equal(new EncryptedRange(MachOWriter.TextOffset, 0x2000, 1), Assert.Single(m.EncryptedRanges));
        Assert.Contains(new DeclaredFunction(MachOWriter.TextOffset + 0x10, 0x10, DeclaredSource.Unwind), m.DeclaredFunctions);
        Assert.Contains(new DeclaredFunction(MachOWriter.TextOffset + 0x24, 8, DeclaredSource.Unwind), m.DeclaredFunctions);
        Assert.Contains(m.DeclaredFunctions, f => f.Rva == MachOWriter.TextOffset + 0x30);
        Assert.DoesNotContain(m.DeclaredFunctions, f => f.Rva == MachOWriter.TextOffset + 0x20);
        w.CompactCompressed = true;
        w.Encryption = (MachOWriter.TextOffset, 0x2000, 0);
        var c = Parse(w);
        Assert.Empty(c.EncryptedRanges);
        Assert.Contains(new DeclaredFunction(MachOWriter.TextOffset + 0x10, 0x10, DeclaredSource.Unwind), c.DeclaredFunctions);
        Assert.Empty(c.Issues);
    }

    [Fact]
    public void CodeSignature_DirectoryEntitlementsAndHashes()
    {
        var w = SampleMachO();
        w.CodeSignature = new("com.example.sample", "ABCDE12345", "<plist><dict><key>get-task-allow</key><true/></dict></plist>", [0x70, 0x02, 0x05, 0x00]);
        var bytes = w.Build();
        var m = MachOFile.FromBytes(bytes);
        Assert.Empty(m.Issues);
        var sig = m.CodeSignature!;
        Assert.Equal(("com.example.sample", "ABCDE12345", 0), (sig.Identifier, sig.TeamId, sig.RequirementCount));
        Assert.Contains("get-task-allow", sig.Entitlements);
        Assert.Equal([0x70, 0x02, 0x05, 0x00], sig.DerEntitlements);
        Assert.True(sig.IsAdHoc);
        var cd = sig.Primary!;
        Assert.Equal(("sha256", 32), (cd.HashName, (int)cd.HashSize));
        Assert.Equal(SHA256.HashData(cd.Blob).AsSpan(0, 20).ToArray(), cd.CdHash);
        Assert.Equal(SHA256.HashData(bytes.AsSpan(0, 0x1000)), cd.CodeSlotHash(0).ToArray());
        Assert.Equal(7u, cd.SpecialSlots);
        Assert.False(cd.SpecialSlotHash(5).IsEmpty);
    }

    [Fact]
    public void BigEndian32_HeadersAndSymbols()
    {
        var w = new MachOWriter { BigEndian = true, Is64 = false, CpuType = MachOWriter.CpuPpc, Symbols = [new("_ppc_fn", MachOWriter.TextOffset)], Exports = [new("_ppc_fn", MachOWriter.TextOffset)] };
        var m = Parse(w);
        Assert.True(m.BigEndian);
        Assert.False(m.Is64Bit);
        Assert.Equal(NativeArch.PowerPc, m.Arch);
        Assert.Empty(m.Issues);
        Assert.Contains(m.Symbols, s => s.Name == "_ppc_fn" && s.Rva == MachOWriter.TextOffset);
        Assert.Equal(MachOWriter.TextOffset, Assert.Single(m.Exports).Rva);
    }

    [Fact]
    public void NotMachO_Throws()
    {
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => MachOFile.FromBytes("\x7F" + "ELF\0\0\0\0"u8.ToArray().Length.ToString() is var _ ? [0x7F, 0x45, 0x4C, 0x46, 0, 0, 0, 0] : [])).Code);
    }

    /// <summary>The real dylib, executable and universal file agree with LibObjectFile on layout, and their fixups match the counts LLVM reports.</summary>
    [Fact]
    public void RealImages_AgreeWithLibObjectFile()
    {
        foreach (var (path, slice) in new[] { (NativeFixtures.OsxArm64DbgShim, (string?)null), (NativeFixtures.OsxArm64AppHost, null), (NativeFixtures.OsxFatSkia, "x86_64"), (NativeFixtures.OsxFatSkia, "arm64") })
        {
            var m = MachOFile.Open(path, slice);
            Assert.Empty(m.Issues);
            using var stream = File.OpenRead(path);
            var oracle = LibObjectFile.MachO.MachOFatFile.IsFat(stream)
                ? LibObjectFile.MachO.MachOFatFile.Read(File.OpenRead(path)).Slices.Select(s => s.File!).Single(f => MachONames.Arch((uint)f.CpuType) == m.Arch)
                : LibObjectFile.MachO.MachOFile.Read(File.OpenRead(path));
            Assert.Equal(oracle.Segments.Select(s => (s.Name, s.VmAddress, s.VmSize)), m.Segments.Select(s => (s.SegmentName, s.VmAddress, s.VmSize)));
            Assert.Equal(oracle.ReadSymbolTable().Count, m.SymbolTable.Count);
            Assert.Equal(oracle.ReadIndirectSymbolTable().Count, m.IndirectSymbols.Count);
            Assert.Equal(oracle.LinkedLibraries.Select(l => l.Name).ToList(), m.Dylibs.Select(d => d.Path).ToList());
            output.WriteLine($"{Path.GetFileName(path)} {slice}: {m.Fixups.Source}, {m.Fixups.RebaseCount} rebases, {m.Fixups.BindCount} binds, {m.Fixups.WeakBinds.Count} weak, " +
                $"{m.Exports.Count} exports, {m.FunctionStarts.Count} function starts, {m.DeclaredFunctions.Count} declared, {m.Stubs.Count} stubs, sig {m.CodeSignature?.Identifier}");
        }
        var dbgshim = MachOFile.Open(NativeFixtures.OsxArm64DbgShim);
        Assert.Equal((362, 187, (ushort?)6), (dbgshim.Fixups.RebaseCount, dbgshim.Fixups.BindCount, dbgshim.Fixups.PointerFormat));
        var apphost = MachOFile.Open(NativeFixtures.OsxArm64AppHost);
        Assert.Equal((24, 103), (apphost.Fixups.RebaseCount, apphost.Fixups.BindCount));
        Assert.Equal(8300u, apphost.EntryPointRva);
        Assert.Equal("2a39b1a0f2f93bf3acaa4d572c837a11", apphost.BuildId);
        Assert.NotNull(apphost.CodeSignature?.Primary);
    }

    /// <summary>Every dylib of the osx-arm64 runtime pack (libcoreclr.dylib and friends) parses cleanly, and agrees with LLVM's fixups when CORVUS_LLVM_BIN is set.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void RuntimePack_Dylibs()
    {
        var dir = Path.GetDirectoryName(RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes/osx-arm64/native/libcoreclr.dylib"))!;
        foreach (var path in Directory.EnumerateFiles(dir, "*.dylib"))
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var m = MachOFile.Open(path);
            FormatFuzz.Touch(m, x => _ = x.Fixups.All.Count + x.Stubs.Count + (x.CodeSignature?.CodeDirectories.Count ?? 0));
            var elapsed = clock.ElapsedMilliseconds;
            Assert.Empty(m.Issues);
            if (LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachODyldInfo, path) is { } info)
            {
                var expected = Regex.Matches(info, @"^\S+\s+\S*\s+0x([0-9A-F]+)\s+0x[0-9A-F]+\s+(bind|rebase)\s", RegexOptions.Multiline)
                    .Select(x => (Convert.ToUInt64(x.Groups[1].Value, 16), x.Groups[2].Value)).Order().ToList();
                Assert.Equal(expected, m.Fixups.All.Select(f => (f.Location, f is MachOFixup.Bind ? "bind" : "rebase")).Order());
            }
            output.WriteLine($"{Path.GetFileName(path)}: {elapsed} ms, {m.Fixups.RebaseCount} rebases, {m.Fixups.BindCount} binds, {m.DeclaredFunctions.Count} declared functions, {m.Exports.Count} exports");
        }
    }

    /// <summary>Fixups, exports and function starts match llvm-objdump's (needs CORVUS_LLVM_BIN).</summary>
    [Fact]
    public void RealImages_AgreeWithLlvm()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        foreach (var path in new[] { NativeFixtures.OsxArm64DbgShim, NativeFixtures.OsxArm64AppHost })
        {
            var m = MachOFile.Open(path);
            var info = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachODyldInfo, path)!;
            var expected = Regex.Matches(info, @"^\S+\s+\S*\s+0x([0-9A-F]+)\s+0x[0-9A-F]+\s+(bind|rebase)\s+(.*)$", RegexOptions.Multiline)
                .Select(x => (Convert.ToUInt64(x.Groups[1].Value, 16), x.Groups[2].Value)).Order().ToList();
            Assert.Equal(expected, m.Fixups.All.Select(f => (f.Location, f is MachOFixup.Bind ? "bind" : "rebase")).Order());
            foreach (Match x in Regex.Matches(info, @"0x([0-9A-F]+)\s+0x[0-9A-F]+\s+bind\s+0x([0-9A-F]+)\s+\S+\s+(\S+)", RegexOptions.Multiline))
                Assert.Equal(x.Groups[3].Value, Assert.IsType<MachOFixup.Bind>(m.Fixups.Resolve(Convert.ToUInt64(x.Groups[1].Value, 16))).Symbol);
            foreach (Match x in Regex.Matches(info, @"0x([0-9A-F]+)\s+0x[0-9A-F]+\s+rebase\s+0x([0-9A-F]+)", RegexOptions.Multiline))
                Assert.Equal(Convert.ToUInt64(x.Groups[2].Value, 16), Assert.IsType<MachOFixup.Rebase>(m.Fixups.Resolve(Convert.ToUInt64(x.Groups[1].Value, 16))).TargetVm);
            var trie = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachOExportsTrie, path)!;
            Assert.Equal(Regex.Matches(trie, @"^0x([0-9A-F]+)\s+(\S+)", RegexOptions.Multiline).Select(x => (x.Groups[2].Value, Convert.ToUInt64(x.Groups[1].Value, 16))).Order(),
                m.ExportTrie.Select(e => (e.Name, e.IsAbsolute ? e.Address : m.ImageBase + e.Address)).Order());
            var starts = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachOFunctionStarts, path)!;
            Assert.Equal(Regex.Matches(starts, @"^([0-9a-f]{16})", RegexOptions.Multiline).Select(x => Convert.ToUInt64(x.Groups[1].Value, 16) - m.ImageBase),
                m.FunctionStarts.Select(s => (ulong)s));
        }
        var skia = NativeFixtures.OsxFatSkia;
        foreach (var arch in new[] { "x86_64", "arm64" })
        {
            var m = MachOFile.Open(skia, arch);
            int Count(string option, string pattern) => Regex.Count(LlvmOracle.Run("llvm-objdump", option + " " + LlvmOracle.Options.MachOArch + arch, skia)!, pattern, RegexOptions.Multiline);
            Assert.Equal(Count(LlvmOracle.Options.MachORebase, @"^__\w+\s+__\w+\s+0x"), m.Fixups.RebaseCount);
            Assert.Equal(Count(LlvmOracle.Options.MachOBind, @"^__\w+\s+__\w+\s+0x") + Count(LlvmOracle.Options.MachOLazyBind, @"^__\w+\s+__\w+\s+0x"), m.Fixups.BindCount);
            Assert.Equal(Count(LlvmOracle.Options.MachOWeakBind, @"^__\w+\s+__\w+\s+0x"), m.Fixups.WeakBinds.Count);
        }
    }

    /// <summary>Dylibs linked by ld64.lld with chained fixups (arm64) and with dyld info opcodes (x86_64) agree with llvm-objdump (needs CORVUS_LLVM_BIN with clang).</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public void ClangBuilds_AgreeWithLlvm()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        const string target = LlvmOracle.Options.Target;
        foreach (var (name, options) in new[] { ("chained", $"{target}arm64-apple-macos11 {LlvmOracle.Options.LinkChainedFixups}"), ("classic", $"{target}x86_64-apple-macos11 {LlvmOracle.Options.LinkNoChainedFixups}") })
        {
            var path = dir.File(name + ".dylib");
            var failure = LlvmOracle.Compile(ElfFileTests.OracleSource, path, $"{LlvmOracle.Options.ClangSharedObject} {LlvmOracle.Options.LinkMachODynamicLookup} {options}");
            Assert.True(failure == null, failure);
            var m = MachOFile.Open(path);
            Assert.Empty(m.Issues);
            int Count(string option) => Regex.Count(LlvmOracle.Run("llvm-objdump", option, path)!, @"^__\w+\s+__\w+\s+0x", RegexOptions.Multiline);
            if (name == "chained")
            {
                var info = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachODyldInfo, path)!;
                Assert.Equal(Regex.Count(info, @"\srebase\s"), m.Fixups.RebaseCount);
                Assert.Equal(Regex.Count(info, @"\sbind\s"), m.Fixups.BindCount);
            }
            else
            {
                Assert.Equal(Count(LlvmOracle.Options.MachORebase), m.Fixups.RebaseCount);
                Assert.Equal(Count(LlvmOracle.Options.MachOBind) + Count(LlvmOracle.Options.MachOLazyBind), m.Fixups.BindCount);
            }
            Assert.Contains(m.Exports, e => e.Name == "_api");
            Assert.Contains(m.Imports, i => i.Name == "_malloc");
            output.WriteLine($"{name}: {m.Fixups.Source}, {m.Fixups.RebaseCount} rebases, {m.Fixups.BindCount} binds, {m.FunctionStarts.Count} function starts");
        }
    }

    [Fact]
    public void MutatedImages_NeverThrow()
    {
        var withSignature = SampleMachO();
        withSignature.CodeSignature = new("id", "TEAM");
        withSignature.CompactUnwind = [(MachOWriter.TextOffset, 0x04000000)];
        var seeds = new List<byte[]> { SampleMachO().Build(), SampleMachO(1).Build(), withSignature.Build(), File.ReadAllBytes(NativeFixtures.OsxArm64AppHost) };
        int iterations = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_FORMAT_FUZZ_ITERATIONS"), out int n) ? n : 300;
        var failures = FormatFuzz.Run(seeds, iterations, 20261012, bytes => FormatFuzz.Touch(MachOFile.FromBytes(bytes, "fuzz.dylib"), m =>
        {
            _ = m.Fixups.All.Count + m.ExportTrie.Count + m.Stubs.Count + m.DataInCode.Count + m.FunctionStarts.Count + m.LoadCommands.Count;
            _ = m.Fixups.Resolve(m.ImageBase + MachOWriter.GotOffset);
            _ = m.CodeSignature?.Primary?.CdHashHex;
        }));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
