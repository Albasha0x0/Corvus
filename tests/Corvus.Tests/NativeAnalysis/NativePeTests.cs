using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The native PE parser on real System32 images and on synthetic, partly malformed images built in memory.</summary>
public sealed class NativePeTests
{
    /// <summary>Reads every public fact of <paramref name="pe"/> and a few mapped ranges; returns the issues.</summary>
    internal static IReadOnlyList<ParseIssue> TouchEverything(PeFile pe)
    {
        _ = (pe.Arch, pe.Is64Bit, pe.IsDll, pe.IsDotNet, pe.ImageBase, pe.EntryPointRva, pe.SizeOfImage, pe.SubsystemName, pe.MachineName);
        _ = (pe.CharacteristicNames, pe.DllCharacteristicNames, pe.DataDirectories, pe.SectionLayouts, pe.CertificateTable);
        _ = (pe.Imports, pe.ImportModules, pe.DelayImportModules, pe.BoundImports, pe.Exports, pe.ExportDirectory);
        _ = (pe.RelocationRvas, pe.BaseRelocations, pe.TlsCallbackRvas, pe.TlsDirectory, pe.RuntimeFunctions);
        _ = (pe.DebugEntries, pe.CodeView, pe.ExDllCharacteristicNames, pe.LoadConfig?.GuardFlagNames);
        _ = (pe.Resources, pe.VersionInfo, pe.Manifest, pe.ResourceStrings, pe.RichHeader, pe.Checksum, pe.Overlay, pe.Mitigations, pe.Certificate);
        Span<byte> buffer = stackalloc byte[64];
        foreach (var s in pe.Sections.Take(64))
        {
            pe.Read(s.Rva, buffer);
            if (pe.TryRvaToFileOffset(s.Rva, out long offset)) pe.TryFileOffsetToRva(offset, out _);
            pe.SectionAt(s.Rva);
            pe.SectionAt(s.Rva + s.MappedSize);
        }
        pe.Read(0, buffer);
        pe.Read(uint.MaxValue - 10, buffer);
        pe.Read(pe.SizeOfImage - 1, buffer);
        foreach (var r in pe.Resources.Take(64)) pe.ReadResource(r, 256);
        return pe.Issues;
    }

    private static PeFile Parse(byte[] bytes) => PeFile.FromBytes(bytes, "test.bin");

    private static bool HasIssue(PeFile pe, string area, string fragment) =>
        pe.Issues.Any(i => i.Area == area && i.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    private static PeBuilder Basic(bool is64 = true)
    {
        var b = new PeBuilder { Is64 = is64, Machine = is64 ? (ushort)0x8664 : (ushort)0x14c, ImageBase = is64 ? 0x140000000UL : 0x400000UL };
        if (!is64) b.Characteristics = 0x0102;
        var text = b.Add(".text", [0xC3, 0xCC, 0xCC, 0xCC], 0x60000020);
        b.EntryPoint = text.Rva;
        return b;
    }

    // ---- real images ----

    [WindowsFact]
    public void Kernel32_X64()
    {
        var path = PeCorpus.System32("kernel32.dll");
        if (path == null) return;
        var pe = PeFile.Open(path);
        Assert.Equal(NativeArch.X64, pe.Arch);
        Assert.True(pe.Is64Bit && pe.IsDll);
        Assert.Equal(64, pe.Sha256.Length);
        Assert.Empty(pe.Issues);

        Assert.Contains(pe.ImportModules, m => m.Name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase));
        Assert.All(pe.Imports, i => Assert.True(i.Name != null || i.Ordinal != null));
        Assert.Contains(pe.DelayImportModules, m => m.IsRvaBased && m.Functions.Count > 0);
        Assert.All(pe.Imports.Where(i => i.IsDelayLoad), i => Assert.NotNull(pe.SectionAt(i.SlotRva)));

        var forwarded = Assert.Single(pe.Exports, e => e.Name == "AcquireSRWLockExclusive");
        Assert.Equal("NTDLL.RtlAcquireSRWLockExclusive", forwarded.ForwardedTo);
        Assert.Contains(pe.Exports, e => e.Name == "GetProcAddress" && e.ForwardedTo == null && pe.SectionAt(e.Rva)?.IsExecutable == true);
        Assert.True(pe.ExportDirectory!.NamesSorted);

        Assert.NotEmpty(pe.RuntimeFunctions);
        Assert.True(pe.RuntimeFunctions.Zip(pe.RuntimeFunctions.Skip(1)).All(p => p.First.BeginRva <= p.Second.BeginRva));
        Assert.NotEmpty(pe.RelocationRvas);
        Assert.True(pe.RelocationRvas.Zip(pe.RelocationRvas.Skip(1)).All(p => p.First < p.Second));

        Assert.Equal("RSDS", pe.CodeView!.Format);
        Assert.EndsWith("kernel32.pdb", pe.CodeView.PdbPath, StringComparison.OrdinalIgnoreCase);
        Assert.True(pe.Checksum.Matches);
        Assert.True(pe.RichHeader is { ChecksumValid: true, Entries.Count: > 0 });

        var m = pe.Mitigations;
        Assert.True(m.Aslr && m.HighEntropyVa && m.Dep && m.ControlFlowGuard && m.GsCookie);
        Assert.Contains("CF_INSTRUMENTED", pe.LoadConfig!.GuardFlagNames);
        Assert.NotEmpty(pe.LoadConfig.GuardCfFunctions);

        var version = pe.VersionInfo!;
        var fvi = FileVersionInfo.GetVersionInfo(path);
        Assert.Equal($"{fvi.FileMajorPart}.{fvi.FileMinorPart}.{fvi.FileBuildPart}.{fvi.FilePrivatePart}", version.Fixed!.FileVersionText);
        Assert.Equal("Microsoft Corporation", version.Get("CompanyName"));
        Assert.Contains(version.Translations, t => (t & 0xFFFF) == 0x0409);

        // Mapping: section starts map to their raw data and back; mapped reads equal the file bytes.
        var file = File.ReadAllBytes(path);
        foreach (var s in pe.Sections.Where(s => s.RawSize > 0))
        {
            Assert.True(pe.TryRvaToFileOffset(s.Rva, out long offset));
            Assert.Equal(s.RawOffset, offset);
            Assert.True(pe.TryFileOffsetToRva(offset + 3, out uint back));
            Assert.Equal(s.Rva + 3, back);
            var mapped = new byte[16];
            Assert.Equal(16, pe.Read(s.Rva, mapped));
            Assert.Equal(file.AsSpan((int)s.RawOffset, 16).ToArray(), mapped);
            Assert.Same(s, pe.SectionAt(s.Rva));
        }
    }

    [WindowsFact]
    public void NtdllAndUser32()
    {
        if (PeCorpus.System32("ntdll.dll") is { } ntdll)
        {
            var pe = PeFile.Open(ntdll);
            Assert.Empty(pe.Imports);
            Assert.Contains(pe.Exports, e => e.Name == "NtCreateFile");
            Assert.Empty(pe.Issues);
        }
        if (PeCorpus.System32("user32.dll") is { } user32)
        {
            var pe = PeFile.Open(user32);
            Assert.Contains(pe.Exports, e => e.Name == null); // ordinal-only exports
            Assert.Empty(pe.Issues);
            // Its strings live in the language resource DLL (a resource-only PE).
            var system = Path.GetDirectoryName(user32)!;
            var mui = Directory.EnumerateDirectories(system).Select(d => Path.Combine(d, "user32.dll.mui")).FirstOrDefault(File.Exists);
            if (mui != null)
            {
                var res = PeFile.Open(mui);
                Assert.Contains(res.ResourceStrings, s => s.Text.Length > 0);
                Assert.NotNull(res.VersionInfo);
                Assert.Empty(res.Issues);
            }
        }
    }

    [WindowsFact]
    public void Kernel32_X86_SafeSeh()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var path = Path.Combine(windows, "SysWOW64", "kernel32.dll");
        if (!File.Exists(path)) return;
        var pe = PeFile.Open(path);
        Assert.Equal(NativeArch.X86, pe.Arch);
        Assert.False(pe.Is64Bit);
        Assert.True(pe.Mitigations.SafeSeh);
        Assert.Equal((int)pe.LoadConfig!.SeHandlerCount, pe.LoadConfig.SeHandlerRvas.Count);
        Assert.Empty(pe.RuntimeFunctions);
        Assert.Contains(pe.RelocationRvas, r => pe.SectionAt(r) != null);
        Assert.Empty(pe.Issues);
    }

    [WindowsFact]
    public void Shell32_Headers()
    {
        var path = PeCorpus.System32("shell32.dll");
        if (path == null) return;
        var pe = PeFile.Open(path);
        Assert.True(pe.Sections.Count > 3);
        Assert.Contains(pe.Sections, s => s.Name == ".rsrc");
        Assert.True(pe.Directory(PeDirectory.Resource).IsPresent);
        Assert.NotNull(pe.SectionAt(pe.EntryPointRva));
    }

    [WindowsFact]
    public void ChecksumMatchesImageHlp()
    {
        var b = Basic();
        b.Overlay = [1, 2, 3]; // odd length
        var bytes = b.Build();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(b.OptionalOffset + 64), 0x12345);
        var pe = Parse(bytes);
        uint expected = ImageHlpChecksum(bytes);
        Assert.Equal(expected, pe.Checksum.Computed);
        Assert.False(pe.Checksum.Matches);
    }

    [DllImport("imagehlp.dll")]
    private static extern IntPtr CheckSumMappedFile(IntPtr baseAddress, uint fileLength, out uint headerSum, out uint checkSum);

    private static uint ImageHlpChecksum(byte[] bytes)
    {
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            CheckSumMappedFile(handle.AddrOfPinnedObject(), (uint)bytes.Length, out _, out uint sum);
            return sum;
        }
        finally { handle.Free(); }
    }

    // ---- not a PE ----

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void NotAPe_Throws(int kind)
    {
        byte[] bytes = kind switch
        {
            0 => [],
            1 => "MZ"u8.ToArray(),
            2 => [(byte)'M', (byte)'Z', .. new byte[0x100]], // DOS program: e_lfanew 0, no PE signature
            _ => Encoding.ASCII.GetBytes("not an executable at all, just text padding padding padding padding"),
        };
        var e = Assert.Throws<ToolError>(() => PeFile.FromBytes(bytes));
        Assert.Equal(ErrorCode.MalformedInput, e.Code);
    }

    [Fact]
    public void LfanewOutOfRange_Throws()
    {
        var bytes = Basic().Build();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x3C), 0xFFFFFFF0);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Parse(bytes)).Code);
    }

    // ---- headers and sections ----

    [Fact]
    public void TruncatedAnywhere_NeverThrows()
    {
        var full = KitchenSink(is64: true);
        for (int length = PeBuilder.PeOffset + 4; length < full.Length; length += length < 0x400 ? 3 : 61)
        {
            var pe = Parse(full[..length]);
            TouchEverything(pe);
            if (length < PeBuilder.PeOffset + 24) Assert.True(HasIssue(pe, "headers", "COFF file header is truncated"));
        }
    }

    [Fact]
    public void SectionTablePastEndOfFile()
    {
        var b = Basic();
        var bytes = b.Build();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(PeBuilder.PeOffset + 6), 0xFFFF);
        var pe = Parse(bytes);
        Assert.True(HasIssue(pe, "headers", $"{PeLimits.MaxSections} are read"));
        Assert.True(HasIssue(pe, "headers", "section table extends past the end of the file"));
        TouchEverything(pe);
    }

    [Fact]
    public void BogusDirectories_RecordIssuesPerArea()
    {
        var b = Basic();
        for (int i = 0; i < 16; i++) b.Directories[i] = (0xFFFFFF00, 0xFFFFFFFF);
        b.NumberOfRvaAndSizes = 0xFFFFFFFF;
        var pe = Parse(b.Build());
        var issues = TouchEverything(pe);
        Assert.Contains(issues, i => i.Area == "headers" && i.Message.Contains("NumberOfRvaAndSizes"));
        foreach (var area in new[] { "imports", "delay imports", "exports", "relocations", "tls", "exception directory", "debug directory", "load config", "resources" })
            Assert.Contains(issues, i => i.Area == area);
        Assert.Empty(pe.Imports);
        Assert.Empty(pe.Exports);
        Assert.DoesNotContain(issues, i => i.Message.StartsWith("internal error", StringComparison.Ordinal));
    }

    [Fact]
    public void SectionLayout_LoaderRules()
    {
        var b = Basic();
        var bss = b.Add(".bss", [], 0xC0000080, virtualSize: 0x3000); // raw size 0
        var noVirtual = b.Add(".novs", Enumerable.Repeat((byte)0xAB, 0x300).ToArray());
        noVirtual.VirtualSize = 0; // virtual size 0: the raw size is used
        var shifted = b.Add(".shift", Enumerable.Range(0, 0x400).Select(i => (byte)i).ToArray());
        var bytes = b.Build();
        var pe = Parse(bytes);
        Assert.Empty(pe.Issues);
        Assert.Same(pe.Sections[1], pe.SectionAt(bss.Rva + 0x2FFF));
        Assert.False(pe.TryRvaToFileOffset(bss.Rva, out _));
        var zero = new byte[4];
        Assert.Equal(4, pe.Read(bss.Rva + 0x10, zero));
        Assert.Equal(new byte[4], zero);
        Assert.Same(pe.Sections[2], pe.SectionAt(noVirtual.Rva + 0x2FF));
        Assert.Equal(0x1000u, pe.SectionLayouts[2].MappedSize);

        // Raw pointer 0x1FF past a 0x200 boundary: the loader maps from the boundary.
        uint rawOffset = pe.Sections[3].RawOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(b.SectionTableOffset + 3 * 40 + 20), rawOffset + 0x1FF);
        pe = Parse(bytes);
        Assert.True(pe.TryRvaToFileOffset(shifted.Rva, out long mappedFrom));
        Assert.Equal(rawOffset, mappedFrom);
    }

    [Fact]
    public void SectionLayout_RawDataPastEndOfFile_ReadsZeros()
    {
        var b = Basic();
        var data = b.Add(".data", Enumerable.Repeat((byte)0x5A, 0x400).ToArray());
        var bytes = b.Build()[..^0x200]; // cut the second half of .data
        var pe = Parse(bytes);
        Assert.True(HasIssue(pe, "headers", "extends past the end of the file"));
        var buffer = new byte[0x400];
        Assert.Equal(0x400, pe.Read(data.Rva, buffer));
        Assert.All(buffer[..0x200], v => Assert.Equal(0x5A, v));
        Assert.All(buffer[0x200..], v => Assert.Equal(0, v));
    }

    [Fact]
    public void SectionLayout_Overlap_LowerSectionWins()
    {
        var b = Basic();
        var first = b.Add(".a", new byte[0x2000]);
        var second = b.Add(".b", new byte[0x100]);
        second.Rva = first.Rva + 0x1000; // inside .a
        var pe = Parse(b.Build());
        Assert.True(HasIssue(pe, "headers", "overlaps"));
        Assert.Equal(".a", pe.SectionAt(second.Rva)!.Name);
    }

    [Fact]
    public void SectionLayout_FlatWhenAlignmentBelowPage()
    {
        var b = new PeBuilder { SectionAlignment = 0x200, FileAlignment = 0x200 };
        var text = b.Add(".text", [0x90, 0xC3]);
        b.EntryPoint = text.Rva;
        var bytes = b.Build();
        var pe = Parse(bytes);
        Assert.Empty(pe.Issues);
        Assert.True(pe.TryRvaToFileOffset(text.Rva, out long offset));
        Assert.Equal(text.Rva, (uint)offset);
        Assert.True(pe.TryRvaToFileOffset(0x10, out offset));
        Assert.Equal(0x10, offset);
    }

    [Fact]
    public void SectionLayout_ReadyToRunForAnotherOsMapsThroughTheSectionTable()
    {
        // crossgen for macOS / Linux: ARM64 ^ the Apple mask, 0x200 alignment, RVAs 0x10000 apart from the file offsets.
        var b = new PeBuilder { Machine = 0xAA64 ^ 0x4644, SectionAlignment = 0x200, FileAlignment = 0x200 };
        var text = b.Add(".text", [1, 2, 3, 4]);
        text.Rva = 0x10200;
        text.RawOffset = 0x200;
        var pe = Parse(b.Build());
        Assert.True(pe.TryRvaToFileOffset(0x10200, out long offset));
        Assert.Equal(0x200, offset);
        var buffer = new byte[4];
        Assert.Equal(4, pe.Read(0x10200, buffer));
        Assert.Equal([1, 2, 3, 4], buffer);
        Assert.Equal("Apple", PeNames.NonWindowsReadyToRunOs(pe.Coff.Machine));
        Assert.Null(PeNames.NonWindowsReadyToRunOs(0x8664));
    }

    [Fact]
    public void MappedReadsCrossSections()
    {
        var b = Basic();
        var a = b.Add(".a", Enumerable.Repeat((byte)1, 0x1000).ToArray());
        b.Add(".b", Enumerable.Repeat((byte)2, 0x10).ToArray());
        var pe = Parse(b.Build());
        var buffer = new byte[0x20];
        Assert.Equal(0x20, pe.Read(a.Rva + 0x1000 - 0x10, buffer));
        Assert.Equal([.. Enumerable.Repeat((byte)1, 0x10), .. Enumerable.Repeat((byte)2, 0x10)], buffer);
        Assert.Equal(0, pe.Read(pe.SizeOfImage + 0x1000, buffer));
    }

    // ---- imports ----

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Imports_ByNameOrdinalAndHint(bool is64)
    {
        var b = Basic(is64);
        uint descriptors = 0, iat = 0;
        b.Add(".idata", rva =>
        {
            var blob = new PeBlob(rva);
            descriptors = blob.Zero(20 * 3);
            uint k32 = blob.Ascii("KERNEL32.dll");
            uint user = blob.Ascii("USER32.dll");
            blob.Align(2);
            uint exit = blob.U16(0x167);
            blob.Ascii("ExitProcess");
            blob.Align(8);
            ulong ordinalFlag = is64 ? 1UL << 63 : 1UL << 31;
            uint ilt = blob.Ptr(is64, exit);
            blob.Ptr(is64, ordinalFlag | 42);
            blob.Ptr(is64, 0);
            iat = blob.Ptr(is64, exit);
            blob.Ptr(is64, ordinalFlag | 42);
            blob.Ptr(is64, 0);
            uint iat2 = blob.Ptr(is64, ordinalFlag | 7); // USER32 without a name table
            blob.Ptr(is64, 0);
            blob.Patch32(descriptors, ilt);
            blob.Patch32(descriptors + 12, k32);
            blob.Patch32(descriptors + 16, iat);
            blob.Patch32(descriptors + 20 + 12, user);
            blob.Patch32(descriptors + 20 + 16, iat2);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Import] = (descriptors, 60);
        var pe = Parse(b.Build());
        Assert.Empty(pe.Issues);
        Assert.Equal(["KERNEL32.dll", "USER32.dll"], pe.ImportModules.Select(m => m.Name));
        var exit = pe.Imports[0];
        Assert.Equal(("KERNEL32.dll", "ExitProcess", (ushort?)null, (ushort)0x167, iat, false), (exit.Module, exit.Name, exit.Ordinal, exit.Hint, exit.SlotRva, exit.IsDelayLoad));
        Assert.Equal((ushort)42, pe.Imports[1].Ordinal);
        Assert.Equal(iat + (uint)(is64 ? 8 : 4), pe.Imports[1].SlotRva);
        Assert.Equal((ushort)7, Assert.Single(pe.ImportModules[1].Functions).Ordinal);
    }

    [Fact]
    public void Imports_Unterminated_HitsLimitsInBoundedTime()
    {
        // A section of repeated descriptors whose name table is a long run of name thunks.
        var b = Basic();
        uint first = 0;
        b.Add(".idata", rva =>
        {
            var blob = new PeBlob(rva);
            uint name = blob.Ascii("LOOP.dll");
            blob.Align(2);
            uint hint = blob.U16(1);
            blob.Ascii("F");
            blob.Align(8);
            uint thunks = blob.Here;
            for (int i = 0; i < 0x20000; i++) blob.U64(hint);
            first = blob.Here;
            for (int i = 0; i < 0x2000; i++)
            {
                blob.U32(thunks);
                blob.U32(0);
                blob.U32(0);
                blob.U32(name);
                blob.U32(thunks);
            }
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Import] = (first, 20);
        var cpu = ThreadCpuClock.Now();
        var pe = Parse(b.Build());
        var issues = TouchEverything(pe);
        Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(5), $"took {took} of CPU");
        Assert.Contains(issues, i => i.Area == "imports" && i.Message.Contains("not read"));
        Assert.True(pe.Imports.Count <= PeLimits.MaxImports);
    }

    [Fact]
    public void Imports_BoundDirectory()
    {
        var b = Basic();
        var bytes = b.Build();
        // Bound import table in the header slack after the section table.
        int at = b.SectionTableOffset + b.Sections.Count * 40 + 8;
        var span = bytes.AsSpan(at);
        BinaryPrimitives.WriteUInt32LittleEndian(span, 0x5000_0000);
        BinaryPrimitives.WriteUInt16LittleEndian(span[4..], 24);
        BinaryPrimitives.WriteUInt16LittleEndian(span[6..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], 0x5000_0001);
        BinaryPrimitives.WriteUInt16LittleEndian(span[12..], 37);
        Encoding.ASCII.GetBytes("KERNEL32.dll\0NTDLL.DLL\0").CopyTo(span[24..]);
        int dir = b.OptionalOffset + 112 + PeDirectory.BoundImport * 8;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dir), (uint)at);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dir + 4), 64);
        var pe = Parse(bytes);
        var bound = Assert.Single(pe.BoundImports);
        Assert.Equal("KERNEL32.dll", bound.Module);
        Assert.Equal(new PeBoundForwarder("NTDLL.DLL", 0x5000_0001), Assert.Single(bound.Forwarders));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DelayImports_RvaAndVaBased(bool rvaBased)
    {
        var b = Basic(is64: false);
        uint descriptor = 0, iat = 0;
        uint Va(uint rva) => rvaBased ? rva : rva + (uint)b.ImageBase;
        b.Add(".didat", rva =>
        {
            var blob = new PeBlob(rva);
            descriptor = blob.Zero(32 * 2);
            uint name = blob.Ascii("COMDLG32.dll");
            blob.Align(2);
            uint hint = blob.U16(3);
            blob.Ascii("GetOpenFileNameW");
            blob.Align(4);
            uint hmod = blob.U32(0);
            uint nameTable = blob.U32(Va(hint));
            blob.U32(0x80000010);
            blob.U32(0);
            iat = blob.U32(0x401000);
            blob.U32(0x401000);
            blob.U32(0);
            blob.Patch32(descriptor, rvaBased ? 1u : 0u);
            blob.Patch32(descriptor + 4, Va(name));
            blob.Patch32(descriptor + 8, Va(hmod));
            blob.Patch32(descriptor + 12, Va(iat));
            blob.Patch32(descriptor + 16, Va(nameTable));
            return blob.ToArray();
        });
        b.Directories[PeDirectory.DelayImport] = (descriptor, 64);
        var pe = Parse(b.Build());
        Assert.Empty(pe.Issues);
        var module = Assert.Single(pe.DelayImportModules);
        Assert.Equal(("COMDLG32.dll", rvaBased, iat), (module.Name, module.IsRvaBased, module.AddressTableRva));
        Assert.Equal(2, module.Functions.Count);
        Assert.Equal(("GetOpenFileNameW", (ushort)3, iat, true), (module.Functions[0].Name, module.Functions[0].Hint, module.Functions[0].SlotRva, module.Functions[0].IsDelayLoad));
        Assert.Equal((ushort)0x10, module.Functions[1].Ordinal);
        Assert.Equal(pe.Imports, module.Functions);
    }

    // ---- exports ----

    [Fact]
    public void Exports_NamesOrdinalsForwardersGaps()
    {
        var b = Basic();
        uint dir = 0, dirSize = 0, forwarder = 0, code = b.Sections[0].Rva;
        b.Add(".edata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            uint dll = blob.Ascii("test.dll");
            uint eat = blob.U32(code);         // ordinal 10: two names
            blob.U32(0);                       // ordinal 11: gap
            uint fwdSlot = blob.U32(0);        // ordinal 12: forwarder
            blob.U32(code + 1);                // ordinal 13: no name
            uint zeta = blob.Ascii("Zeta");
            uint alpha = blob.Ascii("Alpha");
            uint fwd = blob.Ascii("Fwd");
            forwarder = blob.Ascii("OTHER.Target");
            blob.Align(4);
            uint names = blob.U32(zeta);       // unsorted on purpose
            blob.U32(alpha);
            blob.U32(fwd);
            uint ordinals = blob.U16(0);
            blob.U16(0);
            blob.U16(2);
            dirSize = blob.Here - dir;
            blob.Patch32(fwdSlot, forwarder);
            blob.Patch32(dir + 12, dll);
            blob.Patch32(dir + 16, 10);
            blob.Patch32(dir + 20, 4);
            blob.Patch32(dir + 24, 3);
            blob.Patch32(dir + 28, eat);
            blob.Patch32(dir + 32, names);
            blob.Patch32(dir + 36, ordinals);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Export] = (dir, dirSize);
        var pe = Parse(b.Build());
        Assert.Equal("test.dll", pe.ExportDirectory!.DllName);
        Assert.False(pe.ExportDirectory.NamesSorted);
        Assert.True(HasIssue(pe, "exports", "not sorted"));
        Assert.Equal(
            [new NativeExport("Zeta", 10, code, null), new NativeExport("Alpha", 10, code, null), new NativeExport("Fwd", 12, forwarder, "OTHER.Target"), new NativeExport(null, 13, code + 1, null)],
            pe.Exports);
    }

    [Fact]
    public void Exports_HugeCounts_Capped()
    {
        var b = Basic();
        uint dir = 0;
        b.Add(".edata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            blob.Patch32(dir + 20, 0xFFFFFFFF);
            blob.Patch32(dir + 24, 0xFFFFFFFF);
            blob.Patch32(dir + 28, rva);
            blob.Patch32(dir + 32, rva);
            blob.Patch32(dir + 36, rva);
            return [.. blob.ToArray(), .. new byte[0x10000]];
        });
        b.Directories[PeDirectory.Export] = (dir, 40);
        var cpu = ThreadCpuClock.Now();
        var pe = Parse(b.Build());
        TouchEverything(pe);
        Assert.True(ThreadCpuClock.Now() - cpu is var took && took < TimeSpan.FromSeconds(5), $"took {took} of CPU");
        Assert.True(HasIssue(pe, "exports", "declares 4294967295 entries"));
        Assert.True(pe.Exports.Count < 0x10000);
    }

    // ---- relocations, TLS, exception directory ----

    [Fact]
    public void Relocations_TypesAndPointerRvas()
    {
        var b = Basic();
        uint dir = 0, size = 0;
        b.Add(".reloc", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.U32(0x1000);
            blob.U32(8 + 6 * 2);
            blob.U16(0xA000 | 0x010); // DIR64
            blob.U16(0xA000 | 0x008); // DIR64, out of order
            blob.U16(0xA000 | 0x010); // duplicate
            blob.U16(0x3000 | 0x020); // HIGHLOW: not pointer-sized in PE32+
            blob.U16(0x4000 | 0x030); // HIGHADJ + parameter
            blob.U16(0x1234);
            blob.U32(0x2000);
            blob.U32(8 + 2);
            blob.U16(0);              // ABSOLUTE padding
            blob.Align(4);
            blob.U32(0x3000);
            blob.U32(0);              // size 0 ends the walk
            size = blob.Here - dir + 64;
            return [.. blob.ToArray(), .. new byte[64]];
        }, 0x42000040);
        b.Directories[PeDirectory.BaseRelocation] = (dir, size);
        var pe = Parse(b.Build());
        Assert.Equal([0x1008u, 0x1010u], pe.RelocationRvas);
        Assert.Equal(5, pe.BaseRelocations.Count);
        Assert.Equal(new PeRelocation(0x1030, PeRelocationType.HighAdj, 0x1234), pe.BaseRelocations[4]);
        Assert.True(HasIssue(pe, "relocations", "size 0"));
    }

    [Fact]
    public void Tls_CallbacksAndUnrelocatedSlot()
    {
        var b = Basic();
        uint code = b.Sections[0].Rva, dir = 0, array = 0;
        b.Add(".tls", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(40);
            array = blob.U64(b.ImageBase + code);
            blob.U64(b.ImageBase + code + 2);
            blob.U64(0);
            blob.U64(0xDEAD); // after the terminator: not read
            blob.Patch32(dir + 24, (uint)(b.ImageBase + array));
            blob.Patch32(dir + 28, (uint)((b.ImageBase + array) >> 32));
            return blob.ToArray();
        });
        uint reloc = 0;
        b.Add(".reloc", rva =>
        {
            var blob = new PeBlob(rva);
            reloc = blob.U32(array & ~0xFFFu);
            blob.U32(12);
            blob.U16((ushort)(0xA000 | (array & 0xFFF))); // only the first slot
            blob.U16(0);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Tls] = (dir, 40);
        b.Directories[PeDirectory.BaseRelocation] = (reloc, 12);
        var pe = Parse(b.Build());
        Assert.Equal([code, code + 2], pe.TlsCallbackRvas);
        Assert.Equal(b.ImageBase + array, pe.TlsDirectory!.AddressOfCallBacks);
        Assert.True(HasIssue(pe, "tls", "no base relocation"));
    }

    [Fact]
    public void RuntimeFunctions_Arm64PackedAndUnpacked()
    {
        var b = new PeBuilder { Machine = 0xAA64 };
        var text = b.Add(".text", new byte[0x100], 0x60000020);
        b.EntryPoint = text.Rva;
        uint pdata = 0, xdata = 0;
        b.Add(".pdata", rva =>
        {
            var blob = new PeBlob(rva);
            xdata = blob.U32(0x10); // .xdata header: function length 0x10 words
            blob.U32(0);
            pdata = blob.U32(text.Rva + 0x40);
            blob.U32(xdata);
            blob.U32(text.Rva);
            blob.U32(1 | (8 << 2)); // packed, 8 words
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Exception] = (pdata, 16);
        var pe = Parse(b.Build());
        Assert.Equal(NativeArch.Arm64, pe.Arch);
        Assert.Equal([new RuntimeFunction(text.Rva, text.Rva + 32, 0), new RuntimeFunction(text.Rva + 0x40, text.Rva + 0x80, xdata)], pe.RuntimeFunctions);
        Assert.True(HasIssue(pe, "exception directory", "not sorted"));
    }

    [Fact]
    public void LoadConfig_X86SafeSehAndCookie()
    {
        var b = Basic(is64: false);
        uint dir = 0, code = b.Sections[0].Rva;
        b.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            dir = blob.Zero(0x5C);
            uint handlers = blob.U32(code);
            blob.U32(code + 1);
            blob.Patch32(dir, 0x5C);
            blob.Patch32(dir + 60, 0x403000);
            blob.Patch32(dir + 64, (uint)b.ImageBase + handlers);
            blob.Patch32(dir + 68, 2);
            return blob.ToArray();
        });
        b.Directories[PeDirectory.LoadConfig] = (dir, 0x40);
        var pe = Parse(b.Build());
        Assert.Equal(0x403000UL, pe.LoadConfig!.SecurityCookie);
        Assert.Equal([code, code + 1], pe.LoadConfig.SeHandlerRvas);
        Assert.True(pe.Mitigations is { SafeSeh: true, GsCookie: true, Dep: true, Aslr: true, HighEntropyVa: false });
    }

    // ---- resources ----

    private sealed record Res(uint Type, uint Name, uint Lang, byte[] Data);

    /// <summary>A three-level resource tree with the given data entries, followed by their data.</summary>
    private static byte[] ResourceTree(uint rva, IReadOnlyList<Res> items)
    {
        var blob = new PeBlob(rva);
        var types = items.GroupBy(i => i.Type).ToList();
        var dataEntries = new List<(uint EntryRva, Res Item)>();
        uint Dir(int idCount)
        {
            uint at = blob.Zero(12);
            blob.U16(0);
            blob.U16((ushort)idCount);
            return at;
        }
        uint root = Dir(types.Count);
        var typeSlots = types.Select(t => (blob.U32(t.Key), blob.U32(0))).ToList();
        for (int t = 0; t < types.Count; t++)
        {
            var names = types[t].GroupBy(i => i.Name).ToList();
            uint typeDir = Dir(names.Count);
            blob.Patch32(typeSlots[t].Item2, 0x80000000 | (typeDir - root));
            var nameSlots = names.Select(n => (blob.U32(n.Key), blob.U32(0))).ToList();
            for (int n = 0; n < names.Count; n++)
            {
                var langs = names[n].ToList();
                uint nameDir = Dir(langs.Count);
                blob.Patch32(nameSlots[n].Item2, 0x80000000 | (nameDir - root));
                var langSlots = langs.Select(l => (blob.U32(l.Lang), blob.U32(0))).ToList();
                for (int l = 0; l < langs.Count; l++)
                {
                    uint entry = blob.Zero(16);
                    blob.Patch32(langSlots[l].Item2, entry - root);
                    dataEntries.Add((entry, langs[l]));
                }
            }
        }
        foreach (var (entry, item) in dataEntries)
        {
            blob.Align(4);
            uint at = blob.Bytes(item.Data);
            blob.Patch32(entry, at);
            blob.Patch32(entry + 4, (uint)item.Data.Length);
        }
        return blob.ToArray();
    }

    /// <summary>A VS_VERSIONINFO block: length, value length, type, key, value, children; 4-byte aligned.</summary>
    private static byte[] VersionBlock(string key, byte[] value, bool text, params byte[][] children)
    {
        var b = new List<byte>(new byte[6]);
        b.AddRange(Encoding.Unicode.GetBytes(key + "\0"));
        while (b.Count % 4 != 0) b.Add(0);
        b.AddRange(value);
        while (b.Count % 4 != 0) b.Add(0);
        foreach (var c in children)
        {
            b.AddRange(c);
            while (b.Count % 4 != 0) b.Add(0);
        }
        var r = b.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(r, (ushort)r.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(2), (ushort)(text ? value.Length / 2 : value.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(r.AsSpan(4), (ushort)(text ? 1 : 0));
        return r;
    }

    private static byte[] VersionResource()
    {
        var fixedInfo = new byte[52];
        uint[] f = [0xFEEF04BD, 0x10000, 0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008, 0x3F, 0, 0x40004, 1, 0, 0, 0];
        for (int i = 0; i < f.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(fixedInfo.AsSpan(i * 4), f[i]);
        byte[] S(string k, string v) => VersionBlock(k, Encoding.Unicode.GetBytes(v + "\0"), true);
        var table = VersionBlock("040904b0", [], true, S("CompanyName", "Example Corp"), S("FileVersion", "1.2.3.4"));
        var strings = VersionBlock("StringFileInfo", [], true, table);
        var vars = VersionBlock("VarFileInfo", [], true, VersionBlock("Translation", [0x09, 0x04, 0xB0, 0x04], false));
        return VersionBlock("VS_VERSION_INFO", fixedInfo, false, strings, vars);
    }

    private static byte[] StringBlock(params string[] strings)
    {
        var b = new List<byte>();
        for (int i = 0; i < 16; i++)
        {
            string s = i < strings.Length ? strings[i] : "";
            b.Add((byte)s.Length);
            b.Add((byte)(s.Length >> 8));
            b.AddRange(Encoding.Unicode.GetBytes(s));
        }
        return [.. b];
    }

    [Fact]
    public void Resources_VersionManifestStrings()
    {
        var b = Basic();
        var manifest = "﻿<assembly manifestVersion=\"1.0\"/>";
        var rsrc = b.Add(".rsrc", rva => ResourceTree(rva,
        [
            new(PeFile.RtVersion, 1, 0x409, VersionResource()),
            new(PeFile.RtManifest, 1, 0x409, Encoding.UTF8.GetBytes(manifest)),
            new(PeFile.RtString, 2, 0x409, StringBlock("first", "", "third")),
            new(3, 7, 0x407, [1, 2, 3]),
        ]));
        b.Directories[PeDirectory.Resource] = (rsrc.Rva, (uint)rsrc.Data.Length);
        var pe = Parse(b.Build());
        Assert.Empty(pe.Issues);
        Assert.Equal(4, pe.Resources.Count);
        var icon = pe.Resources.Single(r => r.TypeName == "ICON");
        Assert.Equal((7u, 0x407u, 3u), (icon.Name!.Id, icon.Language, icon.Size));
        Assert.Equal([1, 2, 3], pe.ReadResource(icon));

        var v = pe.VersionInfo!;
        Assert.Equal("1.2.3.4", v.Fixed!.FileVersionText);
        Assert.Equal("5.6.7.8", v.Fixed.ProductVersionText);
        Assert.Equal("Example Corp", v.Get("CompanyName"));
        Assert.Equal("040904b0", Assert.Single(v.StringTables).Key);
        Assert.Equal([0x04B00409u], v.Translations);
        Assert.Equal("<assembly manifestVersion=\"1.0\"/>", pe.Manifest);
        Assert.Equal([new PeResourceString(16, 0x409, "first"), new PeResourceString(18, 0x409, "third")], pe.ResourceStrings);
    }

    [Fact]
    public void Resources_IconGroupsPairWithIconsAndCarryFileRanges()
    {
        // GRPICONDIR naming icon 1 (present, a PNG) and icon 2 (missing); icon 3 is a 16x16 DIB in no group.
        var group = new byte[6 + 2 * 14];
        group[2] = 1;
        group[4] = 2;
        (group[6], group[7], group[12]) = (0, 0, 32); // 256x256 32bpp
        BinaryPrimitives.WriteUInt16LittleEndian(group.AsSpan(6 + 12), 1);
        (group[20], group[21], group[26]) = (16, 16, 8);
        BinaryPrimitives.WriteUInt16LittleEndian(group.AsSpan(20 + 12), 2);
        byte[] png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, (byte)'I', (byte)'H', (byte)'D', (byte)'R', 0, 0, 1, 0, 0, 0, 1, 0, 8, 6];
        var dib = new byte[40 + 64];
        BinaryPrimitives.WriteUInt32LittleEndian(dib, 40);
        BinaryPrimitives.WriteInt32LittleEndian(dib.AsSpan(4), 16);
        BinaryPrimitives.WriteInt32LittleEndian(dib.AsSpan(8), 32);
        BinaryPrimitives.WriteUInt16LittleEndian(dib.AsSpan(14), 4);
        var b = Basic();
        var rsrc = b.Add(".rsrc", rva => ResourceTree(rva, [new(14, 1, 0x409, group), new(3, 1, 0x409, png), new(3, 3, 0x409, dib)]));
        b.Directories[PeDirectory.Resource] = (rsrc.Rva, (uint)rsrc.Data.Length);
        var bytes = b.Build();
        var rows = Corvus.Tools.ResourceTools.Win32(Parse(bytes));

        var g = rows.Single(r => r.Name == "GROUP_ICON/#1/1033");
        Assert.Equal([1, 2], g.Icons);
        Assert.Equal([new Corvus.Tools.IconRef(1, 256, 256, 32, "ICON/#1/1033"), new Corvus.Tools.IconRef(2, 16, 16, 8, null)], g.IconEntries);
        var icon = rows.Single(r => r.Name == "ICON/#1/1033");
        Assert.Equal(["GROUP_ICON/#1/1033"], icon.IconGroups);
        Assert.Equal("png 256x256", icon.Image);
        var loose = rows.Single(r => r.Name == "ICON/#3/1033");
        Assert.Null(loose.IconGroups);
        Assert.Equal("dib 16x16 4bpp", loose.Image);
        // The file range holds exactly the hashed bytes.
        long start = Convert.ToInt64(icon.FileOffset, 16), end = Convert.ToInt64(icon.FileEnd, 16);
        Assert.Equal(png, bytes[(int)start..(int)end]);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(png)), icon.Sha256);
    }

    [Fact]
    public void Resources_CycleAndDepth()
    {
        var b = Basic();
        var rsrc = b.Add(".rsrc", rva =>
        {
            var blob = new PeBlob(rva);
            // Root: one entry pointing back at the root (a cycle), one entry leading into a chain deeper than the limit.
            blob.Zero(12);
            blob.U16(0);
            blob.U16(2);
            blob.U32(1);
            blob.U32(0x80000000);
            blob.U32(2);
            blob.U32(0x80000000 | 32);
            for (int level = 0; level < PeLimits.MaxResourceDepth + 4; level++)
            {
                uint here = blob.Here - rva;
                blob.Zero(12);
                blob.U16(0);
                blob.U16(1);
                blob.U32((uint)level);
                blob.U32(0x80000000 | (here + 24));
            }
            return blob.ToArray();
        });
        b.Directories[PeDirectory.Resource] = (rsrc.Rva, (uint)rsrc.Data.Length);
        var pe = Parse(b.Build());
        Assert.Empty(pe.Resources);
        Assert.True(HasIssue(pe, "resources", "referenced again"));
        Assert.True(HasIssue(pe, "resources", "deeper than"));
    }

    // ---- rich header, overlay ----

    [Fact]
    public void RichHeaderAndOverlay()
    {
        var b = Basic();
        b.Overlay = Enumerable.Repeat((byte)0xEE, 100).ToArray();
        var bytes = b.Build();
        // Rich header: DanS, 3 padding, 2 records, Rich, key; key = checksum.
        const int dans = 0x40;
        var records = new (uint CompId, uint Count)[] { (0x0104_7809, 3), (0x0001_0000, 12) };
        uint checksum = dans;
        for (int i = 0; i < dans; i++)
            if (i is < 0x3C or >= 0x40) checksum += System.Numerics.BitOperations.RotateLeft(bytes[i], i);
        foreach (var (id, count) in records) checksum += System.Numerics.BitOperations.RotateLeft(id, (int)(count & 31));
        uint key = checksum;
        var words = new List<uint> { 0x536E6144 ^ key, key, key, key };
        foreach (var (id, count) in records) { words.Add(id ^ key); words.Add(count ^ key); }
        words.Add(0x68636952);
        words.Add(key);
        for (int i = 0; i < words.Count; i++) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dans + i * 4), words[i]);

        var pe = Parse(bytes);
        var rich = pe.RichHeader!;
        Assert.True(rich.ChecksumValid);
        Assert.Equal([new PeRichEntry(0x0104, 0x7809, 3), new PeRichEntry(1, 0, 12)], rich.Entries);
        Assert.Equal(new PeOverlay(bytes.Length - 100, 100, false), pe.Overlay);

        bytes[dans + 16] ^= 1; // edit a record
        Assert.False(Parse(bytes).RichHeader!.ChecksumValid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void KitchenSink_ParsesCleanly(bool is64)
    {
        var pe = Parse(KitchenSink(is64));
        Assert.Empty(TouchEverything(pe));
        Assert.Equal(["KERNEL32.dll", "USER32.dll"], pe.Imports.Select(i => i.Module).Distinct());
        Assert.Equal(["First", "Second"], pe.Exports.Select(e => e.Name));
        Assert.Single(pe.TlsCallbackRvas);
        Assert.Equal(2, pe.LoadConfig!.GuardCfFunctions.Count);
        Assert.Equal("seed.pdb", pe.CodeView!.PdbPath);
        Assert.NotNull(pe.VersionInfo);
        Assert.Equal(is64 ? 1 : 0, pe.RuntimeFunctions.Count);
    }

    [Fact]
    public void MutatedImages_QuickFuzz()
    {
        var seeds = new List<(string, byte[])> { ("kitchen sink x64", KitchenSink(true)), ("kitchen sink x86", KitchenSink(false)) };
        var result = PeFuzzer.Run(seeds, iterations: 300, seed: 1);
        Assert.True(result.Failures.Count == 0, string.Join("\n", result.Failures));
    }

    /// <summary>
    /// A synthetic image with every directory the parser reads: imports, delay imports, exports, TLS, load config with a
    /// CFG table, CodeView, .pdata (x64), base relocations and resources.
    /// </summary>
    internal static byte[] KitchenSink(bool is64)
    {
        var b = Basic(is64);
        uint code = b.Sections[0].Rva, callbacks = 0;
        var dirs = new Dictionary<int, (uint, uint)>();
        b.Add(".rdata", rva =>
        {
            var blob = new PeBlob(rva);
            uint descriptors = blob.Zero(40);
            uint name = blob.Ascii("KERNEL32.dll");
            blob.Align(2);
            uint hint = blob.U16(1);
            blob.Ascii("ExitProcess");
            blob.Align(8);
            uint ilt = blob.Ptr(is64, hint);
            blob.Ptr(is64, 0);
            uint iat = blob.Ptr(is64, hint);
            blob.Ptr(is64, 0);
            blob.Patch32(descriptors, ilt);
            blob.Patch32(descriptors + 12, name);
            blob.Patch32(descriptors + 16, iat);
            dirs[PeDirectory.Import] = (descriptors, 40);

            uint delay = blob.Zero(64);
            uint delayName = blob.Ascii("USER32.dll");
            blob.Align(2);
            uint delayHint = blob.U16(2);
            blob.Ascii("MessageBoxW");
            blob.Align(8);
            uint delayNames = blob.Ptr(is64, delayHint);
            blob.Ptr(is64, 0);
            uint delayIat = blob.Ptr(is64, b.ImageBase + code);
            blob.Ptr(is64, 0);
            uint module = blob.Ptr(is64, 0);
            blob.Patch32(delay, 1);
            blob.Patch32(delay + 4, delayName);
            blob.Patch32(delay + 8, module);
            blob.Patch32(delay + 12, delayIat);
            blob.Patch32(delay + 16, delayNames);
            dirs[PeDirectory.DelayImport] = (delay, 64);

            uint exports = blob.Zero(40);
            uint dll = blob.Ascii("seed.dll");
            blob.Align(4);
            uint eat = blob.U32(code);
            blob.U32(code + 1);
            uint first = blob.Ascii("First");
            uint second = blob.Ascii("Second");
            blob.Align(4);
            uint names = blob.U32(first);
            blob.U32(second);
            uint ordinals = blob.U16(0);
            blob.U16(1);
            blob.Patch32(exports + 12, dll);
            blob.Patch32(exports + 16, 1);
            blob.Patch32(exports + 20, 2);
            blob.Patch32(exports + 24, 2);
            blob.Patch32(exports + 28, eat);
            blob.Patch32(exports + 32, names);
            blob.Patch32(exports + 36, ordinals);
            dirs[PeDirectory.Export] = (exports, blob.Here - exports);

            blob.Align(8);
            uint tls = blob.Zero(is64 ? 40 : 24);
            callbacks = blob.Ptr(is64, b.ImageBase + code);
            blob.Ptr(is64, 0);
            ulong callbacksVa = b.ImageBase + callbacks;
            blob.Patch32(tls + (is64 ? 24u : 12u), (uint)callbacksVa);
            if (is64) blob.Patch32(tls + 28, (uint)(callbacksVa >> 32));
            dirs[PeDirectory.Tls] = (tls, is64 ? 40u : 24u);

            uint lcSize = is64 ? 0x140u : 0xC0u;
            uint lc = blob.Zero((int)lcSize);
            uint cf = blob.U32(code);
            blob.Bytes([0]);
            blob.U32(code + 1);
            blob.Bytes([1]);
            void Pointer(uint at32, uint at64, ulong v)
            {
                blob.Patch32(lc + (is64 ? at64 : at32), (uint)v);
                if (is64) blob.Patch32(lc + at64 + 4, (uint)(v >> 32));
            }
            blob.Patch32(lc, lcSize);
            Pointer(60, 88, b.ImageBase + lc + 8);
            Pointer(80, 128, b.ImageBase + cf);
            Pointer(84, 136, 2);
            blob.Patch32(lc + (is64 ? 144u : 88u), 0x10000500); // CF instrumented, function table present, 1 metadata byte
            dirs[PeDirectory.LoadConfig] = (lc, lcSize);

            blob.Align(4);
            uint debug = blob.Zero(28);
            uint rsds = blob.U32(0x53445352);
            blob.Bytes(Enumerable.Range(1, 16).Select(i => (byte)i).ToArray());
            blob.U32(1);
            blob.Ascii("seed.pdb");
            blob.Patch32(debug + 12, 2);
            blob.Patch32(debug + 16, blob.Here - rsds);
            blob.Patch32(debug + 20, rsds);
            dirs[PeDirectory.Debug] = (debug, 28);

            if (is64)
            {
                blob.Align(4);
                uint pdata = blob.U32(code);
                blob.U32(code + 4);
                blob.U32(code);
                dirs[PeDirectory.Exception] = (pdata, 12);
            }
            return blob.ToArray();
        });
        b.Add(".reloc", rva =>
        {
            var blob = new PeBlob(rva);
            uint block = blob.U32(callbacks & ~0xFFFu);
            blob.U32(12);
            blob.U16((ushort)((is64 ? 0xA000u : 0x3000u) | (callbacks & 0xFFF)));
            blob.U16(0);
            dirs[PeDirectory.BaseRelocation] = (block, 12);
            return blob.ToArray();
        }, 0x42000040);
        b.Add(".rsrc", rva =>
        {
            var data = ResourceTree(rva,
            [
                new(PeFile.RtVersion, 1, 0x409, VersionResource()),
                new(PeFile.RtManifest, 1, 0x409, Encoding.UTF8.GetBytes("<assembly/>")),
                new(PeFile.RtString, 1, 0x409, StringBlock("a", "b")),
                new(3, 1, 0x409, [0x28, 0, 0, 0]),
            ]);
            dirs[PeDirectory.Resource] = (rva, (uint)data.Length);
            return data;
        });
        foreach (var (index, dir) in dirs) b.Directories[index] = dir;
        return b.Build();
    }
}
