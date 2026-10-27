using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Elf;
using Xunit.Abstractions;
using static Corvus.Tests.NativeFormats.FormatWriterTests;

namespace Corvus.Tests.NativeFormats;

public sealed class ElfFileTests(ITestOutputHelper output)
{
    private static ElfFile Parse(ElfWriter w) => ElfFile.FromBytes(w.Build(), "sample.so");

    [Fact]
    public void Function_pointers_in_mov_immediates_of_a_fixed_address_executable_are_functions()
    {
        // entry: mov rdi, offset f1 ; mov esi, offset f2 ; ret   (f1 and f2 are reached only through those immediates)
        const ulong Base = 0x400000;
        uint f1 = ElfWriter.TextRva + 0x20, f2 = ElfWriter.TextRva + 0x30;
        var text = new byte[0x40];
        Array.Fill(text, (byte)0xCC);
        byte[] entry = [0x48, 0xC7, 0xC7, 0, 0, 0, 0, 0xBE, 0, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(3), (uint)(Base + f1));
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(8), (uint)(Base + f2));
        entry.CopyTo(text, 0);
        new byte[] { 0xB8, 0x2A, 0, 0, 0, 0xC3 }.CopyTo(text, (int)(f1 - ElfWriter.TextRva));
        new byte[] { 0x8D, 0x47, 0x01, 0xC3 }.CopyTo(text, (int)(f2 - ElfWriter.TextRva));
        var w = new ElfWriter { Machine = ElfWriter.EmX64, Type = 2, Base = Base, Entry = ElfWriter.TextRva, Text = text, Hash = ElfWriter.HashKind.None };
        var index = Corvus.Native.Code.NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "fixed"));
        foreach (var f in new[] { f1, f2 })
            Assert.True(index.FunctionByStart(f) is { } found && found.Sources.HasFlag(Corvus.Native.Code.FunctionSource.CodeAddress),
                $"0x{f:X}: {string.Join(", ", index.Functions.Select(x => $"0x{x.Start:X}"))}");
    }

    /// <summary>PPC64 ELFv1: function symbols and e_entry name .opd descriptors; the code is at the descriptor's first doubleword.</summary>
    [Fact]
    public void Ppc64_function_descriptors_resolve_to_code()
    {
        var elf = ElfFile.FromBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "ppc64v1.elf")), "ppc64v1.elf");
        var text = elf.Section(".text")!;
        var functions = elf.Symbols.Where(s => s.Name is "_start" or "classify" or "middle" or "leaf").ToList();
        Assert.Equal(4, functions.Count);
        Assert.All(functions, s => Assert.InRange(elf.ImageBase + s.Rva, text.Address, text.Address + text.Size - 1));
        Assert.All(functions, s => Assert.Equal(".text", s.Section));
        Assert.All(functions, s => Assert.Contains(elf.DeclaredFunctions, d => d.Rva == s.Rva));
        Assert.Equal(functions.Single(s => s.Name == "_start").Rva, elf.EntryPointRva);
    }

    /// <summary>
    /// MIPS imports bound through the global GOT, without relocations: each undefined symbol from DT_MIPS_GOTSYM at its slot.
    /// The fixture: clang -target mips-linux-gnu -O2 -fPIC -shared -nostdlib -fuse-ld=lld of a function calling puts and reading an extern int.
    /// </summary>
    [Fact]
    public void Mips_global_got_entries_are_imports()
    {
        var elf = ElfFile.FromBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "mips32be-got.elf")), "mips32be-got.elf");
        Assert.Equal([("puts", 0x20300u), ("shared_counter", 0x20304u)], elf.Imports.Select(i => (i.Name, i.SlotRva)));
    }

    /// <summary>
    /// A non-PIC MIPS executable binds its calls through the MIPS PLT: R_MIPS_JUMP_SLOT in DT_JMPREL.
    /// The fixture: clang -target mips-linux-gnu -O2 -fno-pic -mno-abicalls -nostdlib -fuse-ld=lld of a call to puts, linked to a stub library.
    /// </summary>
    [Fact]
    public void Mips_plt_slots_are_imports()
    {
        var elf = ElfFile.FromBytes(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", "mips32be-plt.elf")), "mips32be-plt.elf");
        var puts = Assert.Single(elf.Imports);
        Assert.Equal(("puts", 0x2032Cu - (uint)elf.ImageBase, true), (puts.Name, puts.SlotRva, puts.IsDelayLoad));
    }

    [Fact]
    public void SharedObject_ImageModel()
    {
        var w = SampleElf();
        var elf = Parse(w);
        INativeImage image = elf;
        Assert.Equal(ImageFormat.Elf, image.Format);
        Assert.Equal(NativeArch.Arm64, image.Arch);
        Assert.True(image.Is64Bit && image.IsDll);
        Assert.Equal(0UL, image.ImageBase);
        Assert.Equal("EM_AARCH64", image.MachineName);
        Assert.Empty(image.Issues);
        Assert.Equal(["libc.so", "libm.so"], image.Dependencies);
        Assert.Equal("libsample.so", elf.SoName);
        Assert.Equal("0102030405060708090a0b0c0d0e0f1011121314", image.BuildId);

        var text = Assert.Single(image.Sections, s => s.Name == ".text");
        Assert.Equal(ElfWriter.TextRva, text.Rva);
        Assert.True(text.IsExecutable);
        Assert.False(Assert.Single(image.Sections, s => s.Name == ".dynsym").IsExecutable);
        Assert.Equal(".data", image.SectionAt(ElfWriter.DataRva + 4)?.Name);
        Assert.Null(image.SectionAt(0x7FFF_0000));

        Assert.Equal(ElfWriter.TextRva + 4, elf.DynamicSymbol("sample_run")!.Value);
        Assert.False(elf.DynamicSymbol("malloc")!.IsDefined);
        Assert.Null(elf.DynamicSymbol("absent"));
        Assert.Equal(["sample_init", "sample_run", "sample_table", "sample_weak"], image.Exports.Select(e => e.Name!).Order());
        Assert.Contains(image.Symbols, s => s.Name == "local_helper" && s.Binding == ImageSymbolBinding.Local && s.Rva == ElfWriter.TextRva + 4);
        Assert.Contains(image.Symbols, s => s.Name == "sample_table" && s.Kind == ImageSymbolKind.Object && s.Section == ".text");

        var malloc = Assert.Single(image.Imports, i => i.Name == "malloc");
        Assert.Equal(("*", ElfWriter.GotRva, false), (malloc.Module, malloc.SlotRva, malloc.IsDelayLoad));
        var free = Assert.Single(image.Imports, i => i.Name == "free");
        Assert.Equal((w.PltSlotRva(0), true), (free.SlotRva, free.IsDelayLoad));
        Assert.Equal([(w.PltRva + 32, w.PltSlotRva(0), "free"), (w.PltRva + 48, w.PltSlotRva(1), "memcpy")],
            elf.PltEntries.Select(p => (p.StubRva, p.SlotRva, p.Symbol)));

        // RELA relative slots are zero in the file and hold their targets in the image view; bound slots read 0.
        Assert.Equal(ElfWriter.TextRva, U64(image, ElfWriter.DataRva));
        Assert.Equal(ElfWriter.TextRva + 4, U64(image, ElfWriter.DataRva + 8));
        Assert.Equal(0UL, U64(image, w.PltSlotRva(0)));
        Assert.Equal([ElfWriter.DataRva, ElfWriter.DataRva + 8], image.RelocationRvas);

        Assert.Contains(new DeclaredFunction(ElfWriter.TextRva, 4, DeclaredSource.Unwind), image.DeclaredFunctions);
        Assert.Contains(new DeclaredFunction(ElfWriter.TextRva + 4, 4, DeclaredSource.Unwind), image.DeclaredFunctions);
    }

    /// <summary>The pointer-sized value at <paramref name="va"/> in the image view.</summary>
    private static ulong Word(ElfFile elf, ulong va)
    {
        var b = Read(elf, (uint)(va - elf.ImageBase), elf.Is64Bit ? 8 : 4);
        return elf.Is64Bit ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    private static ulong U64(INativeImage image, uint rva)
    {
        var b = new byte[8];
        Assert.Equal(8, image.Read(rva, b));
        return BinaryPrimitives.ReadUInt64LittleEndian(b);
    }

    [Fact]
    public void Without_section_headers_segments_and_dynamic_tables_still_serve()
    {
        var w = SampleElf();
        w.SectionHeaders = false;
        var elf = Parse(w);
        Assert.Empty(elf.SectionHeaders);
        Assert.Null(elf.Section(".text"));
        Assert.Equal(["LOAD0", "LOAD1"], elf.Sections.Select(s => s.Name));
        Assert.True(elf.Sections[0].IsExecutable);
        Assert.NotNull(elf.DynamicSymbol("sample_weak"));
        Assert.Equal(3, elf.Imports.Count);
        Assert.Equal(2, elf.PltEntries.Count);
        Assert.Equal(2, elf.DeclaredFunctions.Count(f => f.Source == DeclaredSource.Unwind));
        Assert.Empty(elf.StaticSymbols);
    }

    [Theory]
    [InlineData("Sysv")]
    [InlineData("Gnu")]
    [InlineData("None")]
    public void The_symbol_count_comes_from_either_hash_table(string kind)
    {
        var hash = Enum.Parse<ElfWriter.HashKind>(kind);
        var w = SampleElf();
        w.Hash = hash;
        w.SectionHeaders = false;
        var elf = Parse(w);
        Assert.Equal(1 + w.Symbols.Count + w.PltImports.Count, elf.DynamicSymbols.Count);
        foreach (var s in w.Symbols) Assert.Equal(s.Name, elf.DynamicSymbol(s.Name)?.Name);
        if (hash == ElfWriter.HashKind.None) Assert.Contains(elf.Issues, i => i.Message.Contains("estimated", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_empty_GNU_hash_falls_back_to_the_symbol_table_count(bool sectionHeaders)
    {
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Hash = ElfWriter.HashKind.GnuEmpty, SectionHeaders = sectionHeaders, PltImports = ["abort", "malloc", "free"] };
        var elf = Parse(w);
        Assert.Equal(4, elf.DynamicSymbols.Count);
        Assert.Equal(["abort", "malloc", "free"], elf.Imports.Select(i => i.Name));
    }

    [Fact]
    public void ARM32_REL_tables_exidx_and_Thumb_symbols_are_read()
    {
        var w = SampleElf(is64: false, machine: ElfWriter.EmArm);
        w.Symbols.Add(new("thumb_fn", ElfWriter.TextRva + 1, 2));
        w.Exidx = [(ElfWriter.TextRva + 1, false), (ElfWriter.TextRva + 4, true)];
        w.Fdes = [];
        var elf = Parse(w);
        Assert.Equal(NativeArch.Arm, elf.Arch);
        Assert.False(elf.Is64Bit);
        Assert.Empty(elf.Issues);
        // REL: the addend is the slot's content, so the view is the file.
        Assert.Equal(ElfWriter.TextRva, BitConverter.ToUInt32(Read(elf, ElfWriter.DataRva, 4)));
        Assert.All(elf.Relocations, r => Assert.False(r.ExplicitAddend));
        Assert.Equal([ElfWriter.DataRva, ElfWriter.DataRva + 4], elf.RelocationRvas);
        Assert.Contains(new DeclaredFunction(ElfWriter.TextRva, 4, DeclaredSource.Unwind), elf.DeclaredFunctions);
        Assert.Contains(elf.Exports, e => e.Name == "thumb_fn" && e.Rva == ElfWriter.TextRva);
    }

    private static byte[] Read(INativeImage image, uint rva, int n)
    {
        var b = new byte[n];
        Assert.Equal(n, image.Read(rva, b));
        return b;
    }

    [Fact]
    public void Packed_RELR_and_APS2_relocations_expand()
    {
        var w = SampleElf();
        w.Relr = [ElfWriter.DataRva + 0x10, ElfWriter.DataRva + 0x18, ElfWriter.DataRva + 0x30, ElfWriter.DataRva + 0x80, ElfWriter.DataRva + 0x400 + 8];
        w.PackAndroid = true;
        w.Data = new byte[0x800];
        for (int i = 0; i < w.Relr.Count; i++) BinaryPrimitives.WriteUInt64LittleEndian(w.Data.AsSpan((int)(w.Relr[i] - ElfWriter.DataRva)), 0x1000u + (uint)i);
        w.Relocations = [.. Enumerable.Range(0, 6).Select(i => new ElfWriter.Reloc(ElfWriter.DataRva + 0x200 + (uint)i * 8, 1027, Addend: 0x1100 + i * 4)),
            new(ElfWriter.DataRva + 0x300, 1027, Addend: 0x1200), new(ElfWriter.GotRva, 1025, "malloc")];
        var elf = Parse(w);
        Assert.Empty(elf.Issues);
        Assert.Equal(w.Relr.Select(r => (ulong)r), elf.Relocations.Where(r => r.Table == "DT_RELR").Select(r => r.Offset));
        var packed = elf.Relocations.Where(r => r.Table == "APS2").ToList();
        Assert.Equal(w.Relocations.Select(r => ((ulong)r.Offset, r.Addend, r.Symbol)).Order(), packed.Select(r => (r.Offset, r.Addend, r.Symbol)));
        Assert.Equal(0x1100UL + 5 * 4, U64(elf, ElfWriter.DataRva + 0x200 + 5 * 8));
        Assert.Equal(0x1002UL, U64(elf, ElfWriter.DataRva + 0x30)); // RELR: implicit addend kept
        Assert.Contains(elf.Imports, i => i.Name == "malloc" && i.SlotRva == ElfWriter.GotRva);
    }

    [Fact]
    public void Symbol_versions_name_the_import_library()
    {
        var w = SampleElf();
        w.Versions = new() { ["malloc"] = ("libc.so.6", "GLIBC_2.17"), ["free"] = ("libc.so.6", "GLIBC_2.17") };
        var elf = Parse(w);
        Assert.Equal("GLIBC_2.17", elf.DynamicSymbol("malloc")!.Version);
        Assert.All(elf.Imports.Where(i => i.Name is "malloc" or "free"), i => Assert.Equal("libc.so.6", i.Module));
        Assert.Equal("*", Assert.Single(elf.Imports, i => i.Name == "memcpy").Module);
    }

    /// <summary>A version-definition symbol (V1.0 = 0, SHN_ABS) names no address in the image: no export, no nearest name at the image start.</summary>
    [Fact]
    public void Absolute_symbols_are_neither_exports_nor_image_symbols()
    {
        var w = SampleElf();
        w.Symbols.Add(new ElfWriter.Symbol("V1.0", 0, 0, Type: 1, Version: "V1.0", Section: 0xFFF1));
        var elf = Parse(w);
        Assert.DoesNotContain(elf.Exports, e => e.Name == "V1.0");
        Assert.DoesNotContain(elf.Symbols, s => s.Name == "V1.0");
        Assert.Contains(elf.Exports, e => e.Name == "sample_run");
    }

    [Fact]
    public async Task Export_versions_tell_two_definitions_of_one_name_apart()
    {
        var w = SampleElf();
        uint at = ElfWriter.TextRva;
        w.Symbols.Add(new ElfWriter.Symbol("sample_attr", at, 4, Version: "LIB_2.34"));
        w.Symbols.Add(new ElfWriter.Symbol("sample_attr", at, 4, Version: "LIB_2.2.5", Hidden: true));
        var elf = Parse(w);
        Assert.Equal(["@@LIB_2.34", "@LIB_2.2.5"], elf.Exports.Where(e => e.Name == "sample_attr").Select(e => e.Version));

        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("libver.so"), w.Build());
        using var env = new Env();
        var list = await new Corvus.Tools.NativeTools(env.Workspace, env.Pager).ListExports(dir.File("libver.so"), filter: "sample_attr");
        Assert.Contains("sample_attr@@LIB_2.34", list);
        Assert.Contains("sample_attr@LIB_2.2.5", list);
    }

    [Fact]
    public void Notes_AndroidIdent()
    {
        var w = SampleElf();
        w.AndroidIdent = (24, "r27c");
        var ident = Parse(w).AndroidIdent;
        Assert.Equal(new AndroidIdent(24, "r27c", ""), ident);
    }

    [Fact]
    public void Big_endian_headers_and_symbols_are_read()
    {
        var w = SampleElf(machine: ElfNames.EmPpc64);
        w.BigEndian = true;
        w.PltImports = [];
        w.Relocations = [new(ElfWriter.DataRva, 22, Addend: ElfWriter.TextRva)];
        var elf = Parse(w);
        Assert.True(elf.BigEndian);
        Assert.Equal(NativeArch.PowerPc, elf.Arch);
        Assert.Empty(elf.Issues);
        Assert.Equal(ElfWriter.TextRva + 4, elf.DynamicSymbol("sample_run")!.Value);
        Assert.Equal(["libc.so", "libm.so"], elf.Dependencies);
        Assert.Equal(ElfWriter.TextRva, BinaryPrimitives.ReadUInt64BigEndian(Read(elf, ElfWriter.DataRva, 8)));
    }

    [Fact]
    public void A_mapped_dump_is_read_at_addresses()
    {
        var w = SampleElf();
        var file = Parse(w);
        var dump = new byte[file.SizeOfImage];
        foreach (var s in file.LoadSegments)
            Array.Copy(w.Build(), (long)s.Offset, dump, (long)s.VirtualAddress, (long)s.FileSize);
        var elf = ElfFile.FromBytes(dump, "dump.so");
        Assert.True(elf.IsMappedDump);
        Assert.NotNull(elf.DynamicSymbol("sample_run"));
        Assert.Equal(ElfWriter.TextRva, U64(elf, ElfWriter.DataRva));
        Assert.Equal(file.Imports.Count, elf.Imports.Count);
        Assert.False(file.IsMappedDump);
    }

    [Fact]
    public void NotElf_Throws()
    {
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => ElfFile.FromBytes("MZ\0\0\0\0\0\0\0\0\0\0\0\0\0\0"u8)).Code);
    }

    /// <summary>The real AArch64 and ARM shared objects agree with LibObjectFile on sections, symbols and relocations.</summary>
    [Theory]
    [InlineData("linux-arm64")]
    [InlineData("linux-arm")]
    public void Real_shared_objects_agree_with_LibObjectFile(string rid)
    {
        var path = rid == "linux-arm64" ? NativeFixtures.LinuxArm64DbgShim : NativeFixtures.LinuxArmDbgShim;
        var elf = ElfFile.Open(path);
        var oracle = LibObjectFile.Elf.ElfFile.Read(File.OpenRead(path));
        Assert.Empty(elf.Issues);
        Assert.Equal(oracle.Sections.Count, elf.SectionHeaders.Count);
        foreach (var s in oracle.Sections.Where(s => s.Name.Value.Length > 0))
            Assert.Equal(s.VirtualAddress, elf.Section(s.Name.Value)!.Address);
        var dynsym = oracle.Sections.OfType<LibObjectFile.Elf.ElfSymbolTable>().Single(s => s.Name.Value == ".dynsym");
        Assert.Equal(dynsym.Entries.Count, elf.DynamicSymbols.Count);
        Assert.Equal(dynsym.Entries.Select(e => e.Name.Value), elf.DynamicSymbols.Select(s => s.Name));
        var relocs = oracle.Sections.OfType<LibObjectFile.Elf.ElfRelocationTable>().SelectMany(t => t.Entries).ToList();
        Assert.Equal(relocs.Count, elf.Relocations.Count);
        Assert.Equal(relocs.GroupBy(r => r.Type.ToString()).ToDictionary(g => g.Key, g => g.Count()),
            elf.Relocations.GroupBy(r => ElfNames.RelocationType(elf.Machine, r.Type)).ToDictionary(g => g.Key, g => g.Count()));
        foreach (var name in new[] { "RegisterForRuntimeStartup", "CreateDebuggingInterfaceFromVersion" })
            Assert.Contains(elf.Exports, e => e.Name == name);
        int jumpSlots = elf.Relocations.Count(r => r.Kind == ElfRelocationKind.JumpSlot);
        Assert.Equal(jumpSlots, elf.PltEntries.Count);
        var slotRvas = elf.Relocations.Where(r => r.Kind == ElfRelocationKind.JumpSlot).Select(r => (uint)(r.Offset - elf.ImageBase)).ToHashSet();
        var lazy = elf.Imports.Where(i => slotRvas.Contains(i.SlotRva)).ToList();
        Assert.Equal(jumpSlots, lazy.Count);
        Assert.All(lazy, i => Assert.Equal(!elf.BindNow, i.IsDelayLoad));
        Assert.All(elf.DeclaredFunctions, f => Assert.True(elf.SectionAt(f.Rva)?.IsExecutable, $"0x{f.Rva:X} is not in code"));
        output.WriteLine($"{rid}: {elf.DeclaredFunctions.Count} declared functions, {elf.Imports.Count} imports, {elf.Exports.Count} exports, {elf.Relocations.Count} relocations");
        if (rid == "linux-arm64")
        {
            Assert.Equal(768, elf.DeclaredFunctions.Count(f => f.Source == DeclaredSource.Unwind));
            Assert.NotNull(elf.BuildId);
        }
        else Assert.Contains(elf.DeclaredFunctions, f => f.Source == DeclaredSource.Unwind);
    }

    /// <summary>Every shared object of the linux-arm64 runtime pack (libcoreclr.so and friends) agrees with LibObjectFile, and with LLVM when CORVUS_LLVM_BIN is set.</summary>
    [Fact]
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    public void RuntimePack_SharedObjects()
    {
        var dir = Path.GetDirectoryName(RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes/linux-arm64/native/libcoreclr.so"))!;
        foreach (var path in Directory.EnumerateFiles(dir, "*.so"))
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var elf = ElfFile.Open(path);
            FormatFuzz.Touch(elf, e => _ = e.PltEntries.Count + e.Notes.Count);
            var elapsed = clock.ElapsedMilliseconds;
            Assert.Empty(elf.Issues);
            var oracle = LibObjectFile.Elf.ElfFile.Read(File.OpenRead(path));
            Assert.Equal(oracle.Sections.OfType<LibObjectFile.Elf.ElfSymbolTable>().Single(s => s.Name.Value == ".dynsym").Entries.Count, elf.DynamicSymbols.Count);
            Assert.Equal(oracle.Sections.OfType<LibObjectFile.Elf.ElfRelocationTable>().Sum(t => t.Entries.Count), elf.Relocations.Count);
            Assert.Equal(elf.Relocations.Count(r => r.Kind == ElfRelocationKind.JumpSlot), elf.PltEntries.Count);
            if (LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.UnwindInfo, path) is { } unwind)
            {
                var starts = Regex.Matches(unwind, @"initial_location: 0x([0-9a-f]+)").Select(m => Convert.ToUInt64(m.Groups[1].Value, 16)).ToHashSet();
                Assert.Subset(starts, elf.DeclaredFunctions.Where(f => f.Source == DeclaredSource.Unwind).Select(f => elf.ImageBase + f.Rva).ToHashSet());
            }
            output.WriteLine($"{Path.GetFileName(path)}: {elapsed} ms, {elf.Relocations.Count} relocations, {elf.DeclaredFunctions.Count} declared functions, {elf.Exports.Count} exports, {elf.Imports.Count} imports");
        }
    }

    /// <summary>LLVM's relocation dump and FDE list match ours (needs CORVUS_LLVM_BIN).</summary>
    [Fact]
    public void Real_shared_object_agrees_with_LLVM()
    {
        var path = NativeFixtures.LinuxArm64DbgShim;
        if (LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.Relocations, path) is not { } relocs) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        var elf = ElfFile.Open(path);
        var expected = Regex.Matches(relocs, @"^\s+0x([0-9A-F]+) (R_\w+)", RegexOptions.Multiline).Select(m => (Convert.ToUInt64(m.Groups[1].Value, 16), m.Groups[2].Value)).ToList();
        Assert.Equal(expected, elf.Relocations.Select(r => (r.Offset, ElfNames.RelocationType(elf.Machine, r.Type))));
        var unwind = LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.UnwindInfo, path)!;
        var starts = Regex.Matches(unwind, @"initial_location: 0x([0-9a-f]+)").Select(m => Convert.ToUInt32(m.Groups[1].Value, 16)).ToHashSet();
        Assert.Equal(starts.Order(), elf.DeclaredFunctions.Where(f => f.Source == DeclaredSource.Unwind).Select(f => f.Rva));
    }

    internal const string OracleSource = """
        extern void *malloc(unsigned long);
        extern int puts(const char *);
        extern int shared_counter;
        static int table_a(void) { return 1; }
        static int table_b(void) { return 2; }
        int (*table[])(void) = { table_a, table_b, table_a, table_b, table_a, table_b, table_a, table_b };
        const char *names[] = { "a", "b", "c", "d" };
        int *counter = &shared_counter;
        #define T10(x) x, x, x, x, x, x, x, x, x, x
        const char *strings[] = { T10(T10("s")) };
        #define P { "p", table_a, { 0 } }
        struct pair { const char *name; int (*fn)(void); int pad[5]; } pairs[] = { T10(T10(P)) };
        int api(int x) { puts(names[x & 3]); return table[x & 7]() + (int)(long)malloc(4) + *counter; }
        __attribute__((constructor)) static void init(void) { puts("init"); }
        """;

    /// <summary>Shared objects built by clang and lld agree with LLVM's readers on relocations, dynamic symbols, PLT stubs and unwind starts (needs CORVUS_LLVM_BIN).</summary>
    [Fact]
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    public void Clang_builds_agree_with_LLVM()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        const string target = LlvmOracle.Options.Target;
        (string Name, string Options)[] variants =
        [
            ("a64-aps2-relr", $"{target}aarch64-linux-android21 {LlvmOracle.Options.LinkAndroidPackedRelr} {LlvmOracle.Options.LinkBuildId}"),
            ("a64-relr", $"{target}aarch64-linux-gnu {LlvmOracle.Options.LinkRelr} {LlvmOracle.Options.LinkBothHashes}"),
            ("x64", $"{target}x86_64-linux-gnu {LlvmOracle.Options.LinkLazy}"),
            ("x86", $"{target}i686-linux-gnu"),
            ("arm-aps2", $"{target}armv7a-linux-androideabi21 {LlvmOracle.Options.LinkAndroidPacked}"),
            ("arm-thumb", $"{target}armv7a-linux-gnueabihf -mthumb"),
            ("rv64", $"{target}riscv64-linux-gnu"),
        ];
        foreach (var (name, options) in variants)
        {
            var path = dir.File(name + ".so");
            var failure = LlvmOracle.Compile(OracleSource, path, LlvmOracle.Options.ClangSharedObject + " " + options);
            Assert.True(failure == null, failure);
            var elf = ElfFile.Open(path);
            Assert.Empty(elf.Issues);
            var relocs = LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.Relocations, path)!;
            var expected = Regex.Matches(relocs, @"^\s+0x([0-9A-F]+) (R_\w+)", RegexOptions.Multiline).Select(m => (Convert.ToUInt64(m.Groups[1].Value, 16), m.Groups[2].Value)).Order().ToList();
            Assert.Equal(expected, elf.Relocations.Select(r => (r.Offset, ElfNames.RelocationType(elf.Machine, r.Type))).Order());
            if (name.Contains("aps2", StringComparison.Ordinal)) Assert.Contains(elf.Relocations, r => r.Table == "APS2");
            if (name.Contains("relr", StringComparison.Ordinal)) Assert.Contains(elf.Relocations, r => r.Table == "DT_RELR");
            foreach (var r in elf.Relocations)
            {
                ulong value = Word(elf, r.Offset);
                if (r.Kind == ElfRelocationKind.Relative && r.ExplicitAddend) Assert.Equal((ulong)r.Addend, value);
                if (r.Kind is ElfRelocationKind.JumpSlot or ElfRelocationKind.GlobalData)
                    Assert.Equal(elf.DynamicSymbols[r.SymbolIndex] is { IsDefined: true } s ? s.Value + (ulong)r.Addend : 0, value);
            }

            var syms = LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.DynamicSymbols, path)!;
            Assert.Equal(Regex.Matches(syms, @"Name: (\S*) \(").Select(m => m.Groups[1].Value), elf.DynamicSymbols.Select(s => s.Name));

            var code = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.Disassemble, path)!;
            var stubs = Regex.Matches(code, @"^([0-9a-f]+) <(\w+)@plt>:", RegexOptions.Multiline).Select(m => (Convert.ToUInt64(m.Groups[1].Value, 16), m.Groups[2].Value)).ToList();
            if (elf.Machine != ElfNames.EmRiscV) Assert.Equal(stubs, elf.PltEntries.Select(p => (elf.ImageBase + p.StubRva, p.Symbol!)));

            var unwind = LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.UnwindInfo, path)!;
            var starts = Regex.Matches(unwind, @"(?:initial_location|FunctionAddress): 0x([0-9a-fA-F]+)").Select(m => Convert.ToUInt64(m.Groups[1].Value, 16) & ~1UL).ToHashSet();
            var ours = elf.DeclaredFunctions.Where(f => f.Source == DeclaredSource.Unwind).Select(f => elf.ImageBase + f.Rva).ToHashSet();
            Assert.Subset(starts, ours);
            output.WriteLine($"{name}: {elf.Relocations.Count} relocations, {elf.PltEntries.Count} PLT stubs, {ours.Count} unwind starts, {elf.Imports.Count} imports");
        }
    }

    [Fact]
    [FuzzEntry(typeof(ElfFile))]
    public void MutatedImages_NeverThrow()
    {
        var seeds = new List<byte[]> { SampleElf().Build(), SampleElf(false, ElfWriter.EmArm).Build(), File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim) };
        var withoutHeaders = SampleElf();
        withoutHeaders.SectionHeaders = false;
        withoutHeaders.PackAndroid = true;
        withoutHeaders.Relr = [ElfWriter.DataRva + 0x40];
        seeds.Add(withoutHeaders.Build());
        int iterations = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_FORMAT_FUZZ_ITERATIONS"), out int n) ? n : 300;
        var failures = FormatFuzz.Run(seeds, iterations, 20261011, bytes => FormatFuzz.Touch(ElfFile.FromBytes(bytes, "fuzz.so"), elf =>
        {
            _ = elf.Relocations.Count + elf.PltEntries.Count + elf.Notes.Count + elf.StaticSymbols.Count;
            _ = elf.DynamicSymbol("malloc");
            _ = elf.AndroidIdent;
        }));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }

    // Read as one 64-bit word, every MIPS64 r_info decoded as type 0 with a symbol index from the type bytes.
    [Fact, Trait("Data", "Real")]
    public void MIPS64_relocations_read_the_one_byte_type_after_the_32_bit_symbol()
    {
        var elf = ElfFile.Open(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "linux-mips64", "native", "libe_sqlite3.so"));
        output.WriteLine(string.Join(", ", elf.Relocations.GroupBy(r => ElfNames.RelocationType(elf.Machine, r.Type)).Select(g => $"{g.Key} x{g.Count()}")));
        // The linker starts the table with one R_MIPS_NONE; every other entry is R_MIPS_REL32.
        Assert.Equal(ElfRelocationKind.None, elf.Relocations[0].Kind);
        Assert.True(elf.Relocations.Count > 1000);
        Assert.All(elf.Relocations.Skip(1), r => Assert.Equal(ElfRelocationKind.Relative, r.Kind));
        Assert.All(elf.Relocations, r => Assert.InRange(r.SymbolIndex, 0, elf.DynamicSymbols.Count - 1));
    }

    [Fact]
    public void A_stripped_library_names_its_functions_from_the_MiniDebugInfo_symbol_table()
    {
        var inner = new ElfWriter();
        inner.StaticSymbols = [new("ledger_total", ElfWriter.TextRva, 4, Bind: 0)];
        var outer = SampleElf();
        outer.StaticSymbols = [];
        outer.GnuDebugData = ElfWriter.Xz(inner.Build());
        var elf = Parse(outer);
        Assert.Empty(elf.StaticSymbols);
        var named = Assert.Single(elf.Symbols, s => s.Name == "ledger_total");
        Assert.Equal(ElfWriter.TextRva, named.Rva);
        Assert.Equal(ImageSymbolBinding.Local, named.Binding);
        Assert.Equal(".text", named.Section);
    }

    [Fact]
    public void Damaged_MiniDebugInfo_is_named_and_the_other_symbols_are_kept()
    {
        var outer = SampleElf();
        outer.GnuDebugData = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0, 0, 1, 9, 9];
        var elf = Parse(outer);
        Assert.NotEmpty(elf.Symbols);
        Assert.Contains(elf.Issues, i => i.Message.Contains(".gnu_debugdata is not read", StringComparison.Ordinal));
    }
}
