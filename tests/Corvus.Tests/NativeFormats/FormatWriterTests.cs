using LibObjectFile.Elf;
using LibObjectFile.MachO;
using Xunit.Abstractions;

namespace Corvus.Tests.NativeFormats;

/// <summary>The synthetic ELF / Mach-O writers produce files an independent reader accepts (LibObjectFile; LLVM when CORVUS_LLVM_BIN is set).</summary>
public sealed class FormatWriterTests(ITestOutputHelper output)
{
    internal static ElfWriter SampleElf(bool is64 = true, ushort machine = ElfWriter.EmAarch64) => new()
    {
        Is64 = is64,
        Machine = machine,
        UseRel = !is64,
        SoName = "libsample.so",
        Needed = ["libc.so", "libm.so"],
        Symbols =
        [
            new("malloc", Defined: false),
            new("sample_init", ElfWriter.TextRva, 4),
            new("sample_run", ElfWriter.TextRva + 4, 4),
            new("sample_table", ElfWriter.DataRva, 16, Type: 1),
            new("sample_weak", ElfWriter.TextRva + 4, 4, Bind: 2),
        ],
        PltImports = is64 && machine == ElfWriter.EmAarch64 ? ["free", "memcpy"] : [],
        Relocations =
        [
            new(ElfWriter.DataRva, Relative(machine), Addend: ElfWriter.TextRva),
            new(ElfWriter.DataRva + (is64 ? 8u : 4u), Relative(machine), Addend: ElfWriter.TextRva + 4),
            new(ElfWriter.GotRva, GlobDat(machine), "malloc"),
        ],
        BuildId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        Fdes = [(ElfWriter.TextRva, 4), (ElfWriter.TextRva + 4, 4)],
        InitArray = [ElfWriter.TextRva],
        StaticSymbols = [new("local_helper", ElfWriter.TextRva + 4, 4, Bind: 0)],
    };

    internal static uint Relative(ushort machine) => machine switch { ElfWriter.EmAarch64 => 1027, ElfWriter.EmArm => 23, _ => 8 };
    internal static uint GlobDat(ushort machine) => machine switch { ElfWriter.EmAarch64 => 1025, ElfWriter.EmArm => 21, _ => 6 };

    internal static MachOWriter SampleMachO(ushort? chained = 6) => new()
    {
        Dylibs = [("/usr/lib/libSystem.B.dylib", 0xC), ("@rpath/libweak.dylib", 0x80000018)],
        Rpaths = ["@loader_path"],
        Uuid = [0xAA, 0xBB, 0xCC, 0xDD, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        BuildVersion = (1, 0x000B0000, 0x000E0000),
        Symbols =
        [
            new("_local", MachOWriter.TextOffset + 4, 0x0E),
            new("_sample_init", MachOWriter.TextOffset),
            new("_sample_run", MachOWriter.TextOffset + 4),
            new("_malloc", 0, 0x01, 0, 0x0100),
        ],
        GotSymbols = ["_malloc"],
        Exports = [new("_sample_init", MachOWriter.TextOffset), new("_sample_run", MachOWriter.TextOffset + 4), new("_sample_resolved", MachOWriter.TextOffset, 0x10, MachOWriter.TextOffset + 4)],
        FunctionStarts = [MachOWriter.TextOffset, MachOWriter.TextOffset + 4],
        DataInCode = [(MachOWriter.TextOffset + 4, 4, 1)],
        ChainedFormat = chained,
        Imports = [new(1, "_malloc"), new(2, "_weak_fn", Weak: true)],
        Fixups =
        [
            new(MachOWriter.GotOffset, Import: 0),
            new(MachOWriter.ConstOffset, Target: MachOWriter.TextOffset),
            new(MachOWriter.ConstOffset + 8, Target: MachOWriter.TextOffset + 4),
            new(MachOWriter.DataOffset, Import: 1),
            new(MachOWriter.DataOffset + 0x1800, Target: MachOWriter.DataOffset),
        ],
    };

    [Fact]
    public void ElfWriter_IsReadByLibObjectFile()
    {
        foreach (var (is64, machine) in new[] { (true, ElfWriter.EmAarch64), (true, ElfWriter.EmX64), (false, ElfWriter.EmArm) })
        {
            var writer = SampleElf(is64, machine);
            var bytes = writer.Build();
            var elf = ElfFile.Read(new MemoryStream(bytes));
            var names = elf.Sections.Select(s => s.Name.Value).ToList();
            Assert.Contains(".dynsym", names);
            Assert.Contains(".gnu.hash", names);
            Assert.Contains(".eh_frame_hdr", names);
            var dynsym = elf.Sections.OfType<ElfSymbolTable>().Single(s => s.Name.Value == ".dynsym");
            Assert.Equal(1 + writer.Symbols.Count + writer.PltImports.Count, dynsym.Entries.Count);
            Assert.Contains(dynsym.Entries, e => e.Name.Value == "sample_run");
            var relocations = elf.Sections.OfType<ElfRelocationTable>().Sum(t => t.Entries.Count);
            Assert.Equal(writer.Relocations.Count + writer.PltImports.Count, relocations);
            Assert.Equal(5, elf.Segments.Count);
        }
    }

    [Fact]
    public void MachOWriter_IsReadByLibObjectFile()
    {
        var thin = SampleMachO().Build();
        var file = MachOFile.Read(new MemoryStream(thin));
        Assert.Equal(["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"], file.Segments.Select(s => s.Name).ToArray());
        Assert.Equal(4, file.ReadSymbolTable().Count);
        Assert.Single(file.ReadIndirectSymbolTable());

        var exe = new MachOWriter { FileType = 2, InstallName = null, MainOffset = MachOWriter.TextOffset, ChainedFormat = 6, Fixups = [new(MachOWriter.ConstOffset, Target: MachOWriter.TextOffset)] }.Build();
        Assert.Equal("__PAGEZERO", MachOFile.Read(new MemoryStream(exe)).Segments.First().Name);

        var fat = MachOWriter.Fat([(MachOWriter.CpuX64, 3, new MachOWriter { CpuType = MachOWriter.CpuX64, CpuSubType = 3 }.Build()), (MachOWriter.CpuArm64, 0, thin)]);
        Assert.True(MachOFatFile.IsFat(new MemoryStream(fat)));
        Assert.Equal(2, MachOFatFile.Read(new MemoryStream(fat)).Slices.Count);
    }

    [Fact]
    public void RealFixtures_AreRestored()
    {
        Assert.True(ElfFile.IsElf(File.OpenRead(NativeFixtures.LinuxArm64DbgShim)));
        Assert.True(ElfFile.IsElf(File.OpenRead(NativeFixtures.LinuxArmDbgShim)));
        Assert.True(MachOFile.IsMachO(File.OpenRead(NativeFixtures.OsxArm64DbgShim)));
        Assert.True(MachOFile.IsMachO(File.OpenRead(NativeFixtures.OsxArm64AppHost)));
        Assert.True(MachOFatFile.IsFat(File.OpenRead(NativeFixtures.OsxFatSkia)));
        Assert.Equal((byte)'M', File.ReadAllBytes(NativeFixtures.WinArm64DbgShim)[0]);
    }

    /// <summary>LLVM decodes the writers' packed encodings (RELR, APS2, chained fixups, export trie) to the values the tests put in.</summary>
    [Fact]
    public void Writers_AgreeWithLlvm()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        var elf = SampleElf();
        elf.Relr = [ElfWriter.DataRva + 0x10, ElfWriter.DataRva + 0x18, ElfWriter.DataRva + 0x80, ElfWriter.DataRva + 0x30];
        elf.PackAndroid = true;
        elf.Relocations = [.. Enumerable.Range(0, 5).Select(i => new ElfWriter.Reloc(ElfWriter.DataRva + 0x40 + (uint)i * 8, 1027, Addend: 0x1000 + i)), new(ElfWriter.GotRva, 1025, "malloc")];
        var elfPath = dir.File("sample.so");
        File.WriteAllBytes(elfPath, elf.Build());
        var relocs = LlvmOracle.Run("llvm-readobj", LlvmOracle.Options.Relocations, elfPath);
        Assert.NotNull(relocs);
        output.WriteLine(relocs);
        foreach (var r in elf.Relr) Assert.Contains($"0x{r:X} R_AARCH64_RELATIVE", relocs);
        foreach (var r in elf.Relocations.Where(r => r.Type == 1027)) Assert.Contains($"0x{r.Offset:X} R_AARCH64_RELATIVE - 0x{r.Addend:X}", relocs);

        foreach (ushort format in new ushort[] { 1, 2, 6, 9, 12 })
        {
            var macho = SampleMachO(format);
            var path = dir.File($"chained{format}.dylib");
            File.WriteAllBytes(path, macho.Build());
            var fixups = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachOChainedFixups, path);
            Assert.NotNull(fixups);
            output.WriteLine(fixups);
            Assert.Contains($"pointer_format = {format}", fixups);
            var trie = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachOExportsTrie, path);
            Assert.NotNull(trie);
            Assert.Contains("0x00001004  _sample_run", trie);
            Assert.Contains("_sample_resolved [resolver=0x00001004]", trie);
            if (format is 2 or 6)
            {
                var info = LlvmOracle.Run("llvm-objdump", LlvmOracle.Options.MachODyldInfo, path);
                Assert.NotNull(info);
                output.WriteLine(info);
                Assert.Matches(@"0x4000\s+0x\w+\s+bind\s+0x0\s+libSystem\s+_malloc", info);
                Assert.Matches(@"0x4808\s+0x\w+\s+rebase\s+0x1004", info);
                Assert.Matches(@"0x8000\s+0x\w+\s+bind\s+0x0\s+libweak\s+_weak_fn \(weak import\)", info);
            }
        }
    }
}
