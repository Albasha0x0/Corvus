using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;

namespace Corvus.Tests.NativeFormats;

/// <summary>The DWARF reader on a real separate debug file: the PDB model's symbols and types, compressed sections, damaged input.</summary>
public class DwarfReaderTests
{
    private const string Library = "libSystem.Native.so";
    // facts of the linux-x64 build, checked against llvm-dwarfdump
    private const uint FStat = 0xD7A0;

    private static string Elf(string file = Library) => NativeFixtures.NativeAotLib("linux-x64", file);

    private static PdbFile Read(INativeImage image, string path)
    {
        using var container = DebugContainer.Open(path, image.BuildId);
        return DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(path, image.BuildId));
    }

    [Fact]
    public void Dwarf_types_read_as_the_pdb_type_model()
    {
        var pdb = Read(NativeImageLoader.Open(Elf()), Elf(Library + ".dbg"));
        Assert.Equal(DebugInfoFormat.Dwarf, pdb.Format);
        Assert.Equal(273, pdb.Symbols.Count(s => s.IsFunction));
        var model = PdbTypeModel.Of(pdb, 8);
        var stat = model.Node(Assert.Single(model.Named("stat64")))!;
        Assert.Equal(144, stat.Size);
        Assert.Contains(stat.Members, m => m.Name == "st_size" && m.Offset == 48 && model.Spell(m.Type) == "__int64");
        // C's typedef struct { ... } Name: the struct takes the typedef's name
        Assert.Equal(PdbTypeKind.Struct, model.Node(Assert.Single(model.Named("FileStatus")))!.Kind);
        var fstat = pdb.Symbols.Single(s => s.Name == "SystemNative_FStat");
        Assert.Equal(FStat, fstat.Rva);
        Assert.Equal("int __cdecl(__int64, FileStatus *)", model.Spell(model.FunctionTypeOf(fstat.TypeIndex)));
        var decls = PdbTypes.Build(pdb, 8);
        Assert.Contains("struct sockaddr_in6\n{\n", decls.Declarations);
        Assert.Equal("int __cdecl f(__int64 fd, struct FileStatus *output);", decls.Prototypes.Single(p => p.Rva == FStat).Declaration);
    }

    [Fact]
    public void Source_lines_and_inlined_frames_by_address()
    {
        var pdb = Read(NativeImageLoader.Open(Elf()), Elf(Library + ".dbg"));
        uint strErrorR = pdb.Symbols.Single(s => s.Name == "SystemNative_StrErrorR").Rva!.Value;
        var at = Assert.Single(pdb.Source!.Lookup([strErrorR + 4]))!;
        Assert.EndsWith("System.Native/pal_errno.c", at.File);
        Assert.Equal(17, at.Line);
        Assert.Equal(["StrErrorR:17", "SystemNative_StrErrorR:18"], at.Frames.Select(f => $"{f.Function}:{f.Line}"));
        Assert.Null(pdb.Source.Lookup([0x10])[0]);
    }

    [Fact]
    public void Compressed_debug_sections_read_like_plain_ones()
    {
        using var dir = new TempDir();
        var image = NativeImageLoader.Open(Elf());
        // the debug file again with its DWARF sections compressed three ways (zlib, zstd, GNU .zdebug_)
        using var plain = DebugContainer.Open(Elf(Library + ".dbg"));
        var sections = new List<DebugFileWriter.Section> { DebugFileWriter.BuildId(image.BuildId!) };
        var packings = new[] { DebugFileWriter.Packing.Zlib, DebugFileWriter.Packing.Zstd, DebugFileWriter.Packing.GnuZlib };
        foreach (var (info, i) in plain.Sections.OrderBy(s => s.Name, StringComparer.Ordinal).Select((s, i) => (s, i)))
            sections.Add(DebugFileWriter.Bytes(info.Name, plain.Section(info.Name)!.Slice(0, info.Size).ToArray(), packings[i % 3]));
        var packed = dir.File("packed.debug");
        DebugFileWriter.Write(packed, sections);
        using (var check = DebugContainer.Open(packed)) Assert.Equal(image.BuildId, check.BuildId);
        var reference = Read(image, Elf(Library + ".dbg"));
        var unpacked = Read(image, packed);
        Assert.Empty(unpacked.Issues);
        Assert.Equal(reference.Symbols.Select(s => (s.Name, s.Rva)), unpacked.Symbols.Select(s => (s.Name, s.Rva)));
        var addresses = reference.Symbols.Where(s => s.IsFunction).Select(s => s.Rva!.Value + 2).ToList();
        Assert.Equal(reference.Source!.Lookup(addresses), unpacked.Source!.Lookup(addresses), new SourceComparer());
    }

    private sealed class SourceComparer : IEqualityComparer<DebugSourceInfo?>
    {
        public bool Equals(DebugSourceInfo? x, DebugSourceInfo? y) =>
            x?.File == y?.File && x?.Line == y?.Line && (x?.Frames ?? []).SequenceEqual(y?.Frames ?? []);

        public int GetHashCode(DebugSourceInfo? obj) => obj?.Line ?? 0;
    }

    [Fact]
    public void Damaged_debug_files_are_read_without_exceptions()
    {
        var image = NativeImageLoader.Open(Elf("libSystem.Net.Security.Native.so"));
        var seed = File.ReadAllBytes(Elf("libSystem.Net.Security.Native.so.dbg"));
        var failures = Corvus.Tests.FormatFuzz.Run(seed, bytes =>
        {
            DebugContainer container;
            try { container = DebugContainer.FromMemory("fuzz.dbg", bytes); }
            catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { return; }
            using (container)
            {
                var pdb = DwarfDebugInfo.Read(container, image, () => DebugContainer.FromMemory("fuzz.dbg", bytes));
                PdbTypes.Build(pdb, 8);
                pdb.Source!.Lookup(pdb.Symbols.Where(s => s.Rva != null).Take(8).Select(s => s.Rva!.Value + 1).ToList());
            }
        }, 1500);
        Assert.Empty(failures);
    }
}
