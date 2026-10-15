using Corvus.Native.Pdb;

namespace Corvus.Tests;

/// <summary>Source lines of native PDBs (C13 line subsections, file checksums, /names): address to line and file:line to addresses.</summary>
public class PdbLinesTests
{
    /// <summary>
    /// The sample's Bar::Foo (.text+0x10, 0x20 bytes) from bar.cpp lines 10, 11 and 14, and helper (.text+0x40, 8 bytes)
    /// from util.h line 3; .text is at RVA 0x1000.
    /// </summary>
    private static PdbBuilder WithLines()
    {
        var p = PdbBuilder.Sample();
        p.LineBlocks.Add((0, 1, 0x10, 0x20, @"C:\src\app\bar.cpp", [(0, 10), (6, 11), (0x18, 14)]));
        p.LineBlocks.Add((0, 1, 0x40, 8, @"C:\src\app\util.h", [(0, 3)]));
        return p;
    }

    [Fact]
    public void An_address_reads_its_file_line_and_function()
    {
        var pdb = PdbFile.FromBytes(WithLines().Build());
        var lines = Assert.IsType<PdbLines>(pdb.Source);
        var at = lines.Lookup([0x1010, 0x1017, 0x1028, 0x1044, 0x1050]);
        Assert.Equal((@"C:\src\app\bar.cpp", 10, "Bar::Foo"), (at[0]!.File, at[0]!.Line, at[0]!.Frames[^1].Function));
        Assert.Equal(11, at[1]!.Line);
        Assert.Equal(14, at[2]!.Line);
        Assert.Equal((@"C:\src\app\util.h", 3, "helper"), (at[3]!.File, at[3]!.Line, at[3]!.Frames[^1].Function));
        Assert.Null(at[4]); // past helper's code
        Assert.Equal(2, lines.LineTables);
        Assert.Empty(lines.Notes);
    }

    [Fact]
    public void A_file_line_resolves_to_its_code_or_the_next_line_with_code()
    {
        var lines = Assert.IsType<PdbLines>(PdbFile.FromBytes(WithLines().Build()).Source);
        Assert.Equal([new PdbLineAddress(@"C:\src\app\bar.cpp", 11, 0x1016)], lines.Addresses("app/BAR.cpp", 11));
        // no code on 12 or 13: the stop point goes to 14
        Assert.Equal(0x1028u, Assert.Single(lines.Addresses("bar.cpp", 12)).Rva);
        Assert.Empty(lines.Addresses("other/bar.cpp", 11));
        Assert.Empty(lines.Addresses("bar.cpp", 15));
    }

    [Fact]
    public void A_pdb_without_line_subsections_has_no_source_lookup()
    {
        Assert.Null(PdbFile.FromBytes(PdbBuilder.Sample().Build()).Source);
    }

    [Fact]
    [FuzzEntry(typeof(PdbLines))]
    public void Mutated_line_tables_never_throw()
    {
        var good = WithLines().Build();
        var rng = new Random(4242);
        for (int run = 0; run < 300; run++)
        {
            var bytes = (byte[])good.Clone();
            for (int i = 0, flips = 1 + rng.Next(8); i < flips; i++)
                bytes[56 + rng.Next(bytes.Length - 56)] = rng.Next(4) switch { 0 => 0xFF, 1 => 0, _ => (byte)rng.Next(256) };
            if (PdbFile.FromBytes(bytes).Source is PdbLines lines)
            {
                lines.Lookup([0x1010, 0x1044]);
                lines.Addresses("bar.cpp", 11);
            }
        }
    }
}

/// <summary>Line tables of a PDB the Microsoft linker wrote (needs the Visual Studio build tools; skipped without them).</summary>
public class PdbLinesCompiledTests
{
    private const string Source = "int first(int a)\n{\n    return a * 3;\n}\n\nint second(int b)\n{\n    return first(b) + 1;\n}\n\nint main(void) { return second(2); }\n";

    [Fact, Trait("Speed", "Slow")]
    public void A_compiled_line_resolves_to_code_in_its_function_and_back()
    {
        using var dir = new TempDir();
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return;
        File.WriteAllText(dir.File("lines.c"), Source);
        var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x64 >nul && cl /nologo /Zi /Od /GS- lines.c /link /DEBUG /INCREMENTAL:NO /OUT:lines.exe\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("lines.pdb")), log);
        var pdb = PdbFile.Open(dir.File("lines.pdb"));
        var lines = Assert.IsType<PdbLines>(pdb.Source);
        Assert.Contains(lines.SourceFiles, f => f.EndsWith("lines.c", StringComparison.OrdinalIgnoreCase));
        var second = pdb.Symbols.First(s => s.Name == "second" && s.Kind is PdbSymbolKind.GlobalProc);
        var stop = Assert.Single(lines.Addresses("lines.c", 8));
        Assert.InRange(stop.Rva, second.Rva!.Value, second.Rva.Value + second.Size - 1);
        var back = lines.Lookup([stop.Rva])[0]!;
        Assert.Equal((8, "second"), (back.Line, back.Frames[^1].Function));
        var first = pdb.Symbols.First(s => s.Name == "first" && s.Kind is PdbSymbolKind.GlobalProc);
        Assert.InRange(lines.Lookup([first.Rva!.Value + 8])[0]!.Line, 1, 4);
    }
}
