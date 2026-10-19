using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Services.Analysis;

namespace Corvus.Tests.NativeFormats;

/// <summary>cargo-auditable .dep-v0 dependency lists in ELF and PE images; summarize_file view=rust.</summary>
public sealed class RustAuditTests
{
    private const string Json = """
        {"packages":[
          {"name":"tool","version":"0.3.1","source":"local","dependencies":[1,2],"root":true},
          {"name":"serde","version":"1.0.210","source":"crates.io","dependencies":[]},
          {"name":"cc","version":"1.1.0","source":"crates.io","kind":"build"}
        ]}
        """;

    private static byte[] Zlib(string text)
    {
        var ms = new MemoryStream();
        using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(Encoding.UTF8.GetBytes(text));
        return ms.ToArray();
    }

    private static byte[] Elf(byte[] section) => new ElfWriter { DataSectionName = ".dep-v0", Data = section }.Build();

    private static RustFileView.Facts? View(byte[] bytes, string path = "tool") =>
        new RustFileView().Inspect(new FileInput(path, bytes, Blob.Identify(bytes)), default)?.Detail as RustFileView.Facts;

    [Fact]
    public void Elf_section_gives_crates_kinds_and_edges()
    {
        var f = View(Elf(Zlib(Json)))!;
        Assert.Equal(("tool 0.3.1", 3, 1, 2), (f.Root, f.Crates, f.BuildCrates, f.Edges));
        Assert.Equal(["serde 1.0.210", "cc 1.1.0"], f.Packages[0].Dependencies);
        Assert.Equal(("cc", "build", "crates.io"), (f.Packages[2].Name, f.Packages[2].Kind, f.Packages[2].Source));
        Assert.Equal("runtime", f.Packages[1].Kind);
        Assert.Empty(f.Notes);
    }

    [Fact]
    public void Pe_section_is_read()
    {
        var b = new PeBuilder();
        b.Add(".text", [0xC3], 0x60000020);
        b.Add(".dep-v0", Zlib(Json));
        var f = View(b.Build(), "tool.exe")!;
        Assert.Equal(".dep-v0", f.Section);
        Assert.Equal(3, f.Crates);
    }

    [Fact]
    public void Decompressed_size_is_bounded()
    {
        var bomb = Zlib("{\"packages\":[" + new string(' ', RustAudit.MaxJson) + "]}");
        var audit = RustAudit.Parse(bomb);
        Assert.Empty(audit.Packages);
        Assert.Contains("exceeds", audit.Issues.Single());
    }

    [Fact]
    public void Bad_indexes_and_bad_data_are_issues()
    {
        Assert.Contains("past the package list", RustAudit.Parse(Zlib("""{"packages":[{"name":"a","version":"1","dependencies":[5]}]}""")).Issues.Single());
        Assert.StartsWith("not zlib data", RustAudit.Parse([1, 2, 3, 4]).Issues.Single());
        Assert.StartsWith("malformed JSON", RustAudit.Parse(Zlib("{\"packages\":[")).Issues.Single());
    }

    [Fact]
    public void Images_without_the_section_do_not_apply() => Assert.Null(View(new ElfWriter().Build()));

    [Fact]
    public void Without_the_section_the_rustc_commit_and_the_crates_of_source_paths_are_read()
    {
        const string Commit = "88d9e12ae178fab0fb5cc050a94da85685d449ea";
        var paths = string.Join("\0",
            $"/rustc/{Commit}/library/core/src/str/mod.rs",
            $"/rustc/{Commit}/library/std/src/io/mod.rs",
            @"C:\Users\b\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\regex-automata-0.4.14\src\meta\strategy.rs",
            "/home/b/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/clap_builder-4.6.0/src/parser/parser.rs",
            "/home/b/.cargo/registry/src/github.com-1ecc6299db9ec823/jiff-tzdb-0.1.6/lib.rs",
            "/home/b/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/not a crate/x.rs") + "\0";
        var b = new PeBuilder();
        b.Add(".text", [0xC3], 0x60000020);
        b.Add(".rdata", Encoding.ASCII.GetBytes(paths));
        var f = View(b.Build(), "tool.exe")!;
        Assert.Equal(("source paths", Commit, 3), (f.Section, f.RustcCommit, f.Crates));
        Assert.Equal([("clap_builder", "4.6.0"), ("jiff-tzdb", "0.1.6"), ("regex-automata", "0.4.14")], f.Packages.Select(c => (c.Name, c.Version)));
    }

    [Fact]
    [FuzzEntry(typeof(RustFileView), typeof(RustAudit))]
    public void Fuzzed_section_never_throws()
    {
        var failures = FormatFuzz.Run([Elf(Zlib(Json))], 1500, 13, b => View(b));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(5)));
        var direct = Corvus.Tests.FormatFuzz.Run(Zlib(Json), b => RustAudit.Parse(b), 1500);
        Assert.True(direct.Count == 0, string.Join("\n", direct.Take(5)));
    }
}
