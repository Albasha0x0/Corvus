using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Installers;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Cabinets (stored, MSZIP, LZX) and Windows Installer packages: files under their install paths, custom actions, registry, the installer view.</summary>
public sealed class InstallerTests
{
    internal static byte[] Fixture(string name)
    {
        using var z = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Containers", "InstallerFixtures", name + ".gz")), CompressionMode.Decompress);
        var o = new MemoryStream();
        z.CopyTo(o);
        return o.ToArray();
    }

    /// <summary>The mixed file build-cab.ps1 writes: repeated text and pseudo-random bytes with E8 call bytes (System.Random is stable for a seed).</summary>
    private static byte[] Mixed()
    {
        var rng = new Random(1234);
        var o = new MemoryStream();
        for (int i = 0; i < 40; i++)
        {
            o.Write(Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat($"block {i} of mixed content: the quick brown fox jumps over the lazy dog. ", 20))));
            var noise = new byte[600];
            rng.NextBytes(noise);
            for (int k = 0; k < noise.Length; k += 37) noise[k] = 0xE8;
            o.Write(noise);
        }
        return o.ToArray();
    }

    [Theory]
    [InlineData("stored.cab", "stored")]
    [InlineData("mszip.cab", "MSZIP")]
    [InlineData("lzx21.cab", "LZX:21")]
    [InlineData("lzx15.cab", "LZX:15")]
    public void Cabinet_folders_decode_to_the_original_bytes(string name, string compression)
    {
        var cab = Cabinet.Read(Fixture(name), name);
        Assert.Equal(["readme.txt", "data/mixed.bin", "data/setup.zip"], cab.Files.Select(f => f.Name));
        Assert.Equal(compression, cab.Compression(0));
        Assert.Equal(Mixed(), cab.Extract(cab.Files[1], 1 << 30));
        Assert.Equal(string.Concat(Enumerable.Repeat("cabinet test file ", 40)), Encoding.ASCII.GetString(cab.Extract(cab.Files[0], 1 << 30)!));
    }

    [Fact]
    public void An_msi_gives_its_files_under_install_paths_and_its_custom_action_code()
    {
        var c = Containers.Open(Fixture("sample.msi"), "sample.msi", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("Windows Installer msi", c.Kind);
        // msiextract -l lists the same three paths
        Assert.Equal("installed readme", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "Program Files/Corvus Sample/readme.txt").Bytes));
        Assert.Contains(c.Items, i => i.Name == "Program Files/Corvus Sample/docs/Quarterly Report (final).txt");
        Assert.Contains("CreateObject(\"WScript.Shell\")", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "Binary/CheckScript.vbs").Bytes));
        Assert.Contains("ActiveXObject", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "CustomAction/Greet.js").Bytes));
        var ca = Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "tables/CustomAction.tsv").Bytes).Split('\n');
        Assert.Equal("Action\tType\tSource\tTarget\tExtendedType", ca[0].TrimEnd('\r'));
        Assert.Contains("RunCheck\t3142\tCheckScript\tMain\t", ca.Select(l => l.TrimEnd('\r')));
    }

    [Fact]
    public void The_installer_view_says_what_runs_when_and_as_whom()
    {
        var bytes = Fixture("sample.msi");
        var f = (InstallerFileView.Facts)new InstallerFileView().Inspect(new FileInput("sample.msi", bytes, Blob.Identify(bytes)), default)!.Detail;
        Assert.Equal(("Corvus Sample", "1.2.3", "Corvus Tests"), (f.Product!.Name, f.Product.Version, f.Product.Manufacturer));
        Assert.Equal((3, "compressed files"), (f.Files, f.Summary!["source"]));
        var run = Assert.Single(f.CustomActions, a => a.Name == "RunCheck");
        Assert.Equal(("VBScript", "Binary CheckScript", "deferred, as LocalSystem, errors ignored"), (run.Kind, run.Source, run.Execution));
        Assert.Equal(["InstallExecuteSequence 6599 if NOT REMOVE"], run.When);
        Assert.Contains(f.Findings, x => x is { Keyword: "WScript.Shell", Location: "CustomAction RunCheck:2" });
        Assert.Contains(f.Findings, x => x.Keyword.EndsWith(@"CurrentVersion\Run\CorvusSample", StringComparison.Ordinal));
        Assert.Contains(f.CustomActions, a => a is { Name: "SetTarget", Kind: "set property", Target: "http://example.test/update" });
    }

    [Fact]
    public void Stream_names_unpack_two_characters_per_unit()
    {
        // 0x4840 marks a table, units from 0x3800 hold a pair (low six bits first), units from 0x4800 one character
        Assert.Equal("!x", MsiDatabase.DecodeName("䡀x"));
        Assert.Equal("ab", MsiDatabase.DecodeName(((char)(0x3800 + 36 + (37 << 6))).ToString()));
        Assert.Equal("c", MsiDatabase.DecodeName(((char)(0x4800 + 38)).ToString()));
    }

    [Fact]
    [FuzzEntry(typeof(CabinetReader), typeof(Cabinet), typeof(MsiReader), typeof(MsiDatabase), typeof(MsiPackage), typeof(InstallerFileView))]
    public void Fuzzed_cabinets_and_packages_never_throw_past_a_tool_error()
    {
        foreach (var (name, seed) in new[] { ("a.cab", Fixture("mszip.cab")), ("b.cab", Fixture("lzx21.cab")), ("c.msi", Fixture("sample.msi")) })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
                try { new InstallerFileView().Inspect(new FileInput(name, b, Blob.Identify(b)), default); } catch (ToolError) { }
            }, 200);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
