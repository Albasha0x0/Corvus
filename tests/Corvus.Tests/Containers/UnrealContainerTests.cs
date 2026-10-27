using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Unreal pak files (versions 1-11, both index layouts, compression methods, encryption flags) and IoStore containers.</summary>
public sealed class UnrealContainerTests(ITestOutputHelper output)
{
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Containers", "UnrealFixtures", name);

    // The content build.ps1 generates.
    private static readonly byte[] Settings = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("[Section]\nName=Ledger\nCount=3\n", 40)));
    private static readonly byte[] Notes = Encoding.UTF8.GetBytes("nested entry\n");

    private static ContainerContents Open(byte[] data, string name = "x.pak", string? location = null) =>
        Containers.Open(data, name, AnalysisLimits.Default, default, location, allFiles: true);

    [Theory]
    [InlineData("v1.pak", "pak version 1 (Initial)", null)]
    [InlineData("v2.pak", "pak version 2 (NoTimestamps)", null)]
    [InlineData("v3.pak", "pak version 3 (CompressionEncryption)", null)]
    [InlineData("v3-zlib.pak", "pak version 3 (CompressionEncryption)", "Zlib")]
    [InlineData("v4-zlib.pak", "pak version 4 (IndexEncryption)", "Zlib")]
    [InlineData("v6-zlib.pak", "pak version 6 (DeleteRecords)", "Zlib")]
    [InlineData("v10-zlib.pak", "pak version 10 (PathHashIndex)", "Zlib")]
    [InlineData("v11-gzip.pak", "pak version 11 (Fnv64BugFix)", "Gzip")]
    [InlineData("v11-zstd.pak", "pak version 11 (Fnv64BugFix)", "Zstd")]
    [InlineData("v11-lz4.pak", "pak version 11 (Fnv64BugFix)", "LZ4")]
    public void Each_version_lists_and_extracts_its_files(string fixture, string version, string? method)
    {
        var data = File.ReadAllBytes(Fixture(fixture));
        Assert.Equal("unreal pak", Blob.Identify(data));
        var c = Open(data, fixture);
        Assert.Equal(UnrealPak.Kind, c.Kind);
        Assert.StartsWith($"Unreal {version}: {(method == null ? 2 : 3)} file(s), mount point ../../../Fixture/" + (method != null ? $", compression {method}" : ""), c.Notes[0]);
        Assert.Equal(Settings, Assert.Single(c.Items, i => i.Name == "Config/Settings.ini").Bytes);
        Assert.Equal(Notes, Assert.Single(c.Items, i => i.Name == "Config/Nested/notes.txt").Bytes);
        if (method != null)
        {
            // 200,000 zeros span four 64 KiB compression blocks.
            Assert.Equal(new byte[200000], Assert.Single(c.Items, i => i.Name == "zeros.bin").Bytes);
            Assert.Contains(c.Entries!, e => e.Path == "zeros.bin" && e.Size == 200000 && e.Detail == $"{method} compressed");
        }
    }

    [Fact]
    public void An_encrypted_index_is_named_and_lists_nothing()
    {
        var data = File.ReadAllBytes(Fixture("v11-gzip.pak"));
        // The encrypted-index flag sits after the 16-byte key GUID at the start of the 221-byte footer.
        data[^(221 - 16)] = 1;
        var c = Open(data);
        Assert.Equal("Unreal pak version 11 (Fnv64BugFix): the index is encrypted with the default key; no files listed.", Assert.Single(c.Notes));
        Assert.Empty(c.Entries!);
    }

    [Fact]
    public void A_damaged_index_is_a_malformed_input_error()
    {
        var data = File.ReadAllBytes(Fixture("v3.pak"));
        // The index offset follows the encrypted flag, magic and version of the 45-byte footer.
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(data.Length - 45 + 9), data.Length);
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Open(data)).Code);
    }

    [Fact]
    [FuzzEntry(typeof(UnrealPak))]
    public void Fuzzed_paks_never_throw_unexpectedly()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "v1.pak", "v3-zlib.pak", "v10-zlib.pak", "v11-lz4.pak" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b); } catch (ToolError) { } }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Theory]
    // Chunk type 7 is LoaderInitialLoadMeta before TOC version 5 and ExternalFile from it, as retoc reads it too.
    [InlineData("toc-v2.utoc", "TOC version 2 (DirectoryIndex)", "LoaderInitialLoadMeta")]
    [InlineData("toc-v5.utoc", "TOC version 5 (PerfectHashWithOverflow)", "ExternalFile")]
    [InlineData("toc-v8.utoc", "TOC version 8 (ReplaceIoChunkHashWithIoHash)", "ExternalFile")]
    public void Each_toc_version_lists_its_files_and_reads_them_from_the_data_file(string fixture, string version, string type)
    {
        var path = Fixture(fixture);
        var data = File.ReadAllBytes(path);
        Assert.Equal("unreal utoc", Blob.Identify(data));
        var c = Open(data, fixture, path);
        Assert.Equal(UnrealIoStore.Kind, c.Kind);
        bool large = fixture == "toc-v8.utoc";
        Assert.Matches($@"^Unreal IoStore {Regex.Escape(version)}, container 0x[0-9A-F]{{16}}: {(large ? 3 : 2)} chunk\(s\) \({(large ? 3 : 2)} {type}\), mount point \.\./\.\./\.\./\.$", c.Notes[0]);
        Assert.Equal(Settings, Assert.Single(c.Items, i => i.Name == "Fixture/Config/Settings.ini").Bytes);
        Assert.Equal(Notes, Assert.Single(c.Items, i => i.Name == "Fixture/Config/Nested/notes.txt").Bytes);
        // 66,000 zeros span two 64 KiB blocks.
        if (large) Assert.Equal(new byte[66000], Assert.Single(c.Items, i => i.Name == "Fixture/zeros.bin").Bytes);
    }

    [Fact]
    public void Chunks_without_paths_are_listed_by_id_and_type()
    {
        var path = Fixture("toc-v5-nopaths.utoc");
        var c = Open(File.ReadAllBytes(path), "toc-v5-nopaths.utoc", path);
        Assert.Contains("The container has no directory index; chunks are listed by id.", c.Notes);
        Assert.Equal(Settings, Assert.Single(c.Items, i => i.Name == "chunks/000000000000000100000007.ExternalFile").Bytes);
    }

    [Fact]
    public void A_toc_without_its_data_file_lists_and_names_what_is_missing()
    {
        using var dir = new TempDir();
        var path = dir.File("toc-v5.utoc");
        File.Copy(Fixture("toc-v5.utoc"), path);
        var c = Open(File.ReadAllBytes(path), "toc-v5.utoc", path);
        Assert.Contains("toc-v5.ucas is not beside the TOC; chunks are listed, not read.", c.Notes);
        Assert.Equal(2, c.Entries!.Count);
        Assert.Empty(c.Items);
    }

    [Fact]
    public void An_encrypted_container_is_named_and_not_read()
    {
        var data = File.ReadAllBytes(Fixture("toc-v5.utoc"));
        // Container flags sit at 0x50 of the 144-byte header; 2 is Encrypted.
        data[0x50] |= 2;
        var c = Open(data, "toc-v5.utoc", Fixture("toc-v5.utoc"));
        Assert.Contains("The container is encrypted with the default key; chunk data is not read and the directory index is not listed.", c.Notes);
        Assert.Empty(c.Items);
    }

    [Fact]
    [FuzzEntry(typeof(UnrealIoStore))]
    public void Fuzzed_tocs_never_throw_unexpectedly()
    {
        var failures = new List<string>();
        foreach (var seed in new[] { "toc-v2.utoc", "toc-v8.utoc" })
            failures.AddRange(FormatFuzz.Run(File.ReadAllBytes(Fixture(seed)), b => { try { Open(b, seed, Fixture(seed)); } catch (ToolError) { } }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    // Each pak under CORVUS_UNREAL_PAKS is listed by the tool in CORVUS_PAK_TOOL; where it reads the contents (no
    // encrypted files), each file's SHA-256 is compared. A pak with an encrypted index is skipped by the tool without a
    // key and named by Corvus.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_UNREAL_PAKS", "CORVUS_PAK_TOOL")]
    public void Real_paks_hold_the_files_and_contents_the_reference_tool_reads()
    {
        var tool = ExternalTools.Locate(ExternalTools.PakTool)!.Value.Path;
        var files = Directory.EnumerateFiles(RealData.Path("CORVUS_UNREAL_PAKS"), "*.pak", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        var problems = new List<string>();
        int paks = 0, listed = 0, hashed = 0, encryptedIndex = 0;
        foreach (var file in files)
        {
            string name = Path.GetFileName(file);
            var data = File.ReadAllBytes(file);
            if (!UnrealPak.Looks(data)) continue;
            paks++;
            var c = Open(data, name);
            if (c.Notes[0].Contains("the index is encrypted", StringComparison.Ordinal)) { encryptedIndex++; continue; }
            string mount = Regex.Match(c.Notes[0], @"mount point (.*?)(?:, compression |, frozen index|\.$)").Groups[1].Value;
            var list = Run(tool, "list", file);
            var theirs = list.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Order(StringComparer.Ordinal).ToList();
            var ours = c.Entries!.Select(e => mount + e.Path).Order(StringComparer.Ordinal).ToList();
            if (!theirs.SequenceEqual(ours)) { problems.Add($"{name}: repak lists [{string.Join(", ", theirs)}], Corvus [{string.Join(", ", ours)}]"); continue; }
            listed++;
            if (c.Entries!.Any(e => e.Detail == "encrypted")) continue;
            foreach (var line in Run(tool, "hashes", file).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var (hash, path) = (line[..64], line[65..]);
                var item = c.Items.FirstOrDefault(i => mount + i.Name == path);
                if (item == null) problems.Add($"{name}: {path} not extracted");
                else if (Convert.ToHexStringLower(SHA256.HashData(item.Bytes)) != hash) problems.Add($"{name}: {path} contents differ");
                else hashed++;
            }
        }
        output.WriteLine($"{paks} paks: {listed} listed as repak lists them, {hashed} files equal by SHA-256, {encryptedIndex} with an encrypted index");
        foreach (var p in problems.Take(40)) output.WriteLine(p);
        Assert.Empty(problems);
        Assert.True(listed > 0 && hashed > 0);
    }

    private static string Run(string tool, string op, string file)
    {
        var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.PakTool, op, ("file", file)), TimeSpan.FromMinutes(2), 1 << 24, default);
        Assert.True(run.ExitCode == 0, $"{file}: repak {op} exit {run.ExitCode}: {run.Text}");
        return run.Text;
    }
}
