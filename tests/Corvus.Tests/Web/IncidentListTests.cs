using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Incident lists built here, matched against lockfiles, files and archive members.</summary>
public sealed class IncidentListTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string NpmLock(string name, string version) =>
        "{\"name\":\"app\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"},\"node_modules/" + name + "\":{\"version\":\"" + version
        + "\",\"resolved\":\"https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz\",\"integrity\":\"sha512-AAAA\"}}}";

    private static string Sha(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private string Write(string relative, string text) => Write(relative, Encoding.UTF8.GetBytes(text));

    private string Write(string relative, byte[] bytes)
    {
        var path = _dir.File(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static UnpackService.ContainerSearch Search(string path, string query) =>
        new UnpackService(new AssemblyWorkspace()).Search(path, query, "incident", 50, AnalysisLimits.Default, default);

    [Fact]
    public void A_list_naming_one_version_marks_exactly_that_project_and_package()
    {
        Write("projects/web/package-lock.json", NpmLock("left-pad", "1.3.0"));
        Write("projects/api/package-lock.json", NpmLock("left-pad", "1.1.0"));
        Write("projects/tool/poetry.lock", "[[package]]\nname = \"Left_Pad\"\nversion = \"1.1.0\"\n");
        var list = Write("incident.txt", "# fixture\nleft-pad@1.1.0 fixture entry\n");
        var found = Search(_dir.File("projects"), list);
        Assert.Equal([("api/package-lock.json", "left-pad@1.1.0"), ("tool/poetry.lock", "left-pad@1.1.0")],
            found.Items.Select(i => (i.Path, i.Name)).OrderBy(x => x.Path, StringComparer.Ordinal));
        Assert.All(found.Items, i => Assert.StartsWith("listed in incident.txt", i.Detail, StringComparison.Ordinal));
    }

    [Fact]
    public void Look_alike_names_and_versions_are_not_listed()
    {
        Write("projects/a/package-lock.json", NpmLock("left-pad", "1.1.1"));
        Write("projects/b/package-lock.json", NpmLock("left-pad2", "1.1.0"));
        Write("projects/c/notes.txt", "left-pad@1.1.0\n");
        var list = Write("incident.txt", "left-pad@1.1.0\n");
        Assert.Empty(Search(_dir.File("projects"), list).Items);
    }

    [Fact]
    public void A_listed_sha256_marks_the_file_in_a_folder_and_the_member_of_an_archive()
    {
        var payload = Encoding.UTF8.GetBytes("harmless fixture bytes");
        Write("tree/sub/data.bin", payload);
        Write("tree/other.bin", "unrelated");
        var list = Write("hashes.txt", Sha(payload).ToUpperInvariant() + " fixture\n");
        var folder = Search(_dir.File("tree"), list);
        Assert.Equal(["sub/data.bin"], folder.Items.Select(i => i.Path));

        var zip = _dir.File("bundle.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (var s = archive.CreateEntry("inner/data.bin").Open())
            s.Write(payload);
        var member = Search(zip, list);
        Assert.Contains(member.Items, i => i.Path.EndsWith("data.bin", StringComparison.Ordinal) && i.Name == Sha(payload));
    }

    private static byte[] Pe(byte[]? table = null, uint? tableSize = null)
    {
        var b = new PeBuilder();
        b.Add(".text", new byte[0x200]);
        var bare = b.Build();
        if (table != null) b.Overlay = table;
        if (table != null || tableSize != null) b.Directories[PeImage.SecurityDirectory] = ((uint)bare.Length, tableSize ?? (uint)table!.Length);
        return b.Build();
    }

    /// <summary>The image without CheckSum, the security directory entry and any table, hashed as the Authenticode specification excludes them.</summary>
    private static string Authenticode(byte[] bare, HashAlgorithmName algorithm)
    {
        var pe = PeImage.TryParse(bare)!;
        int entry = pe.DirectoryEntryOffset(PeImage.SecurityDirectory);
        var kept = bare.Take(pe.ChecksumOffset).Concat(bare.Skip(pe.ChecksumOffset + 4).Take(entry - pe.ChecksumOffset - 4)).Concat(bare.Skip(entry + 8)).ToArray();
        return Convert.ToHexStringLower(algorithm == HashAlgorithmName.SHA1 ? SHA1.HashData(kept) : SHA256.HashData(kept));
    }

    [Fact]
    public void A_listed_authenticode_sha256_marks_an_image_whether_or_not_a_certificate_table_follows()
    {
        var bare = Pe();
        var withTable = Pe(Enumerable.Range(0, 24).Select(i => (byte)(i + 1)).ToArray());
        Assert.NotEqual(Sha(bare), Sha(withTable));
        Write("tree/plain.dll", bare);
        Write("tree/tabled.dll", withTable);
        var list = Write("hashes.txt", Authenticode(bare, HashAlgorithmName.SHA256) + " fixture\n");
        var found = Search(_dir.File("tree"), list);
        Assert.Equal(["plain.dll", "tabled.dll"], found.Items.Select(i => i.Path).Order(StringComparer.Ordinal));
        Assert.All(found.Items, i => Assert.StartsWith("listed in hashes.txt, authenticode sha256", i.Detail, StringComparison.Ordinal));
    }

    [Fact]
    public void A_listed_sha1_marks_the_file_and_the_authenticode_hash_by_name()
    {
        var bare = Pe();
        Write("tree/plain.dll", bare);
        Write("tree/note.txt", "harmless");
        var file = Convert.ToHexStringLower(SHA1.HashData(bare));
        var authenticode = Authenticode(bare, HashAlgorithmName.SHA1);
        var found = Search(_dir.File("tree"), Write("hashes.txt", $"{file}\n{authenticode}\n"));
        Assert.Equal([$"listed in hashes.txt, authenticode sha1, {bare.Length:N0} bytes", $"listed in hashes.txt, sha1, {bare.Length:N0} bytes"],
            found.Items.Select(i => i.Detail!).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_certificate_table_outside_the_file_leaves_the_authenticode_hash_unknown_and_named()
    {
        Write("tree/broken.dll", Pe(tableSize: 4096));
        var found = Search(_dir.File("tree"), Write("hashes.txt", new string('a', 64) + "\n"));
        Assert.Empty(found.Items);
        Assert.Contains(found.Notes, n => n.Contains("Authenticode hashes are unknown", StringComparison.Ordinal));
    }

    [Fact]
    public void A_listed_authenticode_sha256_marks_a_member_image_of_an_archive()
    {
        var bare = Pe();
        var zip = _dir.File("bundle.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (var s = archive.CreateEntry("inner/tabled.dll").Open())
            s.Write(Pe(Enumerable.Range(0, 24).Select(i => (byte)(i + 1)).ToArray()));
        var found = Search(zip, Write("hashes.txt", Authenticode(bare, HashAlgorithmName.SHA256) + "\n"));
        Assert.Contains(found.Items, i => i.Path.EndsWith("tabled.dll", StringComparison.Ordinal) && i.Detail!.StartsWith("listed in hashes.txt, authenticode sha256", StringComparison.Ordinal));
    }

    [Fact]
    public void A_package_only_list_computes_no_authenticode_hash()
    {
        Write("tree/broken.dll", Pe(tableSize: 4096));
        var found = Search(_dir.File("tree"), Write("incident.txt", "left-pad@1.1.0\n"));
        Assert.Empty(found.Items);
        Assert.DoesNotContain(found.Notes, n => n.Contains("Authenticode", StringComparison.Ordinal));
    }

    [Fact]
    public void A_sha1_list_names_an_image_whose_certificate_table_is_unreadable()
    {
        Write("tree/broken.dll", Pe(tableSize: 4096));
        var found = Search(_dir.File("tree"), Write("hashes.txt", new string('b', 40) + "\n"));
        Assert.Empty(found.Items);
        Assert.Contains(found.Notes, n => n.Contains("broken.dll", StringComparison.Ordinal) && n.Contains("matched by file hash only", StringComparison.Ordinal));
    }

    [Fact]
    public void A_pack_query_reads_the_lists_of_an_installed_pack()
    {
        var name = "incident-test-" + Guid.NewGuid().ToString("N");
        var folder = Path.Combine(RulePacks.Root, name, "1.0");
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "pack.json"), "{}");
            File.WriteAllText(Path.Combine(folder, "npm.txt"), "left-pad@1.1.0\n");
            Write("projects/api/package-lock.json", NpmLock("left-pad", "1.1.0"));
            var found = Search(_dir.File("projects"), "pack:" + name);
            Assert.Equal(["api/package-lock.json"], found.Items.Select(i => i.Path));
            Assert.Equal($"listed in {name}/npm.txt, package-lock", found.Items[0].Detail);
        }
        finally { Directory.Delete(Path.Combine(RulePacks.Root, name), recursive: true); }
    }

    [Fact]
    public void A_pack_that_is_not_installed_is_named()
    {
        var e = Assert.Throws<ToolError>(() => Search(_dir.File("."), "pack:no-such-incident-pack"));
        Assert.Contains("no-such-incident-pack", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Lines_that_are_not_entries_are_counted_and_skipped()
    {
        var list = IncidentList.Parse(Encoding.UTF8.GetBytes("# c\n\na@1\nnot an entry\n@scope/pkg@2.0.0\nwild*@1\n"), "x");
        Assert.Equal(2, list.Count);
        Assert.Equal(2, list.Unreadable);
        Assert.True(list.Lists("@scope/pkg", "2.0.0", python: false));
    }

    [Fact]
    public void A_list_saved_with_a_byte_order_mark_still_reads_its_first_entry()
    {
        var list = IncidentList.Parse([0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("left-pad@1.1.0\r\n")], "x");
        Assert.True(list.Lists("left-pad", "1.1.0", python: false));
        Assert.Equal(0, list.Unreadable);
    }

    [Fact]
    [FuzzEntry(typeof(IncidentList))]
    public void Fuzzed_incident_lists_never_throw()
    {
        var seed = Encoding.UTF8.GetBytes("# list\nleft-pad@1.1.0 label\n" + new string('a', 64) + " hash\n@s/p@2\n");
        var failures = FormatFuzz.Run(seed, b =>
        {
            var list = IncidentList.Parse(b, "fuzz");
            list.Lists("left-pad", "1.1.0", python: true);
            list.Lists(new string('a', 64));
        }, 100);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    [Fact]
    public void A_label_after_a_listed_hash_is_shown_on_its_row()
    {
        var bytes = Encoding.UTF8.GetBytes("labelled file");
        Write("files/a.bin", bytes);
        Write("files/b.bin", Encoding.UTF8.GetBytes("plain file"));
        var sha1 = Convert.ToHexStringLower(SHA1.HashData(Encoding.UTF8.GetBytes("plain file")));
        var list = Write("incident.txt", $"{Sha(bytes)}  driver   build\t1\n{sha1}\n");
        var rows = Search(_dir.File("files"), list).Items.ToDictionary(i => i.Path, i => i.Detail);
        Assert.EndsWith(", driver build 1", rows["a.bin"], StringComparison.Ordinal);
        Assert.EndsWith(" bytes", rows["b.bin"], StringComparison.Ordinal);
    }

    [Fact]
    public void A_long_label_is_cut_to_80_characters()
    {
        var bytes = Encoding.UTF8.GetBytes("long label");
        Write("files/a.bin", bytes);
        var label = new string('x', 100);
        var list = Write("incident.txt", $"{Convert.ToHexStringLower(SHA1.HashData(bytes))} {label}\n");
        Assert.EndsWith(", " + label[..80], Search(_dir.File("files"), list).Items.Single().Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void A_file_over_the_hash_limit_is_named_as_not_hashed()
    {
        Write("files/big.bin", new byte[2048]);
        var list = Write("incident.txt", Sha(new byte[2048]) + "\n");
        IncidentSearchKind.MaxFileBytesOverride = 1024;
        try
        {
            var found = Search(_dir.File("files"), list);
            Assert.Empty(found.Items);
            Assert.Contains(found.Notes, n => n.Contains("big.bin: larger than 1,024 bytes; not hashed, its hashes are unknown", StringComparison.Ordinal));
        }
        finally { IncidentSearchKind.MaxFileBytesOverride = null; }
    }

    [Fact]
    public void A_walk_past_the_file_limit_names_the_subfolder_call()
    {
        for (int i = 0; i < 3; i++) Write($"files/{i}.bin", [(byte)i]);
        var list = Write("incident.txt", Sha([9]) + "\n");
        IncidentSearchKind.MaxFilesOverride = 2;
        try
        {
            Assert.Contains(Search(_dir.File("files"), list).Notes,
                n => n.Contains("stopped at the 2-file limit", StringComparison.Ordinal) && n.Contains("path=<subfolder>", StringComparison.Ordinal));
        }
        finally { IncidentSearchKind.MaxFilesOverride = null; }
    }
}
