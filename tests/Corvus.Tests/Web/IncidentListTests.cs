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
}
