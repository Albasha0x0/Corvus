using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>malcontent behaviours compared per changed code file of two package versions, with a pack of rules the test writes.</summary>
public sealed class PackageBehavioursTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static WorkerPool Pool() => new(new WorkerPoolOptions
    {
        Enabled = true,
        MemoryLimitBytes = 0,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
    });

    private string Root()
    {
        var pack = Path.Combine(_dir.File("rules"), MalcontentChanges.Pack, "1.27.1");
        Directory.CreateDirectory(Path.Combine(pack, "net/http"));
        File.WriteAllText(Path.Combine(pack, "net/http/request.yara"), """rule http_get : medium { meta: description = "makes HTTP requests" strings: $a = "fetch(" condition: $a }""");
        File.WriteAllText(Path.Combine(pack, "pack.json"), "{}");
        return Path.GetDirectoryName(Path.GetDirectoryName(pack))!;
    }

    private PackageFiles Package(string name, params (string Path, string Text)[] files)
    {
        var root = _dir.File(name);
        foreach (var (p, text) in files)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(root, p))!);
            File.WriteAllText(Path.Combine(root, p), text);
        }
        return PackageFiles.Open(root, default)!;
    }

    private const string Manifest = """{"name":"example-tool","version":"1.0.0","main":"index.js"}""";

    [YaraFact]
    public void A_new_network_call_lists_one_added_behaviour_at_its_file()
    {
        var old = Package("tool-1", ("package.json", Manifest), ("index.js", "console.log(1);\n"), ("util.js", "module.exports = 1;\n"));
        var @new = Package("tool-2", ("package.json", Manifest), ("index.js", "fetch('https://example.invalid/v2');\n"), ("util.js", "module.exports = 1;\n"));
        using var pool = Pool();
        var (rows, notes) = PackageBehaviours.Between(old, @new, default, Root(), pool);
        Assert.Equal([("added", "malcontent/net/http/request at index.js")], rows.Select(r => (r.Kind, r.Key)));
        Assert.Empty(notes);
    }

    [YaraFact]
    public void Differing_files_without_a_matching_behaviour_list_no_rows()
    {
        var old = Package("quiet-1", ("package.json", Manifest), ("index.js", "console.log(1);\n"));
        var @new = Package("quiet-2", ("package.json", Manifest), ("index.js", "console.log(2);\n"), ("extra.js", "var x = 1;\n"));
        using var pool = Pool();
        Assert.Empty(PackageBehaviours.Between(old, @new, default, Root(), pool).Rows);
    }

    [Fact]
    public void A_scan_that_cannot_run_names_the_first_file_and_stops()
    {
        var old = Package("fail-1", ("package.json", Manifest), ("a.js", "1;\n"), ("b.js", "2;\n"));
        var @new = Package("fail-2", ("package.json", Manifest), ("a.js", "3;\n"), ("b.js", "4;\n"));
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = _dir.File("missing-yara-x.dll") } },
        });
        var (rows, notes) = PackageBehaviours.Between(old, @new, default, Root(), pool);
        Assert.Empty(rows);
        var note = Assert.Single(notes);
        Assert.StartsWith("a.js: malcontent 1.27.1 behaviours not compared: ", note, StringComparison.Ordinal);
        Assert.EndsWith("the remaining files' behaviours are unknown", note, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_the_pack_installed_no_file_is_scanned_and_nothing_is_said()
    {
        var old = Package("bare-1", ("package.json", Manifest), ("index.js", "console.log(1);\n"));
        var @new = Package("bare-2", ("package.json", Manifest), ("index.js", "fetch('https://example.invalid/');\n"));
        var (rows, notes) = PackageBehaviours.Between(old, @new, default, _dir.File("no-rules"));
        Assert.Empty(rows);
        Assert.Empty(notes);
    }
}
