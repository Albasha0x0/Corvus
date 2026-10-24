using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>malcontent behaviours compared between two builds, with a pack of rules the test writes.</summary>
public sealed class MalcontentChangesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static WorkerPool Pool(string? library) => new(new WorkerPoolOptions
    {
        Enabled = true,
        MemoryLimitBytes = 0,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = library } },
    });

    // An installed pack laid out as malcontent's: behaviours by folder, risk as a tag, overrides under false_positives/.
    private string Root()
    {
        var root = _dir.File("rules");
        var pack = Path.Combine(root, MalcontentChanges.Pack, "1.27.1");
        void Rule(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(pack, path))!);
            File.WriteAllText(Path.Combine(pack, path), text);
        }
        Rule("net/http/request.yara", """rule http_get : medium { meta: description = "makes HTTP requests" strings: $a = "GET /index" condition: $a }""");
        Rule("fs/file/delete.yara", """rule delete_file : low { meta: description = "deletes files" strings: $a = "DeleteFileW" condition: $a }""");
        Rule("anti-static/marker.yara", """
            private rule marker_bytes { strings: $a = "payload_marker" condition: $a }
            rule marked_payload : high { meta: description = "holds a marked payload" condition: marker_bytes }
            """);
        Rule("false_positives/request.yara", """rule http_get_fixture { strings: $a = "GET /index" condition: $a }""");
        File.WriteAllText(Path.Combine(pack, "pack.json"), "{}");
        return root;
    }

    private (string Old, string New) Builds()
    {
        var old = _dir.File("old.bin");
        var @new = _dir.File("new.bin");
        File.WriteAllText(old, "imports DeleteFileW\n");
        File.WriteAllText(@new, "sends GET /index and keeps payload_marker\n");
        return (old, @new);
    }

    [YaraFact]
    public void Behaviours_one_build_matches_are_added_or_removed_highest_risk_first_without_overrides()
    {
        var (old, @new) = Builds();
        using var pool = Pool(YaraTestTools.Library);
        var (rows, text) = MalcontentChanges.Between(old, @new, default, Root(), pool);
        Assert.Equal(
            [
                ("added", "malcontent/anti-static/marker", "high: holds a marked payload (marked_payload)"),
                ("added", "malcontent/net/http/request", "medium: makes HTTP requests (http_get)"),
                ("removed", "malcontent/fs/file/delete", "low: deletes files (delete_file)"),
            ],
            rows.Select(r => (r.Kind, r.Key, r.New ?? r.Old)));
        Assert.StartsWith("malcontent 1.27.1 behaviours: 2 added, 1 removed.\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_the_pack_installed_nothing_is_compared_or_said()
    {
        var (old, @new) = Builds();
        var (rows, text) = MalcontentChanges.Between(old, @new, default, _dir.File("no-rules"));
        Assert.Empty(rows);
        Assert.Null(text);
    }

    [Fact]
    public void A_worker_that_cannot_load_yara_x_leaves_the_behaviours_not_compared_with_the_reason()
    {
        var (old, @new) = Builds();
        using var pool = Pool(_dir.File("missing-yara-x.dll"));
        var (rows, text) = MalcontentChanges.Between(old, @new, default, Root(), pool);
        Assert.Empty(rows);
        Assert.StartsWith("malcontent 1.27.1 behaviours not compared: ", text, StringComparison.Ordinal);
        Assert.EndsWith("search_container kind=yara query=pack:malcontent on each build lists them.\n", text, StringComparison.Ordinal);
    }
}
