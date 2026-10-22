using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Kept results (S3, D5): content ids, the disk tier shared across restarts and processes, eviction and its reason.</summary>
public sealed class ResultStoreTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private ResultCacheOptions Disk(long maxBytes = 1 << 20) => new(_dir.Path, maxBytes, TimeSpan.FromDays(7));

    private static KeptOrigin Origin(string tool = "list_types") =>
        CallLog.Origin(tool, new Dictionary<string, JsonElement> { ["assembly"] = JsonSerializer.SerializeToElement("app"), ["password"] = JsonSerializer.SerializeToElement("hunter2") });

    private static ToolError NotFound(Action read) => Assert.Throws<ToolError>(read);

    private static string Reason(ToolError e) => JsonSerializer.SerializeToElement(e.Details).GetProperty("reason").GetString()!;

    [Fact]
    public void SameTextGetsTheSameId()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var a = store.Keep("hello", Origin());
        Assert.Equal(a, store.Keep("hello", Origin("other")));
        Assert.Equal(a, new ResultStore(ResultCacheOptions.MemoryOnly).Keep("hello", Origin()));
        Assert.NotEqual(a, store.Keep("hello!", Origin()));
        Assert.Matches("^r-[0-9a-f]{12}$", a);
        Assert.Equal("r-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("hello")))[..12], a);
    }

    [Fact]
    public void ReadableAfterRestart_WithTheSameFolder()
    {
        var id = new ResultStore(Disk()).Keep("line 1\nline 2", Origin(), record: """{"items":[1,2]}""");
        var kept = new ResultStore(Disk()).Read(id.ToUpperInvariant());
        Assert.Equal("line 1\nline 2", kept.Text);
        Assert.Equal("""{"items":[1,2]}""", kept.Record);
        Assert.Equal("list_types", kept.Info.Tool);
        // the side record: arguments canonical with secrets masked, their hash over the unmasked form
        Assert.Equal("""{"assembly":"app","password":"[redacted]"}""", kept.Info.Arguments);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData("""{"assembly":"app","password":"hunter2"}"""u8)), kept.Info.ArgumentsSha256);
        Assert.Equal(13, kept.Info.Chars);
    }

    [Fact]
    public void EvictedIdSaysSoAndNamesTheOriginalCall()
    {
        var store = new ResultStore(Disk(maxBytes: 1_000));
        var first = store.Keep(new string('a', 700), Origin());
        var second = store.Keep(new string('b', 700), Origin());
        var e = NotFound(() => new ResultStore(Disk(maxBytes: 1_000)).Read(first));
        Assert.Equal(ErrorCode.NotFound, e.Code);
        Assert.Equal("evicted", Reason(e));
        Assert.Contains("call list_types again with {\"assembly\":\"app\",\"password\":\"[redacted]\"}", e.Remediation);
        Assert.Equal('b', new ResultStore(Disk()).Read(second).Text[0]);

        var never = NotFound(() => store.Read("r-0123456789ab"));
        Assert.Equal("unknown", Reason(never));
        Assert.Equal("unknown", Reason(NotFound(() => store.Read("r3"))));
    }

    [Fact]
    public void MemoryOnlyEvictionAlsoGivesTheReason()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly) { MemoryLimit = 1_000 };
        var first = store.Keep(new string('a', 700), Origin());
        store.Keep(new string('b', 700), Origin());
        Assert.Equal("evicted", Reason(NotFound(() => store.Read(first))));
    }

    [Fact]
    public void SizeCapIsEnforced()
    {
        var store = new ResultStore(Disk(maxBytes: 2_000));
        for (int i = 0; i < 10; i++) store.Keep(i + new string('x', 500), Origin());
        var status = store.Status();
        Assert.Equal("disk", status.Mode);
        Assert.True(status.Bytes <= 2_000, $"{status.Bytes} bytes kept");
        Assert.InRange(status.Entries, 1, 3);
        Assert.True(status.Evicted >= 7);
    }

    [Fact]
    public void Writes_under_the_size_limit_walk_the_folder_once()
    {
        var store = new ResultStore(Disk());
        for (int i = 0; i < 5; i++) store.Keep("result " + i, Origin());
        Assert.Equal(1, store.Walks);
    }

    [Fact]
    public void Writes_past_the_size_limit_walk_the_folder_once_per_quarter_of_it()
    {
        var store = new ResultStore(Disk(maxBytes: 10_000));
        for (int i = 0; i < 100; i++) store.Keep($"{i:000}" + new string('x', 497), Origin());
        // 50,000 bytes written: one walk to start, then one per 2,500 bytes past the limit, not one per write.
        Assert.InRange(store.Walks, 2, 1 + 50_000 / 2_500);
        Assert.True(store.Status().Bytes <= 10_000);
    }

    [Fact]
    public void Side_records_without_content_past_twice_the_age_limit_are_pruned()
    {
        var store = new ResultStore(Disk());
        var kept = store.Keep("kept", Origin());
        var old = Path.Combine(_dir.Path, "r-0123456789ab.meta.json");
        var recent = Path.Combine(_dir.Path, "r-ba9876543210.meta.json");
        File.WriteAllText(old, "{}");
        File.WriteAllText(recent, "{}");
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddDays(-15));
        store.Evict();
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(recent));
        Assert.True(File.Exists(Path.Combine(_dir.Path, kept + ".meta.json")));
    }

    [Fact]
    public void EntriesUnusedPastTheAgeLimitAreEvicted()
    {
        var store = new ResultStore(Disk());
        var id = store.Keep("old", Origin());
        var text = Path.Combine(_dir.Path, id + ".txt");
        File.SetLastWriteTimeUtc(text, DateTime.UtcNow.AddDays(-8));
        File.SetLastAccessTimeUtc(text, DateTime.UtcNow.AddDays(-8));
        store.Evict();
        Assert.False(File.Exists(text));
        Assert.Equal("evicted", Reason(NotFound(() => new ResultStore(Disk()).Read(id))));
    }

    [Fact]
    public void TruncatedEntryIsAMiss()
    {
        var id = new ResultStore(Disk()).Keep("0123456789", Origin());
        File.WriteAllText(Path.Combine(_dir.Path, id + ".txt"), "01234");
        NotFound(() => new ResultStore(Disk()).Read(id));
        // keeping it again repairs the entry
        new ResultStore(Disk()).Keep("0123456789", Origin());
        Assert.Equal("0123456789", new ResultStore(Disk()).Read(id).Text);
    }

    [Fact]
    public void OffKeepsResultsInMemoryOnly()
    {
        var options = ResultCacheOptions.FromEnvironment(name => name == ResultCacheOptions.RootVariable ? "off" : null);
        Assert.Null(options.Root);
        var store = new ResultStore(options);
        var id = store.Keep("text", Origin());
        Assert.Equal("text", store.Read(id).Text);
        Assert.Equal("memory", store.Status().Mode);
        Assert.Equal("unknown", Reason(NotFound(() => new ResultStore(options).Read(id))));

        var defaults = ResultCacheOptions.FromEnvironment(_ => null);
        Assert.Equal(Corvus.Native.Providers.DataFolder.Combine("results"), defaults.Root);
        Assert.Equal(512L << 20, defaults.MaxBytes);
        Assert.Equal(TimeSpan.FromDays(7), defaults.MaxAge);
        var custom = ResultCacheOptions.FromEnvironment(name => name switch
        {
            ResultCacheOptions.RootVariable => _dir.Path,
            ResultCacheOptions.MaxMegabytesVariable => "16",
            ResultCacheOptions.MaxDaysVariable => "2",
            _ => null,
        });
        Assert.Equal((_dir.Path, 16L << 20, TimeSpan.FromDays(2)), (custom.Root, custom.MaxBytes, custom.MaxAge));
    }

    private Corvus.Tools.SessionTools Tools(ResultStore store) => new(null!, null!, new ServerOptions(), store);

    [Fact]
    public void ReadResultPagesByTokensAtLineEnds()
    {
        var store = new ResultStore(Disk());
        var text = string.Concat(Enumerable.Range(0, 1_000).Select(i => $"line {i:D4} alpha\n"));
        var id = store.Keep(text, Origin());
        var tools = Tools(store);
        var pages = new StringBuilder();
        int offset = 0, calls = 0;
        while (true)
        {
            var page = tools.ReadKept(id, offset, maxTokens: 500);
            calls++;
            var body = page[(page.IndexOf('\n') + 1)..];
            var footer = body[(body.LastIndexOf('[')..)];
            body = body[..body.LastIndexOf('[')];
            Assert.True(CallLog.EstimateTokens(body) <= 500);
            Assert.EndsWith("\n", body);
            pages.Append(body);
            if (footer.StartsWith("[End:")) break;
            offset = int.Parse(footer["[More: offset=".Length..^1]);
        }
        Assert.Equal(text, pages.ToString());
        Assert.True(calls > 2);
    }

    [Fact]
    public void ReadResultSearchesLinesWithOffsets()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("alpha\nBeta one\ngamma\nbeta two\n", Origin());
        var tools = Tools(store);
        Assert.EndsWith("6: Beta one\n21: beta two\n[End: 2 matching lines from offset 0]", tools.ReadKept(id, query: "beta"));
        Assert.EndsWith("21: beta two\n[End: 1 matching line from offset 7]", tools.ReadKept(id, offset: 7, query: "beta"));
        Assert.EndsWith("0: alpha\n15: gamma\n[End: 2 matching lines from offset 0]", tools.ReadKept(id, query: "/^[ag]/"));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => tools.ReadKept(id, query: "/(/")).Code);
    }

    [Fact]
    public void ReadResultWritesTheExactBytesToOutputPath()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var text = "résumé\r\nline 2\n" + new string('z', 50_000);
        var id = store.Keep(text, Origin(), record: """{"total":2,"items":[{"a":1},{"b":[2,3]}]}""");
        var tools = Tools(store);
        var path = _dir.File("out.txt");
        var answer = tools.ReadKept(id, outputPath: path);
        var sha = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text))), sha);
        Assert.Contains($"SHA-256 {sha}", answer);
        Assert.DoesNotContain("zzz", answer);
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => tools.ReadKept(id, outputPath: path)).Code);

        tools.ReadKept(id, format: "jsonl", outputPath: path, overwrite: true);
        Assert.Equal("{\"a\":1}\n{\"b\":[2,3]}\n", File.ReadAllText(path));
        Assert.Contains("\"total\":2", tools.ReadKept(id, format: "json"));
        var textOnly = store.Keep("plain", Origin());
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => tools.ReadKept(textOnly, format: "json")).Code);
    }

    /// <summary>uninstall keeps the default results folder (and names it) unless --purge-data, which removes it.</summary>
    [Fact]
    public void UninstallPurgeRemovesKeptResults()
    {
        var root = Path.Combine(_dir.Path, "install");
        var dataRoot = Path.Combine(_dir.Path, "data");
        Directory.CreateDirectory(Path.Combine(root, "versions"));
        var results = Path.Combine(dataRoot, "results");
        var id = new ResultStore(new ResultCacheOptions(results, 1 << 20, TimeSpan.FromDays(7))).Keep("kept", Origin());
        Assert.Contains("results", Corvus.Setup.Installation.PlanRemoval(root, dataRoot, purgeData: false).Kept);
        Corvus.Setup.Installation.Apply(Corvus.Setup.Installation.PlanRemoval(root, dataRoot, purgeData: true));
        Assert.False(File.Exists(Path.Combine(results, id + ".txt")));
        Assert.False(Directory.Exists(dataRoot));
    }

    /// <summary>A second server process (here the command line) reads an id the first one kept.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task ReadableFromAnotherProcess()
    {
        var id = new ResultStore(Disk()).Keep("kept in one process\nread in another", Origin());
        var start = new System.Diagnostics.ProcessStartInfo("dotnet")
        {
            ArgumentList = { typeof(ResultStore).Assembly.Location, "read_result", "id=" + id, "--no-index" },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.Environment[ResultCacheOptions.RootVariable] = _dir.Path;
        using var process = System.Diagnostics.Process.Start(start)!;
        var stderr = process.StandardError.ReadToEndAsync();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromMinutes(1)).Token);
        Assert.True(process.ExitCode == 0, await stderr);
        Assert.Contains("read in another", output);
    }
}
