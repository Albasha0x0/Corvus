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
    public void Same_text_gets_the_same_ID()
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
    public void Results_are_readable_after_a_restart_with_the_same_folder()
    {
        var id = new ResultStore(Disk()).Keep("line 1\nline 2", Origin(), record: """{"items":[1,2]}""");
        var kept = new ResultStore(Disk()).Read(id.ToUpperInvariant());
        Assert.Equal("line 1\nline 2", kept.Text);
        Assert.Equal("""{"items":[1,2]}""", kept.Record);
        Assert.Equal("list_types", kept.Info.Tool);
        // The side record: arguments canonical with secrets masked, their hash over the unmasked form.
        Assert.Equal("""{"assembly":"app","password":"[redacted]"}""", kept.Info.Arguments);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData("""{"assembly":"app","password":"hunter2"}"""u8)), kept.Info.ArgumentsSha256);
        Assert.Equal(13, kept.Info.Chars);
    }

    [Fact]
    public void An_evicted_ID_says_so_and_names_the_original_call()
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
    public void Memory_only_eviction_also_gives_the_reason()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly) { MemoryLimit = 1_000 };
        var first = store.Keep(new string('a', 700), Origin());
        store.Keep(new string('b', 700), Origin());
        Assert.Equal("evicted", Reason(NotFound(() => store.Read(first))));
    }

    [Fact]
    public void The_size_cap_is_enforced()
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
    public void Entries_unused_past_the_age_limit_are_evicted()
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
    public void A_truncated_entry_is_a_miss()
    {
        var id = new ResultStore(Disk()).Keep("0123456789", Origin());
        File.WriteAllText(Path.Combine(_dir.Path, id + ".txt"), "01234");
        NotFound(() => new ResultStore(Disk()).Read(id));
        // Keeping it again repairs the entry.
        new ResultStore(Disk()).Keep("0123456789", Origin());
        Assert.Equal("0123456789", new ResultStore(Disk()).Read(id).Text);
    }

    [Fact]
    public void Off_keeps_results_in_memory_only()
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
    public void Read_result_pages_by_tokens_at_line_ends()
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
    public void Read_result_searches_lines_with_offsets()
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
    public void Read_result_writes_the_exact_bytes_to_output_path()
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

    [Fact]
    public void Read_result_writes_one_timesketch_event_per_zoned_timestamp()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin("list_resources"), record:
            """{"items":[{"name":"a.bin","size":3,"created":"2024-01-02T03:04:05Z","modified":"2024-01-02T05:04:05+02:00","seen":"2024-01-02T03:04:05"},{"name":"b.bin"}]}""");
        var tools = Tools(store);
        var path = _dir.File("t.jsonl");
        var answer = tools.ReadKept(id, format: "timesketch", outputPath: path);
        Assert.Contains("2 event(s) from 2 item(s), 1 time value(s) skipped", answer);
        var lines = File.ReadAllLines(path);
        Assert.Equal(2, lines.Length);
        var first = JsonDocument.Parse(lines[0]).RootElement;
        Assert.Equal("2024-01-02T03:04:05.000000+00:00", first.GetProperty("datetime").GetString());
        Assert.Equal("created", first.GetProperty("timestamp_desc").GetString());
        Assert.Equal("created: a.bin", first.GetProperty("message").GetString());
        Assert.Equal("corvus:list_resources", first.GetProperty("data_type").GetString());
        Assert.Equal(3, first.GetProperty("size").GetInt32());
        Assert.False(first.TryGetProperty("seen", out _));
        Assert.Equal("2024-01-02T03:04:05.000000+00:00", JsonDocument.Parse(lines[1]).RootElement.GetProperty("datetime").GetString());
    }

    [Fact]
    public void Read_result_timesketch_page_reports_skipped_time_values()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record: """{"items":[{"name":"a","t":"2024-01-02T03:04:05Z","u":"2024-01-02T03:04:05"}]}""");
        Assert.Contains("1 time value(s) skipped", Tools(store).ReadKept(id, format: "timesketch"));
    }

    [Fact]
    public void Read_result_timesketch_skips_pre_epoch_and_malformed_and_keeps_fractions()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record: """
            {"items":[{"name":"a","a":"1970-01-01T00:30:00+01:00","b":"2024-13-45T00:00:00Z","c":"1960-01-01T00:00:00Z","d":"2024-01-02T03:04:05.25Z","datetime":"x","message":"y"}]}
            """);
        var path = _dir.File("p.jsonl");
        Assert.Contains("1 event(s) from 1 item(s), 3 time value(s) skipped", Tools(store).ReadKept(id, format: "timesketch", outputPath: path));
        var e = JsonDocument.Parse(File.ReadAllLines(path).Single()).RootElement;
        Assert.Equal("2024-01-02T03:04:05.250000+00:00", e.GetProperty("datetime").GetString());
        Assert.Equal("d: a", e.GetProperty("message").GetString());
    }

    [Fact]
    public void Read_result_timesketch_refusal_names_skipped_values()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record: """{"items":[{"name":"a","t":"2024-01-02T03:04:05"}]}""");
        var e = Assert.Throws<ToolError>(() => Tools(store).ReadKept(id, format: "timesketch"));
        Assert.Contains("; 1 time value(s) without a zone or out of range were skipped.", e.Message);
    }

    [Fact]
    public void Read_result_timesketch_names_a_result_without_timestamps()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record: """{"items":[{"name":"a"},{"name":"b"}]}""");
        var e = Assert.Throws<ToolError>(() => Tools(store).ReadKept(id, format: "timesketch"));
        Assert.Equal(ErrorCode.NotFound, e.Code);
        Assert.Contains("no UTC timestamps in 2 item(s)", e.Message);
        var textOnly = store.Keep("plain", Origin());
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => Tools(store).ReadKept(textOnly, format: "timesketch")).Code);
    }

    [Fact]
    public void Read_result_timesketch_names_nested_times_by_their_dotted_path()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record:
            """{"items":[{"path":"a/b.bin","times":{"created":"2024-01-02T03:04:05Z","written":["2024-01-03T03:04:05Z"]}},{"x":"2024-01-04T00:00:00Z"}]}""");
        var path = _dir.File("n.jsonl");
        Assert.Contains("3 event(s) from 2 item(s)", Tools(store).ReadKept(id, format: "timesketch", outputPath: path));
        var lines = File.ReadAllLines(path).Select(l => JsonDocument.Parse(l).RootElement).ToArray();
        Assert.Equal("times.created", lines[0].GetProperty("timestamp_desc").GetString());
        Assert.Equal("times.written: a/b.bin", lines[1].GetProperty("message").GetString());
        Assert.Equal("x: item 2", lines[2].GetProperty("message").GetString());
    }

    [Fact]
    public void Read_result_timesketch_reads_a_root_array_of_bare_timestamps()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var id = store.Keep("text", Origin(), record: """["2024-01-02T03:04:05Z","2024-01-02T03:04:06"]""");
        var path = _dir.File("r.jsonl");
        Assert.Contains("1 event(s) from 2 item(s), 1 time value(s) skipped", Tools(store).ReadKept(id, format: "timesketch", outputPath: path));
        Assert.Equal("time", JsonDocument.Parse(File.ReadAllLines(path).Single()).RootElement.GetProperty("timestamp_desc").GetString());
    }

    [Fact]
    public void Read_result_timesketch_skips_pre_epoch_values_and_names_empty_results()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var old = store.Keep("text", Origin(), record: """{"items":[{"t":"1960-01-01T00:00:00Z"}]}""");
        Assert.Contains("1 time value(s) without a zone or out of range were skipped.", Assert.Throws<ToolError>(() => Tools(store).ReadKept(old, format: "timesketch")).Message);
        var emptyStore = new ResultStore(ResultCacheOptions.MemoryOnly);
        var empty = emptyStore.Keep("text", Origin(), record: "[]");
        Assert.Contains("no UTC timestamps in 0 item(s).", Assert.Throws<ToolError>(() => Tools(emptyStore).ReadKept(empty, format: "timesketch")).Message);
    }

    [Fact]
    [FuzzEntry(typeof(Corvus.Tools.TimesketchJsonl))]
    public void Fuzzed_timesketch_records_never_throw_unexpectedly()
    {
        byte[] seed = System.Text.Encoding.UTF8.GetBytes("""{"items":[{"name":"a","t":{"c":"2024-01-02T03:04:05.5Z","d":["1960-01-01T00:00:00Z"]},"n":3}]}""");
        var failures = FormatFuzz.Run(seed, b =>
        {
            try { Corvus.Tools.TimesketchJsonl.From("t", System.Text.Encoding.UTF8.GetString(b)); }
            catch (JsonException) { }
        }, 300);
        Assert.True(failures.Count == 0, string.Join('\n', failures.Take(20)));
    }

    /// <summary>uninstall keeps the default results folder (and names it) unless --purge-data, which removes it.</summary>
    [Fact]
    public void Uninstall_purge_removes_kept_results()
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
    public async Task Results_are_readable_from_another_process()
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
