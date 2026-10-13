using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Engine output across server processes: the same call answers byte for byte the same in both parts whether the
/// engine analyzed the image in this process or loaded the saved analysis (open times, saved-analysis state and push
/// banners are in _meta only).
/// </summary>
public sealed class EngineOutputTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private static string Image => NativeIdaProviderTests.System64;

    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeAnalysisTools Analysis, NativeEngineService Engines);

    /// <summary>One server process: its own workspace and engine sessions over a shared analysis cache and annotation store.</summary>
    private Rig Server()
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush(), new NativeUserTypePush(code)), engines);
    }

    private static async Task<(string Text, string Record, OutputCall Call)> Decompile(Rig rig, string image)
    {
        var (text, call) = await EngineMeta.Run(() => rig.Analysis.DecompileNative(image, Function));
        return (text, ToolOutput.Serialize(call.Record!)!.ToJsonString(), call);
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Decompile_is_byte_identical_in_a_second_process()
    {
        var first = Server();
        var a = await Decompile(first, Image);
        output.WriteLine(a.Text);
        Assert.False((bool)first.Engines.ImageSessions(first.Workspace.Read(() => first.Workspace.Natives[0]))[0].Session!.ReusedDatabase);
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();

        var second = Server();
        var b = await Decompile(second, Image);
        Assert.True(second.Engines.ImageSessions(second.Workspace.Read(() => second.Workspace.Natives[0]))[0].Session!.ReusedDatabase);
        Assert.Equal(a.Text, b.Text);
        Assert.Equal(a.Record, b.Record);
        Assert.DoesNotContain("\r", a.Text);
        Assert.DoesNotContain("analyzed in", a.Text);
        // the details that differ are in _meta
        Assert.Equal(false, a.Call.EngineMeta["savedAnalysis"]);
        Assert.Equal(true, b.Call.EngineMeta["savedAnalysis"]);
        Assert.Equal("complete", b.Call.EngineMeta["analysis"]);
        Assert.NotNull(b.Call.EngineMeta["engineBuild"]);
    }

    private void Close()
    {
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
    }

    private static LoadedNative NativeOf(Rig rig) => rig.Workspace.Read(() => rig.Workspace.Natives[0]);

    /// <summary>
    /// The persistent engine output (EL-1): a later process answers from the stored pseudocode and frame without starting
    /// IDA; a rename (another push), a reanalysis and a script each make later answers come from the engine again.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task A_later_process_answers_from_the_output_cache_until_something_changes()
    {
        var first = Server();
        var cold = await Decompile(first, Image);
        var frameTools = new NativeTypeTools(first.Workspace, first.Engines, new NativeUserTypePush(first.Code), first.Code, new NativeNamePush(first.Code), new NativeTypePush());
        var frame = await frameTools.GetNativeFrame(Image, Function, locals: true);
        Close();

        // a second process: no engine session is opened, the answers are byte-identical
        var second = Server();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var warm = await Decompile(second, Image);
        output.WriteLine($"second process: {clock.Elapsed.TotalMilliseconds:0} ms without opening IDA");
        Assert.Equal(cold.Text, warm.Text);
        Assert.Equal(cold.Record, warm.Record);
        Assert.Empty(second.Engines.ImageSessions(NativeOf(second)));
        Assert.NotNull(warm.Call.EngineMeta["outputCache"]);
        var frameAgain = await new NativeTypeTools(second.Workspace, second.Engines, new NativeUserTypePush(second.Code), second.Code, new NativeNamePush(second.Code),
            new NativeTypePush()).GetNativeFrame(Image, Function, locals: true);
        Assert.Equal(frame, frameAgain);
        Assert.Empty(second.Engines.ImageSessions(NativeOf(second)));

        // a rename changes what is pushed: the engine answers, with the new name
        var native = NativeOf(second);
        var start = native.Image.Exports.First(e => e.Name == Function).Rva;
        new NativeEditService(second.Workspace, second.Code).Rename(native, second.Code.Ready(native) ?? await second.Code.Index(native, null, default), start, "corvus_renamed", false);
        var renamed = await Decompile(second, native.Id);
        Assert.Contains("corvus_renamed", renamed.Text);
        Assert.NotEmpty(second.Engines.ImageSessions(native));

        // in the open session: a repeat is the output cache's; after a reanalysis or a script the engine answers again
        var session = (WorkerSessionBase)second.Engines.OpenSession(native)!;
        var cache = second.Engines.OutputCache!;
        var decompiled = await ((INativeDecompilerSession)session).DecompileAsync(start);
        int hits = cache.Hits;
        Assert.Equal(decompiled.Text, (await ((INativeDecompilerSession)session).DecompileAsync(start)).Text);
        Assert.Equal(hits + 1, cache.Hits);
        var before = session.DatabaseState;
        await EngineControl.Require((INativeDecompilerSession)session, "reanalysis").ReanalyzeAsync([], start, start + 0x10, 60);
        Assert.NotEqual(before, session.DatabaseState);
        hits = cache.Hits;
        await ((INativeDecompilerSession)session).DecompileAsync(start);
        Assert.Equal(hits, cache.Hits);
        Close();

        // the third process starts from the state the second one saved
        var third = Server();
        var again = await Decompile(third, Image);
        Assert.Contains("corvus_renamed", again.Text);
    }

    /// <summary>The largest function of e_sqlite3 (the slowest decompile measured): a second fresh process answers within a second, byte-identical.</summary>
    [Trait("Speed", "Slow")]
    [Trait("Data", "Real")]
    [IdaFact]
    public async Task The_largest_e_sqlite3_function_decompiles_once_across_processes()
    {
        var path = _dir.File("e_sqlite3.dll");
        File.Copy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll"), path);
        var first = Server();
        first.Workspace.LoadAny(path);
        var native = NativeOf(first);
        var index = await first.Code.Index(native, null, default);
        var largest = index.Functions.OrderByDescending(f => f.Size).First();
        var address = $"rva:0x{largest.Start:X}";
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var (cold, coldCall) = await EngineMeta.Run(() => first.Analysis.DecompileNative(path, address, timeoutSeconds: 600));
        output.WriteLine($"{index.NameAt(largest.Start)} ({largest.Size} bytes): first process {clock.Elapsed.TotalSeconds:0.0} s");
        Close();

        var second = Server();
        clock.Restart();
        var (warm, warmCall) = await EngineMeta.Run(() => second.Analysis.DecompileNative(path, address, timeoutSeconds: 600));
        output.WriteLine($"second process {clock.Elapsed.TotalMilliseconds:0} ms");
        Assert.Equal(cold, warm);
        Assert.Equal(ToolOutput.Serialize(coldCall.Record!)!.ToJsonString(), ToolOutput.Serialize(warmCall.Record!)!.ToJsonString());
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"{clock.Elapsed.TotalMilliseconds:0} ms");
    }

    /// <summary>A truncated saved database is analyzed again (EL-12), the call says so, and no stored answer of the old database is served.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task A_truncated_saved_database_is_analyzed_again()
    {
        var first = Server();
        var before = await Decompile(first, Image);
        Close();
        var database = Directory.EnumerateFiles(_dir.File("cache"), "*.i64", SearchOption.AllDirectories).Single();
        using (var f = new FileStream(database, FileMode.Open)) f.SetLength(f.Length / 2);

        var second = Server();
        var after = await Decompile(second, Image);
        Assert.Equal(before.Text, after.Text);
        Assert.Contains(after.Call.Warnings, w => w.Contains("analyzed again", StringComparison.Ordinal));
        Assert.False(second.Engines.ImageSessions(NativeOf(second))[0].Session!.ReusedDatabase);
    }

    /// <summary>
    /// Through the server: a decompile page carries its code and continuation in the record (G1-11) and names the engine with
    /// its build in _meta; a script printing 1 MB answers within the report budget with a resultId; a script exception is an error.
    /// </summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Engine_results_page_in_both_parts_and_script_failures_are_errors()
    {
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions { BackgroundIndexing = false, WatchFiles = false, IdaScripting = true });
        async Task<ModelContextProtocol.Protocol.CallToolResult> Call(string tool, Dictionary<string, object?> args) => await server.Client.CallToolAsync(tool, args);
        static string Text(ModelContextProtocol.Protocol.CallToolResult r) => string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));

        var page = await Call("decompile_native", new() { ["image"] = Image, ["address"] = Function, ["maxTokens"] = 500 });
        Assert.True(page.IsError != true, Text(page));
        var record = page.StructuredContent!.Value;
        Assert.Equal("ida", record.GetProperty("engine").GetString());
        Assert.True(record.TryGetProperty("engineNote", out _));
        var code = record.GetProperty("code").GetString()!;
        int next = record.GetProperty("nextOffset").GetInt32();
        Assert.True(code.Length > 0 && next > 0 && record.GetProperty("totalChars").GetInt32() > next);
        var provenance = page.Meta![ToolOutput.ProvenanceKey]!;
        Assert.Equal("ida", (string?)provenance["engine"]);
        Assert.NotNull(provenance["engineBuild"]);
        var second = await Call("decompile_native", new() { ["image"] = Image, ["address"] = Function, ["maxTokens"] = 500, ["offset"] = next });
        Assert.Equal(next, second.StructuredContent!.Value.GetProperty("offset").GetInt32());

        var big = await Call("ida_python", new() { ["image"] = Image, ["code"] = "print('x' * 1000000)" });
        Assert.True(big.IsError != true, Text(big)[..Math.Min(500, Text(big).Length)]);
        Assert.InRange(TokenEstimate.Of(Text(big)), 1, 4_200);
        Assert.StartsWith("r-", big.StructuredContent!.Value.GetProperty("resultId").GetString());

        var failed = await Call("ida_python", new() { ["image"] = Image, ["code"] = "raise ValueError('corvus boom')" });
        Assert.True(failed.IsError);
        Assert.Contains("corvus boom", Text(failed));
        var allowed = await Call("ida_python", new() { ["image"] = Image, ["code"] = "raise ValueError('corvus boom')", ["allowError"] = true });
        Assert.True(allowed.IsError != true);
        Assert.Contains("corvus boom", allowed.StructuredContent!.Value.GetProperty("error").GetString());
    }

    [Fact]
    public void A_damaged_entry_is_a_miss()
    {
        var cache = new EngineOutputCache(_dir.File("cache-unit"));
        var key = EngineOutputCache.Key("k");
        cache.Put(key, "{\"a\":1}");
        Assert.Equal("{\"a\":1}", cache.Get(key));
        var file = Directory.GetFiles(cache.Root, "*.json", SearchOption.AllDirectories).Single();
        File.WriteAllText(file, File.ReadAllText(file)[..^3]);
        Assert.Null(cache.Get(key));
        Assert.Null(cache.Get(EngineOutputCache.Key("other")));
    }

    [Fact]
    public void A_saved_state_holds_only_while_the_database_is_unchanged()
    {
        var db = _dir.File("db.i64");
        File.WriteAllBytes(db, [1, 2, 3]);
        EngineOutputCache.WriteState(db, "s1");
        Assert.Equal("s1", EngineOutputCache.ReadState(db));
        File.WriteAllBytes(db, [1, 2, 3, 4]);
        Assert.Null(EngineOutputCache.ReadState(db));
        var project = Directory.CreateDirectory(_dir.File("p-1")).FullName;
        File.WriteAllBytes(Path.Combine(project, "corvus.gpr"), [0]);
        EngineOutputCache.WriteState(project, "s2");
        File.WriteAllBytes(Path.Combine(project, "corvus.lock"), [0]); // lock files are no change
        Assert.Equal("s2", EngineOutputCache.ReadState(project));
        File.WriteAllBytes(Path.Combine(project, "corvus.gpr"), [0, 1]);
        Assert.Null(EngineOutputCache.ReadState(project));
    }

    [Fact]
    public void The_cache_keeps_the_most_recently_used_entries_within_its_bound()
    {
        var cache = new EngineOutputCache(_dir.File("cache-bound"), maxBytes: 300);
        var keys = Enumerable.Range(0, 6).Select(i => EngineOutputCache.Key(i)).ToList();
        foreach (var k in keys)
        {
            cache.Put(k, new string('x', 100));
            File.SetLastWriteTimeUtc(Directory.GetFiles(cache.Root, k + ".json", SearchOption.AllDirectories).Single(), DateTime.UtcNow.AddMinutes(keys.IndexOf(k) - 10));
        }
        cache.Evict();
        Assert.Null(cache.Get(keys[0]));
        Assert.NotNull(cache.Get(keys[^1]));
        Assert.True(cache.Size().Bytes <= 300);
    }
}
