using System.Diagnostics;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary>Provider plumbing that needs no IDA: framing, install detection, the analysis cache and process ownership.</summary>
public class NativeProviderTests
{
    [Fact]
    public void Requests_are_one_line_and_escape_line_breaks()
    {
        var line = WorkerProtocol.EncodeRequest(7, "set_comment", new JsonObject { ["text"] = "a\nb\r\u2028c \"q\"" });
        Assert.EndsWith("\n", line);
        Assert.Equal(1, line.Count(c => c == '\n'));
        Assert.DoesNotContain('\r', line);
        var parsed = JsonNode.Parse(line)!;
        Assert.Equal(7, (long)parsed["id"]!);
        Assert.Equal("a\nb\r\u2028c \"q\"", (string)parsed["args"]!["text"]!);
    }

    [Fact]
    public void Worker_lines_parse_into_responses_events_and_noise()
    {
        var ok = Assert.IsType<WorkerMessage.Response>(WorkerProtocol.Parse("{\"id\":3,\"ok\":true,\"result\":[1,2]}\r"));
        Assert.True(ok.Ok);
        Assert.Equal(3, ok.Id);
        Assert.Equal(2, ok.Result.GetArrayLength());

        var err = Assert.IsType<WorkerMessage.Response>(WorkerProtocol.Parse("{\"id\":4,\"ok\":false,\"error\":{\"code\":\"not_found\",\"message\":\"no function\"}}"));
        Assert.False(err.Ok);
        Assert.Equal(ErrorCode.NotFound, WorkerProtocol.MapCode(err.ErrorCode));
        Assert.Equal("no function", err.ErrorMessage);

        var bare = Assert.IsType<WorkerMessage.Response>(WorkerProtocol.Parse("{\"id\":5,\"ok\":false}"));
        Assert.Equal(ErrorCode.Failed, WorkerProtocol.MapCode(bare.ErrorCode));

        var ev = Assert.IsType<WorkerMessage.Event>(WorkerProtocol.Parse("{\"event\":\"progress\",\"elapsed\":2.0}"));
        Assert.Equal("progress", ev.Name);

        foreach (var noise in new[] { "", "Loading processor module...", "[1,2]", "{\"id\":1}", "{broken", "{\"ok\":\"yes\"}" })
            Assert.IsType<WorkerMessage.Noise>(WorkerProtocol.Parse(noise));

        Assert.Equal(ErrorCode.ProviderUnavailable, WorkerProtocol.MapCode("provider_unavailable"));
        Assert.Equal(ErrorCode.Failed, WorkerProtocol.MapCode("no_such_code"));
    }

    [Fact]
    public void Text_tail_keeps_the_end()
    {
        var tail = new TextTail(10);
        tail.Append("0123456789");
        tail.Append("abc\ndef\n");
        Assert.Equal("89abc\ndef\n", tail.Text);
        Assert.Equal("def", tail.LastLines(1));
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("", "\"\"")]
    [InlineData("a b", "\"a b\"")]
    [InlineData("say \"hi\"", "\"say \\\"hi\\\"\"")]
    [InlineData(@"C:\dir with space\", "\"C:\\dir with space\\\\\"")]
    [InlineData(@"a\\b", @"a\\b")]
    public void Arguments_are_quoted_for_CommandLineToArgvW(string arg, string expected) =>
        Assert.Equal(expected, ChildProcess.QuoteArgument(arg));

    [Fact]
    public void Install_detection_reports_what_is_missing()
    {
        using var tmp = new TempDir();
        Assert.Null(IdaInstallation.Locate(tmp.File("absent"), out var reason, out var fix));
        Assert.Contains("does not exist", reason);
        Assert.Contains(IdaInstallation.DirectoryVariable, fix);

        Assert.Null(IdaInstallation.Locate(tmp.Path, out reason, out fix));
        Assert.Contains("no idalib", reason);

        File.WriteAllText(tmp.File(IdaInstallation.LibraryFileName), "");
        Directory.CreateDirectory(Path.Combine(tmp.Path, "idalib", "python", "idapro"));
        File.WriteAllText(Path.Combine(tmp.Path, "idalib", "python", "idapro", "__init__.py"), "");
        var found = IdaInstallation.Locate(tmp.Path, out _, out _);
        Assert.NotNull(found);
        Assert.Equal(Path.GetFullPath(tmp.Path), found.Directory);
        Assert.Equal("configured", found.Source);

        using var provider = new IdaProvider(new IdaProviderOptions { InstallDirectory = tmp.File("absent"), CacheRoot = tmp.File("cache") });
        var availability = provider.CheckAvailability();
        Assert.False(availability.IsAvailable);
        Assert.Equal("ida", availability.ProviderId);
        Assert.NotNull(availability.Remediation);
        var error = Assert.Throws<ToolError>(() => provider.OpenAsync(Env.FixturePath).GetAwaiter().GetResult());
        Assert.Equal(ErrorCode.ProviderUnavailable, error.Code);
    }

    [Fact]
    public void Cache_copies_verifies_and_locks()
    {
        using var tmp = new TempDir();
        var cache = new AnalysisCache(tmp.File("cache"));
        var input = tmp.File("sample.bin");
        File.WriteAllBytes(input, [1, 2, 3, 4, 5]);
        var sha = AnalysisCache.HashFile(input);

        using (var entry = cache.Acquire("test", input, null))
        {
            Assert.Equal(sha, entry.Sha256);
            Assert.NotEqual(Path.GetFullPath(input), entry.InputCopy);
            Assert.Equal(File.ReadAllBytes(input), File.ReadAllBytes(entry.InputCopy));
            Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => cache.Acquire("test", input, sha)).Code);
        }

        // A damaged private copy is replaced from the source.
        using (var entry = cache.Acquire("test", input, sha.ToUpperInvariant()))
            File.WriteAllBytes(entry.InputCopy, [9]);
        using (var entry = cache.Acquire("test", input, sha))
            Assert.Equal(File.ReadAllBytes(input), File.ReadAllBytes(entry.InputCopy));

        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => cache.Acquire("test", input, new string('a', 64))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => cache.Acquire("test", input, "xyz")).Code);
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => cache.Acquire("test", tmp.File("missing.bin"), null)).Code);
    }

    [Fact]
    public void Short_keyed_cache_migrates_full_hash_entries_and_moves_past_collisions()
    {
        using var tmp = new TempDir();
        var cache = new AnalysisCache(tmp.File("cache")) { ShortKeys = true };
        var input = tmp.File(new string('n', 70) + ".dll");
        File.WriteAllBytes(input, [1, 2, 3, 4, 5]);
        var sha = AnalysisCache.HashFile(input);

        // an entry of the full-hash layout is moved to the short key with its database
        var legacy = Path.Combine(cache.Root, "test", sha);
        Directory.CreateDirectory(Path.Combine(legacy, "input"));
        File.WriteAllText(Path.Combine(legacy, "db.i64"), "saved");
        using (var entry = cache.Acquire("test", input, null))
        {
            Assert.Equal(Path.Combine(cache.Root, "test", sha[..16]), entry.Directory);
            Assert.Equal("saved", File.ReadAllText(Path.Combine(entry.Directory, "db.i64")));
            Assert.Equal(AnalysisCache.ShortNameLength, Path.GetFileName(entry.InputCopy).Length);
            Assert.EndsWith(".dll", entry.InputCopy);
            Assert.False(Directory.Exists(legacy));
            Assert.Equal(entry.Directory, cache.Find("test", sha));
        }

        // another input's entry under the same prefix: the key gets longer
        var other = tmp.File("other.bin");
        File.WriteAllBytes(other, [9]);
        var otherSha = AnalysisCache.HashFile(other);
        var taken = Path.Combine(cache.Root, "test", otherSha[..16]);
        Directory.CreateDirectory(taken);
        File.WriteAllText(Path.Combine(taken, AnalysisCache.KeyFile), new string('0', 64));
        using (var entry = cache.Acquire("test", other, null))
        {
            Assert.Equal(Path.Combine(cache.Root, "test", otherSha[..32]), entry.Directory);
            Assert.Equal(entry.Directory, cache.Find("test", otherSha));
        }
        Assert.Null(cache.Find("test", new string('f', 64)));
        // without short keys the full hash stays the key
        using var plain = new AnalysisCache(cache.Root).Acquire("plain", input, null);
        Assert.Equal(Path.Combine(cache.Root, "plain", sha), plain.Directory);
    }

    [Fact]
    public void IDA_paths_over_the_Windows_limit_fail_with_their_length_and_the_folder_to_change()
    {
        var root = "C:\\" + new string('r', 150);
        var path = Path.Combine(root, "ida", new string('0', 16), "input", new string('n', 100) + ".dll");
        Corvus.Native.Providers.Ida.IdaProvider.CheckPathLength(path, "input copy", root, windows: false);
        var e = Assert.Throws<ToolError>(() => Corvus.Native.Providers.Ida.IdaProvider.CheckPathLength(path, "input copy", root, windows: true));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains($"{path.Length} characters", e.Message);
        Assert.Contains("CORVUS_DATA_DIR", e.Remediation);
        Assert.Contains($"at most {259 - (path.Length - root.Length)} characters", e.Remediation);
        Assert.DoesNotContain("licen", e.Remediation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("259 characters", Corvus.Native.Providers.Ida.IdaProvider.Remediation(ErrorCode.ProviderUnavailable, "open_database returned 2 for x"));
    }

    [Fact]
    public void IDA_before_9_is_refused_by_the_version_its_worker_reports()
    {
        using var provider = new Corvus.Native.Providers.Ida.IdaProvider();
        static System.Text.Json.JsonElement Hello(string v) => System.Text.Json.JsonDocument.Parse($$"""{"version":"{{v}}"}""").RootElement.Clone();
        var e = Assert.Throws<ToolError>(() => provider.CheckVersion(Hello("8.4.0")));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("9.0 or newer", e.Message);
        provider.CheckVersion(Hello("9.3.0"));
        Assert.Equal("9.3.0", provider.Version);
    }

    [Fact]
    public void A_locked_entry_names_its_owner_and_can_be_snapshotted()
    {
        using var tmp = new TempDir();
        var cache = new AnalysisCache(tmp.File("cache"));
        var input = tmp.File("sample.bin");
        File.WriteAllBytes(input, [1, 2, 3, 4, 5]);
        string snapshotDir;
        using (var entry = cache.Acquire("test", input, null))
        {
            File.WriteAllText(Path.Combine(entry.Directory, "db.i64"), "saved");
            // as if another server process held it
            File.WriteAllText(Path.Combine(entry.Directory, ".owner"), "4242");
            var e = Assert.Throws<ToolError>(() => cache.Acquire("test", input, null));
            Assert.Equal(ErrorCode.Conflict, e.Code);
            Assert.Contains("process 4242", e.Message);

            using var snapshot = cache.Acquire("test", input, null, (locked, sha) =>
                cache.Snapshot("test", locked, sha, input, [Path.Combine(locked.Directory, "db.i64")]));
            Assert.Equal(4242, snapshot.SnapshotOf);
            Assert.NotEqual(entry.Directory, snapshot.Directory);
            Assert.Equal("saved", File.ReadAllText(Path.Combine(snapshot.Directory, "db.i64")));
            Assert.Equal(File.ReadAllBytes(input), File.ReadAllBytes(snapshot.InputCopy));
            snapshotDir = snapshot.Directory;
        }
        Assert.False(Directory.Exists(snapshotDir));
    }

    [WindowsFact]
    public void Job_close_kills_the_whole_tree()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var child = ChildProcess.Start(new ChildProcessStart(cmd, ["/d", "/c", "ping -n 30 127.0.0.1 >nul"]));
        IReadOnlyList<int> tree = [];
        var clock = Stopwatch.StartNew();
        // cmd starts ping whenever it gets scheduled: wait for that (the minute only guards against a hang).
        while ((tree = child.TreeProcessIds()).Count < 2 && !child.HasExited && clock.Elapsed < TimeSpan.FromMinutes(1)) Thread.Sleep(10);
        Assert.True(tree.Count >= 2, $"expected cmd and ping in the job, saw {tree.Count}");
        Assert.Contains(child.Id, tree);
        Assert.False(child.HasExited);

        var handles = tree.Select(TryOpen).Where(p => p != null).ToList();
        child.Dispose();
        foreach (var p in handles)
            Assert.True(p!.WaitForExit(5000), $"process {p.Id} survived the job close");
        Assert.True(child.Exited.Wait(5000));
    }

    [WindowsFact]
    public void A_process_started_meanwhile_does_not_inherit_the_pipes()
    {
        Assert.NotNull(typeof(Process).GetField("s_createProcessLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static));
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        Process? other = null;
        WindowsJobProcess.PipesCreated = start =>
        {
            if (!start.Arguments.Contains("echo sample-pipes")) return;
            // Process.Start on another thread while our child ends are inheritable: it either waits for them to close
            // (blocked on the shared lock) or starts at once and inherits them.
            var starter = new Thread(() => other = Process.Start(new ProcessStartInfo(cmd, "/d /c ping -n 30 127.0.0.1 >nul") { UseShellExecute = false, CreateNoWindow = true }));
            starter.Start();
            while ((starter.ThreadState & (System.Threading.ThreadState.WaitSleepJoin | System.Threading.ThreadState.Stopped)) == 0) Thread.Sleep(1);
        };
        try
        {
            // With the long-lived process holding the write end, the output never ends and the run comes back empty.
            var run = PythonLocator.RunCapture(cmd, ["/d", "/c", "echo sample-pipes"], TimeSpan.FromSeconds(30));
            Assert.Equal("sample-pipes", run.Stdout.Trim());
        }
        finally
        {
            WindowsJobProcess.PipesCreated = null;
            for (var clock = Stopwatch.StartNew(); other == null && clock.Elapsed < TimeSpan.FromMinutes(1);) Thread.Sleep(10);
            try { other?.Kill(); } catch (InvalidOperationException) { }
            other?.Dispose();
        }
    }

    [WindowsFact]
    public void Job_process_reports_exit_code_and_output()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var run = PythonLocator.RunCapture(cmd, ["/d", "/c", "echo out& echo err 1>&2& exit 3"], TimeSpan.FromSeconds(10));
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Stdout.Trim());
        Assert.Equal("err", run.Stderr.Trim());

        var missing = PythonLocator.RunCapture(Path.Combine(Environment.SystemDirectory, "no-such-program.exe"), [], TimeSpan.FromSeconds(5));
        Assert.NotNull(missing.StartError);
    }

    [WindowsFact]
    public void Job_memory_limit_fails_allocations_past_it_and_is_reported()
    {
        var python = PythonLocator.Find([], []);
        if (python == null) return;
        var limit = 256L << 20;
        using var capped = ChildProcess.Start(new ChildProcessStart(python.Executable, ["-I", "-c", "b = bytearray(1 << 30)"]) { MemoryLimitBytes = limit });
        Assert.True(capped.Exited.Wait(30_000));
        Assert.NotEqual(0, capped.ExitCode);
        Assert.Equal(limit, capped.MemoryLimitReached());

        using var within = ChildProcess.Start(new ChildProcessStart(python.Executable, ["-I", "-c", "b = bytearray(16 << 20)"]) { MemoryLimitBytes = limit });
        Assert.True(within.Exited.Wait(30_000));
        Assert.Equal(0, within.ExitCode);
        Assert.Null(within.MemoryLimitReached());
    }

    [Theory]
    [InlineData(null, 0x1_0000_0000L, 0xC000_0000L)]
    [InlineData("", 0x1_0000_0000L, 0xC000_0000L)]
    [InlineData("2048", 0x1_0000_0000L, 2048L << 20)]
    [InlineData("0", 0x1_0000_0000L, null)]
    [InlineData("off", 0x1_0000_0000L, null)]
    [InlineData("lots", 0x1_0000_0000L, 0xC000_0000L)]
    public void Engine_memory_limit_parses_the_setting(string? value, long available, long? expected) =>
        Assert.Equal(expected, EngineMemoryLimit.Parse(value, available));

    private static Process? TryOpen(int pid)
    {
        try { return Process.GetProcessById(pid); }
        catch (ArgumentException) { return null; }
    }
}
