using System.Diagnostics;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Provider plumbing that needs no IDA: framing, install detection, the analysis cache and process ownership.</summary>
public class NativeProviderTests(ITestOutputHelper output)
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
    public void The_same_arguments_encode_into_a_second_request()
    {
        // Regression: a pool retry after a worker was stopped for another request failed with "The node already has a parent".
        var args = new JsonObject { ["path"] = "a.zip" };
        WorkerProtocol.EncodeRequest(1, "file_summarize", args);
        Assert.Equal("a.zip", (string)JsonNode.Parse(WorkerProtocol.EncodeRequest(2, "file_summarize", args))!["args"]!["path"]!);
        Assert.Null(args.Parent);
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
    public void A_function_Hex_Rays_cannot_decompile_names_Ghidra_and_the_disassembly() =>
        Assert.Contains("engine=ghidra", Corvus.Native.Providers.Ida.IdaProvider.Remediation(ErrorCode.Failed, "decompilation failed: function frame is wrong"));

    [Fact]
    public void A_decompiler_the_IDA_license_lacks_names_Ghidra_rather_than_the_license_terms()
    {
        // The worker's message for Hex-Rays MERR_LICENSE, as the test host's IDA 9.3 gave it for a RISC-V file.
        var next = Corvus.Native.Providers.Ida.IdaProvider.Remediation(ErrorCode.Unsupported,
            "the Hex-Rays decompiler for riscv (32-bit) is not licensed on this machine (license not available (HEXRV))");
        Assert.Contains("engine=ghidra", next);
        Assert.DoesNotContain("license terms", next);
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
            Assert.True(e.Retryable && e.RetryAfter > TimeSpan.Zero);

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

    [PosixFact("Needs a POSIX shell.")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void A_posix_child_and_its_children_end_within_a_second_of_the_watched_process()
    {
        using var stand = Process.Start(new ProcessStartInfo("/bin/sleep", "600") { UseShellExecute = false })!;
        using var child = PosixGroupProcess.Launch(new ChildProcessStart("/bin/sh", ["-c", "echo $$; sleep 600 & echo $!; wait"]), stand.Id);
        using var reader = new StreamReader(child.StandardOutput);
        Assert.Equal(child.Id, int.Parse(reader.ReadLine()!)); // the worker's own id, not its shell parent's
        int grandchild = int.Parse(reader.ReadLine()!);
        // also without a controlling terminal (CI, MCP clients), where dash ignores set -m
        if (OperatingSystem.IsLinux()) Assert.Equal(child.Id, ProcessGroup(child.Id));
        Assert.True(Running(grandchild));
        stand.Kill();
        stand.WaitForExit();
        var clock = Stopwatch.StartNew();
        while ((Running(child.Id) || Running(grandchild)) && clock.ElapsedMilliseconds < 5_000) Thread.Sleep(20);
        Assert.False(Running(child.Id) || Running(grandchild), "a process outlived the one it watched");
        PerfBudget.Time("engines/child-tree-end", clock.Elapsed, TimeSpan.FromSeconds(1), output);
        Assert.True(child.Exited.Wait(10_000));
    }

    [PosixFact("Needs a POSIX shell.")]
    public void Kill_ends_a_posix_childs_children()
    {
        using var child = ChildProcess.Start(new ChildProcessStart("/bin/sh", ["-c", "sleep 600 & echo $!; wait"]));
        using var reader = new StreamReader(child.StandardOutput);
        int grandchild = int.Parse(reader.ReadLine()!);
        child.Kill();
        Assert.True(child.Exited.Wait(10_000));
        var clock = Stopwatch.StartNew();
        while (Running(grandchild) && clock.ElapsedMilliseconds < 5_000) Thread.Sleep(20);
        Assert.False(Running(grandchild), "the child's child outlived Kill");
    }

    [Fact]
    public void A_childs_CPU_time_grows_while_it_computes()
    {
        // Half a second of CPU time, then a wait on stdin so the tree is still running when it is read. The fake tool logs
        // each call to the script ADB_FAKE_SCRIPT names, which another class may have set process-wide, so it is unset.
        using var child = ChildProcess.Start(new ChildProcessStart(FakeTool.Executable, ["spin", "500"])
        {
            Environment = new Dictionary<string, string?> { [FakeTool.ScriptVariable] = null },
        });
        using var reader = new StreamReader(child.StandardOutput);
        Assert.Equal("done", reader.ReadLine()?.Trim());
        var cpu = child.TreeCpuTime();
        // Linux reads another process's CPU time from /proc in clock ticks, which can read below the child's own reading.
        Assert.True(cpu >= TimeSpan.FromMilliseconds(400), $"{cpu}");
        child.Kill();
    }

    private static int ProcessGroup(int pid)
    {
        var stat = File.ReadAllText($"/proc/{pid}/stat");
        return int.Parse(stat[(stat.LastIndexOf(')') + 2)..].Split(' ')[2], System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Running, not a zombie waiting for its parent.</summary>
    private static bool Running(int pid)
    {
        if (!OperatingSystem.IsLinux())
        {
            try { using var p = Process.GetProcessById(pid); return !p.HasExited; }
            catch (ArgumentException) { return false; }
        }
        try
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            return stat[(stat.LastIndexOf(')') + 2)..][0] != 'Z';
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    [PosixFact("Needs a POSIX shell.")]
    public void A_posix_child_keeps_stdin_and_reports_its_exit_code()
    {
        using var child = ChildProcess.Start(new ChildProcessStart("/bin/sh", ["-c", "read line; echo \"got $line\"; exit 7"]));
        child.StandardInput.Write("hello\n"u8);
        child.StandardInput.Flush();
        using var reader = new StreamReader(child.StandardOutput);
        Assert.Equal("got hello", reader.ReadLine());
        Assert.True(child.Exited.Wait(10_000));
        Assert.Equal(7, child.ExitCode);
        Assert.Throws<System.ComponentModel.Win32Exception>(() => ChildProcess.Start(new ChildProcessStart("/no/such/program", [])));
    }

    /// <summary>A replaced worker is disposed while the relay and the process list still ask whether it exited.</summary>
    [PosixFact("Needs a POSIX shell.")]
    public void A_disposed_posix_child_still_reports_its_exit()
    {
        var ended = ChildProcess.Start(new ChildProcessStart("/bin/sh", ["-c", "exit 5"]));
        Assert.True(ended.Exited.Wait(10_000));
        ended.Dispose();
        Assert.True(ended.HasExited);
        Assert.Equal(5, ended.ExitCode);
        Assert.Empty(ended.TreeProcessIds());

        var running = ChildProcess.Start(new ChildProcessStart("/bin/sh", ["-c", "sleep 600"]));
        running.Dispose();
        Assert.True(running.HasExited);
        Assert.NotNull(running.ExitCode);
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
    public void A_launch_releases_the_process_creation_lock_before_its_exit_thread_starts()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        bool? held = null;
        WindowsJobProcess.ExitThreadStarting = _ => held ??= Monitor.IsEntered(WindowsJobProcess.CreateLock);
        try
        {
            using var child = WindowsJobProcess.Launch(new ChildProcessStart(cmd, ["/d", "/c", "exit 0"]));
            Assert.True(child.Exited.Wait(30_000));
        }
        finally { WindowsJobProcess.ExitThreadStarting = null; }
        Assert.False(held);
    }

    [WindowsFact]
    public void Job_process_reports_exit_code_and_output()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        // The limit only guards against a hang: a cmd.exe starved by a busy machine took 12 s to start and exit.
        var run = PythonLocator.RunCapture(cmd, ["/d", "/c", "echo out& echo err 1>&2& exit 3"], TimeSpan.FromMinutes(2));
        Assert.False(run.TimedOut);
        Assert.Equal(3, run.ExitCode);
        Assert.Equal("out", run.Stdout.Trim());
        Assert.Equal("err", run.Stderr.Trim());

        var missing = PythonLocator.RunCapture(Path.Combine(Environment.SystemDirectory, "no-such-program.exe"), [], TimeSpan.FromSeconds(5));
        Assert.NotNull(missing.StartError);
    }

    [Fact]
    public void A_capture_past_its_time_limit_ends_the_child_and_says_it_timed_out()
    {
        using var fake = new FakeTool();
        fake.On("slow", sleepMs: 20_000, stdout: "late");
        var run = PythonLocator.RunCapture(FakeTool.Executable, ["slow"], TimeSpan.FromMilliseconds(500), fake.Environment);
        Assert.True(run.TimedOut);
        // The child prints only after its 20 s sleep, so no output means it was ended at the limit.
        Assert.DoesNotContain("late", run.Stdout);
        Assert.NotNull(run.ExitCode);
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
