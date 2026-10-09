using System.Diagnostics;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Tests;

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

    [WindowsFact]
    public void Job_close_kills_the_whole_tree()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var child = ChildProcess.Start(new ChildProcessStart(cmd, ["/d", "/c", "ping -n 30 127.0.0.1 >nul"]));
        IReadOnlyList<int> tree = [];
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(5) && (tree = child.TreeProcessIds()).Count < 2) Thread.Sleep(10);
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

    private static Process? TryOpen(int pid)
    {
        try { return Process.GetProcessById(pid); }
        catch (ArgumentException) { return null; }
    }
}

/// <summary>A fact that only runs on Windows.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only.";
    }
}
