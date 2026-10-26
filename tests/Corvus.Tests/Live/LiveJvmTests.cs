using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Live.Jdwp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Sessions on a JVM through its JDWP agent: threads and stacks, and stop points at source lines.</summary>
public sealed partial class LiveJvmTests : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly TempDir _dir = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public LiveJvmTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()));
        _tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, _service);
    }

    // A daemon thread calls tick (line 6) every 100 ms while main sleeps.
    private const string App = """
        package sample;

        public class App {
            static int ticks;
            static int tick(int n) {
                ticks += n;
                return ticks;
            }

            public static void main(String[] args) throws Exception {
                Thread t = new Thread(() -> {
                    while (true) {
                        tick(1);
                        try { Thread.sleep(100); } catch (InterruptedException e) { return; }
                    }
                }, "ticker");
                t.setDaemon(true);
                t.start();
                Thread.sleep(600000);
            }
        }
        """;

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    [Theory]
    [InlineData("jdwp:192.168.1.5:8000", "not a loopback address")]
    [InlineData("jdwp:[::ffff:10.0.0.2]:8000", "not a loopback address")]
    [InlineData("jdwp:debug", "is not a port")]
    public void An_agent_off_this_machine_or_without_a_port_is_refused(string program, string reason)
    {
        var e = Assert.Throws<ToolError>(() => JdwpWorker.Endpoint(program));
        Assert.Contains(reason, e.Message);
    }

    [Fact]
    public void A_listening_port_names_the_process_that_listens_on_it()
    {
        if (OperatingSystem.IsMacOS()) return;
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        try { Assert.Equal(Environment.ProcessId, Native.Providers.Live.ListeningProcess.Of(((System.Net.IPEndPoint)listener.LocalEndpoint).Port)); }
        finally { listener.Stop(); }
    }

    /// <summary>
    /// The JVM waits for a debugger (suspend=y): a stop point at App.java:6 is set before App loads, the class prepare
    /// event places it, and the held thread's frames and the main thread's frames in status equal what jstack prints.
    /// </summary>
    [RequiresRealDataFact("CORVUS_JDK")]
    [Trait("Speed", "Slow")]
    public async Task A_point_set_before_its_class_loads_stops_there_and_the_stacks_match_jstack()
    {
        await using var jvm = await Jvm.StartAsync(_dir, suspend: true);
        Assert.Contains("suspended", await _tools.LiveSession("attach", program: "jdwp:" + jvm.Port));
        var set = await _tools.LiveBreak("live-1", "set", at: "App.java:6");
        _output.WriteLine(set);
        Assert.Contains("s1 set at any class from App.java, line 6, once loaded", set);
        Assert.Contains("program started", await _tools.LiveBreak("live-1", "continue"));

        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 60);
        _output.WriteLine(stop);
        Assert.Contains("#0 sample.App.tick App.java:6", stop);
        Assert.Contains("#1 sample.App.lambda$main$0 App.java:13", stop);
        // Main moves from t.start() to its sleep while the ticker is held.
        await Task.Delay(500);

        var status = await _tools.LiveSession("status", session: "live-1");
        _output.WriteLine(status);
        Assert.Contains("1 classes of the program (JDK classes left out) from 1 source file(s):\n  sample/App.java", status.ReplaceLineEndings("\n"));
        var ours = Threads(status);
        var reference = await jvm.JstackAsync();
        foreach (var name in new[] { "ticker", "main" })
        {
            Assert.True(ours.ContainsKey(name) && reference.ContainsKey(name), name);
            Assert.Equal(reference[name], ours[name]);
        }
        Assert.Contains("\"ticker\" running, held at a stop point", status);
        await _tools.LiveSession("close", session: "live-1");
        Assert.False(jvm.HasExited);
    }

    [RequiresRealDataFact("CORVUS_JDK")]
    [Trait("Speed", "Slow")]
    public async Task Native_actions_on_a_jvm_session_are_refused_and_close_leaves_the_program_running()
    {
        await using var jvm = await Jvm.StartAsync(_dir, suspend: false);
        var opened = await _tools.LiveSession("attach", program: "jdwp:" + jvm.Port);
        Assert.Contains($"(jdwp): jdwp:{jvm.Port} pid {jvm.ProcessId}, running", opened);
        var watch = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveWatchCalls("live-1", "set", at: "App.java:6"));
        Assert.Contains("live-1 is a JVM session with classes only", watch.Message);
        var read = await Assert.ThrowsAsync<ToolError>(() => _service.ReadAsync(_service.Get("live-1"), 0x1000, 16, default));
        Assert.Contains("'read' works on native code; a JVM session", read.Message);
        await _tools.LiveSession("close", session: "live-1");
        await Task.Delay(300);
        Assert.False(jvm.HasExited);
    }

    // Per thread name, the frames that carry a line, as Class.method(File:line), from the status text.
    private static Dictionary<string, List<string>> Threads(string status)
    {
        var threads = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        List<string>? current = null;
        foreach (var line in status.ReplaceLineEndings("\n").Split('\n'))
        {
            if (ThreadHeader().Match(line) is { Success: true } h) threads[h.Groups["name"].Value] = current = [];
            else if (current != null && OurFrame().Match(line) is { Success: true } f) current.Add($"{f.Groups["function"].Value}({f.Groups["file"].Value}:{f.Groups["line"].Value})");
        }
        return threads;
    }

    [GeneratedRegex("""^  thread \d+ "(?<name>[^"]*)" """)]
    private static partial Regex ThreadHeader();

    [GeneratedRegex(@"^    #\d+ (?<function>\S+) (?<file>[^\s:]+):(?<line>\d+)$")]
    private static partial Regex OurFrame();

    /// <summary>A JVM running sample.App under its JDWP agent on a free loopback port, compiled from <see cref="App"/>.</summary>
    private sealed partial class Jvm : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly string _bin;

        private Jvm(Process process, string bin, int port) => (_process, _bin, Port) = (process, bin, port);

        public int Port { get; }
        public int ProcessId => _process.Id;
        public bool HasExited => _process.HasExited;

        public static async Task<Jvm> StartAsync(TempDir dir, bool suspend)
        {
            var bin = Path.Combine(Environment.GetEnvironmentVariable("CORVUS_JDK")!, "bin");
            var source = Path.Combine(dir.Path, "src", "sample", "App.java");
            Directory.CreateDirectory(Path.GetDirectoryName(source)!);
            File.WriteAllText(source, App);
            var classes = Path.Combine(dir.Path, "classes");
            await Run(Path.Combine(bin, "javac"), "-g", "-d", classes, source);

            var info = new ProcessStartInfo(Path.Combine(bin, "java")) { RedirectStandardOutput = true, UseShellExecute = false };
            foreach (var a in new[] { $"-agentlib:jdwp=transport=dt_socket,server=y,suspend={(suspend ? "y" : "n")},address=127.0.0.1:0", "-cp", classes, "sample.App" })
                info.ArgumentList.Add(a);
            var process = Process.Start(info)!;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (await process.StandardOutput.ReadLineAsync(cts.Token) is { } line)
                if (Listening().Match(line) is { Success: true } m) return new Jvm(process, bin, int.Parse(m.Groups[1].Value));
            process.Kill();
            throw new InvalidOperationException("java wrote no JDWP port");
        }

        /// <summary>Per thread name, jstack's frames that carry a line, as Class.method(File:line).</summary>
        public async Task<Dictionary<string, List<string>>> JstackAsync()
        {
            var text = await Run(Path.Combine(_bin, "jstack"), _process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var threads = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            List<string>? current = null;
            foreach (var line in text.ReplaceLineEndings("\n").Split('\n'))
            {
                if (line.StartsWith('"')) threads[line[1..line.IndexOf('"', 1)]] = current = [];
                else if (current != null && JstackFrame().Match(line) is { Success: true } f) current.Add($"{f.Groups["function"].Value}({f.Groups["at"].Value})");
            }
            return threads;
        }

        private static async Task<string> Run(string exe, params string[] args)
        {
            var info = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var a in args) info.ArgumentList.Add(a);
            using var p = Process.Start(info)!;
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            await p.WaitForExitAsync(cts.Token);
            Assert.True(p.ExitCode == 0, $"{exe} exited {p.ExitCode}: {await error}");
            return await output;
        }

        public ValueTask DisposeAsync()
        {
            if (!_process.HasExited) _process.Kill();
            _process.Dispose();
            return ValueTask.CompletedTask;
        }

        [GeneratedRegex(@"Listening for transport dt_socket at address: (\d+)")]
        private static partial Regex Listening();

        // A JDK frame names its module first: at java.lang.Thread.run(java.base@24.0.1/Thread.java:1447).
        [GeneratedRegex(@"^\s+at (?<function>[^\s(]+)\((?:[^()/]+/)?(?<at>[^:()/]+:\d+)\)$")]
        private static partial Regex JstackFrame();
    }
}
