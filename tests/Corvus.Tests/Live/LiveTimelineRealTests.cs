using System.Diagnostics;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>An activity trace through event tracing of a program built here: the file it writes and the registry value it reads, by name.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class LiveTimelineRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Source = """
        #include <stdio.h>
        #include <windows.h>
        #pragma comment(lib, "advapi32.lib")
        int main(int argc, char** argv)
        {
            FILE* f = fopen(argv[1], "w");
            if (!f) return 1;
            fputs("orders\n", f);
            fclose(f);
            HKEY key;
            char name[256];
            DWORD size = sizeof(name);
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &key) != ERROR_SUCCESS) return 2;
            if (RegQueryValueExA(key, "ProductName", NULL, NULL, (BYTE*)name, &size) != ERROR_SUCCESS) return 3;
            RegCloseKey(key);
            printf("%s\n", name);
            return 0;
        }
        """;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<string> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool} ({sw.ElapsedMilliseconds} ms): {(text.Length > 2000 ? text[..2000] + "…" : text)}");
        Assert.False(r.IsError == true, text);
        return text;
    }

    [FridaFact(elevated: true)]
    public async Task The_trace_names_the_file_written_and_the_registry_value_read()
    {
        var exe = LiveFridaRealTests.Build(_dir, "settings", Source);
        var written = _dir.File("timeline-out.txt");
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { written } });
        Assert.Contains("tl-1 tracing live-1", await Call(server, "live_timeline", new() { ["session"] = "live-1", ["action"] = "start" }));
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        string list = "";
        for (int i = 0; i < 300 && !list.Contains("complete"); i++)
        {
            await Task.Delay(100);
            list = await Call(server, "live_timeline", new() { ["action"] = "list" });
        }
        Assert.Contains("complete", list);
        Assert.True(File.Exists(written));

        var files = await Call(server, "live_timeline", new() { ["action"] = "report", ["run"] = "tl-1", ["category"] = "file", ["match"] = "timeline-out" });
        Assert.Contains("  file      " + written, files, StringComparison.OrdinalIgnoreCase);
        var registry = await Call(server, "live_timeline", new() { ["action"] = "report", ["run"] = "tl-1", ["category"] = "registry", ["match"] = "Windows NT\\CurrentVersion" });
        Assert.Contains(@"registry  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName", registry, StringComparison.OrdinalIgnoreCase);

        var page = await Call(server, "live_timeline", new() { ["action"] = "list", ["run"] = "tl-1", ["match"] = "timeline-out", ["limit"] = 5 });
        Assert.Matches(@"#\d+ \+\d+\.\d{3}s file ", page);
    }

    /// <summary>A stop's stack is named without the program looking up symbol files: no PDB probes in the trace.</summary>
    [FridaFact(elevated: true)]
    public async Task A_stop_leaves_no_symbol_file_lookups_in_the_trace()
    {
        var exe = LiveFridaRealTests.Build(_dir, "settings", Source);
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { _dir.File("stop-out.txt") } });
        await Call(server, "live_timeline", new() { ["session"] = "live-1", ["action"] = "start" });
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "kernelbase!CreateFileW" });
        Assert.Contains("stopped at s1", await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true }));
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        string list = "";
        for (int i = 0; i < 300 && !list.Contains("complete"); i++)
        {
            await Task.Delay(100);
            list = await Call(server, "live_timeline", new() { ["action"] = "list" });
        }
        Assert.Contains("complete", list);
        Assert.Contains("stop-out.txt", await Call(server, "live_timeline", new() { ["action"] = "report", ["run"] = "tl-1", ["category"] = "file" }));
        Assert.Contains(": 0 entries, 0 names", await Call(server, "live_timeline", new() { ["action"] = "report", ["run"] = "tl-1", ["match"] = ".pdb" }));
    }
}
