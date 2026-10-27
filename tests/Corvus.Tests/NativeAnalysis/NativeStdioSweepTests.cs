using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Native.Pe;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Native tools over stdio on sample Windows images answer within limits and budget or with a typed error, with progress every <see cref="MaxSilence"/> (CORVUS_NATIVE_STDIO_SAMPLE, default 25).</summary>
[Trait("Speed", "Slow")]
public class NativeStdioSweepTests(ITestOutputHelper output)
{
    private static readonly TimeSpan MaxSilence = TimeSpan.FromSeconds(15);

    private static Dictionary<string, object?> Args(params (string Key, object? Value)[] pairs) => pairs.ToDictionary(p => p.Key, p => p.Value);

    [WindowsFact]
    public async Task Native_tools_answer_over_stdio_on_system_images()
    {
        int sample = int.TryParse(Environment.GetEnvironmentVariable("CORVUS_NATIVE_STDIO_SAMPLE"), out var s) ? s : 25;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var files = NativeToolSweepTests.Sample(NativeToolHarness.NativeFiles(Path.Combine(windows, "System32"), maxSize: 64 << 20), sample)
            .Concat(NativeToolSweepTests.Sample(NativeToolHarness.NativeFiles(Path.Combine(windows, "SysWOW64"), maxSize: 64 << 20), sample)).ToList();
        var large = LargeBrowserDll();
        if (large != null) files.Add(large);

        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("cwd"));
        await using var client = await McpProtocolTests.StartServerInAsync(dir.File("cwd"));
        var progress = new ConcurrentQueue<(DateTime At, string Message)>();
        await using var handler = client.RegisterNotificationHandler(NotificationMethods.ProgressNotification, (n, _) =>
        {
            var p = n.Params.Deserialize<ProgressNotificationParams>(McpJsonUtilities.DefaultOptions)!;
            progress.Enqueue((DateTime.UtcNow, p.Progress.Message ?? ""));
            return ValueTask.CompletedTask;
        });
        var failures = new List<string>();
        var timings = new List<(string Call, TimeSpan Elapsed, int Chars)>();
        int calls = 0, errors = 0;

        async Task<string?> Call(string file, string tool, Dictionary<string, object?> args, TimeSpan? limit = null)
        {
            calls++;
            var sw = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(limit ?? TimeSpan.FromSeconds(60));
            CallToolResult result;
            try { result = await client.CallToolAsync(tool, args, new Progress(), cancellationToken: cts.Token); }
            catch (Exception ex)
            {
                failures.Add($"{Path.GetFileName(file)} {tool}: {ex.GetType().Name}: {ex.Message}");
                return null;
            }
            var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
            timings.Add(($"{Path.GetFileName(file)} {tool}", sw.Elapsed, text.Length));
            if (result.IsError == true)
            {
                errors++;
                if (!Regex.IsMatch(text, @"^Error \((invalid_argument|not_found|unsupported|malformed_input|not_loaded)[,)]"))
                    failures.Add($"{Path.GetFileName(file)} {tool}: {text.Split('\n')[0]}");
                return null;
            }
            return text;
        }

        foreach (var file in files)
        {
            var pe = PeFile.Open(file);
            string Va(uint rva) => $"0x{pe.ImageBase + rva:X}";
            var load = await Call(file, "load_assembly", Args(("path", file)));
            if (load == null) continue;
            var id = Regex.Match(load, @"^Loaded native image (\S+):").Groups[1].Value;
            await Call(file, "get_pe_info", Args(("image", id)));
            await Call(file, "list_imports", Args(("image", id)));
            await Call(file, "list_exports", Args(("image", id)));
            await Call(file, "list_resources", Args(("assembly", id)));
            if (pe.Resources.Count > 0) await Call(file, "get_resource", Args(("assembly", id), ("name", Corvus.Services.NativeResourceService.Key(pe.Resources[0]))));
            await Call(file, "search_bytes", Args(("image", id), ("pattern", "48 8B ?? ?? C3"), ("limit", 10_000)));
            await Call(file, "read_bytes", Args(("image", id), ("address", "rva:0"), ("length", 65536)));
            await Call(file, "list_cpp_classes", Args(("image", id), ("slots", true)), TimeSpan.FromMinutes(3));
            var functions = await Call(file, "list_functions", Args(("image", id), ("sort", "callers")), TimeSpan.FromMinutes(10));
            if (pe.EntryPointRva != 0)
            {
                await Call(file, "resolve_address", Args(("image", id), ("address", Va(pe.EntryPointRva))));
                await Call(file, "disassemble", Args(("image", id), ("address", Va(pe.EntryPointRva))));
                await Call(file, "get_cfg", Args(("image", id), ("address", Va(pe.EntryPointRva))));
            }
            if (functions != null && Regex.Match(functions, @"^  (0x[0-9A-F]+) ", RegexOptions.Multiline) is { Success: true } top)
            {
                var at = top.Groups[1].Value;
                await Call(file, "find_xrefs", Args(("image", id), ("address", at)));
                await Call(file, "native_call_tree", Args(("image", id), ("function", at), ("direction", "callers"), ("depth", 8), ("maxNodes", 20_000)));
                await Call(file, "native_call_tree", Args(("image", id), ("function", at), ("depth", 8), ("maxNodes", 20_000)));
                await Call(file, "disassemble", Args(("image", id), ("address", at), ("maxInstructions", 200_000)));
            }
            await Call(file, "search_native_strings", Args(("image", id), ("limit", 5000)));
            await Call(file, "reload_assembly", Args(("assembly", id)));
            await Call(file, "unload_assembly", Args(("assembly", id)));
        }

        // Silence: the longest gap between progress notifications during the large image's index build.
        var gaps = progress.Where(p => p.Message.StartsWith("indexing", StringComparison.Ordinal)).Select(p => p.At).Order().ToList();
        var longest = gaps.Zip(gaps.Skip(1), (a, b) => b - a).DefaultIfEmpty(TimeSpan.Zero).Max();
        output.WriteLine($"{files.Count} images over stdio, {calls} calls, {errors} typed errors, {failures.Count} failures; large image: {large ?? "none"}");
        output.WriteLine($"indexing progress notifications: {gaps.Count}, longest gap {longest.TotalSeconds:0.0} s");
        foreach (var t in timings.OrderByDescending(t => t.Elapsed).Take(10)) output.WriteLine($"  slow: {t.Call} {t.Elapsed.TotalSeconds:0.00} s, {t.Chars} chars");
        foreach (var f in failures.Take(40)) output.WriteLine("FAIL " + f);
        Assert.Empty(failures);
        Assert.True(longest < MaxSilence, $"no progress for {longest.TotalSeconds:0} s while indexing");
    }

    /// <summary>The largest msedge.dll or chrome.dll installed under Program Files, if any.</summary>
    private static string? LargeBrowserDll()
    {
        var candidates = new List<string>();
        foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 }.Select(Environment.GetFolderPath).Distinct())
        {
            foreach (var app in new[] { Path.Combine(root, "Microsoft", "Edge", "Application"), Path.Combine(root, "Google", "Chrome", "Application") })
            {
                if (!Directory.Exists(app)) continue;
                foreach (var version in Directory.EnumerateDirectories(app))
                    candidates.AddRange(new[] { "msedge.dll", "chrome.dll" }.Select(n => Path.Combine(version, n)).Where(File.Exists));
            }
        }
        return candidates.Where(f => new FileInfo(f).Length <= PeLimits.MaxFileSize).OrderByDescending(f => new FileInfo(f).Length).FirstOrDefault();
    }

    /// <summary>Gives each request a progress token; notifications are read by the session-wide handler.</summary>
    private sealed class Progress : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) { }
    }
}
