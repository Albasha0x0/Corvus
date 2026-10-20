using System.Text.RegularExpressions;
using Corvus.Native;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Stop points on each target by each location form (name+offset, live address, image address, module!export in a system
/// module); continue of one thread while another stays held; a stop point and a watch deferred to a library loaded later
/// catch its first call, and a watch's rate limit counts the calls it does not record.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Collection(LiveSessions.Collection)]
public sealed class LiveStopPointRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private Task<string> Set(InProcessServer server, string at) => Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = at });

    private Task<string> Clear(InProcessServer server, string id) => Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = id });

    // ---- each location form reaches the same code

    [LiveTargetFact("win-x64")] public Task Locations_on_win_x64() => Locations(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Locations_on_win_x86() => Locations(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Locations_on_linux_x64() => Locations(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Locations_on_linux_x86() => Locations(LiveTarget.LinuxX86);

    private async Task Locations(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        int totalLine = LivePrograms.Line(LivePrograms.Orders, "o->total +=");
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1", "4", "0");

        // name+offset: the offset the line's address has in AddLine
        var byLine = await Set(server, $"orders.c:{totalLine}");
        var line = Regex.Match(byLine, $@"s1 set at (0x[0-9A-F]+) {name}!AddLine\+(0x[0-9A-F]+)");
        Assert.True(line.Success, byLine);
        await Clear(server, "s1");
        Assert.Contains($"s2 set at {line.Groups[1].Value} ", await Set(server, $"AddLine+{line.Groups[2].Value}"));
        await Clear(server, "s2");

        // the function's live address, then the image address it was loaded from
        var entry = Regex.Match(await Set(server, "AddLine"), @"s3 set at (0x[0-9A-F]+)").Groups[1].Value;
        await Clear(server, "s3");
        Assert.Matches($@"s4 set at {entry} {name}!AddLine\b", await Set(server, entry));
        await Clear(server, "s4");
        var status = await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" });
        var moduleBase = Convert.ToUInt64(Regex.Match(status, $@"(0x[0-9A-F]+) {name}").Groups[1].Value[2..], 16);
        var va = NativeImageLoader.Open(exe).ImageBase + (Convert.ToUInt64(entry[2..], 16) - moduleBase);
        Assert.Contains($"s5 set at {entry} ", await Set(server, $"0x{va:X}"));

        // a system module's export
        Assert.Contains("s6 set at", await Set(server, target.FileOpen));

        int addLine = 0;
        string stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        for (int i = 0; i < 10 && !stop.Contains("stopped at s6"); i++)
        {
            Assert.Matches($@"stopped at s5 \({name}!AddLine\)", stop);
            addLine++;
            stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        }
        Assert.Equal(4, addLine);
        Assert.Contains("stopped at s6", stop);
        Assert.Matches($@"#\d+ 0x[0-9A-F]+ {name}!Touch\+0x", stop);
        await Clear(server, "s5");
        await Clear(server, "s6");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains("lines 4", await Events(server, "live-1", kind: "output"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    // ---- continue one thread: another held thread stays held

    [LiveTargetFact("win-x64")] public Task One_thread_on_win_x64() => OneThread(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task One_thread_on_win_x86() => OneThread(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task One_thread_on_linux_x64() => OneThread(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task One_thread_on_linux_x86() => OneThread(LiveTarget.LinuxX86);

    private async Task OneThread(LiveTarget target)
    {
        var exe = target.Build(_dir, "workers", LivePrograms.Workers);
        await using var server = await Server();
        const int calls = 100;
        var pid = await Spawn(server, exe, "live-1", $"{calls}", "5");
        await Set(server, "Work");
        var first = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        var a = Regex.Match(first, @"thread (\d+) stopped at s1").Groups[1].Value;
        var second = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
        var b = Regex.Match(second, @"thread (\d+) stopped at s1").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b), first + second);
        Assert.NotEqual(a, b);

        Assert.Contains($"resumed thread(s) {a}\n", (await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["thread"] = a })).ReplaceLineEndings("\n"));
        Assert.Contains($"thread {b} (held at s1)", await Ok(server, "live_read", new() { ["session"] = "live-1", ["thread"] = b, ["registers"] = "pc" }));
        // the resumed thread runs on into its next call and stops again, while b has not moved
        var again = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches(@"thread \d+ stopped at s1", again);
        Assert.Contains($"thread {b} (held at s1)", await Ok(server, "live_read", new() { ["session"] = "live-1", ["thread"] = b, ["registers"] = "pc" }));

        await Clear(server, "s1");
        Assert.Contains("resumed thread(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        Assert.Contains("no thread was held", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains($"total {LivePrograms.WorkersTotal(calls)}", await Events(server, "live-1", kind: "output"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    // ---- a library loaded later: its first call stops, its watched calls are counted

    [LiveTargetFact("win-x64")] public Task Deferred_on_win_x64() => Deferred(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Deferred_on_win_x86() => Deferred(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Deferred_on_linux_x64() => Deferred(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Deferred_on_linux_x86() => Deferred(LiveTarget.LinuxX86);

    private async Task Deferred(LiveTarget target)
    {
        var plugin = target.BuildLibrary(_dir, "plugin", LivePrograms.Plugin);
        var exe = target.Build(_dir, "loader", LivePrograms.Loader);
        var module = Path.GetFileNameWithoutExtension(target.Library("plugin"));
        const int calls = 200;
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1", plugin, $"{calls}");

        Assert.Contains("s1 deferred: ", await Set(server, $"{module}!PluginWork"));
        var watch = await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = $"{module}!PluginOther", ["rateLimit"] = 1 });
        Assert.Contains("w1 deferred: ", watch);
        Assert.Contains($"s1 {module}!PluginWork: deferred until {module} loads", await Ok(server, "live_break", new() { ["session"] = "live-1" }));

        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Contains($"stopped at s1 ({target.Library("plugin")}!PluginWork)", stop);
        Assert.Matches($@"#1 0x[0-9A-F]+ {Regex.Escape(target.Exe("loader"))}!main\+0x", stop);
        Assert.Equal(0UL, await FirstArgument(server, target)); // the first call: none was missed while the library loaded
        var modules = await Events(server, "live-1", kind: "module");
        Assert.Contains("deferred stop point s1 set at", modules);
        Assert.Contains("deferred watch w1 set at", modules);

        await Clear(server, "s1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains($"plugin {4L * calls * (calls - 1) / 2}", await Events(server, "live-1", kind: "output"));
        await Task.Delay(500); // the last batch
        var list = await Ok(server, "live_watch", new() { ["session"] = "live-1" });
        var w = Regex.Match(list, @"w1 [^:]+: ([\d,]+) call\(s\) recorded(?:.*?, ([\d,]+) over the rate limit)?");
        Assert.True(w.Success && w.Groups[2].Success, list);
        long recorded = long.Parse(w.Groups[1].Value.Replace(",", "")), skipped = long.Parse(w.Groups[2].Value.Replace(",", ""));
        Assert.Equal(calls, recorded + skipped);
        Assert.InRange(recorded, 1, 10);
        Assert.Matches(@"PluginOther\((?:i=)?(?:0x)?0\) -> (?:0x)?0\b", await Events(server, "live-1", from: "w1"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    // ---- a function with no prototype: its calls are recorded as raw values

    [LiveTargetFact("win-x64")] public Task Raw_values_on_win_x64() => RawValues(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Raw_values_on_win_x86() => RawValues(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Raw_values_on_linux_x64() => RawValues(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Raw_values_on_linux_x86() => RawValues(LiveTarget.LinuxX86);

    private async Task RawValues(LiveTarget target)
    {
        var plugin = target.BuildLibrary(_dir, "plugin", LivePrograms.Plugin, debugInfo: false);
        var exe = target.Build(_dir, "loader", LivePrograms.Loader);
        var module = Path.GetFileNameWithoutExtension(target.Library("plugin"));
        const int calls = 50;
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1", plugin, $"{calls}");

        Assert.Contains("w1 deferred: ", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = $"{module}!PluginOther", ["arguments"] = 2 }));
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        await Task.Delay(500); // the last batch
        var list = await Ok(server, "live_watch", new() { ["session"] = "live-1" });
        Assert.Contains($"w1 {target.Library("plugin")}!PluginOther: PluginOther(a0, a1) (raw values), {calls} call(s) recorded", list);
        // the decoding is known once the library loads: the module event names it
        Assert.Contains($"deferred watch w1 set at {target.Library("plugin")}!PluginOther: PluginOther(a0, a1) (raw values) (", await Events(server, "live-1", kind: "module"));

        var events = await Events(server, "live-1", from: "w1");
        var rows = Regex.Matches(events, @"PluginOther\(a0=0x([0-9A-F]+), a1=0x[0-9A-F]+\) -> 0x([0-9A-F]+)\r?\n");
        Assert.True(rows.Count == calls, events);
        // PluginOther(i) is called with i = 0..calls-1 and returns 2i
        var passed = rows.Select(r => (A: Convert.ToUInt64(r.Groups[1].Value, 16), Ret: Convert.ToUInt64(r.Groups[2].Value, 16))).ToList();
        Assert.Equal(Enumerable.Range(0, calls).Select(i => (ulong)i), passed.Select(p => p.A));
        Assert.All(passed, p => Assert.Equal(2 * p.A, p.Ret));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    /// <summary>The held thread's first integer argument at a function's entry.</summary>
    private async Task<ulong> FirstArgument(InProcessServer server, LiveTarget target)
    {
        if (target.FirstArgument is { } register)
        {
            var regs = await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = register });
            return Convert.ToUInt64(Regex.Match(regs, $@"{register} +0x([0-9a-fA-F]+)").Groups[1].Value, 16);
        }
        var stack = await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = "esp", ["type"] = "uint32[2]" });
        return ulong.Parse(Regex.Match(stack, @"\[1\] (\d+)").Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
    }
}
