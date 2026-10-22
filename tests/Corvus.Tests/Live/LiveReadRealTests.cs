using System.Globalization;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// live_read on each target: strings read to their terminator, globals by name, a module's header by module name, a
/// pointer as wide as the program's, values of each scalar type, and the refusals (unreadable memory, unknown register,
/// a thread not held); memory of a running program read without a stop.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveReadRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [LiveTargetFact("win-x64")] public Task Reads_on_win_x64() => Reads(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Reads_on_win_x86() => Reads(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Reads_on_win_arm64() => Reads(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Reads_on_linux_x64() => Reads(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Reads_on_osx_arm64() => Reads(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86")] public Task Reads_on_linux_x86() => Reads(LiveTarget.LinuxX86);

    private async Task Reads(LiveTarget target)
    {
        var exe = target.Build(_dir, "values", LivePrograms.Values);
        await using var server = await Server();
        var pid = await Spawn(server, exe, "live-1", "3", "500");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Show" });
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        var thread = Regex.Match(stop, @"thread (\d+) stopped at s1").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(thread), stop);

        // a 300-character string and its UTF-16 copy, read whole without a length
        string text = string.Concat(Enumerable.Range(0, 300).Select(i => (char)('a' + i % 26))), wide = text.ToUpperInvariant();
        var cstring = await Read(server, await Argument(server, target, 0), "cstring");
        Assert.Contains($"  \"{text}\"\n", cstring);
        Assert.DoesNotContain("(cut:", cstring);
        Assert.Contains($"  \"{wide}\"\n", await Read(server, await Argument(server, target, 1), "utf16"));
        Assert.Contains($"  \"{text[..16]}\" (cut: no terminator in 16 bytes)", await Read(server, await Argument(server, target, 0), "cstring", length: 16));

        // globals by name, each scalar type
        Assert.Contains("  42\n", await Read(server, "g_count", "int32"));
        Assert.Contains("  2.5\n", await Read(server, "g_ratio", "double"));
        Assert.Contains("  0.5\n", await Read(server, "g_scale", "float"));
        Assert.Contains("  -5000000000\n", await Read(server, "g_big", "int64"));
        var bytes = await Read(server, "g_bytes", "uint8[4]");
        for (int i = 0; i < 4; i++) Assert.Contains($"[{i}] {i + 1}\n", bytes);
        // A module name is its base: the image header's magic (MZ, ELF,
        // MH_MAGIC_64).
        Assert.Contains(target.Windows ? "  23117\n" : target.Mac ? "  4277009103\n" : "  1179403647\n", await Read(server, target.Exe("values"), target.Windows ? "uint16" : "uint32"));

        // At the function's entry the stack pointer holds the return address
        // (ARM64: the link register), the stop's frame #1.
        var caller = Regex.Match(stop, @"#1 (0x[0-9A-F]+) ").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(caller), stop);
        if (target.Arm64) Assert.Matches($@"(?i)\blr +{caller}\b", await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = "lr" }));
        else Assert.Contains($"  {caller}\n", await Read(server, "sp", "pointer"));

        // below 64 KiB nothing is mapped; past the image's size, so not taken as an image address (a PIE's start at 0)
        var (unreadable, e1) = await Call(server, "live_read", new() { ["session"] = "live-1", ["memory"] = "0xF000", ["type"] = "uint32" });
        Assert.True(e1 && unreadable.Contains("\"code\":\"not_found\""), unreadable);
        var (register, e2) = await Call(server, "live_read", new() { ["session"] = "live-1", ["registers"] = "pc,xmm9" });
        Assert.True(e2 && register.Contains("\"code\":\"invalid_argument\"") && register.Contains("xmm9"), register);
        var (notHeld, e3) = await Call(server, "live_read", new() { ["session"] = "live-1", ["thread"] = "1" });
        Assert.True(e3 && notHeld.Contains("\"code\":\"not_found\""), notHeld);

        // running again: memory reads without a stop
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        Assert.Contains($"resumed thread(s) {thread}", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        var running = await Read(server, "g_count", "int32");
        Assert.Matches(@"(?m)^  4[2-5]$", running);
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains("count 45", await Events(server, "live-1", kind: "output"));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    private async Task<string> Read(InProcessServer server, string memory, string type, int? length = null)
    {
        var args = new Dictionary<string, object?> { ["session"] = "live-1", ["memory"] = memory, ["type"] = type };
        if (length != null) args["length"] = length;
        return (await Ok(server, "live_read", args)).ReplaceLineEndings("\n");
    }

    /// <summary>The held thread's integer argument <paramref name="index"/> at a function's entry, as an address.</summary>
    private async Task<string> Argument(InProcessServer server, LiveTarget target, int index)
    {
        if (target.ArgumentRegisters is { } registers)
        {
            var register = registers[index];
            var regs = await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = register });
            return Regex.Match(regs, $@"{register} +(0x[0-9a-fA-F]+)").Groups[1].Value;
        }
        // x86: [esp] is the return address, the arguments follow
        var stack = await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = "esp", ["type"] = $"uint32[{index + 2}]" });
        var value = Regex.Match(stack, $@"\[{index + 1}\] (\d+)").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(value), stack);
        return $"0x{ulong.Parse(value, CultureInfo.InvariantCulture):X}";
    }
}
