using System.Globalization;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The modules and changes views show what the test program wrote at run time.</summary>
[Trait("Speed", "Slow")]
[Permit("live")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class RuntimeWritesViewTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static ulong Address(string text) =>
        ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private async Task Check(LiveTarget target)
    {
        var result = RuntimeWritesProgram.Dump(_dir, target);
        var name = Path.GetFileName(result.Program);
        using var service = new MinidumpService();

        // The modules row names the section the program wrote.
        var module = Assert.Single(service.Modules(result.Dump, null, 0, 200).Rows,
            r => r.Path.EndsWith(name, StringComparison.OrdinalIgnoreCase));
        var written = Assert.Single(module.RuntimeSections!, s => s.Name == RuntimeWritesProgram.SectionName);
        Assert.True(written.BytesWritten > 0 && written.BytesWritten <= RuntimeWritesProgram.SectionSize, $"written {written.BytesWritten}");
        var tools = new MinidumpTools(service);
        Assert.Contains($"{RuntimeWritesProgram.SectionName} (", await tools.OpenMinidump(result.Dump, "modules"));

        var rows = service.Changes(result.Dump, null, name, 0, 1000, default).Rows;

        // One summary row covers the whole section.
        var summary = Assert.Single(rows, r => r.Section == RuntimeWritesProgram.SectionName && r.Kind == "section");
        Assert.Equal(RuntimeWritesProgram.SectionSize, summary.Length);
        Assert.Contains("no raw data in the file", summary.Description);
        Assert.True(Address(summary.Start) <= result.Stubs && result.Stubs < Address(summary.Start) + (ulong)summary.Length);

        // The pointer row names the table's functions in slot order.
        var table = Assert.Single(rows, r => r.Kind == "pointer" && Address(r.Start) == result.Table);
        Assert.Equal((target.Is64 ? 8 : 4) * result.TableEntries.Length, table.Length);
        Assert.Equal(
            "7 slots: kernel32.dll!GetTickCount, kernel32.dll!GetCurrentProcessId, kernel32.dll!Sleep, ntdll.dll!NtClose, "
            + "ntdll.dll!RtlGetCurrentPeb, ntdll.dll!NtYieldExecution, kernel32.dll!GetCurrentThreadId",
            table.Description);

        // The patched function names the system export its two stubs reach.
        var patched = Assert.Single(rows, r => r.Kind == "code" && Address(r.Start) == result.Patched);
        Assert.Equal(result.PatchLength, patched.Length);
        Assert.Contains("then kernel32.dll!GetTickCount (2 hops)", patched.Description);

        var grouped = await tools.OpenMinidump(result.Dump, "changes", modules: name, group: "shape");
        Assert.Contains($" {RuntimeWritesProgram.SectionName} section x1 ", grouped);
        Assert.Contains(" pointer x1 ", grouped);
        Assert.Contains(" code x1 ", grouped);

        // The section is executable in memory, so its writes are code rows that
        // cover every stub; stubs closer than the merge gap form one range.
        ulong end = result.Stubs + (ulong)(result.StubCount * result.StubStride);
        var stubs = rows.Where(r => r.Kind == "code" && Address(r.Start) >= result.Stubs && Address(r.Start) < end).ToList();
        Assert.All(stubs, r => Assert.StartsWith("jump to 0x", r.Description));
        for (int i = 0; i < result.StubCount; i++)
        {
            ulong at = result.Stubs + (ulong)(i * result.StubStride);
            Assert.Contains(stubs, r => Address(r.Start) <= at && at < Address(r.Start) + (ulong)r.Length);
        }
        if (stubs.Count == result.StubCount)
            Assert.Contains($" {RuntimeWritesProgram.SectionName} code x{result.StubCount} ", grouped);
    }

    [Fact]
    public async Task The_test_program_dump_shows_its_run_time_writes_in_both_views()
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var target in new[] { LiveTarget.WinX64, LiveTarget.WinX86 })
            if (target.Missing is null) await Check(target);
    }
}
