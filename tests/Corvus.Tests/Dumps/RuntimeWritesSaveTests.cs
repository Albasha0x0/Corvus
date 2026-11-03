using System.Globalization;
using Corvus.Native.Dump;
using Corvus.Native.Pe;
using Corvus.Services;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>The saved module of the test program holds what it wrote at run time.</summary>
[Trait("Speed", "Slow")]
[Permit("live")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class RuntimeWritesSaveTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task Check(LiveTarget target)
    {
        var result = RuntimeWritesProgram.Dump(_dir, target);
        ulong imageBase;
        using (var dump = MinidumpFile.Open(result.Dump))
            imageBase = dump.ModuleAt(result.Address)!.Base;
        var folder = _dir.File("saved");

        using var service = new MinidumpService();
        var rows = service.Modules(result.Dump, null, 0, 200, folder, default,
            MinidumpService.ModuleOptions.Default with { Module = Path.GetFileName(result.Program) }).Rows;
        var row = Assert.Single(rows, r => r.ImageFile != null);
        var savedPath = Path.Combine(folder, row.ImageFile!);
        var saved = PeFile.FromBytes(File.ReadAllBytes(savedPath));

        // The section holds the copied function in the saved file's raw data.
        var rva = (uint)(result.Address - imageBase);
        var section = Assert.Single(saved.Sections, s => s.Name == RuntimeWritesProgram.SectionName);
        Assert.True(section.Contains(rva));
        Assert.True(section.RawSize >= RuntimeWritesProgram.SectionSize, $"raw {section.RawSize}");
        Assert.True(section.IsExecutable, $"characteristics {section.Characteristics:x}");
        var bytes = File.ReadAllBytes(savedPath);
        var at = (int)(section.RawOffset + (rva - section.Rva));
        Assert.Equal(RuntimeWritesProgram.Function, bytes.AsSpan(at, RuntimeWritesProgram.Function.Length).ToArray());

        // Each table entry is an import at its slot.
        var width = target.Is64 ? 8u : 4u;
        var slot = (uint)(result.Table - imageBase);
        for (var i = 0; i < result.TableEntries.Length; i++)
        {
            var import = Assert.Single(saved.Imports, m => m.SlotRva == slot + (uint)i * width);
            Assert.NotNull(import.Name);
        }
        Assert.Equal(
            ["GetCurrentProcessId", "GetCurrentThreadId", "GetTickCount", "NtClose", "NtYieldExecution", "RtlGetCurrentPeb", "Sleep"],
            saved.Imports.Where(m => m.SlotRva >= slot && m.SlotRva < slot + 7 * width).Select(m => m.Name!).Order(StringComparer.Ordinal));

        // The built-in engine lists the copied function.
        await using var server = await InProcessServer.StartAsync();
        var listed = new List<string>();
        for (var offset = 0; ;)
        {
            var call = await server.Client.CallToolAsync("list_functions",
                new Dictionary<string, object?> { ["image"] = savedPath, ["engine"] = "ours", ["offset"] = offset });
            Assert.True(call.IsError != true);
            var text = string.Concat(call.Content.OfType<TextContentBlock>().Select(t => t.Text));
            listed.Add(text);
            var more = System.Text.RegularExpressions.Regex.Match(text, @"\[More: offset=(\d+)\]");
            if (!more.Success) break;
            offset = int.Parse(more.Groups[1].Value, CultureInfo.InvariantCulture);
        }
        Assert.Contains($"0x{imageBase + rva:X}", string.Join("\n", listed));
    }

    [Fact]
    public async Task The_saved_test_program_holds_its_run_time_code_and_late_bound_imports()
    {
        if (!OperatingSystem.IsWindows() || LiveTarget.WinX64.Missing is not null) return;
        await Check(LiveTarget.WinX64);
    }

    [Fact]
    public async Task The_saved_32_bit_test_program_holds_its_run_time_code_and_late_bound_imports()
    {
        if (!OperatingSystem.IsWindows() || LiveTarget.WinX86.Missing is not null) return;
        await Check(LiveTarget.WinX86);
    }
}
