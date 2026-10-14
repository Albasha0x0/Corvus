using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>reanalyze_native preset=: built-in and file presets give the same settings on every run; unknown names are not_found.</summary>
public sealed class AnalysisPresetTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Presets_resolve_reproducibly_and_a_file_entry_wins()
    {
        var file = _dir.File(AnalysisPresets.FileName);
        Assert.Contains(AnalysisPresets.Options("full", "ghidra", file), p => p.Key == "WindowsResourceReference" && p.Value == "true");
        File.WriteAllText(file, """{"quick": {"ida": ["AF_FLIRT=false"]}, "full": {"ghidra": ["Stack=false"]}}""");
        Assert.Equal(AnalysisPresets.Options("quick", "ida", file), AnalysisPresets.Options("QUICK", "ida", file));
        Assert.Equal([new("Stack", "false")], AnalysisPresets.Options("full", "ghidra", file));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => AnalysisPresets.Options("none", "ida", file)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => AnalysisPresets.Options("quick", "ghidra", file)).Code);
    }
}
