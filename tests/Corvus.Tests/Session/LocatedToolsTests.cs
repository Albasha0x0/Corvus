using Corvus.Native.Providers;

namespace Corvus.Tests;

public sealed class LocatedToolsTests
{
    [Fact]
    public void A_located_tool_is_named_with_its_size_and_time_and_a_missing_one_with_no_path()
    {
        using var dir = new TempDir();
        var file = dir.File("tool.exe");
        File.WriteAllText(file, "v1");
        File.SetLastWriteTimeUtc(file, new DateTime(2020, 1, 2, 0, 0, 0, DateTimeKind.Utc));
        var lines = LocatedTools.Lines([ExternalTools.Adb, ExternalTools.TShark, ExternalTools.Java],
            t => t == ExternalTools.Adb ? file : t == ExternalTools.Java ? dir.File("gone.exe") : null).ToList();
        Assert.Equal([$"tool adb={file} @2 {new DateTime(2020, 1, 2, 0, 0, 0, DateTimeKind.Utc).Ticks}", "tool tshark=", "tool java="], lines);
    }
}
