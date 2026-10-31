using Corvus.Relay;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>The warning for a published build older than its source tree.</summary>
public sealed class RelayStaleBuildTests
{
    private const string Marker = "{\"buildId\":\"20260101T120000Z-ab12cd34\"}";

    // A source tree with publish.ps1 and src/A.cs written at <paramref name="sourceTime"/>.
    private static string Tree(TempDir dir, DateTime sourceTime)
    {
        var publish = Path.Combine(dir.Path, "out", "publish");
        Directory.CreateDirectory(publish);
        Directory.CreateDirectory(Path.Combine(dir.Path, "src"));
        File.WriteAllText(Path.Combine(dir.Path, "publish.ps1"), "");
        var source = Path.Combine(dir.Path, "src", "A.cs");
        File.WriteAllText(source, "");
        File.SetLastWriteTimeUtc(source, sourceTime);
        return publish;
    }

    [Fact]
    public void A_build_older_than_a_source_file_is_reported_with_both_times()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc));

        var note = RelayBuilds.StaleSourceNote(publish, Marker);

        Assert.Contains("2026-01-01 12:00 UTC", note);
        Assert.Contains("2026-02-01 00:00 UTC", note);
    }

    [Fact]
    public void A_build_newer_than_every_source_file_is_not_reported()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc));

        Assert.Null(RelayBuilds.StaleSourceNote(publish, Marker));
    }

    [Fact]
    public void A_build_without_a_source_tree_is_not_reported()
    {
        using var dir = new TempDir();
        Assert.Null(RelayBuilds.StaleSourceNote(dir.Path, Marker));
    }

    [Fact]
    public void A_marker_without_a_build_time_is_reported_as_unknown()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc));

        Assert.Contains("unknown", RelayBuilds.StaleSourceNote(publish, "{}"));
    }

    [Fact]
    public void Source_files_under_build_output_folders_are_ignored()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc));
        var obj = Directory.CreateDirectory(Path.Combine(dir.Path, "src", "obj")).FullName;
        var generated = Path.Combine(obj, "G.cs");
        File.WriteAllText(generated, "");
        File.SetLastWriteTimeUtc(generated, new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        Assert.Null(RelayBuilds.StaleSourceNote(publish, Marker));
    }

    [Fact]
    public void The_status_detail_of_a_stale_relay_build_ends_with_a_warning()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2026, 2, 1, 0, 0, 0, DateTimeKind.Utc));
        File.WriteAllText(Path.Combine(publish, RelayBuilds.MarkerName), Marker);

        Assert.StartsWith("; warning: the build is from", Doctor.StaleBuild(publish));
    }

    [Fact]
    public void The_status_detail_of_a_current_relay_build_has_no_warning()
    {
        using var dir = new TempDir();
        var publish = Tree(dir, new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc));
        File.WriteAllText(Path.Combine(publish, RelayBuilds.MarkerName), Marker);

        Assert.Equal("", Doctor.StaleBuild(publish));
    }
}
