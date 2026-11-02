using Corvus.Relay;

namespace Corvus.Tests;

/// <summary>The relay host handing off to the publish folder's own relay code.</summary>
[Collection(ProcessEnvironmentCollection.Name)]
public sealed class RelayHandoffTests
{
    // A host folder and a publish folder holding a complete build, each with a main assembly of the given text.
    private static (string Host, RelayOptions Options) Folders(TempDir dir, string hostCode, string buildCode)
    {
        var host = Directory.CreateDirectory(Path.Combine(dir.Path, "host")).FullName;
        var publish = Directory.CreateDirectory(Path.Combine(dir.Path, "publish")).FullName;
        File.WriteAllText(Path.Combine(host, RelayBuilds.ProgramDll), hostCode);
        File.WriteAllText(Path.Combine(publish, RelayBuilds.ProgramDll), buildCode);
        File.WriteAllText(Path.Combine(publish, RelayBuilds.ProgramName), buildCode);
        File.WriteAllText(Path.Combine(publish, RelayBuilds.MarkerName), "{\"buildId\":\"20260101T120000Z-ab12cd34\"}");
        return (host, new RelayOptions { Target = publish, StateDirectory = Path.Combine(dir.Path, "state") });
    }

    private static int? Hand(RelayOptions options, string host, List<(string Program, string[] Args, bool Guarded)> runs, TextWriter log,
        Func<string, string, bool, string>? stage = null) =>
        RelayHandoff.TryHandOff(options, ["relay", "--target", options.Target, "--x"], host, log,
            (program, args, environment) =>
            {
                runs.Add((program, [.. args], environment.ContainsKey(RelayHandoff.GuardVariable)));
                return 7;
            }, stage);

    [Fact]
    public void A_host_with_different_relay_code_runs_the_staged_copy_with_its_arguments()
    {
        using var dir = new TempDir();
        var (host, options) = Folders(dir, "old", "new");
        var runs = new List<(string, string[], bool)>();

        var code = Hand(options, host, runs, TextWriter.Null);

        Assert.Equal(7, code);
        var (program, args, guarded) = Assert.Single(runs);
        Assert.True(RelayBuilds.IsInside(program, Path.Combine(options.StateDirectory, "host")));
        Assert.Equal(["relay", "--target", options.Target, "--x"], args);
        Assert.True(guarded);
    }

    [Fact]
    public void A_host_with_the_same_relay_code_keeps_running()
    {
        using var dir = new TempDir();
        var (host, options) = Folders(dir, "same", "same");
        var runs = new List<(string, string[], bool)>();

        Assert.Null(Hand(options, host, runs, TextWriter.Null));
        Assert.Empty(runs);
    }

    [Fact]
    public void A_publish_folder_without_a_marker_is_not_handed_off_to()
    {
        using var dir = new TempDir();
        var (host, options) = Folders(dir, "old", "new");
        File.Delete(Path.Combine(options.Target, RelayBuilds.MarkerName));
        var runs = new List<(string, string[], bool)>();

        Assert.Null(Hand(options, host, runs, TextWriter.Null));
        Assert.Empty(runs);
    }

    [Fact]
    public void The_guard_variable_stops_a_second_handoff()
    {
        using var dir = new TempDir();
        var (host, options) = Folders(dir, "old", "new");
        var runs = new List<(string, string[], bool)>();
        Environment.SetEnvironmentVariable(RelayHandoff.GuardVariable, "1");
        try { Assert.Null(Hand(options, host, runs, TextWriter.Null)); }
        finally { Environment.SetEnvironmentVariable(RelayHandoff.GuardVariable, null); }
        Assert.Empty(runs);
    }

    [Fact]
    public void A_failed_stage_keeps_the_current_host_and_logs_one_line()
    {
        using var dir = new TempDir();
        var (host, options) = Folders(dir, "old", "new");
        var runs = new List<(string, string[], bool)>();
        var log = new StringWriter();

        var code = Hand(options, host, runs, log, (_, _, _) => throw new IOException("disk full"));

        Assert.Null(code);
        Assert.Empty(runs);
        Assert.Single(log.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("disk full", log.ToString());
    }
}
