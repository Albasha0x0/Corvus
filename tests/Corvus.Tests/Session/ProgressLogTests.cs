using ModelContextProtocol;
using Corvus.Core;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>Progress lines for non-terminal stderr.</summary>
public class ProgressLogTests
{
    [Fact]
    public void Reports_inside_one_interval_are_dropped_except_the_final_step()
    {
        var error = new StringWriter();
        long now = 0;
        var log = new ProgressLog(error, TimeSpan.FromSeconds(1), () => now).For("scan");
        log.Report(new ProgressNotificationValue { Progress = 1, Total = 3, Message = "a" });
        now += TimeSpan.TicksPerMillisecond * 100;
        log.Report(new ProgressNotificationValue { Progress = 2, Total = 3, Message = "b" });
        log.Report(new ProgressNotificationValue { Progress = 3, Total = 3, Message = "c" });
        Assert.Equal($"scan: [1/3] a{Environment.NewLine}scan: [3/3] c{Environment.NewLine}", error.ToString());
    }

    [Fact]
    public void A_report_after_the_interval_is_written_without_a_total()
    {
        var error = new StringWriter();
        long now = 0;
        var log = new ProgressLog(error, TimeSpan.FromSeconds(1), () => now).For("scan");
        log.Report(new ProgressNotificationValue { Progress = 5, Message = "x" });
        now += TimeSpan.TicksPerSecond;
        log.Report(new ProgressNotificationValue { Progress = 9, Message = "y" });
        Assert.Equal($"scan: [5] x{Environment.NewLine}scan: [9] y{Environment.NewLine}", error.ToString());
    }

    [Fact]
    public void A_repeated_final_step_and_a_flushed_drop_are_written_once()
    {
        var error = new StringWriter();
        long now = 0;
        var log = new ProgressLog(error, TimeSpan.FromSeconds(1), () => now);
        var scan = log.For("scan");
        scan.Report(new ProgressNotificationValue { Progress = 1, Total = 3, Message = "a" });
        scan.Report(new ProgressNotificationValue { Progress = 2, Total = 3, Message = "b" });
        log.Flush();
        scan.Report(new ProgressNotificationValue { Progress = 3, Total = 3, Message = "c" });
        scan.Report(new ProgressNotificationValue { Progress = 3, Total = 3, Message = "c" });
        var nl = Environment.NewLine;
        Assert.Equal($"scan: [1/3] a{nl}scan: [2/3] b{nl}scan: [3/3] c{nl}", error.ToString());
    }

    [Fact]
    public void A_message_with_line_breaks_stays_on_one_line()
    {
        var error = new StringWriter();
        new ProgressLog(error).For("scan").Report(new ProgressNotificationValue { Progress = 1, Message = "a\r\nb" });
        Assert.Equal($"scan: [1] a b{Environment.NewLine}", error.ToString());
    }

    [Fact]
    public async Task A_piped_call_keeps_progress_lines_out_of_its_stdout_record()
    {
        // In-process parsing keeps compare_folders' hashing progress out of a worker.
        // The client handles each message on its own task, so whether a progress
        // line beats the response to stderr is not asserted (macOS CI on 75c15090).
        var (old, @new) = Folders();
        try
        {
            var (code, output, _) = await ToolCliTests.Run("compare_folders", ServerOptions.InProcessParsingOption, $"oldPath={old}", $"newPath={@new}", "--json");
            Assert.Equal(0, code);
            Assert.DoesNotContain("compare_folders: [", output);
            Assert.NotNull(System.Text.Json.Nodes.JsonNode.Parse(output));
        }
        finally { Directory.Delete(Path.GetDirectoryName(old)!, true); }
    }

    [Fact]
    public async Task A_terminal_stderr_gets_no_progress_log_lines()
    {
        var (old, @new) = Folders();
        try
        {
            using var output = new StringWriter();
            using var error = new StringWriter();
            var io = new CliIo(output, error, new StringReader(""), ErrorTty: true);
            var code = await ToolCli.RunAsync(["compare_folders", ServerOptions.InProcessParsingOption, $"oldPath={old}", $"newPath={@new}"], io, CancellationToken.None);
            Assert.True(code == 0, error.ToString());
            Assert.DoesNotContain("compare_folders: [", error.ToString());
        }
        finally { Directory.Delete(Path.GetDirectoryName(old)!, true); }
    }

    [Fact]
    public async Task A_batch_step_keeps_progress_lines_out_of_its_stdout_record()
    {
        // As for a single call, a progress line may lose the race with the
        // response (release.yml ubuntu on v2.10.0), so stderr is not asserted.
        var (old, @new) = Folders();
        var steps = Path.Combine(Path.GetDirectoryName(old)!, "steps.jsonl");
        try
        {
            File.WriteAllText(steps, System.Text.Json.JsonSerializer.Serialize(new { tool = "compare_folders", args = new { oldPath = old, newPath = @new } }));
            var (code, o, error) = await ToolCliTests.Run("batch", steps, ServerOptions.InProcessParsingOption);
            Assert.True(code == 0, o + error);
            Assert.DoesNotContain("compare_folders: [", o);
            Assert.False(string.IsNullOrWhiteSpace(o));
        }
        finally { Directory.Delete(Path.GetDirectoryName(old)!, true); }
    }

    private static (string Old, string New) Folders()
    {
        var root = Path.Combine(Path.GetTempPath(), "progress-" + Guid.NewGuid().ToString("N"));
        var old = Path.Combine(root, "old");
        var @new = Path.Combine(root, "new");
        Directory.CreateDirectory(old);
        Directory.CreateDirectory(@new);
        for (var i = 0; i < 300; i++) { File.WriteAllText(Path.Combine(old, $"f{i}.txt"), "1"); File.WriteAllText(Path.Combine(@new, $"f{i}.txt"), "2"); }
        return (old, @new);
    }
}
