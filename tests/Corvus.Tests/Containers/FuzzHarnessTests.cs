using System.Text;
using Corvus.Core;
using Corvus.Fuzz;

namespace Corvus.Tests;

/// <summary>
/// The SharpFuzz reader harnesses: every target reads damaged files, a failing
/// input reduces to a fixture.
/// </summary>
public sealed class FuzzHarnessTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    private static FuzzTarget Throwing(string name, byte[] marker) => new(name, (b, _) =>
    {
        if (b.AsSpan().IndexOf(marker) >= 0) throw new InvalidOperationException("marker read");
    });

    private static byte[] Seed(byte[] magic, int length, int random)
    {
        var bytes = new byte[length];
        new Random(random).NextBytes(bytes);
        magic.CopyTo(bytes, 0);
        return bytes;
    }

    // Each seed is a format signature over seeded noise: identified, then unreadable.
    private static readonly byte[][] Seeds =
    [
        Seed([0x7F, (byte)'E', (byte)'L', (byte)'F'], 256, 11),
        Seed([(byte)'P', (byte)'K', 3, 4], 40, 12),
        Seed([(byte)'P', (byte)'K', 5, 6], 22, 13),
        Seed([(byte)'M', (byte)'Z'], 200, 14),
        Seed([0x1F, 0x8B, 8], 64, 15),
        Seed([(byte)'d', (byte)'e', (byte)'x', 10, (byte)'0', (byte)'3', (byte)'5', 0], 200, 16),
    ];

    [Fact]
    public void Every_target_reads_damaged_files_of_each_format_without_a_failure()
    {
        var failures = new List<string>();
        foreach (var seed in Seeds)
            foreach (var t in FuzzTargets.All)
                if (FuzzTargets.Probe(t, seed, Limit) is { } f) failures.Add($"{t.Name}: {f.Signature}");
        Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
    }

    // A zip cut inside its central directory made view=protobuf throw InvalidDataException.
    [Fact]
    public void A_truncated_zip_is_refused_by_the_protobuf_view()
    {
        var failure = FuzzTargets.Probe(FuzzTargets.Find("view-protobuf")!, Seeds[1], Limit);
        Assert.Null(failure);
    }

    [Fact]
    public void A_wrapped_exception_is_named_by_its_inner_cause()
    {
        var target = new FuzzTarget("wrapping", (_, _) => throw new AggregateException(new InvalidOperationException("inner")));
        Assert.StartsWith("InvalidOperationException@", FuzzTargets.Probe(target, [1], Limit)!.Signature);
    }

    [Fact]
    public void A_cancellation_thrown_before_the_limit_is_a_failure_and_not_a_timeout()
    {
        var target = new FuzzTarget("cancelling", (_, _) => throw new OperationCanceledException());
        Assert.StartsWith("OperationCanceledException@", FuzzTargets.Probe(target, [1], Limit)!.Signature);
    }

    [Fact]
    public void A_read_that_ignores_the_cancellation_token_still_ends_at_the_limit()
    {
        var target = new FuzzTarget("spinning", (_, _) => Thread.Sleep(TimeSpan.FromSeconds(30)));
        Assert.Equal("timeout", FuzzTargets.Probe(target, [1], TimeSpan.FromMilliseconds(100))!.Signature);
    }

    [Fact]
    public void Replay_exits_0_for_passing_fixtures_and_2_without_a_folder()
    {
        var entry = typeof(FuzzTargets).Assembly.EntryPoint!;
        var folder = Directory.CreateTempSubdirectory("corvus-fuzz-test-").FullName;
        try
        {
            var target = FuzzTargets.Find("container")!;
            File.WriteAllBytes(Path.Combine(folder, FuzzTargets.FixtureName(target, [1])), [1]);
            Assert.Equal(0, entry.Invoke(null, [new[] { "replay", folder }]));
            File.WriteAllBytes(Path.Combine(folder, "no-such-target-00000000.bin"), [1]);
            Assert.Equal(0, entry.Invoke(null, [new[] { "replay", folder }]));
            Assert.Equal(2, entry.Invoke(null, [new[] { "replay" }]));
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public void The_targets_include_the_container_dispatch_and_the_summarize_file_views()
    {
        var names = FuzzTargets.All.Select(t => t.Name).ToList();
        Assert.Contains("container", names);
        Assert.Contains("view-android", names);
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    [Fact]
    public void A_failing_input_reduces_to_the_bytes_that_cause_the_failure()
    {
        var marker = "BAD"u8.ToArray();
        var target = Throwing("marker", marker);
        var input = new byte[300];
        new Random(7).NextBytes(input);
        marker.CopyTo(input, 120);
        var failure = FuzzTargets.Probe(target, input, Limit)!;
        Assert.StartsWith("InvalidOperationException@", failure.Signature);
        var reduced = Minimizer.Reduce(target, input, failure.Signature, 5000, Limit);
        Assert.Equal(marker, reduced.Bytes);
        Assert.False(reduced.Capped);
        Assert.Equal(failure.Signature, FuzzTargets.Probe(target, reduced.Bytes, Limit)!.Signature);
    }

    [Fact]
    public void A_reduction_stopped_at_the_read_cap_reports_the_cap_and_still_fails()
    {
        var marker = "BAD"u8.ToArray();
        var target = Throwing("marker", marker);
        var input = new byte[300];
        marker.CopyTo(input, 120);
        var reduced = Minimizer.Reduce(target, input, FuzzTargets.Probe(target, input, Limit)!.Signature, 5, Limit);
        Assert.True(reduced.Capped);
        Assert.Equal(5, reduced.Runs);
        Assert.NotNull(FuzzTargets.Probe(target, reduced.Bytes, Limit));
    }

    [Fact]
    public void A_tool_error_is_a_refusal_and_not_a_failure()
    {
        var target = new FuzzTarget("refusing", (_, _) => throw new ToolError(ErrorCode.InvalidArgument, "not this format"));
        Assert.Null(FuzzTargets.Probe(target, Encoding.ASCII.GetBytes("x"), Limit));
    }

    [Fact]
    public void A_read_that_outlasts_the_limit_is_a_timeout_failure()
    {
        var target = new FuzzTarget("waiting", (_, ct) => Task.Delay(TimeSpan.FromMinutes(1), ct).GetAwaiter().GetResult());
        Assert.Equal("timeout", FuzzTargets.Probe(target, [1], TimeSpan.FromMilliseconds(100))!.Signature);
    }

    [Fact]
    public void A_fixture_name_carries_the_target_and_a_hash_of_its_bytes()
    {
        var target = FuzzTargets.Find("container")!;
        var name = FuzzTargets.FixtureName(target, [1, 2, 3]);
        Assert.Matches("^container-[0-9a-f]{8}\\.bin$", name);
        Assert.Same(target, FuzzTargets.OfFixture(name));
        Assert.Null(FuzzTargets.OfFixture("no-such-target-00000000.bin"));
    }

    [Fact]
    public void The_sweep_queue_lists_each_target_once()
    {
        var names = FuzzRotation.Queue("sweep", new DateOnly(2026, 11, 1))!.Select(t => t.Name).ToList();
        Assert.Equal(FuzzTargets.All.Select(t => t.Name), names);
        Assert.Equal(names.Count, names.Distinct().Count());
    }

    [Fact]
    public void A_week_of_nightly_queues_covers_each_target_once()
    {
        var first = new DateOnly(2026, 11, 1);
        var names = Enumerable.Range(0, FuzzRotation.Nights)
            .SelectMany(d => FuzzRotation.Queue("nightly", first.AddDays(d))!.Select(t => t.Name)).ToList();
        Assert.Equal(FuzzTargets.All.Select(t => t.Name).Order(), names.Order());
    }

    [Fact]
    public void A_nightly_queue_is_the_same_on_every_read_of_a_date()
    {
        var date = new DateOnly(2026, 11, 3);
        Assert.Equal(FuzzRotation.Queue("nightly", date)!.Select(t => t.Name), FuzzRotation.Queue("nightly", date)!.Select(t => t.Name));
    }

    [Fact]
    public void An_unknown_queue_mode_has_no_queue()
    {
        Assert.Null(FuzzRotation.Queue("weekly", new DateOnly(2026, 11, 1)));
    }

    [Fact]
    public void Two_dates_of_one_week_give_disjoint_nightly_queues()
    {
        var a = FuzzRotation.Queue("nightly", new DateOnly(2026, 11, 1))!.Select(t => t.Name);
        var b = FuzzRotation.Queue("nightly", new DateOnly(2026, 11, 2))!.Select(t => t.Name);
        Assert.Empty(a.Intersect(b));
    }

    [Fact]
    public void The_queue_command_exits_2_for_a_bad_date_or_a_bad_mode()
    {
        var entry = typeof(FuzzTargets).Assembly.EntryPoint!;
        Assert.Equal(2, entry.Invoke(null, [new[] { "queue", "nightly", "--date", "11/01/2026" }]));
        Assert.Equal(2, entry.Invoke(null, [new[] { "queue", "weekly" }]));
        Assert.Equal(0, entry.Invoke(null, [new[] { "queue", "nightly", "--date", "2026-11-01" }]));
    }
}
