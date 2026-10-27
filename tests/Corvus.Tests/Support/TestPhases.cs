using System.Diagnostics;
using System.Globalization;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The steps a long test completed, each with its time since the test started, so a timeout names the step it reached.
/// </summary>
public sealed class TestPhases(ITestOutputHelper output)
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly List<(TimeSpan At, string Name)> _phases = [];

    /// <summary>Records <paramref name="name"/> as completed now and writes it to the test output.</summary>
    public void Phase(string name)
    {
        var at = _clock.Elapsed;
        lock (_phases) _phases.Add((at, name));
        output.WriteLine($"phase {name} at {Seconds(at)} s");
    }

    /// <summary>
    /// Runs <paramref name="step"/> and records <paramref name="name"/> once it completes; a step that throws is
    /// reported as an <see cref="InvalidOperationException"/> naming the phases reached, with the original inside.
    /// </summary>
    public async Task<T> Run<T>(string name, Func<Task<T>> step)
    {
        T result;
        try { result = await step(); }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"{name} did not complete; {Summary()}", ex);
        }
        Phase(name);
        return result;
    }

    /// <summary>Records the step a successful session tool call completed; other calls record nothing.</summary>
    public void Record(string tool, IReadOnlyDictionary<string, object?> args, string text, bool failed)
    {
        if (failed) return;
        var action = args.TryGetValue("action", out var a) ? a as string : null;
        var phase = (tool, action) switch
        {
            ("live_session", "spawn" or "attach" or "attach_child") => action!.Replace('_', ' '),
            ("live_session", "close") => "close",
            ("live_script", "load") => "load script",
            ("live_break", "set") => "stop point set",
            ("live_watch", "set") => "watch set",
            ("live_coverage", "start") => "coverage start",
            ("live_break", _) when text.Contains("stopped at", StringComparison.Ordinal) => "hit",
            _ => null,
        };
        if (phase != null) Phase(phase);
        else if (text.Contains("no stop within", StringComparison.Ordinal)) output.WriteLine(Summary());
    }

    /// <summary>The last step completed and the list of all of them; "no phase reached" when none was recorded.</summary>
    public string Summary()
    {
        lock (_phases)
        {
            if (_phases.Count == 0) return $"no phase reached in {Seconds(_clock.Elapsed)} s";
            var (at, name) = _phases[^1];
            return $"last phase {name} at {Seconds(at)} s, now {Seconds(_clock.Elapsed)} s; phases: " +
                string.Join(", ", _phases.Select(p => $"{p.Name} {Seconds(p.At)}"));
        }
    }

    private static string Seconds(TimeSpan t) => t.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture);
}
