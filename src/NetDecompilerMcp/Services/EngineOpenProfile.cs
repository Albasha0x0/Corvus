using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>One stage of an engine open, the seconds it took, and its longest parts (the engine's own analysis steps).</summary>
public sealed record EngineOpenStage(string Stage, double Seconds)
{
    public IReadOnlyList<EngineOpenStage>? Parts { get; init; }
}

/// <summary>
/// Where an engine open spent its time: the server's stages (prepare, start, import or load, analysis, save) from one report
/// to the next, the engine's own progress messages (analyzers, at its 2 s heartbeat) as parts of the stage they ran in, and
/// the PDB type load that follows the open.
/// </summary>
public sealed class EngineOpenProfile
{
    /// <summary>Stages the server and its workers name; any other message is an engine step inside the current one.</summary>
    private static readonly HashSet<string> Main = new(StringComparer.Ordinal) { "prepare", "start", "import", "load", "analysis", "save", "rebase" };

    /// <summary>Engine steps that carry an item after a fixed prefix ("Decompiling f", "Stack g"): grouped by the prefix.</summary>
    private static readonly string[] Grouped = ["Decompiling", "Stack", "Analyze OpRefs", "Hashing", "Disassembled", "Searching", "PDB:", "Demangler",
        "Decompiler Parameter ID", "Applying"];

    /// <summary>Parts kept per stage.</summary>
    private const int MaxParts = 6;

    private readonly object _gate = new();
    private readonly List<(string Stage, double At)> _marks = [];
    private double? _end;
    private readonly List<EngineOpenStage> _after = [];

    /// <summary>A stage reported <paramref name="at"/> seconds after the open started; repeats of the current one are ignored, "ready" ends the open.</summary>
    public void Mark(string stage, double at)
    {
        lock (_gate)
        {
            if (_end != null) return;
            if (stage == "ready")
            {
                _end = at;
                return;
            }
            if (_marks.Count == 0 || _marks[^1].Stage != stage) _marks.Add((stage, at));
        }
    }

    /// <summary>A step after the open (PDB types), with its own duration.</summary>
    public void After(string stage, double seconds)
    {
        lock (_gate) _after.Add(new EngineOpenStage(stage, Math.Round(seconds, 2)));
    }

    public bool Finished
    {
        get { lock (_gate) return _end != null; }
    }

    /// <summary>The stages in order with their seconds and longest parts; an unfinished open measures its last stage to <paramref name="now"/>.</summary>
    public IReadOnlyList<EngineOpenStage> Stages(double now)
    {
        lock (_gate)
        {
            var end = _end ?? now;
            var order = new List<string>();
            var seconds = new Dictionary<string, double>();
            var parts = new Dictionary<string, Dictionary<string, double>>();
            string current = "analysis";
            for (int i = 0; i < _marks.Count; i++)
            {
                var (stage, at) = _marks[i];
                double took = (i + 1 < _marks.Count ? _marks[i + 1].At : end) - at;
                if (Main.Contains(stage)) current = stage;
                if (!seconds.ContainsKey(current))
                {
                    order.Add(current);
                    seconds[current] = 0;
                }
                seconds[current] += took;
                if (!Main.Contains(stage))
                {
                    var key = Key(stage);
                    var p = parts.TryGetValue(current, out var x) ? x : parts[current] = [];
                    p[key] = p.GetValueOrDefault(key) + took;
                }
            }
            var result = order.Select(s => new EngineOpenStage(s, Math.Round(seconds[s], 2))
            {
                Parts = parts.TryGetValue(s, out var p)
                    ? [.. p.OrderByDescending(kv => kv.Value).Take(MaxParts).Select(kv => new EngineOpenStage(kv.Key, Math.Round(kv.Value, 2)))]
                    : null,
            }).ToList();
            return [.. result, .. _after];
        }
    }

    private static string Key(string message)
    {
        var m = message.Trim();
        foreach (var prefix in Grouped)
            if (m.StartsWith(prefix, StringComparison.Ordinal)) return prefix.TrimEnd(':');
        return m.Length > 48 ? m[..48] : m.Length == 0 ? "(engine)" : m;
    }

    /// <summary>"start 3.1 s, analysis 20.4 s (x86 Constant Reference Analyzer 9.0 s, ...), save 0.9 s".</summary>
    public static string Describe(IReadOnlyList<EngineOpenStage> stages) =>
        string.Join(", ", stages.Select(s => $"{s.Stage} {s.Seconds:0.0} s" +
                                             (s.Parts is { Count: > 0 } p ? " (" + string.Join(", ", p.Select(x => $"{x.Stage} {x.Seconds:0.0} s")) + ")" : "")));

    /// <summary>Wraps a progress sink so every stage it sees is marked here first, against <paramref name="clock"/>; "ready" passes on with the profile.</summary>
    public IProgress<NativeProviderProgress> Recording(Func<double> clock, IProgress<NativeProviderProgress>? next) => new Recorder(this, clock, next);

    private sealed class Recorder(EngineOpenProfile profile, Func<double> clock, IProgress<NativeProviderProgress>? next) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value)
        {
            profile.Mark(value.Stage, clock());
            next?.Report(value.Stage == "ready" ? value with { Stage = "ready (" + Describe(profile.Stages(clock())) + ")" } : value);
        }
    }
}
