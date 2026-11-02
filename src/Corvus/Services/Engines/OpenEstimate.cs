using System.Text.Json;
using Corvus.Core;
using Corvus.Native;

namespace Corvus.Services;

/// <summary>Estimates the seconds of a first engine analysis from code size and measured opens.</summary>
public sealed class OpenEstimate(string cacheRoot)
{
    internal const string FileName = "open-history.json";

    /// <summary>Measured opens kept per engine.</summary>
    internal const int MaxSamples = 20;

    /// <summary>Seconds per MiB of code before any open is measured.</summary>
    private static readonly Dictionary<string, double> InitialRate = new(StringComparer.Ordinal) { ["ida"] = 2, ["ghidra"] = 8 };

    private const double DefaultRate = 5;
    private const double MinimumSeconds = 5;
    private const double MaximumSeconds = 86400;

    private static readonly object Gate = new();

    private string HistoryPath => Path.Combine(Path.GetFullPath(cacheRoot), FileName);

    /// <summary>Returns the bytes of the executable sections of <paramref name="image"/>.</summary>
    public static long CodeBytes(INativeImage image) => CodeBytes(image.Sections);

    /// <summary>Returns the bytes of the executable sections in <paramref name="sections"/>.</summary>
    public static long CodeBytes(IEnumerable<NativeSection> sections) => sections.Where(s => s.IsExecutable).Sum(s => (long)s.MappedSize);

    /// <summary>The expected seconds of a first analysis, and whether earlier opens of the engine back them.</summary>
    public readonly record struct Estimate(double Seconds, bool FromHistory)
    {
        /// <summary>What the estimate rests on: earlier opens, else the default rate.</summary>
        public string Basis => FromHistory ? "earlier opens" : "default rate";
    }

    /// <summary>Returns the expected seconds of a first analysis; without history the default rate applies.</summary>
    public Estimate Seconds(string engine, long codeBytes)
    {
        var rates = Load().GetValueOrDefault(engine)?.Select(s => s[1] / s[0] * (1 << 20)).Order().ToList();
        var fromHistory = rates is { Count: > 0 };
        var rate = fromHistory ? rates![rates.Count / 2] : InitialRate.GetValueOrDefault(engine, DefaultRate);
        return new(Math.Clamp(Math.Round(rate * codeBytes / (1 << 20)), MinimumSeconds, MaximumSeconds), fromHistory);
    }

    /// <summary>The history key of runs that compare: one engine, one image, and whether the open loaded a saved database, complete or partial.</summary>
    internal static string RunKey(string engine, string imageSha256, bool reusedDatabase, bool partial) =>
        $"{engine}|{imageSha256.ToLowerInvariant()}|{(reusedDatabase ? (partial ? "reused-partial" : "reused") : "analyzed")}";

    /// <summary>The median seconds of earlier opens of the same image by the same engine and kind, or null when there is none.</summary>
    public Estimate? ForRun(string engine, string imageSha256, bool reusedDatabase, bool partial = false)
    {
        var seconds = Load().GetValueOrDefault(RunKey(engine, imageSha256, reusedDatabase, partial))?.Select(s => s[1]).Order().ToList();
        if (seconds is not { Count: > 0 }) return null;
        return new(Math.Clamp(Math.Round(seconds[seconds.Count / 2]), 1, MaximumSeconds), true);
    }

    /// <summary>Keeps one open of an image; an analyzed open counts only when its analysis ran at least 1 s. Returns whether it was kept.</summary>
    public bool RecordRun(string engine, string imageSha256, bool reusedDatabase, double analysisSeconds, double openSeconds, bool partial = false)
    {
        if (!reusedDatabase && analysisSeconds < 1) return false;
        Record(RunKey(engine, imageSha256, reusedDatabase, partial), 1, openSeconds);
        return true;
    }

    /// <summary>Keeps one measured open; a failed write is skipped.</summary>
    public void Record(string engine, long codeBytes, double seconds)
    {
        if (codeBytes <= 0 || !double.IsFinite(seconds) || seconds <= 0) return;
        lock (Gate)
        {
            try
            {
                var all = Load();
                var list = all.GetValueOrDefault(engine) ?? [];
                list.Add([codeBytes, Math.Round(seconds, 2)]);
                all[engine] = [.. list.TakeLast(MaxSamples)];
                SafeFile.WritePrivate(HistoryPath, JsonSerializer.SerializeToUtf8Bytes(all), overwrite: true);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }

    private Dictionary<string, List<double[]>> Load()
    {
        try
        {
            if (File.Exists(HistoryPath) && JsonSerializer.Deserialize<Dictionary<string, List<double[]>>>(File.ReadAllText(HistoryPath)) is { } all)
                return all.Where(e => e.Value != null).ToDictionary(e => e.Key,
                    e => e.Value.Where(s => s is { Length: 2 } && double.IsFinite(s[0]) && double.IsFinite(s[1]) && s[0] > 0 && s[1] > 0).ToList());
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return [];
    }
}
