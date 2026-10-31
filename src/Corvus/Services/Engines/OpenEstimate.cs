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

    /// <summary>Returns the expected seconds of a first analysis for the given code size; an unknown engine uses the default rate of 5 s per MiB.</summary>
    public double Seconds(string engine, long codeBytes)
    {
        var rates = Load().GetValueOrDefault(engine)?.Select(s => s[1] / s[0] * (1 << 20)).Order().ToList();
        var rate = rates is { Count: > 0 } ? rates[rates.Count / 2] : InitialRate.GetValueOrDefault(engine, DefaultRate);
        return Math.Clamp(Math.Round(rate * codeBytes / (1 << 20)), MinimumSeconds, MaximumSeconds);
    }

    /// <summary>Keeps the open only when its analysis ran at least 1 s, since a saved database opens in seconds; returns whether it was kept.</summary>
    public bool RecordOpen(string engine, long codeBytes, double analysisSeconds, double openSeconds)
    {
        if (analysisSeconds < 1) return false;
        Record(engine, codeBytes, openSeconds);
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
