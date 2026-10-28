using System.Globalization;

namespace Corvus.Core;

/// <summary>
/// What one call has produced (bytes, items, steps), shared by every
/// <see cref="AnalysisLimits"/> copy of that call. Past
/// <see cref="Floor"/> bytes produced, output above the expansion ratio
/// times the input size is refused; each count polls the call's token.
/// </summary>
public sealed class Spent(CancellationToken ct = default, int? ratio = null, long floor = Spent.Floor)
{
    /// <summary>The expansion ratio, output bytes per input byte; 0 turns the cap off.</summary>
    public const string ExpansionVariable = "CORVUS_MAX_EXPANSION";

    /// <summary>Bytes produced before the expansion cap applies.</summary>
    public const long Floor = 256L << 20;

    /// <summary>The expansion ratio when <see cref="ExpansionVariable"/> is unset.</summary>
    public const int DefaultRatio = 2000;

    private static readonly AsyncLocal<Spent?> InForce = new();
    private long _bytes, _items, _steps, _input;

    /// <summary>The current call's counter; null outside a call.</summary>
    public static Spent? Current => InForce.Value;

    /// <summary>Makes <paramref name="spent"/> the current call's counter until the scope is disposed.</summary>
    public static IDisposable Enter(Spent? spent)
    {
        var scope = new Scope(InForce.Value);
        InForce.Value = spent;
        return scope;
    }

    /// <summary>The ratio <see cref="ExpansionVariable"/> sets: unset or unreadable is <see cref="DefaultRatio"/>, 0 is off.</summary>
    public static int RatioSetting(string? value) =>
        int.TryParse(value?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var r) ? r : DefaultRatio;

    public int Ratio { get; } = ratio ?? RatioSetting(Environment.GetEnvironmentVariable(ExpansionVariable));

    public long Bytes => Interlocked.Read(ref _bytes);
    public long Items => Interlocked.Read(ref _items);
    public long Steps => Interlocked.Read(ref _steps);

    /// <summary>The largest input recorded; 0 until a reader records one, and the cap applies only after that.</summary>
    public long InputBytes => Interlocked.Read(ref _input);

    /// <summary>Records an input of <paramref name="bytes"/>; the largest one sets the cap.</summary>
    public void Input(long bytes)
    {
        for (long seen = InputBytes; bytes > seen; seen = InputBytes)
            if (Interlocked.CompareExchange(ref _input, bytes, seen) == seen) return;
    }

    /// <summary>
    /// Counts one item of <paramref name="bytes"/>; throws limit_exceeded naming
    /// <paramref name="what"/> and the cap when it lifts the output past it.
    /// </summary>
    public void Produced(long bytes, string what)
    {
        ct.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _items);
        long total = Interlocked.Add(ref _bytes, bytes), input = InputBytes;
        if (Ratio <= 0 || input <= 0 || total <= floor || total <= input * Ratio) return;
        throw new ToolError(ErrorCode.LimitExceeded,
            $"{what} lifts the output of this call to {total:N0} bytes from an input of {input:N0} bytes: past the expansion limit " +
            $"({Ratio:N0}x the input once {floor:N0} bytes are produced). The input repeats or amplifies its data.",
            $"set {ExpansionVariable}=0 for a zero-filled image compressed with xz, bzip2 or zstd, or a larger ratio")
        {
            Details = new { produced = total, input, ratio = Ratio, floor },
        };
    }

    /// <summary>Counts one step of work; every 1,024th polls the call's token.</summary>
    public void Step()
    {
        if ((Interlocked.Increment(ref _steps) & 1023) == 0) ct.ThrowIfCancellationRequested();
    }

    private sealed class Scope(Spent? previous) : IDisposable
    {
        public void Dispose() => InForce.Value = previous;
    }
}
