namespace Corvus.Core;

/// <summary>Types visited so far by the scan of the current call, read by its deadline error.</summary>
public sealed class ScanProgress
{
    private static readonly AsyncLocal<ScanProgress?> Active = new();
    private int _searched;
    private int _total;

    /// <summary>The scan progress of the current call flow, or null outside a joined call.</summary>
    public static ScanProgress? Current => Active.Value;

    /// <summary>Makes <paramref name="progress"/> the current one for this flow.</summary>
    public static void Begin(ScanProgress progress) => Active.Value = progress;

    public int Searched => Volatile.Read(ref _searched);

    /// <summary>Types in scope; 0 until a scan starts.</summary>
    public int Total => Volatile.Read(ref _total);

    internal void Start(int total) => Volatile.Write(ref _total, total);

    internal void Visited() => Interlocked.Increment(ref _searched);
}
