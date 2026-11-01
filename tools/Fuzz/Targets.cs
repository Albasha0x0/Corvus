using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Fuzz;

/// <summary>
/// A reader under test: reads the bytes as one file, returns normally or throws a
/// tool error for input it refuses.
/// </summary>
public sealed class FuzzTarget(string name, Action<byte[], CancellationToken> read)
{
    /// <summary>The name `run`, `check` and `fixture` take; the prefix of its fixtures.</summary>
    public string Name { get; } = name;

    /// <summary>
    /// Reads <paramref name="input"/>; a tool error is a refusal and returns, any
    /// other exception is a failure and propagates.
    /// </summary>
    public void Invoke(byte[] input, CancellationToken ct)
    {
        try { read(input, ct); }
        catch (ToolError) { }
    }
}

/// <summary>
/// What a failing input does: the exception type and the Corvus frame that threw
/// it, or a timeout.
/// </summary>
public sealed record FuzzFailure(string Signature, string Message)
{
    /// <summary>
    /// The failure of <paramref name="ex"/>, unwrapped to its inner cause; reads as
    /// the same failure while its type and throwing frame hold.
    /// </summary>
    public static FuzzFailure Of(Exception ex, bool timedOut)
    {
        if (timedOut) return new FuzzFailure("timeout", "the read did not end within the time limit");
        while (ex is AggregateException or System.Reflection.TargetInvocationException && ex.InnerException != null) ex = ex.InnerException;
        var frame = new StackTrace(ex).GetFrames().Select(f => f.GetMethod()).FirstOrDefault(m => m?.DeclaringType?.FullName?.StartsWith("Corvus.", StringComparison.Ordinal) == true)
            ?? ex.TargetSite;
        return new FuzzFailure($"{ex.GetType().Name}@{frame?.DeclaringType?.Name}.{frame?.Name}", ex.Message);
    }
}

/// <summary>
/// The targets: the container dispatch, each IContainerReader and each
/// summarize_file view.
/// </summary>
public static class FuzzTargets
{
    /// <summary>
    /// Every target, in order: `container`, then `reader-*`, then `view-*`.
    /// </summary>
    public static IReadOnlyList<FuzzTarget> All { get; } = Build();

    /// <summary>The target named <paramref name="name"/>; null when there is none.</summary>
    public static FuzzTarget? Find(string name) => All.FirstOrDefault(t => t.Name == name);

    /// <summary>
    /// The target a fixture file belongs to, from its name; null when the name
    /// carries none.
    /// </summary>
    public static FuzzTarget? OfFixture(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        var cut = name.LastIndexOf('-');
        return cut > 0 ? Find(name[..cut]) : null;
    }

    /// <summary>
    /// The failure of <paramref name="input"/> on <paramref name="target"/>; null
    /// when the read passes. A read still running at <paramref name="timeout"/> is
    /// a timeout failure and is abandoned on its thread.
    /// </summary>
    public static FuzzFailure? Probe(FuzzTarget target, byte[] input, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource();
        var read = Task.Run(() => target.Invoke(input, cts.Token));
        try
        {
            if (read.Wait(timeout)) return null;
        }
        catch (Exception ex)
        {
            return FuzzFailure.Of(ex, timedOut: false);
        }
        cts.Cancel();
        return FuzzFailure.Of(new TimeoutException(), timedOut: true);
    }

    /// <summary>
    /// The fixture name of <paramref name="input"/> for <paramref name="target"/>:
    /// the target, a dash and the first 8 hex digits of the SHA-256.
    /// </summary>
    public static string FixtureName(FuzzTarget target, byte[] input) => $"{target.Name}-{Convert.ToHexString(SHA256.HashData(input))[..8].ToLowerInvariant()}.bin";

    private static string Slug(string text)
    {
        var sb = new StringBuilder();
        foreach (var c in text.ToLowerInvariant()) sb.Append(char.IsAsciiLetterOrDigit(c) ? c : '-');
        return sb.ToString().Trim('-');
    }

    private static List<FuzzTarget> Build()
    {
        var targets = new List<FuzzTarget>
        {
            new("container", (b, ct) => Containers.Open(b, "input.bin", AnalysisLimits.Default, ct, allFiles: true)),
        };
        foreach (var reader in Providers.Of<IContainerReader>())
            targets.Add(new FuzzTarget("reader-" + Slug(reader.Kind), (b, ct) =>
            {
                if (reader.Accepts(b, "input.bin")) reader.Open(b, "input.bin", true, AnalysisLimits.Default, ct);
            }));
        foreach (var view in Providers.Of<IFileSummaryView>())
            targets.Add(new FuzzTarget("view-" + Slug(view.Name), (b, ct) =>
            {
                // A folder of its own: views that look beside the file find nothing there.
                var folder = Directory.CreateTempSubdirectory("corvus-fuzz-");
                try
                {
                    var path = Path.Combine(folder.FullName, "input.bin");
                    File.WriteAllBytes(path, b);
                    view.Inspect(new FileInput(path, b, Blob.Identify(b)) { Options = new FileViewOptions(view.Name) }, ct);
                }
                finally
                {
                    // A view that keeps a handle open must not replace the read's own failure.
                    try { folder.Delete(recursive: true); }
                    catch (IOException) { }
                }
            }));
        return targets;
    }
}
