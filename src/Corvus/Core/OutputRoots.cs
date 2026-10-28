namespace Corvus.Core;

/// <summary>
/// The folders a client's tool call may write outputs under. The command line
/// and file batches are not held to them; <see cref="OutputGuard"/> applies
/// inside every root.
/// </summary>
public static class OutputRoots
{
    /// <summary>Output folders as a path list, or * for any place the guard allows.</summary>
    public const string Variable = "CORVUS_OUTPUT_DIRS";

    private static readonly AsyncLocal<IReadOnlyList<string>?> InForce = new();

    /// <summary>The current call's roots as final paths; null when it has none.</summary>
    public static IReadOnlyList<string>? Current => InForce.Value;

    /// <summary>
    /// Holds the current call's outputs to <paramref name="roots"/> until the
    /// scope is disposed; null holds nothing.
    /// </summary>
    public static IDisposable Enter(IReadOnlyList<string>? roots)
    {
        var scope = new Scope(InForce.Value);
        InForce.Value = roots;
        return scope;
    }

    /// <summary>
    /// The roots for <paramref name="setting"/>: null for "*"; else the data
    /// folder's exports folder, then the listed folders when it is set, or the
    /// temporary folder and <paramref name="clientRoots"/>. A relative folder,
    /// or one the host cannot name, is left out.
    /// </summary>
    public static IReadOnlyList<string>? Resolve(string? setting, IEnumerable<string> clientRoots)
    {
        if (setting?.Trim() == "*") return null;
        // The exports folder is always a root: a default output moves there.
        IEnumerable<string> folders =
        [
            Native.Providers.DataFolder.Combine(OutputGuard.ExportsFolder),
            .. setting is { Length: > 0 } ? setting.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : [Path.GetTempPath(), .. clientRoots],
        ];
        var roots = new List<string>();
        foreach (var folder in folders)
        {
            try
            {
                if (Path.IsPathFullyQualified(folder)) roots.Add(InputFiles.FinalPathOfNew(Path.GetFullPath(folder)));
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException) { }
        }
        return roots;
    }

    /// <summary>
    /// Throws invalid_argument naming the roots and CORVUS_OUTPUT_DIRS when the
    /// current call is held to roots and <paramref name="final"/> is under none.
    /// </summary>
    public static void Check(string final, string shown)
    {
        if (InForce.Value is not { } roots || roots.Any(r => OutputGuard.Under(final, r))) return;
        throw new ToolError(ErrorCode.InvalidArgument,
            $"{shown} is outside the output roots ({(roots.Count > 0 ? string.Join(", ", roots) : "none")}); tool calls write outputs only under them.",
            $"pick a path under a root, or set {Variable} to folders separated by '{Path.PathSeparator}', or to * for any place")
        {
            Details = new OutputGuard.Refused(shown, final, "outside the output roots"),
        };
    }

    /// <summary>
    /// A tool's default output <paramref name="fileName"/> beside
    /// <paramref name="input"/>, or, when the current call's roots do not hold
    /// the input's folder, in &lt;data&gt;/exports/&lt;input name&gt;/ (created);
    /// <paramref name="moved"/> says which.
    /// </summary>
    public static string Default(string input, string fileName, out bool moved)
    {
        var beside = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(input))!, fileName);
        moved = InForce.Value is { } roots && !roots.Any(r => OutputGuard.Under(InputFiles.FinalPathOfNew(beside), r));
        if (!moved) return beside;
        var folder = Native.Providers.DataFolder.Combine(OutputGuard.ExportsFolder, Blob.SafeRelativePath(Path.GetFileName(input), "file"));
        Directory.CreateDirectory(folder);
        return Path.Combine(folder, fileName);
    }

    private sealed class Scope(IReadOnlyList<string>? previous) : IDisposable
    {
        public void Dispose() => InForce.Value = previous;
    }
}
