using ModelContextProtocol;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tools;

/// <summary>Shared parameter descriptions and execution helpers for the tool classes.</summary>
internal static class ToolSupport
{
    public const string SymbolDescription =
        "Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', " +
        "'Ns.Type::Method(int, string)' for one overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'.";

    public const string SymbolOrNativeDescription = SymbolDescription +
        " Or a native export: 'kernel32.dll!CreateFileW' (module with .dll/.exe/.sys extension), or 'native:<image>!<export>' where image is a loaded " +
        "image id, file name or path, or a DLL name found by the loader's search order, and export is a name, '#ordinal', or for a loaded image an " +
        "address or function name ('native:KERNELBASE.dll!0x180034560'). Matches the P/Invoke declarations bound to that code and their callers.";

    public const string AssemblyFilterDescription =
        "Assembly id, name, file name or path (see list_assemblies). Optional: omit to use all loaded assemblies.";

    public const string AssemblyDescription = "Assembly id, name, file name or path (see list_assemblies).";

    public const string OffsetDescription = "Character offset for paging long output (use the value from the truncation footer).";
    public const string MaxCharsDescription = "Max characters in this page (default from server config, ~60000).";
    public const string DryRunDescription = "Preview the change without applying it.";

    /// <summary>Runs work off the transport thread under the shared read lock.</summary>
    public static Task<string> Read(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Read(work), ct);

    /// <summary>Runs work off the transport thread under the exclusive write lock.</summary>
    public static Task<string> Write(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Write(work), ct);

    /// <summary>Dry runs use the read lock so they do not bump the workspace generation and invalidate caches.</summary>
    public static Task<string> Edit(AssemblyWorkspace ws, bool dryRun, Func<string> work, CancellationToken ct) =>
        dryRun ? Read(ws, work, ct) : Write(ws, work, ct);

    public static void Report(IProgress<ProgressNotificationValue>? progress, int done, int total, string message) =>
        progress?.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = message });

    public static string Plural(int n, string word)
    {
        if (n == 1) return $"1 {word}";
        var plural = word.EndsWith("ch") || word.EndsWith("sh") || word.EndsWith('s') || word.EndsWith('x') ? word + "es"
            : word.EndsWith('y') && word.Length > 1 && !"aeiou".Contains(word[^2]) ? word[..^1] + "ies"
            : word + "s";
        return $"{n} {plural}";
    }

    public static int ClampLimit(int limit, int max = 5_000) => Math.Clamp(limit, 1, max);

    public static string TruncationNote(int shown, int total) => total > shown ? $" (showing {shown}; raise limit or refine)" : "";

    /// <summary>
    /// One line counting the method bodies of the searched assemblies that are not valid IL (encrypted or corrupt): their
    /// instructions are read only up to the first undecodable one. Empty when there are none.
    /// </summary>
    public static string SkippedBodiesNote(IEnumerable<LoadedAssembly> searched)
    {
        var affected = searched.Where(a => a.BodyHealth.Invalid > 0).ToList();
        if (affected.Count == 0) return "";
        var each = string.Join(", ", affected.Take(5).Select(a => $"{a.Id} {a.BodyHealth.Invalid}")) + (affected.Count > 5 ? ", …" : "");
        int total = affected.Sum(a => a.BodyHealth.Invalid);
        return $"Skipped: {Plural(total, "method body")} not valid IL ({each}), read only up to the first invalid instruction; matches inside may be missing.\n";
    }
}
