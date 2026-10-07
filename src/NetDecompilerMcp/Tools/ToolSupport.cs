using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tools;

/// <summary>Shared parameter descriptions and execution helpers for the tool classes.</summary>
internal static class ToolSupport
{
    public const string SymbolDescription =
        "Type or member. Forms: 'Ns.Type', 'Ns.Outer+Inner', short 'Type', 'Ns.Type::Method', 'Ns.Type.Method', " +
        "'Ns.Type::Method(int, string)' for an overload, 'Ns.Type::.ctor', or a metadata token like '0x06000123'.";

    public const string AssemblyDescription =
        "Assembly id, name, file name or path (see list_assemblies). Optional: omit to search all loaded assemblies.";

    public const string OffsetDescription = "Character offset for paging long output (use the value given in the truncation footer).";
    public const string MaxCharsDescription = "Max characters to return in this page (default from server config, ~60000).";

    /// <summary>Runs work off the transport thread under the shared (read) lock.</summary>
    public static Task<string> Read(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Read(work), ct);

    /// <summary>Runs work under the exclusive (write) lock — for anything that mutates the workspace.</summary>
    public static Task<string> Write(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Write(work), ct);

    public static string Plural(int n, string word) => n == 1 ? $"1 {word}" : $"{n} {word}s";

    public static int ClampLimit(int limit, int max = 5_000) => Math.Clamp(limit, 1, max);
}
