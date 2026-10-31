using ModelContextProtocol;
using Corvus.Core;

namespace Corvus.Tools;

/// <summary>Shared parameter descriptions and execution helpers for the tool classes.</summary>
internal static class ToolSupport
{
    public const string SymbolDescription =
        "Type or member: Ns.Type, Ns.Outer+Inner, Ns.Type::Method(int), short name, token.";

    public const string SymbolOrNativeDescription =
        "Type or member (Ns.Type::Method(int), short name, token) or native export (kernel32.dll!CreateFileW, native:IMAGE!NAME|#ORD|ADDR).";

    public const string AssemblyFilterDescription =
        "Assembly id, name or path; omit: all loaded.";

    public const string AssemblyDescription = "Assembly id, name or path.";

    /// <summary>Offset of a list tool, in rows; the agent passes the previous page's nextOffset.</summary>
    public const string RowOffsetDescription = "Rows to skip.";
    /// <summary>Offset of a text tool, in characters.</summary>
    public const string CharOffsetDescription = "Character offset (a page's nextOffset).";
    public const string MaxTokensDescription = "Page size in tokens.";
    /// <summary>Limit of a list tool, in rows; the token budget can cut the page further.</summary>
    public const string LimitDescription = "Max rows.";
    public const string DryRunDescription = "Preview the change without applying it.";
    /// <summary>The dryRun text of editing tools whose dryRun defaults to true.</summary>
    public const string DryRunDefaultTrueDescription = "true previews; false applies.";

    /// <summary>Runs work off the transport thread under the shared read lock.</summary>
    public static Task<string> Read(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Read(work), ct);

    /// <summary>Runs work off the transport thread under the exclusive write lock.</summary>
    public static Task<string> Write(AssemblyWorkspace ws, Func<string> work, CancellationToken ct) =>
        Task.Run(() => ws.Write(work), ct);

    /// <summary>Dry runs use the read lock so they do not bump the workspace generation and invalidate caches.</summary>
    public static Task<string> Edit(AssemblyWorkspace ws, bool dryRun, Func<string> work, CancellationToken ct) =>
        dryRun ? Read(ws, work, ct) : Write(ws, work, ct);

    /// <summary>A C# edit, compiled under the shared lock first so the exclusive merge does not block calls through the compile.</summary>
    public static Task<string> CompiledEdit(AssemblyWorkspace ws, Corvus.Services.EditService edits, bool dryRun, Func<string> work, CancellationToken ct) =>
        dryRun ? Read(ws, work, ct) : Task.Run(() =>
        {
            using var reuse = edits.ReuseCompiles();
            int generation = ws.Read(() =>
            {
                edits.Prepare(work);
                return ws.Generation;
            });
            return ws.Write(() =>
            {
                if (ws.Generation == generation) return work();
                // Another exclusive section ran in between, so the prepared work may describe another module.
                using var fresh = edits.ReuseCompiles();
                return work();
            });
        }, ct);

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

    /// <summary>The end of a page, offset + limit, clamped to int.MaxValue.</summary>
    public static int End(int offset, int limit) => (int)Math.Min((long)offset + Math.Max(0, limit), int.MaxValue);

    /// <summary>The page of <paramref name="all"/> that <see cref="OutputPager.PageRows"/> shows, as a structured list: (items, offset, total, truncated).</summary>
    public static TResult Paged<T, TResult>(IReadOnlyList<T> all, int offset, int limit, Func<IReadOnlyList<T>, int, int, bool, TResult> make)
    {
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = all.Skip(offset).Take(limit).ToList();
        return make(page, offset, all.Count, offset + page.Count < all.Count);
    }

    /// <summary>The first <paramref name="limit"/> of <paramref name="total"/> results as a structured list, offset 0.</summary>
    public static TResult Firsts<T, TResult>(IEnumerable<T> shown, int total, Func<IReadOnlyList<T>, int, int, bool, TResult> make)
    {
        var items = shown.ToList();
        return make(items, 0, total, items.Count < total);
    }

    public static string TruncationNote(int shown, int total) => total > shown ? $" (showing {shown}; raise limit or refine)" : "";

    /// <summary>One line counting searched method bodies that are not valid IL; empty when there are none.</summary>
    public static string SkippedBodiesNote(IEnumerable<LoadedAssembly> searched)
    {
        var affected = searched.Where(a => a.BodyHealth.Invalid > 0).ToList();
        if (affected.Count == 0) return "";
        var each = string.Join(", ", affected.Take(5).Select(a => $"{a.Id} {a.BodyHealth.Invalid}")) + (affected.Count > 5 ? ", …" : "");
        int total = affected.Sum(a => a.BodyHealth.Invalid);
        return $"Skipped: {Plural(total, "method body")} not valid IL ({each}), read only up to the first invalid instruction; matches inside may be missing.\n";
    }
}
