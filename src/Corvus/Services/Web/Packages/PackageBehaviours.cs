using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Services.Analysis;

namespace Corvus.Services.Web.Packages;

/// <summary>Malcontent behaviours added or removed in each code file two package versions differ in.</summary>
internal static class PackageBehaviours
{
    private const int MaxFiles = 100;

    // Files a behaviour rule can match: scripts, build files and loadable code.
    private static readonly HashSet<string> CodeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".php", ".ps1", ".psm1", ".sh", ".bat", ".cmd", ".vbs",
        ".targets", ".props", ".dll", ".exe", ".so", ".dylib", ".node",
    };

    // A file read on neither side (over the read limit) is not compared.
    private static bool Differs(byte[]? a, byte[]? b) => a == null ? b != null : b == null || !a.AsSpan().SequenceEqual(b);

    /// <summary>Rows keyed "malcontent/&lt;behaviour&gt; at &lt;path&gt;" and notes; both empty when the pack is absent or no code file differs.</summary>
    public static (IReadOnlyList<EvidenceChange> Rows, IReadOnlyList<string> Notes) Between(PackageFiles old, PackageFiles @new, CancellationToken ct,
        string? root = null, WorkerPool? pool = null)
    {
        var changed = old.Paths.Union(@new.Paths, StringComparer.Ordinal).Where(p => CodeExtensions.Contains(Path.GetExtension(p)))
            .Where(p => Differs(old.Bytes(p), @new.Bytes(p))).Order(StringComparer.Ordinal).ToList();
        if (changed.Count == 0 || RulePacks.Folder(root ?? RulePacks.Root, MalcontentChanges.Pack) == null) return ([], []);
        var notes = new List<string>();
        if (changed.Count > MaxFiles) notes.Add($"malcontent behaviours: {changed.Count} code files differ; the first {MaxFiles} by path are compared, the others' behaviours are unknown");
        var rows = new List<EvidenceChange>();
        var temp = Directory.CreateTempSubdirectory("corvus-behaviours-");
        try
        {
            foreach (var path in changed.Take(MaxFiles))
            {
                ct.ThrowIfCancellationRequested();
                // A side without the file, or over the read limit, is scanned as an empty file.
                string Write(PackageFiles files, string side)
                {
                    return SafeFile.WriteUnderRoot(temp.FullName, side + Path.GetExtension(path), files.Bytes(path) ?? [], overwrite: true);
                }
                var (found, text) = MalcontentChanges.Between(Write(old, "old"), Write(@new, "new"), ct, root, pool);
                rows.AddRange(found.Select(r => r with { Key = $"{r.Key} at {path}" }));
                // A failed scan would fail again for every file, and each waits up to the scan limit.
                if (text != null && text.Contains("not compared", StringComparison.Ordinal))
                {
                    notes.Add($"{path}: {text.TrimEnd('\n')}; the remaining files' behaviours are unknown");
                    break;
                }
            }
        }
        finally { temp.Delete(true); }
        return (rows, notes);
    }
}
