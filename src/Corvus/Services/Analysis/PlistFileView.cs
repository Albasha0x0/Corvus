using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Analysis;

/// <summary>view=plist: a binary or XML property list as JSON, NSKeyedArchiver archives decoded to their object graph.</summary>
internal sealed class PlistFileView : IFileSummaryView
{
    private const int MaxJsonChars = 24_000;
    /// <summary>A streamed file's values keep this many bytes: the JSON shown is clipped well before.</summary>
    private const int MaxValue = 1 << 20;

    public sealed record Facts(string Format, bool KeyedArchive, IReadOnlyList<string>? TopKeys, string Json, bool Clipped, IReadOnlyList<string>? Issues);

    public string Name => "plist";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        var head = file.Head.AsSpan(0, Math.Min(file.Head.Length, 512));
        if (!Plist.IsBinary(head) && head.IndexOf("<plist"u8) < 0) return null;
        PlistDocument doc;
        if (!file.Streamed) doc = Plist.Read(file.Bytes);
        else
            using (var stream = file.OpenRead()) doc = Plist.Read(stream, MaxValue);
        if (doc.Root is not { } root) return null;
        var issues = doc.Issues.Select(i => $"{i.Area}: {i.Message}").ToList();
        bool keyed = KeyedArchive.IsKeyedArchive(root);
        if (keyed)
        {
            var projected = KeyedArchive.Project(root);
            root = projected.Root;
            issues.AddRange(projected.Issues.Select(i => $"{i.Area}: {i.Message}"));
        }
        var json = Plist.ToJson(root);
        bool clipped = json.Length > MaxJsonChars;
        var keys = (root as PlistDict)?.Entries.Select(e => e.Key).Take(200).ToList();
        var facts = new Facts(doc.Format, keyed, keys, clipped ? json[..MaxJsonChars] : json, clipped, issues.Count > 0 ? issues : null);
        return new FileView(facts, [$"Property list ({doc.Format}{(keyed ? ", NSKeyedArchiver archive decoded" : "")})" +
                                    (keys != null ? $": {keys.Count} top-level keys ({string.Join(", ", keys.Take(8))}{(keys.Count > 8 ? ", ..." : "")})" : "") + "."]);
    }
}
