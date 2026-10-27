using Microsoft.CodeAnalysis;

namespace Corvus.Services;

/// <summary>Reuses the scratch merge's source, models and images in the second merge of an edit
/// (EditService.MergeSafely).</summary>
public sealed partial class CSharpPatcher
{
    private sealed class ReplayCache
    {
        public readonly Dictionary<string, string> Sources = new(StringComparer.Ordinal);
        public readonly Dictionary<string, SyntaxTree> Trees = new(StringComparer.Ordinal);
        public readonly Dictionary<SyntaxTree, SemanticModel> Models = new();
        public readonly Dictionary<string, byte[]> Images = new(StringComparer.Ordinal);
    }

    private static readonly AsyncLocal<ReplayCache?> Replay = new();

    /// <summary>Shares compile work on this thread until disposed; with <paramref name="join"/>, an open scope is kept.</summary>
    public IDisposable ReuseCompiles(bool join = false)
    {
        var previous = Replay.Value;
        if (join && previous != null) return new Scope(() => { });
        Replay.Value = new ReplayCache();
        return new Scope(() => Replay.Value = previous);
    }

    private sealed class Scope(Action exit) : IDisposable
    {
        public void Dispose() => exit();
    }

    /// <summary>The tree of an earlier run with the same text (its nodes carry the same annotations), else <paramref name="tree"/>.</summary>
    private static SyntaxTree Reused(SyntaxTree tree)
    {
        if (Replay.Value is not { } cache) return tree;
        var key = tree.GetText().ToString();
        if (cache.Trees.TryGetValue(key, out var earlier)) return earlier;
        cache.Trees[key] = tree;
        return tree;
    }
}
