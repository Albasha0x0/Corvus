using Microsoft.CodeAnalysis;

namespace Corvus.Services;

/// <summary>
/// An edit merges twice, into a scratch copy and then into the module (EditService.MergeSafely). The inputs of both runs
/// are the same, so the second takes the first run's decompiled source, bound models and compiled images instead of
/// computing them again; only the merge into the module is repeated.
/// </summary>
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

    /// <summary>Until disposed, operations on this thread reuse each other's compile work (see <see cref="ReplayCache"/>).</summary>
    public IDisposable ReuseCompiles()
    {
        var previous = Replay.Value;
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
