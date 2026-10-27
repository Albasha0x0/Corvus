using System.Reflection;

namespace Corvus.Core;

/// <summary>One instance of each concrete provider class in this assembly, ordered by full type name; nothing is registered.</summary>
public static class Providers
{
    private static readonly Dictionary<Type, object> Found = [];
    private static readonly AsyncLocal<object[]?> Extra = new();

    public static IReadOnlyList<T> Of<T>() where T : class
    {
        IReadOnlyList<T> list;
        lock (Found)
        {
            if (Found.TryGetValue(typeof(T), out var cached)) list = (IReadOnlyList<T>)cached;
            else Found[typeof(T)] = list = Scan<T>(typeof(Providers).Assembly);
        }
        return Extra.Value is { } extra ? [.. list, .. extra.OfType<T>()] : list;
    }

    /// <summary>Tests: <paramref name="extra"/> join the scanned providers in this async flow until disposed.</summary>
    internal static IDisposable With(params object[] extra)
    {
        var before = Extra.Value;
        Extra.Value = [.. before ?? [], .. extra];
        return new Restore(() => Extra.Value = before);
    }

    private sealed class Restore(Action undo) : IDisposable
    {
        public void Dispose() => undo();
    }

    /// <summary>The providers of <typeparamref name="T"/> in <paramref name="assembly"/>.</summary>
    public static IReadOnlyList<T> Scan<T>(Assembly assembly) where T : class =>
        [.. assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false, ContainsGenericParameters: false } && typeof(T).IsAssignableFrom(t) && t.GetConstructor(Type.EmptyTypes) != null)
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .Select(t => (T)Activator.CreateInstance(t)!)];
}

/// <summary>A container format beyond the built-in ones, asked only about data no built-in reader takes; bounded by <see cref="AnalysisLimits"/>, never runs what it reads.</summary>
public interface IContainerReader
{
    /// <summary>The container kind as reported (e.g. "tar").</summary>
    string Kind { get; }

    /// <summary>Whether <paramref name="data"/> (the whole file) is this format; <paramref name="name"/> is its file name.</summary>
    bool Accepts(ReadOnlySpan<byte> data, string name);

    /// <summary>One container level: items to extract and every entry; without <paramref name="allFiles"/> items may be limited.</summary>
    ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct);

    /// <summary>The same level read from a seekable stream without holding the file; null when the format needs the bytes.</summary>
    ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) => null;
}
