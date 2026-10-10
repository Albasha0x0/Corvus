using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// Where a name or comment at a native address comes from. At one address the highest source wins:
/// user (rename_native / comment_native) &gt; pdb &gt; il2cpp &gt; discovered (exports, imports, sub_&lt;rva&gt;).
/// </summary>
public enum NativeNameSource { Discovered = 0, Il2Cpp = 1, Pdb = 2, User = 3 }

public static class NativeNameSources
{
    /// <summary>The source's identifier in tool output and sidecar files: user, pdb, il2cpp, discovered.</summary>
    public static string Id(this NativeNameSource source) => source switch
    {
        NativeNameSource.User => "user",
        NativeNameSource.Pdb => "pdb",
        NativeNameSource.Il2Cpp => "il2cpp",
        _ => "discovered",
    };

    public static NativeNameSource? Parse(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "user" => NativeNameSource.User,
        "pdb" => NativeNameSource.Pdb,
        "il2cpp" => NativeNameSource.Il2Cpp,
        _ => null,
    };
}

/// <summary>
/// Names and comments of one code index by source (<see cref="NativeNameSource.Discovered"/> excluded: those are the
/// index's own). Answers the name and comment in effect at an address and the address of a name in effect.
/// Thread-safe.
/// </summary>
public sealed class SourcedNames
{
    private const int Sources = (int)NativeNameSource.User + 1;
    private readonly object _gate = new();
    private readonly Dictionary<uint, string>[] _names = Enumerable.Range(0, Sources).Select(_ => new Dictionary<uint, string>()).ToArray();
    private readonly Dictionary<uint, string>[] _comments = Enumerable.Range(0, Sources).Select(_ => new Dictionary<uint, string>()).ToArray();
    private readonly Dictionary<string, uint> _addressOf = new(StringComparer.Ordinal);

    /// <summary>Sets (null or empty clears) one source's name at <paramref name="rva"/>; returns the name now in effect there.</summary>
    public string? SetName(uint rva, string? name, NativeNameSource source)
    {
        lock (_gate)
        {
            var before = NameCore(rva)?.Name;
            if (string.IsNullOrEmpty(name)) _names[(int)source].Remove(rva);
            else _names[(int)source][rva] = name;
            return Track(rva, before);
        }
    }

    /// <summary>Replaces every name of <paramref name="source"/>; returns the addresses whose name in effect changed, with that name.</summary>
    public List<(uint Rva, string? Name)> ReplaceNames(NativeNameSource source, IReadOnlyDictionary<uint, string>? names)
    {
        lock (_gate)
        {
            var old = _names[(int)source];
            var touched = new HashSet<uint>(old.Keys);
            if (names != null) touched.UnionWith(names.Keys);
            var before = touched.ToDictionary(r => r, r => NameCore(r)?.Name);
            _names[(int)source] = names != null ? names.Where(kv => !string.IsNullOrEmpty(kv.Value)).ToDictionary() : new();
            var changed = new List<(uint, string?)>();
            foreach (var rva in touched)
            {
                var now = Track(rva, before[rva]);
                if (now != before[rva]) changed.Add((rva, now));
            }
            return changed;
        }
    }

    public void SetComment(uint rva, string? text, NativeNameSource source)
    {
        lock (_gate)
        {
            if (string.IsNullOrEmpty(text)) _comments[(int)source].Remove(rva);
            else _comments[(int)source][rva] = text;
        }
    }

    public void ReplaceComments(NativeNameSource source, IReadOnlyDictionary<uint, string>? comments)
    {
        lock (_gate)
            _comments[(int)source] = comments != null ? comments.Where(kv => !string.IsNullOrEmpty(kv.Value)).ToDictionary() : new();
    }

    /// <summary>The highest-priority name at <paramref name="rva"/> and its source, or null.</summary>
    public (string Name, NativeNameSource Source)? NameAt(uint rva)
    {
        lock (_gate) return NameCore(rva);
    }

    public (string Text, NativeNameSource Source)? CommentAt(uint rva)
    {
        lock (_gate)
        {
            for (int s = Sources - 1; s > 0; s--)
                if (_comments[s].TryGetValue(rva, out var c)) return (c, (NativeNameSource)s);
            return null;
        }
    }

    /// <summary>The address where <paramref name="name"/> is the name in effect (the lowest one when several).</summary>
    public uint? AddressOf(string name)
    {
        lock (_gate) return _addressOf.TryGetValue(name, out var rva) ? rva : null;
    }

    public int Count(NativeNameSource source)
    {
        lock (_gate) return _names[(int)source].Count;
    }

    private (string Name, NativeNameSource Source)? NameCore(uint rva)
    {
        for (int s = Sources - 1; s > 0; s--)
            if (_names[s].TryGetValue(rva, out var n)) return (n, (NativeNameSource)s);
        return null;
    }

    private string? Track(uint rva, string? before)
    {
        var now = NameCore(rva)?.Name;
        if (before == now) return now;
        if (before != null && _addressOf.TryGetValue(before, out var at) && at == rva) _addressOf.Remove(before);
        if (now != null && (!_addressOf.TryGetValue(now, out var other) || rva < other)) _addressOf[now] = rva;
        return now;
    }
}

/// <summary>
/// The imported (non-user) names and comments of a loaded image, one layer per source, each replaced or removed as a
/// whole. Kept per <see cref="LoadedNative"/> so they survive in-memory patching (which rebuilds the code index) and
/// replayed onto every newly built index; a reload starts without them.
/// </summary>
public sealed class NativeNameLayers
{
    private static readonly ConditionalWeakTable<LoadedNative, NativeNameLayers> Table = new();
    private readonly object _gate = new();
    private readonly Dictionary<NativeNameSource, Layer> _layers = new();

    /// <summary>One source's names and comments by RVA, with where they came from (for reports).</summary>
    public sealed record Layer(NativeNameSource Source, IReadOnlyDictionary<uint, string> Names, IReadOnlyDictionary<uint, string> Comments, string Origin);

    public static NativeNameLayers Of(LoadedNative native) => Table.GetValue(native, _ => new NativeNameLayers());

    public static NativeNameLayers? OfOrNull(LoadedNative native) => Table.TryGetValue(native, out var layers) ? layers : null;

    public Layer? Get(NativeNameSource source)
    {
        lock (_gate) return _layers.GetValueOrDefault(source);
    }

    public IReadOnlyList<Layer> Layers
    {
        get { lock (_gate) return _layers.Values.OrderByDescending(l => l.Source).ToList(); }
    }

    /// <summary>Replaces the layer of <paramref name="layer"/>'s source and applies it to <paramref name="index"/> when given.</summary>
    public void Set(Layer layer, NativeCodeIndex? index)
    {
        if (layer.Source is NativeNameSource.User or NativeNameSource.Discovered)
            throw new ArgumentException("Only imported sources form layers.", nameof(layer));
        lock (_gate)
        {
            _layers[layer.Source] = layer;
            index?.ReplaceSource(layer.Source, layer.Names, layer.Comments);
        }
    }

    /// <summary>Removes a source's layer (and its names from <paramref name="index"/>); returns the removed layer.</summary>
    public Layer? Remove(NativeNameSource source, NativeCodeIndex? index)
    {
        lock (_gate)
        {
            if (!_layers.Remove(source, out var removed)) return null;
            index?.ReplaceSource(source, null, null);
            return removed;
        }
    }

    /// <summary>Applies every layer to a newly built index.</summary>
    public void ReplayInto(NativeCodeIndex index)
    {
        lock (_gate)
            foreach (var layer in _layers.Values) index.ReplaceSource(layer.Source, layer.Names, layer.Comments);
    }
}
