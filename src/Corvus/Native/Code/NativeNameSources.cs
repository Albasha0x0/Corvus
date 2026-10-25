using System.Runtime.CompilerServices;
using Corvus.Core;

namespace Corvus.Native.Code;

/// <summary>
/// Where a name or comment at a native address comes from. At one address the highest source wins:
/// user (rename_native / comment_native) &gt; pdb &gt; nativeaot &gt; il2cpp &gt; objc &gt; swift (Mach-O runtime metadata) &gt; dart (Dart AOT snapshot objects) &gt;
/// napi (Node-API add-on registrations) &gt;
/// ida (library functions IDA recognized by signature) &gt;
/// ghidra (names from Ghidra's loader and analysis, Function ID included) &gt; discovered (exports, imports, sub_&lt;rva&gt;). Values are stored in saved layers; priority is <see cref="NativeNameSources.Rank"/>.
/// </summary>
public enum NativeNameSource { Discovered = 0, Ida = 1, Il2Cpp = 2, Pdb = 3, User = 4, NativeAot = 5, Ghidra = 6, ObjC = 7, Swift = 8, NodeApi = 9, Dart = 10 }

public static class NativeNameSources
{
    /// <summary>Imported and user sources, highest priority first.</summary>
    public static readonly IReadOnlyList<NativeNameSource> ByPriority =
        [NativeNameSource.User, NativeNameSource.Pdb, NativeNameSource.NativeAot, NativeNameSource.Il2Cpp, NativeNameSource.ObjC, NativeNameSource.Swift,
            NativeNameSource.Dart, NativeNameSource.NodeApi, NativeNameSource.Ida, NativeNameSource.Ghidra];

    /// <summary>Priority of a source at one address: higher wins.</summary>
    public static int Rank(this NativeNameSource source) => source switch
    {
        NativeNameSource.User => 10,
        NativeNameSource.Pdb => 9,
        NativeNameSource.NativeAot => 8,
        NativeNameSource.Il2Cpp => 7,
        NativeNameSource.ObjC => 6,
        NativeNameSource.Swift => 5,
        NativeNameSource.Dart => 4,
        NativeNameSource.NodeApi => 3,
        NativeNameSource.Ida => 2,
        NativeNameSource.Ghidra => 1,
        _ => 0,
    };

    /// <summary>The source's identifier in tool output and sidecar files: user, pdb, nativeaot, il2cpp, objc, swift, dart, napi, ida, ghidra, discovered.</summary>
    public static string Id(this NativeNameSource source) => source switch
    {
        NativeNameSource.User => "user",
        NativeNameSource.Pdb => "pdb",
        NativeNameSource.NativeAot => "nativeaot",
        NativeNameSource.Il2Cpp => "il2cpp",
        NativeNameSource.ObjC => "objc",
        NativeNameSource.Swift => "swift",
        NativeNameSource.Dart => "dart",
        NativeNameSource.NodeApi => "napi",
        NativeNameSource.Ida => "ida",
        NativeNameSource.Ghidra => "ghidra",
        _ => "discovered",
    };

    public static NativeNameSource? Parse(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "user" => NativeNameSource.User,
        "pdb" => NativeNameSource.Pdb,
        "il2cpp" => NativeNameSource.Il2Cpp,
        "nativeaot" => NativeNameSource.NativeAot,
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
    private const int Sources = (int)NativeNameSource.Dart + 1;
    private static readonly NativeNameSource[] Priority = [.. NativeNameSources.ByPriority];
    private readonly object _gate = new();
    private readonly Dictionary<uint, string>[] _names = Enumerable.Range(0, Sources).Select(_ => new Dictionary<uint, string>()).ToArray();
    private readonly Dictionary<uint, string>[] _comments = Enumerable.Range(0, Sources).Select(_ => new Dictionary<uint, string>()).ToArray();
    // Name in effect -> address; most names are unique, so only repeated ones get a set.
    private readonly Dictionary<string, uint> _addressOf = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<uint>> _addressesOf = new(StringComparer.Ordinal);
    private int _version;

    /// <summary>Incremented by every change; output cached under it goes stale with the names.</summary>
    public int Version => Volatile.Read(ref _version);

    /// <summary>Sets (null or empty clears) one source's name at <paramref name="rva"/>; returns the name now in effect there.</summary>
    public string? SetName(uint rva, string? name, NativeNameSource source)
    {
        lock (_gate)
        {
            _version++;
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
            _version++;
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
            _version++;
            if (string.IsNullOrEmpty(text)) _comments[(int)source].Remove(rva);
            else _comments[(int)source][rva] = text;
        }
    }

    public void ReplaceComments(NativeNameSource source, IReadOnlyDictionary<uint, string>? comments)
    {
        lock (_gate)
        {
            _version++;
            _comments[(int)source] = comments != null ? comments.Where(kv => !string.IsNullOrEmpty(kv.Value)).ToDictionary() : new();
        }
    }

    /// <summary>The highest-priority name at <paramref name="rva"/> and its source, or null.</summary>
    public (string Name, NativeNameSource Source)? NameAt(uint rva)
    {
        lock (_gate) return NameCore(rva);
    }

    /// <summary>One source's name at <paramref name="rva"/>, whether or not it is the one in effect.</summary>
    public string? NameAt(uint rva, NativeNameSource source)
    {
        if (source == NativeNameSource.Discovered) return null;
        lock (_gate) return _names[(int)source].GetValueOrDefault(rva);
    }

    public (string Text, NativeNameSource Source)? CommentAt(uint rva)
    {
        lock (_gate)
        {
            foreach (var s in Priority)
                if (_comments[(int)s].TryGetValue(rva, out var c)) return (c, s);
            return null;
        }
    }

    /// <summary>Every address where <paramref name="name"/> is the name in effect, ascending, with the source that set it there.</summary>
    public IReadOnlyList<(uint Rva, NativeNameSource Source)> AddressesOf(string name)
    {
        lock (_gate)
        {
            if (_addressOf.TryGetValue(name, out var rva)) return [(rva, NameCore(rva)!.Value.Source)];
            if (!_addressesOf.TryGetValue(name, out var set)) return [];
            return set.Order().Select(r => (r, NameCore(r)!.Value.Source)).ToList();
        }
    }

    /// <summary>The names and comments in effect at addresses in [<paramref name="start"/>, <paramref name="end"/>), ascending.</summary>
    public List<(uint Rva, string? Name, string? Comment, NativeNameSource Source)> In(uint start, uint end)
    {
        lock (_gate)
        {
            var at = new SortedSet<uint>();
            foreach (var d in _names) foreach (var r in d.Keys) if (r >= start && r < end) at.Add(r);
            foreach (var d in _comments) foreach (var r in d.Keys) if (r >= start && r < end) at.Add(r);
            var result = new List<(uint, string?, string?, NativeNameSource)>(at.Count);
            foreach (var r in at)
            {
                var name = NameCore(r);
                var comment = Priority.Select(s => (Text: _comments[(int)s].GetValueOrDefault(r), Source: s)).FirstOrDefault(c => c.Text != null);
                result.Add((r, name?.Name, comment.Text, name?.Source ?? comment.Source));
            }
            return result;
        }
    }

    public int Count(NativeNameSource source)
    {
        lock (_gate) return _names[(int)source].Count;
    }

    private (string Name, NativeNameSource Source)? NameCore(uint rva)
    {
        foreach (var s in Priority)
            if (_names[(int)s].TryGetValue(rva, out var n)) return (n, s);
        return null;
    }

    private string? Track(uint rva, string? before)
    {
        var now = NameCore(rva)?.Name;
        if (before == now) return now;
        if (before != null) Unmap(before, rva);
        if (now != null) Map(now, rva);
        return now;
    }

    private void Map(string name, uint rva)
    {
        if (_addressesOf.TryGetValue(name, out var set)) set.Add(rva);
        else if (!_addressOf.TryGetValue(name, out var at)) _addressOf[name] = rva;
        else if (at != rva)
        {
            _addressOf.Remove(name);
            _addressesOf[name] = [at, rva];
        }
    }

    private void Unmap(string name, uint rva)
    {
        if (_addressesOf.TryGetValue(name, out var set))
        {
            if (!set.Remove(rva) || set.Count > 1) return;
            _addressesOf.Remove(name);
            _addressOf[name] = set.First();
        }
        else if (_addressOf.TryGetValue(name, out var at) && at == rva) _addressOf.Remove(name);
    }
}

/// <summary>
/// Where a saved layer came from: the source file (PDB, global-metadata.dat, script.json or dummy assembly), its identity
/// when imported (PDB "GUID age", else the file's SHA-256), when, the function starts it contributes to the code index
/// (PDB), and whether this layer was read back from disk at load rather than imported in this session.
/// </summary>
public sealed record ImportInfo(string? SourcePath, string? SourceIdentity, DateTime ImportedUtc, IReadOnlyList<uint>? FunctionStarts = null, bool Restored = false);

/// <summary>
/// The imported (non-user) names and comments of a loaded image, one layer per source, each replaced or removed as a
/// whole. Kept per <see cref="LoadedNative"/> so they survive in-memory patching (which rebuilds the code index) and
/// replayed onto every newly built index. Layers with <see cref="ImportInfo"/> (load_pdb, apply_il2cpp_names, NativeAOT) are also
/// saved beside the image's annotations and restored when the image is loaded again.
/// </summary>
public sealed class NativeNameLayers
{
    private static readonly ConditionalWeakTable<LoadedNative, NativeNameLayers> Table = new();
    private readonly object _gate = new();
    private readonly Dictionary<NativeNameSource, Layer> _layers = new();

    /// <summary>One source's names and comments by RVA, with where they came from (for reports).</summary>
    /// <param name="Info">Provenance of an import that is saved with the image's annotations; null for layers not saved.</param>
    public sealed record Layer(NativeNameSource Source, IReadOnlyDictionary<uint, string> Names, IReadOnlyDictionary<uint, string> Comments, string Origin,
        ImportInfo? Info = null);

    public static NativeNameLayers Of(LoadedNative native) => Table.GetValue(native, _ => new NativeNameLayers());

    public static NativeNameLayers? OfOrNull(LoadedNative native) => Table.TryGetValue(native, out var layers) ? layers : null;

    public Layer? Get(NativeNameSource source)
    {
        lock (_gate) return _layers.GetValueOrDefault(source);
    }

    public IReadOnlyList<Layer> Layers
    {
        get { lock (_gate) return _layers.Values.OrderByDescending(l => l.Source.Rank()).ToList(); }
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
