using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>The Node-API name layer of a .node add-on: callbacks named by their JavaScript registration, rebuilt at each index build.</summary>
public static class NodeApiNames
{
    /// <summary>Sets the layer on <paramref name="index"/> for an add-on; returns the number of names, or null for other images.</summary>
    public static int? AutoApply(LoadedNative native, NativeCodeIndex index, CancellationToken ct)
    {
        if (!NodeApi.IsAddon(index.Image)) return null;
        var found = NodeApi.Find(index, ct);
        var (names, comments) = NodeApi.Names(index.Image, found.Registrations);
        NativeNameLayers.Of(native).Set(new NativeNameLayers.Layer(NativeNameSource.NodeApi, names, comments,
            $"Node-API registrations ({names.Count} callbacks{(found.Notes.Count > 0 ? "; " + string.Join("; ", found.Notes) : "")})"), index);
        return names.Count;
    }
}
