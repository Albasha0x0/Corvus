using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Services;

/// <summary>Ghidra's loader and analysis names as the <see cref="NativeNameSource.Ghidra"/> layer, above discovered names
/// only; imported from an open session, never starts one.</summary>
public static class GhidraNames
{
    public const string Origin = "Ghidra analysis";

    /// <summary>Reads the session's names into the ghidra layer (replacing it) and applies it to the built index; returns the number of names.</summary>
    internal static async Task<int> ImportAsync(LoadedNative native, GhidraSession session, NativeCodeService? code, CancellationToken ct)
    {
        var found = await session.ListNamesAsync(ct).ConfigureAwait(false);
        var user = native.AnnotationsOrNull?.Names().Select(n => n.Rva).ToHashSet() ?? [];
        var names = new Dictionary<uint, string>();
        foreach (var n in found)
            if (!user.Contains(n.Rva) && (n.Function || !names.ContainsKey(n.Rva))) names[n.Rva] = n.Name;
        var layers = NativeNameLayers.Of(native);
        var index = code?.Ready(native);
        layers.Set(new NativeNameLayers.Layer(NativeNameSource.Ghidra, names, new Dictionary<uint, string>(), $"{Origin} ({names.Count} names)"), index);
        // An index that finished building meanwhile replayed the layers before this one was set.
        if (code?.Ready(native) is { } built && !ReferenceEquals(built, index)) layers.ReplayInto(built);
        return names.Count;
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedNative, Task<int>> Refreshes = new();

    /// <summary>Re-imports a Ghidra session's names in the background after an analysis edit; null for other engines.</summary>
    public static Task<int>? Refresh(LoadedNative native, INativeDecompilerSession session, NativeCodeService? code)
    {
        if (session is not GhidraSession ghidra) return null;
        var task = Task.Run(async () =>
        {
            try { return await ImportAsync(native, ghidra, code, native.Released).ConfigureAwait(false); }
            catch (Exception ex) when (ex is ToolError or OperationCanceledException or ObjectDisposedException) { return -1; }
        });
        Refreshes.AddOrUpdate(native, task);
        return task;
    }

    /// <summary>The latest background refresh of the image's ghidra layer, or null when none ran.</summary>
    public static Task<int>? LastRefresh(LoadedNative native) => Refreshes.TryGetValue(native, out var t) ? t : null;
}
