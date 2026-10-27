using Corvus.Core;
using Corvus.Native.Code;
using Corvus.Native.Providers;

namespace Corvus.Services;

/// <summary>IDA's recognized library functions (FUNC_LIB) as the <see cref="NativeNameSource.Ida"/> name layer, above
/// discovered names; imported from an open session, never starts one.</summary>
public static class EngineLibraryNames
{
    public const string Origin = "IDA library recognition";

    /// <summary>Replaces the ida layer with the session's library functions, skipping placeholder and user names; returns the
    /// number of names.</summary>
    public static async Task<int> ImportAsync(LoadedNative native, INativeDecompilerSession session, NativeCodeService? code, CancellationToken ct)
    {
        var functions = await session.ListFunctionsAsync(ct).ConfigureAwait(false);
        var user = native.AnnotationsOrNull?.Names().Select(n => n.Rva).ToHashSet() ?? [];
        var names = new Dictionary<uint, string>();
        foreach (var f in functions)
            if (f.Flags.HasFlag(NativeFunctionFlags.Library) && IsRecognized(f.Name) && !user.Contains(f.StartRva))
                names[f.StartRva] = f.Name;
        var layers = NativeNameLayers.Of(native);
        var index = code?.Ready(native);
        layers.Set(new NativeNameLayers.Layer(NativeNameSource.Ida, names, new Dictionary<uint, string>(), $"{Origin} ({names.Count} functions)"), index);
        // An index that finished building meanwhile replayed the layers before this one was set.
        if (code?.Ready(native) is { } built && !ReferenceEquals(built, index)) layers.ReplayInto(built);
        return names.Count;
    }

    private static bool IsRecognized(string name) =>
        name.Length > 0
        && !name.StartsWith("unknown_libname_", StringComparison.Ordinal)
        && !name.StartsWith("sub_", StringComparison.Ordinal)
        && !name.StartsWith("nullsub_", StringComparison.Ordinal)
        && !name.StartsWith("j_", StringComparison.Ordinal);

    /// <summary>Whether the ida layer names the function at <paramref name="rva"/> (a recognized library function).</summary>
    public static bool IsLibrary(NativeCodeIndex index, uint rva) => index.Sourced.NameAt(rva, NativeNameSource.Ida) != null;
}
