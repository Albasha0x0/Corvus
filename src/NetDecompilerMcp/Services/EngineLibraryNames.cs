using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The library functions IDA recognized (FLIRT signatures and other library matching: FUNC_LIB) as the
/// <see cref="NativeNameSource.Ida"/> name layer of an image: below user, PDB and Il2Cpp names, above discovered ones.
/// Imported from an engine session once it is open; never starts one.
/// </summary>
public static class EngineLibraryNames
{
    public const string Origin = "IDA library recognition";

    /// <summary>
    /// Reads the session's library functions into the ida layer (replacing it) and applies it to the built index.
    /// Returns the number of names. IDA's placeholder names (unknown_libname_N, sub_, nullsub_, j_) are skipped, and so
    /// are addresses with a user name (this server pushed those into the database).
    /// </summary>
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
