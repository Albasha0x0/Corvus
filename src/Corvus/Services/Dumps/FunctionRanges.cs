using Corvus.Core;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>A function's half-open RVA range [Start, End) in one build, named by module and PE time stamp.</summary>
public sealed record FunctionRange(string Module, uint? TimeDateStamp, string Name, uint Start, uint End);

/// <summary>RVA ranges of named functions in one loaded build.</summary>
public static class FunctionRanges
{
    /// <summary>
    /// Returns the range of each name that resolves to one function in <paramref name="index"/>; any other name
    /// is left out (see <see cref="Lookup"/> for the reason). The time stamp is null for a non-PE image.
    /// </summary>
    public static IReadOnlyList<FunctionRange> Of(LoadedNative native, NativeCodeIndex index, IEnumerable<string> names) =>
        [.. Lookup(native, index, names).Where(l => l.Range != null).Select(l => l.Range!)];

    /// <summary>
    /// Returns one entry per name, in order: the range, or the reason none is known ("absent", "ambiguous",
    /// "inside_function" when the name lies inside a larger function, "no_extent"). The time stamp is null for a non-PE image.
    /// </summary>
    public static IReadOnlyList<FunctionLookup> Lookup(LoadedNative native, NativeCodeIndex index, IEnumerable<string> names)
    {
        var module = Path.GetFileName(native.FilePath);
        var stamp = native.Pe?.Coff.TimeDateStamp;
        var result = new List<FunctionLookup>();
        foreach (var name in names)
        {
            var found = index.AddressesOfName(name);
            if (found.Count == 0) { result.Add(new(name, null, "absent")); continue; }
            if (found.Count > 1) { result.Add(new(name, null, "ambiguous")); continue; }
            if (index.FunctionAt(found[0].Rva) is not { } f) { result.Add(new(name, null, "no_extent")); continue; }
            result.Add(f.Start != found[0].Rva ? new(name, null, "inside_function")
                : new(name, new FunctionRange(module, stamp, name, f.Start, f.End), "found"));
        }
        return result;
    }
}

/// <summary>The outcome for one name: its range when status is "found", otherwise the reason it has none.</summary>
public sealed record FunctionLookup(string Name, FunctionRange? Range, string Status);
